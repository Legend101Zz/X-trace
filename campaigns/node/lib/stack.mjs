// Stack helpers: PostgreSQL (Docker tmpfs, ephemeral) + Docker or host app helpers.
import fs from "node:fs";
import netMod from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { container, net, docker, PREFIX } from "./docker.mjs";

export const POSTGRES_IMAGE = process.env.XTRACE_CAMP_POSTGRES_IMAGE || "postgres@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db";  // == postgres:18.3 (image index digest)

export function isHostMode() {
  return process.env.XCAMP_APP_MODE === "host";
}

export function nodeBin() {
  return process.env.XCAMP_NODE || process.execPath;
}

export function freePort() {
  return new Promise((resolve, reject) => {
    const srv = netMod.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/** Strips reserved X-trace launcher vars and NODE_OPTIONS preloads before spawning a clean host process or xtrace run. */
export function cleanLaunchEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  for (const reserved of ["XTRACE_BOOTSTRAP_PATH", "XTRACE_NODE_ORIGINAL_OPTIONS", "XTRACE_NODE_OPTIONS_WAS_SET"]) {
    delete env[reserved];
  }
  if (!Object.prototype.hasOwnProperty.call(extra, "NODE_OPTIONS")) {
    delete env.NODE_OPTIONS;
  }
  return env;
}

/** Streams a long host command (prepare/build/migrate) to a log file; resolves with the exit code. */
export function runHostLogged(cmd, args, logPath, { cwd, env, timeoutMs = 3600000 } = {}) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    const out = fs.openSync(logPath, "a", 0o600);
    const p = spawn(cmd, args, {
      cwd,
      env: env || cleanLaunchEnv(),
      stdio: ["ignore", out, out],
    });
    let settled = false;
    const finish = (code, err) => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      try { fs.closeSync(out); } catch {}
      if (err) reject(err);
      else resolve(code ?? 1);
    };
    const t = setTimeout(() => {
      try { p.kill("SIGTERM"); } catch {}
    }, timeoutMs);
    p.on("error", (err) => finish(1, err));
    p.on("close", (code, sig) => finish(code !== null ? code : (sig === "SIGTERM" ? 143 : 1)));
  });
}

/** Installs an exact pinned pnpm version into a local private prefix (no corepack / no global writes). */
export async function ensurePnpm(prefixDir, version, logPath) {
  const binDir = path.join(prefixDir, "node_modules", ".bin");
  const pnpmBin = path.join(binDir, "pnpm");
  if (fs.existsSync(pnpmBin)) return binDir;
  fs.mkdirSync(prefixDir, { recursive: true });
  const npmCache = path.join(prefixDir, ".npm-cache");
  const code = await runHostLogged(
    "npm",
    ["install", "--no-save", "--no-audit", "--no-fund", "--prefix", prefixDir, `pnpm@${version}`],
    logPath,
    {
      env: cleanLaunchEnv({
        npm_config_cache: npmCache,
        npm_config_update_notifier: "false",
        DO_NOT_TRACK: "1",
      }),
    },
  );
  if (code !== 0 || !fs.existsSync(pnpmBin)) {
    throw new Error(`failed to install pinned pnpm@${version} (exit ${code})`);
  }
  return binDir;
}

/**
 * Spawns a long-running host process (app server, worker, or `xtrace run ...`) writing output to `logPath`.
 * `stop()` delivers SIGTERM to the spawned PID (matching `xtrace run`'s signal forwarding and drain contract).
 */
export function spawnHostProcess(cmd, args, logPath, { cwd, env } = {}) {
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const out = fs.openSync(logPath, "a", 0o600);
  const proc = spawn(cmd, args, {
    cwd,
    env: env || cleanLaunchEnv(),
    stdio: ["ignore", out, out],
    detached: true,
  });
  try { fs.closeSync(out); } catch {}
  let exited = false;
  let exitCode = null;
  const exitPromise = new Promise((resolve) => {
    proc.on("error", () => {
      exited = true;
      exitCode = 127;
      resolve(exitCode);
    });
    proc.on("close", (code, sig) => {
      exited = true;
      exitCode = code !== null ? code : (sig === "SIGTERM" ? 143 : sig === "SIGINT" ? 130 : sig === "SIGKILL" ? 137 : -1);
      resolve(exitCode);
    });
  });
  return {
    proc,
    pid: proc.pid,
    isAlive: () => !exited && proc.exitCode === null && proc.signalCode === null,
    exitCode: () => exitCode,
    async stop(timeoutMs = 30000) {
      if (exited) return exitCode;
      try { proc.kill("SIGTERM"); } catch {}
      const done = await Promise.race([exitPromise, sleep(timeoutMs).then(() => null)]);
      if (done === null && !exited) {
        try { process.kill(-proc.pid, "SIGKILL"); } catch {}
        try { proc.kill("SIGKILL"); } catch {}
        await Promise.race([exitPromise, sleep(5000)]);
      }
      return exitCode;
    },
  };
}

export function names(project, tag) {
  const t = `${PREFIX}${project}-${tag}`;
  return { net: t + "-net", db: t + "-db", app: t + "-app" };
}

export async function startPostgres({ netName, dbName, database, user = "xtrace", password }) {
  container.runDetached(dbName, [
    "--network", netName,
    "--network-alias", "db",
    "--tmpfs", "/var/lib/postgresql",
    "-e", `POSTGRES_USER=${user}`,
    "-e", `POSTGRES_PASSWORD=${password}`,
    "-e", `POSTGRES_DB=${database}`,
    "-p", "127.0.0.1::5432",
    POSTGRES_IMAGE,
    "-c", "fsync=off", "-c", "log_statement=none",
  ]);
  const deadline = Date.now() + 90000;
  for (;;) {
    const r = container.exec(dbName, ["pg_isready", "-U", user, "-d", database], { allowFail: true });
    if (r.status === 0) {
      // the entrypoint restarts postgres once after init; confirm with a real query twice
      const q = container.exec(dbName, ["psql", "-U", user, "-d", database, "-Atc", "select 1"], { allowFail: true });
      if (q.status === 0) { await sleep(1500); const q2 = container.exec(dbName, ["psql", "-U", user, "-d", database, "-Atc", "select 1"], { allowFail: true }); if (q2.status === 0) return; }
    }
    if (Date.now() > deadline) throw new Error("postgres readiness deadline");
    await sleep(500);
  }
}

export function psql(dbName, database, sql, user = "xtrace") {
  const r = container.exec(dbName, ["psql", "-U", user, "-d", database, "-At", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c", sql]);
  return r.stdout.trim();
}

export function psqlRows(dbName, database, sql, user = "xtrace") {
  const out = psql(dbName, database, sql, user);
  return out === "" ? [] : out.split("\n").map((l) => l.split("|"));
}

export async function waitHttp(url, { timeoutMs = 180000, isAlive, okStatuses = [200] } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (isAlive && !isAlive()) throw new Error("app container exited before readiness");
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (okStatuses.includes(r.status)) return;
    } catch {}
    if (Date.now() > deadline) throw new Error("readiness deadline exceeded: " + url);
    await sleep(500);
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function teardown({ netName, dbName, appName }) {
  if (appName) container.rm(appName);
  if (dbName) container.rm(dbName);
  if (netName) net.rm(netName);
}
