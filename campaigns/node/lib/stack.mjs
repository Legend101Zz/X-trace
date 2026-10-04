// Docker stack helpers: PostgreSQL (tmpfs, ephemeral) + app container on a private network.
import { container, net, docker, PREFIX } from "./docker.mjs";

export const POSTGRES_IMAGE = process.env.XTRACE_CAMP_POSTGRES_IMAGE || "postgres:18.3";

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
