#!/usr/bin/env node
// Directus campaign harness (preparation lane; baseline only).
//   node run.mjs prepare            install + build @directus/api in the pinned checkout (Docker, Node 22)
//   node run.mjs baseline <n>       reset DB, start Directus + PostgreSQL in Docker, run scenarios
//   node run.mjs compare <n> <m>..  compare semantic fingerprints of baseline dirs
// Requires Docker Desktop (linux/arm64). See ../campaign.json for the pins.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dockerLogged, container, docker, PLATFORM } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, randomSecret, imageId } from "../../lib/baseline.mjs";
import { runInstrumented } from "../../lib/instr.mjs";
import {
  startPostgres,
  waitHttp,
  isHostMode,
  nodeBin,
  freePort,
  cleanLaunchEnv,
  runHostLogged,
  ensurePnpm,
  spawnHostProcess,
} from "../../lib/stack.mjs";
import { compareRuns } from "../../lib/harness.mjs";
import { sha256Hex } from "../../lib/canonical.mjs";
import { directusScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const root = projectRoot("directus");
const upstream = path.join(root, "upstream");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);

const DIRECTUS_SPECS = {
  "auth-anonymous-denied": {},
  "auth-invalid-login": { expectDb: true },
  "auth-admin-login": { expectDb: true },
  "item-create-read-db": { expectDb: true },
  "item-validation-null-required": {},
  "item-update-persists": { expectDb: true },
  "concurrent-writes-and-reads": { expectDb: true },
  "item-delete-then-gone": { expectDb: true },
  "outbound-file-import-success": { expectDb: true, expectOutbound: true },
  "outbound-file-import-dependency-5xx": { expectOutbound: true },
  "outbound-file-import-denied-address": {},
  "error-unknown-route": { allowRouteless: true },
};

const DIRECTUS_CANARY_REQUESTS = [
  { method: "POST", path: "/auth/login" },
  { method: "GET", path: "/users/me" },
];

const PREPARE = `set -ex
corepack prepare pnpm@${campaign.packageManager.version} --activate
pnpm config set store-dir /work/.xtrace-pnpm-store
pnpm install --frozen-lockfile --filter @directus/api... --filter directus...
pnpm --filter @directus/api... build
`;

async function prepare() {
  fs.mkdirSync(root, { recursive: true });
  const log = path.join(root, "prepare.log");
  if (isHostMode()) {
    const pnpmBinDir = await ensurePnpm(path.join(root, ".xtrace-pnpm-bin"), campaign.packageManager.version, log);
    const pnpmExe = path.join(pnpmBinDir, "pnpm");
    const env = cleanLaunchEnv({
      PATH: `${pnpmBinDir}:${process.env.PATH || ""}`,
      NODE_OPTIONS: "--max-old-space-size=6144",
      DO_NOT_TRACK: "1",
    });
    const storeDir = path.join(upstream, ".xtrace-pnpm-store");
    let code = await runHostLogged(
      pnpmExe,
      ["install", "--store-dir", storeDir, "--frozen-lockfile", "--filter", "@directus/api...", "--filter", "directus..."],
      log,
      { cwd: upstream, env },
    );
    if (code === 0) {
      code = await runHostLogged(pnpmExe, ["--filter", "@directus/api...", "build"], log, { cwd: upstream, env });
    }
    console.log("prepare (host) exit", code, "log", log);
    process.exitCode = code;
    return;
  }
  fs.writeFileSync(path.join(upstream, ".xtrace-prepare.sh"), PREPARE);
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-directus-prepare", "--platform", PLATFORM, "-v", `${upstream}:/work`, "-e", "COREPACK_HOME=/work/.xtrace-corepack", "-e", "NODE_OPTIONS=--max-old-space-size=6144", image, "sh", "/work/.xtrace-prepare.sh"],
    log,
  );
  console.log("prepare exit", code, "log", log);
  process.exitCode = code;
}

async function buildStack({ names, outDir, launchPrefix = null, extraEnv = {}, logFile = null }) {
  const dbPassword = randomSecret();
  const admin = { email: "xtrace-baseline@example.com", password: randomSecret() };
  const database = "directus";
  const dbUser = "xtrace";
  fs.writeFileSync(path.join(outDir, "credentials.json"), JSON.stringify({ admin, dbPassword }), { mode: 0o600 });
  await startPostgres({ netName: names.net, dbName: names.db, database, user: dbUser, password: dbPassword });

  if (isHostMode()) {
    const pgPort = container.hostPort(names.db, 5432);
    const depImage = `node:${NODE_VERSION}-bookworm-slim`;
    // Keep dependency server in Docker so Directus's default IMPORT_IP_DENY_LIST allows its bridge IP.
    container.runDetached(names.dep, [
      "--network", names.net, "--network-alias", "dep",
      "-p", "127.0.0.1::8080",
      "-v", `${here}:/dep:ro`,
      depImage, "node", "/dep/dependency-server.mjs",
    ]);
    const depPort = container.hostPort(names.dep, 8080);
    const depIp = container.ipAddress(names.dep);
    await waitHttp(`http://127.0.0.1:${depPort}/__requests`, { isAlive: () => container.running(names.dep), timeoutMs: 60000 });

    const appPort = await freePort();
    const extDir = path.join(outDir, "ext");
    const uploadsDir = path.join(outDir, "uploads");
    fs.mkdirSync(extDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(uploadsDir, { recursive: true, mode: 0o700 });

    const baseEnv = {
      HOST: "127.0.0.1",
      PORT: String(appPort),
      DB_CLIENT: "pg",
      DB_HOST: "127.0.0.1",
      DB_PORT: String(pgPort),
      DB_DATABASE: database,
      DB_USER: dbUser,
      DB_PASSWORD: dbPassword,
      SECRET: randomSecret(32),
      ADMIN_EMAIL: admin.email,
      ADMIN_PASSWORD: admin.password,
      TELEMETRY: "false",
      AI_TELEMETRY_ENABLED: "false",
      SERVE_APP: "false",
      NODE_ENV: "production",
      LOG_LEVEL: "warn",
      EXTENSIONS_PATH: extDir,
      STORAGE_LOCAL_ROOT: uploadsDir,
      DO_NOT_TRACK: "1",
    };
    const bootstrapCode = await runHostLogged(
      nodeBin(),
      ["api/dist/cli/run.js", "bootstrap"],
      path.join(outDir, "bootstrap.log"),
      { cwd: upstream, env: cleanLaunchEnv(baseEnv), timeoutMs: 300000 },
    );
    if (bootstrapCode !== 0) throw new Error(`directus bootstrap exited ${bootstrapCode}`);

    const appEnv = cleanLaunchEnv({ ...baseEnv, ...extraEnv });
    const appLog = logFile || path.join(outDir, "app.log");
    const cmd = launchPrefix ? launchPrefix[0] : nodeBin();
    const args = launchPrefix
      ? [...launchPrefix.slice(1), nodeBin(), "api/dist/cli/run.js", "start"]
      : ["api/dist/cli/run.js", "start"];
    const appProc = spawnHostProcess(cmd, args, appLog, { cwd: upstream, env: appEnv });
    const baseUrl = `http://127.0.0.1:${appPort}`;
    try {
      await waitHttp(`${baseUrl}/server/ping`, { isAlive: () => appProc.isAlive(), timeoutMs: 900000 });
    } catch (err) {
      await appProc.stop(15000);
      throw err;
    }
    const dep = { internalUrl: `http://${depIp}:8080`, hostUrl: `http://127.0.0.1:${depPort}` };
    return {
      baseUrl,
      admin,
      dep,
      db: { container: names.db, database, user: dbUser },
      extra: {},
      stopHost: (ms) => appProc.stop(ms),
    };
  }

  const env = {
    HOST: "0.0.0.0",
    PORT: "8055",
    DB_CLIENT: "pg",
    DB_HOST: "db",
    DB_PORT: "5432",
    DB_DATABASE: database,
    DB_USER: dbUser,
    DB_PASSWORD: dbPassword,
    SECRET: randomSecret(32),
    ADMIN_EMAIL: admin.email,
    ADMIN_PASSWORD: admin.password,
    TELEMETRY: "false",
    AI_TELEMETRY_ENABLED: "false",
    SERVE_APP: "false",
    NODE_ENV: "production",
    LOG_LEVEL: "warn",
    EXTENSIONS_PATH: "/tmp/xtrace-extensions",
    STORAGE_LOCAL_ROOT: "/tmp/xtrace-uploads",
    DO_NOT_TRACK: "1",
  };
  // Deterministic local dependency for the outbound scenarios (alias `dep` on the harness network).
  container.runDetached(names.dep, [
    "--network", names.net, "--network-alias", "dep",
    "-p", "127.0.0.1::8080",
    "-v", `${here}:/dep:ro`,
    image, "node", "/dep/dependency-server.mjs",
  ]);
  const depPort = container.hostPort(names.dep, 8080);
  await waitHttp(`http://127.0.0.1:${depPort}/__requests`, { isAlive: () => container.running(names.dep), timeoutMs: 60000 });
  const envArgs = Object.entries(env).flatMap(([k, v]) => ["-e", `${k}=${v}`]);
  // Pre-start command = the upstream CLI exactly as shipped: `bootstrap` (migrations + admin) then `start`.
  container.runDetached(names.app, [
    "--network", names.net,
    "-p", "127.0.0.1::8055",
    "-v", `${upstream}:/work`,
    "-w", "/work",
    ...envArgs,
    image,
    "sh", "-c", "mkdir -p /tmp/xtrace-extensions /tmp/xtrace-uploads && node api/dist/cli/run.js bootstrap && exec node api/dist/cli/run.js start",
  ]);
  const port = container.hostPort(names.app, 8055);
  const baseUrl = `http://127.0.0.1:${port}`;
  await waitHttp(`${baseUrl}/server/ping`, { isAlive: () => container.running(names.app), timeoutMs: 900000 });
  const dep = { internalUrl: "http://dep:8080", hostUrl: `http://127.0.0.1:${depPort}` };
  return { baseUrl, admin, dep, db: { container: names.db, database, user: dbUser }, extra: {} };
}

function commonMeta() {
  const pkgSha = sha256Hex(fs.readFileSync(path.join(upstream, "pnpm-lock.yaml")));
  return {
    upstreamSha: campaign.upstream.sha,
    upstreamTag: campaign.upstream.stableTag,
    appMode: isHostMode() ? "host" : "docker",
    nodeVersion: isHostMode() ? process.version : NODE_VERSION,
    ...(isHostMode() ? {} : { nodeImage: image, nodeImageId: imageId(image) }),
    platform: `${PLATFORM} (${process.env.XCAMP_PLATFORM ? "CI runner" : "Docker Desktop"})`,
    database: campaign.runtime.database,
    lockfileSha256: pkgSha,
    scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
  };
}

const cmd = process.argv[2];
if (cmd === "prepare") await prepare();
else if (cmd === "baseline") {
  const n = Number(process.argv[3]);
  await runBaseline({
    project: "directus",
    n,
    root,
    keep: process.argv.includes("--keep"),
    buildStack,
    scenarios: (ctx) => directusScenarios(ctx),
    meta: commonMeta(),
  });
} else if (cmd === "instrumented") {
  if (!isHostMode()) throw new Error("directus instrumented requires XCAMP_APP_MODE=host");
  await runInstrumented({
    project: "directus",
    root,
    projectDir: process.env.XCAMP_PROJECT_DIR || upstream,
    buildStack,
    scenarios: (ctx) => directusScenarios(ctx),
    scenarioSpecs: DIRECTUS_SPECS,
    canaryRequests: DIRECTUS_CANARY_REQUESTS,
    meta: commonMeta(),
  });
} else if (cmd === "compare") {
  const dirs = process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`));
  const r = compareRuns(dirs);
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs prepare | baseline <n> [--keep] | instrumented | compare <n> <m> ...");
  process.exitCode = 2;
}
