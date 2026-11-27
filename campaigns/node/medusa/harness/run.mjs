#!/usr/bin/env node
// Medusa v2 campaign harness (preparation lane; baseline only).
//   node run.mjs prepare            pnpm install the pinned dtc-starter backend (Docker, Node 24)
//   node run.mjs baseline <n>       reset DB, run migrations + admin user + `medusa start` in Docker
//   node run.mjs compare <n> <m>..  compare semantic fingerprints
// Upstream backend code = @medusajs/* 2.21.2 from the registry (same version as the pinned medusa tag).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dockerLogged, container, PLATFORM } from "../../lib/docker.mjs";
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
import { medusaScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const root = projectRoot("medusa");
const starter = path.join(root, "starter");
const backendDir = path.join(starter, "apps", "backend");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);
const CLI = "node ./node_modules/@medusajs/cli/cli.js";

const MEDUSA_SPECS = {
  "auth-unauthorized-admin": {},
  "auth-invalid-login": { expectDb: true },
  "auth-admin-login": { expectDb: true },
  "product-validation-strict": {},
  "product-create-read-db": { expectDb: true },
  "product-update-persists": { expectDb: true },
  "product-duplicate-handle-conflict": { expectDb: true },
  "storefront-publishable-key-flow": { expectDb: true },
  "concurrent-writes-and-reads": { expectDb: true },
  "product-delete-then-gone": { expectDb: true },
  "error-unknown-route": { allowRouteless: true },
};

const MEDUSA_CANARY_REQUESTS = [
  { method: "POST", path: "/auth/user/emailpass" },
  { method: "GET", path: "/admin/products" },
];

const PREPARE = `set -ex
corepack prepare pnpm@${campaign.packageManager.version} --activate
pnpm config set store-dir /work/.xtrace-pnpm-store
pnpm install --frozen-lockfile --filter @dtc/backend...
`;

async function prepare() {
  const log = path.join(root, "prepare.log");
  if (isHostMode()) {
    const pnpmBinDir = await ensurePnpm(path.join(root, ".xtrace-pnpm-bin"), campaign.packageManager.version, log);
    const pnpmExe = path.join(pnpmBinDir, "pnpm");
    const env = cleanLaunchEnv({
      PATH: `${pnpmBinDir}:${process.env.PATH || ""}`,
      DO_NOT_TRACK: "1",
    });
    const storeDir = path.join(starter, ".xtrace-pnpm-store");
    const code = await runHostLogged(
      pnpmExe,
      ["install", "--store-dir", storeDir, "--frozen-lockfile", "--filter", "@dtc/backend..."],
      log,
      { cwd: starter, env },
    );
    console.log("prepare (host) exit", code, "log", log);
    process.exitCode = code;
    return;
  }
  fs.writeFileSync(path.join(starter, ".xtrace-prepare.sh"), PREPARE);
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-medusa-prepare", "--platform", PLATFORM, "-v", `${starter}:/work`, "-e", "COREPACK_HOME=/work/.xtrace-corepack", image, "sh", "/work/.xtrace-prepare.sh"],
    log,
  );
  console.log("prepare exit", code, "log", log);
  process.exitCode = code;
}

async function buildStack({ names, outDir, launchPrefix = null, extraEnv = {}, logFile = null }) {
  const dbPassword = randomSecret();
  const admin = { email: "xtrace-baseline@example.invalid", password: randomSecret() };
  const database = "medusa";
  const dbUser = "xtrace";
  fs.writeFileSync(path.join(outDir, "credentials.json"), JSON.stringify({ admin, dbPassword }), { mode: 0o600 });
  await startPostgres({ netName: names.net, dbName: names.db, database, user: dbUser, password: dbPassword });

  if (isHostMode()) {
    const pgPort = container.hostPort(names.db, 5432);
    const appPort = await freePort();
    const baseEnv = {
      NODE_ENV: "development",
      HOST: "127.0.0.1",
      PORT: String(appPort),
      DATABASE_URL: `postgres://${dbUser}:${dbPassword}@127.0.0.1:${pgPort}/${database}?sslmode=disable`,
      DB_NAME: database,
      STORE_CORS: "http://localhost:8000",
      ADMIN_CORS: `http://127.0.0.1:${appPort}`,
      AUTH_CORS: `http://127.0.0.1:${appPort}`,
      JWT_SECRET: randomSecret(32),
      COOKIE_SECRET: randomSecret(32),
      ADMIN_EMAIL: admin.email,
      ADMIN_PASSWORD: admin.password,
      MEDUSA_DISABLE_TELEMETRY: "1",
      DO_NOT_TRACK: "1",
    };
    const bootstrapLog = path.join(outDir, "bootstrap.log");
    let code = await runHostLogged(
      nodeBin(),
      ["./node_modules/@medusajs/cli/cli.js", "db:migrate"],
      bootstrapLog,
      { cwd: backendDir, env: cleanLaunchEnv(baseEnv), timeoutMs: 300000 },
    );
    if (code !== 0) throw new Error(`medusa db:migrate exited ${code}`);
    code = await runHostLogged(
      nodeBin(),
      ["./node_modules/@medusajs/cli/cli.js", "user", "-e", admin.email, "-p", admin.password],
      bootstrapLog,
      { cwd: backendDir, env: cleanLaunchEnv(baseEnv), timeoutMs: 120000 },
    );
    if (code !== 0) throw new Error(`medusa user create exited ${code}`);

    const appEnv = cleanLaunchEnv({ ...baseEnv, ...extraEnv });
    const appLog = logFile || path.join(outDir, "app.log");
    const cmd = launchPrefix ? launchPrefix[0] : nodeBin();
    const args = launchPrefix
      ? [...launchPrefix.slice(1), nodeBin(), "./node_modules/@medusajs/cli/cli.js", "start"]
      : ["./node_modules/@medusajs/cli/cli.js", "start"];
    const appProc = spawnHostProcess(cmd, args, appLog, { cwd: backendDir, env: appEnv });
    const baseUrl = `http://127.0.0.1:${appPort}`;
    try {
      await waitHttp(`${baseUrl}/health`, { isAlive: () => appProc.isAlive(), timeoutMs: 300000 });
    } catch (err) {
      await appProc.stop(15000);
      throw err;
    }
    return {
      baseUrl,
      admin,
      db: { container: names.db, database, user: dbUser },
      extra: {},
      stopHost: (ms) => appProc.stop(ms),
    };
  }

  const env = {
    NODE_ENV: "development",
    HOST: "0.0.0.0",
    PORT: "9000",
    DATABASE_URL: `postgres://${dbUser}:${dbPassword}@db:5432/${database}?sslmode=disable`,
    DB_NAME: database,
    STORE_CORS: "http://localhost:8000",
    ADMIN_CORS: "http://localhost:9000",
    AUTH_CORS: "http://localhost:9000",
    JWT_SECRET: randomSecret(32),
    COOKIE_SECRET: randomSecret(32),
    ADMIN_EMAIL: admin.email,
    ADMIN_PASSWORD: admin.password,
    MEDUSA_DISABLE_TELEMETRY: "1",
    DO_NOT_TRACK: "1",
  };
  const envArgs = Object.entries(env).flatMap(([k, v]) => ["-e", `${k}=${v}`]);
  const startCmd = process.env.XTRACE_CAMP_MEDUSA_START || `${CLI} start`;
  container.runDetached(names.app, [
    "--network", names.net,
    "-p", "127.0.0.1::9000",
    "-v", `${starter}:/work`,
    "-w", "/work/apps/backend",
    ...envArgs,
    image,
    "sh", "-c", `${CLI} db:migrate && ${CLI} user -e "$ADMIN_EMAIL" -p "$ADMIN_PASSWORD" && exec ${startCmd}`,
  ]);
  const port = container.hostPort(names.app, 9000);
  const baseUrl = `http://127.0.0.1:${port}`;
  await waitHttp(`${baseUrl}/health`, { isAlive: () => container.running(names.app), timeoutMs: 300000 });
  return { baseUrl, admin, db: { container: names.db, database, user: dbUser }, extra: {} };
}

function commonMeta() {
  return {
    upstreamSha: campaign.upstream.sha,
    upstreamTag: campaign.upstream.stableTag,
    starterSha: campaign.starter.sha,
    appMode: isHostMode() ? "host" : "docker",
    nodeVersion: isHostMode() ? process.version : NODE_VERSION,
    ...(isHostMode() ? {} : { nodeImage: image, nodeImageId: imageId(image) }),
    platform: `${PLATFORM} (${process.env.XCAMP_PLATFORM ? "CI runner" : "Docker Desktop"})`,
    database: campaign.runtime.database,
    lockfileSha256: sha256Hex(fs.readFileSync(path.join(starter, "pnpm-lock.yaml"))),
    scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
  };
}

const cmd = process.argv[2];
if (cmd === "prepare") await prepare();
else if (cmd === "baseline") {
  const n = Number(process.argv[3]);
  await runBaseline({
    project: "medusa",
    n,
    root,
    keep: process.argv.includes("--keep"),
    buildStack,
    scenarios: (ctx) => medusaScenarios(ctx),
    meta: commonMeta(),
  });
} else if (cmd === "instrumented") {
  if (!isHostMode()) throw new Error("medusa instrumented requires XCAMP_APP_MODE=host");
  await runInstrumented({
    project: "medusa",
    root,
    projectDir: process.env.XCAMP_PROJECT_DIR || starter,
    buildStack,
    scenarios: (ctx) => medusaScenarios(ctx),
    scenarioSpecs: MEDUSA_SPECS,
    canaryRequests: MEDUSA_CANARY_REQUESTS,
    meta: commonMeta(),
  });
} else if (cmd === "compare") {
  const r = compareRuns(process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`)));
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs prepare | baseline <n> [--keep] | instrumented | compare <n> <m> ...");
  process.exitCode = 2;
}
