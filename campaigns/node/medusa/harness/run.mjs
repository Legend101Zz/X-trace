#!/usr/bin/env node
// Medusa v2 campaign harness (preparation lane; baseline only).
//   node run.mjs prepare            pnpm install the pinned dtc-starter backend (Docker, Node 24)
//   node run.mjs baseline <n>       reset DB, run migrations + admin user + `medusa start` in Docker
//   node run.mjs compare <n> <m>..  compare semantic fingerprints
// Upstream backend code = @medusajs/* 2.21.2 from the registry (same version as the pinned medusa tag).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dockerLogged, container } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, randomSecret, imageId } from "../../lib/baseline.mjs";
import { startPostgres, waitHttp } from "../../lib/stack.mjs";
import { compareRuns } from "../../lib/harness.mjs";
import { sha256Hex } from "../../lib/canonical.mjs";
import { medusaScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const root = projectRoot("medusa");
const starter = path.join(root, "starter");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);
const CLI = "node ./node_modules/@medusajs/cli/cli.js";

const PREPARE = `set -ex
corepack prepare pnpm@${campaign.packageManager.version} --activate
pnpm config set store-dir /work/.xtrace-pnpm-store
pnpm install --frozen-lockfile --filter @dtc/backend...
`;

async function prepare() {
  fs.writeFileSync(path.join(starter, ".xtrace-prepare.sh"), PREPARE);
  const log = path.join(root, "prepare.log");
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-medusa-prepare", "--platform", "linux/arm64", "-v", `${starter}:/work`, "-e", "COREPACK_HOME=/work/.xtrace-corepack", image, "sh", "/work/.xtrace-prepare.sh"],
    log,
  );
  console.log("prepare exit", code, "log", log);
  process.exitCode = code;
}

async function buildStack({ names, outDir }) {
  const dbPassword = randomSecret();
  const admin = { email: "xtrace-baseline@example.invalid", password: randomSecret() };
  const database = "medusa";
  const dbUser = "xtrace";
  fs.writeFileSync(path.join(outDir, "credentials.json"), JSON.stringify({ admin, dbPassword }), { mode: 0o600 });
  await startPostgres({ netName: names.net, dbName: names.db, database, user: dbUser, password: dbPassword });
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
    meta: {
      upstreamSha: campaign.upstream.sha,
      upstreamTag: campaign.upstream.stableTag,
      starterSha: campaign.starter.sha,
      nodeVersion: NODE_VERSION,
      nodeImage: image,
      nodeImageId: imageId(image),
      platform: "linux/arm64 (Docker Desktop)",
      database: campaign.runtime.database,
      lockfileSha256: sha256Hex(fs.readFileSync(path.join(starter, "pnpm-lock.yaml"))),
      scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
    },
  });
} else if (cmd === "compare") {
  const r = compareRuns(process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`)));
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs prepare | baseline <n> [--keep] | compare <n> <m> ...");
  process.exitCode = 2;
}
