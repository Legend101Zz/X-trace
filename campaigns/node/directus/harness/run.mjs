#!/usr/bin/env node
// Directus campaign harness (preparation lane; baseline only).
//   node run.mjs prepare            install + build @directus/api in the pinned checkout (Docker, Node 22)
//   node run.mjs baseline <n>       reset DB, start Directus + PostgreSQL in Docker, run scenarios
//   node run.mjs compare <n> <m>..  compare semantic fingerprints of baseline dirs
// Requires Docker Desktop (linux/arm64). See ../campaign.json for the pins.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dockerLogged, container, docker } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, randomSecret, imageId } from "../../lib/baseline.mjs";
import { startPostgres, waitHttp } from "../../lib/stack.mjs";
import { compareRuns } from "../../lib/harness.mjs";
import { sha256Hex } from "../../lib/canonical.mjs";
import { directusScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const root = projectRoot("directus");
const upstream = path.join(root, "upstream");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);

const PREPARE = `set -ex
corepack prepare pnpm@${campaign.packageManager.version} --activate
pnpm config set store-dir /work/.xtrace-pnpm-store
pnpm install --frozen-lockfile --filter @directus/api... --filter directus...
pnpm --filter @directus/api... build
`;

async function prepare() {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(upstream, ".xtrace-prepare.sh"), PREPARE);
  const log = path.join(root, "prepare.log");
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-directus-prepare", "--platform", "linux/arm64", "-v", `${upstream}:/work`, "-e", "COREPACK_HOME=/work/.xtrace-corepack", "-e", "NODE_OPTIONS=--max-old-space-size=6144", image, "sh", "/work/.xtrace-prepare.sh"],
    log,
  );
  console.log("prepare exit", code, "log", log);
  process.exitCode = code;
}

async function buildStack({ names, outDir }) {
  const dbPassword = randomSecret();
  const admin = { email: "xtrace-baseline@example.com", password: randomSecret() };
  const database = "directus";
  const dbUser = "xtrace";
  fs.writeFileSync(path.join(outDir, "credentials.json"), JSON.stringify({ admin, dbPassword }), { mode: 0o600 });
  await startPostgres({ netName: names.net, dbName: names.db, database, user: dbUser, password: dbPassword });
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
  return { baseUrl, admin, db: { container: names.db, database, user: dbUser }, extra: {} };
}

const cmd = process.argv[2];
if (cmd === "prepare") await prepare();
else if (cmd === "baseline") {
  const n = Number(process.argv[3]);
  const pkgSha = sha256Hex(fs.readFileSync(path.join(upstream, "pnpm-lock.yaml")));
  await runBaseline({
    project: "directus",
    n,
    root,
    keep: process.argv.includes("--keep"),
    buildStack,
    scenarios: (ctx) => directusScenarios(ctx),
    meta: {
      upstreamSha: campaign.upstream.sha,
      upstreamTag: campaign.upstream.stableTag,
      nodeVersion: NODE_VERSION,
      nodeImage: image,
      nodeImageId: imageId(image),
      platform: "linux/arm64 (Docker Desktop)",
      database: campaign.runtime.database,
      lockfileSha256: pkgSha,
      scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
    },
  });
} else if (cmd === "compare") {
  const dirs = process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`));
  const r = compareRuns(dirs);
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs prepare | baseline <n> [--keep] | compare <n> <m> ...");
  process.exitCode = 2;
}
