#!/usr/bin/env node
// Vendure v3.7.3 campaign harness (preparation lane; baseline only).
//   node run.mjs create             official `@vendure/create@3.7.3 --ci --db sqlite` in Docker (Node 24)
//   node run.mjs build              stage the tracked PostgreSQL starter, npm ci, compile server + worker
//   node run.mjs seed               populate sample data into a throwaway PostgreSQL and dump seed.sql
//   node run.mjs baseline <n>       fresh PostgreSQL restored from seed.sql, stock server + separate stock worker, run scenarios
//   node run.mjs compare <n> <m>..  compare semantic fingerprints
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { claimWorkspace, generatorExitCode, stageStarter, verifyStarter, verifyBuild, prepareBaselineSeed, writeFreshSeed } from "./preparation.mjs";
import { dockerLogged, container, docker, net, PREFIX, PLATFORM } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, imageId, randomSecret } from "../../lib/baseline.mjs";
import { waitHttp, sleep, startPostgres } from "../../lib/stack.mjs";
import { compareRuns } from "../../lib/harness.mjs";
import { sha256Hex } from "../../lib/canonical.mjs";
import { vendureScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const campaignRoot = projectRoot("vendure");
const workspaceParent = process.env.XTRACE_VENDURE_PREPARATION_PARENT || campaignRoot;
const root = path.join(workspaceParent, "preparation");
const appUser = ["--user", `${process.getuid()}:${process.getgid()}`, "-e", "HOME=/work/.xtrace-home"];
const appDir = path.join(root, "app");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);

async function create() {
  claimWorkspace(workspaceParent, process.env.RUNNER_TEMP);
  const log = path.join(root, "create.log");
  const code = await dockerLogged(
    [
      "run", "--rm", "--name", "xtrace-camp-node-vendure-create", "--platform", PLATFORM, ...appUser,
      "-v", `${root}:/work`,
      "-e", "npm_config_cache=/work/.xtrace-npm-cache", "-e", "npm_config_update_notifier=false",
      "-e", "CI=true", "-e", "DO_NOT_TRACK=1", "-e", "NODE_OPTIONS=--max-old-space-size=6144",
      image, "sh", "-c",
      `cd /work && npm exec --yes --package=@vendure/create@${campaign.starter.package.version} -- create app --ci --use-npm --db sqlite --log-level verbose`,
    ],
    log,
  );
  process.exitCode = generatorExitCode(code);
  console.log("create exit", process.exitCode, "log", log);
}

const PG_DB = "vendure";
const PG_USER = "xtrace";

async function build() {
  const log = path.join(root, "build.log");
  stageStarter(appDir);
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-vendure-build", "--platform", PLATFORM,
     ...appUser, "-v", `${root}:/work`, "-w", "/work/app",
     "-v", `${path.join(here, "..")}:/xtrace-vendure:ro`,
     "-e", "npm_config_cache=/work/.xtrace-npm-cache", "-e", "CI=true", "-e", "DO_NOT_TRACK=1", image,
     "sh", "-c", "npm ci && node /xtrace-vendure/harness/preparation.mjs before-compile /work/app && npm run build:server && npm run build:worker && node /xtrace-vendure/harness/preparation.mjs finish /work/app"],
    log,
  );
  verifyStarter(appDir);
  if (code !== 0) throw new Error("Vendure build did not exit successfully; see private build.log");
  verifyBuild(appDir);
  console.log("build exit", code, "log", log);
  process.exitCode = code;
}

function verifiedAssets() {
  return JSON.parse(execFileSync("python3", ["-B", path.join(here, "seed_assets.py"), "verify",
    path.join(root, "create-assets.tgz"), path.join(root, "create-assets")], { encoding: "utf8", stdio: "pipe" }));
}

// Populate sample data into a throwaway PostgreSQL once and dump it as the reset seed (seed.sql).
async function seed() {
  verifyBuild(appDir);
  const assets = verifiedAssets();
  const tag = "seed";
  const names = { net: `${PREFIX}vendure-${tag}-net`, db: `${PREFIX}vendure-${tag}-db` };
  fs.copyFileSync(path.join(here, "seed-populate.cjs"), path.join(appDir, "dist", "xtrace-seed-populate.cjs"), fs.constants.COPYFILE_EXCL);
  verifyBuild(appDir, true);
  const password = randomSecret();
  try {
    net.create(names.net);
    await startPostgres({ netName: names.net, dbName: names.db, database: PG_DB, user: PG_USER, password });
    const code = await dockerLogged(
      ["run", "--rm", "--name", "xtrace-camp-node-vendure-seed", "--platform", PLATFORM, ...appUser, "--network", names.net, "-v", `${root}:/work`, "-w", "/work/app",
       "-e", "DB_HOST=db", "-e", "DB_PORT=5432", "-e", `DB_NAME=${PG_DB}`, "-e", `DB_USERNAME=${PG_USER}`, "-e", `DB_PASSWORD=${password}`, "-e", "DB_SCHEMA=public",
       "-e", "APP_ENV=dev", "-e", "PORT=3000", "-e", "CREATE_ASSETS_DIR=/work/create-assets", "-e", "DO_NOT_TRACK=1", image, "node", "./dist/xtrace-seed-populate.cjs"],
      path.join(root, "seed.log"),
    );
    if (code !== 0) throw new Error("populate failed; see seed.log");
    verifyBuild(appDir, true);
    const dump = docker(["exec", names.db, "pg_dump", "-U", PG_USER, "-d", PG_DB, "--no-owner", "--no-acl"]).stdout;
    writeFreshSeed(appDir, dump);
    fs.writeFileSync(path.join(appDir, "xtrace-seed-inputs.json"), JSON.stringify({
      schemaVersion: 1, kind: "vendure-seed-inputs", releaseAcceptance: false, assets,
      buildReceiptSha256: sha256Hex(fs.readFileSync(path.join(appDir, "xtrace-build-inputs.json"))),
      helperSha256: sha256Hex(fs.readFileSync(path.join(here, "seed-populate.cjs"))),
      seedSha256: sha256Hex(dump),
    }, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    console.log("seed.sql bytes", dump.length, "sha256", sha256Hex(dump));
  } finally {
    container.rm(names.db);
    net.rm(names.net);
  }
}

function readEnvFile() {
  const env = {};
  for (const line of fs.readFileSync(path.join(appDir, ".env"), "utf8").split("\n")) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line);
    if (m) env[m[1]] = m[2].trim();
  }
  return env;
}

async function buildStack({ names }, seed) {
  const env = readEnvFile();
  const admin = { identifier: env.SUPERADMIN_USERNAME, password: env.SUPERADMIN_PASSWORD };
  const dbPassword = randomSecret();
  await seed.startAndRestore({ container: names.db, username: PG_USER, database: PG_DB },
    () => startPostgres({ netName: names.net, dbName: names.db, database: PG_DB, user: PG_USER, password: dbPassword }),
    docker);
  const common = [
    ...appUser, "--network", names.net, "-v", `${root}:/work`, "-w", "/work/app",
    "-e", "DB_HOST=db", "-e", "DB_PORT=5432", "-e", `DB_NAME=${PG_DB}`, "-e", `DB_USERNAME=${PG_USER}`, "-e", `DB_PASSWORD=${dbPassword}`, "-e", "DB_SCHEMA=public",
    "-e", "PORT=3000", "-e", "APP_ENV=dev", "-e", "DO_NOT_TRACK=1", "-e", "VENDURE_DISABLE_TELEMETRY=1",
  ];
  // The upstream topology: stock server entry and, as a separate process/container, the stock worker entry.
  container.runDetached(names.worker, [...common, image, "node", "./dist/index-worker.js"]);
  container.runDetached(names.app, ["-p", "127.0.0.1::3000", ...common, image, "node", "./dist/index.js"]);
  const port = container.hostPort(names.app, 3000);
  const baseUrl = `http://127.0.0.1:${port}`;
  // Readiness (necessary, never sufficient): shop-api answers and the worker logged "ready".
  const deadline = Date.now() + 300000;
  for (;;) {
    if (!container.running(names.app)) throw new Error("app container exited before readiness");
    if (!container.running(names.worker)) throw new Error("worker container exited before readiness");
    try {
      const r = await fetch(baseUrl + "/shop-api", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query: "{__typename}" }), signal: AbortSignal.timeout(3000) });
      const w = container.logs(names.worker);
      if (r.status === 200 && /Vendure Worker is ready/.test((w.stdout || "") + (w.stderr || ""))) break;
    } catch {}
    if (Date.now() > deadline) throw new Error("readiness deadline exceeded");
    await sleep(500);
  }
  // rows as objects, via PostgreSQL json_agg
  const sql = (q) => {
    const out = container.exec(names.db, ["psql", "-U", PG_USER, "-d", PG_DB, "-At", "-c", `select coalesce(json_agg(t),'[]'::json) from (${q}) t`]).stdout.trim();
    return JSON.parse(out);
  };
  return { baseUrl, admin, sql, extra: { sql, admin } };
}

const cmd = process.argv[2];
if (cmd === "create") await create();
else if (cmd === "build") await build();
else if (cmd === "seed") await seed();
else if (cmd === "baseline") {
  const n = Number(process.argv[3]);
  const seed = prepareBaselineSeed(appDir, verifiedAssets);
  await runBaseline({
    project: "vendure",
    n,
    root: campaignRoot,
    keep: process.argv.includes("--keep"),
    buildStack: args => buildStack(args, seed),
    scenarios: (ctx) => vendureScenarios(ctx),
    meta: {
      ...seed.metadata,
      upstreamSha: campaign.upstream.sha,
      upstreamTag: campaign.upstream.stableTag,
      starter: campaign.starter.package,
      nodeVersion: NODE_VERSION,
      nodeImage: image,
      nodeImageId: imageId(image),
      platform: `${PLATFORM} (${process.env.XCAMP_PLATFORM ? "CI runner" : "Docker Desktop"})`,
      database: campaign.runtime.database,
      lockfileSha256: campaign.starter.lockfileSha256,
      scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
    },
  });
} else if (cmd === "compare") {
  const r = compareRuns(process.argv.slice(3).map((n) => path.join(campaignRoot, `baseline-${n}`)));
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs create | build | seed | baseline <n> [--keep] | compare <n> <m> ...");
  process.exitCode = 2;
}
