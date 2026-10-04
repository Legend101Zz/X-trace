#!/usr/bin/env node
// Vendure v3.7.3 campaign harness (preparation lane; baseline only).
//   node run.mjs create             official `@vendure/create@3.7.3 --ci --db sqlite` in Docker (Node 24)
//   node run.mjs build              adapt config to PostgreSQL (DB_* env), install pg, compile server + worker
//   node run.mjs seed               populate sample data into a throwaway PostgreSQL and dump seed.sql
//   node run.mjs baseline <n>       fresh PostgreSQL restored from seed.sql, stock server + separate stock worker, run scenarios
//   node run.mjs compare <n> <m>..  compare semantic fingerprints
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dockerLogged, container, docker, net, PREFIX } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, imageId, randomSecret } from "../../lib/baseline.mjs";
import { waitHttp, sleep, startPostgres } from "../../lib/stack.mjs";
import { compareRuns } from "../../lib/harness.mjs";
import { sha256Hex } from "../../lib/canonical.mjs";
import { vendureScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const root = projectRoot("vendure");
const appDir = path.join(root, "app");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);

async function create() {
  fs.mkdirSync(root, { recursive: true });
  const log = path.join(root, "create.log");
  const code = await dockerLogged(
    [
      "run", "--rm", "--name", "xtrace-camp-node-vendure-create", "--platform", "linux/arm64",
      "-v", `${root}:/work`,
      "-e", "npm_config_cache=/work/.xtrace-npm-cache", "-e", "npm_config_update_notifier=false",
      "-e", "CI=true", "-e", "DO_NOT_TRACK=1", "-e", "NODE_OPTIONS=--max-old-space-size=6144",
      image, "sh", "-c",
      `cd /work && npm exec --yes --package=@vendure/create@${campaign.starter.package.version} -- create app --ci --use-npm --db sqlite --log-level verbose`,
    ],
    log,
  );
  console.log("create exit", code, "log", log);
  process.exitCode = code;
}

const PG_DB = "vendure";
const PG_USER = "xtrace";

// Config-only adaptation SQLite -> PostgreSQL: the exact dbConnectionOptions the pinned create
// template (templates/vendure-config.hbs) renders for `--db postgres`, driven by DB_* env.
function patchConfigForPostgres() {
  const file = path.join(appDir, "src", "vendure-config.ts");
  let src = fs.readFileSync(file, "utf8");
  if (src.includes("process.env.DB_HOST")) return "config already adapted";
  fs.mkdirSync(path.join(root, "config-original"), { recursive: true });
  fs.writeFileSync(path.join(root, "config-original", "vendure-config.sqlite.ts"), src);
  const before = sha256Hex(src);
  src = src
    .replace("type: 'better-sqlite3',", "type: 'postgres',")
    .replace("database: path.join(__dirname, '../vendure.sqlite'),",
      "database: process.env.DB_NAME,\n        schema: process.env.DB_SCHEMA,\n        host: process.env.DB_HOST,\n        port: +process.env.DB_PORT,\n        username: process.env.DB_USERNAME,\n        password: process.env.DB_PASSWORD,");
  if (!src.includes("process.env.DB_HOST") || !src.includes("type: 'postgres'")) throw new Error("config patch did not apply");
  fs.writeFileSync(file, src);
  // environment.d.ts: add the DB_* declarations the postgres template renders
  const envd = path.join(appDir, "src", "environment.d.ts");
  let e = fs.readFileSync(envd, "utf8");
  if (!e.includes("DB_HOST")) {
    e = e.replace("CORS_ORIGINS?: string;\n", "CORS_ORIGINS?: string;\n            DB_HOST: string;\n            DB_PORT: number;\n            DB_NAME: string;\n            DB_USERNAME: string;\n            DB_PASSWORD: string;\n            DB_SCHEMA: string;\n");
    fs.writeFileSync(envd, e);
  }
  return `${before} -> ${sha256Hex(src)}`;
}

async function build() {
  const log = path.join(root, "build.log");
  console.log("config:", patchConfigForPostgres());
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-vendure-build", "--platform", "linux/arm64", "-v", `${root}:/work`, "-w", "/work/app",
     "-e", "npm_config_cache=/work/.xtrace-npm-cache", "-e", "CI=true", "-e", "DO_NOT_TRACK=1", image,
     "sh", "-c", "(npm ls pg >/dev/null 2>&1 || (npm uninstall better-sqlite3 && npm install --save-exact pg)) && npm run build:server && npm run build:worker && ls -l dist"],
    log,
  );
  console.log("build exit", code, "log", log);
  process.exitCode = code;
}

// Populate sample data into a throwaway PostgreSQL once and dump it as the reset seed (seed.sql).
async function seed() {
  const tag = "seed";
  const names = { net: `${PREFIX}vendure-${tag}-net`, db: `${PREFIX}vendure-${tag}-db` };
  fs.copyFileSync(path.join(here, "seed-populate.cjs"), path.join(appDir, "dist", "xtrace-seed-populate.cjs"));
  const password = randomSecret();
  try {
    net.create(names.net);
    await startPostgres({ netName: names.net, dbName: names.db, database: PG_DB, user: PG_USER, password });
    const code = await dockerLogged(
      ["run", "--rm", "--name", "xtrace-camp-node-vendure-seed", "--platform", "linux/arm64", "--network", names.net, "-v", `${root}:/work`, "-w", "/work/app",
       "-e", "DB_HOST=db", "-e", "DB_PORT=5432", "-e", `DB_NAME=${PG_DB}`, "-e", `DB_USERNAME=${PG_USER}`, "-e", `DB_PASSWORD=${password}`, "-e", "DB_SCHEMA=public",
       "-e", "APP_ENV=dev", "-e", "PORT=3000", "-e", "CREATE_ASSETS_DIR=/work/create-assets", "-e", "DO_NOT_TRACK=1", image, "node", "./dist/xtrace-seed-populate.cjs"],
      path.join(root, "seed.log"),
    );
    if (code !== 0) throw new Error("populate failed; see seed.log");
    const dump = docker(["exec", names.db, "pg_dump", "-U", PG_USER, "-d", PG_DB, "--no-owner", "--no-acl"]).stdout;
    fs.writeFileSync(path.join(appDir, "seed.sql"), dump);
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

async function buildStack({ names }) {
  const env = readEnvFile();
  const admin = { identifier: env.SUPERADMIN_USERNAME, password: env.SUPERADMIN_PASSWORD };
  const dbPassword = randomSecret();
  await startPostgres({ netName: names.net, dbName: names.db, database: PG_DB, user: PG_USER, password: dbPassword });
  // reset = restore the pristine seed into the fresh (tmpfs) database
  docker(["exec", "-i", names.db, "psql", "-U", PG_USER, "-d", PG_DB, "-q", "-v", "ON_ERROR_STOP=1"], { input: fs.readFileSync(path.join(appDir, "seed.sql"), "utf8") });
  const common = [
    "--network", names.net, "-v", `${root}:/work`, "-w", "/work/app",
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
  await runBaseline({
    project: "vendure",
    n,
    root,
    keep: process.argv.includes("--keep"),
    buildStack,
    scenarios: (ctx) => vendureScenarios(ctx),
    meta: {
      upstreamSha: campaign.upstream.sha,
      upstreamTag: campaign.upstream.stableTag,
      starter: campaign.starter.package,
      nodeVersion: NODE_VERSION,
      nodeImage: image,
      nodeImageId: imageId(image),
      platform: "linux/arm64 (Docker Desktop)",
      database: campaign.runtime.database,
      lockfileSha256: sha256Hex(fs.readFileSync(path.join(appDir, "package-lock.json"))),
      seedSha256: sha256Hex(fs.readFileSync(path.join(appDir, "seed.sql"))),
      scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
    },
  });
} else if (cmd === "compare") {
  const r = compareRuns(process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`)));
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs create | build | seed | baseline <n> [--keep] | compare <n> <m> ...");
  process.exitCode = 2;
}
