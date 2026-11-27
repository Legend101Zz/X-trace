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
import { dockerLogged, container, docker, net, PREFIX, PLATFORM } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, imageId, randomSecret } from "../../lib/baseline.mjs";
import { runInstrumented } from "../../lib/instr.mjs";
import {
  waitHttp,
  sleep,
  startPostgres,
  isHostMode,
  nodeBin,
  freePort,
  cleanLaunchEnv,
  runHostLogged,
  spawnHostProcess,
} from "../../lib/stack.mjs";
import { compareRuns } from "../../lib/harness.mjs";
import { sha256Hex } from "../../lib/canonical.mjs";
import { vendureScenarios } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "..", "campaign.json"), "utf8"));
const root = projectRoot("vendure");
const appDir = path.join(root, "app");
const NODE_VERSION = campaign.runtime.nodeImageVersion;
const image = IMAGE(NODE_VERSION);

const VENDURE_SPECS = {
  "auth-anonymous-admin-denied": {},
  "auth-invalid-login": { expectDb: true },
  "auth-admin-login": { expectDb: true },
  "product-create-read-db": { expectDb: true },
  "product-validation-invalid-language": {},
  "product-update-persists": { expectDb: true },
  "shop-order-flow": { expectDb: true },
  "worker-search-index-job": { expectDb: true },
  "concurrent-writes-and-reads": { expectDb: true },
  "product-delete-then-gone": { expectDb: true },
  "error-malformed-and-unknown": { allowRouteless: true },
};

const VENDURE_CANARY_REQUESTS = [
  { method: "POST", path: "/admin-api" },
  { method: "POST", path: "/shop-api" },
];

async function create() {
  fs.mkdirSync(root, { recursive: true });
  const log = path.join(root, "create.log");
  if (isHostMode()) {
    const code = await runHostLogged(
      "npm",
      ["exec", "--yes", `--package=@vendure/create@${campaign.starter.package.version}`, "--", "create", "app", "--ci", "--use-npm", "--db", "sqlite", "--log-level", "verbose"],
      log,
      {
        cwd: root,
        env: cleanLaunchEnv({
          npm_config_cache: path.join(root, ".xtrace-npm-cache"),
          npm_config_update_notifier: "false",
          CI: "true",
          DO_NOT_TRACK: "1",
          NODE_OPTIONS: "--max-old-space-size=6144",
        }),
      },
    );
    console.log("create (host) exit", code, "log", log);
    process.exitCode = code;
    return;
  }
  const code = await dockerLogged(
    [
      "run", "--rm", "--name", "xtrace-camp-node-vendure-create", "--platform", PLATFORM,
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
  if (isHostMode()) {
    const code = await runHostLogged(
      "sh",
      ["-c", "(npm ls pg >/dev/null 2>&1 || (npm uninstall better-sqlite3 && npm install --save-exact pg)) && npm run build:server && npm run build:worker && ls -l dist"],
      log,
      {
        cwd: appDir,
        env: cleanLaunchEnv({
          npm_config_cache: path.join(root, ".xtrace-npm-cache"),
          CI: "true",
          DO_NOT_TRACK: "1",
        }),
      },
    );
    console.log("build (host) exit", code, "log", log);
    process.exitCode = code;
    return;
  }
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-vendure-build", "--platform", PLATFORM, "-v", `${root}:/work`, "-w", "/work/app",
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
    let code;
    if (isHostMode()) {
      const pgPort = container.hostPort(names.db, 5432);
      code = await runHostLogged(
        nodeBin(),
        ["./dist/xtrace-seed-populate.cjs"],
        path.join(root, "seed.log"),
        {
          cwd: appDir,
          env: cleanLaunchEnv({
            DB_HOST: "127.0.0.1",
            DB_PORT: String(pgPort),
            DB_NAME: PG_DB,
            DB_USERNAME: PG_USER,
            DB_PASSWORD: password,
            DB_SCHEMA: "public",
            APP_ENV: "dev",
            PORT: "3000",
            CREATE_ASSETS_DIR: path.join(root, "create-assets"),
            DO_NOT_TRACK: "1",
          }),
          timeoutMs: 600000,
        },
      );
    } else {
      code = await dockerLogged(
        ["run", "--rm", "--name", "xtrace-camp-node-vendure-seed", "--platform", PLATFORM, "--network", names.net, "-v", `${root}:/work`, "-w", "/work/app",
         "-e", "DB_HOST=db", "-e", "DB_PORT=5432", "-e", `DB_NAME=${PG_DB}`, "-e", `DB_USERNAME=${PG_USER}`, "-e", `DB_PASSWORD=${password}`, "-e", "DB_SCHEMA=public",
         "-e", "APP_ENV=dev", "-e", "PORT=3000", "-e", "CREATE_ASSETS_DIR=/work/create-assets", "-e", "DO_NOT_TRACK=1", image, "node", "./dist/xtrace-seed-populate.cjs"],
        path.join(root, "seed.log"),
      );
    }
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

async function buildStack({ names, outDir, launchPrefix = null, extraEnv = {}, logFile = null }) {
  const env = readEnvFile();
  const admin = { identifier: env.SUPERADMIN_USERNAME, password: env.SUPERADMIN_PASSWORD };
  const dbPassword = randomSecret();
  await startPostgres({ netName: names.net, dbName: names.db, database: PG_DB, user: PG_USER, password: dbPassword });
  // reset = restore the pristine seed into the fresh (tmpfs) database
  docker(["exec", "-i", names.db, "psql", "-U", PG_USER, "-d", PG_DB, "-q", "-v", "ON_ERROR_STOP=1"], { input: fs.readFileSync(path.join(appDir, "seed.sql"), "utf8") });

  const sql = (q) => {
    const out = container.exec(names.db, ["psql", "-U", PG_USER, "-d", PG_DB, "-At", "-c", `select coalesce(json_agg(t),'[]'::json) from (${q}) t`]).stdout.trim();
    return JSON.parse(out);
  };

  if (isHostMode()) {
    const pgPort = container.hostPort(names.db, 5432);
    const appPort = await freePort();
    const baseEnv = {
      DB_HOST: "127.0.0.1",
      DB_PORT: String(pgPort),
      DB_NAME: PG_DB,
      DB_USERNAME: PG_USER,
      DB_PASSWORD: dbPassword,
      DB_SCHEMA: "public",
      PORT: String(appPort),
      APP_ENV: "dev",
      DO_NOT_TRACK: "1",
      VENDURE_DISABLE_TELEMETRY: "1",
    };
    const workerLog = path.join(outDir, "worker.log");
    fs.writeFileSync(workerLog, "", { mode: 0o600 });
    const appLog = logFile || path.join(outDir, "app.log");
    // Stock worker runs uninstrumented alongside the (optionally instrumented) server.
    const workerProc = spawnHostProcess(nodeBin(), ["./dist/index-worker.js"], workerLog, {
      cwd: appDir,
      env: cleanLaunchEnv(baseEnv),
    });
    const serverCmd = launchPrefix ? launchPrefix[0] : nodeBin();
    const serverArgs = launchPrefix
      ? [...launchPrefix.slice(1), nodeBin(), "./dist/index.js"]
      : ["./dist/index.js"];
    const appProc = spawnHostProcess(serverCmd, serverArgs, appLog, {
      cwd: appDir,
      env: cleanLaunchEnv({ ...baseEnv, ...extraEnv }),
    });
    const baseUrl = `http://127.0.0.1:${appPort}`;
    const deadline = Date.now() + 300000;
    try {
      for (;;) {
        if (!appProc.isAlive()) throw new Error("app host process exited before readiness");
        if (!workerProc.isAlive()) throw new Error("worker host process exited before readiness");
        try {
          const r = await fetch(baseUrl + "/shop-api", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ query: "{__typename}" }),
            signal: AbortSignal.timeout(3000),
          });
          const w = fs.readFileSync(workerLog, "utf8");
          if (r.status === 200 && /Vendure Worker is ready/.test(w)) break;
        } catch {}
        if (Date.now() > deadline) throw new Error("readiness deadline exceeded");
        await sleep(500);
      }
    } catch (err) {
      await appProc.stop(15000);
      await workerProc.stop(15000);
      throw err;
    }
    return {
      baseUrl,
      admin,
      sql,
      extra: { sql, admin },
      stopHost: (ms) => appProc.stop(ms),
      stopWorker: (ms) => workerProc.stop(ms),
    };
  }

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
  return { baseUrl, admin, sql, extra: { sql, admin } };
}

function commonMeta() {
  return {
    upstreamSha: campaign.upstream.sha,
    upstreamTag: campaign.upstream.stableTag,
    starter: campaign.starter.package,
    appMode: isHostMode() ? "host" : "docker",
    nodeVersion: isHostMode() ? process.version : NODE_VERSION,
    ...(isHostMode() ? {} : { nodeImage: image, nodeImageId: imageId(image) }),
    platform: `${PLATFORM} (${process.env.XCAMP_PLATFORM ? "CI runner" : "Docker Desktop"})`,
    database: campaign.runtime.database,
    lockfileSha256: sha256Hex(fs.readFileSync(path.join(appDir, "package-lock.json"))),
    seedSha256: sha256Hex(fs.readFileSync(path.join(appDir, "seed.sql"))),
    scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
  };
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
    meta: commonMeta(),
  });
} else if (cmd === "instrumented") {
  if (!isHostMode()) throw new Error("vendure instrumented requires XCAMP_APP_MODE=host");
  await runInstrumented({
    project: "vendure",
    root,
    projectDir: process.env.XCAMP_PROJECT_DIR || appDir,
    buildStack,
    scenarios: (ctx) => vendureScenarios(ctx),
    scenarioSpecs: VENDURE_SPECS,
    canaryRequests: VENDURE_CANARY_REQUESTS,
    meta: commonMeta(),
  });
} else if (cmd === "compare") {
  const r = compareRuns(process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`)));
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs create | build | seed | baseline <n> [--keep] | instrumented | compare <n> <m> ...");
  process.exitCode = 2;
}
