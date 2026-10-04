#!/usr/bin/env node
// Vendure v3.7.3 campaign harness (preparation lane; baseline only).
//   node run.mjs create             official `@vendure/create@3.7.3 --ci --db sqlite` in Docker (Node 24)
//   node run.mjs build              compile server + worker (vendure build server|worker), snapshot seed.sqlite
//   node run.mjs baseline <n>       reset SQLite from seed, start server + worker containers, run scenarios
//   node run.mjs compare <n> <m>..  compare semantic fingerprints
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dockerLogged, container, docker } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { runBaseline, imageId } from "../../lib/baseline.mjs";
import { waitHttp, sleep } from "../../lib/stack.mjs";
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

async function build() {
  const log = path.join(root, "build.log");
  const code = await dockerLogged(
    ["run", "--rm", "--name", "xtrace-camp-node-vendure-build", "--platform", "linux/arm64", "-v", `${root}:/work`, "-w", "/work/app",
     "-e", "npm_config_cache=/work/.xtrace-npm-cache", "-e", "CI=true", "-e", "DO_NOT_TRACK=1", image,
     "sh", "-c", "npm run build:server && npm run build:worker && cp -n vendure.sqlite seed.sqlite && ls -l dist seed.sqlite"],
    log,
  );
  if (code === 0) fs.copyFileSync(path.join(here, "xtrace-index-inprocess.cjs"), path.join(appDir, "dist", "xtrace-index-inprocess.cjs"));
  console.log("build exit", code, "log", log);
  process.exitCode = code;
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
  const common = [
    "--network", names.net,
    "-v", `${root}:/work`,
    "-w", "/work/app",
    "-e", "PORT=3000", "-e", "APP_ENV=dev", "-e", "DO_NOT_TRACK=1", "-e", "VENDURE_DISABLE_TELEMETRY=1",
    image,
  ];
  // Reset: pristine seed copied to container-local storage (fast local locking for SQLite). Single process: server + in-process job queue (see xtrace-index-inprocess.cjs).
  // /work/app/vendure.sqlite becomes a symlink to it, so vendure-config.ts is used unmodified.
  const script =
    "set -e; mkdir -p /tmp/xtrace-data && cp /work/app/seed.sqlite /tmp/xtrace-data/vendure.sqlite && " +
    "ln -sfn /tmp/xtrace-data/vendure.sqlite /work/app/vendure.sqlite && rm -rf /work/app/static/email/test-emails; " +
    "exec node ./dist/xtrace-index-inprocess.cjs";
  container.runDetached(names.app, ["-p", "127.0.0.1::3000", ...common.slice(0, -1), image, "sh", "-c", script]);
  const port = container.hostPort(names.app, 3000);
  const baseUrl = `http://127.0.0.1:${port}`;
  // Readiness: shop-api responds to a trivial typename query (necessary, never sufficient).
  const deadline = Date.now() + 300000;
  for (;;) {
    if (!container.running(names.app)) throw new Error("app container exited before readiness");
    try {
      const r = await fetch(baseUrl + "/shop-api", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query: "{__typename}" }), signal: AbortSignal.timeout(3000) });
      if (r.status === 200) break;
    } catch {}
    if (Date.now() > deadline) throw new Error("readiness deadline exceeded");
    await sleep(500);
  }
  const sql = (q) => {
    const script = "const D=require('better-sqlite3');const db=new D('/tmp/xtrace-data/vendure.sqlite',{readonly:true});console.log(JSON.stringify(db.prepare(process.argv[1]).all()))";
    const out = docker(["exec", "-w", "/work/app", names.app, "node", "-e", script, q]).stdout.trim();
    return JSON.parse(out);
  };
  return { baseUrl, admin, sql, extra: { sql, admin } };
}

const cmd = process.argv[2];
if (cmd === "create") await create();
else if (cmd === "build") await build();
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
      seedSha256: sha256Hex(fs.readFileSync(path.join(appDir, "seed.sqlite"))),
      scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))),
    },
  });
} else if (cmd === "compare") {
  const r = compareRuns(process.argv.slice(3).map((n) => path.join(root, `baseline-${n}`)));
  console.log(JSON.stringify(r, null, 2));
  process.exitCode = r.stable ? 0 : 1;
} else {
  console.error("usage: run.mjs create | build | baseline <n> [--keep] | compare <n> <m> ...");
  process.exitCode = 2;
}
