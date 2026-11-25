#!/usr/bin/env node
// The hosted ordinary/installed-public.mjs wrapper keeps this driver’s streams private.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { docker, PREFIX, PLATFORM } from "../../lib/docker.mjs";
import { projectRoot, IMAGE } from "../../lib/paths.mjs";
import { randomSecret } from "../../lib/baseline.mjs";
import { POSTGRES_IMAGE, sleep } from "../../lib/stack.mjs";
import { runScenarios } from "../../lib/harness.mjs";
import { sha256Hex, canonicalJson } from "../../lib/canonical.mjs";
import { workload } from "./scenarios.mjs";
import { admitNetwork, admitMembers, routeInventory, appTransport, awaitPing } from "./isolated-runtime.mjs";
import { boundedSummary, compareWorkload } from "./installed-judge.mjs";
import { requireFact } from "./installed-readback.mjs";
import { withoutProgressOutput } from "./installed-output.mjs";
import { createOwned, removeOwned } from "./installed-ownership.mjs";
import { ORDINARY_IDS, ordinaryScenarios } from "./installed-ordinary-scope.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../../../..");
const campaign = JSON.parse(fs.readFileSync(path.join(here, "../campaign.json")));
process.umask(0o077);

function privateDirectory(directory) {
  const absolute = path.resolve(directory);
  for (let p = absolute;; p = path.dirname(p)) {
    const st = fs.lstatSync(p);
    requireFact(st.isDirectory() && !st.isSymbolicLink() && [0, process.getuid()].includes(st.uid)
      && !(st.mode & 0o022), "private_ancestor");
    if (p === path.dirname(p)) break;
  }
  const st = fs.statSync(absolute);
  requireFact(st.uid === process.getuid() && (st.mode & 0o777) === 0o700, "private_root_mode");
  return absolute;
}

function git(source, args) {
  const result = spawnSync("git", ["-C", source, ...args], { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  requireFact(result.status === 0, "upstream_git"); return result.stdout;
}

function treeInventory(directory) {
  const rows = [];
  function visit(current, rel) {
    const st = fs.lstatSync(current);
    if (st.isSymbolicLink()) rows.push([rel, "link", fs.readlinkSync(current)]);
    else if (st.isDirectory()) for (const name of fs.readdirSync(current).sort()) visit(path.join(current, name), path.posix.join(rel, name));
    else { requireFact(st.isFile(), "build_input_type"); rows.push([rel, st.size, sha256Hex(fs.readFileSync(current))]); }
  }
  visit(directory, "."); return rows;
}

function sourceIdentity(upstream) {
  requireFact(git(upstream, ["rev-parse", "HEAD"]).trim() === campaign.upstream.sha, "upstream_revision");
  requireFact(git(upstream, ["status", "--porcelain", "--untracked-files=no"]).trim() === "", "upstream_tracked_dirty");
  const license = sha256Hex(fs.readFileSync(path.join(upstream, campaign.license.file)));
  const lockfile = sha256Hex(fs.readFileSync(path.join(upstream, campaign.packageManager.lockfile)));
  requireFact(license === campaign.license.sha256 && lockfile === campaign.packageManager.lockfileSha256, "upstream_pins");
  const tracked = git(upstream, ["ls-files", "-z"]).split("\0").filter(Boolean);
  const inventory = tracked.map((name) => {
    const file = path.join(upstream, name);
    return [name, fs.lstatSync(file).isSymbolicLink() ? fs.readlinkSync(file) : sha256Hex(fs.readFileSync(file))];
  });
  const manifests = tracked.filter((name) => path.basename(name) === "package.json");
  const builds = manifests.map((name) => path.join(path.dirname(name), "dist"))
    .filter((name) => fs.existsSync(path.join(upstream, name)))
    .map((name) => [name, treeInventory(path.join(upstream, name))]);
  const dependencies = manifests.map((name) => path.join(path.dirname(name), "node_modules"))
    .filter((name) => fs.existsSync(path.join(upstream, name)))
    .map((name) => [name, treeInventory(path.join(upstream, name))]);
  requireFact(fs.existsSync(path.join(upstream, "api/dist/cli/run.js")) && builds.length > 0, "built_application_missing");
  requireFact(dependencies.length > 0, "installed_application_dependencies_missing");
  return { upstreamSha: campaign.upstream.sha, licenseSha256: license, lockfileSha256: lockfile,
    trackedSha256: sha256Hex(canonicalJson(inventory)), builtSha256: sha256Hex(canonicalJson(builds)),
    dependenciesSha256: sha256Hex(canonicalJson(dependencies)) };
}

function imageIdentity(reference) {
  const rows = JSON.parse(docker(["image", "inspect", reference]).stdout);
  requireFact(rows.length === 1 && /^sha256:[a-f0-9]{64}$/.test(rows[0].Id), "image_identity");
  return { id: rows[0].Id, os: rows[0].Os, architecture: rows[0].Architecture, repoDigests: rows[0].RepoDigests || [],
    labels: rows[0].Config?.Labels || {} };
}

function nodeIdentity(image) {
  const source = "const fs=require('node:fs'),c=require('node:crypto');console.log(JSON.stringify({version:process.version,sha256:c.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex')}))";
  const result = docker(["run", "--rm", "--network", "none", "--read-only", "--platform", PLATFORM, image.id, "node", "-e", source]);
  const identity = JSON.parse(result.stdout);
  requireFact(identity.version === "v" + campaign.runtime.nodeImageVersion && /^[a-f0-9]{64}$/.test(identity.sha256 || ""), "node_binary_identity");
  return identity;
}

function running(id) {
  return !!id && docker(["inspect", "-f", "{{.State.Running}}", id], { allowFail: true }).stdout.trim() === "true";
}
async function readyDatabase(id, user, database) {
  const deadline = Date.now() + 90000;
  for (;;) {
    const exec = (args) => docker(["exec", id, ...args], { allowFail: true });
    if (exec(["pg_isready", "-U", user, "-d", database]).status === 0
      && exec(["psql", "-U", user, "-d", database, "-Atc", "select 1"]).status === 0) {
      await sleep(1500);
      if (exec(["psql", "-U", user, "-d", database, "-Atc", "select 1"]).status === 0) return;
    }
    requireFact(Date.now() <= deadline, "postgres_readiness_deadline");
    await sleep(500);
  }
}

async function leg({ mode, root, names, upstream, archive, archiveSha256, candidateSha, packagePlatform, runtime, databaseImage, runtimeNode }) {
  const outDir = path.join(root, mode); fs.mkdirSync(outDir, { mode: 0o700 });
  const dataDir = path.join(outDir, "data"); fs.mkdirSync(dataDir, { mode: 0o700 });
  const stages = []; let summary = null;
  const admin = { email: "xtrace-baseline@example.com", password: randomSecret() };
  const dbPassword = randomSecret(), database = "directus", dbUser = "xtrace";
  const appEnv = { HOST: "0.0.0.0", PORT: "8055", DB_CLIENT: "pg", DB_PORT: "5432",
    DB_DATABASE: database, DB_USER: dbUser, DB_PASSWORD: dbPassword, SECRET: randomSecret(32),
    ADMIN_EMAIL: admin.email, ADMIN_PASSWORD: admin.password, TELEMETRY: "false", AI_TELEMETRY_ENABLED: "false",
    SERVE_APP: "false", NODE_ENV: "production", LOG_LEVEL: "warn", EXTENSIONS_PATH: "/x/extensions", STORAGE_LOCAL_ROOT: "/x/uploads", DO_NOT_TRACK: "1" };
  // Refuse collisions before using the shared lifecycle helpers, which otherwise
  // intentionally replace objects in their own preparation namespace.
  requireFact(docker(["network", "inspect", names.net], { allowFail: true }).status !== 0, "network_already_exists");
  for (const key of ["app", "db"]) requireFact(docker(["container", "inspect", names[key]], { allowFail: true }).status !== 0, "container_already_exists");
  const owned = [], ids = {}; let networkId = null, networkAttempted = false;
  try {
    networkAttempted = true;
    networkId = docker(["network", "create", "--driver", "bridge", "--internal", "--ipv6=false",
      "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", names.net]).stdout.trim();
    requireFact(/^[a-f0-9]{64}$/.test(networkId), "network_identity");
    const network = () => JSON.parse(docker(["network", "inspect", networkId]).stdout)[0];
    admitNetwork(network(), networkId, names.net);
    const isolated = ["--network", networkId, "--dns", "127.0.0.1", "--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--entrypoint", "tail"];
    ids.db = createOwned(docker, owned, names.db, [...isolated, "--tmpfs", "/var/lib/postgresql",
      "-e", `POSTGRES_USER=${dbUser}`, "-e", `POSTGRES_PASSWORD=${dbPassword}`, "-e", `POSTGRES_DB=${database}`,
      databaseImage.id, "-f", "/dev/null"], PLATFORM);
    ids.app = createOwned(docker, owned, names.app, [...isolated,
      "--user", `${process.getuid()}:${process.getgid()}`, "--tmpfs", `/x:mode=0700,uid=${process.getuid()},gid=${process.getgid()}`,
      "-v", `${upstream}:/x/project`, "-v", `${outDir}:/x/evidence`, "-v", `${archive}:/x/archive.tar.gz:ro`,
      "-v", `${dataDir}:/x/data`, "-v", `${repo}:/repo:ro`, "-w", "/x/project", runtime.id, "-f", "/dev/null"], PLATFORM);
    const objects = JSON.parse(docker(["container", "inspect", ids.db, ids.app]).stdout);
    const topology = network();
    admitNetwork(topology, networkId, names.net);
    const dbIp = admitMembers(topology, objects, ids, { app: runtime.id, db: databaseImage.id });
    for (const id of [ids.db, ids.app]) {
      const routes = file => docker(["exec", id, "cat", "/proc/net/" + file]).stdout;
      routeInventory(routes("route"), routes("ipv6_route"), topology.IPAM.Config[0].Subnet);
    }
    stages.push({ name: "network_admitted", status: "passed" });
    appEnv.DB_HOST = dbIp;
    fs.writeFileSync(path.join(outDir, "config.json"), JSON.stringify({ mode, appEnv, archiveSha256, candidateSha,
      packagePlatform, nodeBinarySha256: runtimeNode.sha256 }), { mode: 0o600, flag: "wx" });
    docker(["exec", "-d", ids.db, "docker-entrypoint.sh", "postgres", "-c", "fsync=off", "-c", "log_statement=none"]);
    await readyDatabase(ids.db, dbUser, database);
    stages.push({ name: "database_readiness", status: "passed" });
    docker(["exec", "-d", ids.app, "node", "/repo/campaigns/node/directus/ordinary/installed-driver.mjs"]);
    await awaitPing(ids.app, () => running(ids.app));
    stages.push({ name: "application_readiness", status: "passed" });
    const sql = text => docker(["exec", ids.db, "psql", "-U", dbUser, "-d", database,
      "-At", "-F", "|", "-v", "ON_ERROR_STOP=1", "-c", text]).stdout.trim();
    const rows = () => {
      const result = sql("select name, quantity from xtrace_campaign_items order by name, quantity");
      return result ? result.split("\n").map(line => line.split("|")) : [];
    };
    const tableCount = () => Number(sql("select count(*) from xtrace_campaign_items"));
    const scenarios = ordinaryScenarios(workload({ admin, rows, tableCount }));
    summary = await withoutProgressOutput(() => runScenarios({ project: "directus", baseUrl: "", outDir,
      scenarios, transport: appTransport(ids.app) }));
    // Correct the inherited preparation label without changing any scenario or
    // fingerprint. These files are private development evidence, not receipts.
    summary.kind = mode === "baseline" ? "uninstrumented_baseline_only" : "installed_instrumented_development";
    fs.writeFileSync(path.join(outDir, "scenarios.json"), JSON.stringify(summary, null, 2) + "\n", { mode: 0o600 });
    stages.push({ name: "scenario_workload", status: summary.result === "passed" ? "passed" : "failed" });
  } catch { stages.push({ name: "leg", status: "failed" }); }
  finally {
    try {
      if (running(ids.app)) {
        const result = docker(["exec", ids.app, "node", "/repo/campaigns/node/directus/ordinary/installed-driver.mjs", "finish"], { allowFail: true });
        stages.push({ name: "driver_finish", status: result.status === 0 ? "passed" : "failed" });
      } else stages.push({ name: "driver_finish", status: "unreached" });
    } catch { stages.push({ name: "driver_finish", status: "failed" }); }
    let cleanupPassed = !owned.uncertain && (!networkAttempted || networkId !== null && /^[a-f0-9]{64}$/.test(networkId));
    for (const key of ["app", "db"]) if (ids[key]) {
      try {
        const log = docker(["logs", ids[key]], { allowFail: true });
        fs.writeFileSync(path.join(outDir, key + ".container.log"), log.stdout + log.stderr, { mode: 0o600 });
      } catch { cleanupPassed = false; }
    }
    for (const id of [...owned].reverse()) cleanupPassed = removeOwned(docker, "container", id) && cleanupPassed;
    if (networkId && /^[a-f0-9]{64}$/.test(networkId)) cleanupPassed = removeOwned(docker, "network", networkId) && cleanupPassed;
    stages.push({ name: "cleanup", status: cleanupPassed ? "passed" : "failed" });
    const expected = ["network_admitted", "database_readiness",
      "application_readiness", "scenario_workload"];
    for (const name of expected)
      if (!stages.some((s) => s.name === name)) stages.push({ name, status: "unreached" });
    fs.writeFileSync(path.join(outDir, "stages.json"), JSON.stringify(stages), { mode: 0o600 });
  }
  return { summary, stages, outDir };
}

async function main() {
  requireFact(process.platform === "linux" && typeof process.getuid === "function" && process.argv.length === 3, "hosted_linux_config_required");
  requireFact(process.env.DOCKER_HOST === "unix:///var/run/docker.sock" && !process.env.DOCKER_CONTEXT
    && !process.env.XTRACE_CAMP_DOCKER_HOST && !process.env.XTRACE_CAMP_DOCKER_CONFIG, "local_docker_endpoint");
  const configFile = path.resolve(process.argv[2]);
  requireFact(fs.lstatSync(configFile).isFile() && (fs.statSync(configFile).mode & 0o077) === 0, "private_config_required");
  const config = JSON.parse(fs.readFileSync(configFile));
  requireFact(process.env.XTRACE_CAMP_NODE_ROOT && /^[a-z0-9-]{1,24}$/.test(config.runId || "")
    && /^[a-f0-9]{40}$/.test(config.candidateSha || "") && /^[a-f0-9]{64}$/.test(config.archiveSha256 || "")
    && /^sha256:[a-f0-9]{64}$/.test(config.runtimeImageId || ""), "config_identity");
  const project = privateDirectory(projectRoot("directus"));
  const upstream = path.join(project, "upstream");
  requireFact(!fs.existsSync(path.join(upstream, ".xtrace")), "fresh_project_pointer_required");
  const archive = path.resolve(config.archive);
  requireFact(fs.lstatSync(archive).isFile() && sha256Hex(fs.readFileSync(archive)) === config.archiveSha256, "archive_digest");
  requireFact(POSTGRES_IMAGE === "postgres@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db", "database_pin_override");
  const preparationRuntime = imageIdentity(IMAGE(campaign.runtime.nodeImageVersion));
  const runtime = imageIdentity(config.runtimeImageId);
  requireFact(runtime.id === preparationRuntime.id, "compatible_runtime_provenance");
  const database = imageIdentity(POSTGRES_IMAGE);
  requireFact(runtime.os === "linux" && `${runtime.os}/${runtime.architecture}` === PLATFORM, "runtime_platform");
  requireFact(database.os === "linux" && database.architecture === runtime.architecture, "database_platform");
  const preparationNode = nodeIdentity(preparationRuntime), runtimeNode = nodeIdentity(runtime);
  requireFact(canonicalJson(preparationNode) === canonicalJson(runtimeNode), "same_node_toolchain_bytes");
  const packagePlatform = runtime.architecture === "amd64" ? "linux-x86_64" : runtime.architecture === "arm64" ? "linux-aarch64-dev" : null;
  requireFact(packagePlatform, "unsupported_package_platform");
  const identity = sourceIdentity(upstream);
  const root = path.join(project, "installed-" + config.runId); fs.mkdirSync(root, { mode: 0o700 });
  const metadata = { ...identity, preparationRuntime, runtime, runtimeNode, database, candidateSha: config.candidateSha, archiveSha256: config.archiveSha256,
    runtimeRecipeSha256: sha256Hex(fs.readFileSync(path.join(here, "installed-ordinary-runtime.Dockerfile"))),
    scenarioHarnessSha256: sha256Hex(fs.readFileSync(path.join(here, "scenarios.mjs"))) };
  fs.writeFileSync(path.join(root, "identity.json"), JSON.stringify(metadata, null, 2), { mode: 0o600 });
  let baseline, instrumented;
  const stages = [];
  try {
    for (const mode of ["baseline", "instrumented"]) {
      requireFact(canonicalJson(sourceIdentity(upstream)) === canonicalJson(identity), "same_run_input_drift");
      const prefix = `${PREFIX}directus-${config.runId}-${mode}`;
      const result = await leg({ mode, root, upstream, archive, archiveSha256: config.archiveSha256,
        candidateSha: config.candidateSha, packagePlatform, runtime, databaseImage: database, runtimeNode,
        names: { net: prefix + "-net", db: prefix + "-db", app: prefix + "-app" } });
      for (const s of result.stages) stages.push({ ...s, name: mode + ":" + s.name });
      if (mode === "baseline") baseline = result; else instrumented = result;
    }
    requireFact(canonicalJson(sourceIdentity(upstream)) === canonicalJson(identity), "final_input_drift");
    stages.push({ name: "same_run_inputs", status: "passed" });
  } catch { stages.push({ name: "same_run_inputs", status: "failed" }); }
  const load = (name) => { try { return JSON.parse(fs.readFileSync(path.join(root, "instrumented", name))); } catch { return null; } };
  const driver = load("driver.json");
  for (const s of driver?.stages || []) stages.push({ ...s, name: "installed:" + s.name });
  try {
    const baselineDriver = JSON.parse(fs.readFileSync(path.join(root, "baseline", "driver.json")));
    for (const s of baselineDriver.stages) stages.push({ ...s, name: "baseline-installed:" + s.name });
    requireFact(canonicalJson(baselineDriver.identity) === canonicalJson(driver?.identity), "same_installed_payload");
    stages.push({ name: "same_installed_payload", status: "passed" });
  } catch { stages.push({ name: "same_installed_payload", status: "failed" }); }
  const cli = load("cli-readback.json"), api = load("api-readback.json");
  const workload = compareWorkload(baseline?.summary, instrumented?.summary, ORDINARY_IDS);
  const report = boundedSummary({ stages, workload, readback: cli && api ? { cli, api } : null, analyzer: driver?.analyzer });
  fs.writeFileSync(path.join(root, "summary.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  // Only fixed schema, enum, count and boolean fields cross the private boundary.
  console.log(JSON.stringify(report));
  process.exitCode = report.result === "passed" ? 0 : 1;
}

main().catch(() => { console.log(JSON.stringify({ kind: "directus_installed_ordinary_development", releaseAcceptance: false, result: "failed", phase: "preflight_or_evidence_write" })); process.exitCode = 1; });
