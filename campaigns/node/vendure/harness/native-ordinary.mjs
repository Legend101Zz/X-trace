// One hosted lifecycle. The initial qualification selects only the installed launch.
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { docker, PLATFORM, PREFIX } from "../../lib/docker.mjs";
import { POSTGRES_IMAGE, startPostgres } from "../../lib/stack.mjs";
import { OwnedServicesFixture } from "./owned-services.mjs";
import { prepareBaselineSeed } from "./preparation.mjs";
import { installVendurePackage } from "./installed-package.mjs";
import { readPreflightObservation, readPreflightReceipt } from "./installed-preflight-observation.mjs";
import { incompleteNotice, launch, observeStartup, stop } from "./native-process.mjs";
import { prepareNativeStarter } from "./native-starter.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureRoot = path.resolve(here, "../../../..");
const packageSource = "3bc74469d586ab1cb421c85e98eff8e3a9d515a9";
const packageTree = "1a6d23aaec700b8d39871304fc7e7a51d2e26d79";
const need = ok => { if (!ok) throw new Error("native Vendure stage incomplete"); };
const fresh = dir => { fs.mkdirSync(dir, { mode: 0o700 }); return dir; };

// No URLs, command lines, application objects or installation identities leave private storage.
async function main() {
  need(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
    process.platform === "linux" && process.arch === "x64" && process.versions.node === "24.21.0" &&
    PLATFORM === "linux/amd64" && POSTGRES_IMAGE === "postgres@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db" &&
    process.env.XTRACE_CAMP_DOCKER_HOST === "unix:///var/run/docker.sock" && !process.env.DOCKER_CONTEXT);
  const [leg] = process.argv.slice(2);
  need(process.argv.length === 3 && ["direct", "installed"].includes(leg));
  process.umask(0o077);
  // Each checkout keeps its own history and tests. Only productRoot supplies
  // the archive and verifier; only fixtureRoot supplies the Vendure driver.
  const workspace = fs.realpathSync(process.env.GITHUB_WORKSPACE);
  const productRoot = fs.realpathSync(path.join(workspace, "product"));
  need(productRoot === path.join(workspace, "product") &&
    fixtureRoot === fs.realpathSync(path.join(workspace, "fixture")) &&
    fixtureRoot === path.join(workspace, "fixture") && productRoot !== fixtureRoot &&
    process.env.PRODUCT === packageSource && /^[0-9a-f]{40}$/.test(process.env.FIXTURE || "") &&
    /^[0-9a-f]{40}$/.test(process.env.FIXTURE_TREE || "") && process.env.FIXTURE !== packageSource);
  for (const [root, sha, tree] of [[productRoot, packageSource, packageTree],
      [fixtureRoot, process.env.FIXTURE, process.env.FIXTURE_TREE]]) {
    const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    need(git("rev-parse", "--show-toplevel") === root && git("rev-parse", "HEAD") === sha &&
      git("rev-parse", "HEAD^{tree}") === tree && git("status", "--porcelain", "--untracked-files=all") === "");
  }
  const proof = fs.realpathSync(process.env.PROOF);
  need(proof.startsWith(fs.realpathSync(process.env.RUNNER_TEMP) + path.sep));
  const prepared = path.join(proof, "preparation-parent/preparation");
  const original = path.join(prepared, "app");
  const dir = fresh(path.join(proof, "native-" + leg));
  const app = path.join(dir, "app");
  const home = fresh(path.join(dir, "home"));
  const temporary = fresh(path.join(dir, "temporary"));
  const env = { HOME: home, TMPDIR: temporary, PATH: path.dirname(process.execPath) + ":" + process.env.PATH,
    CI: "true", DO_NOT_TRACK: "1", VENDURE_DISABLE_TELEMETRY: "1", npm_config_update_notifier: "false" };
  const progress = { kind: "vendure-native-ordinary", releaseAcceptance: false, leg, stages: {},
    startupEvidence: { workerContextReady: false, serverListenBanner: false, serverProcessMatched: false, serverAtJointReady: null },
    preflight: null, captureIncompleteNotice: null, serverStop: null, workerStop: null, databaseRelease: "unreached", status: "incomplete" };
  const checkpoint = () => {
    const target = path.join(dir, "progress.private.json");
    fs.writeFileSync(target + ".next", JSON.stringify(progress) + "\n", { flag: "wx", mode: 0o600 });
    fs.renameSync(target + ".next", target);
  };
  async function stage(name, command) {
    progress.stages[name] = "running"; checkpoint();
    try {
      const value = await command();
      progress.stages[name] = "passed"; checkpoint();
      return value;
    } catch (error) {
      progress.stages[name] = "failed"; checkpoint();
      throw error;
    }
  }
  const names = { net: PREFIX + "vendure-native-" + leg + "-net", db: PREFIX + "vendure-native-" + leg + "-db" };
  const fixture = new OwnedServicesFixture(dir, names, null);
  let worker, server, installed, project;
  checkpoint();
  try {
    if (leg === "installed") {
      installed = await stage("install", () => installVendurePackage({ repo: productRoot, directory: path.join(dir, "package"),
        sourceCommit: process.env.PRODUCT, archive: path.join(proof, "dist/linux-x86_64/xtrace-0.0.1-linux-x86_64.tar.gz") }));
      env.XTRACE_DATA_HOME = installed.data;
      project = fresh(path.join(dir, "project"));
      await stage("initEmptyList", () => {
        const config = path.join(dir, "preflight-input.json");
        fs.writeFileSync(config, JSON.stringify({ ...installed, uid: process.getuid(), control: dir,
          project, nodeVersion: process.versions.node }), { flag: "wx", mode: 0o600 });
        try {
          execFileSync(process.execPath, [path.join(here, "installed-preflight.mjs"), config], {
            cwd: dir, env, stdio: ["ignore", "ignore", "ignore"], timeout: 180000, killSignal: "SIGKILL" });
        } finally { progress.preflight = readPreflightObservation(path.join(dir, "preflight-observation.json")); }
        need(progress.preflight?.phase === "receipt" && progress.preflight.status === "passed" &&
          readPreflightReceipt(path.join(dir, "preflight.json"))?.passed === true);
      });
    }
    const seed = await stage("seedIdentity", () => prepareBaselineSeed(original, () =>
      JSON.parse(execFileSync("python3", ["-B", path.join(here, "seed_assets.py"), "verify",
        path.join(prepared, "create-assets.tgz"), path.join(prepared, "create-assets")], { encoding: "utf8", stdio: "pipe" }))));
    await stage("nativeBuild", () => prepareNativeStarter(original, app, path.join(dir, "npm.private.log"), env));
    const dbPassword = randomBytes(32).toString("hex");
    await stage("restore", () => seed.startAndRestore({ username: "xtrace", database: "vendure" }, async () => {
      fixture.createNetwork(names.net);
      await startPostgres({ netName: fixture.network, dbName: names.db, database: "vendure", user: "xtrace", password: dbPassword }, fixture);
      return fixture.id(names.db);
    }, docker));
    const runtime = { ...env, APP_ENV: "dev", PORT: "34117", DB_HOST: "127.0.0.1",
      DB_PORT: String(fixture.hostPort(names.db, 5432)), DB_SCHEMA: "public", DB_NAME: "vendure",
      DB_USERNAME: "xtrace", DB_PASSWORD: dbPassword };
    await stage("startup", async () => {
      worker = launch([process.execPath, "./dist/index-worker.js"], app, runtime, dir, "worker");
      const command = [process.execPath, "./dist/index.js"];
      if (leg === "installed") command.unshift(installed.cli, "run", "--project-dir", project,
        "--node-adapter", installed.pack, "--node-mode", "auto", "--");
      server = launch(command, app, runtime, dir, "server");
      await observeStartup(server, worker, leg, progress.startupEvidence, checkpoint);
    });
  } catch { /* stage owns the finite failure record */ }
  finally {
    if (server) {
      try {
        await stage("serverStop", async () => {
          const result = progress.serverStop = await stop(server, leg);
          if (leg === "installed") progress.captureIncompleteNotice = incompleteNotice(server);
          need(result.live && result.signalled && result.closed && result.code === 0 && result.signal === null &&
            result.nodeBeforeStop === "live-match" && result.nodeGone === true);
        });
      } catch { /* continue releasing independent exact handles */ }
    }
    if (worker) {
      try {
        await stage("workerStop", async () => {
          const result = progress.workerStop = await stop(worker, leg);
          need(result.live && result.signalled && result.closed &&
            ((result.code === 0 && result.signal === null) || (result.code === null && result.signal === "SIGTERM")));
        });
      } catch { /* retain independent evidence */ }
    }
    if (fixture.network || fixture.containers.size) {
      // If a stock process cannot be accounted for, leave its database with the disposable runner.
      const serverGone = !server || (progress.serverStop?.closed && (leg === "direct" || progress.serverStop.nodeGone === true));
      if (!serverGone || (worker && !progress.workerStop?.closed)) {
        fixture.recordKeptHandles(dir); progress.databaseRelease = "retained";
      } else {
        progress.databaseRelease = "running";
        try { checkpoint(); }
        finally {
          try { fixture.cleanup(); progress.databaseRelease = "passed"; }
          catch { progress.databaseRelease = "retained"; }
        }
      }
    }
    const needed = ["seedIdentity", "nativeBuild", "restore", "startup", "serverStop", "workerStop"];
    if (leg === "installed") needed.push("install", "initEmptyList");
    const lifecycle = needed.every(name => progress.stages[name] === "passed") && progress.databaseRelease === "passed";
    if (lifecycle && (leg === "direct" || progress.captureIncompleteNotice === false)) progress.status = "passed";
    checkpoint();
  }
  return progress.status === "passed" ? 0 : 1;
}

main().then(code => { process.exitCode = code; }, () => { process.exitCode = 1; });
