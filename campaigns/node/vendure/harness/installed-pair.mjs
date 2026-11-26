// Preparation is already complete. Both disposable legs independently re-admit its same seed.
// Functional parity, product recording readback and exact-witness privacy are separate verdicts.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { builtImage } from "./fixture.mjs";
import { OwnedServicesFixture } from "./owned-services.mjs";
import { prepareBaselineSeed } from "./preparation.mjs";
import { createVendureRuntime } from "./runtime.mjs";
import { runOrdinaryVendureWorkload, compareVendureWorkloads } from "./installed-workload.mjs";
import { cleanupPairFixture, installedReadbackReceipt, installedCaptureDisposition, launcherObservations } from "./installed-lifecycle.mjs";
import { judgeInstalledVendurePrivacy } from "./installed-privacy.mjs";
import { installVendurePackage } from "./installed-package.mjs";
import { PLATFORM, PREFIX } from "../../lib/docker.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "../campaign.json"), "utf8"));
function need(ok) { if (!ok) throw new Error("Vendure installed pair condition failed"); }
function fresh(directory) { fs.mkdirSync(directory, { mode: 0o700 }); return directory; }
function write(file, value) { fs.writeFileSync(file, JSON.stringify(value) + "\n", { mode: 0o600, flag: "wx" }); }

export async function runInstalledVendurePair({ repo, workspaceParent, outDir, archive, sourceCommit }) {
  need(PLATFORM === "linux/amd64");
  fresh(outDir);
  const root = path.join(workspaceParent, "preparation"), image = builtImage(workspaceParent);
  const report = { releaseAcceptance: false, package: "unreached", legs: {},
    functionalParity: "unreached", recordingReadback: "unreached", privacyAdjudication: "unreached",
    status: "incomplete" };
  let packageInfo, firstSeed;
  const results = {};
  let checkpointNumber = 0;
  const checkpoint = () => {
    try { write(path.join(outDir, `checkpoint-${++checkpointNumber}.private.json`), report); }
    catch { report.checkpointFailure = true; }
  };
  checkpoint();
  function verifiedAssets() {
    return JSON.parse(execFileSync("python3", ["-B", path.join(here, "seed_assets.py"), "verify",
      path.join(root, "create-assets.tgz"), path.join(root, "create-assets")], { encoding: "utf8", stdio: "pipe" }));
  }
  try {
    report.package = "failed";
    checkpoint();
    packageInfo = installVendurePackage({ repo, archive, sourceCommit, directory: path.join(outDir, "package") });
    report.package = "verified";
    report.packageIdentity = packageInfo.identity;
    checkpoint();
    for (const leg of ["baseline", "installed"]) {
      const directory = fresh(path.join(outDir, leg)), control = fresh(path.join(directory, "control"));
      const names = Object.fromEntries(["net", "db", "app", "worker"].map(role =>
        [role, `${PREFIX}vendure-pair-${leg}-${role}`]));
      const fixture = new OwnedServicesFixture(directory, names, image);
      const state = report.legs[leg] = { inputs: "unreached", startup: "unreached", workload: "unreached",
        shutdown: "unreached", cleanup: "unreached" };
      const mounts = ["-v", `${here}:/xtrace-vendure-harness:ro`, "-v", `${control}:${control}`];
      checkpoint();
      let project, projectId, snapshot;
      const command = ["/usr/local/bin/node", "./dist/index.js"];
      const capture = { mounts, supervisor: "/xtrace-vendure-harness/installed-server.mjs", control };
      try {
        state.inputs = "failed";
        need(builtImage(workspaceParent) === image);
        const seed = prepareBaselineSeed(path.join(root, "app"), verifiedAssets);
        const identity = JSON.stringify(seed.metadata);
        if (firstSeed === undefined) firstSeed = identity;
        need(firstSeed === identity);
        state.inputs = "verified";
        checkpoint();
        state.seedSha256 = seed.metadata.seedSha256;
        if (leg === "installed") {
          project = fresh(path.join(directory, "project"));
          const temporary = fresh(path.join(directory, "temporary"));
          mounts.push("-v", `${packageInfo.prefix}:${packageInfo.prefix}:ro`, "-v", `${packageInfo.data}:${packageInfo.data}`,
            "-v", `${project}:${project}`, "-v", `${temporary}:${temporary}`,
            "-e", `XTRACE_DATA_HOME=${packageInfo.data}`, "-e", `TMPDIR=${temporary}`);
          const preflight = path.join(control, "preflight-input.json");
          write(preflight, { ...packageInfo, nodeVersion: campaign.runtime.nodeImageVersion,
            uid: process.getuid(), project, control });
          state.preflight = "failed";
          const code = await fixture.runLogged(`${PREFIX}vendure-pair-installed-preflight`, [
            "--user", `${process.getuid()}:${process.getgid()}`, "--network", "none", ...mounts, image,
            "/usr/local/bin/node", "/xtrace-vendure-harness/installed-preflight.mjs", preflight,
          ], path.join(directory, "preflight.log"));
          const admitted = JSON.parse(fs.readFileSync(path.join(control, "preflight.json"), "utf8"));
          need(code === 0 && admitted.passed === true);
          projectId = admitted.projectId;
          state.preflight = "passed";
          checkpoint();
          command.unshift(packageInfo.cli, "run", "--project-dir", project, "--node-adapter", packageInfo.pack,
            "--node-mode", "auto", "--");
        }
        write(path.join(control, "launch.json"), { argv: command });
        fixture.createNetwork(names.net);
        state.startup = "failed";
        const runtime = createVendureRuntime({ root, image, fixture });
        const context = await runtime.buildStack({ names }, seed, capture);
        state.startup = "ready";
        checkpoint();
        if (leg === "installed") {
          state.readinessRecording = "failed";
          const output = fresh(path.join(control, "readiness"));
          snapshot = path.join(output, "snapshot.json");
          const input = path.join(control, "snapshot-input.json");
          write(input, { cli: packageInfo.cli, project, projectId, output, expected: context.readinessResponses });
          const code = await fixture.runLogged(`${PREFIX}vendure-pair-installed-snapshot`, [
            "--user", `${process.getuid()}:${process.getgid()}`, "--network", "none", ...mounts, image,
            "/usr/local/bin/node", "/xtrace-vendure-harness/installed-snapshot.mjs", input,
          ], path.join(directory, "snapshot.log"));
          need(code === 0);
          state.readinessRecording = "complete-cohort-observed";
        }
        state.workload = "failed";
        checkpoint();
        results[leg] = await runOrdinaryVendureWorkload({ leg, ...context, outDir: path.join(directory, "workload") });
        state.workload = results[leg].passed ? "passed" : "failed";
        checkpoint();
      } catch {
        // Raw command output is private; the bounded stage statuses identify where execution stopped.
      } finally {
        try {
          if (fixture.containers.has(names.app)) {
            state.shutdown = "failed";
            checkpoint();
            const live = fixture.running(names.app);
            state.workerBeforeStop = fixture.running(names.worker) ? "observed-running" : "not-observed-running";
            fs.writeFileSync(path.join(control, "stop.request"), "stop\n", { flag: "wx", mode: 0o600 });
            // wait observes the created container only; termination is by the supervisor's own ChildProcess.
            const wait = fixture.command(["wait", fixture.id(names.app)], { allowFail: true, timeoutMs: 30000 });
            const terminal = JSON.parse(fs.readFileSync(path.join(control, "terminal.json"), "utf8"));
            state.terminal = terminal;
            Object.assign(state, launcherObservations(live, wait, terminal));
            if (state.shutdown === "normal") {
              state.workerSurvival = "unavailable";
              try { state.workerSurvival = fixture.running(names.worker) ? "observed-running" : "not-observed-running"; }
              catch { /* Keep the observed launcher terminal if the worker inspection fails. */ }
            }
          }
        } catch { state.shutdown = "failed"; }
        if (leg === "installed" && installedCaptureDisposition(state).allowReadback && results.installed && snapshot) {
          const output = path.join(control, "readback");
          let readbackProcess = { attachExit: null, processExit: null };
          try {
            fresh(output);
            report.recordingReadback = "failed";
            const witness = path.join(directory, "workload/privacy-witness.private.json");
            const observed = JSON.parse(fs.readFileSync(witness, "utf8"));
            const input = path.join(control, "readback-input.json");
            write(input, { cli: packageInfo.cli, project, output, snapshot, statuses: observed.statuses,
              responses: results.installed.rows.reduce((sum, row) => sum + row.responsesRead, 0) });
            readbackProcess = await fixture.runObserved(`${PREFIX}vendure-pair-installed-readback`, [
              "--user", `${process.getuid()}:${process.getgid()}`, "--network", "none", ...mounts, image,
              "/usr/local/bin/node", "/xtrace-vendure-harness/installed-readback.mjs", input,
            ], path.join(directory, "readback.log"));
          } catch { /* An unavailable process result remains unknown even if its document survived. */ }
          report.recordingReadback = installedReadbackReceipt(readbackProcess, () =>
            JSON.parse(fs.readFileSync(path.join(output, "readback.json"), "utf8")));
          if (report.recordingReadback.status !== "passed") report.recordingReadbackFailure = "installed-readback-failed";
          try {
            report.privacyAdjudication = judgeInstalledVendurePrivacy({ dataHome: packageInfo.data, readback: output,
              diagnostic: path.join(control, "launcher.stderr"), witness: path.join(directory, "workload/privacy-witness.private.json") });
          } catch { report.privacyAdjudication = { status: "failed", failure: "bounded-privacy-inspection-failed" }; }
        }
        try { fixture.collect(names, directory); } catch { state.collection = "failed"; }
        try { state.cleanup = cleanupPairFixture(fixture, names, directory); } catch { state.cleanup = "failed"; }
        state.serviceStops = fixture.stops;
        checkpoint();
      }
    }
    if (results.baseline && results.installed) {
      const parity = compareVendureWorkloads(results.baseline, results.installed);
      report.functionalParity = parity;
      const lifecycle = Object.values(report.legs).every(leg => leg.inputs === "verified" && leg.startup === "ready" &&
        leg.workload === "passed" && leg.shutdown === "normal" && leg.cleanup === "passed" &&
        leg.workerBeforeStop === "observed-running" && leg.workerSurvival === "observed-running" &&
        leg.serviceStops.db === "owned-normal-exit" && ["owned-normal-exit", "owned-term-exit"].includes(leg.serviceStops.worker) && leg.collection !== "failed");
      if (!report.checkpointFailure && parity.parity && lifecycle && installedCaptureDisposition(report.legs.installed).eligibleForPass && report.recordingReadback.status === "passed" && report.recordingReadback.processSucceeded === true &&
          !report.recordingReadbackFailure && report.privacyAdjudication.status === "passed") {
        report.status = "passed-development-only";
      }
    }
  } catch { report.failure = "package-or-pair-operation-failed"; }
  write(path.join(outDir, "pair.private.json"), report);
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  need(process.platform === "linux" && process.env.GITHUB_ACTIONS === "true" && process.argv.length === 3);
  need(!["DOCKER_HOST", "DOCKER_CONTEXT", "XTRACE_CAMP_DOCKER_HOST", "XTRACE_CAMP_DOCKER_CONFIG"].some(key => process.env[key]));
  process.umask(0o077);
  const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const result = await runInstalledVendurePair(config);
  // No request/response content, auth material, paths, exception details or raw fingerprints.
  console.log(JSON.stringify({ status: result.status, releaseAcceptance: false }));
  if (result.status !== "passed-development-only") process.exitCode = 1;
}
