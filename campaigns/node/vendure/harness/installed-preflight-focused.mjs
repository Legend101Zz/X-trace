// A single installed preflight only. No application workload or capture is started.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { builtImage, VendureFixture } from "./fixture.mjs";
import { installVendurePackage } from "./installed-package.mjs";
import { cleanupPairFixture } from "./installed-lifecycle.mjs";
import { preflightExitVerdict, readPreflightObservation, readPreflightReceipt } from "./installed-preflight-observation.mjs";
import { PLATFORM, PREFIX } from "../../lib/docker.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const campaign = JSON.parse(fs.readFileSync(path.join(here, "../campaign.json"), "utf8"));
const root = process.env.PROOF, repo = process.cwd(), sourceCommit = process.env.PRODUCT;
if (process.platform !== "linux" || process.env.GITHUB_ACTIONS !== "true" || PLATFORM !== "linux/amd64" ||
    !root || !/^[a-f0-9]{40}$/.test(sourceCommit) ||
    ["DOCKER_HOST", "DOCKER_CONTEXT", "XTRACE_CAMP_DOCKER_HOST", "XTRACE_CAMP_DOCKER_CONFIG"].some(key => process.env[key])) throw new Error("preflight proof admission failed");
process.umask(0o077);
const output = path.join(root, "pair"), directory = path.join(output, "installed"), control = path.join(directory, "control");
const fresh = dir => fs.mkdirSync(dir, { mode: 0o700 });
fresh(output); fresh(directory); fresh(control);
const report = { schemaVersion: 1, kind: "vendure-installed-preflight-only", source: sourceCommit,
  releaseAcceptance: false, package: "unreached", preflight: "unreached", observation: null,
  attachExit: null, processExit: null, receiptValid: null, cleanup: "unreached", status: "incomplete" };
// Replace the checkpoint atomically so an interruption preserves the last complete observation.
const checkpoint = path.join(root, "safe", "preflight.json");
let checkpointFailed = false;
function save() {
  const temporary = checkpoint + ".pending";
  try {
    fs.writeFileSync(temporary, JSON.stringify(report) + "\n", { mode: 0o600, flag: "wx" });
    fs.renameSync(temporary, checkpoint);
  } catch { checkpointFailed = true; }
}
const fixture = new VendureFixture();
let packageInfo;
try {
  report.package = "running"; save();
  try {
    packageInfo = installVendurePackage({ repo, sourceCommit,
      archive: path.join(root, "dist/linux-x86_64/xtrace-0.0.1-linux-x86_64.tar.gz"), directory: path.join(output, "package") });
  } catch (error) {
    report.package = "failed";
    throw error;
  }
  report.package = "verified"; save();
  const image = builtImage(path.join(root, "preparation-parent"));
  const project = path.join(directory, "project"), temporary = path.join(directory, "temporary"); fresh(project); fresh(temporary);
  const input = path.join(control, "preflight-input.json");
  fs.writeFileSync(input, JSON.stringify({ ...packageInfo, nodeVersion: campaign.runtime.nodeImageVersion,
    uid: process.getuid(), project, control }) + "\n", { mode: 0o600, flag: "wx" });
  const mounts = ["-v", `${here}:/xtrace-vendure-harness:ro`, "-v", `${control}:${control}`,
    "-v", `${packageInfo.prefix}:${packageInfo.prefix}:ro`, "-v", `${packageInfo.data}:${packageInfo.data}`,
    "-v", `${project}:${project}`, "-v", `${temporary}:${temporary}`,
    "-e", `XTRACE_DATA_HOME=${packageInfo.data}`, "-e", `TMPDIR=${temporary}`];
  report.preflight = "running"; save();
  const observed = await fixture.runObserved(`${PREFIX}vendure-pair-installed-preflight`, [
    "--user", `${process.getuid()}:${process.getgid()}`, "--network", "none", ...mounts, image,
    "/usr/local/bin/node", "/xtrace-vendure-harness/installed-preflight.mjs", input,
  ], path.join(directory, "preflight.log"));
  report.attachExit = observed.attachExit; report.processExit = observed.processExit;
} catch {
  // The final reader can still observe a marker written before an attach or inspect failure.
} finally {
  if (report.preflight === "running") {
    report.observation = readPreflightObservation(path.join(control, "preflight-observation.json"));
    const receipt = readPreflightReceipt(path.join(control, "preflight.json"));
    report.receiptValid = receipt !== null;
    report.preflight = preflightExitVerdict(report, receipt, report.observation) ? "passed" : "failed";
  }
  save();
  if (fixture.containers.size) {
    report.cleanup = "running"; save();
    try { report.cleanup = cleanupPairFixture(fixture, {}, directory); } catch { report.cleanup = "failed"; }
  }
  report.status = report.package === "verified" && report.preflight === "passed" && report.cleanup === "passed" ? "passed" : "incomplete";
  save();
}
if (checkpointFailed || report.status !== "passed") process.exitCode = 1;
