// Executes only inside the same pinned image/UID/mounts used by the installed server.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { recordingId } from "./installed-evidence.mjs";
import { signalClass } from "./installed-preflight-observation.mjs";
const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const digest = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
// Each marker is a closed vocabulary and is written before the operation. A
// missing or running marker cannot be promoted to a completed observation.
const phases = ["identity", "version", "init", "list", "empty", "receipt"];
let phase = "identity";
const checkpoint = (status, error = null) => {
  const code = Number.isInteger(error?.status) && error.status >= 0 && error.status <= 255 ? error.status : null;
  const signal = code === null ? signalClass(error?.signal) : null;
  fs.writeFileSync(path.join(config.control, "preflight-observation.json"),
    JSON.stringify({ phase, status, code, signal }) + "\n", { mode: 0o600 });
};
const enter = next => { if (!phases.includes(next)) throw new Error("invalid preflight phase"); phase = next; checkpoint("running"); };
try {
  checkpoint("running");
  if (process.versions.node !== config.nodeVersion || process.getuid() !== config.uid ||
      digest(config.cli) !== config.identity.cliSha256 ||
      digest(path.join(config.pack, "manifest.sha256")) !== config.identity.nodePackManifestSha256) {
    throw new Error("Vendure package runtime preflight failed");
  }
  enter("version");
  execFileSync(config.cli, ["--version"], { stdio: "pipe", timeout: 30000 });
  enter("init");
  execFileSync(config.cli, ["init", "--project-dir", config.project], { stdio: "pipe", timeout: 30000 });
  enter("list");
  const empty = JSON.parse(execFileSync(config.cli, ["recording", "list", "--project-dir", config.project],
    { encoding: "utf8", stdio: "pipe", timeout: 30000 }));
  enter("empty");
  if (!Array.isArray(empty.recordings) || empty.recordings.length || empty.next_after !== null) {
    throw new Error("Vendure installed project was not empty");
  }
  const projectId = recordingId(empty.project_id);
  enter("receipt");
  fs.writeFileSync(path.join(config.control, "preflight.json"), JSON.stringify({ passed: true, projectId }) + "\n", { mode: 0o600, flag: "wx" });
  checkpoint("passed");
} catch (error) {
  checkpoint("failed", error);
  throw error;
}
