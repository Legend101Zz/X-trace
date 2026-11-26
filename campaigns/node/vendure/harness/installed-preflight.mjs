// Executes only inside the same pinned image/UID/mounts used by the installed server.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { recordingId } from "./installed-evidence.mjs";
const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const digest = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
if (process.versions.node !== config.nodeVersion || process.getuid() !== config.uid ||
    digest(config.cli) !== config.identity.cliSha256 ||
    digest(path.join(config.pack, "manifest.sha256")) !== config.identity.nodePackManifestSha256) {
  throw new Error("Vendure package runtime preflight failed");
}
for (const args of [["--version"], ["init", "--project-dir", config.project]]) {
  execFileSync(config.cli, args, { stdio: "pipe", timeout: 30000 });
}
const empty = JSON.parse(execFileSync(config.cli, ["recording", "list", "--project-dir", config.project],
  { encoding: "utf8", stdio: "pipe", timeout: 30000 }));
if (!Array.isArray(empty.recordings) || empty.recordings.length || empty.next_after !== null) {
  throw new Error("Vendure installed project was not empty");
}
fs.writeFileSync(path.join(config.control, "preflight.json"), JSON.stringify({ passed: true, projectId: recordingId(empty.project_id) }) + "\n", { mode: 0o600, flag: "wx" });
