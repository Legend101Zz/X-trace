// Executed in an owned container with the same private installed mounts, without networking.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pages, keys, inventory, recordingId } from "./installed-evidence.mjs";
const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
let sequence = 0;
const deadline = Date.now() + 30000;
let listed;
for (;;) {
  listed = await pages(async after => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("Vendure readiness recording deadline");
    const args = ["recording", "list", "--project-dir", config.project, "--limit", "20", ...(after ? ["--after", after] : [])];
    const bytes = execFileSync(config.cli, args, { timeout: Math.min(5000, remaining), maxBuffer: 16 * 1024 * 1024, stdio: "pipe" });
    fs.writeFileSync(path.join(config.output, `cli-${++sequence}.json`), bytes, { flag: "wx", mode: 0o600 });
    return JSON.parse(bytes);
  }, "recordings", "next_after", 20, 400);
  const rows = listed.flatMap(doc => doc.recordings);
  if (rows.length > config.expected) throw new Error("Vendure readiness recording count mismatch");
  if (rows.length === config.expected && rows.every(row => row.status === "complete" && row.completion === "complete" &&
    Array.isArray(row.incomplete_evidence) && row.incomplete_evidence.length === 0)) break;
  if (Date.now() >= deadline) throw new Error("Vendure readiness recording deadline");
  await new Promise(resolve => setTimeout(resolve, Math.min(100, deadline - Date.now())));
}
const projectId = recordingId(config.projectId);
inventory(listed, projectId, false);
fs.writeFileSync(path.join(config.output, "snapshot.json"), JSON.stringify({ projectId, ids: keys(listed, "recordings", "recording_id") }) + "\n", { flag: "wx", mode: 0o600 });
