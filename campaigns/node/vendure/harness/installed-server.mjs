// Runs inside the owned fixture. Only this process signals the launcher it spawned.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { signalOwnedChild } from "./installed-lifecycle.mjs";

const control = process.argv[2];
const config = JSON.parse(fs.readFileSync(path.join(control, "launch.json"), "utf8"));
if (!Array.isArray(config.argv) || !config.argv.length || config.argv.some(x => typeof x !== "string")) {
  throw new Error("Vendure launcher argv invalid");
}
const out = fs.openSync(path.join(control, "launcher.stdout"), "wx", 0o600);
const err = fs.openSync(path.join(control, "launcher.stderr"), "wx+", 0o600);
let stopped = false, stopSignalled = false, deadline = false, spawned = false, timer;
const child = spawn(config.argv[0], config.argv.slice(1), { stdio: ["ignore", out, err] });
child.once("spawn", () => { spawned = true; });
function requestStop() {
  if (stopped || !fs.existsSync(path.join(control, "stop.request"))) return;
  stopped = true;
  // The direct ChildProcess remains ours until close. No enumeration/group/container signal.
  stopSignalled = signalOwnedChild(child, "SIGTERM");
  // Preserve the source launcher recipe's 25-second normal grace; outer wait includes five seconds of recovery.
  timer = setTimeout(() => {
    deadline = true;
    signalOwnedChild(child, "SIGKILL"); // Recovery is a failed normal shutdown, retained in the terminal receipt.
  }, 25000);
}
const watcher = fs.watch(control, requestStop);
requestStop(); // A request can precede watcher registration.
child.once("error", () => {}); // close records launch failure without persisting OS paths.
child.once("close", (code, signal) => {
  watcher.close();
  clearTimeout(timer);
  let incomplete = null;
  try {
    const size = fs.fstatSync(err).size;
    if (size <= 16 * 1024 * 1024) {
      const bytes = Buffer.alloc(size);
      let offset = 0;
      while (offset < size) {
        const n = fs.readSync(err, bytes, offset, size - offset, offset);
        if (!n) break;
        offset += n;
      }
      if (offset === size && fs.fstatSync(err).size === size) {
        incomplete = bytes.includes(Buffer.from("XTR-RUN-CAPTURE-INCOMPLETE"));
      }
    }
  } catch { /* An unavailable diagnostic does not establish marker presence or absence. */ }
  fs.closeSync(out); fs.closeSync(err);
  const terminal = { spawned, stopRequested: stopped, stopSignalled, deadline, code, signal,
    captureIncompleteNotice: incomplete,
    normalExit: spawned && stopped && stopSignalled && !deadline && code === 0 && signal === null };
  fs.writeFileSync(path.join(control, "terminal.json"), JSON.stringify(terminal) + "\n", { mode: 0o600, flag: "wx" });
  process.exitCode = terminal.normalExit ? 0 : 1;
});
