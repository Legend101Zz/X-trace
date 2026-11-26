// Hosted only: actual direct children establish the shutdown receipt, without Docker or HTTP.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { once } from "node:events";

const supervisor = fileURLToPath(new URL("./installed-server.mjs", import.meta.url));
function waitForFile(file) {
  return new Promise((resolve, reject) => {
    const finish = error => { watcher.close(); clearTimeout(timer); error ? reject(error) : resolve(); };
    const inspect = () => { if (fs.existsSync(file)) finish(); };
    const watcher = fs.watch(path.dirname(file), inspect);
    const timer = setTimeout(() => finish(new Error("owned child did not become ready")), 10000);
    inspect();
  });
}
for (const [name, source, expected, oversized] of [
  ["normal direct-child exit", 'process.on("SIGTERM",()=>process.exit(0));', true],
  ["nonzero direct-child exit", 'process.on("SIGTERM",()=>process.exit(7));', false],
  ["incomplete capture notice remains visible", 'process.stderr.write("XTR-RUN-CAPTURE-INCOMPLETE\\n");process.on("SIGTERM",()=>process.exit(0));', true],
  ["oversized diagnostic leaves capture notice unknown after normal shutdown",
    'require("node:fs").ftruncateSync(2,16*1024*1024+1);process.on("SIGTERM",()=>process.exit(0));', true, true],
]) {
  test(name, async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-vendure-launcher-"));
    const ready = path.join(directory, "ready");
    const childSource = source + `require("node:fs").writeFileSync(${JSON.stringify(ready)},"ready");setInterval(()=>{},1000);`;
    fs.writeFileSync(path.join(directory, "launch.json"), JSON.stringify({ argv: [process.execPath, "-e", childSource] }), { mode: 0o600 });
    const child = spawn(process.execPath, [supervisor, directory], { stdio: "ignore" });
    const closed = once(child, "close");
    try {
      await waitForFile(ready);
      fs.writeFileSync(path.join(directory, "stop.request"), "stop", { flag: "wx", mode: 0o600 });
      const [exit] = await closed;
      const terminal = JSON.parse(fs.readFileSync(path.join(directory, "terminal.json"), "utf8"));
      assert.equal(terminal.spawned, true);
      assert.equal(terminal.stopRequested, true);
      assert.equal(terminal.deadline, false);
      assert.equal(terminal.normalExit, expected);
      assert.equal(exit, expected ? 0 : 1);
      assert.equal(terminal.captureIncompleteNotice, oversized ? null : name === "incomplete capture notice remains visible");
    } finally {
      // Ask the supervisor to terminate only its own launcher even on a failed assertion.
      if (child.exitCode === null && child.signalCode === null && !fs.existsSync(path.join(directory, "stop.request"))) {
        fs.writeFileSync(path.join(directory, "stop.request"), "stop", { flag: "wx", mode: 0o600 });
      }
      await closed;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
}
