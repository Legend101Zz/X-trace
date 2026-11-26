// Hosted-only regressions for review A1/A2/A3/B1. They do not qualify an installed app.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { cleanupPairFixture, readbackVerdict, stopOwnedViewer, signalOwnedChild } from "./installed-lifecycle.mjs";
import { runScenarios } from "../../lib/harness.mjs";

for (const failure of ["live", "unavailable"]) {
  test(`A1 retains exact fixture handles when app removal is ${failure}`, () => {
    const calls = [], app = "a".repeat(64);
    const fixture = { containers: new Map([["app", app]]), id: name => fixture.containers.get(name),
      command(args) { calls.push(args); if (failure === "unavailable") throw new Error("private command failure"); return { status: 1 }; },
      cleanup() { assert.fail("live app must never enter forced cleanup"); },
      recordKeptHandles(directory) { calls.push(["retained", directory]); } };
    assert.equal(cleanupPairFixture(fixture, { app: "app" }, "private-output"), "retained");
    assert.deepEqual(calls, [["rm", "-v", app], ["retained", "private-output"]]);
    assert.equal(fixture.containers.get("app"), app);
  });
}
test("A1 app is removed without force before ordinary other-resource cleanup", () => {
  const app = "b".repeat(64), calls = [];
  const fixture = { containers: new Map([["app", app], ["worker", "c".repeat(64)]]), id: () => app,
    command(args) { calls.push(args); return { status: 0 }; },
    cleanup() { assert.equal(fixture.containers.has("app"), false); calls.push(["other-resource-cleanup"]); } };
  assert.equal(cleanupPairFixture(fixture, { app: "app", worker: "worker" }, "private-output"), "passed");
  assert.deepEqual(calls, [["rm", "-v", app], ["other-resource-cleanup"]]);
});
for (const code of [1, null, undefined]) {
  test(`A2 passed document cannot override unsuccessful process ${String(code)}`, () => {
    const result = readbackVerdict(code, { status: "passed", cliViewerParity: true });
    assert.equal(result.status, "failed"); assert.equal(result.processSucceeded, false);
  });
}
test("A2 process success cannot override a failed document", () => {
  assert.equal(readbackVerdict(0, { status: "failed" }).status, "failed");
  assert.deepEqual(readbackVerdict(0, { status: "passed" }), { status: "passed", processSucceeded: true });
});
test("A3 scenario logs use the private callback rather than global stdout", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-vendure-log-"));
  const original = console.log, logs = [];
  try {
    console.log = () => { throw new Error("unexpected public scenario output"); };
    const result = await runScenarios({ project: "fixture", baseUrl: "http://127.0.0.1:1", outDir: directory,
      scenarios: [{ id: "original-assertion", run: async () => ({ assertions: { observed: true } }) }], log: line => logs.push(line) });
    assert.equal(result.result, "passed"); assert.equal(logs.length, 1);
    assert.match(logs[0], /original-assertion/);
  } finally { console.log = original; fs.rmSync(directory, { recursive: true, force: true }); }
});
test("B1 actual already-exited viewer receives no new signal and remains failed", async () => {
  const child = spawn(process.execPath, ["-e", "process.exit(0)"], { stdio: "ignore" });
  const closed = once(child, "close"); await closed;
  child.kill = () => { assert.fail("an exited child must not be signalled"); };
  const result = await stopOwnedViewer(child, closed);
  assert.equal(result.status, "failed"); assert.equal(result.earlyExit, true);
});
test("B1 actual exit racing the timeout is reconciled without a stale recovery signal", async () => {
  const child = spawn(process.execPath, ["-e", 'process.on("SIGTERM",()=>process.exit(0));process.stdout.write("ready\\n");setInterval(()=>{},1000);'], { stdio: ["ignore", "pipe", "ignore"] });
  const closed = once(child, "close"); await once(child.stdout, "data");
  const signals = [], originalKill = child.kill.bind(child);
  child.kill = signal => { signals.push(signal); return originalKill(signal); };
  try {
    const result = await stopOwnedViewer(child, closed, async (promise, budget) => {
      await promise;
      if (budget === 25000) throw new Error("timeout and exit were delivered together");
      return promise;
    });
    assert.deepEqual(signals, ["SIGTERM"]);
    assert.equal(result.status, "failed"); assert.equal(result.recovery, true);
    assert.equal(result.recoverySignalled, false);
  } finally {
    if (child.exitCode === null && child.signalCode === null) originalKill("SIGTERM");
    await closed;
  }
});
test("B1 recovery is explicitly failed even when its own still-live child is killed", async () => {
  const signals = [];
  const child = { exitCode: null, signalCode: null, kill(signal) { signals.push(signal); return true; } };
  const result = await stopOwnedViewer(child, Promise.resolve([null, "SIGKILL"]), async (_, budget) => {
    if (budget === 25000) throw new Error("original grace expired");
    child.signalCode = "SIGKILL"; return [null, "SIGKILL"];
  });
  assert.deepEqual(signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(result.status, "failed"); assert.equal(result.recovery, true);
});

test("B1 the app supervisor's shared signal guard also rejects an exited handle", () => {
  const child = { exitCode: 0, signalCode: null, kill() { assert.fail("exited app child must not be signalled"); } };
  assert.equal(signalOwnedChild(child, "SIGTERM"), false);
  assert.equal(signalOwnedChild(child, "SIGKILL"), false);
});

test("A1 a live readback helper is retained rather than force-cleaned after the app stops", () => {
  const calls = [], app = "d".repeat(64), helper = "e".repeat(64);
  const fixture = { containers: new Map([["app", app], ["readback", helper]]),
    command(args) { calls.push(args); return { status: args.at(-1) === app ? 0 : 1 }; },
    recordKeptHandles() { calls.push(["retained"]); }, cleanup() { assert.fail("live helper must not be forced"); } };
  assert.equal(cleanupPairFixture(fixture, { app: "app" }, "private-output"), "retained");
  assert.deepEqual(calls, [["rm", "-v", app], ["rm", "-v", helper], ["retained"]]);
  assert.equal(fixture.containers.has("app"), false);
  assert.equal(fixture.containers.get("readback"), helper);
});
