import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Worker } from "node:worker_threads";
import type { CaptureDiagnostic } from "../capture-diagnostics.cjs";
import { createCaptureCredits, createHttpCaptureTransport } from "../runtime/transport.cjs";

test("a real worker returns charged capacity before main-thread credit notifications run", async (t) => {
  const credits = createCaptureCredits();
  const signal = new Int32Array(new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT));
  const worker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    const { returnCaptureCredit } = require(workerData.transport);
    const notify = () => {
      Atomics.add(workerData.signal, 1, 1);
      parentPort.postMessage({ type: "staged" });
    };
    let handled = 0;
    parentPort.on("message", (message) => {
      if (message.type !== "fixture-stage") { handled += 1; return; }
      if (handled !== 63) throw new Error("fixture did not receive its admitted messages");
      for (let i = 0; i < 4; i += 1) returnCaptureCredit(workerData.credits, notify);
      Atomics.store(workerData.signal, 0, 1);
      Atomics.notify(workerData.signal, 0);
    });
  `, { eval: true, workerData: {
    credits, signal, transport: fileURLToPath(new URL("../runtime/transport.cjs", import.meta.url)),
  } });
  t.after(async () => { await worker.terminate(); });
  await once(worker, "online");
  let notifications = 0;
  worker.on("message", () => { notifications += 1; });
  const observations = new Map<string, number>();
  const diagnostic: CaptureDiagnostic = {
    workerBuffer: credits.buffer,
    increment(name) { observations.set(name, (observations.get(name) ?? 0) + 1); },
    setExpress() {}, transportFailed() {}, closeRequested() {},
  };
  const transport = createHttpCaptureTransport(worker, credits, diagnostic);
  const event = {
    kind: "frame-enter" as const, eventId: "fixture-event", sequence: 2n, monotonicNs: 2n,
    parentEventId: "", symbol: "fixture", exceptionType: "",
  };
  assert.equal(transport.start("first", "GET", 1n), true);
  for (let i = 0; i < 62; i += 1) assert.equal(transport.event("first", event), true);
  assert.equal(transport.start("second", "GET", 1n), false);
  worker.postMessage({ type: "fixture-stage" });
  assert.notEqual(Atomics.wait(signal, 0, 0, 5_000), "timed-out");
  assert.equal(Atomics.load(credits, 0), 4);
  assert.equal(Atomics.load(signal, 1), 1, "four credits coalesce into one diagnostic wakeup");
  assert.equal(notifications, 0);
  assert.equal(transport.start("second", "GET", 1n), true);
  assert.equal(transport.event("second", event), true);
  assert.equal(transport.route?.("second", "/fixture"), true);
  assert.equal(transport.event("second", event), false);
  assert.equal(transport.finish("first", 2n, 1n, 0), true);
  assert.equal(transport.finish("second", 2n, 1n, 0), true);
  assert.equal(transport.finish("second", 2n, 1n, 0), false);
  for (const kind of ["start", "event", "route"]) {
    assert.equal(observations.get(kind + "BeforeCreditNotification"), 1);
  }
});

test("a notification alone cannot refund capacity and unsigned credit wrap still preserves the bound", () => {
  const credits = createCaptureCredits();
  Atomics.store(credits, 0, 0xffff_ffff);
  const worker = Object.assign(new EventEmitter(), { postMessage() {} });
  const transport = createHttpCaptureTransport(worker as unknown as Worker, credits);
  for (let i = 0; i < 64; i += 1) assert.equal(transport.route?.("fixture", "/fixture"), true);
  worker.emit("message", { type: "staged" });
  assert.equal(transport.route?.("fixture", "/fixture"), false);
  Atomics.add(credits, 0, 1);
  assert.equal(Atomics.load(credits, 0), 0);
  assert.equal(transport.route?.("fixture", "/fixture"), true);
  assert.equal(transport.start("fixture", "GET", 1n), false);
});
