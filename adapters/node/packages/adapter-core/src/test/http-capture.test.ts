import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { once } from "node:events";
import { createRequire } from "node:module";
import * as http from "node:http";
import test from "node:test";
import type { Worker } from "node:worker_threads";
import type { CaptureEvent, HttpCaptureTransport } from "../http-capture.cjs";

const require = createRequire(import.meta.url);
const {
  installHttpCapture,
  createHttpCaptureTransport,
  installProcessShutdownHooks,
  wrapRequestListener,
} = require("../http-capture.cjs") as typeof import("../http-capture.cjs");
const {
  CONTROL_DRAIN_INDEX,
  CONTROL_STAGED_INDEX,
  DEFAULT_MAX_ACTIVE_RECORDINGS,
  DEFAULT_MAX_IN_FLIGHT_MESSAGES,
  SHARED_CONTROL_WORDS,
} = require("../runtime/transport.cjs") as typeof import("../runtime/transport.cjs");

class CapturedTransport implements HttpCaptureTransport {
  readonly recordings = new Map<string, { method: string; events: CaptureEvent[]; finish?: { finalSequence: bigint; durationNs: bigint; droppedEvents: number } }>();
  failure?: () => void;
  acceptEvents = true;

  start(recordingId: string, method: string, _startedAtNs: bigint): boolean {
    this.recordings.set(recordingId, { method, events: [] });
    return true;
  }
  event(recordingId: string, event: CaptureEvent): boolean {
    if (!this.acceptEvents) return false;
    this.recordings.get(recordingId)?.events.push(event);
    return true;
  }
  finish(recordingId: string, finalSequence: bigint, durationNs: bigint, droppedEvents: number): boolean {
    const recording = this.recordings.get(recordingId);
    if (!recording) return false;
    recording.finish = { finalSequence, durationNs, droppedEvents };
    return true;
  }
  onFailure(callback: () => void): void { this.failure = callback; }
  close(): void {}
}

test("native HTTP callback capture keeps concurrent async requests correlated and omits request values", async () => {
  const transport = new CapturedTransport();
  installHttpCapture(transport);
  const server = http.createServer(async (_request, response) => {
    await new Promise((resolve) => setTimeout(resolve, 8));
    response.statusCode = 200;
    response.end("ok");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const canary = "private-canary-7dd6";
  await Promise.all([
    fetch(`http://127.0.0.1:${address.port}/${canary}?q=${canary}`, { method: "POST", headers: { "x-private": canary }, body: canary }),
    fetch(`http://127.0.0.1:${address.port}/second?q=${canary}`, { method: "POST", headers: { "x-private": canary }, body: canary }),
  ]);
  await new Promise((resolve) => setTimeout(resolve, 10));
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));

  assert.equal(transport.recordings.size, 2);
  const recordings = [...transport.recordings.values()];
  assert.deepEqual(recordings.map((recording) => recording.method), ["POST", "POST"]);
  for (const recording of recordings) {
    assert.deepEqual(recording.events.map((event) => event.kind), ["frame-enter", "frame-exit", "response-finish"]);
    assert.ok(recording.finish);
    assert.equal(recording.finish.droppedEvents, 0);
    assert.ok(recording.finish.durationNs > 0n);
    assert.ok(recording.events.some((event) => event.symbol === "node:http.response.finish"));
  }
  assert.equal(JSON.stringify([...transport.recordings], (_key, value: unknown) => typeof value === "bigint" ? value.toString() : value).includes(canary), false);
});

test("CommonJS and ESM callers both use the same patched native createServer boundary", async () => {
  const transport = new CapturedTransport();
  installHttpCapture(transport);
  const cjsHttp = require("node:http") as typeof http;
  const servers = [
    cjsHttp.createServer((_request, response) => response.end("cjs")),
    http.createServer((_request, response) => response.end("esm")),
  ];
  for (const server of servers) {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await fetch(`http://127.0.0.1:${address.port}/`);
    await new Promise((resolve) => setTimeout(resolve, 4));
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
  assert.equal(transport.recordings.size, 2);
  assert.ok([...transport.recordings.values()].every((recording) => recording.events.some((event) => event.kind === "response-finish")));
});

test("synchronous application errors stay unchanged and record only a safe error type", () => {
  const transport = new CapturedTransport();
  installHttpCapture(transport);
  const canary = "private-exception-canary-93b1";
  const original = new Error(canary);
  const response = new EventEmitter();
  const listener = wrapRequestListener(() => { throw original; });
  assert.throws(
    () => listener.call({} as http.Server, { method: "GET" } as http.IncomingMessage, response as unknown as http.ServerResponse),
    (error: unknown) => error === original,
  );
  response.emit("close");
  const recording = [...transport.recordings.values()][0];
  assert.ok(recording);
  assert.deepEqual(recording.events.map((event) => event.kind), ["frame-enter", "frame-throw", "response-close"]);
  assert.ok(recording.events.some((event) => event.exceptionType === "Error"));
  assert.equal(JSON.stringify(recording.events, (_key, value: unknown) => typeof value === "bigint" ? value.toString() : value).includes(canary), false);
});

test("a real response close is distinct and queue saturation is carried as a dropped-event count", async () => {
  const transport = new CapturedTransport();
  installHttpCapture(transport);
  const server = http.createServer((_request, response) => response.destroy());
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  await assert.rejects(fetch(`http://127.0.0.1:${address.port}/closed`));
  await new Promise((resolve) => setTimeout(resolve, 5));
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  const partial = [...transport.recordings.values()][0];
  assert.ok(partial?.events.some((event) => event.kind === "response-close"));

  class DelayedWorker extends EventEmitter {
    readonly sent: unknown[] = [];
    postMessage(message: unknown): void { this.sent.push(message); }
  }
  const worker = new DelayedWorker();
  const bounded = createHttpCaptureTransport(worker as unknown as Worker, {
    maxInFlightMessages: 64,
    maxActiveRecordings: 64,
  });
  assert.equal(bounded.start("01900000-0000-7000-8000-000000000001", "GET", 1n), true);
  for (let index = 0; index < 62; index += 1) {
    assert.equal(bounded.event("01900000-0000-7000-8000-000000000001", {
      kind: "frame-enter", eventId: `e${index}`, sequence: BigInt(index + 2), monotonicNs: 2n,
      parentEventId: "", symbol: "node:http.createServer.listener", exceptionType: "",
    }), true);
  }
  assert.equal(bounded.event("01900000-0000-7000-8000-000000000001", {
    kind: "frame-exit", eventId: "overflow", sequence: 64n, monotonicNs: 3n,
    parentEventId: "", symbol: "node:http.createServer.listener", exceptionType: "",
  }), false);
  assert.equal(bounded.finish("01900000-0000-7000-8000-000000000001", 63n, 10n, 1), true);
  const terminal = worker.sent.at(-1) as { type: string; droppedEvents: number };
  assert.equal(terminal.type, "finish");
  assert.equal(terminal.droppedEvents, 1);
});

test("default transport burst capacity admits concurrent bursts while remaining bounded and updating shared credits", () => {
  class BurstWorker extends EventEmitter {
    readonly sent: Array<Record<string, unknown>> = [];
    unrefCalled = false;
    refCalled = false;
    postMessage(message: Record<string, unknown>): void { this.sent.push(message); }
    ref(): void { this.refCalled = true; }
    unref(): void { this.unrefCalled = true; }
  }
  const sharedBuffer = new SharedArrayBuffer(SHARED_CONTROL_WORDS * Int32Array.BYTES_PER_ELEMENT);
  const sharedControl = new Int32Array(sharedBuffer);
  const worker = new BurstWorker();
  const transport = createHttpCaptureTransport(worker as unknown as Worker, { sharedControl });

  assert.ok(DEFAULT_MAX_ACTIVE_RECORDINGS >= 128);
  assert.ok(DEFAULT_MAX_IN_FLIGHT_MESSAGES >= 1024);

  // Admit a concurrent burst exceeding the old 64 limit without main-thread message callbacks.
  for (let i = 0; i < 80; i += 1) {
    const id = `01900000-0000-7000-8000-${String(i).padStart(12, "0")}`;
    assert.equal(transport.start(id, "GET", BigInt(i + 1), true), true, `start ${i} admitted`);
    for (let ev = 0; ev < 8; ev += 1) {
      assert.equal(transport.event(id, {
        kind: "frame-enter",
        eventId: `${id}:${ev}`,
        sequence: BigInt(ev + 2),
        monotonicNs: BigInt(ev + 2),
        parentEventId: "",
        symbol: "express.handler",
        exceptionType: "",
      }), true);
    }
    assert.equal(transport.route?.(id, "/store/products"), true);
    assert.equal(transport.finish(id, 10n, 50n, 0, { route: "/store/products", httpStatus: 200, outcome: "responded" }), true);
    // Worker atomically retires staged messages via SharedArrayBuffer without posting to main thread.
    Atomics.add(sharedControl, CONTROL_STAGED_INDEX, 11);
  }
  assert.equal(transport.rejectedStarts?.(), 0);

  // Fill active recording cap to verify strict bounding and honest rejection counting.
  for (let i = 0; i < DEFAULT_MAX_ACTIVE_RECORDINGS; i += 1) {
    const id = `01900000-0001-7000-8000-${String(i).padStart(12, "0")}`;
    assert.equal(transport.start(id, "GET", 1n), true);
    Atomics.add(sharedControl, CONTROL_STAGED_INDEX, 1);
  }
  assert.equal(transport.start("01900000-0002-7000-8000-000000000001", "GET", 1n), false);
  assert.equal(transport.rejectedStarts?.(), 1);
});

test("process.exit hook runs synchronous drain once, respects re-entrant exit, and bounds timeout", () => {
  class SyncDrainWorker extends EventEmitter {
    readonly sent: Array<Record<string, unknown>> = [];
    constructor(private readonly shared: Int32Array, private readonly completeImmediately: boolean) { super(); }
    postMessage(message: Record<string, unknown>): void {
      this.sent.push(message);
      if (message.type === "close" && this.completeImmediately) {
        Atomics.store(this.shared, CONTROL_DRAIN_INDEX, 1);
        Atomics.notify(this.shared, CONTROL_DRAIN_INDEX);
      }
    }
    ref(): void {}
    unref(): void {}
  }

  // Case 1: complete drain before native exit, plus re-entrant process.exit inside exit handler.
  const buf1 = new SharedArrayBuffer(SHARED_CONTROL_WORDS * Int32Array.BYTES_PER_ELEMENT);
  const ctrl1 = new Int32Array(buf1);
  const w1 = new SyncDrainWorker(ctrl1, true);
  const t1 = createHttpCaptureTransport(w1 as unknown as Worker, { sharedControl: ctrl1, drainTimeoutMs: 250 });
  assert.equal(t1.start("01900000-0000-7000-8000-000000000010", "GET", 1n), true);
  assert.equal(t1.finish("01900000-0000-7000-8000-000000000010", 2n, 5n, 0), true);

  const originalExit = process.exit;
  const exitCalls: Array<number | string | null | undefined> = [];
  process.exit = ((code?: number | string | null): never => {
    exitCalls.push(code);
    if (exitCalls.length === 1) {
      // Simulate a re-entrant process.exit() triggered by an exit hook.
      process.exit(99);
    }
    return undefined as never;
  }) as typeof process.exit;

  const dispose1 = installProcessShutdownHooks(t1, { drainTimeoutMs: 200 });
  try {
    process.exit(0);
    assert.deepEqual(exitCalls, [0, 99]);
    assert.equal(w1.sent.filter((m) => m.type === "close").length, 1, "close posted exactly once across re-entrant exit");
  } finally {
    dispose1();
    process.exit = originalExit;
  }

  // Case 2: stalled worker respects bounded timeout without hanging.
  const buf2 = new SharedArrayBuffer(SHARED_CONTROL_WORDS * Int32Array.BYTES_PER_ELEMENT);
  const ctrl2 = new Int32Array(buf2);
  const w2 = new SyncDrainWorker(ctrl2, false);
  const t2 = createHttpCaptureTransport(w2 as unknown as Worker, { sharedControl: ctrl2, drainTimeoutMs: 25 });
  assert.equal(t2.start("01900000-0000-7000-8000-000000000011", "GET", 1n), true);
  const startedAt = Date.now();
  assert.equal(t2.drainSync?.(25), false);
  assert.ok(Date.now() - startedAt < 500, "stalled drainSync returned within bounded deadline");
});

test("SIGTERM and SIGINT hooks drain cleanly without app handlers and flush non-destructively with app handlers", async () => {
  // Case 1: App has its own SIGTERM listener -> non-blocking flush only, never swallows or re-signals.
  const flushed: string[] = [];
  const signalsRaised: NodeJS.Signals[] = [];
  let closed = false;
  const appMockTransport: HttpCaptureTransport = {
    start: () => true,
    event: () => true,
    finish: () => true,
    onFailure() {},
    flush() { flushed.push("flushed"); },
    drainAsync: async () => { closed = true; return true; },
    close() { closed = true; },
  };
  let appListenerRan = false;
  const appListener = () => { appListenerRan = true; };
  const disposeApp = installProcessShutdownHooks(appMockTransport, {
    drainTimeoutMs: 100,
    onExitSignal: (sig) => { signalsRaised.push(sig); },
  });
  process.on("SIGTERM", appListener);
  try {
    process.emit("SIGTERM", "SIGTERM");
    assert.deepEqual(flushed, ["flushed"]);
    assert.equal(appListenerRan, true);
    assert.equal(closed, false, "app-owned signal lifecycle must not close transport prematurely");
    assert.deepEqual(signalsRaised, []);
  } finally {
    process.off("SIGTERM", appListener);
    disposeApp();
  }

  // Case 2: App has NO SIGTERM listener -> bounded drainAsync completes before re-raising signal.
  class AsyncDrainWorker extends EventEmitter {
    readonly sent: Array<Record<string, unknown>> = [];
    postMessage(message: Record<string, unknown>): void {
      this.sent.push(message);
      if (message.type === "close") {
        setTimeout(() => this.emit("message", { type: "drained" }), 5);
      }
    }
    ref(): void {}
    unref(): void {}
  }
  const worker = new AsyncDrainWorker();
  const t2 = createHttpCaptureTransport(worker as unknown as Worker, { drainTimeoutMs: 200 });
  const raised: NodeJS.Signals[] = [];
  let resolveSignal!: () => void;
  const signalDone = new Promise<void>((resolve) => { resolveSignal = resolve; });
  const disposeNoApp = installProcessShutdownHooks(t2, {
    drainTimeoutMs: 200,
    onExitSignal: (sig) => {
      raised.push(sig);
      resolveSignal();
    },
  });
  try {
    process.emit("SIGTERM", "SIGTERM");
    await signalDone;
    assert.deepEqual(raised, ["SIGTERM"]);
    assert.equal(worker.sent.filter((m) => m.type === "close").length, 1);
  } finally {
    disposeNoApp();
  }
});
