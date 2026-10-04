import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { once } from "node:events";
import { createRequire } from "node:module";
import * as http from "node:http";
import test from "node:test";
import type { Worker } from "node:worker_threads";
import type { CaptureEvent, HttpCaptureTransport } from "../http-capture.cjs";

const require = createRequire(import.meta.url);
const { installHttpCapture, createHttpCaptureTransport, wrapRequestListener } = require("../http-capture.cjs") as typeof import("../http-capture.cjs");

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
  const bounded = createHttpCaptureTransport(worker as unknown as Worker);
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
