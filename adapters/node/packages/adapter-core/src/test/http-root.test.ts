import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import * as http from "node:http";
import * as https from "node:https";
import { createRequire } from "node:module";
import test from "node:test";
import type { CaptureEvent, HttpCaptureTransport, RecordingSummary } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const { installHttpCapture } = require("../http-capture.cjs") as typeof import("../http-capture.cjs");

interface Recorded { method: string; events: CaptureEvent[]; summary?: RecordingSummary; finalSequence?: bigint; dropped?: number }

class Transport implements HttpCaptureTransport {
  readonly recordings = new Map<string, Recorded>();
  start(id: string, method: string): boolean { this.recordings.set(id, { method, events: [] }); return true; }
  event(id: string, event: CaptureEvent): boolean { this.recordings.get(id)?.events.push(event); return true; }
  finish(id: string, finalSequence: bigint, _d: bigint, dropped: number, summary?: RecordingSummary): boolean {
    const recording = this.recordings.get(id);
    if (!recording) return false;
    Object.assign(recording, { finalSequence, dropped, ...(summary ? { summary } : {}) });
    return true;
  }
  onFailure(): void {}
  close(): void {}
  list(): Recorded[] { return [...this.recordings.values()]; }
}

async function listen(server: http.Server): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return address.port;
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 15));
const closeServer = (server: http.Server) => new Promise<void>((resolve, reject) => { server.closeAllConnections(); server.close((error) => error ? reject(error) : resolve()); });

test("server.on('request') and new http.Server are each captured exactly once with status", async () => {
  const transport = new Transport();
  installHttpCapture(transport);
  const canary = "query-canary-5f2a";
  const viaOn = http.createServer();
  viaOn.on("request", (request, response) => { response.statusCode = request.url?.startsWith("/missing") ? 404 : 200; response.end("x"); });
  const viaCtor = new http.Server((_request, response) => { response.statusCode = 500; response.end("boom"); });
  for (const [server, path] of [[viaOn, "/ok"], [viaOn, "/missing/1"], [viaCtor, "/ctor"]] as const) {
    const port = await listen(server);
    const result = await fetch(`http://127.0.0.1:${port}${path}?secret=${canary}`);
    await result.text();
    await settle();
    await closeServer(server);
  }
  const recordings = transport.list();
  assert.equal(recordings.length, 3);
  assert.deepEqual(recordings.map((r) => [r.summary?.httpStatus, r.summary?.outcome]), [
    [200, "responded"], [404, "responded"], [500, "responded"],
  ]);
  for (const recording of recordings) {
    assert.deepEqual(recording.events.map((event) => event.kind), ["frame-enter", "frame-exit", "response-finish"]);
  }
  assert.equal(JSON.stringify(recordings, (_k, v: unknown) => typeof v === "bigint" ? v.toString() : v).includes(canary), false);
});

test("a client abort records client-aborted, not responded", async () => {
  const transport = new Transport();
  installHttpCapture(transport);
  const server = http.createServer(() => { /* never answers */ });
  const port = await listen(server);
  const controller = new AbortController();
  const pending = fetch(`http://127.0.0.1:${port}/slow`, { signal: controller.signal }).catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 40));
  controller.abort();
  await pending;
  await settle();
  await closeServer(server);
  const [recording] = transport.list();
  assert.ok(recording);
  assert.equal(recording.summary?.outcome, "client-aborted");
  assert.equal(recording.summary?.httpStatus, 0);
  assert.ok(recording.events.some((event) => event.kind === "response-close"));
});

test("50 concurrent keep-alive requests produce 50 distinct recordings with contiguous sequence", async () => {
  const transport = new Transport();
  installHttpCapture(transport);
  const server = http.createServer(async (_request, response) => {
    await new Promise((resolve) => setTimeout(resolve, 2));
    response.end("ok");
  });
  const port = await listen(server);
  const agent = new http.Agent({ keepAlive: true, maxSockets: 4 });
  const get = (path: string) => new Promise<void>((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path, agent }, (response) => { response.resume(); response.on("end", resolve); }).on("error", reject);
  });
  await Promise.all(Array.from({ length: 50 }, (_unused, index) => get(`/r${index}`)));
  await settle();
  agent.destroy();
  await closeServer(server);
  const recordings = transport.list();
  assert.equal(recordings.length, 50);
  assert.equal(new Set(transport.recordings.keys()).size, 50);
  for (const recording of recordings) {
    assert.deepEqual(recording.events.map((event) => event.sequence), [2n, 3n, 4n]);
    assert.equal(recording.finalSequence, 4n);
  }
});

test("https servers get the same root at the shared emit seam", () => {
  const transport = new Transport();
  installHttpCapture(transport);
  const secure = https.createServer({});
  let handled = 0;
  secure.on("request", (_request, response) => { handled += 1; (response as unknown as EventEmitter).emit("finish"); });
  const response = Object.assign(new EventEmitter(), { statusCode: 204, writableFinished: true });
  secure.emit("request", { method: "DELETE", url: "/things/1?x=y" }, response);
  assert.equal(handled, 1);
  const [recording] = transport.list();
  assert.equal(recording?.method, "DELETE");
  assert.equal(recording?.summary?.httpStatus, 204);
});

test("a request already rooted is not recorded twice and unknown methods map to empty", () => {
  const transport = new Transport();
  installHttpCapture(transport);
  const server = http.createServer();
  server.on("request", () => undefined);
  server.on("request", () => undefined);
  const request = { method: "BREW", url: "/pot" };
  const response = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true });
  server.emit("request", request, response);
  server.emit("request", request, response);
  assert.equal(transport.list().length, 1);
  assert.equal(transport.list()[0]?.method, "");
});
