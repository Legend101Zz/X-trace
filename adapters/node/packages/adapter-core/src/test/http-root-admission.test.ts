import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import test from "node:test";
import type { Worker } from "node:worker_threads";
import { installHttpCapture, wrapRequestListener } from "../http-capture.cjs";
import { createCaptureCredits, createHttpCaptureTransport, MAX_IN_FLIGHT_MESSAGES,
  type RecordingSummary } from "../runtime/transport.cjs";
import type { InputMessage } from "../worker-core.js";

function captureRequestAtOccupancy(occupied: number): InputMessage[] {
  const posts: InputMessage[] = [];
  const worker = Object.assign(new EventEmitter(), {
    postMessage(message: InputMessage) { posts.push(message); },
    ref() {},
  });
  const transport = createHttpCaptureTransport(worker as unknown as Worker, createCaptureCredits());
  for (let i = 0; i < occupied; i += 1) {
    assert.equal(transport.route?.("fixture-queued-work", "/products"), true);
  }
  installHttpCapture(transport);
  const request = { method: "GET" } as IncomingMessage;
  const response = Object.assign(new EventEmitter(), { statusCode: 200, writableFinished: true });
  let calls = 0;
  wrapRequestListener(() => { calls += 1; })(request, response as unknown as ServerResponse);
  assert.equal(calls, 1, "the same application handler runs at every capture occupancy");
  response.emit("finish");
  response.emit("close");
  return posts.slice(occupied);
}

function assertRespondedFinish(message: InputMessage, recordingId: string | undefined,
  finalSequence: bigint, droppedEvents: number): void {
  assert.equal(message.type, "finish");
  assert.equal(message.recordingId, recordingId);
  assert.equal(message.finalSequence, finalSequence);
  assert.equal(message.droppedEvents, droppedEvents);
  const summary: RecordingSummary | undefined = message.summary;
  assert.equal(summary?.outcome, "responded");
  assert.equal(summary?.httpStatus, 200);
}

test("capture pressure distinguishes a retained root, a root lost after admission, and refusal", () => {
  const withRoot = captureRequestAtOccupancy(MAX_IN_FLIGHT_MESSAGES - 3);
  assert.deepEqual(withRoot.map(({ type }) => type), ["start", "event", "finish"]);
  const [started, root, finished] = withRoot;
  assert.ok(started && root && finished);
  assert.equal(root.recordingId, started.recordingId);
  assert.equal(root.kind, "frame-enter");
  assert.equal(root.symbol, "node:http.Server.request");
  assert.equal(root.sequence, 2n);
  assert.equal(root.parentEventId, "");
  assertRespondedFinish(finished, started.recordingId, 2n, 2);

  const withoutRoot = captureRequestAtOccupancy(MAX_IN_FLIGHT_MESSAGES - 2);
  assert.deepEqual(withoutRoot.map(({ type }) => type), ["start", "finish"]);
  const [admitted, replied] = withoutRoot;
  assert.ok(admitted && replied);
  assertRespondedFinish(replied, admitted.recordingId, 1n, 3);

  assert.deepEqual(captureRequestAtOccupancy(MAX_IN_FLIGHT_MESSAGES - 1), []);
});
