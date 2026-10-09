import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import test from "node:test";
import type { AgentEnvelope, RecordingEvent, RecordingStarted } from "@xtrace/protocol";
import { createRecordingAssembler, type InputMessage } from "../worker-core.js";

const require = createRequire(import.meta.url);
const { createHttpCaptureTransport } = require("../runtime/transport.cjs") as typeof import("../runtime/transport.cjs");

const ID = "01900000-0000-7000-8000-000000000001";
type Sent = { id: string; payload: AgentEnvelope["payload"] };

function harness() {
  const sent: Sent[] = [];
  const assembler = createRecordingAssembler(async (id, payload) => { sent.push({ id, payload }); return undefined; }, () => 5n);
  return { sent, assembler };
}
const start = (): InputMessage => ({ type: "start", recordingId: ID, method: "GET", startedAtNs: 1n, holdStart: true });
const event = (sequence: bigint): InputMessage => ({
  type: "event", recordingId: ID, kind: "frame-enter", eventId: `${ID}:event:${sequence}`, sequence, monotonicNs: sequence, symbol: "s",
});
const route = (value: string): InputMessage => ({ type: "route", recordingId: ID, route: value });
const templateOf = (sent: Sent[]) => (sent[0]!.payload.value as RecordingStarted).matchedRouteTemplate;

test("a route message releases the held start with the template, then held events follow in sequence order", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start());
  await assembler.handle(event(2n));
  await assembler.handle(event(3n));
  assert.equal(sent.length, 0);
  await assembler.handle(route("/owners/:id"));
  assert.deepEqual(sent.map((entry) => entry.payload.case), ["recordingStarted", "eventBatch", "eventBatch"]);
  assert.equal(templateOf(sent), "/owners/:id");
  const sequences = sent.slice(1).map((entry) => (entry.payload.value as { events: RecordingEvent[] }).events[0]!.recordingSeq);
  assert.deepEqual(sequences, [2n, 3n]);
  await assembler.handle(event(4n));
  assert.equal(sent.length, 4, "events after the release flow straight through");
});

test("the first route announcement wins and a later one changes nothing", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start());
  await assembler.handle(route("/first"));
  await assembler.handle(route("/second"));
  assert.equal(sent.length, 1);
  assert.equal(templateOf(sent), "/first");
});

test("a route after the start already went out is ignored and the finish says route_unavailable", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start());
  await assembler.flushHeld();
  assert.equal(templateOf(sent), "");
  await assembler.handle(route("/late"));
  assert.equal(sent.length, 1, "nothing new is sent for a late route");
  await assembler.handle({ type: "finish", recordingId: ID, finalSequence: 2n, durationNs: 9n, droppedEvents: 0, summary: { route: "/late", outcome: "responded", httpStatus: 200, limitations: [] } });
  const last = sent.at(-1)!.payload;
  assert.equal(last.case, "recordingFinished");
  assert.ok((last.value as { unsupportedCapabilityCodes: string[] }).unsupportedCapabilityCodes.includes("route_unavailable"));
  assert.equal(templateOf(sent), "", "the start never claims a route it did not carry");
});

test("an empty route message is ignored", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start());
  await assembler.handle(route(""));
  assert.equal(sent.length, 0);
});

test("transport.route posts a route message and refuses at the in-flight limit", () => {
  const posted: Array<Record<string, unknown>> = [];
  const worker = Object.assign(new EventEmitter(), { postMessage(message: Record<string, unknown>) { posted.push(message); } });
  const transport = createHttpCaptureTransport(worker as never);
  assert.equal(transport.route?.(ID, "/owners/:id"), true);
  assert.deepEqual(posted.at(-1), { type: "route", recordingId: ID, route: "/owners/:id" });
  // Each accepted message stays pending until the worker stages it; fill the 64-message window.
  let accepted = 1;
  while (transport.route?.(ID, "/x") && accepted < 200) accepted += 1;
  assert.equal(accepted, 64, "route() is bounded like event()");
  assert.equal(transport.route?.(ID, "/y"), false);
});
