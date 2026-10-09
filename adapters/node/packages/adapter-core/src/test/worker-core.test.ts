import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  AgentEnvelopeSchema,
  OutcomeKind,
  RecordingEventKind,
  RecordingFinishedSchema,
  SourceBinding,
  type AgentEnvelope,
  type RecordingEvent,
  type RecordingFinished,
  type RecordingStarted,
} from "@xtrace/protocol";
import {
  MAX_HELD_EVENTS,
  capabilitySetFor,
  createRecordingAssembler,
  encodeEvent,
  encodeOutcome,
  eventKindFor,
  sourceParts,
  wireStatus,
  type InputMessage,
} from "../worker-core.js";
import type { CaptureEvent, HttpCaptureTransport, RecordingSummary } from "../runtime/transport.cjs";

const require = createRequire(import.meta.url);
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const { events } = require("../runtime/events.cjs") as typeof import("../runtime/events.cjs");
const manifest = require("../manifest.cjs") as typeof import("../manifest.cjs");

const ID = "01900000-0000-7000-8000-000000000001";
type Sent = { id: string; payload: AgentEnvelope["payload"] };

function harness() {
  const sent: Sent[] = [];
  const assembler = createRecordingAssembler(async (id, payload) => { sent.push({ id, payload }); return undefined; }, () => 5n);
  // Wire round trip: every payload must survive encode/decode as an envelope.
  const decoded = () => sent.map((entry) => entry.payload);
  return { sent, assembler, decoded };
}

const start = (extra: Partial<InputMessage> = {}): InputMessage => ({ type: "start", recordingId: ID, method: "GET", startedAtNs: 1n, ...extra });
const event = (sequence: bigint, extra: Partial<InputMessage> = {}): InputMessage => ({
  type: "event", recordingId: ID, kind: "frame-enter", eventId: `${ID}:event:${sequence}`, sequence, monotonicNs: sequence, symbol: "s", ...extra,
});
const finish = (summary: RecordingSummary, extra: Partial<InputMessage> = {}): InputMessage => ({
  type: "finish", recordingId: ID, finalSequence: 3n, durationNs: 9n, droppedEvents: 0, summary, ...extra,
});

function finished(sent: Sent[]): RecordingFinished {
  const last = sent.at(-1)!.payload;
  assert.equal(last.case, "recordingFinished");
  return last.value as RecordingFinished;
}

test("start is sent immediately by default so an interrupted request stays visible", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start());
  assert.deepEqual(sent.map((entry) => entry.payload.case), ["recordingStarted"]);
  const started = sent[0]!.payload.value as RecordingStarted;
  assert.equal(started.recordingSeq, 1n);
  assert.equal(started.method, "GET");
  assert.equal(started.urlShape, "", "raw request path is never sent as the URL shape");
  await assembler.handle(event(2n));
  assert.deepEqual(sent.map((entry) => entry.payload.case), ["recordingStarted", "eventBatch"]);
});

test("held start: start seq 1 goes first, events 2..n follow in order, route arrives with finish", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start({ holdStart: true }));
  await assembler.handle(event(2n));
  await assembler.handle(event(3n, { kind: "frame-exit" }));
  assert.equal(sent.length, 0, "nothing is sent while the route is unresolved");
  await assembler.handle(finish({ route: "/owners/{id}", outcome: "responded", httpStatus: 200 }));
  assert.deepEqual(sent.map((entry) => entry.payload.case), ["recordingStarted", "eventBatch", "eventBatch", "recordingFinished"]);
  assert.equal((sent[0]!.payload.value as RecordingStarted).matchedRouteTemplate, "/owners/{id}");
  const sequences = sent.slice(1, 3).map((entry) => (entry.payload.value as { events: RecordingEvent[] }).events[0]!.recordingSeq);
  assert.deepEqual(sequences, [2n, 3n]);
});

test("held start is released at the cap without a route, then events keep flowing in order", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start({ holdStart: true }));
  for (let sequence = 2n; sequence < BigInt(MAX_HELD_EVENTS) + 2n; sequence += 1n) await assembler.handle(event(sequence));
  assert.equal(sent.length, 0);
  const overflow = BigInt(MAX_HELD_EVENTS) + 2n;
  await assembler.handle(event(overflow));
  assert.equal(sent[0]!.payload.case, "recordingStarted");
  assert.equal((sent[0]!.payload.value as RecordingStarted).matchedRouteTemplate, "");
  const sequences = sent.slice(1).map((entry) => (entry.payload.value as { events: RecordingEvent[] }).events[0]!.recordingSeq);
  assert.equal(sequences.length, MAX_HELD_EVENTS + 1);
  assert.deepEqual(sequences, [...sequences].sort((left, right) => (left < right ? -1 : 1)));
  assert.equal(sequences[0], 2n);
  assert.equal(sequences.at(-1), overflow);
});

test("closing flushes held starts so an unfinished request reopens as partial", async () => {
  const { sent, assembler } = harness();
  await assembler.handle(start({ holdStart: true }));
  await assembler.handle(event(2n));
  await assembler.flushHeld();
  assert.deepEqual(sent.map((entry) => entry.payload.case), ["recordingStarted", "eventBatch"]);
  await assembler.flushHeld();
  assert.equal(sent.length, 2, "flush is idempotent");
});

test("finished message for all four outcomes obeys the exception-present-iff rule", async () => {
  const cases: Array<[RecordingSummary, OutcomeKind, number, boolean]> = [
    [{ outcome: "responded", httpStatus: 204 }, OutcomeKind.RESPONDED, 204, false],
    [{ outcome: "client-aborted", httpStatus: 0 }, OutcomeKind.CLIENT_ABORTED, 0, false],
    [{ outcome: "unobserved" }, OutcomeKind.UNOBSERVED, 0, false],
    [{ outcome: "exception-propagated", httpStatus: 0, thrownFromEventId: `${ID}:event:2`, exceptionType: "Error" }, OutcomeKind.EXCEPTION_PROPAGATED, 0, true],
  ];
  for (const [summary, kind, status, hasException] of cases) {
    const { sent, assembler } = harness();
    await assembler.handle(start());
    await assembler.handle(finish(summary));
    const message = finished(sent);
    const roundTrip = fromBinary(RecordingFinishedSchema, toBinary(RecordingFinishedSchema, message));
    const outcome = roundTrip.outcome!;
    assert.equal(outcome.kind, kind);
    assert.equal(outcome.httpStatus, status);
    assert.equal(outcome.exception !== undefined, hasException, "exception present iff EXCEPTION_PROPAGATED");
    if (hasException) {
      assert.equal(outcome.thrownFromEventId, `${ID}:event:2`);
      assert.equal(outcome.exception!.exceptionType, "Error");
      assert.equal(outcome.exception!.sanitizedMessage, "", "no message text is forwarded");
    } else {
      assert.equal(outcome.thrownFromEventId, "");
    }
  }
});

test("http status outside 100..=599 is not observed and unobserved always carries 0", () => {
  for (const status of [0, 1, 99, 600, 999, 1000, -5, 200.5, Number.NaN]) assert.equal(wireStatus(status, "responded"), 0, String(status));
  for (const status of [100, 200, 404, 599]) assert.equal(wireStatus(status, "responded"), status);
  assert.equal(wireStatus(200, "unobserved"), 0);
  assert.equal(encodeOutcome({ outcome: "responded", httpStatus: 700 }).httpStatus, 0);
});

test("a real context carries its limitations and the root throw into the finished message", async () => {
  const captured: { events: CaptureEvent[]; summary?: RecordingSummary; final?: bigint } = { events: [] };
  const transport: HttpCaptureTransport = {
    start: () => true,
    event: (_id, captureEvent) => { captured.events.push(captureEvent); return true; },
    finish: (_id, final, _d, _dropped, summary) => { captured.final = final; if (summary) captured.summary = summary; return true; },
    onFailure() {},
    close() {},
  };
  context.setCaptureProfile({
    limitations: manifest.effectiveLimitations(new Set(["node-http", "async-context"])),
    holdStart: false,
  });
  try {
    const ctx = context.createContext("GET", 1n);
    context.runInContext(ctx, () => {
      const enter = context.recordEvent(ctx, transport, events.frameEnter("root"));
      const thrown = events.frameThrow("root", enter, new Error("secret-canary"));
      ctx.exceptionType = thrown.exceptionType ?? "";
      ctx.threw = true;
      ctx.thrownFromEventId = context.recordEvent(ctx, transport, thrown);
      ctx.outcome = "exception-propagated";
    });
    context.finishContext(ctx, transport);
    const { sent, assembler } = harness();
    await assembler.handle(start());
    await assembler.handle(finish(captured.summary!, { finalSequence: captured.final! }));
    const message = finished(sent);
    assert.ok(message.unsupportedCapabilityCodes.includes("route_unavailable"));
    assert.ok(message.unsupportedCapabilityCodes.includes("values_unavailable"));
    assert.ok(message.unsupportedCapabilityCodes.includes("source_locations_unavailable"));
    assert.ok(!message.unsupportedCapabilityCodes.includes("http_root_unavailable"), "installed modules do not add their absence codes");
    assert.equal(message.outcome?.thrownFromEventId, `${ctx.id}:event:3`);
    assert.equal(message.outcome?.exception?.exceptionType, "Error");
    assert.ok(!JSON.stringify(message, (_k, v) => (typeof v === "bigint" ? String(v) : v)).includes("secret-canary"));
  } finally {
    context.setCaptureProfile({ limitations: [], holdStart: false });
  }
});

test("a module that failed to install adds its absence limitations to the profile", () => {
  const without = manifest.effectiveLimitations(new Set(["async-context"]));
  assert.ok(without.includes("http_root_unavailable"));
  assert.ok(without.includes("http_status_unavailable"));
});

test("interaction kind decides the event kind; no process kind exists to mis-encode", () => {
  const db = { kind: "database" as const, driver: "pg", method: "query", summary: "select ?" };
  const http = { kind: "outbound-http" as const, driver: "http", method: "GET", summary: "GET /x", host: "h", port: 80, statusCode: 200 };
  assert.equal(eventKindFor({ kind: "interaction-start", interaction: db }), RecordingEventKind.DATABASE_START);
  assert.equal(eventKindFor({ kind: "interaction-end", interaction: db }), RecordingEventKind.DATABASE_END);
  assert.equal(eventKindFor({ kind: "interaction-start", interaction: http }), RecordingEventKind.OUTBOUND_HTTP_START);
  assert.equal(eventKindFor({ kind: "interaction-end", interaction: http }), RecordingEventKind.OUTBOUND_HTTP_END);
  assert.throws(() => eventKindFor({ kind: "nope" as never }));
  const encoded = encodeEvent({ type: "event", kind: "interaction-start", eventId: "e", sequence: 2n, interaction: http, symbol: "http.GET" });
  assert.equal(encoded.kind, RecordingEventKind.OUTBOUND_HTTP_START);
  assert.equal(encoded.interaction?.statusCode, 200);
  assert.equal(encoded.interaction?.sanitizedShape, "GET /x");
});

test("source is encoded with its binding; inconsistent source is dropped, never sent half-claimed", () => {
  const hash = "ab".repeat(32);
  const base = { path: "src/app.ts", startLine: 3, startColumn: 1, endLine: 3, endColumn: 9 };
  const verified = encodeEvent({ type: "event", kind: "frame-enter", eventId: "e", sequence: 2n, source: { ...base, binding: "verified", contentHash: hash } });
  assert.equal(verified.sourceBinding, SourceBinding.VERIFIED);
  assert.equal(verified.source?.contentHash.length, 32);
  const unattested = sourceParts({ ...base, binding: "observed-unattested", contentHash: hash });
  assert.equal(unattested?.binding, SourceBinding.OBSERVED_UNATTESTED);
  const generated = sourceParts({ ...base, binding: "source-map-absent", contentHash: "" });
  assert.equal(generated?.binding, SourceBinding.SOURCE_MAP_ABSENT);
  assert.equal(generated?.source.contentHash.length, 0, "generated path may carry an empty hash");
  for (const bad of ["", "xyz", "AB".repeat(32), "ab".repeat(31)]) {
    const dropped = encodeEvent({ type: "event", kind: "frame-enter", eventId: "e", sequence: 2n, source: { ...base, binding: "verified", contentHash: bad } });
    assert.equal(dropped.source, undefined, `bad hash ${JSON.stringify(bad)} drops the source`);
    assert.equal(dropped.sourceBinding, SourceBinding.UNSPECIFIED, "no binding without a source");
  }
  assert.equal(sourceParts({ ...base, binding: "verified", path: "", contentHash: hash }), undefined);
});

test("gap, async parent and exception payloads are encoded", () => {
  const gap = encodeEvent({
    type: "event", kind: "gap", eventId: "g", sequence: 4n, symbol: "gap.queue-full",
    gap: { reason: "queue-full", count: 2, firstSequence: 4n, lastSequence: 5n },
  });
  assert.equal(gap.kind, RecordingEventKind.GAP);
  assert.equal(gap.gap?.count, 2n);
  assert.equal(gap.gap?.firstRecordingSeq, 4n);
  const link = encodeEvent({ type: "event", kind: "async-link", eventId: "a", sequence: 5n, parentEventId: "p", asyncParentEventId: "q", symbol: "async.link" });
  assert.equal(link.asyncParentEventId, "q");
  const exception = encodeEvent({ type: "event", kind: "exception", eventId: "x", sequence: 6n, exception: { type: "TypeError", message: "" }, symbol: "TypeError" });
  assert.equal(exception.exception?.exceptionType, "TypeError");
});

test("capability set advertises exactly the named, known capabilities", () => {
  assert.deepEqual(capabilitySetFor(["http.server.request_root", "unknown.thing"]).capabilities.map((c) => c.name), ["http.server.request_root"]);
  assert.deepEqual(capabilitySetFor([]).capabilities, []);
});

test("worker output decodes with the shared protocol and matches the shape of the outcome golden", async () => {
  const path = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../../schema/fixtures/xtp-agent/recording-finished-outcome-exception.json");
  const golden = JSON.parse(await readFile(path, "utf8")) as { bytes_hex: string };
  const envelope = fromBinary(AgentEnvelopeSchema, Buffer.from(golden.bytes_hex, "hex"));
  assert.equal(envelope.payload.case, "recordingFinished");
  const goldenOutcome = (envelope.payload.value as RecordingFinished).outcome!;
  assert.equal(goldenOutcome.kind, OutcomeKind.EXCEPTION_PROPAGATED);
  const mine = encodeOutcome({ outcome: "exception-propagated", httpStatus: 500, thrownFromEventId: "e-3", exceptionType: "app.NotFoundException" });
  assert.equal(mine.kind, goldenOutcome.kind);
  assert.equal(mine.httpStatus, goldenOutcome.httpStatus);
  assert.equal(mine.thrownFromEventId, goldenOutcome.thrownFromEventId);
  assert.equal(mine.exception?.exceptionType, goldenOutcome.exception?.exceptionType);
});
