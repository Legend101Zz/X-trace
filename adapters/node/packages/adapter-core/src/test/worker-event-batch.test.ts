import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { MessageChannel, receiveMessageOnPort, type Worker } from "node:worker_threads";
import { create, toBinary } from "@bufbuild/protobuf";
import { blake3 } from "hash-wasm";
import { AgentEnvelopeSchema, RecordingEventKind, type AgentEnvelope } from "@xtrace/protocol";
import { createCaptureCredits, createHttpCaptureTransport } from "../runtime/transport.cjs";
import { createRecordingAssembler, HOLD_START_MS, type InputMessage, type SendFn } from "../worker-core.js";
import { createWorkerDelivery } from "../worker-delivery.js";
import { noteFinishProgress, noteFinishWork, readFinishProgress, type FinishBoundary, type FinishWork } from "../runtime/finish-progress.cjs";

const A = "01900000-0000-7000-8000-000000000001";
const B = "01900000-0000-7000-8000-000000000002";

const start = (id = A, holdStart = false): InputMessage => ({ type: "start", recordingId: id, method: "GET", holdStart });
const event = (sequence: number, id = A): InputMessage => ({
  type: "event", recordingId: id, eventId: `${id}:event:${sequence}`, sequence: BigInt(sequence),
  monotonicNs: BigInt(sequence), kind: "frame-enter", symbol: "handler",
});
const finish = (finalSequence: number, id = A): InputMessage =>
  ({ type: "finish", recordingId: id, finalSequence: BigInt(finalSequence) });
const close: InputMessage = { type: "close" };

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((pass, fail) => { resolve = pass; reject = fail; });
  return { resolve, reject, promise };
}

type Payload = AgentEnvelope["payload"];

function wireEvents(payload: Payload): bigint[] {
  assert.equal(payload.case, "eventBatch");
  return payload.value.events.map((value) => value.recordingSeq);
}

function createHarness(
  send: SendFn, maxBatchEvents = 64,
  fitsEnvelope: NonNullable<Parameters<typeof createRecordingAssembler>[3]>["fitsEnvelope"] = () => true,
  receivePending?: () => InputMessage | undefined,
  finishProgress?: (boundary: "received" | "dispatched") => void,
  activeWork?: (type: FinishWork) => void,
) {
  const assembler = createRecordingAssembler(send, () => 5n, undefined, { maxBatchEvents, fitsEnvelope });
  const done = deferred();
  const failed = deferred();
  let credits = 0;
  const stagedFolds: number[] = [];
  const delivery = createWorkerDelivery(assembler, {
    ...(receivePending ? { receivePending } : {}),
    ...(finishProgress ? { finishProgress } : {}),
    ...(activeWork ? { activeWork } : {}),
    staged: () => { credits += 1; },
    routeFoldStaged: (events) => { stagedFolds.push(events); },
    close: async () => done.resolve(),
    fail: failed.resolve,
  });
  return { assembler, delivery, done: done.promise, failed: failed.promise, credits: () => credits, stagedFolds };
}

test("queued adjacent events batch in wire order across interleaved recordings and route, gap and finish boundaries", async () => {
  const startAck = deferred();
  const sent: Array<{ id: string; payload: Payload; recording?: string }> = [];
  const h = createHarness(async (id, payload, recording) => {
    sent.push({ id, payload, ...(recording === undefined ? {} : { recording }) });
    if (sent.length === 1) await startAck.promise;
  });
  const gap: InputMessage = { ...event(6), kind: "gap", gap: {
    reason: "queue-full", count: 1, firstSequence: 6n, lastSequence: 6n,
  } };
  const messages = [start(), event(2), event(3), { type: "route", recordingId: A, route: "/items" } as const,
    event(4), start(B), event(2, B), event(5), gap, event(7), event(8), finish(8), finish(2, B)];
  for (const message of [...messages, close, event(9)]) h.delivery.enqueue(message);
  assert.deepEqual(sent.map(({ payload }) => payload.case), ["recordingStarted"]);
  assert.equal(h.credits(), 0);
  startAck.resolve();
  await Promise.race([h.done, h.failed.then(() => assert.fail("delivery failed"))]);

  assert.equal(h.credits(), messages.length);
  assert.deepEqual(sent.map(({ recording, payload }) =>
    [recording, payload.case === "eventBatch" ? wireEvents(payload) : payload.case]), [
    [A, "recordingStarted"], [A, [2n, 3n]], [A, [4n]], [B, "recordingStarted"], [B, [2n]],
    [A, [5n]], [A, [6n]], [A, [7n, 8n]], [A, "recordingFinished"], [B, "recordingFinished"],
  ]);
  const gapBatch = sent[6]!.payload;
  assert.equal(gapBatch.case, "eventBatch");
  assert.equal(gapBatch.value.events[0]!.kind, RecordingEventKind.GAP);
  const sealed = sent[8]!.payload;
  assert.equal(sealed.case, "recordingFinished");
  assert.equal(sealed.value.finalRecordingSeq, 8n);
  const ids = [2, 3, 4, 5, 6, 7, 8].map((sequence) => event(sequence).eventId).join("");
  assert.equal(Buffer.from(sealed.value.eventDigest).toString("hex"), await blake3(Buffer.from(ids)));
});

test("count and full-envelope byte limits split batches without changing event order", async () => {
  const sample: Payload[] = [];
  const single = createRecordingAssembler(async (_, payload) => { sample.push(payload); }, () => 5n);
  await single.handle(start());
  await single.handle(event(2));
  const singleBytes = sample[1]!;
  assert.equal(singleBytes.case, "eventBatch");
  const envelopeSize = (id: string, payload: Payload, correlationToken: string) =>
    toBinary(AgentEnvelopeSchema, create(AgentEnvelopeSchema, {
      protocolMajor: 1, sessionSeq: 0xffff_ffff_ffff_ffffn, sentMonotonicNs: 1n,
      runtimeSessionId: new Uint8Array(16), messageId: id, correlationToken, payload,
    })).length;
  const byteLimit = envelopeSize(`node-http-${A}-event-2`, singleBytes, A);
  for (const [fits, counts] of [
    [() => true, [[2n, 3n], [4n, 5n], [6n]]],
    [(id: string, payload: Payload, token: string) => envelopeSize(id, payload, token) <= byteLimit,
      [[2n], [3n], [4n], [5n], [6n]]],
  ] as const) {
    const sent: bigint[][] = [];
    let credited = 0;
    const assembler = createRecordingAssembler(async (id, payload, token) => {
      if (payload.case === "eventBatch") {
        if (counts.length === 5) assert.ok(envelopeSize(id, payload, token!) <= byteLimit);
        sent.push(wireEvents(payload));
      }
    }, () => 5n, undefined, { maxBatchEvents: 2, fitsEnvelope: fits });
    await assembler.handle(start());
    await assembler.handleEvents([2, 3, 4, 5, 6].map((sequence) => event(sequence)), (count) => { credited += count; });
    assert.deepEqual(sent, counts);
    assert.equal(credited, 5);
  }
});

test("a split batch returns credits only for acknowledged constituents and stops at a rejection", async () => {
  const startAck = deferred();
  const firstAck = deferred();
  const secondAck = deferred();
  const firstSent = deferred();
  const secondSent = deferred();
  const sent: Payload[] = [];
  const h = createHarness(async (_, payload) => {
    sent.push(payload);
    if (payload.case === "recordingStarted") await startAck.promise;
    if (payload.case === "eventBatch") {
      const sequences = wireEvents(payload);
      if (sequences[0] === 2n) { firstSent.resolve(); await firstAck.promise; }
      else { secondSent.resolve(); await secondAck.promise; }
    }
  }, 2);
  for (const message of [start(), event(2), event(3), event(4), event(5), finish(5), close]) {
    h.delivery.enqueue(message);
  }
  startAck.resolve();
  await firstSent.promise;
  assert.equal(h.credits(), 1);
  firstAck.resolve();
  await secondSent.promise;
  assert.equal(h.credits(), 3);
  secondAck.reject(new Error("fixture ACK refused"));
  await h.failed;
  assert.equal(h.credits(), 3);
  assert.deepEqual(sent.map((payload) => payload.case === "eventBatch" ? wireEvents(payload) : payload.case),
    ["recordingStarted", [2n, 3n], [4n, 5n]]);
});

test("an empty event identity cannot make its valid neighbor part of a rejected batch", async () => {
  const startAck = deferred();
  const sent: bigint[][] = [];
  const h = createHarness(async (_, payload) => {
    if (payload.case === "recordingStarted") await startAck.promise;
    if (payload.case === "eventBatch") {
      sent.push(wireEvents(payload));
      if (payload.value.events.some((value) => value.eventId === "")) throw new Error("fixture event rejected");
    }
  });
  for (const message of [start(), event(2), { ...event(3), eventId: "" }, event(4), finish(4), close]) {
    h.delivery.enqueue(message);
  }
  startAck.resolve();
  await h.failed;
  assert.deepEqual(sent, [[2n], [3n]]);
  assert.equal(h.credits(), 2);
});

test("app thread still charges all 64 logical messages and preserves the reserved finish", async () => {
  const startAck = deferred();
  const eventAck = deferred();
  const sent = deferred();
  const done = deferred();
  const worker = new EventEmitter() as EventEmitter & { postMessage(message: InputMessage): void; ref(): void };
  const assembler = createRecordingAssembler(async (_, payload) => {
    if (payload.case === "recordingStarted") await startAck.promise;
    if (payload.case === "eventBatch") {
      assert.equal(payload.value.events.length, 62);
      sent.resolve();
      await eventAck.promise;
    }
  }, () => 5n, undefined, { maxBatchEvents: 64, fitsEnvelope: () => true });
  const credits = createCaptureCredits();
  const delivery = createWorkerDelivery(assembler, {
    staged: () => { Atomics.add(credits, 0, 1); },
    close: async () => done.resolve(),
    fail: () => done.reject(new Error("fixture delivery failed")),
  });
  worker.ref = () => {};
  worker.postMessage = delivery.enqueue;
  const transport = createHttpCaptureTransport(worker as unknown as Worker, credits);
  assert.equal(transport.start(A, "GET", 1n), true);
  for (let sequence = 2n; sequence <= 63n; sequence += 1n) {
    assert.equal(transport.event(A, {
      kind: "frame-enter", eventId: `event-${sequence}`, sequence, monotonicNs: sequence,
      parentEventId: "", symbol: "handler", exceptionType: "",
    }), true);
  }
  assert.equal(transport.start(B, "GET", 1n), false);
  assert.equal(transport.finish(A, 63n, 1n, 0), true, "the finish reservation survives event pressure");
  startAck.resolve();
  await Promise.race([sent.promise, done.promise.then(() => assert.fail("no event batch"))]);
  assert.equal(transport.start(B, "GET", 1n), false, "a posted batch has yet to return any logical credits");
  eventAck.resolve();
  transport.close();
  await done.promise;
});

test("timed release keeps held events before later same-recording events and credits them once", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const startAck = deferred();
  const seen: Payload[] = [];
  const assembler = createRecordingAssembler(async (_, payload) => {
    seen.push(payload);
    if (payload.case === "recordingStarted") await startAck.promise;
  }, () => 5n, undefined, { maxBatchEvents: 64, fitsEnvelope: () => true });
  let credited = 0;
  const credit = (count: number) => { credited += count; };
  await assembler.handle(start(A, true));
  await assembler.handleEvents([event(2), event(3)], credit);
  assert.equal(credited, 2);
  assert.equal(seen.length, 0);
  context.mock.timers.tick(HOLD_START_MS);
  const pending = assembler.handleEvents([event(4), event(5)], credit);
  assert.deepEqual(seen.map((payload) => payload.case), ["recordingStarted"]);
  assert.equal(credited, 2);
  startAck.resolve();
  await pending;
  await assembler.handle(finish(5));
  assert.deepEqual(seen.map((payload) => payload.case === "eventBatch" ? wireEvents(payload) : payload.case),
    ["recordingStarted", [2n, 3n], [4n, 5n], "recordingFinished"]);
  assert.equal(credited, 4);
});

test("route release combines the staged held prefix with consecutive queued handler events", async () => {
  const startAck = deferred();
  const eventAck = deferred();
  const startSent = deferred();
  const eventsSent = deferred();
  const sent: Payload[] = [];
  const h = createHarness(async (_, payload) => {
    sent.push(payload);
    if (payload.case === "recordingStarted") { startSent.resolve(); await startAck.promise; }
    if (payload.case === "eventBatch") { eventsSent.resolve(); await eventAck.promise; }
  });
  for (const message of [start(A, true), event(2), event(3),
    { type: "route", recordingId: A, route: "/items" } as const]) h.delivery.enqueue(message);
  await startSent.promise;
  assert.equal(h.credits(), 3, "previously held events retain their original local credits");
  for (const message of [event(4), event(5), finish(5), close]) h.delivery.enqueue(message);
  startAck.resolve();
  await eventsSent.promise;
  const [routed, batch] = sent;
  assert.equal(routed?.case, "recordingStarted");
  assert.equal(routed.value.matchedRouteTemplate, "/items");
  assert.deepEqual(wireEvents(batch!), [2n, 3n, 4n, 5n]);
  assert.equal(h.credits(), 3, "neither the route nor the folded events credit before the batch ACK");
  assert.equal(h.stagedFolds.length, 0);
  eventAck.resolve();
  await Promise.race([h.done, h.failed.then(() => assert.fail("delivery failed"))]);
  assert.deepEqual(h.stagedFolds, [2], "only the two staged queued events are counted as folded");
  assert.equal(h.credits(), 7, "exactly the original seven logical messages are credited");
  assert.deepEqual(sent.map(({ case: kind }) => kind), ["recordingStarted", "eventBatch", "recordingFinished"]);
  const sealed = sent[2]!;
  assert.equal(sealed.case, "recordingFinished");
  const ids = [2, 3, 4, 5].map((sequence) => event(sequence).eventId).join("");
  assert.equal(Buffer.from(sealed.value.eventDigest).toString("hex"), await blake3(Buffer.from(ids)));
});

test("route release preserves a control boundary and falls back at the negotiated byte limit", async () => {
  for (const constrained of [false, true]) {
    const startAck = deferred();
    const batches: bigint[][] = [];
    const h = createHarness(async (_, payload, recording) => {
      if (payload.case === "recordingStarted" && recording === A) await startAck.promise;
      if (payload.case === "eventBatch") batches.push(wireEvents(payload));
    }, 64, (_, payload) => !constrained || payload.case !== "eventBatch" || payload.value.events.length === 1);
    const messages = [start(A, true), event(2), { type: "route", recordingId: A, route: "/items" } as const];
    if (!constrained) messages.push(start(B), finish(1, B));
    messages.push(event(3), finish(3), close);
    for (const message of messages) h.delivery.enqueue(message);
    startAck.resolve();
    await Promise.race([h.done, h.failed.then(() => assert.fail("delivery failed"))]);
    assert.deepEqual(batches, [[2n], [3n]]);
    assert.equal(h.stagedFolds.length, 0);
    assert.equal(h.credits(), messages.length - 1);
  }
});

test("a rejected folded route batch refunds neither the route nor its queued events", async () => {
  const startAck = deferred();
  const sent: Payload[] = [];
  const h = createHarness(async (_, payload) => {
    sent.push(payload);
    if (payload.case === "recordingStarted") await startAck.promise;
    if (payload.case === "eventBatch") throw new Error("fixture ACK refused");
  });
  for (const message of [start(A, true), event(2), { type: "route", recordingId: A, route: "/items" } as const,
    event(3), finish(3), close]) h.delivery.enqueue(message);
  startAck.resolve();
  await h.failed;
  assert.equal(h.credits(), 2);
  assert.equal(h.stagedFolds.length, 0);
  assert.deepEqual(sent.map((payload) => payload.case === "eventBatch" ? wireEvents(payload) : payload.case),
    ["recordingStarted", [2n, 3n]]);
});


test("the worker batches adjacent port messages without crossing gaps, finish or close", async (t) => {
  const { port1, port2 } = new MessageChannel();
  t.after(() => { port1.close(); port2.close(); });
  const startSent = deferred();
  const startAck = deferred();
  const firstBatchSent = deferred();
  const firstBatchAck = deferred();
  const finishReceived = deferred();
  const payloads: Payload[] = [];
  const progress = new BigUint64Array(new SharedArrayBuffer(BigUint64Array.BYTES_PER_ELEMENT));
  const note = (boundary: FinishBoundary) => noteFinishProgress(progress, boundary);
  const h = createHarness(async (_, payload) => {
    payloads.push(payload);
    if (payload.case === "recordingStarted") {
      startSent.resolve();
      await startAck.promise;
    } else if (payloads.length === 2) {
      firstBatchSent.resolve();
      await firstBatchAck.promise;
    } else if (payload.case === "recordingFinished") {
      assert.deepEqual(readFinishProgress(progress),
        { received: 1, dispatched: 1, submitted: 0, written: 0, staged: 0, active: "finish" });
      note("submitted");
      note("written");
    }
  }, 64, undefined, () => receiveMessageOnPort(port1)?.message as InputMessage | undefined, (phase) => {
    note(phase);
    if (phase === "received") finishReceived.resolve();
  }, (type) => noteFinishWork(progress, type));

  h.delivery.enqueue(start(A, true));
  h.delivery.enqueue(event(2));
  h.delivery.enqueue({ type: "route", recordingId: A, route: "/items" });
  await startSent.promise;
  assert.equal(readFinishProgress(progress)?.active, "route-start");
  assert.equal(h.credits(), 2, "the route remains charged before its start ACK");
  const gap: InputMessage = { ...event(5), kind: "gap", gap: {
    reason: "queue-full", count: 1, firstSequence: 5n, lastSequence: 5n,
  } };
  for (const message of [event(3), event(4), gap, event(6), event(7), finish(7), close, start(B)]) {
    port2.postMessage(message);
  }
  startAck.resolve();
  await firstBatchSent.promise;
  assert.deepEqual(wireEvents(payloads[1]!), [2n, 3n, 4n]);
  assert.equal(readFinishProgress(progress)?.active, "route-held-events");
  assert.equal(h.credits(), 2, "only the held start and prefix have returned credit");
  assert.deepEqual(h.stagedFolds, []);
  port1.on("message", (message: InputMessage) => h.delivery.enqueue(message));
  await finishReceived.promise;
  assert.deepEqual(readFinishProgress(progress),
    { received: 1, dispatched: 0, submitted: 0, written: 0, staged: 0, active: "route-held-events" });
  assert.equal(h.credits(), 2, "the queued finish and route batch have returned no credit");
  firstBatchAck.resolve();
  await Promise.race([h.done, h.failed.then(() => assert.fail("port delivery failed"))]);
  assert.deepEqual(payloads.map((p) => p.case === "eventBatch" ? wireEvents(p) : p.case),
    ["recordingStarted", [2n, 3n, 4n], [5n], [6n, 7n], "recordingFinished"]);
  assert.equal(h.credits(), 9);
  assert.deepEqual(h.stagedFolds, [2]);
  assert.deepEqual(readFinishProgress(progress),
    { received: 1, dispatched: 1, submitted: 1, written: 1, staged: 0, active: "idle" });
  note("staged");
  assert.equal(readFinishProgress(progress)?.staged, 1);
  Atomics.store(progress, 0, 4095n);
  note("received");
  assert.equal(readFinishProgress(progress), null, "counter overflow is unavailable rather than wrapped");
});
