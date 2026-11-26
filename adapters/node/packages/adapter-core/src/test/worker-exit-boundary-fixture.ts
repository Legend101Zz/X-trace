import assert from "node:assert/strict";
import { writeSync } from "node:fs";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import { OutcomeKind } from "@xtrace/protocol";
import { installHttpCapture } from "../http-capture.cjs";
import { drainCapture } from "../index.js";
import { createCaptureCredits, createHttpCaptureTransport, returnCaptureCredit } from "../runtime/transport.cjs";
import { createRecordingAssembler, type InputMessage } from "../worker-core.js";
import { createWorkerDelivery } from "../worker-delivery.js";

type Mode = "capacity" | "natural" | "explicit" | "cooperative" | "aborted";
const FIRST = "01900000-0000-7000-8000-000000000001";
const SECOND = "01900000-0000-7000-8000-000000000002";
const slot = { startEntered: 0, startStaged: 1, eventsStaged: 2, finishEntered: 3, finishStaged: 4, closeSeen: 5 } as const;

interface FixtureData {
  mode: Mode;
  credits: Uint32Array<SharedArrayBuffer>;
  state: Int32Array<SharedArrayBuffer>;
}

function runWorker({ mode, credits, state }: FixtureData): void {
  const port = parentPort!;
  let release!: () => void;
  // Deliberately stop exactly one envelope at the staged-ACK seam until the
  // worker receives close. No network, real daemon, or remote storage is involved.
  const ack = new Promise<void>((resolve) => { release = resolve; });
  function entered(index: number): void {
    Atomics.add(state, index, 1);
    Atomics.notify(state, index);
  }
  const assembler = createRecordingAssembler(async (_, payload) => {
    if (payload.case === "recordingStarted") {
      entered(slot.startEntered);
      if (mode === "capacity") await ack;
      Atomics.add(state, slot.startStaged, 1);
    } else if (payload.case === "eventBatch") {
      Atomics.add(state, slot.eventsStaged, payload.value.events.length);
    } else if (payload.case === "recordingFinished") {
      assert.equal(payload.value.finalRecordingSeq, mode === "capacity" ? 63n : 1n);
      assert.equal(payload.value.outcome?.kind, OutcomeKind.RESPONDED);
      assert.equal(payload.value.outcome?.httpStatus, 200);
      entered(slot.finishEntered);
      if (mode !== "capacity") await ack;
      Atomics.add(state, slot.finishStaged, 1);
    }
  }, undefined, undefined, { maxBatchEvents: 64, fitsEnvelope: () => true });
  const delivery = createWorkerDelivery(assembler, {
    staged: () => returnCaptureCredit(credits),
    async close() {
      port.postMessage({ type: "drained" });
      port.close();
    },
    fail() {
      port.postMessage({ type: "failure" });
      port.close();
      process.exitCode = 1;
    },
  });
  port.on("message", (message: InputMessage) => {
    if (message.type === "close") {
      Atomics.add(state, slot.closeSeen, 1);
      if (mode === "aborted") port.postMessage({ type: "fixture-close" });
      else release();
    }
    delivery.enqueue(message);
  });
}

async function runChild(mode: Mode): Promise<void> {
  const credits = createCaptureCredits();
  const state = new Int32Array(new SharedArrayBuffer(Object.keys(slot).length * Int32Array.BYTES_PER_ELEMENT));
  const worker = new Worker(new URL(import.meta.url), { workerData: { mode, credits, state } satisfies FixtureData });
  const transport = createHttpCaptureTransport(worker, credits);
  installHttpCapture(transport);
  worker.unref();

  function waitFor(index: number): void {
    assert.notEqual(Atomics.wait(state, index, 0, 5_000), "timed-out");
    assert.equal(Atomics.load(state, index), 1);
  }
  function load(index: number): number { return Atomics.load(state, index); }

  let capacityRefusals = 0;
  let finalSequence = 1n;
  assert.equal(transport.start(FIRST, "GET", 1n), true);
  if (mode === "capacity") {
    waitFor(slot.startEntered);
    assert.equal(load(slot.startStaged), 0);
    for (let sequence = 2n; sequence <= 63n; sequence += 1n) {
      assert.equal(transport.event(FIRST, {
        kind: "frame-enter", eventId: `fixture-${sequence}`, sequence, monotonicNs: sequence,
        parentEventId: "", symbol: "fixture", exceptionType: "",
      }), true);
    }
    assert.equal(transport.start(SECOND, "GET", 1n), false);
    capacityRefusals = 1;
    finalSequence = 63n;
  }
  const finishPosted = transport.finish(FIRST, finalSequence, 1n, 0, { outcome: "responded", httpStatus: 200 });
  assert.equal(finishPosted, true);
  if (mode !== "capacity") {
    waitFor(slot.finishEntered);
    assert.equal(load(slot.startStaged), 1);
    assert.equal(load(slot.finishStaged), 0);
    assert.equal(load(slot.closeSeen), 0);
  }

  let drainResult: boolean | undefined;
  process.once("exit", () => {
    // Exit only emits fixed fixture counters. The explicit leg cannot queue a drain here.
    writeSync(1, JSON.stringify({
      capacityRefusals, finishPosted,
      ...(drainResult === undefined ? {} : { drainResult }),
      startEntered: load(slot.startEntered), startStaged: load(slot.startStaged),
      eventsStaged: load(slot.eventsStaged), finishEntered: load(slot.finishEntered),
      finishStaged: load(slot.finishStaged), closeSeen: load(slot.closeSeen),
    }) + "\n");
  });
  if (mode === "explicit") process.exit(0);
  if (mode === "cooperative" || mode === "aborted") {
    const deadline = new AbortController();
    if (mode === "aborted") {
      worker.on("message", (message: { type: string }) => {
        if (message.type === "fixture-close") deadline.abort();
      });
    }
    drainResult = await drainCapture(deadline.signal);
    process.exit(mode === "cooperative" ? 37 : 38);
  }
}

if (isMainThread) {
  const mode = process.argv[2];
  assert.ok(mode === "capacity" || mode === "natural" || mode === "explicit" ||
    mode === "cooperative" || mode === "aborted");
  await runChild(mode);
} else {
  runWorker(workerData as FixtureData);
}
