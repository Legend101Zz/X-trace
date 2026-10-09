import { fileURLToPath } from "node:url";
import { create } from "@bufbuild/protobuf";
import { blake3 } from "hash-wasm";
import { parse as parseUuid, v7 as uuidv7 } from "uuid";
import {
  CapabilitySetSchema,
  EventBatchSchema,
  RecordingEventKind,
  RecordingEventSchema,
  RecordingFinishedSchema,
  RecordingStartedSchema,
} from "@xtrace/protocol";
import { openXtpSession, readBootstrap, XtraceClientError } from "@xtrace/adapter-core";

async function main(): Promise<void> {
  const path = process.argv[2];
  if (!path || process.argv.length !== 3) {
    throw new XtraceClientError("XTR-NODE-ARGUMENT", "usage: xtrace-node-synthetic <bootstrap-path>");
  }
  const bootstrap = await readBootstrap(path);
  const manifestPath = fileURLToPath(new URL("../../../fixtures/synthetic-manifest.json", import.meta.url));
  const session = await openXtpSession(bootstrap, manifestPath, {
    adapterName: "xtrace-node-synthetic-client",
    adapterVersion: "0.0.1",
    language: "node",
    runtimeName: "node",
    runtimeVersion: process.version,
    pid: BigInt(process.pid),
    processStartMonotonicNs: process.hrtime.bigint(),
  });
  const recordingId = uuidv7();
  const recordingIdBytes = Buffer.from(parseUuid(recordingId));
  const eventId = `${recordingId}:event-1`;
  const event = create(RecordingEventSchema, {
    eventId,
    recordingSeq: 2n,
    monotonicNs: process.hrtime.bigint(),
    priority: 1,
    kind: RecordingEventKind.FRAME_ENTER,
    symbol: "synthetic.handler",
  });
  let stagedAcks = 0;
  try {
    const capabilityAck = await session.send("node-synthetic-capabilities", {
      case: "capabilitySet",
      value: create(CapabilitySetSchema, { capabilities: [] }),
    });
    if (capabilityAck.case !== "ack") throw new XtraceClientError("XTR-NODE-ACK", "capability acknowledgement is invalid");
    stagedAcks += 1;
    const startedAck = await session.send("node-synthetic-recording-started", {
      case: "recordingStarted",
      value: create(RecordingStartedSchema, {
        recordingId: recordingIdBytes,
        recordingSeq: 1n,
        method: "GET",
        matchedRouteTemplate: "/__xtrace_synthetic",
        urlShape: "/__xtrace_synthetic",
        startMonotonicNs: process.hrtime.bigint(),
      }),
    }, recordingId);
    if (startedAck.case !== "ack" || startedAck.value.highestContiguousRecordingSeq[recordingId] !== 1n) {
      throw new XtraceClientError("XTR-NODE-ACK", "recording-start acknowledgement is invalid");
    }
    stagedAcks += 1;
    const eventAck = await session.send("node-synthetic-event-batch", {
      case: "eventBatch",
      value: create(EventBatchSchema, { recordingId: recordingIdBytes, events: [event] }),
    }, recordingId);
    if (eventAck.case !== "ack" || eventAck.value.highestContiguousRecordingSeq[recordingId] !== 2n) {
      throw new XtraceClientError("XTR-NODE-ACK", "event-batch acknowledgement is invalid");
    }
    stagedAcks += 1;
    const finishedAck = await session.send("node-synthetic-recording-finished", {
      case: "recordingFinished",
      value: create(RecordingFinishedSchema, {
        recordingId: recordingIdBytes,
        finalRecordingSeq: 2n,
        durationNs: 1n,
        eventDigest: Buffer.from(await blake3(Buffer.from(eventId, "utf8")), "hex"),
      }),
    }, recordingId);
    if (finishedAck.case !== "ack" || finishedAck.value.highestContiguousRecordingSeq[recordingId] !== 2n) {
      throw new XtraceClientError("XTR-NODE-ACK", "recording-finish acknowledgement is invalid");
    }
    stagedAcks += 1;
  } finally {
    await session.close();
  }
  process.stdout.write(`${JSON.stringify({
    kind: "synthetic_recording_staged",
    recording_id: recordingId,
    event_id: eventId,
    staged_acks: stagedAcks,
    capture_supported: false,
  })}\n`);
}

main().catch((error: unknown) => {
  const safe = error instanceof XtraceClientError
    ? { code: error.code, message: error.message }
    : { code: "XTR-NODE-CLIENT", message: "synthetic XTP client failed" };
  process.stderr.write(`${JSON.stringify(safe)}\n`);
  process.exitCode = 1;
});
