import { create } from "@bufbuild/protobuf";
import { blake3 } from "hash-wasm";
import { parentPort, workerData } from "node:worker_threads";
import {
  CapabilitySchema,
  CapabilitySetSchema,
  EventBatchSchema,
  RecordingEventKind,
  RecordingEventSchema,
  RecordingFinishedSchema,
  RecordingStartedSchema,
} from "@xtrace/protocol";
import { openXtpSession, readBootstrap, type AuthenticatedXtpSession } from "./index.js";

interface StartupData {
  bootstrapPath: string;
  startupBarrier: SharedArrayBuffer;
  manifestPath: string;
}

interface InputMessage {
  type: "start" | "event" | "finish" | "close";
  recordingId?: string;
  method?: string;
  startedAtNs?: bigint;
  eventId?: string;
  sequence?: bigint;
  monotonicNs?: bigint;
  parentEventId?: string;
  symbol?: string;
  exceptionType?: string;
  kind?: "frame-enter" | "frame-exit" | "frame-throw" | "response-finish" | "response-close";
  finalSequence?: bigint;
  durationNs?: bigint;
  droppedEvents?: number;
}

interface RecordingState {
  bytes: Uint8Array;
  eventIds: string[];
}

const data = workerData as StartupData;
const startup = new Int32Array(data.startupBarrier);
const recordings = new Map<string, RecordingState>();
let session: AuthenticatedXtpSession | undefined;
let delivery = Promise.resolve();
let shuttingDown = false;
let closingRequested = false;

function setStartup(state: 1 | 2): void {
  Atomics.store(startup, 0, state);
  Atomics.notify(startup, 0);
  parentPort?.postMessage({ type: state === 1 ? "ready" : "startup-failure" });
}

function fail(): void {
  setStartup(2);
  parentPort?.postMessage({ type: "failure" });
  shuttingDown = true;
  void session?.close().catch(() => undefined);
}

async function sendCapabilitySet(): Promise<void> {
  const capabilities = [
    create(CapabilitySchema, {
      name: "http.server.request_root",
      config: {
        boundary: "node:http.createServer-listener",
        route: "unavailable",
        http_status: "unavailable",
        handler_depth: "registered-listener-call",
        response_boundary: "finish-or-close",
        async_handler_completion: "unobserved",
      },
    }),
    create(CapabilitySchema, {
      name: "async_correlation",
      config: { mechanism: "AsyncLocalStorage", scope: "request-callback-and-descendant-async-resources" },
    }),
  ];
  await session!.send("node-http-capabilities", {
    case: "capabilitySet",
    value: create(CapabilitySetSchema, { capabilities }),
  });
}

function kindFor(kind: InputMessage["kind"]): RecordingEventKind {
  switch (kind) {
    case "frame-enter": return RecordingEventKind.FRAME_ENTER;
    case "frame-exit": return RecordingEventKind.FRAME_EXIT;
    case "frame-throw": return RecordingEventKind.FRAME_THROW;
    case "response-finish":
    case "response-close": return RecordingEventKind.RESPONSE;
    default: throw new Error("invalid capture event kind");
  }
}

async function deliver(message: InputMessage): Promise<void> {
  if (!session || shuttingDown) return;
  const recordingId = message.recordingId;
  if (typeof recordingId !== "string") throw new Error("recording identity absent");
  const bytes = Buffer.from(recordingId.replaceAll("-", ""), "hex");
  if (bytes.length !== 16) throw new Error("recording identity invalid");

  if (message.type === "start") {
    const started = create(RecordingStartedSchema, {
      recordingId: bytes,
      recordingSeq: 1n,
      method: message.method ?? "",
      matchedRouteTemplate: "",
      urlShape: "",
      startMonotonicNs: message.startedAtNs ?? process.hrtime.bigint(),
      threadOrTaskId: String(process.pid),
      asyncContextId: recordingId,
      capturePolicyId: "node-http-boundary-v1",
      capturePolicyDigest: "",
      redactionPolicyDigest: "",
      sourceRevisionId: "",
    });
    await session.send(`node-http-${recordingId}-start`, { case: "recordingStarted", value: started }, recordingId);
    recordings.set(recordingId, { bytes, eventIds: [] });
  } else if (message.type === "event") {
    const state = recordings.get(recordingId);
    if (!state || typeof message.eventId !== "string" || typeof message.sequence !== "bigint") return;
    const event = create(RecordingEventSchema, {
      eventId: message.eventId,
      recordingSeq: message.sequence,
      parentEventId: message.parentEventId ?? "",
      monotonicNs: message.monotonicNs ?? process.hrtime.bigint(),
      priority: 1,
      kind: kindFor(message.kind),
      symbol: message.kind === "response-close" ? "node:http.response.close"
        : message.kind === "response-finish" ? "node:http.response.finish"
          : message.symbol ?? "",
      exception: message.kind === "frame-throw"
        ? { exceptionType: message.exceptionType ?? "UnknownError", sanitizedMessage: "", stackFrames: [] }
        : undefined,
    });
    await session.send(`node-http-${recordingId}-event-${message.sequence}`, {
      case: "eventBatch",
      value: create(EventBatchSchema, { recordingId: state.bytes, events: [event] }),
    }, recordingId);
    state.eventIds.push(message.eventId);
  } else if (message.type === "finish") {
    const state = recordings.get(recordingId);
    if (!state) return;
    const digest = Buffer.from(await blake3(Buffer.from(state.eventIds.join(""), "utf8")), "hex");
    const dropped = Math.max(0, Math.min(message.droppedEvents ?? 0, 0xffff_ffff));
    await session.send(`node-http-${recordingId}-finish`, {
      case: "recordingFinished",
      value: create(RecordingFinishedSchema, {
        recordingId: state.bytes,
        finalRecordingSeq: message.finalSequence ?? 1n,
        durationNs: message.durationNs ?? 0n,
        dropCountsByPriority: dropped === 0 ? {} : { 1: BigInt(dropped) },
        unsupportedCapabilityCodes: [],
        eventDigest: digest,
      }),
    }, recordingId);
    recordings.delete(recordingId);
  }
  parentPort?.postMessage({ type: "staged" });
}

async function initialize(): Promise<void> {
  const bootstrap = await readBootstrap(data.bootstrapPath);
  session = await openXtpSession(bootstrap, data.manifestPath, {
    adapterName: "xtrace-node-http",
    adapterVersion: "0.1.0",
    language: "node",
    runtimeName: "node",
    runtimeVersion: process.version,
    pid: BigInt(process.pid),
    processStartMonotonicNs: process.hrtime.bigint(),
  });
  await sendCapabilitySet();
  setStartup(1);
}

parentPort?.on("message", (message: InputMessage) => {
  if (message.type === "close") {
    closingRequested = true;
    delivery = delivery.then(async () => {
      shuttingDown = true;
      await session?.close();
      parentPort?.close();
    }).catch(() => fail());
    return;
  }
  if (closingRequested) return;
  delivery = delivery.then(() => deliver(message)).catch(() => fail());
});

void initialize().catch(() => fail());
