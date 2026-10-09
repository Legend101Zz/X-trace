import { create } from "@bufbuild/protobuf";
import { blake3 } from "hash-wasm";
import { parentPort, workerData } from "node:worker_threads";
import {
  CapabilitySchema,
  CapabilitySetSchema,
  ExceptionPayloadSchema,
  GapPayloadSchema,
  GapReason,
  InteractionKind,
  InteractionSchema,
  OutcomeKind,
  RecordingOutcomeSchema,
  SourceRangeSchema,
  EventBatchSchema,
  RecordingEventKind,
  RecordingEventSchema,
  RecordingFinishedSchema,
  RecordingStartedSchema,
} from "@xtrace/protocol";
import { openXtpSession, readBootstrap, type AuthenticatedXtpSession } from "./index.js";
import type { CaptureEventKind, ExceptionFacts, GapFacts, InteractionFacts, SourceFacts } from "./runtime/events.cjs";
import type { RecordingSummary } from "./runtime/transport.cjs";

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
  kind?: CaptureEventKind;
  asyncParentEventId?: string;
  interaction?: InteractionFacts;
  exception?: ExceptionFacts;
  source?: SourceFacts;
  gap?: GapFacts;
  finalSequence?: bigint;
  durationNs?: bigint;
  droppedEvents?: number;
  summary?: RecordingSummary;
}

/** Events held back per recording while the route is unresolved; beyond this the start is released without it. */
const MAX_HELD_EVENTS = 4096;

interface RecordingState {
  bytes: Uint8Array;
  eventIds: string[];
  method: string;
  startedAtNs: bigint;
  /** RecordingStarted is sent once the route is known (finish) or the hold limit is hit. */
  started: boolean;
  held: InputMessage[];
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
        boundary: "node:http.Server.emit(request)",
        route: "framework-module-only",
        http_status: "response-statusCode-at-finish",
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

const KINDS: Record<CaptureEventKind, RecordingEventKind> = {
  "frame-enter": RecordingEventKind.FRAME_ENTER,
  "frame-exit": RecordingEventKind.FRAME_EXIT,
  "frame-throw": RecordingEventKind.FRAME_THROW,
  "response-finish": RecordingEventKind.RESPONSE,
  "response-close": RecordingEventKind.RESPONSE,
  "interaction-start": RecordingEventKind.DATABASE_START,
  "interaction-end": RecordingEventKind.DATABASE_END,
  "exception": RecordingEventKind.EXCEPTION,
  "async-link": RecordingEventKind.ASYNC_LINK,
  "gap": RecordingEventKind.GAP,
};

const GAP_REASONS: Record<GapFacts["reason"], GapReason> = {
  "queue-full": GapReason.QUEUE_FULL,
  "correlation-lost": GapReason.CORRELATION_LOST,
  "module-loaded-before-arm": GapReason.MODULE_LOADED_BEFORE_ARM,
  "source-map-absent": GapReason.SOURCE_MAP_ABSENT,
  "child-process-not-instrumented": GapReason.CHILD_PROCESS_NOT_INSTRUMENTED,
  "bootstrap-consumed": GapReason.BOOTSTRAP_CONSUMED,
};

const INTERACTION_KINDS: Record<InteractionFacts["kind"], InteractionKind> = {
  "database": InteractionKind.DATABASE,
  "outbound-http": InteractionKind.OUTBOUND_HTTP,
  "process": InteractionKind.PROCESS,
};

const OUTCOMES: Record<NonNullable<RecordingSummary["outcome"]>, OutcomeKind> = {
  "responded": OutcomeKind.RESPONDED,
  "exception-propagated": OutcomeKind.EXCEPTION_PROPAGATED,
  "client-aborted": OutcomeKind.CLIENT_ABORTED,
  "unobserved": OutcomeKind.UNOBSERVED,
};

function kindFor(kind: InputMessage["kind"]): RecordingEventKind {
  const mapped = kind ? KINDS[kind] : undefined;
  if (mapped === undefined) throw new Error("invalid capture event kind");
  return mapped;
}

function interactionPayload(facts: InteractionFacts) {
  return create(InteractionSchema, {
    kind: INTERACTION_KINDS[facts.kind],
    driver: facts.driver,
    method: facts.method,
    host: facts.host ?? "",
    port: facts.port ?? 0,
    statusCode: facts.statusCode ?? 0,
    sanitizedShape: facts.summary,
  });
}

function sourcePayload(facts: SourceFacts) {
  return create(SourceRangeSchema, {
    path: facts.path,
    startLine: facts.startLine,
    startColumn: facts.startColumn,
    endLine: facts.endLine,
    endColumn: facts.endColumn,
    contentHash: /^[0-9a-f]{64}$/.test(facts.contentHash) ? Buffer.from(facts.contentHash, "hex") : new Uint8Array(),
  });
}

function eventFrom(message: InputMessage) {
  const exception = message.exception
    ? create(ExceptionPayloadSchema, { exceptionType: message.exception.type, sanitizedMessage: message.exception.message, stackFrames: [] })
    : message.kind === "frame-throw"
      ? create(ExceptionPayloadSchema, { exceptionType: message.exceptionType ?? "UnknownError", sanitizedMessage: "", stackFrames: [] })
      : undefined;
  return create(RecordingEventSchema, {
    eventId: message.eventId ?? "",
    recordingSeq: message.sequence ?? 0n,
    parentEventId: message.parentEventId ?? "",
    asyncParentEventId: message.asyncParentEventId ?? "",
    monotonicNs: message.monotonicNs ?? process.hrtime.bigint(),
    priority: 1,
    kind: kindFor(message.kind),
    symbol: message.kind === "response-close" ? "node:http.response.close"
      : message.kind === "response-finish" ? "node:http.response.finish"
        : message.symbol ?? "",
    ...(exception ? { exception } : {}),
    ...(message.interaction ? { interaction: interactionPayload(message.interaction) } : {}),
    ...(message.source ? { source: sourcePayload(message.source) } : {}),
    ...(message.gap ? {
      gap: create(GapPayloadSchema, {
        reason: GAP_REASONS[message.gap.reason],
        count: BigInt(message.gap.count),
        firstRecordingSeq: message.gap.firstSequence,
        lastRecordingSeq: message.gap.lastSequence,
      }),
    } : {}),
  });
}

async function sendStart(recordingId: string, state: RecordingState, summary?: RecordingSummary): Promise<void> {
  const started = create(RecordingStartedSchema, {
    recordingId: state.bytes,
    recordingSeq: 1n,
    method: state.method,
    matchedRouteTemplate: summary?.route ?? "",
    urlShape: summary?.urlShape ?? "",
    startMonotonicNs: state.startedAtNs,
    threadOrTaskId: String(process.pid),
    asyncContextId: recordingId,
    capturePolicyId: "xtrace.standard.v1",
    capturePolicyDigest: "",
    redactionPolicyDigest: "",
    sourceRevisionId: "",
  });
  await session!.send(`node-http-${recordingId}-start`, { case: "recordingStarted", value: started }, recordingId);
  state.started = true;
}

async function sendEvent(recordingId: string, state: RecordingState, message: InputMessage): Promise<void> {
  if (typeof message.eventId !== "string" || typeof message.sequence !== "bigint") return;
  await session!.send(`node-http-${recordingId}-event-${message.sequence}`, {
    case: "eventBatch",
    value: create(EventBatchSchema, { recordingId: state.bytes, events: [eventFrom(message)] }),
  }, recordingId);
  state.eventIds.push(message.eventId);
}

async function deliver(message: InputMessage): Promise<void> {
  if (!session || shuttingDown) return;
  const recordingId = message.recordingId;
  if (typeof recordingId !== "string") throw new Error("recording identity absent");
  const bytes = Buffer.from(recordingId.replaceAll("-", ""), "hex");
  if (bytes.length !== 16) throw new Error("recording identity invalid");

  if (message.type === "start") {
    // The route is only known after routing, so RecordingStarted is held (seq 1) until the
    // request finishes or the hold limit is reached; events keep their original sequence.
    recordings.set(recordingId, {
      bytes,
      eventIds: [],
      method: message.method ?? "",
      startedAtNs: message.startedAtNs ?? process.hrtime.bigint(),
      started: false,
      held: [],
    });
  } else if (message.type === "event") {
    const state = recordings.get(recordingId);
    if (!state) return;
    if (state.started) await sendEvent(recordingId, state, message);
    else if (state.held.length < MAX_HELD_EVENTS) state.held.push(message);
    else {
      await sendStart(recordingId, state);
      for (const held of state.held.splice(0)) await sendEvent(recordingId, state, held);
      await sendEvent(recordingId, state, message);
    }
  } else if (message.type === "finish") {
    const state = recordings.get(recordingId);
    if (!state) return;
    const summary = message.summary;
    if (!state.started) {
      await sendStart(recordingId, state, summary);
      for (const held of state.held.splice(0)) await sendEvent(recordingId, state, held);
    }
    const digest = Buffer.from(await blake3(Buffer.from(state.eventIds.join(""), "utf8")), "hex");
    const dropped = Math.max(0, Math.min(message.droppedEvents ?? 0, 0xffff_ffff));
    const limitations = (summary?.limitations ?? []).filter((code) => /^[a-z][a-z0-9_]{0,127}$/.test(code)).slice(0, 64);
    await session.send(`node-http-${recordingId}-finish`, {
      case: "recordingFinished",
      value: create(RecordingFinishedSchema, {
        recordingId: state.bytes,
        finalRecordingSeq: message.finalSequence ?? 1n,
        durationNs: message.durationNs ?? 0n,
        dropCountsByPriority: dropped === 0 ? {} : { 1: BigInt(dropped) },
        unsupportedCapabilityCodes: limitations,
        eventDigest: digest,
        outcome: create(RecordingOutcomeSchema, {
          kind: OUTCOMES[summary?.outcome ?? "unobserved"],
          httpStatus: Math.max(0, Math.min(summary?.httpStatus ?? 0, 999)),
          thrownFromEventId: "",
        }),
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
