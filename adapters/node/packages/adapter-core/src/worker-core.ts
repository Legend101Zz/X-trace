/**
 * Pure half of the transport worker: turns the app-thread handoff messages into XTP-Agent
 * envelopes and decides when RecordingStarted goes out. No top-level effects, so tests can
 * drive it with an injected `send` and decode exactly what would have gone to the daemon.
 */
import { create } from "@bufbuild/protobuf";
import { blake3 } from "hash-wasm";
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
  SourceBinding,
  SourceRangeSchema,
  EventBatchSchema,
  RecordingEventKind,
  RecordingEventSchema,
  RecordingFinishedSchema,
  RecordingStartedSchema,
  type AgentEnvelope,
} from "@xtrace/protocol";
import type { CaptureEventKind, ExceptionFacts, GapFacts, InteractionFacts, SourceBindingName, SourceFacts } from "./runtime/events.cjs";
import type { RecordingSummary } from "./runtime/transport.cjs";

export interface InputMessage {
  type: "start" | "event" | "finish" | "close";
  recordingId?: string;
  method?: string;
  startedAtNs?: bigint;
  holdStart?: boolean;
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

export type SendFn = (messageId: string, payload: AgentEnvelope["payload"], correlationToken?: string) => Promise<unknown>;

/** Events held back per recording while the route is unresolved; beyond this the start is released without it. */
export const MAX_HELD_EVENTS = 4096;

interface RecordingState {
  bytes: Uint8Array;
  eventIds: string[];
  method: string;
  startedAtNs: bigint;
  hold: boolean;
  /** RecordingStarted has been sent. */
  started: boolean;
  held: InputMessage[];
}

/** Config the handshake advertises per capability name; unknown names are never advertised. */
const CAPABILITY_CONFIG: Record<string, Record<string, string>> = {
  "http.server.request_root": {
    boundary: "node:http.Server.emit(request)",
    route: "framework-module-only",
    http_status: "response-statusCode-at-finish",
    handler_depth: "registered-listener-call",
    response_boundary: "finish-or-close",
    async_handler_completion: "unobserved",
  },
  async_correlation: { mechanism: "AsyncLocalStorage", scope: "request-callback-and-descendant-async-resources" },
  "http.server.route_template": { source: "express-layer-route-path", scope: "express-4-and-5" },
};

const START_KINDS: Record<CaptureEventKind, RecordingEventKind> = {
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
};

const OUTCOMES: Record<NonNullable<RecordingSummary["outcome"]>, OutcomeKind> = {
  "responded": OutcomeKind.RESPONDED,
  "exception-propagated": OutcomeKind.EXCEPTION_PROPAGATED,
  "client-aborted": OutcomeKind.CLIENT_ABORTED,
  "unobserved": OutcomeKind.UNOBSERVED,
};

const SOURCE_BINDINGS: Record<SourceBindingName, SourceBinding> = {
  "verified": SourceBinding.VERIFIED,
  "observed-unattested": SourceBinding.OBSERVED_UNATTESTED,
  "source-map-absent": SourceBinding.SOURCE_MAP_ABSENT,
  "source-map-unresolved": SourceBinding.SOURCE_MAP_UNRESOLVED,
};

/** Event kind follows the payload, not just the capture kind: HTTP interactions have their own kinds. */
export function eventKindFor(message: Pick<InputMessage, "kind" | "interaction">): RecordingEventKind {
  const kind = message.kind;
  if (!kind || START_KINDS[kind] === undefined) throw new Error("invalid capture event kind");
  if ((kind === "interaction-start" || kind === "interaction-end") && message.interaction?.kind === "outbound-http") {
    return kind === "interaction-start" ? RecordingEventKind.OUTBOUND_HTTP_START : RecordingEventKind.OUTBOUND_HTTP_END;
  }
  return START_KINDS[kind];
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

const HEX_64 = /^[0-9a-f]{64}$/;

/** Returns the source and its binding together, or nothing when they would disagree (ingest rule 6). */
export function sourceParts(facts: SourceFacts): { source: ReturnType<typeof create<typeof SourceRangeSchema>>; binding: SourceBinding } | undefined {
  const binding = SOURCE_BINDINGS[facts.binding];
  if (binding === undefined || !facts.path) return undefined;
  const needsHash = facts.binding === "verified" || facts.binding === "observed-unattested";
  if (needsHash && !HEX_64.test(facts.contentHash)) return undefined;
  const hash = HEX_64.test(facts.contentHash) ? Buffer.from(facts.contentHash, "hex") : new Uint8Array();
  return {
    binding,
    source: create(SourceRangeSchema, {
      path: facts.path,
      startLine: facts.startLine,
      startColumn: facts.startColumn,
      endLine: facts.endLine,
      endColumn: facts.endColumn,
      contentHash: hash,
    }),
  };
}

export function encodeEvent(message: InputMessage) {
  const exception = message.exception
    ? create(ExceptionPayloadSchema, { exceptionType: message.exception.type, sanitizedMessage: message.exception.message, stackFrames: [] })
    : message.kind === "frame-throw"
      ? create(ExceptionPayloadSchema, { exceptionType: message.exceptionType ?? "UnknownError", sanitizedMessage: "", stackFrames: [] })
      : undefined;
  const source = message.source ? sourceParts(message.source) : undefined;
  return create(RecordingEventSchema, {
    eventId: message.eventId ?? "",
    recordingSeq: message.sequence ?? 0n,
    parentEventId: message.parentEventId ?? "",
    asyncParentEventId: message.asyncParentEventId ?? "",
    monotonicNs: message.monotonicNs ?? 0n,
    priority: 1,
    kind: eventKindFor(message),
    symbol: message.kind === "response-close" ? "node:http.response.close"
      : message.kind === "response-finish" ? "node:http.response.finish"
        : message.symbol ?? "",
    ...(exception ? { exception } : {}),
    ...(message.interaction ? { interaction: interactionPayload(message.interaction) } : {}),
    ...(source ? { source: source.source, sourceBinding: source.binding } : {}),
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

/** Only 0 (not observed) or 100..=599 is valid on the wire; UNOBSERVED must carry 0. */
export function wireStatus(status: number | undefined, outcome: NonNullable<RecordingSummary["outcome"]>): number {
  if (outcome === "unobserved") return 0;
  return Number.isInteger(status) && status! >= 100 && status! <= 599 ? status! : 0;
}

export function encodeOutcome(summary: RecordingSummary | undefined) {
  const outcome = summary?.outcome ?? "unobserved";
  return create(RecordingOutcomeSchema, {
    kind: OUTCOMES[outcome],
    httpStatus: wireStatus(summary?.httpStatus, outcome),
    ...(outcome === "exception-propagated"
      ? {
        exception: create(ExceptionPayloadSchema, { exceptionType: summary?.exceptionType || "UnknownError", sanitizedMessage: "", stackFrames: [] }),
        thrownFromEventId: (summary?.thrownFromEventId ?? "").slice(0, 128),
      }
      : {}),
  });
}

export function capabilitySetFor(names: readonly string[]) {
  const capabilities = names
    .filter((name) => CAPABILITY_CONFIG[name] !== undefined)
    .map((name) => create(CapabilitySchema, { name, config: CAPABILITY_CONFIG[name]! }));
  return create(CapabilitySetSchema, { capabilities });
}

export interface RecordingAssembler {
  handle(message: InputMessage): Promise<boolean>;
  /** Sends held starts and their events for recordings that never finished (worker closing). */
  flushHeld(): Promise<void>;
}

export function createRecordingAssembler(send: SendFn, now: () => bigint = () => process.hrtime.bigint()): RecordingAssembler {
  const recordings = new Map<string, RecordingState>();

  async function sendStart(recordingId: string, state: RecordingState, summary?: RecordingSummary): Promise<void> {
    const started = create(RecordingStartedSchema, {
      recordingId: state.bytes,
      recordingSeq: 1n,
      method: state.method,
      matchedRouteTemplate: summary?.route ?? "",
      urlShape: "",
      startMonotonicNs: state.startedAtNs,
      threadOrTaskId: String(process.pid),
      asyncContextId: recordingId,
      capturePolicyId: "xtrace.standard.v1",
      capturePolicyDigest: "",
      redactionPolicyDigest: "",
      sourceRevisionId: "",
    });
    await send(`node-http-${recordingId}-start`, { case: "recordingStarted", value: started }, recordingId);
    state.started = true;
  }

  async function sendEvent(recordingId: string, state: RecordingState, message: InputMessage): Promise<void> {
    if (typeof message.eventId !== "string" || typeof message.sequence !== "bigint") return;
    await send(`node-http-${recordingId}-event-${message.sequence}`, {
      case: "eventBatch",
      value: create(EventBatchSchema, { recordingId: state.bytes, events: [encodeEvent({ ...message, monotonicNs: message.monotonicNs ?? now() })] }),
    }, recordingId);
    state.eventIds.push(message.eventId);
  }

  async function release(recordingId: string, state: RecordingState, summary?: RecordingSummary): Promise<void> {
    if (!state.started) await sendStart(recordingId, state, summary);
    for (const held of state.held.splice(0)) await sendEvent(recordingId, state, held);
  }

  return {
    async handle(message) {
      const recordingId = message.recordingId;
      if (typeof recordingId !== "string") throw new Error("recording identity absent");
      const bytes = Buffer.from(recordingId.replaceAll("-", ""), "hex");
      if (bytes.length !== 16) throw new Error("recording identity invalid");

      if (message.type === "start") {
        const state: RecordingState = {
          bytes,
          eventIds: [],
          method: message.method ?? "",
          startedAtNs: message.startedAtNs ?? now(),
          hold: message.holdStart === true,
          started: false,
          held: [],
        };
        recordings.set(recordingId, state);
        // Without a module that can still resolve a route the start goes out immediately, so an
        // interrupted request is visible (and reopens as partial) instead of vanishing.
        if (!state.hold) await sendStart(recordingId, state);
        return true;
      }
      const state = recordings.get(recordingId);
      if (!state) return false;
      if (message.type === "event") {
        if (state.started) await sendEvent(recordingId, state, message);
        else if (state.held.length < MAX_HELD_EVENTS) state.held.push(message);
        else {
          await release(recordingId, state);
          await sendEvent(recordingId, state, message);
        }
        return true;
      }
      if (message.type === "finish") {
        const summary = message.summary;
        await release(recordingId, state, summary);
        const digest = Buffer.from(await blake3(Buffer.from(state.eventIds.join(""), "utf8")), "hex");
        const dropped = Math.max(0, Math.min(message.droppedEvents ?? 0, 0xffff_ffff));
        const limitations = (summary?.limitations ?? []).filter((code) => /^[a-z][a-z0-9_]{0,127}$/.test(code)).slice(0, 64);
        await send(`node-http-${recordingId}-finish`, {
          case: "recordingFinished",
          value: create(RecordingFinishedSchema, {
            recordingId: state.bytes,
            finalRecordingSeq: message.finalSequence ?? 1n,
            durationNs: message.durationNs ?? 0n,
            dropCountsByPriority: dropped === 0 ? {} : { 1: BigInt(dropped) },
            unsupportedCapabilityCodes: limitations,
            eventDigest: digest,
            outcome: encodeOutcome(summary),
          }),
        }, recordingId);
        recordings.delete(recordingId);
        return true;
      }
      return false;
    },
    async flushHeld() {
      for (const [recordingId, state] of recordings) {
        if (!state.started || state.held.length > 0) await release(recordingId, state);
      }
    },
  };
}
