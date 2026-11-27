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
  HealthSchema,
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
  type: "start" | "event" | "finish" | "close" | "route";
  /** `route` message: the matched route template, known before the response finished. */
  route?: string;
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

/**
 * Longest a RecordingStarted is held waiting for a route that is only known at response finish.
 * After this the start goes out without it, so a long-running, crashing or killed request is
 * still visible (and reopens as partial). A process that dies inside this window loses that
 * request: the documented trade-off for carrying the route on the start.
 */
export const HOLD_START_MS = 250;

const MAX_WORKER_BATCH_EVENTS = 256;

interface RecordingState {
  bytes: Uint8Array;
  eventIds: string[];
  method: string;
  startedAtNs: bigint;
  hold: boolean;
  /** RecordingStarted has been sent. */
  started: boolean;
  held: InputMessage[];
  /** Start went out before the response finished, so it carries no route template. */
  routeLost: boolean;
  /** Route template announced while the request ran (framework match time); wins over the finish summary. */
  route?: string;
  timer?: ReturnType<typeof setTimeout> | undefined;
  releasePromise?: Promise<void> | undefined;
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
    abort_attribution: "connection-closed-before-finish",
  },
  async_correlation: { mechanism: "AsyncLocalStorage", scope: "request-callback-and-descendant-async-resources" },
  "http.server.route_template": { source: "express-layer-match", express: "4.x-and-5.x", scope: "literal-route-path-composed-with-literal-mount-paths", mounted_routers: "composed-when-literal-else-unresolved", resolved_at: "route-match", path_form: "as-authored" },
  "http.server.fastify": { source: "fastify-public-hooks", fastify: "4.x-and-5.x", scope: "encapsulated-plugin-scope", hooks: "onRequest,preHandler,onError,onResponse", resolved_at: "route-match", path_form: "as-authored" },
  "framework.nest": { source: "nest-controller-service-frames", adapters: "express,fastify", root_policy: "attach-only-no-duplicate-root" },
  "interactions.pg": { driver: "pg", sanitization: "literals-and-params-redacted" },
  "interactions.mysql": { driver: "mysql,mysql2", sanitization: "literals-and-params-redacted" },
  "interactions.outbound_http": { clients: "node:http,node:https,fetch,undici", sanitization: "host-method-sanitized-path-only" },
  process_linkage: { boundaries: "worker_threads.Worker,child_process.spawn,child_process.fork,child_process.execFile", env_policy: "no_env_leak_explicit_gap_or_opt_in_link" },
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
    schema: facts.schema ?? "",
    table: facts.table ?? "",
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

export function healthForRejectedStarts(rejectedStarts: number, monotonicNs: bigint) {
  const count = Math.max(0, Math.trunc(rejectedStarts));
  return create(HealthSchema, {
    monotonicNs,
    queueDepthBatches: 0,
    residentBytes: 0n,
    status: `recording-starts-rejected=${count}`,
  });
}

export interface RecordingAssemblerOptions {
  /** Maximum events packed into one `EventBatch`; defaults to 1 to preserve unit-step assembly. */
  maxBatchEvents?: number | undefined;
}

export interface RecordingAssembler {
  handle(message: InputMessage): Promise<boolean>;
  /** Coalesces multiple ordered event messages for one recording up to the configured batch cap. */
  handleEventBatch?(recordingId: string, messages: readonly InputMessage[]): Promise<boolean>;
  /** Sends held starts and their events for recordings that never finished (worker closing). */
  flushHeld(): Promise<void>;
}

export function createRecordingAssembler(
  send: SendFn,
  now: () => bigint = () => process.hrtime.bigint(),
  holdMs: number = HOLD_START_MS,
  options: RecordingAssemblerOptions = {},
): RecordingAssembler {
  const batchLimit = Math.max(1, Math.min(Math.trunc(options.maxBatchEvents ?? 1), MAX_WORKER_BATCH_EVENTS));
  const recordings = new Map<string, RecordingState>();

  async function sendStart(recordingId: string, state: RecordingState, summary?: RecordingSummary): Promise<void> {
    const started = create(RecordingStartedSchema, {
      recordingId: state.bytes,
      recordingSeq: 1n,
      method: state.method,
      matchedRouteTemplate: state.route ?? summary?.route ?? "",
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

  async function sendEventBatch(recordingId: string, state: RecordingState, messages: readonly InputMessage[]): Promise<void> {
    const valid = messages.filter(
      (message): message is InputMessage & { eventId: string; sequence: bigint } =>
        typeof message.eventId === "string" && typeof message.sequence === "bigint",
    );
    if (valid.length === 0) return;
    const encoded = valid.map((message) => encodeEvent({ ...message, monotonicNs: message.monotonicNs ?? now() }));
    const firstSeq = valid[0]!.sequence;
    const lastSeq = valid[valid.length - 1]!.sequence;
    const messageId = valid.length === 1
      ? `node-http-${recordingId}-event-${firstSeq}`
      : `node-http-${recordingId}-events-${firstSeq}-${lastSeq}`;
    await send(messageId, {
      case: "eventBatch",
      value: create(EventBatchSchema, { recordingId: state.bytes, events: encoded }),
    }, recordingId);
    for (const item of valid) state.eventIds.push(item.eventId);
  }

  async function sendEventsChunked(recordingId: string, state: RecordingState, messages: readonly InputMessage[]): Promise<void> {
    for (let offset = 0; offset < messages.length; offset += batchLimit) {
      await sendEventBatch(recordingId, state, messages.slice(offset, offset + batchLimit));
    }
  }

  async function release(recordingId: string, state: RecordingState, summary?: RecordingSummary): Promise<void> {
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = undefined;
    }
    if (state.releasePromise) {
      await state.releasePromise;
    }
    if (state.started && state.held.length === 0) return;
    const run = (async () => {
      if (!state.started) {
        state.routeLost = summary === undefined;
        await sendStart(recordingId, state, summary);
      }
      while (state.held.length > 0) {
        const chunk = state.held.splice(0, batchLimit);
        await sendEventBatch(recordingId, state, chunk);
      }
    })();
    state.releasePromise = run;
    try {
      await run;
    } finally {
      if (state.releasePromise === run) state.releasePromise = undefined;
    }
  }

  async function appendEvents(recordingId: string, state: RecordingState, messages: readonly InputMessage[]): Promise<void> {
    if (messages.length === 0) return;
    if (state.releasePromise) {
      // Wait for an in-flight release() to finish draining state.held before sending newer events
      // so recording_seq ordering stays strictly contiguous.
      await state.releasePromise;
    }
    if (state.started && state.held.length === 0) {
      await sendEventsChunked(recordingId, state, messages);
      return;
    }
    if (state.held.length + messages.length <= MAX_HELD_EVENTS) {
      state.held.push(...messages);
      return;
    }
    const room = Math.max(0, MAX_HELD_EVENTS - state.held.length);
    if (room > 0) state.held.push(...messages.slice(0, room));
    await release(recordingId, state);
    if (room < messages.length) {
      await sendEventsChunked(recordingId, state, messages.slice(room));
    }
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
          routeLost: false,
        };
        recordings.set(recordingId, state);
        // Without a module that can still resolve a route the start goes out immediately, so an
        // interrupted request is visible (and reopens as partial) instead of vanishing.
        if (!state.hold) await sendStart(recordingId, state);
        else {
          state.timer = setTimeout(() => {
            if (recordings.get(recordingId) === state && !state.started) void release(recordingId, state).catch(() => undefined);
          }, holdMs);
          state.timer.unref?.();
        }
        return true;
      }
      const state = recordings.get(recordingId);
      if (!state) return false;
      if (message.type === "route") {
        // The route is known at match time: release the held start now so a long request is visible
        // with its template. Only the first announcement counts, and only before the start went out.
        if (typeof message.route === "string" && message.route !== "" && !state.started && state.route === undefined) {
          state.route = message.route.slice(0, 1024);
          await release(recordingId, state, { route: state.route });
        }
        return true;
      }
      if (message.type === "event") {
        await appendEvents(recordingId, state, [message]);
        return true;
      }
      if (message.type === "finish") {
        const summary = message.summary;
        await release(recordingId, state, summary);
        const digest = Buffer.from(await blake3(Buffer.from(state.eventIds.join(""), "utf8")), "hex");
        const dropped = Math.max(0, Math.min(message.droppedEvents ?? 0, 0xffff_ffff));
        const limitations = (summary?.limitations ?? []).filter((code) => /^[a-z][a-z0-9_]{0,127}$/.test(code)).slice(0, 64);
        // The start already went out without the route, so the finished recording must not claim one.
        if (state.routeLost && !limitations.includes("route_unavailable")) limitations.push("route_unavailable");
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
    async handleEventBatch(recordingId, messages) {
      const state = recordings.get(recordingId);
      if (!state) return false;
      await appendEvents(recordingId, state, messages);
      return true;
    },
    async flushHeld() {
      for (const [recordingId, state] of recordings) {
        if (!state.started || state.held.length > 0) await release(recordingId, state);
      }
    },
  };
}

export interface WorkerDeliverySchedulerOptions {
  maxBatchEvents?: number | undefined;
  beforeDeliver?: (() => Promise<void>) | undefined;
  onStaged?: ((count: number) => void) | undefined;
  onError?: ((error: unknown) => void) | undefined;
}

export interface WorkerDeliveryScheduler {
  enqueue(message: InputMessage): void;
  flush(): Promise<void>;
  drain(): Promise<void>;
}

/**
 * Per-recording FIFO scheduler that prioritizes recordings whose `finish` has arrived and
 * coalesces consecutive `event` messages for the same recording up to `maxBatchEvents`.
 */
export function createWorkerDeliveryScheduler(
  assembler: RecordingAssembler,
  options: WorkerDeliverySchedulerOptions = {},
): WorkerDeliveryScheduler {
  const batchLimit = Math.max(1, Math.min(Math.trunc(options.maxBatchEvents ?? 1), MAX_WORKER_BATCH_EVENTS));
  const mailboxes = new Map<string, InputMessage[]>();
  const finishedIds = new Set<string>();
  const orphanQueue: InputMessage[] = [];
  let failed = false;
  let pumpPromise: Promise<void> | undefined;

  const pickNextRecordingId = (): string | undefined => {
    for (const id of finishedIds) {
      const box = mailboxes.get(id);
      if (box && box.length > 0) return id;
      finishedIds.delete(id);
    }
    for (const [id, box] of mailboxes) {
      if (box.length > 0) return id;
      mailboxes.delete(id);
    }
    return undefined;
  };

  const runPump = async (): Promise<void> => {
    await options.beforeDeliver?.();
    while (!failed) {
      if (orphanQueue.length > 0) {
        const orphan = orphanQueue.shift()!;
        await assembler.handle(orphan);
        options.onStaged?.(1);
        continue;
      }
      const recordingId = pickNextRecordingId();
      if (!recordingId) break;
      const mailbox = mailboxes.get(recordingId)!;
      const first = mailbox[0]!;
      if (first.type === "event" && assembler.handleEventBatch) {
        let count = 1;
        while (count < batchLimit && count < mailbox.length && mailbox[count]!.type === "event") {
          count += 1;
        }
        const batch = mailbox.splice(0, count);
        if (mailbox.length === 0) {
          mailboxes.delete(recordingId);
          finishedIds.delete(recordingId);
        }
        await assembler.handleEventBatch(recordingId, batch);
        options.onStaged?.(batch.length);
        continue;
      }
      mailbox.shift();
      if (mailbox.length === 0) {
        mailboxes.delete(recordingId);
        finishedIds.delete(recordingId);
      }
      await assembler.handle(first);
      options.onStaged?.(1);
    }
  };

  const ensurePump = (): Promise<void> => {
    if (!pumpPromise) {
      pumpPromise = runPump()
        .catch((error) => {
          failed = true;
          mailboxes.clear();
          finishedIds.clear();
          orphanQueue.length = 0;
          options.onError?.(error);
        })
        .finally(() => {
          pumpPromise = undefined;
          if (!failed && (orphanQueue.length > 0 || mailboxes.size > 0)) {
            void ensurePump();
          }
        });
    }
    return pumpPromise;
  };

  const drain = async (): Promise<void> => {
    while (!failed && (pumpPromise !== undefined || mailboxes.size > 0 || orphanQueue.length > 0)) {
      await ensurePump();
    }
  };

  return {
    enqueue(message) {
      if (failed) return;
      const recordingId = message.recordingId;
      if (typeof recordingId !== "string") {
        orphanQueue.push(message);
        void ensurePump();
        return;
      }
      let mailbox = mailboxes.get(recordingId);
      if (!mailbox) {
        mailbox = [];
        mailboxes.set(recordingId, mailbox);
      }
      mailbox.push(message);
      if (message.type === "finish") {
        finishedIds.add(recordingId);
      }
      void ensurePump();
    },
    flush: drain,
    drain,
  };
}
