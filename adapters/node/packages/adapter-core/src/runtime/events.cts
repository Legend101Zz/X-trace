/** Event vocabulary shared by every instrumentation module and the transport worker handoff. */

export type CaptureEventKind =
  | "frame-enter"
  | "frame-exit"
  | "frame-throw"
  | "response-finish"
  | "response-close"
  | "interaction-start"
  | "interaction-end"
  | "exception"
  | "async-link"
  | "gap";

/** Closed interaction kinds; the worker maps them onto the protocol enum. */
export type InteractionKindName = "database" | "outbound-http";

export interface InteractionFacts {
  kind: InteractionKindName;
  driver: string;
  method: string;
  /** Sanitized shape only: never literals, query strings, headers or bodies. */
  summary: string;
  host?: string;
  port?: number;
  statusCode?: number;
  error?: string;
}

export interface ExceptionFacts {
  /** Constructor-derived type name, or `UnknownError`. */
  type: string;
  /** Already sanitized and size-capped by the producer; empty when redaction cannot be proven. */
  message: string;
}

/** Source-attestation outcome the adapter itself observed; maps onto the protocol SourceBinding. */
export type SourceBindingName = "verified" | "observed-unattested" | "source-map-absent" | "source-map-unresolved";

export interface SourceFacts {
  /** Repo-relative path; the worker drops a source that is inconsistent with its binding. */
  binding: SourceBindingName;
  path: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  /** 64 lowercase hex chars (BLAKE3 or SHA-256 per attestation); may be empty only for source-map bindings. */
  contentHash: string;
}

export type GapReasonName =
  | "queue-full"
  | "correlation-lost"
  | "module-loaded-before-arm"
  | "source-map-absent"
  | "child-process-not-instrumented"
  | "bootstrap-consumed";

export interface GapFacts {
  reason: GapReasonName;
  count: number;
  firstSequence: bigint;
  lastSequence: bigint;
}

/** One event handed from the application thread to the transport worker. */
export interface CaptureEvent {
  kind: CaptureEventKind;
  eventId: string;
  sequence: bigint;
  monotonicNs: bigint;
  parentEventId: string;
  symbol: string;
  exceptionType: string;
  /** Event this one was causally scheduled from when it ran on a different async resource. */
  asyncParentEventId?: string;
  interaction?: InteractionFacts;
  exception?: ExceptionFacts;
  source?: SourceFacts;
  gap?: GapFacts;
}

/** Fields a caller supplies; identity, ordering and time come from the context sequencer. */
export interface EventDraft {
  parentEventId?: string;
  symbol?: string;
  exceptionType?: string;
  asyncParentEventId?: string;
  interaction?: InteractionFacts;
  exception?: ExceptionFacts;
  source?: SourceFacts;
  gap?: GapFacts;
}

export type EventBuilder = (kind: CaptureEventKind, draft: EventDraft) => EventDraft & { kind: CaptureEventKind };

/** Typed builders: each returns the kind and the exact fields that kind may carry. */
export const events = {
  frameEnter(symbol: string, source?: SourceFacts): EventDraft & { kind: "frame-enter" } {
    return { kind: "frame-enter", symbol, ...(source ? { source } : {}) };
  },
  frameExit(symbol: string, parentEventId: string, source?: SourceFacts): EventDraft & { kind: "frame-exit" } {
    return { kind: "frame-exit", symbol, parentEventId, ...(source ? { source } : {}) };
  },
  frameThrow(symbol: string, parentEventId: string, error: unknown): EventDraft & { kind: "frame-throw" } {
    return { kind: "frame-throw", symbol, parentEventId, exceptionType: safeExceptionType(error) };
  },
  response(kind: "response-finish" | "response-close", parentEventId: string): EventDraft & { kind: typeof kind } {
    return {
      kind,
      symbol: kind === "response-finish" ? "node:http.response.finish" : "node:http.response.close",
      parentEventId,
    };
  },
  interactionStart(facts: InteractionFacts, parentEventId: string, asyncParentEventId = ""): EventDraft & { kind: "interaction-start" } {
    return {
      kind: "interaction-start",
      symbol: `${facts.driver}.${facts.method}`,
      parentEventId,
      interaction: facts,
      ...(asyncParentEventId ? { asyncParentEventId } : {}),
    };
  },
  interactionEnd(facts: InteractionFacts, parentEventId: string): EventDraft & { kind: "interaction-end" } {
    return { kind: "interaction-end", symbol: `${facts.driver}.${facts.method}`, parentEventId, interaction: facts };
  },
  exception(facts: ExceptionFacts, parentEventId: string): EventDraft & { kind: "exception" } {
    return { kind: "exception", symbol: facts.type, parentEventId, exceptionType: facts.type, exception: facts };
  },
  asyncLink(parentEventId: string, asyncParentEventId: string): EventDraft & { kind: "async-link" } {
    return { kind: "async-link", symbol: "async.link", parentEventId, asyncParentEventId };
  },
  gap(facts: GapFacts, parentEventId = ""): EventDraft & { kind: "gap" } {
    return { kind: "gap", symbol: `gap.${facts.reason}`, parentEventId, gap: facts };
  },
};

/** Never forwards messages or stacks: only a type name that is safe to persist. */
export function safeExceptionType(error: unknown): string {
  return error instanceof Error ? "Error" : "UnknownError";
}
