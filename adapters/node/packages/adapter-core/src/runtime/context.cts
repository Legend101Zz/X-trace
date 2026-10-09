import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import type { CaptureEvent, EventDraft, CaptureEventKind } from "./events.cjs";
import type { HttpCaptureTransport, RecordingSummary } from "./transport.cjs";

/** Final classification of how the request ended, from what the adapter itself observed. */
export type ObservedOutcome = "responded" | "exception-propagated" | "client-aborted" | "unobserved";

/** One recording per HTTP request root; modules enrich it but never create a second one. */
export interface RecordingContext {
  id: string;
  startedAtNs: bigint;
  method: string;
  nextSequence: bigint;
  droppedEvents: number;
  finished: boolean;
  /** The root listener frame; parent for response events. */
  frameEventId: string;
  /** True once a root exists for this request; modules check it before opening anything new. */
  rootCreated: boolean;
  /** Route template once a framework module resolves it; empty when unresolved. */
  route: string;
  /** Response status once observed; 0 means not observed. */
  status: number;
  threw: boolean;
  /** Event id of the root frame-throw and the thrown type, when the root listener threw. */
  thrownFromEventId: string;
  exceptionType: string;
  /** True when a framework module may still resolve the route, so the start is held until finish. */
  holdStart: boolean;
  outcome: ObservedOutcome;
  /** Stack of open frame event ids, innermost last. */
  frameStack: string[];
  limitations: Set<string>;
}

/** What this process's installed modules imply for every recording; set once at capture start. */
export interface CaptureProfile {
  limitations: readonly string[];
  holdStart: boolean;
}

let profile: CaptureProfile = { limitations: [], holdStart: false };

export function setCaptureProfile(next: CaptureProfile): void {
  profile = { limitations: [...next.limitations], holdStart: next.holdStart };
}

export function captureProfile(): CaptureProfile {
  return { limitations: [...profile.limitations], holdStart: profile.holdStart };
}

/** Resolves a route template from the finished request; framework modules register one each. */
export type RouteResolver = (request: unknown) => string;
const routeResolvers: RouteResolver[] = [];

export function registerRouteResolver(resolver: RouteResolver): void {
  routeResolvers.push(resolver);
}

/** First resolver that yields a template wins; a throwing resolver never affects the application. */
export function resolveRoute(request: unknown): string {
  for (const resolver of routeResolvers) {
    try {
      const route = resolver(request);
      if (route) return route;
    } catch { /* resolvers are best effort */ }
  }
  return "";
}

/**
 * A framework matched a route while the request ran: remember it, tell the worker (which releases
 * the held start with the template) and drop `route_unavailable` for this recording only.
 * First announcement wins; later matches of the same request never change what the start carried.
 */
export function announceRoute(context: RecordingContext, transport: HttpCaptureTransport, route: string): void {
  if (context.route !== "" || context.finished || route === "") return;
  context.route = route;
  context.limitations.delete("route_unavailable");
  try { transport.route?.(context.id, route); } catch { /* best effort */ }
}

const contexts = new AsyncLocalStorage<RecordingContext>();
const suppression = new AsyncLocalStorage<true>();

export function currentContext(): RecordingContext | undefined {
  return contexts.getStore();
}

const byRequest = new WeakMap<object, RecordingContext>();

/** Remembers which recording a request belongs to, for callbacks AsyncLocalStorage does not reach (raw `req.on('data')`). */
export function bindRequest(request: unknown, context: RecordingContext): void {
  if (request !== null && typeof request === "object") byRequest.set(request, context);
}

export function contextForRequest(request: unknown): RecordingContext | undefined {
  return request !== null && typeof request === "object" ? byRequest.get(request) : undefined;
}

export function runInContext<T>(context: RecordingContext, callback: () => T): T {
  return contexts.run(context, callback);
}

/** Runs callback so that nothing it does (X-trace's own sockets, timers) can be recorded. */
export function withoutCapture<T>(callback: () => T): T {
  return suppression.run(true, callback);
}

export function captureSuppressed(): boolean {
  return suppression.getStore() === true;
}

export function createContext(method: string, startedAtNs: bigint): RecordingContext {
  return {
    id: uuidV7(),
    startedAtNs,
    method,
    nextSequence: 2n,
    droppedEvents: 0,
    finished: false,
    frameEventId: "",
    rootCreated: true,
    route: "",
    status: 0,
    threw: false,
    thrownFromEventId: "",
    exceptionType: "",
    holdStart: profile.holdStart,
    outcome: "unobserved",
    frameStack: [],
    limitations: new Set(profile.limitations),
  };
}

/**
 * Assigns the next contiguous recording sequence and hands the event to the transport.
 * Returns the new event id, or "" when the event was suppressed, out of context, or dropped
 * (drops are counted so the terminal message can carry them).
 */
export function recordEvent(
  context: RecordingContext,
  transport: HttpCaptureTransport,
  draft: EventDraft & { kind: CaptureEventKind },
): string {
  if (captureSuppressed() || contexts.getStore() !== context) return "";
  const sequence = context.nextSequence;
  const eventId = `${context.id}:event:${sequence}`;
  const { kind, parentEventId, symbol, exceptionType, ...rest } = draft;
  const event: CaptureEvent = {
    kind,
    eventId,
    sequence,
    monotonicNs: process.hrtime.bigint(),
    parentEventId: parentEventId ?? "",
    symbol: symbol ?? "",
    exceptionType: exceptionType ?? "",
    ...rest,
  };
  const accepted = transport.event(context.id, event);
  if (accepted) context.nextSequence += 1n;
  else context.droppedEvents += 1;
  return accepted ? eventId : "";
}

/** Closes the recording exactly once, carrying whatever route, status and outcome were resolved. */
export function finishContext(context: RecordingContext, transport: HttpCaptureTransport): void {
  const duration = process.hrtime.bigint() - context.startedAtNs;
  const summary: RecordingSummary = {
    route: context.route,
    httpStatus: context.status,
    outcome: context.outcome,
    limitations: [...context.limitations].sort(),
    ...(context.outcome === "exception-propagated"
      ? { thrownFromEventId: context.thrownFromEventId, exceptionType: context.exceptionType || "UnknownError" }
      : {}),
  };
  transport.finish(context.id, context.nextSequence - 1n, duration >= 0n ? duration : 0n, context.droppedEvents, summary);
}

export function uuidV7(): string {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
