import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import http = require("node:http");
import nodeModule = require("node:module");
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Worker } from "node:worker_threads";

const PATCHED = Symbol.for("xtrace.node.http.capture.v1");
const MAX_IN_FLIGHT_MESSAGES = 64;
const MAX_ACTIVE_RECORDINGS = 64;
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);
type RequestListener = (request: IncomingMessage, response: ServerResponse) => unknown;

export type HttpCaptureEventKind = "frame-enter" | "frame-exit" | "frame-throw" | "response-finish" | "response-close";

export interface HttpCaptureTransport {
  start(recordingId: string, method: string, startedAtNs: bigint): boolean;
  event(recordingId: string, event: CaptureEvent): boolean;
  finish(recordingId: string, finalSequence: bigint, durationNs: bigint, droppedEvents: number): boolean;
  onFailure(callback: () => void): void;
  close(): void;
}

interface WorkerMessage {
  type: "staged" | "failure";
}

interface RecordingMessage {
  type: "start" | "event" | "finish";
  [key: string]: string | bigint | number | Uint8Array | undefined;
}

/** Keeps app-thread handoff bounded and reserves one terminal slot per admitted request. */
export function createHttpCaptureTransport(worker: Worker): HttpCaptureTransport {
  let pending = 0;
  let reservedFinishes = 0;
  let failed = false;
  let failureCallback: (() => void) | undefined;

  const fail = () => {
    if (failed) return;
    failed = true;
    pending = 0;
    reservedFinishes = 0;
    failureCallback?.();
  };
  worker.on("message", (message: WorkerMessage) => {
    if (message?.type === "staged") pending = Math.max(0, pending - 1);
    else if (message?.type === "failure") fail();
  });
  worker.on("error", fail);
  worker.on("exit", (code) => { if (code !== 0) fail(); });

  const post = (message: RecordingMessage): boolean => {
    if (failed) return false;
    try {
      worker.postMessage(message);
      pending += 1;
      return true;
    } catch {
      fail();
      return false;
    }
  };

  return {
    start(recordingId, method, startedAtNs) {
      if (pending + reservedFinishes + 2 > MAX_IN_FLIGHT_MESSAGES || reservedFinishes >= MAX_ACTIVE_RECORDINGS) return false;
      reservedFinishes += 1;
      if (post({ type: "start", recordingId, method, startedAtNs })) return true;
      reservedFinishes = Math.max(0, reservedFinishes - 1);
      return false;
    },
    event(recordingId, event) {
      if (pending + reservedFinishes >= MAX_IN_FLIGHT_MESSAGES) return false;
      return post({ type: "event", recordingId, ...event });
    },
    finish(recordingId, finalSequence, durationNs, droppedEvents) {
      if (reservedFinishes === 0 || failed) return false;
      reservedFinishes -= 1;
      return post({ type: "finish", recordingId, finalSequence, durationNs, droppedEvents });
    },
    onFailure(callback) { failureCallback = callback; },
    close() {
      if (!failed) {
        try {
          worker.ref();
          worker.postMessage({ type: "close" });
        } catch { fail(); }
      }
    },
  };
}

export interface CaptureEvent {
  kind: HttpCaptureEventKind;
  eventId: string;
  sequence: bigint;
  monotonicNs: bigint;
  parentEventId: string;
  symbol: string;
  exceptionType: string;
}

interface RecordingContext {
  id: string;
  startedAtNs: bigint;
  nextSequence: bigint;
  droppedEvents: number;
  finished: boolean;
  frameEventId: string;
}

const contexts = new AsyncLocalStorage<RecordingContext>();
let activeTransport: HttpCaptureTransport | undefined;
let warningIssued = false;

/** Installs the native `node:http` createServer callback boundary once. */
export function installHttpCapture(transport: HttpCaptureTransport): void {
  if ((http.createServer as typeof http.createServer & { [PATCHED]?: boolean })[PATCHED]) {
    activeTransport = transport;
    transport.onFailure(disableCapture);
    return;
  }
  activeTransport = transport;
  transport.onFailure(disableCapture);

  const createServer = http.createServer as (...args: unknown[]) => http.Server;
  const wrappedCreateServer = function xtraceCreateServer(this: typeof http, ...args: unknown[]): http.Server {
    const listenerIndex = typeof args[0] === "function" ? 0 : typeof args[1] === "function" ? 1 : -1;
    if (listenerIndex < 0) return createServer.apply(this, args);
    const listener = args[listenerIndex] as RequestListener;
    const wrapped = wrapRequestListener(listener);
    Object.defineProperty(wrapped, "listener", { value: listener });
    const nextArgs = [...args];
    nextArgs[listenerIndex] = wrapped;
    return createServer.apply(this, nextArgs);
  } as typeof http.createServer & { [PATCHED]?: boolean };
  Object.defineProperty(wrappedCreateServer, PATCHED, { value: true });
  http.createServer = wrappedCreateServer;
  nodeModule.syncBuiltinESMExports();

  process.once("beforeExit", () => activeTransport?.close());
}

/** Wraps one registered native server callback, retaining only call and response-boundary events. */
export function wrapRequestListener(listener: RequestListener): RequestListener {
  return function xtraceRequestBoundary(this: unknown, request: IncomingMessage, response: ServerResponse): unknown {
    const transport = activeTransport;
    if (!transport) return Reflect.apply(listener, this, [request, response]) as void;
    const startedAtNs = process.hrtime.bigint();
    const context: RecordingContext = {
      id: uuidV7(),
      startedAtNs,
      nextSequence: 2n,
      droppedEvents: 0,
      finished: false,
      frameEventId: "",
    };
    const method = typeof request.method === "string" && HTTP_METHODS.has(request.method) ? request.method : "";
    if (!transport.start(context.id, method, startedAtNs)) {
      return Reflect.apply(listener, this, [request, response]) as void;
    }

    return contexts.run(context, () => {
      response.once("finish", () => contexts.run(context, () => finish(context, "response-finish", transport)));
      response.once("close", () => contexts.run(context, () => finish(context, "response-close", transport)));
      context.frameEventId = recordEvent(context, "frame-enter", "node:http.createServer.listener", "", transport);
      try {
        const result = Reflect.apply(listener, this, [request, response]);
        if (context.frameEventId) recordEvent(context, "frame-exit", "node:http.createServer.listener", "", transport, context.frameEventId);
        else context.droppedEvents += 1;
        return result;
      } catch (error) {
        recordEvent(context, "frame-throw", "node:http.createServer.listener", safeExceptionType(error), transport, context.frameEventId);
        throw error;
      }
    });
  };
}

function recordEvent(
  context: RecordingContext,
  kind: HttpCaptureEventKind,
  symbol: string,
  exceptionType: string,
  transport: HttpCaptureTransport,
  parentEventId = "",
): string {
  if (contexts.getStore() !== context) return "";
  const sequence = context.nextSequence;
  const eventId = `${context.id}:event:${sequence}`;
  const accepted = transport.event(context.id, {
    kind,
    eventId,
    sequence,
    monotonicNs: process.hrtime.bigint(),
    parentEventId,
    symbol,
    exceptionType,
  });
  if (accepted) context.nextSequence += 1n;
  else context.droppedEvents += 1;
  return accepted ? eventId : "";
}

function finish(context: RecordingContext, kind: "response-finish" | "response-close", transport: HttpCaptureTransport): void {
  if (context.finished) return;
  context.finished = true;
  recordEvent(context, kind, kind === "response-finish" ? "node:http.response.finish" : "node:http.response.close", "", transport, context.frameEventId);
  const duration = process.hrtime.bigint() - context.startedAtNs;
  transport.finish(context.id, context.nextSequence - 1n, duration >= 0n ? duration : 0n, context.droppedEvents);
}

function safeExceptionType(error: unknown): string {
  if (error instanceof Error) {
    return "Error";
  }
  return "UnknownError";
}

function uuidV7(): string {
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

function disableCapture(): void {
  activeTransport = undefined;
  if (warningIssued) return;
  warningIssued = true;
  process.emitWarning("X-trace Node HTTP capture stopped after a transport failure.", { code: "XTR-NODE-TRANSPORT" });
}
