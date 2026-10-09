import http = require("node:http");
import https = require("node:https");
import type { IncomingMessage, ServerResponse } from "node:http";
import { captureSuppressed, createContext, finishContext, recordEvent, runInContext, type RecordingContext } from "./runtime/context.cjs";
import { events, type CaptureEvent, type CaptureEventKind } from "./runtime/events.cjs";
import { createHttpCaptureTransport, type HttpCaptureTransport } from "./runtime/transport.cjs";

export { createHttpCaptureTransport, type HttpCaptureTransport };
export type { CaptureEvent };
export type HttpCaptureEventKind = CaptureEventKind;

const PATCHED = Symbol.for("xtrace.node.http.capture.v2");
const SEEN = new WeakSet<object>();
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);
const ROOT_SYMBOL = "node:http.Server.request";
const MAX_URL_SHAPE_BYTES = 2048;
type RequestListener = (request: IncomingMessage, response: ServerResponse) => unknown;
type Emit = (this: unknown, event: string | symbol, ...args: unknown[]) => boolean;

let activeTransport: HttpCaptureTransport | undefined;
let warningIssued = false;

/**
 * Installs the request root once at `Server.prototype.emit('request')` for http and https.
 * That single seam sees every listener however it was registered (createServer argument,
 * `new Server(listener)`, `server.on('request')`, frameworks), and each request exactly once.
 */
export function installHttpCapture(transport: HttpCaptureTransport): void {
  activeTransport = transport;
  transport.onFailure(disableCapture);
  let installedNow = false;
  for (const prototype of [http.Server.prototype, https.Server.prototype]) {
    installedNow = patchEmit(prototype) || installedNow;
  }
  if (installedNow) process.once("beforeExit", () => activeTransport?.close());
}

function patchEmit(prototype: { emit: Emit }): boolean {
  const original = prototype.emit as Emit & { [PATCHED]?: boolean };
  if (original[PATCHED]) return false;
  const wrapped = function xtraceServerEmit(this: unknown, event: string | symbol, ...args: unknown[]): boolean {
    const request = args[0] as IncomingMessage | undefined;
    const response = args[1] as ServerResponse | undefined;
    if (event !== "request" || !request || !response || typeof request !== "object") {
      return Reflect.apply(original, this, [event, ...args]) as boolean;
    }
    return captureRequest(this, request, response, () => Reflect.apply(original, this, [event, ...args]) as boolean) as boolean;
  } as Emit & { [PATCHED]?: boolean };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  prototype.emit = wrapped;
  return true;
}

/** Wraps one registered request listener with the same root handling (used directly by tests). */
export function wrapRequestListener(listener: RequestListener): RequestListener {
  return function xtraceRequestBoundary(this: unknown, request: IncomingMessage, response: ServerResponse): unknown {
    return captureRequest(this, request, response, () => Reflect.apply(listener, this, [request, response]));
  };
}

/** Path only: no query, fragment or authority, so URL canaries cannot reach the recording. */
export function urlShapeOf(rawUrl: string | undefined): string {
  if (typeof rawUrl !== "string" || !rawUrl.startsWith("/")) return "";
  const cut = rawUrl.search(/[?#]/);
  const path = cut < 0 ? rawUrl : rawUrl.slice(0, cut);
  return Buffer.byteLength(path) > MAX_URL_SHAPE_BYTES ? "" : path;
}

function captureRequest(_thisArg: unknown, request: IncomingMessage, response: ServerResponse, invoke: () => unknown): unknown {
  const transport = activeTransport;
  if (!transport || SEEN.has(request) || captureSuppressed()) return invoke();
  SEEN.add(request);
  const startedAtNs = process.hrtime.bigint();
  const method = typeof request.method === "string" && HTTP_METHODS.has(request.method) ? request.method : "";
  const context = createContext(method, startedAtNs);
  context.urlShape = urlShapeOf(request.url);
  if (!transport.start(context.id, method, startedAtNs)) return invoke();

  return runInContext(context, () => {
    response.once("finish", () => runInContext(context, () => closeRecording(context, "response-finish", response, transport)));
    response.once("close", () => runInContext(context, () => closeRecording(context, "response-close", response, transport)));
    context.frameEventId = recordEvent(context, transport, events.frameEnter(ROOT_SYMBOL));
    if (context.frameEventId) context.frameStack.push(context.frameEventId);
    try {
      const result = invoke();
      if (context.frameEventId) recordEvent(context, transport, events.frameExit(ROOT_SYMBOL, context.frameEventId));
      else context.droppedEvents += 1;
      return result;
    } catch (error) {
      context.threw = true;
      recordEvent(context, transport, events.frameThrow(ROOT_SYMBOL, context.frameEventId, error));
      throw error;
    }
  });
}

function closeRecording(
  context: RecordingContext,
  kind: "response-finish" | "response-close",
  response: ServerResponse,
  transport: HttpCaptureTransport,
): void {
  if (context.finished) return;
  context.finished = true;
  const completed = kind === "response-finish" || response.writableFinished;
  context.status = completed && Number.isInteger(response.statusCode) ? response.statusCode : 0;
  context.outcome = completed ? "responded" : context.threw ? "exception-propagated" : "client-aborted";
  if (context.threw && !completed) context.status = 0;
  recordEvent(context, transport, events.response(kind, context.frameEventId));
  finishContext(context, transport);
}

function disableCapture(): void {
  activeTransport = undefined;
  if (warningIssued) return;
  warningIssued = true;
  process.emitWarning("X-trace Node HTTP capture stopped after a transport failure.", { code: "XTR-NODE-TRANSPORT" });
}
