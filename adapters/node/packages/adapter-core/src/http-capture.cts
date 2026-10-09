import http = require("node:http");
import https = require("node:https");
import type { IncomingMessage, ServerResponse } from "node:http";
import { captureSuppressed, createContext, finishContext, recordEvent, resolveRoute, runInContext, type RecordingContext } from "./runtime/context.cjs";
import { events, type CaptureEvent, type CaptureEventKind } from "./runtime/events.cjs";
import { createHttpCaptureTransport, type HttpCaptureTransport } from "./runtime/transport.cjs";

export { createHttpCaptureTransport, type HttpCaptureTransport };
export type { CaptureEvent };
export type HttpCaptureEventKind = CaptureEventKind;

const PATCHED = Symbol.for("xtrace.node.http.capture.v2");
const SEEN = new WeakSet<object>();
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);
const ROOT_SYMBOL = "node:http.Server.request";
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

function captureRequest(_thisArg: unknown, request: IncomingMessage, response: ServerResponse, invoke: () => unknown): unknown {
  const transport = activeTransport;
  if (!transport || SEEN.has(request) || captureSuppressed()) return invoke();
  if (typeof response?.once !== "function") return invoke();
  SEEN.add(request);
  const startedAtNs = process.hrtime.bigint();
  const method = typeof request.method === "string" && HTTP_METHODS.has(request.method) ? request.method : "";
  const context = createContext(method, startedAtNs);
  if (!transport.start(context.id, method, startedAtNs, context.holdStart)) return invoke();

  return runInContext(context, () => {
    // Listener bodies must never throw into the application's response machinery.
    const close = (kind: "response-finish" | "response-close") => {
      try {
        runInContext(context, () => closeRecording(context, kind, response, transport, request));
      } catch {
        context.finished = true;
      }
    };
    response.once("finish", () => close("response-finish"));
    response.once("close", () => close("response-close"));
    context.frameEventId = recordEvent(context, transport, events.frameEnter(ROOT_SYMBOL));
    if (context.frameEventId) context.frameStack.push(context.frameEventId);
    try {
      const result = invoke();
      if (context.frameEventId) recordEvent(context, transport, events.frameExit(ROOT_SYMBOL, context.frameEventId));
      else context.droppedEvents += 1;
      return result;
    } catch (error) {
      context.threw = true;
      const thrown = events.frameThrow(ROOT_SYMBOL, context.frameEventId, error);
      context.exceptionType = thrown.exceptionType ?? "UnknownError";
      context.thrownFromEventId = recordEvent(context, transport, thrown);
      throw error;
    }
  });
}

function closeRecording(
  context: RecordingContext,
  kind: "response-finish" | "response-close",
  response: ServerResponse,
  transport: HttpCaptureTransport,
  request: IncomingMessage,
): void {
  if (context.finished) return;
  context.finished = true;
  const completed = kind === "response-finish" || response.writableFinished;
  context.status = completed && Number.isInteger(response.statusCode) ? response.statusCode : 0;
  context.outcome = completed ? "responded" : context.threw ? "exception-propagated" : "client-aborted";
  if (context.threw && !completed) context.status = 0;
  recordEvent(context, transport, events.response(kind, context.frameEventId));
  const route = context.route === "" ? resolveRoute(request) : "";
  if (route) {
    context.route = route;
    context.limitations.delete("route_unavailable");
  }
  finishContext(context, transport);
}

function disableCapture(): void {
  activeTransport = undefined;
  if (warningIssued) return;
  warningIssued = true;
  process.emitWarning("X-trace Node HTTP capture stopped after a transport failure.", { code: "XTR-NODE-TRANSPORT" });
}
