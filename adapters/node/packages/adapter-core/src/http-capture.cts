import http = require("node:http");
import nodeModule = require("node:module");
import type { IncomingMessage, ServerResponse } from "node:http";
import { createContext, finishContext, recordEvent, runInContext, type RecordingContext } from "./runtime/context.cjs";
import { events, type CaptureEvent, type CaptureEventKind } from "./runtime/events.cjs";
import { createHttpCaptureTransport, type HttpCaptureTransport } from "./runtime/transport.cjs";

export { createHttpCaptureTransport, type HttpCaptureTransport };
export type { CaptureEvent };
export type HttpCaptureEventKind = CaptureEventKind;

const PATCHED = Symbol.for("xtrace.node.http.capture.v1");
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);
const ROOT_SYMBOL = "node:http.createServer.listener";
type RequestListener = (request: IncomingMessage, response: ServerResponse) => unknown;

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
    const method = typeof request.method === "string" && HTTP_METHODS.has(request.method) ? request.method : "";
    const context = createContext(method, startedAtNs);
    if (!transport.start(context.id, method, startedAtNs)) {
      return Reflect.apply(listener, this, [request, response]) as void;
    }

    return runInContext(context, () => {
      response.once("finish", () => runInContext(context, () => closeRecording(context, "response-finish", transport)));
      response.once("close", () => runInContext(context, () => closeRecording(context, "response-close", transport)));
      context.frameEventId = recordEvent(context, transport, events.frameEnter(ROOT_SYMBOL));
      if (context.frameEventId) context.frameStack.push(context.frameEventId);
      try {
        const result = Reflect.apply(listener, this, [request, response]);
        if (context.frameEventId) recordEvent(context, transport, events.frameExit(ROOT_SYMBOL, context.frameEventId));
        else context.droppedEvents += 1;
        return result;
      } catch (error) {
        context.threw = true;
        recordEvent(context, transport, events.frameThrow(ROOT_SYMBOL, context.frameEventId, error));
        throw error;
      }
    });
  };
}

function closeRecording(context: RecordingContext, kind: "response-finish" | "response-close", transport: HttpCaptureTransport): void {
  if (context.finished) return;
  context.finished = true;
  recordEvent(context, transport, events.response(kind, context.frameEventId));
  finishContext(context, transport);
}

function disableCapture(): void {
  activeTransport = undefined;
  if (warningIssued) return;
  warningIssued = true;
  process.emitWarning("X-trace Node HTTP capture stopped after a transport failure.", { code: "XTR-NODE-TRANSPORT" });
}
