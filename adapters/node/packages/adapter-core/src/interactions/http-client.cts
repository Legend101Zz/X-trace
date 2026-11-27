import { AsyncLocalStorage } from "node:async_hooks";
import http = require("node:http");
import https = require("node:https");
import nodeModule = require("node:module");
import { captureSuppressed, currentContext, recordEvent, runInContext, type RecordingContext } from "../runtime/context.cjs";
import { events } from "../runtime/events.cjs";
import {
  safeExceptionFacts,
  sanitizeHttpTarget,
  sanitizeInteractionFacts,
  sanitizeStatusCode,
} from "./redact.cjs";
import type { InteractionPatchHooks } from "./pg.cjs";

/**
 * Outbound HTTP interaction capture for `node:http`/`node:https` (`.request`/`.get`),
 * `globalThis.fetch`, and `undici` (`.request`/`.fetch`).
 * Never leaks query parameters, credentials (`user:pass@`, `options.auth`), Authorization/Cookie
 * headers, or request/response bodies. Preserves `EventEmitter.listenerCount("error")` by
 * wrapping `emit` on the request/response instance rather than registering an `'error'` listener.
 */

const PATCHED = Symbol.for("xtrace.node.http.client.patch.v1");
const UNDICI_ENTRY = /[\\/]node_modules[\\/]undici[\\/]index\.js$/;

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;
type EmitFn = (this: unknown, event: string | symbol, ...args: unknown[]) => unknown;
type CompileFn = (this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]) => unknown;

export interface HttpClientPatchStatus {
  patched: number;
  undiciPatched: number;
}

let hooks: InteractionPatchHooks | undefined;
const counters: HttpClientPatchStatus = { patched: 0, undiciPatched: 0 };
const inOutboundHttp = new AsyncLocalStorage<true>();
const seenRequests = new WeakSet<object>();

export function httpClientPatchStatus(): Readonly<HttpClientPatchStatus> {
  return { ...counters };
}

export function installHttpClientCapture(next: InteractionPatchHooks): void {
  hooks = next;
  patchNodeHttpModule(http, "node:http", "http:");
  patchNodeHttpModule(https, "node:https", "https:");
  try {
    (nodeModule as unknown as { syncBuiltinESMExports?: () => void }).syncBuiltinESMExports?.();
  } catch { /* best effort */ }
  patchGlobalFetch();
  installUndiciHook();
}

function patchNodeHttpModule(
  mod: { request: unknown; get: unknown },
  driver: "node:http" | "node:https",
  defaultProtocol: "http:" | "https:",
): void {
  for (const methodName of ["request", "get"] as const) {
    const original = mod[methodName] as (AnyFn & { [PATCHED]?: true }) | undefined;
    if (typeof original !== "function" || original[PATCHED]) continue;
    const wrapped = function xtraceNodeHttpOutbound(this: unknown, ...args: unknown[]): unknown {
      const context = currentContext();
      const transport = hooks?.transport();
      if (!context || !transport || context.finished || captureSuppressed() || inOutboundHttp.getStore()) {
        return Reflect.apply(original, this, args);
      }

      const target = extractNodeHttpTarget(args, defaultProtocol);
      const startFacts = sanitizeInteractionFacts({
        kind: "outbound-http",
        driver,
        method: target.method,
        summary: target.summary,
        host: target.host,
        ...(target.port !== undefined ? { port: target.port } : {}),
      });
      const parent = currentParent(context);
      const startId = recordEvent(context, transport, events.interactionStart(startFacts, parent));
      const targetParent = startId || parent;

      let ended = false;
      const finish = (statusCode?: number, err?: unknown): void => {
        if (ended) return;
        ended = true;
        if (context.finished) return;
        runInContext(context, () => {
          if (err !== undefined && err !== null) {
            recordEvent(context, transport, events.exception(safeExceptionFacts(err), targetParent));
          }
          const endFacts = sanitizeInteractionFacts({
            ...startFacts,
            ...(statusCode !== undefined ? { statusCode } : {}),
          });
          recordEvent(context, transport, events.interactionEnd(endFacts, targetParent));
        });
      };

      let req: unknown;
      try {
        req = inOutboundHttp.run(true, () => Reflect.apply(original, this, args));
      } catch (error) {
        finish(undefined, error);
        throw error;
      }

      if (req !== null && typeof req === "object") {
        if (seenRequests.has(req)) return req;
        seenRequests.add(req);
        const emitter = req as { emit?: EmitFn };
        if (typeof emitter.emit === "function") {
          const origReqEmit = emitter.emit;
          let observedStatus: number | undefined;
          emitter.emit = function xtraceClientReqEmit(this: unknown, event: string | symbol, ...emitArgs: unknown[]): unknown {
            if (event === "response") {
              const res = emitArgs[0] as { statusCode?: unknown; emit?: EmitFn } | undefined;
              observedStatus = sanitizeStatusCode(res?.statusCode);
              if (res && typeof res === "object" && typeof res.emit === "function") {
                const origResEmit = res.emit;
                res.emit = function xtraceClientResEmit(this: unknown, resEvent: string | symbol, ...resArgs: unknown[]): unknown {
                  if (resEvent === "error") finish(observedStatus, resArgs[0]);
                  else if (resEvent === "end" || resEvent === "close") finish(observedStatus);
                  return Reflect.apply(origResEmit, this, [resEvent, ...resArgs]);
                };
              } else {
                finish(observedStatus);
              }
            } else if (event === "error") {
              finish(observedStatus, emitArgs[0]);
            } else if (event === "close") {
              finish(observedStatus);
            }
            return Reflect.apply(origReqEmit, this, [event, ...emitArgs]);
          };
        } else {
          finish();
        }
      } else {
        finish();
      }
      return req;
    } as AnyFn & { [PATCHED]?: true };

    Object.defineProperty(wrapped, "length", { value: original.length });
    Object.defineProperty(wrapped, "name", { value: original.name });
    Object.defineProperty(wrapped, PATCHED, { value: true });
    (mod as Record<string, unknown>)[methodName] = wrapped;
    counters.patched += 1;
  }
}

function patchGlobalFetch(): void {
  const g = globalThis as { fetch?: AnyFn & { [PATCHED]?: true } };
  const originalFetch = g.fetch;
  if (typeof originalFetch !== "function" || originalFetch[PATCHED]) return;
  const wrapped = wrapFetchFn(originalFetch, "fetch");
  g.fetch = wrapped;
  counters.patched += 1;
}

function installUndiciHook(): void {
  const proto = (nodeModule as unknown as { prototype: { _compile: CompileFn & { [PATCHED]?: true } } }).prototype;
  if (proto._compile[PATCHED]) return;
  const original = proto._compile;
  const wrapped = function xtraceUndiciCompile(this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]): unknown {
    const result = Reflect.apply(original, this, [content, filename, ...rest]);
    if (typeof filename === "string" && UNDICI_ENTRY.test(filename)) {
      try { instrumentUndiciModule(this.exports, hooks); } catch { /* ignore unrecognized shape */ }
    }
    return result;
  } as CompileFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto._compile = wrapped;
}

export function instrumentUndiciModule(undiciExports: unknown, customHooks?: InteractionPatchHooks): boolean {
  if (customHooks) hooks = customHooks;
  if (undiciExports === null || typeof undiciExports !== "object") return false;
  const mod = undiciExports as { request?: AnyFn & { [PATCHED]?: true }; fetch?: AnyFn & { [PATCHED]?: true } };
  let didPatch = false;
  if (typeof mod.fetch === "function" && !mod.fetch[PATCHED]) {
    mod.fetch = wrapFetchFn(mod.fetch, "undici");
    counters.undiciPatched += 1;
    didPatch = true;
  }
  if (typeof mod.request === "function" && !mod.request[PATCHED]) {
    const originalReq = mod.request;
    const wrappedReq = function xtraceUndiciRequest(this: unknown, urlArg: unknown, optionsArg?: unknown, ...rest: unknown[]): unknown {
      const context = currentContext();
      const transport = hooks?.transport();
      if (!context || !transport || context.finished || captureSuppressed() || inOutboundHttp.getStore()) {
        return Reflect.apply(originalReq, this, [urlArg, optionsArg, ...rest]);
      }
      const opts = optionsArg !== null && typeof optionsArg === "object"
        ? optionsArg as { method?: unknown; path?: unknown }
        : {};
      const target = sanitizeHttpTarget(urlArg, { method: opts.method, path: opts.path }, "http:");
      const startFacts = sanitizeInteractionFacts({
        kind: "outbound-http",
        driver: "undici",
        method: target.method,
        summary: target.summary,
        host: target.host,
        ...(target.port !== undefined ? { port: target.port } : {}),
      });
      return runPromiseHttpInteraction(context, transport, startFacts, () =>
        inOutboundHttp.run(true, () => Reflect.apply(originalReq, this, [urlArg, optionsArg, ...rest])),
      );
    } as AnyFn & { [PATCHED]?: true };
    Object.defineProperty(wrappedReq, "length", { value: originalReq.length });
    Object.defineProperty(wrappedReq, "name", { value: originalReq.name });
    Object.defineProperty(wrappedReq, PATCHED, { value: true });
    mod.request = wrappedReq;
    counters.undiciPatched += 1;
    didPatch = true;
  }
  return didPatch;
}

function wrapFetchFn(originalFetch: AnyFn, driver: "fetch" | "undici"): AnyFn & { [PATCHED]?: true } {
  const wrapped = function xtraceFetch(this: unknown, input: unknown, init?: unknown, ...rest: unknown[]): unknown {
    const context = currentContext();
    const transport = hooks?.transport();
    if (!context || !transport || context.finished || captureSuppressed() || inOutboundHttp.getStore()) {
      return Reflect.apply(originalFetch, this, [input, init, ...rest]);
    }
    const target = extractFetchTarget(input, init);
    const startFacts = sanitizeInteractionFacts({
      kind: "outbound-http",
      driver,
      method: target.method,
      summary: target.summary,
      host: target.host,
      ...(target.port !== undefined ? { port: target.port } : {}),
    });
    return runPromiseHttpInteraction(context, transport, startFacts, () =>
      inOutboundHttp.run(true, () => Reflect.apply(originalFetch, this, [input, init, ...rest])),
    );
  } as AnyFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, "length", { value: originalFetch.length });
  Object.defineProperty(wrapped, "name", { value: originalFetch.name });
  Object.defineProperty(wrapped, PATCHED, { value: true });
  return wrapped;
}

function runPromiseHttpInteraction(
  context: RecordingContext,
  transport: ReturnType<InteractionPatchHooks["transport"]>,
  startFacts: ReturnType<typeof sanitizeInteractionFacts>,
  invoke: () => unknown,
): unknown {
  const parent = currentParent(context);
  const startId = recordEvent(context, transport, events.interactionStart(startFacts, parent));
  const targetParent = startId || parent;
  let ended = false;

  const finish = (statusCode?: number, err?: unknown): void => {
    if (ended) return;
    ended = true;
    if (context.finished) return;
    runInContext(context, () => {
      if (err !== undefined && err !== null) {
        recordEvent(context, transport, events.exception(safeExceptionFacts(err), targetParent));
      }
      const endFacts = sanitizeInteractionFacts({
        ...startFacts,
        ...(statusCode !== undefined ? { statusCode } : {}),
      });
      recordEvent(context, transport, events.interactionEnd(endFacts, targetParent));
    });
  };

  try {
    const result = invoke();
    if (isThenable(result)) {
      void Promise.resolve(result).then(
        (response) => {
          const resp = response as { status?: unknown; statusCode?: unknown } | undefined;
          finish(sanitizeStatusCode(resp?.status ?? resp?.statusCode));
        },
        (err) => finish(undefined, err),
      );
    } else {
      finish();
    }
    return result;
  } catch (error) {
    finish(undefined, error);
    throw error;
  }
}

function extractNodeHttpTarget(args: unknown[], defaultProtocol: "http:" | "https:") {
  let urlArg: unknown;
  let optionsArg: Record<string, unknown> = {};
  if (typeof args[0] === "string" || args[0] instanceof URL) {
    urlArg = args[0];
    if (args[1] !== null && typeof args[1] === "object") optionsArg = args[1] as Record<string, unknown>;
  } else if (args[0] !== null && typeof args[0] === "object") {
    optionsArg = args[0] as Record<string, unknown>;
  }
  return sanitizeHttpTarget(urlArg, {
    method: optionsArg.method,
    host: optionsArg.host,
    hostname: optionsArg.hostname,
    port: optionsArg.port,
    path: optionsArg.path,
    protocol: optionsArg.protocol ?? defaultProtocol,
  }, defaultProtocol);
}

function extractFetchTarget(input: unknown, init: unknown) {
  let urlArg: unknown;
  let reqMethod: unknown;
  if (typeof input === "string" || input instanceof URL) {
    urlArg = input;
  } else if (input !== null && typeof input === "object") {
    const reqObj = input as { url?: unknown; method?: unknown };
    urlArg = reqObj.url;
    reqMethod = reqObj.method;
  }
  const initMethod = init !== null && typeof init === "object" ? (init as { method?: unknown }).method : undefined;
  return sanitizeHttpTarget(urlArg, { method: initMethod ?? reqMethod ?? "GET" }, "http:");
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return value !== null && (typeof value === "object" || typeof value === "function") && typeof (value as { then?: unknown }).then === "function";
}

function currentParent(context: RecordingContext): string {
  return context.frameStack[context.frameStack.length - 1] ?? context.frameEventId ?? "";
}
