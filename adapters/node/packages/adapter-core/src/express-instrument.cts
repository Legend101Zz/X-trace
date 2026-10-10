import nodeModule = require("node:module");
import { readFileSync } from "node:fs";
import { announceRoute, contextForRequest, currentContext, runInContext, recordEvent, type RecordingContext } from "./runtime/context.cjs";
import { events } from "./runtime/events.cjs";
import type { HttpCaptureTransport } from "./runtime/transport.cjs";

/**
 * Express 4 (`express/lib/router/layer.js`) and Express 5 (`router@2` `lib/layer.js`) share one shape:
 * every middleware, route container and route handler is a `Layer`. Patching the Layer once, as the
 * module finishes loading, sees router order, the matched Route, handlers and error handlers for both
 * versions with no change to the application and nothing touched when the shape is not recognized.
 */

const PATCHED = Symbol.for("xtrace.node.express.layer.v1");
const MOUNT_PATH = Symbol.for("xtrace.node.express.layer.path");
const WRAPPED_HANDLE = Symbol.for("xtrace.node.express.handle.v1");

const EXPRESS4_LAYER = /[\\/]node_modules[\\/]express[\\/]lib[\\/]router[\\/]layer\.js$/;
const ROUTER2_LAYER = /[\\/]node_modules[\\/]router[\\/]lib[\\/]layer\.js$/;
/** Express's own built-in layers: not application handlers, so they get no frame. */
const INTERNAL_LAYERS = new Set(["query", "expressInit"]);
/** Characters a mount path may contain and still be treated as a literal-with-params template. */
const TEMPLATE_PATH = /^\/[\w\-./:~@%]*$/;

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;

interface LayerLike {
  handle?: AnyFn & { stack?: unknown; [WRAPPED_HANDLE]?: true } | undefined;
  route?: { path?: unknown } | undefined;
  name?: unknown;
  [MOUNT_PATH]?: unknown;
}

interface RequestLike {
  baseUrl?: unknown;
}

/** Mount prefixes entered by this request, innermost last (only routers whose path is a literal string). */
const mounts = new WeakMap<object, Array<string | null>>();

type CompileFn = (this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]) => unknown;

/** What the patch needs to know about a recognized Layer module. */
export interface ExpressPatchStatus {
  patched: number;
}

export interface ExpressPatchHooks {
  transport(): HttpCaptureTransport;
}

let hooks: ExpressPatchHooks | undefined;
const status: ExpressPatchStatus = { patched: 0 };

export function expressPatchStatus(): Readonly<ExpressPatchStatus> {
  return status;
}

/**
 * Observes CommonJS compilation (also used by ESM `import` of CommonJS packages) and patches the
 * Layer module of a supported Express/router version as soon as it has loaded. Idempotent.
 */
export function installExpressLayerPatch(next: ExpressPatchHooks): void {
  hooks = next;
  const proto = (nodeModule as unknown as { prototype: { _compile: CompileFn & { [PATCHED]?: true } } }).prototype;
  if (proto._compile[PATCHED]) return;
  const original = proto._compile;
  const wrapped = function xtraceExpressCompile(this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]): unknown {
    const result = Reflect.apply(original, this, [content, filename, ...rest]);
    if (typeof filename === "string" && (EXPRESS4_LAYER.test(filename) || ROUTER2_LAYER.test(filename))) {
      try { patchLayerModule(this, filename); } catch { /* an unrecognized shape stays unpatched */ }
    }
    return result;
  } as CompileFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto._compile = wrapped;
}

function majorOf(packageJsonPath: string, name: string): number {
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { name?: unknown; version?: unknown };
    if (parsed.name !== name || typeof parsed.version !== "string") return 0;
    return Number.parseInt(parsed.version, 10) || 0;
  } catch {
    return 0;
  }
}

function patchLayerModule(module: { exports: unknown }, filename: string): void {
  const express4 = EXPRESS4_LAYER.test(filename);
  const major = express4
    ? majorOf(filename.replace(/[\\/]lib[\\/]router[\\/]layer\.js$/, "/package.json"), "express")
    : majorOf(filename.replace(/[\\/]lib[\\/]layer\.js$/, "/package.json"), "router");
  if (express4 ? major !== 4 : major !== 2) return;
  const Layer = module.exports as (new (path: unknown, options: unknown, fn: unknown) => LayerLike) & { prototype: Record<string, unknown> };
  if (typeof Layer !== "function") return;
  const requestName = express4 ? "handle_request" : "handleRequest";
  const errorName = express4 ? "handle_error" : "handleError";
  const originalRequest = Layer.prototype[requestName];
  const originalError = Layer.prototype[errorName];
  if (typeof originalRequest !== "function" || typeof originalError !== "function") return;
  if ((originalRequest as { [PATCHED]?: true })[PATCHED]) return;

  Layer.prototype[requestName] = tag(function xtraceHandleRequest(this: LayerLike, request: unknown, response: unknown, next: unknown): unknown {
    let forward = next;
    try {
      prepareHandle(this);
      if (this.route) withRequestContext(request, () => matched(this, request));
      else if (isRouterMount(this) && typeof next === "function") {
        const stack = mountStack(request);
        stack.push(mountPathOf(this));
        let popped = false;
        forward = function xtraceMountNext(this: unknown, ...args: unknown[]): unknown {
          if (!popped) { popped = true; stack.pop(); }
          return Reflect.apply(next as AnyFn, this, args);
        };
      }
    } catch { /* instrumentation never changes what the application does */ }
    return withRequestContext(request, () => Reflect.apply(originalRequest as AnyFn, this, [request, response, forward]));
  } as AnyFn);

  Layer.prototype[errorName] = tag(function xtraceHandleError(this: LayerLike, error: unknown, request: unknown, response: unknown, next: unknown): unknown {
    try { prepareHandle(this); } catch { /* see above */ }
    return withRequestContext(request, () => Reflect.apply(originalError as AnyFn, this, [error, request, response, next]));
  } as AnyFn);

  // Remember the path string every layer was created with: Express itself keeps only a compiled matcher.
  const Original = Layer;
  const Wrapped = function XtraceLayer(this: unknown, path: unknown, options: unknown, fn: unknown): LayerLike {
    const layer = new Original(path, options, fn);
    try { Object.defineProperty(layer, MOUNT_PATH, { value: path, enumerable: false }); } catch { /* frozen? ignore */ }
    return layer;
  } as unknown as typeof Original;
  Wrapped.prototype = Original.prototype;
  Object.setPrototypeOf(Wrapped, Original);
  module.exports = Wrapped;
  status.patched += 1;
}

/**
 * AsyncLocalStorage is lost in callbacks that bypass async resources (a raw `req.on('data')` handler
 * calling `next()`): fall back to the recording the root bound to this request object.
 */
function withRequestContext<T>(request: unknown, callback: () => T): T {
  if (currentContext()) return callback();
  const bound = contextForRequest(request);
  return bound && !bound.finished ? runInContext(bound, callback) : callback();
}

function tag(fn: AnyFn): AnyFn {
  Object.defineProperty(fn, PATCHED, { value: true });
  return fn;
}

function mountStack(request: unknown): Array<string | null> {
  const key = request as object;
  let stack = mounts.get(key);
  if (!stack) { stack = []; mounts.set(key, stack); }
  return stack;
}

function mountPathOf(layer: LayerLike): string | null {
  const path = layer[MOUNT_PATH];
  if (path === "/" || path === undefined) return "";
  return typeof path === "string" && TEMPLATE_PATH.test(path) ? path.replace(/\/+$/, "") : null;
}

function isRouterMount(layer: LayerLike): boolean {
  return "route" in layer && layer.route === undefined && typeof layer.handle === "function" && Array.isArray(layer.handle.stack);
}

/** The matched Route layer was entered: its template is known now, before any handler runs. */
function matched(layer: LayerLike, request: unknown): void {
  const context = currentContext();
  const transport = hooks?.transport();
  if (!context || !transport || context.route !== "") return;
  const template = composeTemplate(layer.route?.path, request);
  if (template) announceRoute(context, transport, template);
}

/**
 * Mount prefixes plus the route path, only when every piece is a literal string and the prefixes
 * account for exactly the `baseUrl` Express matched. Regex or array paths, unusual characters and
 * mounts this patch cannot see (sub-apps) leave the route unresolved: never a guessed template.
 */
export function composeTemplate(routePath: unknown, request: unknown): string {
  if (typeof routePath !== "string" || !routePath.startsWith("/") || routePath.length > 1024) return "";
  const stack = (request && typeof request === "object" ? mounts.get(request) : undefined) ?? [];
  if (stack.some((part) => part === null)) return "";
  const prefix = stack.join("");
  const base = (request as RequestLike | undefined)?.baseUrl;
  const baseUrl = typeof base === "string" ? base : "";
  if (!prefixCovers(prefix, baseUrl)) return "";
  const composed = prefix === "" ? routePath : routePath === "/" ? prefix : prefix + routePath;
  // Never hand the worker something it would cut: a truncated template would be a wrong one.
  return composed.length > 1024 ? "" : composed;
}

function prefixCovers(prefix: string, baseUrl: string): boolean {
  if (prefix === "") return baseUrl === "";
  const source = prefix.split("/").map((segment) => segment.startsWith(":")
    ? "[^/]+"
    : segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("/");
  return new RegExp(`^${source}$`).test(baseUrl);
}

/** Wraps a handler once so its frame brackets the call; Express catches throws, so it is recorded here. */
function prepareHandle(layer: LayerLike): void {
  const fn = layer.handle;
  if (typeof fn !== "function" || fn[WRAPPED_HANDLE] || layer.route || Array.isArray(fn.stack)) return;
  if (INTERNAL_LAYERS.has(fn.name)) return;
  const kind = "route" in layer ? "middleware" : "handler";
  const label = symbolName(layer.name, fn.name);
  const wrapped = function xtraceExpressHandle(this: unknown, ...args: unknown[]): unknown {
    const context = currentContext();
    const transport = hooks?.transport();
    if (!context || !transport || context.finished) return Reflect.apply(fn, this, args);
    const symbol = `express.${args.length === 4 ? "error_handler" : kind}:${label}`;
    const parent = context.frameStack[context.frameStack.length - 1] ?? "";
    const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: parent });
    if (enter) context.frameStack.push(enter);
    try {
      const result = Reflect.apply(fn, this, args);
      if (enter) recordEvent(context, transport, events.frameExit(symbol, enter));
      return result;
    } catch (error) {
      if (enter) recordEvent(context, transport, events.frameThrow(symbol, enter, error));
      throw error;
    } finally {
      if (enter) leave(context, enter);
    }
  };
  Object.defineProperty(wrapped, "length", { value: fn.length });
  Object.defineProperty(wrapped, "name", { value: fn.name });
  Object.defineProperty(wrapped, WRAPPED_HANDLE, { value: true });
  layer.handle = wrapped as typeof layer.handle;
}

function leave(context: RecordingContext, eventId: string): void {
  const index = context.frameStack.lastIndexOf(eventId);
  if (index >= 0) context.frameStack.splice(index, 1);
}

/** Function names are source symbols, but capped and restricted so a hostile name cannot shape the wire. */
function symbolName(layerName: unknown, fnName: string): string {
  const raw = typeof layerName === "string" && layerName !== "" ? layerName : fnName;
  const clean = raw.replace(/[^\w$.<>-]/g, "_").slice(0, 64);
  return clean === "" || clean === "<anonymous>" ? "anonymous" : clean;
}
