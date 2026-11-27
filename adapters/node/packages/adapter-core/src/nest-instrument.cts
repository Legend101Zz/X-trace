import nodeModule = require("node:module");
import { readFileSync } from "node:fs";
import { types as utilTypes } from "node:util";
import { contextForRequest, currentContext, recordEvent, runInContext, type RecordingContext } from "./runtime/context.cjs";
import { events } from "./runtime/events.cjs";
import type { HttpCaptureTransport } from "./runtime/transport.cjs";

/**
 * NestJS controller and service method identity instrumentation on top of Express or Fastify.
 * Never creates a second HTTP request root (`RecordingContext`): attaches to the active
 * AsyncLocalStorage context (or recovers from `contextForRequest` with a `correlation-lost`
 * gap if ALS dropped), and records an honest missing-root gap if no HTTP root exists.
 */

const PATCHED = Symbol.for("xtrace.node.nest.patch.v1");
const WRAPPED_METHOD = Symbol.for("xtrace.node.nest.method.v1");
const INSTRUMENTED_INSTANCE = Symbol.for("xtrace.node.nest.instance.v1");

const NEST_EXEC_CTX = /[\\/]node_modules[\\/]@nestjs[\\/]core[\\/]router[\\/]router-execution-context\.js$/;
const NEST_INJECTOR = /[\\/]node_modules[\\/]@nestjs[\\/]core[\\/]injector[\\/]injector\.js$/;
const NEST_PKG = /[\\/]node_modules[\\/]@nestjs[\\/]core[\\/]/;

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;
type CompileFn = (this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]) => unknown;

export interface NestMissingRootGap {
  reason: "correlation-lost";
  symbol: string;
  role: "controller" | "service";
}

export interface NestPatchStatus {
  patched: number;
  unsupported: number;
  missingRootGaps: number;
  limitations: string[];
  lastMissingRootGap?: NestMissingRootGap;
}

export interface NestPatchHooks {
  transport(): HttpCaptureTransport;
  onMissingRootGap?(gap: NestMissingRootGap): void;
}

let hooks: NestPatchHooks | undefined;
const limitationSet = new Set<string>();
const counters = { patched: 0, unsupported: 0, missingRootGaps: 0 };
let lastMissingGap: NestMissingRootGap | undefined;

export function nestPatchStatus(): Readonly<NestPatchStatus> {
  return {
    patched: counters.patched,
    unsupported: counters.unsupported,
    missingRootGaps: counters.missingRootGaps,
    limitations: [...limitationSet].sort(),
    ...(lastMissingGap ? { lastMissingRootGap: { ...lastMissingGap } } : {}),
  };
}

/** Resets diagnostic gap counters (for test isolation; never affects active recordings). */
export function resetNestDiagnostics(): void {
  counters.missingRootGaps = 0;
  lastMissingGap = undefined;
  limitationSet.delete("nest_missing_http_root");
}

function noteLimitation(code: string): void {
  if (/^[a-z][a-z0-9_]{0,127}$/.test(code)) limitationSet.add(code);
}

/**
 * Observes CommonJS/ESM loading of `@nestjs/core` internals (`RouterExecutionContext` and
 * `Injector`) via `Module._compile` and instruments controller/service boundaries. Idempotent.
 */
export function installNestPatch(next: NestPatchHooks): void {
  hooks = next;
  const proto = (nodeModule as unknown as { prototype: { _compile: CompileFn & { [PATCHED]?: true } } }).prototype;
  if (proto._compile[PATCHED]) return;
  const original = proto._compile;
  const wrapped = function xtraceNestCompile(this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]): unknown {
    const result = Reflect.apply(original, this, [content, filename, ...rest]);
    if (typeof filename === "string" && NEST_PKG.test(filename)) {
      if (NEST_EXEC_CTX.test(filename)) {
        try { patchExecutionContextModule(this, filename); } catch {
          counters.unsupported += 1;
          noteLimitation("nest_shape_unsupported");
        }
      } else if (NEST_INJECTOR.test(filename)) {
        try { patchInjectorModule(this, filename); } catch {
          counters.unsupported += 1;
          noteLimitation("nest_shape_unsupported");
        }
      }
    }
    return result;
  } as CompileFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto._compile = wrapped;
}

function nestMajor(filename: string): number {
  try {
    const match = /[\\/]@nestjs[\\/]core[\\/]/.exec(filename);
    const pkgPath = match ? `${filename.slice(0, match.index + match[0].length)}package.json` : "";
    if (!pkgPath) return 0;
    const parsed = JSON.parse(readFileSync(pkgPath, "utf8")) as { name?: unknown; version?: unknown };
    if (parsed.name !== "@nestjs/core" || typeof parsed.version !== "string") return 0;
    return Number.parseInt(parsed.version, 10) || 0;
  } catch {
    return 0;
  }
}

function isSupportedMajor(major: number): boolean {
  return major === 0 || (major >= 8 && major <= 11);
}

function patchExecutionContextModule(module: { exports: unknown }, filename: string): void {
  const major = nestMajor(filename);
  if (!isSupportedMajor(major)) {
    counters.unsupported += 1;
    noteLimitation("nest_version_unsupported");
    return;
  }
  const exported = module.exports as { RouterExecutionContext?: { prototype?: unknown } } | undefined;
  const proto = exported?.RouterExecutionContext?.prototype;
  if (!instrumentNestRouterExecutionContext(proto)) {
    counters.unsupported += 1;
    noteLimitation("nest_shape_unsupported");
    return;
  }
  counters.patched += 1;
}

function patchInjectorModule(module: { exports: unknown }, filename: string): void {
  const major = nestMajor(filename);
  if (!isSupportedMajor(major)) return;
  const exported = module.exports as { Injector?: { prototype?: Record<string, unknown> } } | undefined;
  const proto = exported?.Injector?.prototype;
  if (!proto || typeof proto.instantiateClass !== "function") return;
  const originalInstantiate = proto.instantiateClass as AnyFn & { [PATCHED]?: true };
  if (originalInstantiate[PATCHED]) return;

  const wrappedInstantiate = function xtraceNestInstantiate(this: unknown, ...args: unknown[]): unknown {
    const result = Reflect.apply(originalInstantiate, this, args);
    const wrapper = args[0] as { metatype?: unknown; name?: unknown } | undefined;
    const metatype = wrapper?.metatype;
    if (isThenable(result)) {
      return Promise.resolve(result).then((instance) => {
        try { instrumentDiscoveredInstance(instance, metatype); } catch { /* never break DI */ }
        return instance;
      });
    }
    try { instrumentDiscoveredInstance(result, metatype); } catch { /* never break DI */ }
    return result;
  } as AnyFn & { [PATCHED]?: true };
  Object.defineProperty(wrappedInstantiate, PATCHED, { value: true });
  proto.instantiateClass = wrappedInstantiate;
  counters.patched += 1;
}

function instrumentDiscoveredInstance(instance: unknown, metatype: unknown): void {
  if (instance === null || typeof instance !== "object" || utilTypes.isProxy(instance)) return;
  const reflectApi = (globalThis as { Reflect?: { getMetadata?: (key: string, target: unknown) => unknown } }).Reflect;
  const isController = typeof metatype === "function" && reflectApi?.getMetadata?.("__controller__", metatype) === true;
  const isInjectable = typeof metatype === "function" && reflectApi?.getMetadata?.("__injectable__", metatype) === true;
  const className = typeof metatype === "function" && metatype.name ? metatype.name : undefined;
  if (isController) {
    instrumentNestController(instance, className ? { className } : undefined);
  } else if (isInjectable) {
    instrumentNestService(instance, className ? { className } : undefined);
  }
}

/**
 * Patches a Nest `RouterExecutionContext.prototype` so route callbacks created for Express or
 * Fastify attach cleanly to the active HTTP `RecordingContext` and wrap controller methods.
 */
export function instrumentNestRouterExecutionContext(proto: unknown): boolean {
  if (proto === null || typeof proto !== "object") return false;
  const target = proto as { create?: AnyFn & { [PATCHED]?: true } };
  if (typeof target.create !== "function") return false;
  if (target.create[PATCHED]) return true;

  const originalCreate = target.create;
  const wrappedCreate = function xtraceNestCreate(this: unknown, ...args: unknown[]): unknown {
    const instance = args[0];
    const callback = args[1];
    const methodName = args[2];
    const forwardArgs = [...args];

    try {
      if (instance !== null && typeof instance === "object" && typeof callback === "function") {
        const className = resolveClassName(instance);
        const fnName = typeof methodName === "string" && methodName !== "" ? methodName : callback.name || "handler";
        const wrappedCallback = wrapNestMethod("controller", className, fnName, callback as AnyFn);
        forwardArgs[1] = wrappedCallback;
        // Also instrument any injectable service instances attached as own properties.
        instrumentAttachedServices(instance);
      }
    } catch { /* never alter Nest route wiring */ }

    const routeHandler = Reflect.apply(originalCreate, this, forwardArgs);
    if (typeof routeHandler !== "function") return routeHandler;

    // Outer boundary preserves/recovers ALS from req (Express or Fastify request.raw) without ever creating a root.
    const wrappedHandler = function xtraceNestRouteBoundary(this: unknown, ...reqArgs: unknown[]): unknown {
      const req = reqArgs[0];
      const active = currentContext();
      if (active) return Reflect.apply(routeHandler as AnyFn, this, reqArgs);

      const bound = recoverRequestContext(req);
      if (bound && !bound.finished) {
        return runInContext(bound, () => {
          const transport = hooks?.transport();
          if (transport) {
            recordEvent(
              bound,
              transport,
              events.gap(
                { reason: "correlation-lost", count: 1, firstSequence: bound.nextSequence, lastSequence: bound.nextSequence },
                currentParent(bound),
              ),
            );
          }
          return Reflect.apply(routeHandler as AnyFn, this, reqArgs);
        });
      }
      return Reflect.apply(routeHandler as AnyFn, this, reqArgs);
    };
    Object.defineProperty(wrappedHandler, "length", { value: routeHandler.length });
    Object.defineProperty(wrappedHandler, "name", { value: routeHandler.name });
    return wrappedHandler;
  } as AnyFn & { [PATCHED]?: true };

  Object.defineProperty(wrappedCreate, PATCHED, { value: true });
  target.create = wrappedCreate;
  return true;
}

/** Instruments all own/class-prototype methods on a Nest controller instance (idempotent). */
export function instrumentNestController(
  controller: unknown,
  options?: { className?: string; hooks?: NestPatchHooks },
): boolean {
  if (options?.hooks) hooks = options.hooks;
  return instrumentNestObject(controller, "controller", options?.className);
}

/** Instruments all own/class-prototype methods on a Nest service (`@Injectable()`) instance (idempotent). */
export function instrumentNestService(
  service: unknown,
  options?: { className?: string; hooks?: NestPatchHooks },
): boolean {
  if (options?.hooks) hooks = options.hooks;
  return instrumentNestObject(service, "service", options?.className);
}

/**
 * Optional application-level discovery for NestJS containers/instances exposing `getHttpAdapter`
 * or `container` (`modules`). Never triggers `listen()` and never creates an HTTP root.
 */
export function instrumentNestApplication(app: unknown, customHooks?: NestPatchHooks): boolean {
  if (customHooks) hooks = customHooks;
  if (app === null || typeof app !== "object" || utilTypes.isProxy(app)) return false;
  const candidate = app as {
    container?: { getModules?: () => Map<unknown, { controllers?: Map<unknown, { instance?: unknown; metatype?: unknown }>; providers?: Map<unknown, { instance?: unknown; metatype?: unknown }> }> };
  };
  let instrumentedAny = false;
  const modulesMap = candidate.container?.getModules?.();
  if (modulesMap && typeof modulesMap.values === "function") {
    for (const mod of modulesMap.values()) {
      if (mod?.controllers && typeof mod.controllers.values === "function") {
        for (const wrapper of mod.controllers.values()) {
          if (wrapper?.instance && instrumentNestController(wrapper.instance)) instrumentedAny = true;
        }
      }
      if (mod?.providers && typeof mod.providers.values === "function") {
        for (const wrapper of mod.providers.values()) {
          if (wrapper?.instance && instrumentNestService(wrapper.instance)) instrumentedAny = true;
        }
      }
    }
  }
  return instrumentedAny;
}

function instrumentAttachedServices(controller: object): void {
  const reflectApi = (globalThis as { Reflect?: { getMetadata?: (key: string, target: unknown) => unknown } }).Reflect;
  for (const key of Object.getOwnPropertyNames(controller)) {
    const desc = Object.getOwnPropertyDescriptor(controller, key);
    if (!desc || !("value" in desc)) continue; // never invoke getters
    const value = desc.value;
    if (value === null || typeof value !== "object" || utilTypes.isProxy(value)) continue;
    const ctor = (value as { constructor?: unknown }).constructor;
    if (typeof ctor !== "function" || ctor === Object || ctor === Array || ctor === Map || ctor === Set) continue;
    if (reflectApi?.getMetadata?.("__injectable__", ctor) === true) {
      instrumentNestService(value);
    }
  }
}

function instrumentNestObject(target: unknown, role: "controller" | "service", explicitClassName?: string): boolean {
  if (target === null || typeof target !== "object" || utilTypes.isProxy(target)) return false;
  const obj = target as Record<string, unknown> & { [INSTRUMENTED_INSTANCE]?: true };
  if (obj[INSTRUMENTED_INSTANCE]) return true;

  const className = sanitizeSymbolPart(explicitClassName || resolveClassName(obj));
  let wrappedCount = 0;

  // 1. Wrap own data-property methods directly on the instance.
  for (const key of Object.getOwnPropertyNames(obj)) {
    if (key === "constructor") continue;
    const desc = Object.getOwnPropertyDescriptor(obj, key);
    if (!desc || typeof desc.value !== "function") continue; // never invoke getters/setters
    if (!desc.writable && !desc.configurable) continue;
    const wrapped = wrapNestMethod(role, className, key, desc.value as AnyFn);
    if (wrapped !== desc.value) {
      Object.defineProperty(obj, key, { ...desc, value: wrapped });
    }
    wrappedCount += 1;
  }

  // 2. Wrap prototype methods on user classes (stopping strictly before Object.prototype).
  let proto = Object.getPrototypeOf(obj) as Record<string, unknown> | null;
  while (proto && proto !== Object.prototype && !isBuiltinPrototype(proto)) {
    for (const key of Object.getOwnPropertyNames(proto)) {
      if (key === "constructor") continue;
      const desc = Object.getOwnPropertyDescriptor(proto, key);
      if (!desc || typeof desc.value !== "function") continue;
      if (!desc.writable && !desc.configurable) continue;
      const wrapped = wrapNestMethod(role, className, key, desc.value as AnyFn);
      if (wrapped !== desc.value) {
        Object.defineProperty(proto, key, { ...desc, value: wrapped });
      }
      wrappedCount += 1;
    }
    proto = Object.getPrototypeOf(proto) as Record<string, unknown> | null;
  }

  Object.defineProperty(obj, INSTRUMENTED_INSTANCE, { value: true });
  return wrappedCount > 0;
}

export function wrapNestMethod(
  role: "controller" | "service",
  className: string,
  methodName: string,
  fn: AnyFn,
): AnyFn {
  if ((fn as { [WRAPPED_METHOD]?: true })[WRAPPED_METHOD]) return fn;
  const safeClass = sanitizeSymbolPart(className) || "Anonymous";
  const safeMethod = sanitizeSymbolPart(methodName) || "anonymous";
  const symbol = `nest.${role}:${safeClass}.${safeMethod}`;

  const wrapped = function xtraceNestMethod(this: unknown, ...args: unknown[]): unknown {
    let context = currentContext();
    let recoveredWithGap = false;
    if (!context) {
      const bound = args.length > 0 ? recoverRequestContext(args[0]) : undefined;
      if (bound && !bound.finished) {
        context = bound;
        recoveredWithGap = true;
      }
    }

    const transport = hooks?.transport();
    if (!context || !transport || context.finished) {
      if (!context) recordMissingRootGap(role, symbol);
      return Reflect.apply(fn, this, args);
    }

    return runInContext(context, () => {
      if (recoveredWithGap) {
        recordEvent(
          context,
          transport,
          events.gap(
            { reason: "correlation-lost", count: 1, firstSequence: context.nextSequence, lastSequence: context.nextSequence },
            currentParent(context),
          ),
        );
      }
      const parent = currentParent(context);
      const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: parent });
      if (enter) context.frameStack.push(enter);
      let asyncHandled = false;
      try {
        const result = Reflect.apply(fn, this, args);
        if (isThenable(result)) {
          asyncHandled = true;
          void Promise.resolve(result).then(
            () => {
              if (!context.finished && enter) {
                runInContext(context, () => {
                  recordEvent(context, transport, events.frameExit(symbol, enter));
                });
              }
              if (enter) leave(context, enter);
            },
            (err) => {
              if (!context.finished && enter) {
                runInContext(context, () => {
                  recordEvent(context, transport, events.frameThrow(symbol, enter, err));
                });
              }
              if (enter) leave(context, enter);
            },
          );
          return result;
        }
        if (enter) recordEvent(context, transport, events.frameExit(symbol, enter));
        return result;
      } catch (error) {
        if (enter) recordEvent(context, transport, events.frameThrow(symbol, enter, error));
        throw error;
      } finally {
        if (enter && !asyncHandled) leave(context, enter);
      }
    });
  };

  Object.defineProperty(wrapped, "length", { value: fn.length });
  Object.defineProperty(wrapped, "name", { value: fn.name });
  Object.defineProperty(wrapped, WRAPPED_METHOD, { value: true });
  return wrapped;
}

function recordMissingRootGap(role: "controller" | "service", symbol: string): void {
  counters.missingRootGaps += 1;
  noteLimitation("nest_missing_http_root");
  const gap: NestMissingRootGap = { reason: "correlation-lost", symbol, role };
  lastMissingGap = gap;
  try { hooks?.onMissingRootGap?.(gap); } catch { /* best effort */ }
}

function recoverRequestContext(request: unknown): RecordingContext | undefined {
  if (request === null || typeof request !== "object") return undefined;
  const direct = contextForRequest(request);
  if (direct) return direct;
  const raw = (request as { raw?: unknown }).raw;
  return raw !== undefined ? contextForRequest(raw) : undefined;
}

function resolveClassName(instance: object): string {
  const ctor = (instance as { constructor?: { name?: unknown } }).constructor;
  if (ctor && typeof ctor.name === "string" && ctor.name !== "" && ctor.name !== "Object") return ctor.name;
  return "AnonymousNestClass";
}

function isBuiltinPrototype(proto: object): boolean {
  return proto === Function.prototype || proto === Array.prototype || proto === Map.prototype || proto === Set.prototype;
}

function sanitizeSymbolPart(raw: string): string {
  const clean = raw.replace(/[^\w$.<>-]/g, "_").slice(0, 64);
  return clean === "<anonymous>" ? "anonymous" : clean;
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return value !== null && (typeof value === "object" || typeof value === "function") && typeof (value as { then?: unknown }).then === "function";
}

function currentParent(context: RecordingContext): string {
  return context.frameStack[context.frameStack.length - 1] ?? context.frameEventId ?? "";
}

function leave(context: RecordingContext, eventId: string): void {
  const index = context.frameStack.lastIndexOf(eventId);
  if (index >= 0) context.frameStack.splice(index, 1);
}
