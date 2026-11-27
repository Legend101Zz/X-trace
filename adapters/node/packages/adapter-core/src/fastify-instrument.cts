import nodeModule = require("node:module");
import { readFileSync } from "node:fs";
import { announceRoute, contextForRequest, currentContext, recordEvent, runInContext, type RecordingContext } from "./runtime/context.cjs";
import { events } from "./runtime/events.cjs";
import type { HttpCaptureTransport } from "./runtime/transport.cjs";

/**
 * Fastify 4.x and 5.x instrumentation through Fastify's public hook surface (`onRegister`,
 * `onRoute`, `onRequest`, `preHandler`, `onError`, `onResponse`). Preserves encapsulation
 * plugin scope identity on frames, announces matched route templates without reading raw
 * URLs/values, reports explicit unsupported/limitation codes, and never mutates request,
 * response, or error propagation behavior.
 */

const PATCHED = Symbol.for("xtrace.node.fastify.patch.v1");
const INSTANCE_PATCHED = Symbol.for("xtrace.node.fastify.instance.v1");
const WRAPPED_FN = Symbol.for("xtrace.node.fastify.fn.v1");
const INTERNAL_HOOK = Symbol.for("xtrace.node.fastify.internalHook.v1");
const SKIP_OVERRIDE = Symbol.for("skip-override");
const DISPLAY_NAME = Symbol.for("fastify.display-name");

const FASTIFY_ENTRY = /[\\/]node_modules[\\/]fastify[\\/](?:fastify|lib[\\/]fastify)\.js$/;
const LIFECYCLE_HOOKS = new Set(["onRequest", "preHandler", "onError", "onResponse"]);
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;
type CompileFn = (this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]) => unknown;

export interface FastifyScopeInfo {
  id: string;
  name: string;
  prefix: string;
  parentScopeId: string;
  encapsulated: boolean;
}

export interface FastifyPatchStatus {
  patched: number;
  unsupported: number;
  onResponseAfterFinish: number;
  limitations: string[];
}

export interface FastifyPatchHooks {
  transport(): HttpCaptureTransport;
}

interface PendingRegister {
  pluginName: string;
  skipOverride: boolean;
  prefixOpt: string;
  parentScope: FastifyScopeInfo;
}

interface FastifyRouteMeta {
  scope: FastifyScopeInfo;
  template: string;
  unsupportedTemplate: boolean;
}

interface FastifyInstanceLike {
  version?: unknown;
  prefix?: unknown;
  pluginName?: unknown;
  addHook?: AnyFn;
  register?: AnyFn;
}

interface FastifyRequestLike {
  raw?: unknown;
  is404?: unknown;
  routerPath?: unknown;
  routeOptions?: { url?: unknown; method?: unknown; handler?: unknown } | undefined;
}

interface FastifyReplyLike {
  raw?: unknown;
  context?: { config?: { url?: unknown }; handler?: unknown } | undefined;
}

interface FastifyRouteOptionsLike {
  url?: unknown;
  routePath?: unknown;
  path?: unknown;
  method?: unknown;
  prefix?: unknown;
  handler?: unknown;
  onRequest?: unknown;
  preHandler?: unknown;
  onError?: unknown;
  onResponse?: unknown;
}

let hooks: FastifyPatchHooks | undefined;
const limitationSet = new Set<string>();
const statusCounters = { patched: 0, unsupported: 0, onResponseAfterFinish: 0 };

const scopes = new WeakMap<object, FastifyScopeInfo>();
const patchedMethods = new WeakMap<object, { addHook?: AnyFn; register?: AnyFn }>();
const routeMetaByHandler = new WeakMap<object, FastifyRouteMeta>();
const routeMetaByKey = new WeakMap<object, Map<string, FastifyRouteMeta>>();

export function fastifyPatchStatus(): Readonly<FastifyPatchStatus> {
  return {
    patched: statusCounters.patched,
    unsupported: statusCounters.unsupported,
    onResponseAfterFinish: statusCounters.onResponseAfterFinish,
    limitations: [...limitationSet].sort(),
  };
}

function noteLimitation(code: string): void {
  if (/^[a-z][a-z0-9_]{0,127}$/.test(code)) limitationSet.add(code);
}

/**
 * Observes CommonJS/ESM loading of `fastify` via `Module._compile` and instruments created
 * Fastify instances without touching unrelated modules. Idempotent.
 */
export function installFastifyPatch(next: FastifyPatchHooks): void {
  hooks = next;
  checkAlreadyLoadedFastify();
  const proto = (nodeModule as unknown as { prototype: { _compile: CompileFn & { [PATCHED]?: true } } }).prototype;
  if (proto._compile[PATCHED]) return;
  const original = proto._compile;
  const wrapped = function xtraceFastifyCompile(this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]): unknown {
    const result = Reflect.apply(original, this, [content, filename, ...rest]);
    if (typeof filename === "string" && FASTIFY_ENTRY.test(filename)) {
      try { patchFastifyModule(this, filename); } catch {
        statusCounters.unsupported += 1;
        noteLimitation("fastify_shape_unsupported");
      }
    }
    return result;
  } as CompileFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto._compile = wrapped;
}

function checkAlreadyLoadedFastify(): void {
  try {
    const cache = require.cache as Record<string, { exports?: unknown } | undefined>;
    for (const filename of Object.keys(cache)) {
      if (FASTIFY_ENTRY.test(filename)) {
        noteLimitation("fastify_loaded_before_arm");
        break;
      }
    }
  } catch { /* best effort */ }
}

function majorOf(packageJsonPath: string): { validName: boolean; major: number } {
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { name?: unknown; version?: unknown };
    if (parsed.name !== "fastify" || typeof parsed.version !== "string") return { validName: false, major: 0 };
    return { validName: true, major: Number.parseInt(parsed.version, 10) || 0 };
  } catch {
    return { validName: false, major: 0 };
  }
}

function patchFastifyModule(module: { exports: unknown }, filename: string): void {
  const pkgPath = filename.replace(/[\\/](?:lib[\\/])?fastify\.js$/, "/package.json");
  const { validName, major } = majorOf(pkgPath);
  if (validName && major !== 4 && major !== 5) {
    statusCounters.unsupported += 1;
    noteLimitation("fastify_version_unsupported");
    return;
  }
  const exported = module.exports as AnyFn & { fastify?: unknown; default?: unknown; [PATCHED]?: true };
  if (typeof exported !== "function") {
    statusCounters.unsupported += 1;
    noteLimitation("fastify_shape_unsupported");
    return;
  }
  if (exported[PATCHED]) return;

  const wrappedFactory = function xtraceFastifyFactory(this: unknown, ...args: unknown[]): unknown {
    const instance = Reflect.apply(exported, this, args);
    try {
      if (instance !== null && typeof instance === "object") {
        instrumentFastifyInstance(instance, hooks);
      }
    } catch { /* never break fastify construction */ }
    return instance;
  } as AnyFn & Record<string | symbol, unknown>;

  for (const key of Reflect.ownKeys(exported)) {
    if (key === "length" || key === "name" || key === "prototype") continue;
    const desc = Object.getOwnPropertyDescriptor(exported, key);
    if (!desc) continue;
    if ((key === "fastify" || key === "default") && desc.value === exported) {
      Object.defineProperty(wrappedFactory, key, { ...desc, value: wrappedFactory });
    } else {
      Object.defineProperty(wrappedFactory, key, desc);
    }
  }
  wrappedFactory.prototype = exported.prototype;
  Object.defineProperty(wrappedFactory, PATCHED, { value: true });
  module.exports = wrappedFactory;
  statusCounters.patched += 1;
}

/**
 * Instruments a Fastify instance directly via its public `addHook` and `register` APIs.
 * Safe and idempotent; returns `false` and records an explicit limitation if the instance
 * does not match a supported Fastify shape or version.
 */
export function instrumentFastifyInstance(instance: unknown, customHooks?: FastifyPatchHooks): boolean {
  if (customHooks) hooks = customHooks;
  if (instance === null || typeof instance !== "object") {
    statusCounters.unsupported += 1;
    noteLimitation("fastify_shape_unsupported");
    return false;
  }
  const fastify = instance as FastifyInstanceLike & { [INSTANCE_PATCHED]?: true };
  if (fastify[INSTANCE_PATCHED]) return true;
  if (typeof fastify.addHook !== "function") {
    statusCounters.unsupported += 1;
    noteLimitation("fastify_hooks_unavailable");
    return false;
  }
  if (typeof fastify.version === "string") {
    const major = Number.parseInt(fastify.version, 10) || 0;
    if (major !== 0 && major !== 4 && major !== 5) {
      statusCounters.unsupported += 1;
      noteLimitation("fastify_version_unsupported");
      return false;
    }
  }

  Object.defineProperty(fastify, INSTANCE_PATCHED, { value: true });
  const rootPrefix = normalizePrefix(fastify.prefix);
  const rootScope: FastifyScopeInfo = {
    id: rootPrefix ? `root@${rootPrefix}` : "root",
    name: "root",
    prefix: rootPrefix,
    parentScopeId: "",
    encapsulated: true,
  };
  scopes.set(fastify, rootScope);

  const instanceLimitations = new Set<string>();
  const pendingQueue: PendingRegister[] = [];
  let pendingSync: PendingRegister | undefined;
  let anonSeq = 0;

  const originalAddHook = fastify.addHook;
  const originalRegister = typeof fastify.register === "function" ? fastify.register : undefined;
  const rootKeys = new Map<string, FastifyRouteMeta>();
  routeMetaByKey.set(fastify, rootKeys);

  const resolveOwnOrParentScope = (target: unknown): FastifyScopeInfo => {
    if (target !== null && typeof target === "object") {
      const direct = scopes.get(target);
      if (direct) return direct;
      let proto = Object.getPrototypeOf(target) as object | null;
      while (proto && proto !== Object.prototype) {
        const hit = scopes.get(proto);
        if (hit) return hit;
        proto = Object.getPrototypeOf(proto) as object | null;
      }
    }
    return rootScope;
  };

  const scopeForRequest = (thisArg: unknown, request: unknown, reply: unknown): FastifyScopeInfo => {
    const req = request as FastifyRequestLike | undefined;
    const rep = reply as FastifyReplyLike | undefined;
    const handler = req?.routeOptions?.handler ?? rep?.context?.handler;
    if (typeof handler === "function") {
      const meta = routeMetaByHandler.get(handler);
      if (meta) return meta.scope;
    }
    const routeUrl = extractTemplateCandidate(req?.routeOptions?.url ?? req?.routerPath ?? rep?.context?.config?.url);
    const method = typeof req?.routeOptions?.method === "string" ? req.routeOptions.method.toUpperCase() : "";
    if (routeUrl) {
      const byKey = rootKeys.get(`${method}:${routeUrl}`) ?? rootKeys.get(`*:${routeUrl}`);
      if (byKey) return byKey.scope;
    }
    return resolveOwnOrParentScope(thisArg);
  };

  const attachMethods = (target: FastifyInstanceLike): void => {
    const ownAddHook = Object.getOwnPropertyDescriptor(target, "addHook");
    if (!patchedMethods.has(target) || ownAddHook) {
      const currentAddHook = typeof target.addHook === "function" ? target.addHook : originalAddHook;
      const wrappedAddHook = function xtraceFastifyAddHook(this: FastifyInstanceLike, name: unknown, fn: unknown, ...rest: unknown[]): unknown {
        let hookArg = fn;
        try {
          if (typeof name === "string" && LIFECYCLE_HOOKS.has(name) && typeof fn === "function" && !(fn as { [INTERNAL_HOOK]?: true })[INTERNAL_HOOK]) {
            const registeringScope = resolveOwnOrParentScope(this);
            hookArg = wrapUserHook(name, fn as AnyFn, (thisArg, req, rep) => {
              const direct = resolveOwnOrParentScope(thisArg);
              return direct !== rootScope ? direct : registeringScope !== rootScope ? registeringScope : scopeForRequest(thisArg, req, rep);
            });
          }
        } catch { /* never alter hook registration */ }
        const baseAddHook = patchedMethods.get(target)?.addHook ?? originalAddHook;
        return Reflect.apply(baseAddHook, this, [name, hookArg, ...rest]);
      };
      if (!(currentAddHook as { [WRAPPED_FN]?: true })[WRAPPED_FN]) {
        Object.defineProperty(wrappedAddHook, WRAPPED_FN, { value: true });
        target.addHook = wrappedAddHook as AnyFn;
      }
      const currentRegister = typeof target.register === "function" ? target.register : originalRegister;
      if (currentRegister && !(currentRegister as { [WRAPPED_FN]?: true })[WRAPPED_FN]) {
        const wrappedRegister = function xtraceFastifyRegister(this: FastifyInstanceLike, plugin: unknown, opts?: unknown, ...rest: unknown[]): unknown {
          const parentScope = resolveOwnOrParentScope(this);
          const pluginObj = plugin as ((...a: unknown[]) => unknown) & { [SKIP_OVERRIDE]?: unknown; [DISPLAY_NAME]?: unknown } | undefined;
          const skipOverride = Boolean(pluginObj && pluginObj[SKIP_OVERRIDE]);
          const displayName = pluginObj && typeof pluginObj[DISPLAY_NAME] === "string" ? pluginObj[DISPLAY_NAME] : "";
          const fnName = typeof plugin === "function" ? (displayName || plugin.name || "") : "";
          const optPrefix = opts !== null && typeof opts === "object" ? normalizePrefix((opts as { prefix?: unknown }).prefix) : "";
          const entry: PendingRegister = {
            pluginName: fnName,
            skipOverride,
            prefixOpt: optPrefix,
            parentScope,
          };
          pendingQueue.push(entry);
          const prevSync = pendingSync;
          pendingSync = entry;
          const baseRegister = patchedMethods.get(target)?.register ?? originalRegister!;
          try {
            return Reflect.apply(baseRegister, this, [plugin, opts, ...rest]);
          } finally {
            pendingSync = prevSync;
          }
        };
        Object.defineProperty(wrappedRegister, WRAPPED_FN, { value: true });
        target.register = wrappedRegister as AnyFn;
      }
      patchedMethods.set(target, { addHook: currentAddHook, ...(currentRegister ? { register: currentRegister } : {}) });
    }
  };

  attachMethods(fastify);

  const buildChildScope = (child: FastifyInstanceLike, opts: unknown, parentHint?: FastifyScopeInfo): FastifyScopeInfo => {
    const pending = pendingSync ?? pendingQueue.shift();
    const parent = parentHint ?? pending?.parentScope ?? resolveOwnOrParentScope(Object.getPrototypeOf(child));
    if (pending?.skipOverride || child === fastify) return parent;
    const rawPluginName = typeof child.pluginName === "string" && child.pluginName !== ""
      ? child.pluginName
      : pending?.pluginName ?? "";
    let name = sanitizeSymbolPart(rawPluginName);
    if (name === "" || name === "anonymous") {
      anonSeq += 1;
      name = `anonymous_${anonSeq}`;
    }
    const optPrefix = opts !== null && typeof opts === "object" ? normalizePrefix((opts as { prefix?: unknown }).prefix) : pending?.prefixOpt ?? "";
    const prefix = normalizePrefix(child.prefix) || joinPrefix(parent.prefix, optPrefix);
    const id = sanitizeScopeId(prefix ? `plugin:${name}@${prefix}` : `plugin:${name}`);
    return { id, name, prefix, parentScopeId: parent.id, encapsulated: true };
  };

  // Observe child plugin scopes when Fastify creates encapsulated contexts.
  try {
    Reflect.apply(originalAddHook, fastify, [
      "onRegister",
      tagInternal(function xtraceFastifyOnRegister(this: unknown, child: unknown, opts: unknown): void {
        try {
          if (child === null || typeof child !== "object") return;
          const parentScope = resolveOwnOrParentScope(this);
          const childInstance = child as FastifyInstanceLike;
          if (!scopes.has(childInstance)) {
            const childScope = buildChildScope(childInstance, opts, parentScope);
            scopes.set(childInstance, childScope);
          }
          attachMethods(childInstance);
        } catch { /* never interfere with plugin registration */ }
      }),
    ]);
  } catch {
    instanceLimitations.add("fastify_encapsulation_unobserved");
    noteLimitation("fastify_encapsulation_unobserved");
  }

  // Observe every registered route and wrap route-level handler/hooks preserving scope identity.
  try {
    Reflect.apply(originalAddHook, fastify, [
      "onRoute",
      tagInternal(function xtraceFastifyOnRoute(this: unknown, routeOptions: unknown): void {
        try {
          if (routeOptions === null || typeof routeOptions !== "object") return;
          const opts = routeOptions as FastifyRouteOptionsLike;
          const baseScope = resolveOwnOrParentScope(this);
          const routePrefix = normalizePrefix(opts.prefix);
          const effectiveScope: FastifyScopeInfo =
            routePrefix !== "" && baseScope.prefix === ""
              ? { ...baseScope, prefix: routePrefix, id: sanitizeScopeId(`${baseScope.id}@${routePrefix}`) }
              : baseScope;

          const rawUrl = opts.url ?? opts.routePath ?? opts.path;
          const template = extractTemplateCandidate(rawUrl);
          const unsupportedTemplate = rawUrl !== undefined && template === "";
          const meta: FastifyRouteMeta = { scope: effectiveScope, template, unsupportedTemplate };

          const methods = Array.isArray(opts.method) ? opts.method : [opts.method];
          for (const m of methods) {
            if (typeof m === "string" && template) rootKeys.set(`${m.toUpperCase()}:${template}`, meta);
          }
          if (template) rootKeys.set(`*:${template}`, meta);

          if (typeof opts.handler === "function") {
            const origHandler = opts.handler as AnyFn;
            routeMetaByHandler.set(origHandler, meta);
            const wrappedHandler = wrapRouteHandler(origHandler, meta);
            routeMetaByHandler.set(wrappedHandler, meta);
            opts.handler = wrappedHandler;
          }

          for (const hookName of LIFECYCLE_HOOKS) {
            const key = hookName as keyof FastifyRouteOptionsLike;
            const value = opts[key];
            if (typeof value === "function") {
              (opts as Record<string, unknown>)[hookName] = wrapUserHook(hookName, value as AnyFn, () => effectiveScope);
            } else if (Array.isArray(value)) {
              (opts as Record<string, unknown>)[hookName] = value.map((item) =>
                typeof item === "function" ? wrapUserHook(hookName, item as AnyFn, () => effectiveScope) : item,
              );
            }
          }
        } catch { /* never break route registration */ }
      }),
    ]);
  } catch {
    instanceLimitations.add("fastify_on_route_unsupported");
    noteLimitation("fastify_on_route_unsupported");
  }

  // Register lifecycle observers at the root so routes without user hooks still emit lifecycle frames.
  Reflect.apply(originalAddHook, fastify, [
    "onRequest",
    tagInternal(function xtraceFastifyOnRequest(this: unknown, request: unknown, reply: unknown, done?: unknown): void {
      try {
        const context = resolveContext(request);
        const transport = hooks?.transport();
        if (context && transport && !context.finished) {
          runInContext(context, () => {
            for (const code of instanceLimitations) context.limitations.add(code);
            announceFastifyRoute(context, transport, request, reply);
            const scope = scopeForRequest(this, request, reply);
            const symbol = `fastify.hook.onRequest:${scope.id}`;
            const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: currentParent(context) });
            if (enter) recordEvent(context, transport, events.frameExit(symbol, enter));
          });
        }
      } catch { /* never fail request */ }
      if (typeof done === "function") (done as () => void)();
    }),
  ]);

  Reflect.apply(originalAddHook, fastify, [
    "preHandler",
    tagInternal(function xtraceFastifyPreHandler(this: unknown, request: unknown, reply: unknown, done?: unknown): void {
      try {
        const context = resolveContext(request);
        const transport = hooks?.transport();
        if (context && transport && !context.finished) {
          runInContext(context, () => {
            const scope = scopeForRequest(this, request, reply);
            const symbol = `fastify.hook.preHandler:${scope.id}`;
            const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: currentParent(context) });
            if (enter) recordEvent(context, transport, events.frameExit(symbol, enter));
          });
        }
      } catch { /* never fail request */ }
      if (typeof done === "function") (done as () => void)();
    }),
  ]);

  Reflect.apply(originalAddHook, fastify, [
    "onError",
    tagInternal(function xtraceFastifyOnError(this: unknown, request: unknown, reply: unknown, error: unknown, done?: unknown): void {
      try {
        const context = resolveContext(request);
        const transport = hooks?.transport();
        if (context && transport && !context.finished) {
          runInContext(context, () => {
            const scope = scopeForRequest(this, request, reply);
            const symbol = `fastify.hook.onError:${scope.id}`;
            const parent = currentParent(context);
            const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: parent });
            const targetParent = enter || parent;
            recordEvent(context, transport, events.exception({ type: safeFastifyExceptionType(error), message: "" }, targetParent));
            if (enter) recordEvent(context, transport, events.frameExit(symbol, enter));
          });
        }
      } catch { /* never interfere with error handling */ }
      if (typeof done === "function") (done as () => void)();
    }),
  ]);

  Reflect.apply(originalAddHook, fastify, [
    "onResponse",
    tagInternal(function xtraceFastifyOnResponse(this: unknown, request: unknown, reply: unknown, done?: unknown): void {
      try {
        const context = resolveContext(request);
        const transport = hooks?.transport();
        if (context && transport) {
          if (context.finished) {
            statusCounters.onResponseAfterFinish += 1;
            noteLimitation("fastify_on_response_after_finish");
          } else {
            runInContext(context, () => {
              const scope = scopeForRequest(this, request, reply);
              const symbol = `fastify.hook.onResponse:${scope.id}`;
              const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: currentParent(context) });
              if (enter) recordEvent(context, transport, events.frameExit(symbol, enter));
            });
          }
        }
      } catch { /* never fail response cleanup */ }
      if (typeof done === "function") (done as () => void)();
    }),
  ]);

  statusCounters.patched += 1;
  return true;
}

/** Finish-time route template fallback for Fastify requests (`modules.cts` route resolver). */
export function resolveFastifyRoute(request: unknown): string {
  const req = request as FastifyRequestLike | undefined;
  if (!req || req.is404 === true) return "";
  return extractTemplateCandidate(req.routeOptions?.url ?? req.routerPath);
}

function resolveContext(request: unknown): RecordingContext | undefined {
  const active = currentContext();
  if (active) return active;
  const req = request as FastifyRequestLike | undefined;
  return contextForRequest(req?.raw ?? request);
}

function announceFastifyRoute(
  context: RecordingContext,
  transport: HttpCaptureTransport,
  request: unknown,
  reply: unknown,
): void {
  const req = request as FastifyRequestLike | undefined;
  const rep = reply as FastifyReplyLike | undefined;
  if (req?.is404 === true) return;
  const rawCandidate = req?.routeOptions?.url ?? req?.routerPath ?? rep?.context?.config?.url;
  const template = extractTemplateCandidate(rawCandidate);
  if (template) {
    announceRoute(context, transport, template);
  } else if (rawCandidate !== undefined) {
    context.limitations.add("fastify_route_template_unsupported");
  }
}

function wrapRouteHandler(fn: AnyFn, meta: FastifyRouteMeta): AnyFn {
  if ((fn as { [WRAPPED_FN]?: true })[WRAPPED_FN]) return fn;
  const fnLabel = sanitizeSymbolPart(fn.name) || "anonymous";
  const symbol = `fastify.handler:${meta.scope.id}:${fnLabel}`;
  const wrapped = function xtraceFastifyHandler(this: unknown, ...args: unknown[]): unknown {
    const request = args[0];
    const reply = args[1];
    const context = resolveContext(request);
    const transport = hooks?.transport();
    if (!context || !transport || context.finished) return Reflect.apply(fn, this, args);

    return runInContext(context, () => {
      if (meta.template) announceRoute(context, transport, meta.template);
      else if (meta.unsupportedTemplate) context.limitations.add("fastify_route_template_unsupported");
      else announceFastifyRoute(context, transport, request, reply);

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
  preserveFnShape(wrapped, fn);
  Object.defineProperty(wrapped, WRAPPED_FN, { value: true });
  return wrapped;
}

function wrapUserHook(
  hookName: string,
  fn: AnyFn,
  resolveScope: (thisArg: unknown, request: unknown, reply: unknown) => FastifyScopeInfo,
): AnyFn {
  if ((fn as { [WRAPPED_FN]?: true })[WRAPPED_FN]) return fn;
  const fnLabel = sanitizeSymbolPart(fn.name) || "anonymous";
  const doneArgIndex = hookName === "onError" ? 3 : 2;

  const wrapped = function xtraceFastifyUserHook(this: unknown, ...args: unknown[]): unknown {
    const request = args[0];
    const reply = args[1];
    const context = resolveContext(request);
    const transport = hooks?.transport();
    if (!context || !transport || context.finished) {
      if (hookName === "onResponse" && context?.finished) {
        statusCounters.onResponseAfterFinish += 1;
        noteLimitation("fastify_on_response_after_finish");
      }
      return Reflect.apply(fn, this, args);
    }

    return runInContext(context, () => {
      const scope = resolveScope(this, request, reply);
      const symbol = `fastify.hook.${hookName}:${scope.id}:${fnLabel}`;
      const parent = currentParent(context);
      const enter = recordEvent(context, transport, { ...events.frameEnter(symbol), parentEventId: parent });
      if (enter) context.frameStack.push(enter);

      let deferred = false;
      const forwardArgs = [...args];
      const maybeDone = args[doneArgIndex];
      if (fn.length > doneArgIndex && typeof maybeDone === "function") {
        deferred = true;
        let doneCalled = false;
        forwardArgs[doneArgIndex] = function xtraceFastifyHookDone(this: unknown, ...doneArgs: unknown[]): unknown {
          if (!doneCalled) {
            doneCalled = true;
            if (!context.finished && enter) {
              runInContext(context, () => {
                if (doneArgs[0]) recordEvent(context, transport, events.frameThrow(symbol, enter, doneArgs[0]));
                else recordEvent(context, transport, events.frameExit(symbol, enter));
              });
            }
            if (enter) leave(context, enter);
          }
          return Reflect.apply(maybeDone as AnyFn, this, doneArgs);
        };
      }

      try {
        const result = Reflect.apply(fn, this, forwardArgs);
        if (!deferred && isThenable(result)) {
          deferred = true;
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
        if (!deferred && enter) recordEvent(context, transport, events.frameExit(symbol, enter));
        return result;
      } catch (error) {
        if (enter) recordEvent(context, transport, events.frameThrow(symbol, enter, error));
        deferred = false;
        throw error;
      } finally {
        if (enter && !deferred) leave(context, enter);
      }
    });
  };
  preserveFnShape(wrapped, fn);
  Object.defineProperty(wrapped, WRAPPED_FN, { value: true });
  return wrapped;
}

function extractTemplateCandidate(candidate: unknown): string {
  if (typeof candidate !== "string") return "";
  if (!candidate.startsWith("/") || candidate.length > 1024) return "";
  if (candidate.includes("?") || candidate.includes("#") || CONTROL_CHARS.test(candidate)) return "";
  return candidate;
}

function normalizePrefix(raw: unknown): string {
  if (typeof raw !== "string") return "";
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed === "/") return "";
  if (!trimmed.startsWith("/") || trimmed.includes("?") || trimmed.includes("#") || CONTROL_CHARS.test(trimmed)) return "";
  return trimmed.replace(/\/+$/, "").slice(0, 64);
}

function joinPrefix(parent: string, child: string): string {
  if (child === "") return parent;
  if (parent === "") return child;
  return `${parent}${child}`.slice(0, 64);
}

function sanitizeSymbolPart(raw: string): string {
  const clean = raw.replace(/[^\w$.<>-]/g, "_").slice(0, 48);
  return clean === "<anonymous>" ? "anonymous" : clean;
}

function sanitizeScopeId(raw: string): string {
  return raw.replace(/[^\w$.:/@<>-]/g, "_").slice(0, 64) || "root";
}

function safeFastifyExceptionType(error: unknown): string {
  if (!(error instanceof Error)) return "UnknownError";
  const name = typeof error.name === "string" && /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(error.name) ? error.name : "Error";
  return name;
}

function preserveFnShape(target: AnyFn, source: AnyFn): void {
  Object.defineProperty(target, "length", { value: source.length });
  Object.defineProperty(target, "name", { value: source.name });
}

function tagInternal<T extends AnyFn>(fn: T): T {
  Object.defineProperty(fn, INTERNAL_HOOK, { value: true });
  return fn;
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
