import { AsyncLocalStorage } from "node:async_hooks";
import nodeModule = require("node:module");
import { captureSuppressed, currentContext, recordEvent, runInContext, type RecordingContext } from "../runtime/context.cjs";
import { events } from "../runtime/events.cjs";
import type { HttpCaptureTransport } from "../runtime/transport.cjs";
import {
  extractConnectionTarget,
  safeExceptionFacts,
  sanitizeHost,
  sanitizeIdentifier,
  sanitizeInteractionFacts,
  sanitizePort,
  sanitizeSql,
} from "./redact.cjs";

/**
 * `pg` (node-postgres) database interaction capture.
 * Patches `Client.prototype.query` and `Pool.prototype.query` with ALS deduplication so a
 * `Pool.query()` call that delegates to `Client.query()` emits a single interaction pair.
 */

const PATCHED = Symbol.for("xtrace.node.pg.patch.v1");
const PG_CLIENT = /[\\/]node_modules[\\/]pg[\\/]lib[\\/]client\.js$/;
const PG_POOL = /[\\/]node_modules[\\/](?:pg[\\/]lib[\\/]pool|pg-pool[\\/]index)\.js$/;
const PG_INDEX = /[\\/]node_modules[\\/]pg[\\/]lib[\\/]index\.js$/;

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;
type EmitFn = (this: unknown, event: string | symbol, ...args: unknown[]) => unknown;
type CompileFn = (this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]) => unknown;

export interface InteractionPatchHooks {
  transport(): HttpCaptureTransport;
}

export interface PgPatchStatus {
  patched: number;
  unsupported: number;
}

let hooks: InteractionPatchHooks | undefined;
const counters: PgPatchStatus = { patched: 0, unsupported: 0 };
const inPgQuery = new AsyncLocalStorage<true>();

export function pgPatchStatus(): Readonly<PgPatchStatus> {
  return { ...counters };
}

export function installPgCapture(next: InteractionPatchHooks): void {
  hooks = next;
  const proto = (nodeModule as unknown as { prototype: { _compile: CompileFn & { [PATCHED]?: true } } }).prototype;
  if (proto._compile[PATCHED]) return;
  const original = proto._compile;
  const wrapped = function xtracePgCompile(this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]): unknown {
    const result = Reflect.apply(original, this, [content, filename, ...rest]);
    if (typeof filename === "string") {
      try {
        if (PG_CLIENT.test(filename)) instrumentPgClient(this.exports, hooks);
        else if (PG_POOL.test(filename)) instrumentPgPool(this.exports, hooks);
        else if (PG_INDEX.test(filename)) instrumentPgModule(this.exports, hooks);
      } catch {
        counters.unsupported += 1;
      }
    }
    return result;
  } as CompileFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto._compile = wrapped;
}

export function instrumentPgModule(pgExports: unknown, customHooks?: InteractionPatchHooks): boolean {
  if (customHooks) hooks = customHooks;
  if (pgExports === null || typeof pgExports !== "object") return false;
  const mod = pgExports as { Client?: unknown; Pool?: unknown };
  const c = mod.Client ? instrumentPgClient(mod.Client, hooks) : false;
  const p = mod.Pool ? instrumentPgPool(mod.Pool, hooks) : false;
  return c || p;
}

export function instrumentPgClient(clientOrProto: unknown, customHooks?: InteractionPatchHooks): boolean {
  if (customHooks) hooks = customHooks;
  return patchQueryTarget(clientOrProto, false);
}

export function instrumentPgPool(poolOrProto: unknown, customHooks?: InteractionPatchHooks): boolean {
  if (customHooks) hooks = customHooks;
  return patchQueryTarget(poolOrProto, true);
}

function patchQueryTarget(target: unknown, isPool: boolean): boolean {
  const proto = typeof target === "function"
    ? (target as { prototype?: Record<string, unknown> }).prototype
    : target !== null && typeof target === "object"
      ? (target as Record<string, unknown>)
      : undefined;
  if (!proto || typeof proto.query !== "function") return false;
  const original = proto.query as AnyFn & { [PATCHED]?: true };
  if (original[PATCHED]) return true;

  const wrapped = function xtracePgQuery(this: unknown, ...args: unknown[]): unknown {
    const context = currentContext();
    const transport = hooks?.transport();
    if (!context || !transport || context.finished || captureSuppressed() || inPgQuery.getStore()) {
      return Reflect.apply(original, this, args);
    }

    const facts = buildPgFacts(this, args[0]);
    const parent = currentParent(context);
    const startId = recordEvent(context, transport, events.interactionStart(facts, parent));
    const targetParent = startId || parent;

    let finished = false;
    const finish = (err?: unknown): void => {
      if (finished) return;
      finished = true;
      if (context.finished) return;
      runInContext(context, () => {
        if (err !== undefined && err !== null) {
          recordEvent(context, transport, events.exception(safeExceptionFacts(err), targetParent));
        }
        recordEvent(context, transport, events.interactionEnd(facts, targetParent));
      });
    };

    const forwardArgs = [...args];
    const lastIdx = forwardArgs.length - 1;
    let hasCallback = false;
    if (lastIdx >= 0 && typeof forwardArgs[lastIdx] === "function") {
      hasCallback = true;
      const userCb = forwardArgs[lastIdx] as AnyFn;
      forwardArgs[lastIdx] = function xtracePgCallback(this: unknown, ...cbArgs: unknown[]): unknown {
        finish(cbArgs[0]);
        return Reflect.apply(userCb, this, cbArgs);
      };
    }

    const invoke = () => (isPool
      ? inPgQuery.run(true, () => Reflect.apply(original, this, forwardArgs))
      : Reflect.apply(original, this, forwardArgs));

    try {
      const result = invoke();
      if (!hasCallback) {
        if (isThenable(result)) {
          void Promise.resolve(result).then(
            () => finish(),
            (err) => finish(err),
          );
        } else if (isEmitterLike(result)) {
          observeEmitter(result, finish);
        } else {
          finish();
        }
      }
      return result;
    } catch (error) {
      finish(error);
      throw error;
    }
  } as AnyFn & { [PATCHED]?: true };

  Object.defineProperty(wrapped, "length", { value: original.length });
  Object.defineProperty(wrapped, "name", { value: original.name });
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto.query = wrapped;
  counters.patched += 1;
  return true;
}

function buildPgFacts(conn: unknown, sqlArg: unknown) {
  const sql = sanitizeSql(sqlArg);
  const obj = conn !== null && typeof conn === "object"
    ? conn as {
      host?: unknown;
      port?: unknown;
      database?: unknown;
      connectionParameters?: { host?: unknown; port?: unknown; database?: unknown };
      options?: { host?: unknown; port?: unknown; database?: unknown; connectionString?: unknown };
    }
    : undefined;
  const fromUrl = extractConnectionTarget(obj?.options?.connectionString);
  const host = sanitizeHost(obj?.host ?? obj?.connectionParameters?.host ?? obj?.options?.host ?? fromUrl.host);
  const port = sanitizePort(obj?.port ?? obj?.connectionParameters?.port ?? obj?.options?.port ?? fromUrl.port);
  const dbName = sanitizeIdentifier(obj?.database ?? obj?.connectionParameters?.database ?? obj?.options?.database ?? fromUrl.schema);
  return sanitizeInteractionFacts({
    kind: "database",
    driver: "pg",
    method: sql.summary ? sql.statementKind : "query",
    summary: sql.summary || "query",
    schema: sql.schema || dbName,
    table: sql.table,
    host,
    ...(port !== undefined ? { port } : {}),
  });
}

function observeEmitter(emitter: { emit: EmitFn }, finish: (err?: unknown) => void): void {
  const origEmit = emitter.emit;
  emitter.emit = function xtracePgEmitterEmit(this: unknown, event: string | symbol, ...args: unknown[]): unknown {
    if (event === "error") finish(args[0]);
    else if (event === "end" || event === "close") finish();
    return Reflect.apply(origEmit, this, [event, ...args]);
  };
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return value !== null && (typeof value === "object" || typeof value === "function") && typeof (value as { then?: unknown }).then === "function";
}

function isEmitterLike(value: unknown): value is { emit: EmitFn; once: AnyFn } {
  return value !== null && typeof value === "object" && typeof (value as { emit?: unknown }).emit === "function" && typeof (value as { once?: unknown }).once === "function";
}

function currentParent(context: RecordingContext): string {
  return context.frameStack[context.frameStack.length - 1] ?? context.frameEventId ?? "";
}
