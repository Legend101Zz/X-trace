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
import type { InteractionPatchHooks } from "./pg.cjs";

/**
 * `mysql` and `mysql2` (including `mysql2/promise`) database interaction capture.
 * Patches `.query` and `.execute` with ALS deduplication so Promise/Pool wrappers that delegate
 * to an underlying connection emit a single sanitized interaction pair.
 */

const PATCHED = Symbol.for("xtrace.node.mysql.patch.v1");

const MYSQL_CONN = /[\\/]node_modules[\\/]mysql[\\/]lib[\\/](?:Connection|Pool)\.js$/;
const MYSQL2_TARGET = /[\\/]node_modules[\\/]mysql2[\\/]lib[\\/](?:(?:base[\\/])?(?:connection|pool)|promise[\\/](?:connection|pool))\.js$/;
const MYSQL_INDEX = /[\\/]node_modules[\\/](mysql|mysql2)[\\/](?:index|promise)\.js$/;

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;
type EmitFn = (this: unknown, event: string | symbol, ...args: unknown[]) => unknown;
type CompileFn = (this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]) => unknown;
export type MysqlDriverName = "mysql" | "mysql2";

export interface MysqlPatchStatus {
  patched: number;
  unsupported: number;
}

let hooks: InteractionPatchHooks | undefined;
const counters: MysqlPatchStatus = { patched: 0, unsupported: 0 };
const inMysqlQuery = new AsyncLocalStorage<true>();

export function mysqlPatchStatus(): Readonly<MysqlPatchStatus> {
  return { ...counters };
}

export function installMysqlCapture(next: InteractionPatchHooks): void {
  hooks = next;
  const proto = (nodeModule as unknown as { prototype: { _compile: CompileFn & { [PATCHED]?: true } } }).prototype;
  if (proto._compile[PATCHED]) return;
  const original = proto._compile;
  const wrapped = function xtraceMysqlCompile(this: { exports: unknown }, content: string, filename: string, ...rest: unknown[]): unknown {
    const result = Reflect.apply(original, this, [content, filename, ...rest]);
    if (typeof filename === "string") {
      try {
        if (MYSQL_CONN.test(filename)) {
          instrumentMysqlConnection(this.exports, "mysql", hooks);
        } else if (MYSQL2_TARGET.test(filename)) {
          instrumentMysqlConnection(this.exports, "mysql2", hooks);
        } else {
          const idx = MYSQL_INDEX.exec(filename);
          if (idx) instrumentMysqlModule(this.exports, idx[1] as MysqlDriverName, hooks);
        }
      } catch {
        counters.unsupported += 1;
      }
    }
    return result;
  } as CompileFn & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  proto._compile = wrapped;
}

export function instrumentMysqlModule(
  mysqlExports: unknown,
  driver: MysqlDriverName = "mysql2",
  customHooks?: InteractionPatchHooks,
): boolean {
  if (customHooks) hooks = customHooks;
  if (mysqlExports === null || typeof mysqlExports !== "object") return false;
  const mod = mysqlExports as { Connection?: unknown; Pool?: unknown; PromiseConnection?: unknown; PromisePool?: unknown };
  let ok = false;
  for (const ctor of [mod.Connection, mod.Pool, mod.PromiseConnection, mod.PromisePool]) {
    if (ctor && instrumentMysqlConnection(ctor, driver, hooks)) ok = true;
  }
  return ok;
}

export function instrumentMysqlConnection(
  target: unknown,
  driver: MysqlDriverName = "mysql2",
  customHooks?: InteractionPatchHooks,
): boolean {
  if (customHooks) hooks = customHooks;
  const proto = typeof target === "function"
    ? (target as { prototype?: Record<string, unknown> }).prototype
    : target !== null && typeof target === "object"
      ? (target as Record<string, unknown>)
      : undefined;
  if (!proto) return false;
  const q = patchMethod(proto, "query", driver);
  const e = patchMethod(proto, "execute", driver);
  return q || e;
}

function patchMethod(proto: Record<string, unknown>, methodName: "query" | "execute", driver: MysqlDriverName): boolean {
  if (typeof proto[methodName] !== "function") return false;
  const original = proto[methodName] as AnyFn & { [PATCHED]?: true };
  if (original[PATCHED]) return true;

  const wrapped = function xtraceMysqlMethod(this: unknown, ...args: unknown[]): unknown {
    const context = currentContext();
    const transport = hooks?.transport();
    if (!context || !transport || context.finished || captureSuppressed() || inMysqlQuery.getStore()) {
      return Reflect.apply(original, this, args);
    }

    const facts = buildMysqlFacts(this, args[0], driver, methodName);
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
      forwardArgs[lastIdx] = function xtraceMysqlCallback(this: unknown, ...cbArgs: unknown[]): unknown {
        finish(cbArgs[0]);
        return Reflect.apply(userCb, this, cbArgs);
      };
    }

    try {
      const result = inMysqlQuery.run(true, () => Reflect.apply(original, this, forwardArgs));
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
  proto[methodName] = wrapped;
  counters.patched += 1;
  return true;
}

function buildMysqlFacts(conn: unknown, sqlArg: unknown, driver: MysqlDriverName, fallbackMethod: "query" | "execute") {
  const sql = sanitizeSql(sqlArg);
  const obj = conn !== null && typeof conn === "object"
    ? conn as {
      config?: { host?: unknown; port?: unknown; database?: unknown; uri?: unknown; connectionConfig?: { host?: unknown; port?: unknown; database?: unknown } };
      connection?: { config?: { host?: unknown; port?: unknown; database?: unknown } };
    }
    : undefined;
  const cfg = obj?.config?.connectionConfig ?? obj?.config ?? obj?.connection?.config;
  const fromUri = extractConnectionTarget(obj?.config?.uri);
  const host = sanitizeHost(cfg?.host ?? fromUri.host);
  const port = sanitizePort(cfg?.port ?? fromUri.port);
  const dbName = sanitizeIdentifier(cfg?.database ?? fromUri.schema);
  return sanitizeInteractionFacts({
    kind: "database",
    driver,
    method: sql.summary ? sql.statementKind : fallbackMethod,
    summary: sql.summary || fallbackMethod,
    schema: sql.schema || dbName,
    table: sql.table,
    host,
    ...(port !== undefined ? { port } : {}),
  });
}

function observeEmitter(emitter: { emit: EmitFn }, finish: (err?: unknown) => void): void {
  const origEmit = emitter.emit;
  emitter.emit = function xtraceMysqlEmitterEmit(this: unknown, event: string | symbol, ...args: unknown[]): unknown {
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
