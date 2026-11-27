import { AsyncLocalStorage } from "node:async_hooks";
import childProcess = require("node:child_process");
import { createHash } from "node:crypto";
import nodeModule = require("node:module");
import workerThreads = require("node:worker_threads");
import {
  captureSuppressed,
  currentContext,
  recordEvent,
  uuidV7,
  type RecordingContext,
} from "./runtime/context.cjs";
import { events, type GapReasonName } from "./runtime/events.cjs";
import type { HttpCaptureTransport } from "./runtime/transport.cjs";

/**
 * Observes `worker_threads.Worker` and `child_process.{spawn,fork,execFile}` when armed.
 *
 * Privacy and launcher-environment invariants:
 * - Never modifies or inspects `NODE_OPTIONS`, `XTRACE_BOOTSTRAP_PATH`, `process.env`, or child `options.env`.
 * - Never captures raw command paths, `argv`, or `workerData` payloads.
 * - Emits bounded explicit gap events (`child-process-not-instrumented`, `correlation-lost`, or
 *   `bootstrap-consumed`) when child instrumentation or correlation is absent/invalid, and links
 *   supported child runtime sessions only via explicit verified opt-in registration.
 */

const PATCHED = Symbol.for("xtrace.node.process.linkage.patch.v1");
const MAX_LINK_RECORDS = 256;
const MAX_SESSION_ID_BYTES = 128;
const MAX_TOKEN_BYTES = 256;
const TOKEN_HASH_DOMAIN = "xtrace.process-linkage.correlation-token.v1\0";
const DEFAULT_PARENT_SESSION_ID = "00000000-0000-7000-8000-000000000000";

export type NodeSpawnKind = "node_worker" | "node_child_process";
export type NodeSessionLinkStatus = "linked" | "uninstrumented_gap" | "correlation_lost";
export type NodeProcessGapReason = Extract<
  GapReasonName,
  "child-process-not-instrumented" | "correlation-lost" | "bootstrap-consumed"
>;

export interface NodeProcessLinkRecord {
  readonly linkId: string;
  readonly parentSessionId: string;
  readonly parentRecordingId?: string;
  readonly childSessionId?: string;
  readonly childRecordingId?: string;
  readonly spawnKind: NodeSpawnKind;
  readonly status: NodeSessionLinkStatus;
  readonly gapReason?: NodeProcessGapReason;
  readonly correlationTokenHash?: string;
  readonly createdAtMs: number;
}

export interface ProcessLinkageHooks {
  transport: () => HttpCaptureTransport;
  parentSessionId?: () => string;
}

export interface RegisterChildSessionLinkInput {
  parentSessionId?: string;
  parentRecordingId?: string;
  childSessionId?: string;
  childRecordingId?: string;
  spawnKind: NodeSpawnKind;
  correlationToken?: string;
  expectedCorrelationToken?: string;
  detached?: boolean;
  target?: object;
}

export interface OptInChildSpawnRegistration {
  childSessionId?: string;
  childRecordingId?: string;
  correlationToken?: string;
  expectedCorrelationToken?: string;
  detached?: boolean;
}

export interface ProcessLinkagePatchStatus {
  workerPatched: boolean;
  childProcessPatched: number;
  linkedCount: number;
  gapCount: number;
}

type AnyFn = (this: unknown, ...args: unknown[]) => unknown;

interface OptInClaimState {
  registration: OptInChildSpawnRegistration;
  consumed: boolean;
}

let hooks: ProcessLinkageHooks | undefined;
let workerPatched = false;
let childProcessPatched = 0;
let linkedCount = 0;
let gapCount = 0;
const records: NodeProcessLinkRecord[] = [];
const linkedTargets = new WeakSet<object>();
const inSpawnHook = new AsyncLocalStorage<true>();
const optInClaimStore = new AsyncLocalStorage<OptInClaimState>();

let originalWorker: typeof workerThreads.Worker | undefined;
const originalChildMethods: Partial<Record<"spawn" | "fork" | "execFile", AnyFn>> = {};

export function processLinkagePatchStatus(): Readonly<ProcessLinkagePatchStatus> {
  return { workerPatched, childProcessPatched, linkedCount, gapCount };
}

export function recordedProcessLinks(): readonly NodeProcessLinkRecord[] {
  return records.slice();
}

/**
 * Hashes a bounded correlation token synchronously using SHA-256 with domain separation.
 * Returns `undefined` if the token is empty, oversized, or contains control characters.
 */
export function hashCorrelationToken(token: string | undefined): string | undefined {
  if (typeof token !== "string" || token.length === 0) return undefined;
  if (Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) return undefined;
  for (let i = 0; i < token.length; i += 1) {
    if (token.charCodeAt(i) < 0x20 || token.charCodeAt(i) === 0x7f) return undefined;
  }
  const digest = createHash("sha256").update(TOKEN_HASH_DOMAIN, "utf8").update(token, "utf8").digest("hex");
  return `sha256:${digest}`;
}

export function installProcessLinkageCapture(next: ProcessLinkageHooks): void {
  hooks = next;
  patchWorkerConstructor();
  patchChildProcessMethods();
  try {
    (nodeModule as unknown as { syncBuiltinESMExports?: () => void }).syncBuiltinESMExports?.();
  } catch { /* best effort */ }
}

/**
 * Registers an explicit parent-child correlation link when valid child session identity and
 * matching correlation token are provided; fails closed to an explicit `correlation-lost` gap
 * otherwise (never guessing or fabricating a link).
 */
export function registerChildSessionLink(
  input: RegisterChildSessionLinkInput,
): { ok: boolean; link: NodeProcessLinkRecord } {
  const context = activeRecordingContext();
  const parentSessionId = boundedId(input.parentSessionId)
    ?? boundedId(hooks?.parentSessionId?.())
    ?? DEFAULT_PARENT_SESSION_ID;
  const parentRecordingId = boundedId(input.parentRecordingId) ?? context?.id;
  const childSessionId = boundedId(input.childSessionId);
  const childRecordingId = boundedId(input.childRecordingId);
  const tokenHash = hashCorrelationToken(input.correlationToken);
  const expectedHash = input.expectedCorrelationToken !== undefined
    ? hashCorrelationToken(input.expectedCorrelationToken)
    : tokenHash;

  const validMatch =
    input.detached !== true
    && childSessionId !== undefined
    && childSessionId !== parentSessionId
    && (parentRecordingId === undefined || childRecordingId === undefined || parentRecordingId !== childRecordingId)
    && tokenHash !== undefined
    && expectedHash !== undefined
    && tokenHash === expectedHash;

  if (validMatch) {
    const link: NodeProcessLinkRecord = {
      linkId: uuidV7(),
      parentSessionId,
      ...(parentRecordingId !== undefined ? { parentRecordingId } : {}),
      childSessionId,
      ...(childRecordingId !== undefined ? { childRecordingId } : {}),
      spawnKind: input.spawnKind,
      status: "linked",
      correlationTokenHash: tokenHash,
      createdAtMs: Date.now(),
    };
    pushRecord(link);
    linkedCount += 1;
    if (input.target !== undefined) linkedTargets.add(input.target);
    emitLinkedEvent(context, childRecordingId ?? childSessionId);
    return { ok: true, link };
  }

  const gapLink: NodeProcessLinkRecord = {
    linkId: uuidV7(),
    parentSessionId,
    ...(parentRecordingId !== undefined ? { parentRecordingId } : {}),
    ...(childSessionId !== undefined && childSessionId !== parentSessionId ? { childSessionId } : {}),
    spawnKind: input.spawnKind,
    status: "correlation_lost",
    gapReason: "correlation-lost",
    ...(tokenHash !== undefined ? { correlationTokenHash: tokenHash } : {}),
    createdAtMs: Date.now(),
  };
  pushRecord(gapLink);
  gapCount += 1;
  emitGapEvent(context, "correlation-lost");
  return { ok: false, link: gapLink };
}

/**
 * Scopes a single-use opt-in child linkage claim around a `Worker` or `child_process` call.
 * A second spawn inside the same scope fails closed with `bootstrap-consumed`.
 */
export function withOptInChildLink<T>(
  registration: OptInChildSpawnRegistration,
  fn: () => T,
): T {
  return optInClaimStore.run({ registration, consumed: false }, fn);
}

/** Resets in-memory state and restores original Node constructors/methods (test helper). */
export function resetProcessLinkageForTest(): void {
  hooks = undefined;
  records.length = 0;
  linkedCount = 0;
  gapCount = 0;
  if (originalWorker) {
    (workerThreads as { Worker: typeof workerThreads.Worker }).Worker = originalWorker;
    originalWorker = undefined;
  }
  workerPatched = false;
  for (const methodName of ["spawn", "fork", "execFile"] as const) {
    const orig = originalChildMethods[methodName];
    if (orig) {
      (childProcess as unknown as Record<string, unknown>)[methodName] = orig;
      delete originalChildMethods[methodName];
    }
  }
  childProcessPatched = 0;
  try {
    (nodeModule as unknown as { syncBuiltinESMExports?: () => void }).syncBuiltinESMExports?.();
  } catch { /* best effort */ }
}

function patchWorkerConstructor(): void {
  const current = workerThreads.Worker as typeof workerThreads.Worker & { [PATCHED]?: true };
  if (typeof current !== "function" || current[PATCHED]) return;
  originalWorker = current;
  const wrapped = new Proxy(current, {
    construct(target, args, newTarget) {
      if (captureSuppressed() || inSpawnHook.getStore()) {
        return Reflect.construct(target, args, newTarget) as object;
      }
      const optIn = optInClaimStore.getStore();
      const claim = optIn ? consumeOptInClaim(optIn) : undefined;
      const options = readSafeBoundaryFlags(args[1]);
      const worker = inSpawnHook.run(true, () => Reflect.construct(target, args, newTarget)) as object;
      recordObservedSpawn("node_worker", options.evalMode || options.detached, claim, worker);
      return worker;
    },
  }) as typeof workerThreads.Worker & { [PATCHED]?: true };
  Object.defineProperty(wrapped, PATCHED, { value: true });
  (workerThreads as { Worker: typeof workerThreads.Worker }).Worker = wrapped;
  workerPatched = true;
}

function patchChildProcessMethods(): void {
  const mod = childProcess as unknown as Record<string, unknown>;
  for (const methodName of ["spawn", "fork", "execFile"] as const) {
    const original = mod[methodName] as (AnyFn & { [PATCHED]?: true }) | undefined;
    if (typeof original !== "function" || original[PATCHED]) continue;
    originalChildMethods[methodName] = original;
    const wrapped = function xtraceChildProcessSpawn(this: unknown, ...args: unknown[]): unknown {
      if (captureSuppressed() || inSpawnHook.getStore()) {
        return Reflect.apply(original, this, args);
      }
      const optIn = optInClaimStore.getStore();
      const claim = optIn ? consumeOptInClaim(optIn) : undefined;
      const options = readSafeSpawnFlags(args);
      const child = inSpawnHook.run(true, () => Reflect.apply(original, this, args));
      const targetObj = child !== null && typeof child === "object" ? child : undefined;
      recordObservedSpawn("node_child_process", options.detached, claim, targetObj);
      return child;
    } as AnyFn & { [PATCHED]?: true };
    Object.defineProperty(wrapped, "length", { value: original.length });
    Object.defineProperty(wrapped, "name", { value: original.name });
    Object.defineProperty(wrapped, PATCHED, { value: true });
    mod[methodName] = wrapped;
    childProcessPatched += 1;
  }
}

type ConsumedClaim =
  | { kind: "fresh"; registration: OptInChildSpawnRegistration }
  | { kind: "already-consumed" };

function consumeOptInClaim(state: OptInClaimState): ConsumedClaim {
  if (state.consumed) return { kind: "already-consumed" };
  state.consumed = true;
  return { kind: "fresh", registration: state.registration };
}

function recordObservedSpawn(
  spawnKind: NodeSpawnKind,
  detachedOrEval: boolean,
  claim: ConsumedClaim | undefined,
  target: object | undefined,
): void {
  if (target !== undefined && linkedTargets.has(target)) return;

  if (claim !== undefined) {
    if (claim.kind === "already-consumed") {
      recordExplicitGap(spawnKind, "uninstrumented_gap", "bootstrap-consumed");
      return;
    }
    const reg = claim.registration;
    registerChildSessionLink({
      spawnKind,
      ...(reg.childSessionId !== undefined ? { childSessionId: reg.childSessionId } : {}),
      ...(reg.childRecordingId !== undefined ? { childRecordingId: reg.childRecordingId } : {}),
      ...(reg.correlationToken !== undefined ? { correlationToken: reg.correlationToken } : {}),
      ...(reg.expectedCorrelationToken !== undefined ? { expectedCorrelationToken: reg.expectedCorrelationToken } : {}),
      detached: reg.detached === true || detachedOrEval,
      ...(target !== undefined ? { target } : {}),
    });
    return;
  }

  if (detachedOrEval) {
    recordExplicitGap(spawnKind, "correlation_lost", "correlation-lost");
  } else {
    recordExplicitGap(spawnKind, "uninstrumented_gap", "child-process-not-instrumented");
  }
}

function recordExplicitGap(
  spawnKind: NodeSpawnKind,
  status: "uninstrumented_gap" | "correlation_lost",
  gapReason: NodeProcessGapReason,
): void {
  const context = activeRecordingContext();
  const parentSessionId = boundedId(hooks?.parentSessionId?.()) ?? DEFAULT_PARENT_SESSION_ID;
  const parentRecordingId = context?.id;
  const record: NodeProcessLinkRecord = {
    linkId: uuidV7(),
    parentSessionId,
    ...(parentRecordingId !== undefined ? { parentRecordingId } : {}),
    spawnKind,
    status,
    gapReason,
    createdAtMs: Date.now(),
  };
  pushRecord(record);
  gapCount += 1;
  emitGapEvent(context, gapReason);
}

function emitGapEvent(context: RecordingContext | undefined, reason: NodeProcessGapReason): void {
  const transport = hooks?.transport();
  if (!context || !transport || context.finished) return;
  const parent = currentParent(context);
  const seq = context.nextSequence;
  recordEvent(context, transport, events.gap({ reason, count: 1, firstSequence: seq, lastSequence: seq }, parent));
}

function emitLinkedEvent(context: RecordingContext | undefined, childLinkId: string): void {
  const transport = hooks?.transport();
  if (!context || !transport || context.finished) return;
  const parent = currentParent(context);
  recordEvent(context, transport, events.asyncLink(parent, childLinkId));
}

function activeRecordingContext(): RecordingContext | undefined {
  const context = currentContext();
  if (!context || context.finished || captureSuppressed()) return undefined;
  return context;
}

function currentParent(context: RecordingContext): string {
  return context.frameStack[context.frameStack.length - 1] ?? context.frameEventId ?? "";
}

function pushRecord(record: NodeProcessLinkRecord): void {
  if (records.length >= MAX_LINK_RECORDS) records.shift();
  records.push(record);
}

function readSafeBoundaryFlags(options: unknown): { evalMode: boolean; detached: boolean } {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    return { evalMode: false, detached: false };
  }
  const obj = options as { eval?: unknown; detached?: unknown };
  return { evalMode: obj.eval === true, detached: obj.detached === true };
}

function readSafeSpawnFlags(args: unknown[]): { detached: boolean } {
  for (const candidate of [args[1], args[2]]) {
    if (candidate !== null && typeof candidate === "object" && !Array.isArray(candidate)) {
      if ((candidate as { detached?: unknown }).detached === true) {
        return { detached: true };
      }
    }
  }
  return { detached: false };
}

function boundedId(value: string | undefined): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  if (Buffer.byteLength(value, "utf8") > MAX_SESSION_ID_BYTES) return undefined;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) return undefined;
  }
  return value;
}
