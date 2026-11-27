import type { Worker } from "node:worker_threads";
import type { CaptureEvent } from "./events.cjs";

export type { CaptureEvent };

export const DEFAULT_MAX_IN_FLIGHT_MESSAGES = 2048;
export const DEFAULT_MAX_ACTIVE_RECORDINGS = 256;
export const DEFAULT_DRAIN_TIMEOUT_MS = 10000;

/** Shared Int32Array layout shared between preload, transport, and transport-worker. */
export const SHARED_CONTROL_WORDS = 4;
export const CONTROL_STARTUP_INDEX = 0;
export const CONTROL_STAGED_INDEX = 1;
export const CONTROL_DRAIN_INDEX = 2;

const SHUTDOWN_HOOKS_INSTALLED = Symbol.for("xtrace.node.shutdown.hooks.v1");

/** Optional bounds and shared-memory counters for `createHttpCaptureTransport`. */
export interface HttpCaptureTransportOptions {
  maxInFlightMessages?: number | undefined;
  maxActiveRecordings?: number | undefined;
  sharedControl?: Int32Array | undefined;
  drainTimeoutMs?: number | undefined;
}

/** Optional overrides for deterministic testing of process shutdown hooks. */
export interface ProcessShutdownHookOptions {
  drainTimeoutMs?: number | undefined;
  onExitSignal?: ((signal: NodeJS.Signals) => void) | undefined;
}

/** What the application thread needs from the worker handoff. */
export interface HttpCaptureTransport {
  /** `holdStart` asks the worker to delay RecordingStarted until finish (only when a module can still set the route). */
  start(recordingId: string, method: string, startedAtNs: bigint, holdStart?: boolean): boolean;
  event(recordingId: string, event: CaptureEvent): boolean;
  /** Optional: announces the route template the moment a framework matches it (releases a held start). */
  route?(recordingId: string, route: string): boolean;
  finish(recordingId: string, finalSequence: bigint, durationNs: bigint, droppedEvents: number, summary?: RecordingSummary): boolean;
  onFailure(callback: () => void): void;
  /** Non-destructive cooperative flush of queued work without terminating capture. */
  flush?(): void;
  /** Requests bounded close and waits asynchronously for worker drain confirmation. */
  drainAsync?(timeoutMs?: number): Promise<boolean>;
  /** Requests bounded close and waits synchronously via SharedArrayBuffer before native exit. */
  drainSync?(timeoutMs?: number): boolean;
  /** Number of starts refused due to bounded capacity. */
  rejectedStarts?(): number;
  close(): void;
}

/** Facts resolved while the request ran; the worker uses them when it releases the held start. */
export interface RecordingSummary {
  route?: string;
  httpStatus?: number;
  outcome?: "responded" | "exception-propagated" | "client-aborted" | "unobserved";
  limitations?: readonly string[];
  /** Set for exception-propagated: the root frame-throw event and the thrown constructor name. */
  thrownFromEventId?: string;
  exceptionType?: string;
}

interface WorkerMessage {
  type: "staged" | "drained" | "failure";
}

interface RecordingMessage {
  type: "start" | "event" | "finish" | "route";
  [key: string]: unknown;
}

/** Keeps app-thread handoff bounded and reserves one terminal slot per admitted request. */
export function createHttpCaptureTransport(
  worker: Worker,
  options: HttpCaptureTransportOptions = {},
): HttpCaptureTransport {
  const maxInFlightMessages = validPositiveLimit(options.maxInFlightMessages, DEFAULT_MAX_IN_FLIGHT_MESSAGES, 2);
  const maxActiveRecordings = validPositiveLimit(options.maxActiveRecordings, DEFAULT_MAX_ACTIVE_RECORDINGS, 1);
  const drainTimeoutMs = validPositiveLimit(options.drainTimeoutMs, DEFAULT_DRAIN_TIMEOUT_MS, 1);
  const sharedControl = options.sharedControl && options.sharedControl.length > CONTROL_DRAIN_INDEX
    ? options.sharedControl
    : undefined;

  let pending = 0;
  let postedCount = 0;
  let hasPostedCapture = false;
  let reservedFinishes = 0;
  let rejectedStartCount = 0;
  let closePosted = false;
  let hadPendingWorkAtClose = false;
  let drainedCleanly = false;
  let workerExited = false;
  let failed = false;
  let failureCallback: (() => void) | undefined;
  const drainWaiters: Array<(drained: boolean) => void> = [];

  const resolveDrainWaiters = (value: boolean) => {
    for (const waiter of drainWaiters.splice(0)) waiter(value);
  };

  const inFlight = (): number => {
    if (sharedControl) {
      const completed = Atomics.load(sharedControl, CONTROL_STAGED_INDEX) >>> 0;
      return (postedCount - completed) >>> 0;
    }
    return pending;
  };

  const markDrainState = (state: 1 | 2) => {
    if (!sharedControl) return;
    Atomics.store(sharedControl, CONTROL_DRAIN_INDEX, state);
    Atomics.notify(sharedControl, CONTROL_DRAIN_INDEX);
  };

  const fail = () => {
    if (failed) return;
    failed = true;
    pending = 0;
    reservedFinishes = 0;
    markDrainState(2);
    resolveDrainWaiters(false);
    failureCallback?.();
  };

  worker.on("message", (message: WorkerMessage) => {
    if (message?.type === "staged") {
      if (!sharedControl) pending = Math.max(0, pending - 1);
    } else if (message?.type === "drained") {
      drainedCleanly = true;
      resolveDrainWaiters(true);
    } else if (message?.type === "failure") {
      fail();
    }
  });
  worker.on("error", fail);
  worker.on("exit", (code) => {
    workerExited = true;
    if (code !== 0) {
      fail();
      return;
    }
    if (sharedControl && Atomics.load(sharedControl, CONTROL_DRAIN_INDEX) === 0) {
      markDrainState(2);
    }
    resolveDrainWaiters(drainedCleanly);
  });

  const post = (message: RecordingMessage): boolean => {
    if (failed || workerExited || closePosted) return false;
    try {
      worker.postMessage(message);
      postedCount = (postedCount + 1) >>> 0;
      hasPostedCapture = true;
      if (!sharedControl) pending += 1;
      return true;
    } catch {
      fail();
      return false;
    }
  };

  const close = (): void => {
    if (closePosted || failed || workerExited) return;
    hadPendingWorkAtClose = hasPostedCapture || inFlight() > 0 || reservedFinishes > 0 || rejectedStartCount > 0;
    closePosted = true;
    try {
      worker.ref?.();
      const safetyTimer = setTimeout(() => {
        if (!workerExited && !drainedCleanly) {
          try { worker.unref?.(); } catch { /* ignore */ }
        }
      }, drainTimeoutMs);
      safetyTimer.unref?.();
      worker.postMessage({ type: "close", rejectedStarts: rejectedStartCount });
    } catch {
      fail();
    }
  };

  return {
    start(recordingId, method, startedAtNs, holdStart = false) {
      if (closePosted || failed || workerExited) return false;
      if (inFlight() + reservedFinishes + 2 > maxInFlightMessages || reservedFinishes >= maxActiveRecordings) {
        rejectedStartCount += 1;
        return false;
      }
      reservedFinishes += 1;
      if (post({ type: "start", recordingId, method, startedAtNs, holdStart })) return true;
      reservedFinishes = Math.max(0, reservedFinishes - 1);
      return false;
    },
    event(recordingId, event) {
      if (closePosted || failed || workerExited) return false;
      if (inFlight() + reservedFinishes >= maxInFlightMessages) return false;
      return post({ type: "event", recordingId, ...event });
    },
    route(recordingId, route) {
      if (closePosted || failed || workerExited) return false;
      if (inFlight() + reservedFinishes >= maxInFlightMessages) return false;
      return post({ type: "route", recordingId, route });
    },
    finish(recordingId, finalSequence, durationNs, droppedEvents, summary) {
      if (reservedFinishes === 0 || closePosted || failed || workerExited) return false;
      reservedFinishes -= 1;
      return post({ type: "finish", recordingId, finalSequence, durationNs, droppedEvents, ...(summary ? { summary } : {}) });
    },
    onFailure(callback) { failureCallback = callback; },
    flush() {
      if (closePosted || failed || workerExited) return;
      try {
        worker.postMessage({ type: "flush" });
      } catch {
        fail();
      }
    },
    drainAsync(timeoutMs = drainTimeoutMs) {
      const budget = validPositiveLimit(timeoutMs, drainTimeoutMs, 1);
      if (failed) return Promise.resolve(false);
      if (drainedCleanly || (sharedControl && Atomics.load(sharedControl, CONTROL_DRAIN_INDEX) === 1)) {
        return Promise.resolve(true);
      }
      if (workerExited) return Promise.resolve(false);
      close();
      if (failed || workerExited) {
        const settled = drainedCleanly || (sharedControl !== undefined && Atomics.load(sharedControl, CONTROL_DRAIN_INDEX) === 1);
        return Promise.resolve(!failed && settled);
      }
      return new Promise<boolean>((resolve) => {
        let finished = false;
        const complete = (result: boolean) => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          if (!result) {
            try { worker.unref?.(); } catch { /* ignore */ }
          }
          resolve(result);
        };
        drainWaiters.push(complete);
        const timer = setTimeout(() => complete(false), budget);
        timer.unref?.();
      });
    },
    drainSync(timeoutMs = drainTimeoutMs) {
      const budget = validPositiveLimit(timeoutMs, drainTimeoutMs, 1);
      if (failed) return false;
      close();
      if (!sharedControl) return drainedCleanly;
      const current = Atomics.load(sharedControl, CONTROL_DRAIN_INDEX);
      if (current === 1) return true;
      if (current === 2 || failed || workerExited) return false;
      const effectiveBudget = hadPendingWorkAtClose ? budget : Math.min(budget, 250);
      const deadline = Date.now() + effectiveBudget;
      while (true) {
        const state = Atomics.load(sharedControl, CONTROL_DRAIN_INDEX);
        if (state === 1) return true;
        if (state === 2) return false;
        const remaining = deadline - Date.now();
        if (remaining <= 0) return false;
        Atomics.wait(sharedControl, CONTROL_DRAIN_INDEX, 0, remaining);
      }
    },
    rejectedStarts() {
      return rejectedStartCount;
    },
    close,
  };
}

/**
 * Installs bounded cooperative drain hooks on `beforeExit`, `process.exit()`, and `SIGTERM`/`SIGINT`.
 * - On `SIGTERM`/`SIGINT`, if the application registered its own listeners, X-trace triggers a
 *   non-blocking flush and lets the application's handlers run untouched; if no app listener exists,
 *   X-trace drains cooperatively up to a short bounded deadline before re-raising the signal.
 * - On native `process.exit()`, X-trace performs a bounded synchronous drain once while delegating
 *   re-entrant `process.exit()` calls directly to native `process.exit`.
 */
export function installProcessShutdownHooks(
  transport: HttpCaptureTransport,
  options: ProcessShutdownHookOptions = {},
): () => void {
  const holder = process as unknown as Record<symbol, boolean | undefined>;
  if (holder[SHUTDOWN_HOOKS_INSTALLED]) return () => {};
  Object.defineProperty(holder, SHUTDOWN_HOOKS_INSTALLED, { value: true, configurable: true, enumerable: false });

  const drainTimeoutMs = validPositiveLimit(options.drainTimeoutMs, DEFAULT_DRAIN_TIMEOUT_MS, 1);
  const onExitSignal = options.onExitSignal ?? ((signal: NodeJS.Signals) => {
    try { process.kill(process.pid, signal); } catch { /* ignore */ }
  });

  const originalExit = process.exit;
  let insideExit = false;
  let signalDraining = false;

  const onBeforeExit = () => {
    transport.close();
  };

  const wrappedExit = function xtraceProcessExit(
    this: NodeJS.Process,
    ...args: Parameters<typeof process.exit>
  ): never {
    if (!insideExit) {
      insideExit = true;
      try {
        transport.drainSync?.(drainTimeoutMs);
      } catch {
        // Exit drain must never throw or block native process termination.
      }
    }
    return Reflect.apply(originalExit, this, args) as never;
  };

  let sigtermListener: ((signal: NodeJS.Signals) => void) | undefined;
  let sigintListener: ((signal: NodeJS.Signals) => void) | undefined;

  const removeSignalListeners = () => {
    if (sigtermListener) {
      process.off("SIGTERM", sigtermListener);
      sigtermListener = undefined;
    }
    if (sigintListener) {
      process.off("SIGINT", sigintListener);
      sigintListener = undefined;
    }
  };

  const makeSignalListener = (signal: "SIGTERM" | "SIGINT") => {
    const listener = (): void => {
      const otherListeners = process.listeners(signal).filter((fn) => fn !== listener);
      if (otherListeners.length > 0) {
        // Application owns signal lifecycle: flush queued capture non-destructively and return.
        transport.flush?.();
        return;
      }
      if (signalDraining) {
        // Second signal during bounded drain immediately restores default signal termination.
        removeSignalListeners();
        onExitSignal(signal);
        return;
      }
      signalDraining = true;
      const drain = transport.drainAsync
        ? transport.drainAsync(drainTimeoutMs)
        : (transport.close(), Promise.resolve(false));
      void drain.catch(() => false).finally(() => {
        removeSignalListeners();
        onExitSignal(signal);
      });
    };
    return listener;
  };

  sigtermListener = makeSignalListener("SIGTERM");
  sigintListener = makeSignalListener("SIGINT");

  process.once("beforeExit", onBeforeExit);
  process.exit = wrappedExit as typeof process.exit;
  process.on("SIGTERM", sigtermListener);
  process.on("SIGINT", sigintListener);

  let disposed = false;
  return () => {
    if (disposed) return;
    disposed = true;
    process.off("beforeExit", onBeforeExit);
    removeSignalListeners();
    if (process.exit === wrappedExit) {
      process.exit = originalExit;
    }
    delete holder[SHUTDOWN_HOOKS_INSTALLED];
  };
}

function validPositiveLimit(value: number | undefined, fallback: number, minimum: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const truncated = Math.trunc(value);
  return truncated >= minimum ? truncated : fallback;
}
