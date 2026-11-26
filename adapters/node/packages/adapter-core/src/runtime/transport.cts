import type { CaptureDiagnostic } from "../capture-diagnostics.cjs";
import type { Worker } from "node:worker_threads";
import type { CaptureEvent } from "./events.cjs";

export type { CaptureEvent };

const MAX_IN_FLIGHT_MESSAGES = 64;
const MAX_ACTIVE_RECORDINGS = 64;

export const workerCounters = { startStaged: 0, finishStaged: 1, failed: 2 } as const;

/** What the application thread needs from the worker handoff. */
export interface HttpCaptureTransport {
  /** `holdStart` asks the worker to delay RecordingStarted until finish (only when a module can still set the route). */
  start(recordingId: string, method: string, startedAtNs: bigint, holdStart?: boolean): boolean;
  event(recordingId: string, event: CaptureEvent): boolean;
  /** Optional: announces the route template the moment a framework matches it (releases a held start). */
  route?(recordingId: string, route: string): boolean;
  finish(recordingId: string, finalSequence: bigint, durationNs: bigint, droppedEvents: number, summary?: RecordingSummary): boolean;
  onFailure(callback: () => void): void;
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
  type: "staged" | "failure";
}

interface RecordingMessage {
  type: "start" | "event" | "finish" | "route";
  [key: string]: unknown;
}

/** Keeps app-thread handoff bounded and reserves one terminal slot per admitted request. */
export function createHttpCaptureTransport(worker: Worker, diagnostic?: CaptureDiagnostic): HttpCaptureTransport {
  let pending = 0;
  let reservedFinishes = 0;
  let failed = false;
  let failureCallback: (() => void) | undefined;

  const fail = () => {
    if (failed) return;
    failed = true;
    diagnostic?.transportFailed();
    pending = 0;
    reservedFinishes = 0;
    failureCallback?.();
  };
  worker.on("message", (message: WorkerMessage) => {
    if (message?.type === "staged") pending = Math.max(0, pending - 1);
    else if (message?.type === "failure") fail();
  });
  worker.on("error", fail);
  worker.on("exit", (code) => { if (code !== 0) fail(); });

  const post = (message: RecordingMessage): boolean => {
    if (failed) return false;
    try {
      worker.postMessage(message);
      pending += 1;
      return true;
    } catch {
      fail();
      return false;
    }
  };

  return {
    start(recordingId, method, startedAtNs, holdStart = false) {
      diagnostic?.increment("startAttempts");
      if (pending + reservedFinishes + 2 > MAX_IN_FLIGHT_MESSAGES || reservedFinishes >= MAX_ACTIVE_RECORDINGS) {
        diagnostic?.increment("startCapacityRejected");
        return false;
      }
      reservedFinishes += 1;
      if (post({ type: "start", recordingId, method, startedAtNs, holdStart })) {
        diagnostic?.increment("startAccepted");
        return true;
      }
      reservedFinishes = Math.max(0, reservedFinishes - 1);
      diagnostic?.increment("startOtherRejected");
      return false;
    },
    event(recordingId, event) {
      const posted = pending + reservedFinishes < MAX_IN_FLIGHT_MESSAGES && post({ type: "event", recordingId, ...event });
      if (!posted) diagnostic?.increment("eventRejected");
      return posted;
    },
    route(recordingId, route) {
      const posted = pending + reservedFinishes < MAX_IN_FLIGHT_MESSAGES && post({ type: "route", recordingId, route });
      if (!posted) diagnostic?.increment("routeRejected");
      return posted;
    },
    finish(recordingId, finalSequence, durationNs, droppedEvents, summary) {
      if (reservedFinishes === 0 || failed) {
        diagnostic?.increment("finishRejected");
        return false;
      }
      reservedFinishes -= 1;
      const posted = post({ type: "finish", recordingId, finalSequence, durationNs, droppedEvents, ...(summary ? { summary } : {}) });
      diagnostic?.increment(posted ? "finishPosted" : "finishRejected");
      return posted;
    },
    onFailure(callback) { failureCallback = callback; },
    close() {
      if (!failed) {
        try {
          worker.ref();
          worker.postMessage({ type: "close" });
          diagnostic?.closeRequested();
        } catch { fail(); }
      }
    },
  };
}
