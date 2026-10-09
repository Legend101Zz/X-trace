import type { Worker } from "node:worker_threads";
import type { CaptureEvent } from "./events.cjs";

export type { CaptureEvent };

const MAX_IN_FLIGHT_MESSAGES = 64;
const MAX_ACTIVE_RECORDINGS = 64;

/** What the application thread needs from the worker handoff. */
export interface HttpCaptureTransport {
  start(recordingId: string, method: string, startedAtNs: bigint): boolean;
  event(recordingId: string, event: CaptureEvent): boolean;
  finish(recordingId: string, finalSequence: bigint, durationNs: bigint, droppedEvents: number, summary?: RecordingSummary): boolean;
  onFailure(callback: () => void): void;
  close(): void;
}

/** Facts resolved while the request ran; the worker uses them when it releases the held start. */
export interface RecordingSummary {
  route?: string;
  urlShape?: string;
  httpStatus?: number;
  outcome?: "responded" | "exception-propagated" | "client-aborted" | "unobserved";
  limitations?: readonly string[];
}

interface WorkerMessage {
  type: "staged" | "failure";
}

interface RecordingMessage {
  type: "start" | "event" | "finish";
  [key: string]: unknown;
}

/** Keeps app-thread handoff bounded and reserves one terminal slot per admitted request. */
export function createHttpCaptureTransport(worker: Worker): HttpCaptureTransport {
  let pending = 0;
  let reservedFinishes = 0;
  let failed = false;
  let failureCallback: (() => void) | undefined;

  const fail = () => {
    if (failed) return;
    failed = true;
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
    start(recordingId, method, startedAtNs) {
      if (pending + reservedFinishes + 2 > MAX_IN_FLIGHT_MESSAGES || reservedFinishes >= MAX_ACTIVE_RECORDINGS) return false;
      reservedFinishes += 1;
      if (post({ type: "start", recordingId, method, startedAtNs })) return true;
      reservedFinishes = Math.max(0, reservedFinishes - 1);
      return false;
    },
    event(recordingId, event) {
      if (pending + reservedFinishes >= MAX_IN_FLIGHT_MESSAGES) return false;
      return post({ type: "event", recordingId, ...event });
    },
    finish(recordingId, finalSequence, durationNs, droppedEvents, summary) {
      if (reservedFinishes === 0 || failed) return false;
      reservedFinishes -= 1;
      return post({ type: "finish", recordingId, finalSequence, durationNs, droppedEvents, ...(summary ? { summary } : {}) });
    },
    onFailure(callback) { failureCallback = callback; },
    close() {
      if (!failed) {
        try {
          worker.ref();
          worker.postMessage({ type: "close" });
        } catch { fail(); }
      }
    },
  };
}
