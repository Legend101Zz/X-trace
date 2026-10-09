import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { createHttpCaptureTransport, installHttpCapture } from "./http-capture.cjs";

const STARTUP_TIMEOUT_MS = 5_000;

export function startCaptureFromRequire(): void {
  const bootstrapPath = process.env.XTRACE_BOOTSTRAP_PATH;
  restoreLauncherEnvironment();
  if (!bootstrapPath) {
    warnUnavailable("XTR-NODE-BOOTSTRAP");
    return;
  }
  const startupBarrier = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  let worker: Worker;
  try {
    worker = new Worker(join(__dirname, "transport-worker.js"), {
      execArgv: [],
      workerData: {
        bootstrapPath,
        startupBarrier,
        manifestPath: join(__dirname, "node-capabilities.json"),
      },
    });
  } catch {
    warnUnavailable("XTR-NODE-STARTUP");
    return;
  }
  const state = new Int32Array(startupBarrier);
  const wait = Atomics.wait(state, 0, 0, STARTUP_TIMEOUT_MS);
  if (wait === "timed-out" || Atomics.load(state, 0) !== 1) {
    void worker.terminate();
    warnUnavailable("XTR-NODE-STARTUP");
    return;
  }
  try {
    installHttpCapture(createHttpCaptureTransport(worker));
    worker.unref();
  } catch {
    void worker.terminate();
    warnUnavailable("XTR-NODE-STARTUP");
  }
}

function restoreLauncherEnvironment(): void {
  const original = process.env.XTRACE_NODE_ORIGINAL_OPTIONS;
  if (process.env.XTRACE_NODE_OPTIONS_WAS_SET === "1") process.env.NODE_OPTIONS = original ?? "";
  else delete process.env.NODE_OPTIONS;
  delete process.env.XTRACE_BOOTSTRAP_PATH;
  delete process.env.XTRACE_NODE_ORIGINAL_OPTIONS;
  delete process.env.XTRACE_NODE_OPTIONS_WAS_SET;
}

function warnUnavailable(code: string): void {
  process.emitWarning("X-trace Node HTTP capture could not start; application launch continues.", { code });
}
