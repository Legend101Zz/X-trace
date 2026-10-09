import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { createHttpCaptureTransport, installHttpCapture } from "./http-capture.cjs";
import { claimCaptureStart } from "./capture-start.cjs";

const STARTUP_TIMEOUT_MS = 5_000;
const DIST_DIRECTORY = dirname(fileURLToPath(import.meta.url));

/** Starts authenticated transport before an ESM application's entry module executes. */
export async function startCapture(): Promise<void> {
  if (!claimCaptureStart()) return;
  const bootstrapPath = process.env.XTRACE_BOOTSTRAP_PATH;
  restoreLauncherEnvironment();
  if (!bootstrapPath) {
    warnUnavailable("XTR-NODE-BOOTSTRAP");
    return;
  }
  let worker: Worker;
  try {
    worker = new Worker(join(DIST_DIRECTORY, "transport-worker.js"), {
      execArgv: [],
      workerData: { bootstrapPath, startupBarrier: new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT), manifestPath: join(DIST_DIRECTORY, "node-capabilities.json") },
    });
  } catch {
    warnUnavailable("XTR-NODE-STARTUP");
    return;
  }
  let timer: NodeJS.Timeout | undefined;
  const ready = await Promise.race([
    new Promise<boolean>((resolve) => {
      worker.once("message", (message: { type?: string }) => resolve(message?.type === "ready"));
      worker.once("error", () => resolve(false));
    }),
    new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), STARTUP_TIMEOUT_MS); }),
  ]);
  if (timer) clearTimeout(timer);
  if (!ready) {
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
