import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { createHttpCaptureTransport, installHttpCapture } from "./http-capture.cjs";

const STARTUP_TIMEOUT_MS = 5_000;
const DIST_DIRECTORY = dirname(fileURLToPath(import.meta.url));

/** Starts authenticated transport before an ESM application's entry module executes. */
export async function startCapture(): Promise<void> {
  const bootstrapPath = process.env.XTRACE_BOOTSTRAP_PATH;
  if (!bootstrapPath) {
    warnUnavailable("XTR-NODE-BOOTSTRAP");
    return;
  }
  let worker: Worker;
  try {
    worker = new Worker(join(DIST_DIRECTORY, "transport-worker.js"), {
      workerData: { bootstrapPath, startupBarrier: new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT), manifestPath: join(DIST_DIRECTORY, "node-http-manifest.json") },
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
  worker.unref();
  try {
    installHttpCapture(createHttpCaptureTransport(worker));
  } catch {
    void worker.terminate();
    warnUnavailable("XTR-NODE-STARTUP");
  }
}

function warnUnavailable(code: string): void {
  process.emitWarning("X-trace Node HTTP capture could not start; application launch continues.", { code });
}
