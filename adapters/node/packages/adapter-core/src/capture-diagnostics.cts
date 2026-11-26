import { realpathSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { expressPatchStatus, observeExpressHandlers } from "./express-instrument.cjs";
import { resolveFromEntry, resolveMedusaExpress } from "./modules.cjs";
import { finishProgressDiagnosticOffset, readFinishProgress } from "./runtime/finish-progress.cjs";
import { routeFoldDiagnosticOffset, workerCounters } from "./runtime/transport.cjs";
import type { ModuleStatus } from "./runtime/registry.cjs";

const counters = ["startAttempts", "startAccepted", "startCapacityRejected", "startOtherRejected",
  "finishPosted", "finishRejected", "eventRejected", "routeRejected",
  "startBeforeCreditNotification", "eventBeforeCreditNotification", "routeBeforeCreditNotification"] as const;
type Counter = typeof counters[number];

type ExpressScope = "same-package" | "different-package" | "transitive-only" | "entry-only" | "neither";
type ExpressState = "not-observed" | "installed" | "express-not-found" | "unsupported-express"
  | "unsupported-node" | "install-failed" | "disabled-other";

function expressScope(): ExpressScope {
  const resolution = (find: () => string): string | undefined => {
    try { return realpathSync(find()); } catch { return undefined; }
  };
  const direct = resolution(() => resolveFromEntry("express/package.json"));
  const transitive = resolution(resolveMedusaExpress);
  if (direct && transitive) return direct === transitive ? "same-package" : "different-package";
  if (transitive) return "transitive-only";
  return direct ? "entry-only" : "neither";
}

export interface CaptureDiagnostic {
  workerBuffer: SharedArrayBuffer;
  increment(name: Counter): void;
  setExpress(status: ModuleStatus): void;
  transportFailed(): void;
  closeRequested(): void;
}

export function captureDiagnostic(): CaptureDiagnostic | undefined {
  const nonce = process.env.XTRACE_MEDUSA_CAPTURE_DIAGNOSTIC;
  if (nonce === undefined) return;
  delete process.env.XTRACE_MEDUSA_CAPTURE_DIAGNOSTIC;
  if (!/^[a-f0-9]{48}$/.test(nonce)) return;
  const counts = Object.fromEntries(counters.map((key) => [key, 0])) as Record<Counter, number>;
  const workerBuffer = new SharedArrayBuffer(finishProgressDiagnosticOffset + BigUint64Array.BYTES_PER_ELEMENT);
  const routeFolds = new BigUint64Array(workerBuffer, routeFoldDiagnosticOffset, 1);
  const worker = new Uint32Array(workerBuffer);
  const finishBoundaries = new BigUint64Array(workerBuffer, finishProgressDiagnosticOffset, 1);
  const scope = expressScope();
  const expressEvidence = { invoked: 0, withContext: 0, posted: 0 };
  try {
    const layer = realpathSync(join(dirname(resolveMedusaExpress()), "lib", "router", "layer.js"));
    observeExpressHandlers(layer, (stage) => { expressEvidence[stage] += 1; });
  } catch { /* No exact Medusa Express 4 Layer to observe. */ }
  let express: ExpressState = "not-observed";
  let transportFailed = false;
  let closeRequested = false;
  process.once("exit", (exitCode) => {
    // Do not schedule work or keep the worker alive. This is a snapshot, not a drain barrier.
    // The nonce only authenticates this finite line from the proof's private stream.
    try {
      const folded = Atomics.load(routeFolds, 0);
      const finishProgress = readFinishProgress(finishBoundaries);
      writeSync(2, "XTR-MEDUSA-CAPTURE-DIAGNOSTIC-V7 " + JSON.stringify({
        nonce, exitCode, scope, express, patchedLayers: expressPatchStatus().patched, counts,
        expressEvidence: { ...expressEvidence, anyLayerStaged: Atomics.load(worker, workerCounters.expressHandlerStaged) },
        routeFoldEvidence: { batches: Number(folded >> 32n), events: Number(folded & 0xffff_ffffn) },
        startStaged: Atomics.load(worker, workerCounters.startStaged),
        finishProgress,
        finishStaged: finishProgress?.staged ?? Atomics.load(worker, workerCounters.finishStaged),
        workerFailed: Atomics.load(worker, workerCounters.failed) === 1,
        transportFailed, closeRequested,
      }) + "\n");
    } catch { /* A missing diagnostic cannot change application exit. */ }
  });
  return {
    workerBuffer,
    increment(name) { counts[name] += 1; },
    setExpress(status) {
      if (status.name !== "express") return;
      if (status.state === "installed") { express = "installed"; return; }
      switch (status.code) {
        case "express_not_found": express = "express-not-found"; break;
        case "express_version_unsupported": express = "unsupported-express"; break;
        case "node_runtime_unsupported": express = "unsupported-node"; break;
        case "module_install_failed": express = "install-failed"; break;
        default: express = "disabled-other";
      }
    },
    transportFailed() { transportFailed = true; },
    closeRequested() { closeRequested = true; },
  };
}
