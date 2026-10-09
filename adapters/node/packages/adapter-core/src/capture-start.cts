import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { createHttpCaptureTransport } from "./http-capture.cjs";
import { effectiveLimitations } from "./manifest.cjs";
import { asyncContextModule, expressModule, nodeHttpModule } from "./modules.cjs";
import { setCaptureProfile } from "./runtime/context.cjs";
import { ModuleRegistry, type InstallEnvironment, type InstrumentationModule } from "./runtime/registry.cjs";
import type { HttpCaptureTransport } from "./runtime/transport.cjs";

const STARTUP_TIMEOUT_MS = 5_000;

const STARTED = Symbol.for("xtrace.capture.started.v1");

/** True the first time only: `--require` and `--import` preloads may both run, capture starts once. */
export function claimCaptureStart(): boolean {
  const holder = globalThis as unknown as Record<symbol, boolean | undefined>;
  if (holder[STARTED]) return false;
  Object.defineProperty(holder, STARTED, { value: true, enumerable: false });
  return true;
}

export interface CapturePlan {
  /** Capability names the worker handshake advertises (computed from detection, before install). */
  planned: string[];
  /** Installs the modules for the transport, then sets the recording profile (limitations, hold). */
  install(transport: HttpCaptureTransport): void;
}

/** One place for module detection, registry install and capture profile, shared by the CJS and ESM entries. */
export function planCapture(): CapturePlan {
  const environment: InstallEnvironment = { nodeVersion: process.version, packageVersion: "" };
  let transport: HttpCaptureTransport | undefined;
  const modules: InstrumentationModule[] = [nodeHttpModule(() => transport!), asyncContextModule(), expressModule()];
  const planned = modules.filter((module) => module.detect(environment).supported).map((module) => module.descriptor.capability);
  return {
    planned,
    install(created) {
      transport = created;
      const registry = new ModuleRegistry();
      for (const module of modules) registry.tryInstall(module, environment);
      // Recordings carry the limitations that really hold: the baseline plus every module that did not install.
      setCaptureProfile({
        limitations: effectiveLimitations(new Set(registry.statuses().filter((status) => status.state === "installed").map((status) => status.name))),
        // The start is held briefly (bounded in the worker) so a route resolved at finish can ride on it.
        holdStart: registry.capabilities().includes("http.server.route_template"),
      });
    },
  };
}

export function startCaptureFromRequire(): void {
  if (!claimCaptureStart()) return;
  const bootstrapPath = process.env.XTRACE_BOOTSTRAP_PATH;
  restoreLauncherEnvironment();
  if (!bootstrapPath) {
    warnUnavailable("XTR-NODE-BOOTSTRAP");
    return;
  }
  const plan = planCapture();
  const startupBarrier = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  let worker: Worker;
  try {
    worker = new Worker(join(__dirname, "transport-worker.js"), {
      execArgv: [],
      workerData: {
        bootstrapPath,
        startupBarrier,
        manifestPath: join(__dirname, "node-capabilities.json"),
        capabilities: plan.planned,
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
    plan.install(createHttpCaptureTransport(worker));
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
