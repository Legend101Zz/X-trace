import { parentPort, workerData } from "node:worker_threads";
import { openXtpSession, readBootstrap, type AuthenticatedXtpSession } from "./index.js";
import { CONTROL_DRAIN_INDEX, CONTROL_STAGED_INDEX, CONTROL_STARTUP_INDEX } from "./runtime/transport.cjs";
import {
  HOLD_START_MS,
  capabilitySetFor,
  createRecordingAssembler,
  createWorkerDeliveryScheduler,
  healthForRejectedStarts,
  type InputMessage,
  type RecordingAssembler,
  type WorkerDeliveryScheduler,
} from "./worker-core.js";

interface StartupData {
  bootstrapPath: string;
  startupBarrier: SharedArrayBuffer;
  manifestPath: string;
  /** Capabilities of the modules that will install; only these are advertised to the daemon. */
  capabilities?: string[];
}

type WorkerControlMessage =
  | InputMessage
  | { type: "flush" }
  | { type: "close"; rejectedStarts?: number | undefined };

const DEFAULT_WORKER_BATCH_EVENTS = 64;

const data = workerData as StartupData;
const startup = new Int32Array(data.startupBarrier);
let session: AuthenticatedXtpSession | undefined;
let assembler: RecordingAssembler | undefined;
let scheduler: WorkerDeliveryScheduler | undefined;
let shuttingDown = false;
let closingRequested = false;
let maxRejectedStarts = 0;
let closePromise: Promise<void> | undefined;
const earlyMessages: InputMessage[] = [];

function setStartup(state: 1 | 2): void {
  Atomics.store(startup, CONTROL_STARTUP_INDEX, state);
  Atomics.notify(startup, CONTROL_STARTUP_INDEX);
  parentPort?.postMessage({ type: state === 1 ? "ready" : "startup-failure" });
}

function setDrainState(state: 1 | 2): void {
  if (startup.length <= CONTROL_DRAIN_INDEX) return;
  Atomics.store(startup, CONTROL_DRAIN_INDEX, state);
  Atomics.notify(startup, CONTROL_DRAIN_INDEX);
}

function markStaged(count: number): void {
  if (count <= 0) return;
  if (startup.length > CONTROL_STAGED_INDEX) {
    Atomics.add(startup, CONTROL_STAGED_INDEX, count);
    return;
  }
  for (let i = 0; i < count; i += 1) parentPort?.postMessage({ type: "staged" });
}

function fail(): void {
  setStartup(2);
  setDrainState(2);
  parentPort?.postMessage({ type: "failure" });
  shuttingDown = true;
  void session?.close().catch(() => undefined);
}

let markReady!: () => void;
const readyPromise = new Promise<void>((resolve) => { markReady = resolve; });

async function initialize(): Promise<void> {
  const bootstrap = await readBootstrap(data.bootstrapPath);
  const opened = await openXtpSession(bootstrap, data.manifestPath, {
    adapterName: "xtrace-node-http",
    adapterVersion: "0.0.1",
    language: "node",
    runtimeName: "node",
    runtimeVersion: process.version,
    pid: BigInt(process.pid),
    processStartMonotonicNs: process.hrtime.bigint(),
  });
  session = opened;
  await opened.send("node-http-capabilities", {
    case: "capabilitySet",
    value: capabilitySetFor(data.capabilities ?? ["http.server.request_root", "async_correlation"]),
  });
  const maxBatchEvents = Math.max(1, Math.min(DEFAULT_WORKER_BATCH_EVENTS, opened.maxBatchEvents));
  const createdAssembler = createRecordingAssembler(
    (id, payload, token) => opened.send(id, payload, token),
    undefined,
    HOLD_START_MS,
    { maxBatchEvents },
  );
  const createdScheduler = createWorkerDeliveryScheduler(createdAssembler, {
    maxBatchEvents,
    onStaged: markStaged,
    onError: fail,
  });
  assembler = createdAssembler;
  scheduler = createdScheduler;
  for (const queued of earlyMessages.splice(0)) createdScheduler.enqueue(queued);
  setStartup(1);
  markReady();
}

function runClose(): Promise<void> {
  if (closePromise) return closePromise;
  closingRequested = true;
  closePromise = (async () => {
    await readyPromise;
    await scheduler?.drain();
    // Held starts are released so an unfinished request reopens as partial instead of vanishing.
    if (session && assembler && !shuttingDown) {
      await assembler.flushHeld();
    }
    if (session && !shuttingDown && maxRejectedStarts > 0) {
      await session.send("node-http-health-rejections", {
        case: "health",
        value: healthForRejectedStarts(maxRejectedStarts, process.hrtime.bigint()),
      });
    }
    shuttingDown = true;
    await session?.close();
    setDrainState(1);
    parentPort?.postMessage({ type: "drained" });
    parentPort?.close();
  })().catch(() => fail());
  return closePromise;
}

parentPort?.on("message", (message: WorkerControlMessage) => {
  if (message.type === "close") {
    const rejected = "rejectedStarts" in message ? message.rejectedStarts : undefined;
    if (typeof rejected === "number" && rejected > maxRejectedStarts) {
      maxRejectedStarts = Math.trunc(rejected);
    }
    void runClose();
    return;
  }
  if (message.type === "flush") {
    if (!closingRequested && !shuttingDown) {
      void scheduler?.flush().catch(() => fail());
    }
    return;
  }
  if (closingRequested || shuttingDown) {
    markStaged(1);
    return;
  }
  if (scheduler) {
    scheduler.enqueue(message);
  } else {
    earlyMessages.push(message);
  }
});

void initialize().catch(() => {
  markReady();
  fail();
});
