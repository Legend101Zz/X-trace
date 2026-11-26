import { RecordingEventKind } from "@xtrace/protocol";
import { parentPort, receiveMessageOnPort, workerData } from "node:worker_threads";
import { returnCaptureCredits, routeFoldDiagnosticOffset, workerCounters } from "./runtime/transport.cjs";
import { openXtpSession, readBootstrap, type AuthenticatedXtpSession } from "./index.js";
import { capabilitySetFor, createRecordingAssembler, type InputMessage, type SendFn } from "./worker-core.js";
import { FINISH_PROGRESS_WORDS, finishProgressDiagnosticOffset, noteFinishPreparation,
  noteFinishProgress, noteFinishWork, type FinishWork } from "./runtime/finish-progress.cjs";
import { createWorkerDelivery } from "./worker-delivery.js";

interface StartupData {
  bootstrapPath: string;
  startupBarrier: SharedArrayBuffer;
  credits: Uint32Array<SharedArrayBuffer>;
  manifestPath: string;
  /** Capabilities of the modules that will install; only these are advertised to the daemon. */
  capabilities?: string[];
  diagnosticBuffer?: SharedArrayBuffer;
}

const data = workerData as StartupData;
const startup = new Int32Array(data.startupBarrier);
const diagnostic = data.diagnosticBuffer && new Uint32Array(data.diagnosticBuffer);
const routeFolds = data.diagnosticBuffer && new BigUint64Array(data.diagnosticBuffer, routeFoldDiagnosticOffset, 1);
const finishProgress = data.diagnosticBuffer && new BigUint64Array(data.diagnosticBuffer, finishProgressDiagnosticOffset, FINISH_PROGRESS_WORDS);
let session: AuthenticatedXtpSession | undefined;
let delivery: ReturnType<typeof createWorkerDelivery> | undefined;
let shuttingDown = false;

const send: SendFn = (id, payload, token) => session!.send(id, payload, token);
const observedSend: SendFn = diagnostic ? async (id, payload, token) => {
  if (payload.case === "recordingFinished" && finishProgress) {
    noteFinishPreparation(finishProgress, null);
    noteFinishProgress(finishProgress, "submitted");
    const result = await session!.send(id, payload, token, () => noteFinishProgress(finishProgress, "written"));
    noteFinishProgress(finishProgress, "staged");
    Atomics.add(diagnostic, workerCounters.finishStaged, 1);
    return result;
  }
  const result = await send(id, payload, token);
  if (payload.case === "recordingStarted") Atomics.add(diagnostic, workerCounters.startStaged, 1);
  if (payload.case === "eventBatch") {
    for (const event of payload.value.events) {
      if (event.kind === RecordingEventKind.FRAME_ENTER && event.symbol.startsWith("express.handler:")) {
        Atomics.add(diagnostic, workerCounters.expressHandlerStaged, 1);
      }
    }
  }
  return result;
} : send;

function setStartup(state: 1 | 2): void {
  Atomics.store(startup, 0, state);
  Atomics.notify(startup, 0);
  parentPort?.postMessage({ type: state === 1 ? "ready" : "startup-failure" });
}

function fail(): void {
  if (shuttingDown) return;
  shuttingDown = true;
  delivery?.abort();
  if (diagnostic) Atomics.store(diagnostic, workerCounters.failed, 1);
  setStartup(2);
  parentPort?.postMessage({ type: "failure" });
  // A queued close may already have referenced this worker. Abort discards that
  // queue, so close the message port here as well as the authenticated session.
  parentPort?.close();
  void session?.close().catch(() => undefined);
}

async function initialize(): Promise<void> {
  const bootstrap = await readBootstrap(data.bootstrapPath);
  session = await openXtpSession(bootstrap, data.manifestPath, {
    adapterName: "xtrace-node-http",
    adapterVersion: "0.0.1",
    language: "node",
    runtimeName: "node",
    runtimeVersion: process.version,
    pid: BigInt(process.pid),
    processStartMonotonicNs: process.hrtime.bigint(),
  });
  await session.send("node-http-capabilities", {
    case: "capabilitySet",
    value: capabilitySetFor(data.capabilities ?? ["http.server.request_root", "async_correlation"]),
  });
  const assembler = createRecordingAssembler(
    observedSend, undefined, undefined, session, fail,
    finishProgress && ((phase) => noteFinishPreparation(finishProgress, phase)),
  );
  // The opt-in receipt samples a notification-driven view. Wakeups coalesce.
  const notify = diagnostic ? () => parentPort?.postMessage({ type: "staged" }) : undefined;
  delivery = createWorkerDelivery(assembler, {
    receivePending: () => parentPort
      ? receiveMessageOnPort(parentPort)?.message as InputMessage | undefined
      : undefined,
    staged: (count) => returnCaptureCredits(data.credits, count, notify),
    ...(finishProgress ? {
      finishProgress: (boundary: "received" | "dispatched") => noteFinishProgress(finishProgress, boundary),
      activeWork: (type: FinishWork) => noteFinishWork(finishProgress, type),
    } : {}),
    ...(routeFolds ? {
      routeFoldStaged(events: number) {
        // One atomic pair so the exit snapshot cannot observe half a fold.
        Atomics.add(routeFolds, 0, (1n << 32n) + BigInt(events));
      },
    } : {}),
    async close() {
      await session!.close();
      parentPort?.postMessage({ type: "drained" });
      parentPort?.close();
      shuttingDown = true;
    },
    fail,
  });
  setStartup(1);
}

parentPort?.on("message", (message: InputMessage) => delivery?.enqueue(message));

void initialize().catch(() => fail());
