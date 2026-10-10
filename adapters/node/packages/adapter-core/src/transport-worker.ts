import { parentPort, workerData } from "node:worker_threads";
import { openXtpSession, readBootstrap, type AuthenticatedXtpSession } from "./index.js";
import { capabilitySetFor, createRecordingAssembler, type InputMessage } from "./worker-core.js";

interface StartupData {
  bootstrapPath: string;
  startupBarrier: SharedArrayBuffer;
  manifestPath: string;
  /** Capabilities of the modules that will install; only these are advertised to the daemon. */
  capabilities?: string[];
}

const data = workerData as StartupData;
const startup = new Int32Array(data.startupBarrier);
let session: AuthenticatedXtpSession | undefined;
let delivery = Promise.resolve();
let shuttingDown = false;
let closingRequested = false;

const assembler = createRecordingAssembler((id, payload, token) => session!.send(id, payload, token));

function setStartup(state: 1 | 2): void {
  Atomics.store(startup, 0, state);
  Atomics.notify(startup, 0);
  parentPort?.postMessage({ type: state === 1 ? "ready" : "startup-failure" });
}

function fail(): void {
  setStartup(2);
  parentPort?.postMessage({ type: "failure" });
  shuttingDown = true;
  void session?.close().catch(() => undefined);
}

async function deliver(message: InputMessage): Promise<void> {
  if (!session || shuttingDown) return;
  await assembler.handle(message);
  parentPort?.postMessage({ type: "staged" });
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
  setStartup(1);
}

parentPort?.on("message", (message: InputMessage) => {
  if (message.type === "close") {
    closingRequested = true;
    delivery = delivery.then(async () => {
      // Held starts are released so an unfinished request reopens as partial instead of vanishing.
      if (session && !shuttingDown) await assembler.flushHeld();
      shuttingDown = true;
      await session?.close();
      parentPort?.close();
    }).catch(() => fail());
    return;
  }
  if (closingRequested) return;
  delivery = delivery.then(() => deliver(message)).catch(() => fail());
});

void initialize().catch(() => fail());
