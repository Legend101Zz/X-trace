import assert from "node:assert/strict";
import type * as childProcessTypes from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type * as workerThreadsTypes from "node:worker_threads";
import { GapReason, RecordingEventKind } from "@xtrace/protocol";
import type { CaptureEvent, HttpCaptureTransport } from "../runtime/transport.cjs";
import { encodeEvent } from "../worker-core.js";

const require = createRequire(import.meta.url);
const childProcess = require("node:child_process") as typeof childProcessTypes;
const workerThreads = require("node:worker_threads") as typeof workerThreadsTypes;
const context = require("../runtime/context.cjs") as typeof import("../runtime/context.cjs");
const { events } = require("../runtime/events.cjs") as typeof import("../runtime/events.cjs");
const { processLinkageModule } = require("../modules.cjs") as typeof import("../modules.cjs");
const processLinkage = require("../process-linkage.cjs") as typeof import("../process-linkage.cjs");

class RecordingTransport implements HttpCaptureTransport {
  readonly events: CaptureEvent[] = [];
  start(): boolean { return true; }
  event(_id: string, event: CaptureEvent): boolean {
    this.events.push(event);
    return true;
  }
  finish(): boolean { return true; }
  onFailure(): void {}
  close(): void {}
}

function closeProcess(proc: childProcessTypes.ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (proc.exitCode !== null || proc.killed) {
      resolve();
      return;
    }
    proc.once("close", () => resolve());
    proc.once("error", () => resolve());
  });
}

function terminateWorker(worker: workerThreadsTypes.Worker): Promise<void> {
  return new Promise((resolve) => {
    worker.once("exit", () => resolve());
    worker.once("error", () => resolve());
    void worker.terminate().catch(() => resolve());
  });
}

test("uninstrumented Worker and child_process calls emit bounded gaps with zero raw argv or env leakage", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "xtrace-node-proc-"));
  t.after(() => {
    processLinkage.resetProcessLinkageForTest();
    rmSync(dir, { recursive: true, force: true });
  });

  const workerFile = join(dir, "worker.cjs");
  const childFile = join(dir, "child.cjs");
  writeFileSync(workerFile, "const { parentPort } = require('node:worker_threads'); parentPort?.postMessage('ok');\n");
  writeFileSync(childFile, "console.log(JSON.stringify({ nodeOptions: process.env.NODE_OPTIONS ?? null, bootstrap: process.env.XTRACE_BOOTSTRAP_PATH ?? null }));\n");

  const transport = new RecordingTransport();
  const parentSessionId = "01900000-0000-7000-8000-000000000010";
  processLinkage.installProcessLinkageCapture({
    transport: () => transport,
    parentSessionId: () => parentSessionId,
  });

  const status = processLinkage.processLinkagePatchStatus();
  assert.equal(status.workerPatched, true);
  assert.equal(status.childProcessPatched, 3);

  const secretArgCanary = "secret-argv-canary-991a";
  const secretEnvCanary = "secret-env-canary-882b";
  const ctx = context.createContext("POST", 1n);

  let spawnedChild: childProcessTypes.ChildProcess | undefined;
  let spawnedExecChild: childProcessTypes.ChildProcess | undefined;
  let spawnedWorker: workerThreadsTypes.Worker | undefined;
  let evalWorker: workerThreadsTypes.Worker | undefined;
  let childStdout = "";

  await context.runInContext(ctx, async () => {
    const enter = context.recordEvent(ctx, transport, events.frameEnter("OrderHandler.dispatch"));
    ctx.frameStack.push(enter);

    spawnedChild = childProcess.spawn(process.execPath, [childFile, secretArgCanary], {
      env: { PATH: process.env.PATH, SECRET_TOKEN: secretEnvCanary },
      stdio: ["ignore", "pipe", "pipe"],
    });
    spawnedChild.stdout?.on("data", (chunk: Buffer) => {
      childStdout += chunk.toString("utf8");
    });

    spawnedExecChild = childProcess.execFile(process.execPath, [childFile, secretArgCanary], {
      env: { PATH: process.env.PATH, SECRET_TOKEN: secretEnvCanary },
    });

    spawnedWorker = new workerThreads.Worker(workerFile, {
      argv: [secretArgCanary],
      env: { SECRET_TOKEN: secretEnvCanary },
    });

    evalWorker = new workerThreads.Worker("/* eval worker */", { eval: true });
  });

  if (spawnedChild) await closeProcess(spawnedChild);
  if (spawnedExecChild) await closeProcess(spawnedExecChild);
  if (spawnedWorker) await terminateWorker(spawnedWorker);
  if (evalWorker) await terminateWorker(evalWorker);

  // Verify child environment was never polluted with X-trace preload/bootstrap variables.
  const parsedChild = JSON.parse(childStdout.trim()) as { nodeOptions: string | null; bootstrap: string | null };
  assert.equal(parsedChild.nodeOptions, null);
  assert.equal(parsedChild.bootstrap, null);

  const gaps = transport.events.filter((ev) => ev.kind === "gap");
  assert.equal(gaps.length, 4, "exactly one bounded event per spawn/execFile/Worker/evalWorker without double counting");
  assert.deepEqual(
    gaps.map((g) => g.gap?.reason),
    [
      "child-process-not-instrumented",
      "child-process-not-instrumented",
      "child-process-not-instrumented",
      "correlation-lost",
    ],
  );

  // Encode through worker-core to confirm protobuf wire compatibility.
  const wireGaps = gaps.map((g) =>
    encodeEvent({
      type: "event",
      kind: g.kind,
      eventId: g.eventId,
      sequence: g.sequence,
      parentEventId: g.parentEventId,
      symbol: g.symbol,
      ...(g.gap ? { gap: g.gap } : {}),
    }),
  );
  assert.equal(wireGaps[0]!.kind, RecordingEventKind.GAP);
  assert.equal(wireGaps[0]!.gap?.reason, GapReason.CHILD_PROCESS_NOT_INSTRUMENTED);
  assert.equal(wireGaps[3]!.gap?.reason, GapReason.CORRELATION_LOST);

  const records = processLinkage.recordedProcessLinks();
  assert.equal(records.length, 4);
  assert.equal(records[0]!.spawnKind, "node_child_process");
  assert.equal(records[0]!.status, "uninstrumented_gap");
  assert.equal(records[2]!.spawnKind, "node_worker");
  assert.equal(records[2]!.status, "uninstrumented_gap");
  assert.equal(records[3]!.spawnKind, "node_worker");
  assert.equal(records[3]!.status, "correlation_lost");

  // Privacy invariant: raw argv, env, workerData, or script paths never appear anywhere.
  const serialized = JSON.stringify({ events: transport.events, records }, (_k, v) =>
    typeof v === "bigint" ? v.toString() : v,
  );
  assert.equal(serialized.includes(secretArgCanary), false);
  assert.equal(serialized.includes(secretEnvCanary), false);
  assert.equal(serialized.includes(workerFile), false);
  assert.equal(serialized.includes(childFile), false);
});

test("explicit opt-in child session registration links cleanly and fails closed on mismatch or reuse", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "xtrace-node-optin-"));
  t.after(() => {
    processLinkage.resetProcessLinkageForTest();
    rmSync(dir, { recursive: true, force: true });
  });

  const workerFile = join(dir, "worker.cjs");
  writeFileSync(workerFile, "setTimeout(() => {}, 10);\n");

  const transport = new RecordingTransport();
  const parentSessionId = "01900000-0000-7000-8000-000000000020";
  const childSessionId = "01900000-0000-7000-8000-000000000021";
  const childRecordingId = "01900000-0000-7000-8000-000000000022";
  const secretToken = "raw-child-handshake-secret-canary";

  processLinkage.installProcessLinkageCapture({
    transport: () => transport,
    parentSessionId: () => parentSessionId,
  });

  const ctx = context.createContext("GET", 1n);
  let linkedWorker: workerThreadsTypes.Worker | undefined;
  let reusedWorker: workerThreadsTypes.Worker | undefined;

  await context.runInContext(ctx, async () => {
    const enter = context.recordEvent(ctx, transport, events.frameEnter("Root.work"));
    ctx.frameStack.push(enter);

    processLinkage.withOptInChildLink(
      {
        childSessionId,
        childRecordingId,
        correlationToken: secretToken,
        expectedCorrelationToken: secretToken,
      },
      () => {
        linkedWorker = new workerThreads.Worker(workerFile);
        // Second spawn inside the same single-use opt-in scope fails closed with bootstrap-consumed.
        reusedWorker = new workerThreads.Worker(workerFile);
      },
    );

    // Explicit registration with mismatched token fails closed to correlation_lost.
    const failed = processLinkage.registerChildSessionLink({
      spawnKind: "node_child_process",
      childSessionId: "01900000-0000-7000-8000-000000000023",
      correlationToken: "wrong-token",
      expectedCorrelationToken: secretToken,
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.link.status, "correlation_lost");
    assert.equal(failed.link.gapReason, "correlation-lost");

    // Self-link is rejected fail-closed.
    const selfLink = processLinkage.registerChildSessionLink({
      spawnKind: "node_worker",
      parentSessionId,
      childSessionId: parentSessionId,
      correlationToken: secretToken,
    });
    assert.equal(selfLink.ok, false);
    assert.equal(selfLink.link.status, "correlation_lost");
  });

  if (linkedWorker) await terminateWorker(linkedWorker);
  if (reusedWorker) await terminateWorker(reusedWorker);

  const records = processLinkage.recordedProcessLinks();
  assert.equal(records.length, 4);
  assert.equal(records[0]!.status, "linked");
  assert.equal(records[0]!.childSessionId, childSessionId);
  assert.equal(records[0]!.childRecordingId, childRecordingId);
  assert.ok(records[0]!.correlationTokenHash?.startsWith("sha256:"));
  assert.equal(records[1]!.status, "uninstrumented_gap");
  assert.equal(records[1]!.gapReason, "bootstrap-consumed");
  assert.equal(records[2]!.status, "correlation_lost");
  assert.equal(records[3]!.status, "correlation_lost");

  assert.equal(transport.events[1]!.kind, "async-link");
  assert.equal(transport.events[1]!.asyncParentEventId, childRecordingId);
  assert.equal(transport.events[2]!.gap?.reason, "bootstrap-consumed");
  assert.equal(transport.events[3]!.gap?.reason, "correlation-lost");

  // Raw token never appears in stored records or emitted events.
  const serialized = JSON.stringify({ events: transport.events, records }, (_k, v) =>
    typeof v === "bigint" ? v.toString() : v,
  );
  assert.equal(serialized.includes(secretToken), false);
});

test("captureSuppressed prevents recording X-trace's own internal workers", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "xtrace-node-suppress-"));
  t.after(() => {
    processLinkage.resetProcessLinkageForTest();
    rmSync(dir, { recursive: true, force: true });
  });

  const workerFile = join(dir, "internal-worker.cjs");
  writeFileSync(workerFile, "setTimeout(() => {}, 10);\n");

  const transport = new RecordingTransport();
  const mod = processLinkageModule(() => transport);
  assert.deepEqual(mod.detect({ nodeVersion: process.version, packageVersion: "" }), { supported: true });
  mod.install({ nodeVersion: process.version, packageVersion: "" });

  const ctx = context.createContext("GET", 1n);
  let internalWorker: workerThreadsTypes.Worker | undefined;
  context.runInContext(ctx, () => {
    context.withoutCapture(() => {
      internalWorker = new workerThreads.Worker(workerFile);
    });
  });
  if (internalWorker) await terminateWorker(internalWorker);

  assert.equal(transport.events.length, 0);
  assert.equal(processLinkage.recordedProcessLinks().length, 0);
});
