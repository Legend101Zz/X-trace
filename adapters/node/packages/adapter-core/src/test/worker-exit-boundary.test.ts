import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { EventEmitter } from "node:events";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { Worker } from "node:worker_threads";
import { createCaptureCredits, createHttpCaptureTransport } from "../runtime/transport.cjs";

const fixture = fileURLToPath(new URL("./worker-exit-boundary-fixture.js", import.meta.url));

type Mode = "capacity" | "natural" | "explicit" | "cooperative" | "aborted" | "queued-explicit" | "queued-cooperative";

async function run(mode: Mode, expectedCode = 0): Promise<unknown> {
  let code = 0;
  const { stdout, stderr } = await promisify(execFile)(process.execPath, [fixture, mode], {
    encoding: "utf8", timeout: 10_000, maxBuffer: 4096, env: {},
  }).catch((failure: unknown) => {
    const error = failure as { code?: unknown; signal?: unknown; stdout?: unknown; stderr?: unknown };
    assert.equal(typeof error.code, "number");
    assert.equal(error.signal, null);
    assert.equal(typeof error.stdout, "string");
    assert.equal(typeof error.stderr, "string");
    code = error.code as number;
    return { stdout: error.stdout as string, stderr: error.stderr as string };
  });
  assert.equal(code, expectedCode);
  assert.equal(stderr, "");
  return JSON.parse(stdout) as unknown;
}

test("an admission refusal never enters the worker while the reserved finish still drains", async () => {
  assert.deepEqual(await run("capacity"), {
    capacityRefusals: 1, finishPosted: true, startEntered: 1, startStaged: 1,
    eventsStaged: 62, finishEntered: 1, finishStaged: 1, closeSeen: 1,
  });
});

test("explicit exit can leave an admitted finish unstaged while natural exit drains it", async () => {
  const admitted = {
    capacityRefusals: 0, finishPosted: true, startEntered: 1, startStaged: 1, eventsStaged: 0, finishEntered: 1,
  };
  assert.deepEqual(await run("explicit"), { ...admitted, finishStaged: 0, closeSeen: 0 });
  assert.deepEqual(await run("natural"), { ...admitted, finishStaged: 1, closeSeen: 1 });
});

test("cooperative drain stages the finish before explicit exit and preserves the requested exit code", async () => {
  assert.deepEqual(await run("cooperative", 37), {
    capacityRefusals: 0, finishPosted: true, drainResult: true,
    startEntered: 1, startStaged: 1, eventsStaged: 0, finishEntered: 1, finishStaged: 1, closeSeen: 1,
  });
});

test("the caller's abort releases an outstanding cooperative drain without claiming staging", async () => {
  assert.deepEqual(await run("aborted", 38), {
    capacityRefusals: 0, finishPosted: true, drainResult: false,
    startEntered: 1, startStaged: 1, eventsStaged: 0, finishEntered: 1, finishStaged: 0, closeSeen: 1,
  });
});

test("an already exited worker cannot start or confirm a cooperative drain", async () => {
  let calls = 0;
  const worker = Object.assign(new EventEmitter(), {
    postMessage() { calls += 1; },
    ref() { calls += 1; },
  });
  const transport = createHttpCaptureTransport(worker as unknown as Worker, createCaptureCredits());
  worker.emit("exit", 0);
  assert.equal(transport.start("fixture", "GET", 1n), false);
  assert.equal(await transport.drain?.(new AbortController().signal), false);
  assert.equal(calls, 0);
});


test("owned close drains a second finish queued behind an outstanding ACK", async () => {
  const shared = { capacityRefusals: 0, finishPosted: true, eventsStaged: 0, bothFinishesReceived: true };
  assert.deepEqual(await run("queued-explicit"), {
    ...shared, startEntered: 1, startStaged: 1, finishEntered: 1, finishStaged: 0, closeSeen: 0,
  });
  assert.deepEqual(await run("queued-cooperative", 37), {
    ...shared, drainResult: true, startEntered: 2, startStaged: 2, finishEntered: 2, finishStaged: 2, closeSeen: 1,
  });
});
