import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const fixture = fileURLToPath(new URL("./worker-exit-boundary-fixture.js", import.meta.url));

async function run(mode: "capacity" | "natural" | "explicit"): Promise<unknown> {
  const { stdout, stderr } = await promisify(execFile)(process.execPath, [fixture, mode], {
    encoding: "utf8", timeout: 10_000, maxBuffer: 4096, env: {},
  });
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
