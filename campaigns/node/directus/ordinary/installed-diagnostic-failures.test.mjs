import assert from "node:assert/strict";
import test from "node:test";
import { finishOrdinaryDriver, sameInstalledPayload } from "./installed-diagnostic.mjs";

test("ordinary payload parity requires both verified installed identities and independent pins", () => {
  const pins = { sourceCommit: "a".repeat(40), platform: "linux-x86_64", nodeVersion: "v22.23.0",
    archiveSha256: "b".repeat(64), nodeBinarySha256: "c".repeat(64) };
  const identity = { ...pins, manifestSha256: "d".repeat(64), cliSha256: "e".repeat(64),
    nodePackManifestSha256: "f".repeat(64), analyzerSha256: "0".repeat(64) };
  const stages = ["package-verifier", "extract", "install", "verify-install"].map(name => ({ name, status: "passed", exitCode: 0 }));
  const pair = (left, right, expected = pins) => sameInstalledPayload(
    { mode: "baseline", stages, identity: left }, { mode: "instrumented", stages, identity: right }, expected);
  assert.equal(pair(identity, { ...identity }), true);
  for (const missing of [null, undefined, {}, { ...identity, analyzerSha256: "" }]) {
    assert.equal(pair(missing, missing), false);
    assert.equal(pair(identity, missing), false);
  }
  for (const field of Object.keys(identity)) {
    const incomplete = { ...identity };
    delete incomplete[field];
    assert.equal(pair(incomplete, incomplete), false);
  }
  assert.equal(pair(identity, { ...identity, cliSha256: "1".repeat(64) }), false);
  for (const key of Object.keys(pins)) assert.equal(pair(identity, identity, { ...pins, [key]: "wrong-pin" }), false);
  for (const broken of [stages.slice(0, 3), [...stages, stages[0]], [...stages.slice(0, 3), { ...stages[3], exitCode: 1 }]]) {
    assert.equal(sameInstalledPayload({ mode: "baseline", stages, identity }, { mode: "instrumented", stages: broken, identity }, pins), false);
  }
});

test("an unavailable ordinary container leaves required finish unreached and preserves the first host failure", () => {
  const note = { phase: "scenario-evidence", failure: null };
  let attempts = 0;
  const finish = () => { attempts += 1; return { status: 0 }; };
  assert.deepEqual(finishOrdinaryDriver(note, () => false, finish), { name: "driver_finish", status: "unreached" });
  assert.deepEqual(note.failure, { phase: "driver-finish", reason: "finish-container-unavailable" });
  assert.equal(attempts, 0);
  const unknown = { phase: "scenario-evidence", failure: null };
  assert.equal(finishOrdinaryDriver(unknown, () => { throw Error("PRIVATE"); }, finish).status, "unreached");
  assert.deepEqual(unknown.failure, { phase: "driver-finish", reason: "unclassified" });
  assert.equal(attempts, 0);
  const prior = { phase: "application-readiness", reason: "application_readiness_deadline" };
  const earlierFailure = { phase: prior.phase, failure: prior };
  assert.equal(finishOrdinaryDriver(earlierFailure, () => false, finish).status, "unreached");
  assert.deepEqual(earlierFailure.failure, prior);
  assert.equal(attempts, 0);
  assert.equal(finishOrdinaryDriver({ phase: "scenario-evidence", failure: null }, () => true, finish).status, "passed");
  assert.equal(attempts, 1);
});
