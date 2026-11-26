import assert from "node:assert/strict";
import test from "node:test";
import { describeLeg, recordHostFailure } from "./installed-diagnostic.mjs";
import { projectPublicOutput } from "./installed-output.mjs";

function publicReport(baseline, instrumented) {
  return projectPublicOutput(JSON.stringify({ schemaVersion: 1, kind: "directus_installed_ordinary_development",
    releaseAcceptance: false, campaignComplete: false, projectionValid: true, result: "failed",
    capture: { recordings: 0 }, workload: { scenarios: 8, passedScenarios: 0 },
    requestCoverage: { scope: "ordinary-subset", responses: 0, missingRecordingsLowerBound: 0, individuallyAttributed: 0 },
    readback: { parity: false }, progress: { baseline, instrumented, inputCheckStage: "passed", payloadCheckStage: "failed" } }), 1);
}

test("unentered ordinary legs keep missing workload distinct from an observed empty summary", () => {
  const note = { phase: "not-started", failure: null };
  const absent = describeLeg(note, undefined, null);
  const empty = describeLeg({ phase: "cleanup", failure: null }, { scenarios: [] }, { stages: [] });
  const out = publicReport(absent, empty);
  assert.equal(out.projectionValid, true);
  assert.equal(out.progress.baseline.driver, null);
  assert.equal(out.progress.baseline.workload, null);
  assert.deepEqual(out.progress.instrumented.driver, { stages: 0, last: null, firstFailed: null });
  assert.deepEqual(out.progress.instrumented.workload, { scenarios: 0, requests: 0, responses: 0 });
  assert.equal(describeLeg(note, { scenarios: [{}] }, null).workload, null);
  assert.equal(out.result, "failed");
});

test("first observed host failure and private driver order are preserved separately", () => {
  const note = { phase: "application-readiness", failure: null };
  recordHostFailure(note, "application_readiness_deadline");
  note.phase = "driver-finish";
  recordHostFailure(note, "unsuccessful-result");
  const leg = describeLeg(note, { scenarios: [{ requests: [{ status: 200 }, { status: 0 }] }] },
    { stages: [{ name: "init-0", status: "passed" }, { name: "scan", status: "failed" }, { name: "driver", status: "failed" }] });
  const out = publicReport(leg, describeLeg({ phase: "not-started", failure: null }, null, null));
  assert.equal(out.projectionValid, true);
  assert.deepEqual(out.progress.baseline.failure, { phase: "application-readiness", reason: "application_readiness_deadline" });
  assert.deepEqual(out.progress.baseline.workload, { scenarios: 1, requests: 2, responses: 1 });
  assert.deepEqual(out.progress.baseline.driver, { stages: 3, firstFailed: "scan", last: "driver" });
});

test("private values and unbounded progress cannot enter the public ordinary receipt", () => {
  const secret = "PRIVATE-ORDINARY-PROBE";
  const note = { phase: "member-admission", failure: null };
  recordHostFailure(note, secret);
  const leg = describeLeg(note, { scenarios: [{ requests: [{ status: 200, body: secret }] }] },
    { stages: [{ name: secret, status: "failed" }] });
  const projected = publicReport({ ...leg, unexpected: secret }, leg);
  assert.equal(projected.projectionValid, true);
  assert.equal(projected.progress.baseline.failure.reason, "unclassified");
  assert.equal(projected.progress.baseline.driver.firstFailed, "unclassified");
  assert.equal(JSON.stringify(projected).includes(secret), false);
  for (const bad of [{ ...leg, phase: secret }, { ...leg, failure: { phase: "cleanup", reason: secret } },
    { ...leg, workload: { scenarios: 9, requests: 1, responses: 1 } },
    { ...leg, workload: { scenarios: 1, requests: 1, responses: 2 } },
    { ...leg, driver: { stages: 1, last: "scan", firstFailed: secret } }]) {
    const out = publicReport(leg, bad);
    assert.equal(out.projectionValid, false);
    assert.equal(Object.hasOwn(out, "progress"), false);
    assert.equal(JSON.stringify(out).includes(secret), false);
  }
});
