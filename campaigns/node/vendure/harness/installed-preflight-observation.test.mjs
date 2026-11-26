// Deterministic hosted regressions; no real application or package claim.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { preflightExitVerdict, readPreflightObservation, readPreflightReceipt, signalClass, validObservation } from "./installed-preflight-observation.mjs";

const valid = { phase: "init", status: "failed", code: 1, signal: null };
test("preflight observations distinguish running, failed and passed boundaries", () => {
  assert.equal(validObservation(valid), true);
  assert.equal(validObservation({ phase: "list", status: "running", code: null, signal: null }), true);
  assert.equal(validObservation({ phase: "receipt", status: "passed", code: null, signal: null }), true);
  assert.equal(validObservation({ phase: "list", status: "passed", code: null, signal: null }), false);
  assert.equal(validObservation({ phase: "list", status: "running", code: 0, signal: null }), false);
  assert.equal(validObservation({ phase: "list", status: "failed", code: 1, signal: "SIGTERM" }), false);
});
test("preflight observation reader rejects extra, duplicate, malformed and oversized fields", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vendure-observation-")), file = path.join(root, "marker");
  try {
    assert.equal(readPreflightObservation(file), null);
    for (const text of [JSON.stringify({ ...valid, private: "no" }) + "\n",
      '{"phase":"init","phase":"list","status":"failed","code":1,"signal":null}\n',
      '{"phase":"init",', "x".repeat(1025)]) {
      fs.writeFileSync(file, text, { mode: 0o600 });
      assert.equal(readPreflightObservation(file), null);
    }
    fs.writeFileSync(file, JSON.stringify(valid) + "\n", { mode: 0o600 });
    assert.deepEqual(readPreflightObservation(file), valid);
    fs.chmodSync(file, 0o644);
    assert.equal(readPreflightObservation(file), null);
    fs.unlinkSync(file);
    fs.symlinkSync("missing", file);
    assert.equal(readPreflightObservation(file), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test("container attach and process failures cannot borrow one another's success", () => {
  const passed = { passed: true };
  const marker = { phase: "receipt", status: "passed", code: null, signal: null };
  for (const [attachExit, processExit] of [[1, 0], [0, 1], [null, 0], [0, null]]) {
    assert.equal(preflightExitVerdict({ attachExit, processExit }, passed, marker), false);
  }
  assert.equal(preflightExitVerdict({ attachExit: 0, processExit: 0 }, null, marker), false);
  assert.equal(preflightExitVerdict({ attachExit: 0, processExit: 0 }, passed, null), false);
  assert.equal(preflightExitVerdict({ attachExit: 0, processExit: 0 }, passed, marker), true);
});
test("only closed signal classes are reported", () => {
  assert.equal(signalClass("SIGTERM"), "SIGTERM"); assert.equal(signalClass("SIGKILL"), "SIGKILL");
  assert.equal(signalClass("SIGINT"), "other"); assert.equal(signalClass("private text"), null);
  assert.equal(signalClass(null), null);
});

test("receipt reader requires exact private keys and a UUIDv7 identity", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vendure-preflight-receipt-")), file = path.join(root, "receipt");
  const row = { passed: true, projectId: "018f233a-2345-7123-8123-123456789abc" };
  try {
    fs.writeFileSync(file, JSON.stringify(row) + "\n", { mode: 0o600 });
    assert.deepEqual(readPreflightReceipt(file), row);
    fs.writeFileSync(file, JSON.stringify({ ...row, extra: "private" }) + "\n");
    assert.equal(readPreflightReceipt(file), null);
    fs.writeFileSync(file, JSON.stringify({ ...row, projectId: "bad" }) + "\n");
    assert.equal(readPreflightReceipt(file), null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
