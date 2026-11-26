// Hosted-only finite evidence tests. These do not stand in for a real Vendure campaign.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pages, detail, equal } from "./installed-evidence.mjs";
import { judgeVendurePrivacy } from "./installed-privacy.mjs";

test("a repeated continuation is rejected without requesting an unbounded next page", async () => {
  let calls = 0;
  await assert.rejects(pages(async () => { calls++; return { rows: [{}], next: "same" }; }, "rows", "next", 1, 10));
  assert.equal(calls, 2);
});
test("empty continuations and unreached final pages cannot pass", async () => {
  await assert.rejects(pages(async () => ({ rows: [], next: "another" }), "rows", "next", 1, 1));
  await assert.rejects(pages(async () => ({ rows: [{}] }), "rows", "next", 1, 1));
});
test("detail rejects repeated event sequence across windows", () => {
  const event = { sequence: "0", kind: "frame", gap: null, symbol: null, interaction: null, exception: null,
    event_id: null, parent_event_id: null, async_parent_event_id: null, frame_id: null, source_binding: null };
  const row = { recording_id: "id", status: "partial", incomplete_evidence: [], drop_counts_by_priority: {}, completion: "partial", outcome: null, events: [event] };
  assert.throws(() => detail([row, row], "id", false));
});
test("projection parity compares nested values rather than JSON object insertion order", () => {
  equal({ outcome: { kind: "responded", httpStatus: 200 } }, { outcome: { httpStatus: 200, kind: "responded" } });
  assert.throws(() => equal({ event: { source: null } }, { event: { source: "fabricated" } }));
});
test("privacy checks private persisted bytes and excludes expected auth readiness transport", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-vendure-privacy-"));
  const dataHome = path.join(root, "data"), readback = path.join(root, "readback");
  fs.mkdirSync(dataHome, { mode: 0o700 }); fs.mkdirSync(readback, { mode: 0o700 });
  const witness = path.join(root, "witness.json"), diagnostic = path.join(root, "launcher.stderr");
  const secret = "synthetic-private-value-7261";
  const write = (file, text) => fs.writeFileSync(file, text, { mode: 0o600 });
  try {
    write(witness, JSON.stringify({ values: [secret] })); write(diagnostic, "");
    write(path.join(readback, "cli-1.json"), "{}"); write(path.join(readback, "api-2.json"), "{}");
    write(path.join(readback, "viewer.stderr"), "");
    write(path.join(readback, "viewer-readiness.private.json"), secret);
    write(path.join(dataHome, "segment.xtf"), Buffer.from([0, 1, 2]));
    const args = { dataHome, readback, diagnostic, witness };
    assert.equal(judgeVendurePrivacy(args).status, "passed");
    write(path.join(dataHome, "segment.xtf"), Buffer.concat([Buffer.from([0]), Buffer.from(secret), Buffer.from([0])]));
    assert.equal(judgeVendurePrivacy(args).status, "failed");
    fs.symlinkSync(witness, path.join(dataHome, "linked"));
    assert.throws(() => judgeVendurePrivacy(args));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
