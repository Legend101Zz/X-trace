import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { zstdCompressSync } from "node:zlib";
import { equal, inventory, missingParents, verifiedDetail, judgeObservedWorkload } from "./installed-evidence.mjs";
import { judgeInstalledVendurePrivacy } from "./installed-privacy.mjs";
import { installedCaptureDisposition, installedReadbackReceipt, launcherObservations, readbackReceipt } from "./installed-lifecycle.mjs";
import { OwnedServicesFixture } from "./owned-services.mjs";

const rename = value => Object.fromEntries(Object.entries(value).map(([key, field]) =>
  [key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()), field]));

const project = "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa", id = "bbbbbbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb";
const list = { project_id: project, after: null, next_after: null, limit: 20, recordings: [
  { recording_id: id, status: "complete", incomplete_evidence: [], completion: "complete", segment_count: "1", event_count: "2", first_sequence: "0", last_sequence: "1" },
] };
const event = { gap: null, sequence: "0", kind: "frame", symbol: null, interaction: null, exception: null, source_binding: null,
  event_id: "first", parent_event_id: null, async_parent_event_id: null, frame_id: null };
const window = { project_id: project, recording_id: id, status: "complete", incomplete_evidence: [], completion: "complete", segment_count: "1", limit: 100,
  drop_counts_by_priority: {}, cursor: null, next_cursor: null, first_sequence: "0", last_sequence: "0", events: [event], outcome: null };

test("shared truncated CLI and API detail cannot satisfy the independent list count and range", () => {
  const row = inventory([list], project, false).get(id);
  assert.throws(() => verifiedDetail([window], id, project, row, false));
  const whole = { ...window, last_sequence: "1", events: [event, { ...event, sequence: "1" }] };
  assert.equal(verifiedDetail([whole], id, project, row, false).events.length, 2);
});

test("each actual list and detail page must echo project, bound and cursor", () => {
  const row = inventory([list], project, false).get(id);
  for (const bad of [{ after: "wrong" }, { project_id: id }, { limit: 19 }]) {
    assert.throws(() => inventory([{ ...list, ...bad }], project, false));
  }
  const whole = { ...window, last_sequence: "1", events: [event, { ...event, sequence: "1" }] };
  for (const bad of [{ cursor: "wrong" }, { project_id: id }, { limit: 99 }, { segment_count: "2" }, { last_sequence: "0" }]) {
    assert.throws(() => verifiedDetail([{ ...whole, ...bad }], id, project, row, false));
  }
});

test("an async parent cannot be resolved using another request's events", () => {
  const events = [{ eventId: "one", parentEventId: null, asyncParentEventId: null },
    { eventId: "two", parentEventId: "one", asyncParentEventId: "elsewhere" }];
  assert.deepEqual(missingParents(events), { direct: 0, async: 1 });
});

test("an uncertain service stop retains its exact handle and cannot invoke forced disposal", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-owned-service-"));
  const calls = [];
  try {
    const fixture = new OwnedServicesFixture(directory, { db: "db" }, "node", args => {
      calls.push(args); return { status: 1, stdout: "" };
    });
    fixture.containers.set("db", "a".repeat(64));
    fixture.controls.set("db", directory);
    assert.throws(() => fixture.cleanup());
    assert.deepEqual(calls, [["wait", "a".repeat(64)]]);
    assert.ok(fs.existsSync(path.join(directory, "stop.request")));
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, "kept-fixture.json"))).containers.db, "a".repeat(64));
  } finally { fs.rmSync(directory, { force: true, recursive: true }); }
});

test("persisted privacy requires exact project DB, segment inventory, and decoded XTF witnesses", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-vendure-store-"));
  const mkdir = name => { fs.mkdirSync(name, { mode: 0o700 }); return name; };
  const write = (file, bytes) => fs.writeFileSync(file, bytes, { mode: 0o600 });
  const secret = "private-example-975231";
  const args = { dataHome: mkdir(path.join(dir, "data")), readback: mkdir(path.join(dir, "reader")),
    witness: path.join(dir, "witness.json"), diagnostic: path.join(dir, "launcher.stderr") };
  try {
    write(args.witness, JSON.stringify({ values: [secret] })); write(args.diagnostic, "");
    for (const name of ["api-1.json", "cli-2.json", "viewer.stderr"]) write(path.join(args.readback, name), "{}");
    const inventoryFile = path.join(args.readback, "store-inventory.private.json");
    assert.throws(() => judgeInstalledVendurePrivacy(args));
    write(inventoryFile, JSON.stringify({ projectId: project, recordings: [] }));
    assert.throws(() => judgeInstalledVendurePrivacy(args));
    const record = { projectId: project, recordings: [[id, { segments: 1, count: 2 }]] };
    write(inventoryFile, JSON.stringify(record));
    assert.throws(() => judgeInstalledVendurePrivacy(args));
    const prefix = mkdir(path.join(mkdir(path.join(args.dataHome, "projects")), project));
    const database = path.join(prefix, "metadata.sqlite3");
    write(database, Buffer.alloc(0));
    const db = new DatabaseSync(database);
    const uuidBytes = value => Buffer.from(value.replaceAll("-", ""), "hex");
    const hash = Buffer.alloc(32, 0xab);
    const logical = Buffer.from("XTF1" + secret.repeat(30));
    const compressed = zstdCompressSync(logical);
    try {
      db.exec("CREATE TABLE recordings(recording_id BLOB, project_id BLOB); CREATE TABLE recording_segments(recording_id BLOB, object_hash BLOB, segment_ordinal INTEGER, event_count INTEGER, compressed_bytes INTEGER, uncompressed_bytes INTEGER)");
      db.prepare("INSERT INTO recordings VALUES(?,?)").run(uuidBytes(id), uuidBytes(project));
      db.prepare("INSERT INTO recording_segments VALUES(?,?,0,2,?,?)").run(uuidBytes(id), hash, compressed.length, logical.length);
    } finally { db.close(); }
    assert.throws(() => judgeInstalledVendurePrivacy(args));
    const b3 = mkdir(path.join(mkdir(path.join(prefix, "objects")), "b3"));
    const file = path.join(mkdir(path.join(b3, "ab")), "ab".repeat(31) + ".xtf.zst");
    write(file, compressed);
    const actual = judgeInstalledVendurePrivacy(args);
    assert.equal(actual.status, "failed"); assert.equal(actual.decodedSegments, 1);
    assert.equal(actual.decodedMatches, 1); assert.ok(actual.surfaces.persisted.files >= 2);
    write(inventoryFile, JSON.stringify({ ...record, projectId: id }));
    assert.throws(() => judgeInstalledVendurePrivacy(args));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("failed readback retains observed counters and the exact process exit", () => {
  const failed = { status: "failed", workloadRecordings: 7, complete: 5, cliViewerParity: true };
  for (const code of [0, 1, null]) {
    const result = readbackReceipt(code, () => failed);
    assert.equal(result.status, "failed"); assert.equal(result.complete, 5);
    assert.equal(result.workloadRecordings, 7); assert.equal(result.cliViewerParity, true);
    assert.equal(result.processSucceeded, code === 0); assert.equal(result.processExit, code);
  }
  const contradictory = readbackReceipt(1, () => ({ ...failed, status: "passed" }));
  assert.equal(contradictory.status, "failed"); assert.equal(contradictory.complete, 5);
  assert.equal(contradictory.processExit, 1); assert.equal(contradictory.processSucceeded, false);
  const gone = readbackReceipt(0, () => { throw new Error("private parse detail"); });
  assert.equal(gone.status, "failed"); assert.equal(gone.documentAvailable, false);
  assert.equal(gone.processSucceeded, true);
});

test("verified private store inventory survives a later recording semantics failure", () => {
  const rows = inventory([list], project, false), written = new Map();
  const report = { status: "failed", cliViewerParity: false, workloadRecordings: 0, complete: 0,
    httpRoots: 0, expressHandlers: 0, orphanParents: 0, orphanAsyncParents: 0, absentOutcome: 0 };
  const selected = { status: "partial", completion: "partial", events: [], outcome: null };
  assert.throws(() => judgeObservedWorkload({ save: (name, bytes) => written.set(name, bytes),
    projectId: project, cliRows: rows, readyIds: [], details: new Map([[id, selected]]),
    config: { responses: 1, statuses: { 200: 1 } }, report }));
  assert.equal(report.cliViewerParity, true); assert.equal(report.workloadRecordings, 1);
  assert.equal(report.absentOutcome, 1); assert.equal(report.status, "failed");
  assert.equal(report.aggregateResponseStatusMultisetMatches, false);
  assert.deepEqual(JSON.parse(written.get("store-inventory.private.json")),
    { projectId: project, recordings: [...rows] });
});

test("equal event counts and sequences cannot hide a lifecycle or window-specific gap disagreement", () => {
  const cliRow = inventory([list], project, false).get(id);
  const cliDoc = { ...window, last_sequence: "1", events: [event, { ...event, sequence: "1" }] };
  const cliDetail = verifiedDetail([cliDoc], id, project, cliRow, false);
  const apiDoc = { ...rename(cliDoc), events: cliDoc.events.map(rename) };
  const apiList = { ...rename(list), recordings: list.recordings.map(rename) };
  const apiRow = inventory([apiList], project, true).get(id);
  equal(apiRow, cliRow);
  equal(verifiedDetail([apiDoc], id, project, apiRow, true), cliDetail);
  const otherList = { ...apiList, recordings: [{ ...apiList.recordings[0], status: "finalizing" }] };
  assert.throws(() => equal(inventory([otherList], project, true).get(id), cliRow));
  assert.throws(() => verifiedDetail([{ ...apiDoc, status: "partial" }], id, project, apiRow, true));
  const otherWindow = verifiedDetail([{ ...apiDoc, incompleteEvidence: ["gap_event_sequence:1"] }], id, project, apiRow, true);
  assert.throws(() => equal(otherWindow, cliDetail));
  const cliWindows = [
    { ...window, next_cursor: "page-two" },
    { ...window, cursor: "page-two", first_sequence: "1", last_sequence: "1",
      events: [cliDoc.events[1]], incomplete_evidence: ["gap_event_sequence:1"] },
  ];
  const apiWindows = cliWindows.map(doc => ({ ...rename(doc), events: doc.events.map(rename) }));
  const twoPages = verifiedDetail(cliWindows, id, project, cliRow, false);
  equal(verifiedDetail(apiWindows, id, project, apiRow, true), twoPages);
  apiWindows[0].incompleteEvidence = apiWindows[1].incompleteEvidence;
  apiWindows[1].incompleteEvidence = [];
  assert.throws(() => equal(verifiedDetail(apiWindows, id, project, apiRow, true), twoPages));
});

test("complete recording credit requires the durable terminal and clean gap evidence on both reads", () => {
  const row = inventory([list], project, false).get(id);
  const root = { ...event, kind: "recording_event_kind:frame_enter", symbol: "node:http.Server.request" };
  const handler = { ...root, sequence: "1", event_id: "second", parent_event_id: "first", symbol: "express.handler:item" };
  const full = { ...window, outcome: { kind: "responded", httpStatus: 200 }, last_sequence: "1", events: [root, handler] };
  const observe = (doc, metadata = row) => {
    const report = { workloadRecordings: 0, complete: 0, httpRoots: 0, expressHandlers: 0, absentOutcome: 0,
      orphanParents: 0, orphanAsyncParents: 0 };
    const verified = verifiedDetail([doc], id, project, metadata, false);
    judgeObservedWorkload({ save() {}, projectId: project, cliRows: new Map([[id,metadata]]), readyIds: [],
      details: new Map([[id, verified]]), config: { responses: 1, statuses: { 200: 1 } }, report });
    return report;
  };
  assert.equal(observe(full).complete, 1);
  assert.throws(() => observe({ ...full, status: "recording" }, { ...row, status: "recording" }));
  assert.throws(() => observe({ ...full, incomplete_evidence: ["gap_event_sequence:1"] }));
  assert.throws(() => observe(full, { ...row, incompleteEvidence: ["persisted_status:partial"] }));
  assert.throws(() => observe({ ...full, drop_counts_by_priority: { 1: "2" } }));
  assert.throws(() => observe({ ...full, events: [root, { ...handler, gap: { dropped: "1" } }] }));
});

test("normal launcher shutdown preserves worker and readback eligibility across all capture notice observations", () => {
  const wait = { status: 0, stdout: "0" };
  for (const [marker, expected] of [[false, "absent"], [true, "present"], [null, "unknown"]]) {
    const terminal = { normalExit: true, captureIncompleteNotice: marker };
    const state = launcherObservations(true, wait, terminal);
    assert.deepEqual(state, { shutdown: "normal", captureNotice: expected });
    assert.deepEqual(installedCaptureDisposition(state), { allowReadback: true, eligibleForPass: marker === false });
    const failed = launcherObservations(true, { status: 1, stdout: "" }, terminal);
    assert.deepEqual(installedCaptureDisposition(failed), { allowReadback: false, eligibleForPass: false });
  }
});

test("readback distinguishes the attached command from the exact owned container exit", async () => {
  const handle = "c".repeat(64);
  for (const [attachExit, state, processExit, verdict] of [
    [7, "running 0", null, "failed"], [8, "exited 0", 0, "failed"], [null, "exited 7", 7, "failed"],
    [0, "exited 9", 9, "failed"], [0, "exited 0", 0, "passed"],
  ]) {
    const fixture = new OwnedServicesFixture("private", { db: "db" }, "node", args => {
      assert.deepEqual(args, ["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", handle]);
      return { status: 0, stdout: state };
    }, args => { assert.deepEqual(args, ["start", "--attach", handle]); return attachExit; });
    fixture.create = () => handle;
    const observed = await fixture.runObserved("reader", [], "private-log");
    const receipt = installedReadbackReceipt(observed, () => ({ status: "passed", complete: 2 }));
    assert.deepEqual(observed, { attachExit, processExit });
    assert.equal(receipt.status, verdict); assert.equal(receipt.complete, 2);
    assert.equal(receipt.documentStatus, "passed"); assert.equal(receipt.documentAvailable, true);
    assert.equal(receipt.processSucceeded, processExit === 0);
  }
});

test("identical events and ordinal reasons must cover the same ranges in both readers", () => {
  const row = { ...inventory([list], project, false).get(id), count: 4, last: "3" };
  const events = ["0", "1", "2", "3"].map(sequence => ({ ...event, sequence }));
  function windows(split) {
    return [events.slice(0, split), events.slice(split)].map((part, i) => ({ ...window,
      events: part, first_sequence: part[0].sequence, last_sequence: part.at(-1).sequence,
      cursor: i === 0 ? null : "next", next_cursor: i === 0 ? "next" : null,
      incomplete_evidence: i === 0 ? [] : ["window-specific"],
    }));
  }
  const left = verifiedDetail(windows(2), id, project, row, false);
  const apiWindows = split => windows(split).map(doc => ({ ...rename(doc), events: doc.events.map(rename) }));
  equal(left, verifiedDetail(apiWindows(2), id, project, row, true));
  assert.throws(() => equal(left, verifiedDetail(apiWindows(1), id, project, row, true)));
});
