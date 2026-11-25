import test from "node:test";
import assert from "node:assert/strict";
import { compareWorkload, inspectCapture, parity, boundedSummary } from "./installed-judge.mjs";
import { pages, validateEvents } from "./installed-readback.mjs";
import { spawnSync } from "node:child_process";
import { createOwned, removeOwned } from "./installed-ownership.mjs";
import { captureNoticeOutcome } from "./installed-drain.mjs";
import { projectPublicOutput } from "./installed-output.mjs";
import { ORDINARY_IDS, ordinaryRequest, ordinaryScenarios } from "./installed-ordinary-scope.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const fingerprint = "a".repeat(64);
const scenario = { id: "auth-admin-login", result: "passed", requests: [{ status: 200 }], semanticEffectFingerprint: fingerprint };
const run = (...scenarios) => ({ scenarios });
const enter = { sequence: "1", kind: "recording_event_kind:frame_enter", symbol: "node:http.Server.request", eventId: "root", parentEventId: null };
const express = { sequence: "2", kind: "recording_event_kind:frame_enter", symbol: "express.middleware", eventId: "middleware", parentEventId: "root" };
const detail = () => ({ completion: "complete", outcome: { kind: "responded", httpStatus: 200 }, events: [enter, express], limitations: [] });

test("workload requires complete identical passing scenario sets", () => {
  assert.equal(compareWorkload(run(scenario), run(scenario), [scenario.id]).passed, true);
  for (const changed of [run(), run({ ...scenario, result: "failed" }), run(scenario, scenario),
    run({ ...scenario, semanticEffectFingerprint: "b".repeat(64) }), run({ ...scenario, semanticEffectFingerprint: null })]) {
    assert.equal(compareWorkload(run(scenario), changed, [scenario.id]).passed, false);
  }
  assert.equal(compareWorkload(run(scenario), run(scenario), []).passed, false);
});

test("a partial capture, orphan, invented root parent and absent outcome stay visible", () => {
  const d = detail(); d.completion = "partial"; d.outcome = null;
  d.events = [{ ...enter, parentEventId: "missing" }, express];
  const report = inspectCapture({ selected: d });
  assert.equal(report.complete, 0); assert.equal(report.oneRoot, 0);
  assert.equal(report.outcomes, 0); assert.equal(report.orphanParents, 1);
});

test("a recorded async parent must resolve, and the HTTP root must have no parent of either kind", () => {
  const d = detail();
  d.events = [{ ...enter, asyncParentEventId: "missing" }, { ...express, asyncParentEventId: "missing" }];
  const report = inspectCapture({ selected: d });
  assert.equal(report.oneRoot, 0);
  assert.equal(report.orphanParents, 2);
  d.events = [enter, { ...express, asyncParentEventId: "root" }];
  const linked = inspectCapture({ selected: d });
  assert.equal(linked.oneRoot, 1);
  assert.equal(linked.orphanParents, 0);
});

test("source needs matched bytes, an excerpt and an acceptable binding", () => {
  for (const binding of [undefined, "source_map_absent", "class_bytes_mismatch"]) {
    const d = detail(); d.events = [{ ...express, sourceBinding: binding,
      source: { status: "matched", startLine: 3, excerpt: "example" } }];
    assert.equal(inspectCapture({ selected: d }).sourcedRecordings, 0);
  }
  const d = detail(); d.events.push({ ...express, sourceBinding: "observed_unattested",
    source: { status: "matched", startLine: 3, excerpt: "example" } });
  assert.equal(inspectCapture({ selected: d }).sourcedRecordings, 1);
});

test("CLI/API parity compares event identity, parent, source, exception and interaction", () => {
  const d = detail();
  const cli = { selected: { ...d, events: d.events.map(({ eventId, parentEventId, ...e }) => ({ ...e, event_id: eventId, parent_event_id: parentEventId })) } };
  assert.equal(parity(cli, { selected: d }), true);
  for (const change of [{ eventId: "different" }, { parentEventId: "different" }, { sourceBinding: "verified" },
    { interaction: { kind: "sql" } }, { exception: { exceptionType: "Error" } }]) {
    assert.equal(parity(cli, { selected: { ...d, events: [{ ...enter, ...change }, express] } }), false);
  }
  for (const change of [{ frameId: "frame" }, { parentFrameId: "parent" }, { asyncParentFrameId: "async" },
    { asyncParentEventId: "parent" }, { line: 4 }, { depth: 0 }, { monotonicNs: "2" },
    { gap: { reason: "queue_full" } }, { bindings: [{ name: "x" }] }, { navigation: { next: { state: "boundary" } } },
    { fieldTruncations: [{ field: "symbol", originalBytes: "100", representation: "truncated" }] }]) {
    assert.equal(parity(cli, { selected: { ...d, events: [{ ...enter, ...change }, express] } }), false);
  }
  const cliEvent = { ...enter, frame_id: "frame", monotonic_ns: "99", parent_frame_id: "parent", async_parent_frame_id: "async",
    field_truncations: [{ field: "symbol", original_bytes: "100", representation: "truncated" }] };
  const apiEvent = { ...enter, frameId: "frame", monotonicNs: "99", parentFrameId: "parent", asyncParentFrameId: "async",
    fieldTruncations: [{ field: "symbol", originalBytes: "100", representation: "truncated" }] };
  assert.equal(parity({ selected: { ...d, events: [cliEvent] } }, { selected: { ...d, events: [apiEvent] } }), true);
  assert.equal(parity({}, {}), false);
  assert.equal(parity(cli, {}), false);
});

test("bounded summary withholds symbols, source, raw exceptions and identifiers", () => {
  const marker = "PRIVATE-CANARY-DO-NOT-PUBLISH";
  const d = detail(); d.events.push({ ...express, symbol: marker, source: { path: marker, excerpt: marker }, exception: { exceptionType: marker } });
  const result = boundedSummary({ stages: [], workload: { passed: false, rows: [] }, readback: { cli: { [marker]: d }, api: { [marker]: d } } });
  assert.equal(JSON.stringify(result).includes(marker), false);
  assert.equal(result.releaseAcceptance, false);
  assert.equal(result.result, "failed");
  assert.match(result.gaps.join(" "), /Concurrent/);
});

test("pagination retains every row and requests every continuation", async () => {
  const seen = [];
  const result = await pages(async (cursor) => { seen.push(cursor); return cursor ? { events: [2], next: null } : { events: [1], next: "more" }; },
    { rowsKey: "events", cursorKey: "next" });
  assert.deepEqual(result, [1, 2]); assert.deepEqual(seen, [null, "more"]);
});

test("pagination refuses malformed, repeated and over-bound evidence", async () => {
  const options = { rowsKey: "events", cursorKey: "next", maxRows: 2, maxPages: 2 };
  for (const [doc, reason] of [
    [{ events: [], next: "same" }, "readback_empty_continuation"],
    [{ events: [], next: 7 }, "readback_cursor_schema"],
    [{ events: [], next: undefined }, "readback_cursor_schema"],
    [{ events: [1, 2, 3], next: null }, "readback_row_bound"],
    [{ next: null }, "readback_page_schema"],
  ]) {
    await assert.rejects(pages(async () => doc, options), { message: reason });
  }
  for (const [lastCursor, reason] of [["a", "readback_repeated_cursor"], ["b", "readback_page_bound"]]) {
    const requested = [];
    await assert.rejects(pages(async (cursor) => {
      requested.push(cursor);
      return cursor === null ? { events: [1], next: "a" } : { events: [2], next: lastCursor };
    }, options), { message: reason });
    assert.deepEqual(requested, [null, "a"]);
  }
});

test("duplicate or reversed event pages cannot look like full readback", () => {
  assert.deepEqual(validateEvents([{ sequence: "1" }, { sequence: "2" }]), [{ sequence: "1" }, { sequence: "2" }]);
  for (const events of [[{ sequence: "1" }, { sequence: "1" }], [{ sequence: "2" }, { sequence: "1" }],
    [{ sequence: 1 }], [{ sequence: "bad" }]]) assert.throws(() => validateEvents(events));
});

test("matching capture evidence cannot pass when a required phase was unreached", () => {
  const d = detail();
  const report = boundedSummary({ stages: [], workload: { passed: true, rows: [] }, readback: { cli: { selected: d }, api: { selected: d } } });
  assert.equal(report.result, "failed"); assert.equal(report.campaignComplete, false);
});

test("public summary rebuilds counts and rejects private fields in all external projections", () => {
  const marker = "PRIVATE-CANARY-DO-NOT-PUBLISH";
  const validStage = { name: "installed:app_shutdown", status: "passed", exitCode: 0, signal: null };
  const validRow = { id: scenario.id, passed: true, baselineRequests: 1, instrumentedRequests: 1,
    instrumentedResponses: 1, instrumentedTransportFailures: 0 };
  const good = { stages: [validStage], workload: { passed: false, rows: [validRow] }, analyzer: { status: "complete", linkedCatalogRequested: true } };
  const result = boundedSummary(good);
  assert.equal(result.projectionValid, true);
  assert.deepEqual(result.stages, { passed: 1, failed: 0, unreached: 0 });
  assert.deepEqual(result.workload, { scenarios: 1, passedScenarios: 1, passed: false });
  for (const changed of [
    { ...good, stages: [{ ...validStage, extra: marker }] },
    { ...good, stages: [{ ...validStage, name: marker }] },
    { ...good, stages: [{ ...validStage, signal: marker }] },
    { ...good, analyzer: { status: "complete", linkedCatalogRequested: true, error: marker } },
    { ...good, workload: { passed: false, rows: [{ ...validRow, id: marker }] } },
    { ...good, workload: { passed: false, rows: [{ ...validRow, instrumentedRequests: marker }] } },
  ]) {
    const projected = boundedSummary(changed);
    assert.equal(projected.projectionValid, false);
    assert.equal(projected.result, "failed");
    assert.equal(JSON.stringify(projected).includes(marker), false);
  }
});

test("scenario progress cannot reach stdout on success or rejection", () => {
  const moduleUrl = new URL("./installed-output.mjs", import.meta.url).href;
  const script = `import { withoutProgressOutput } from ${JSON.stringify(moduleUrl)};
    for (const fail of [false, true]) {
      try { await withoutProgressOutput(async () => { console.log('PRIVATE-FINGERPRINT'); if (fail) throw Error('PRIVATE-ERROR'); }); }
      catch { console.log('failed'); }
    }
    console.log('done');`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(child.status, 0);
  assert.equal(child.stdout, "failed\ndone\n");
  assert.equal(child.stderr, "");
});

test("empty continuation is rejected even when the next page would terminate", async () => {
  let calls = 0;
  await assert.rejects(pages(async () => {
    calls++;
    return calls === 1 ? { events: [1], next: "a" } : calls === 2 ? { events: [], next: "b" } : { events: [], next: null };
  }, { rowsKey: "events", cursorKey: "next" }), /readback_empty_continuation/);
  assert.equal(calls, 2);
});

test("owned Docker cleanup never pre-deletes names and requires successful absence queries", () => {
  const id = "a".repeat(64), owned = [], calls = [];
  const docker = (args) => { calls.push(args); return { status: 0, stdout: args[0] === "create" ? id : "" }; };
  assert.equal(createOwned(docker, owned, "xtrace-camp-node-case", ["image"], "linux/amd64"), id);
  assert.deepEqual(owned, [id]);
  assert.deepEqual(calls.map((args) => args[0]), ["create", "start"]);
  assert.equal(removeOwned(docker, "container", id), true);
  assert.equal(calls[2].at(-1), id);
  assert.equal(removeOwned(() => ({ status: 1, stdout: "" }), "container", id), false);
  assert.equal(removeOwned((args) => ({ status: 0, stdout: args[0] === "network" && args[1] === "ls" ? id : "" }), "network", id), false);
  assert.equal(removeOwned(docker, "container", "xtrace-camp-node-case"), false);
  const partial = [];
  assert.throws(() => createOwned((args) => {
    if (args[0] === "start") throw Error("start failed");
    return { status: 0, stdout: id };
  }, partial, "xtrace-camp-node-case", ["image"], "linux/amd64"));
  assert.deepEqual(partial, [id]);
  assert.throws(() => createOwned(() => { throw Error("name collision"); }, [], "xtrace-camp-node-case", ["image"], "linux/amd64"));
});

test("capture notice and unavailable stderr cannot be mistaken for absence", () => {
  assert.equal(captureNoticeOutcome(Buffer.from('{"kind":"capture_incomplete","code":"XTR-RUN-CAPTURE-INCOMPLETE"}\n')), "present");
  assert.equal(captureNoticeOutcome(Buffer.from("ordinary stderr\n")), "absent");
  assert.equal(captureNoticeOutcome(null), "unavailable");
  assert.equal(captureNoticeOutcome(Buffer.alloc(32 * 1024 * 1024 + 1)), "unavailable");
});

test("a failed cleanup or notice check prevents an otherwise complete probe from passing", () => {
  const names = ["baseline:network_admitted", "instrumented:network_admitted", "baseline:application_readiness", "baseline:scenario_workload", "baseline:driver_finish", "baseline:cleanup",
    "instrumented:application_readiness", "instrumented:scenario_workload", "instrumented:driver_finish", "instrumented:cleanup",
    "same_run_inputs", "same_installed_payload", "baseline-installed:app_shutdown", "installed:app_shutdown",
    "installed:capture_notice_check", "installed:persisted_readback", "installed:installed_analyzer_result"];
  const stages = names.map((name) => ({ name, status: "passed" }));
  const rows = ORDINARY_IDS.map((id) => ({ id, passed: true, baselineRequests: 1, instrumentedRequests: 1,
    instrumentedResponses: 1, instrumentedTransportFailures: 0 }));
  const records = Object.fromEntries(rows.map((_, index) => [String(index), detail()]));
  const input = { stages, workload: { passed: true, rows }, readback: { cli: records, api: records },
    analyzer: { status: "complete", linkedCatalogRequested: true } };
  assert.equal(boundedSummary(input).result, "passed");
  for (const name of ["baseline:cleanup", "instrumented:cleanup", "installed:capture_notice_check"]) {
    const changed = stages.map((row) => row.name === name ? { ...row, status: "failed" } : row);
    assert.equal(boundedSummary({ ...input, stages: changed }).result, "failed");
  }
});

test("public entry point keeps child streams private on preflight failure", () => {
  const directory = fs.mkdtempSync(path.join(os.homedir(), "xtrace-output-test-"));
  fs.chmodSync(directory, 0o700);
  const config = path.join(directory, "input.json");
  fs.writeFileSync(config, '{"private":"PRIVATE-CLI-CANARY"}', { mode: 0o600 });
  try {
    const executable = fileURLToPath(new URL("./installed-public.mjs", import.meta.url));
    const child = spawnSync(process.execPath, [executable, config, directory], { encoding: "utf8" });
    assert.equal(child.status, 1);
    assert.equal(child.stderr, "");
    assert.equal(child.stdout.includes("PRIVATE-CLI-CANARY"), false);
    assert.deepEqual(JSON.parse(child.stdout), { schemaVersion: 1, kind: "directus_installed_ordinary_development", result: "failed",
      releaseAcceptance: false, campaignComplete: false, fullQualification: "incomplete", deniedAddressScenario: "unreached", projectionValid: false });
    assert.equal(fs.statSync(path.join(directory, "installed.stdout.private")).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.join(directory, "installed.stderr.private")).mode & 0o777, 0o600);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test("public output is rebuilt from bounded primitives and refuses mixed progress", () => {
  const privateValue = { schemaVersion: 1, kind: "directus_installed_ordinary_development", result: "passed",
    releaseAcceptance: false, campaignComplete: false, projectionValid: true, private: "PRIVATE-CANARY",
    capture: { recordings: 2 }, workload: { scenarios: 8, passedScenarios: 8 },
    requestCoverage: { scope: "ordinary-subset", responses: 2, missingRecordingsLowerBound: 0, individuallyAttributed: 0 }, readback: { parity: true } };
  assert.equal(projectPublicOutput(JSON.stringify({ ...privateValue, readback: { parity: false } }), 0).result, "failed");
  const result = projectPublicOutput(JSON.stringify(privateValue), 0);
  assert.equal(result.result, "passed");
  assert.equal(JSON.stringify(result).includes("PRIVATE-CANARY"), false);
  assert.equal(projectPublicOutput("PRIVATE-CANARY\n" + JSON.stringify(privateValue), 0).result, "failed");
  assert.equal(projectPublicOutput(JSON.stringify(privateValue), 1).result, "failed");
  privateValue.capture.recordings = "PRIVATE-CANARY";
  assert.equal(projectPublicOutput(JSON.stringify(privateValue), 0).projectionValid, false);
});

test("ordinary scope uses exactly the ordered login and CRUD allowlist", () => {
  const input = [...ORDINARY_IDS].reverse().map((id) => ({ id }));
  assert.deepEqual(ordinaryScenarios(input).map(({ id }) => id), ORDINARY_IDS);
  assert.throws(() => ordinaryScenarios([...input, { id: "other" }]), /ordinary_scenario_inventory/);
  assert.throws(() => ordinaryScenarios(input.slice(1)), /ordinary_scenario_inventory/);
  assert.equal(ordinaryRequest("POST", "/auth/login"), true);
  assert.equal(ordinaryRequest("PATCH", "/items/xtrace_campaign_items/123"), true);
  assert.equal(ordinaryRequest("PUT", "/items/xtrace_campaign_items/123"), false);
  assert.equal(ordinaryRequest("GET", "/items/xtrace_campaign_items/123?other=1"), false);
  assert.equal(ordinaryRequest("GET", "/unknown"), false);
  const result = projectPublicOutput("", 1);
  assert.equal(result.fullQualification, "incomplete");
  assert.equal(result.deniedAddressScenario, "unreached");
  assert.equal(result.result, "failed");
});
