import { ORDINARY_IDS } from "./installed-ordinary-scope.mjs";
// Pure projections for the installed development lane. Never assign a recording
// to an individual concurrent request from timestamps, order, or matching status.
import { canonicalJson } from "../../lib/canonical.mjs";

export function compareWorkload(baseline, instrumented, scenarioIds) {
  const rows = scenarioIds.map((id) => {
    const a = baseline?.scenarios?.filter((s) => s.id === id) || [];
    const b = instrumented?.scenarios?.filter((s) => s.id === id) || [];
    return { id, passed: a.length === 1 && b.length === 1 && a[0].result === "passed" && b[0].result === "passed"
      && /^[a-f0-9]{64}$/.test(a[0].semanticEffectFingerprint || "")
      && a[0].semanticEffectFingerprint === b[0].semanticEffectFingerprint,
    baselineRequests: a[0]?.requests?.length ?? 0, instrumentedRequests: b[0]?.requests?.length ?? 0,
    instrumentedResponses: b[0]?.requests?.filter((r) => Number.isInteger(r.status) && r.status >= 100 && r.status <= 599).length ?? 0,
    instrumentedTransportFailures: b[0]?.requests?.filter((r) => r.status === 0).length ?? 0 };
  });
  return { passed: rows.length > 0 && rows.every((r) => r.passed)
    && baseline?.scenarios?.length === rows.length && instrumented?.scenarios?.length === rows.length, rows };
}

export function inspectCapture(details) {
  const rows = Object.values(details).map((d) => {
    const events = d.events || [];
    const enters = events.filter((e) => String(e.kind).endsWith(":frame_enter"));
    const roots = enters.filter((e) => e.symbol === "node:http.Server.request");
    const ids = new Set(events.map((e) => e.eventId ?? e.event_id).filter(Boolean));
    const parent = (e) => e.parentEventId ?? e.parent_event_id;
    const parents = (e) => [parent(e), e.asyncParentEventId ?? e.async_parent_event_id].filter((id) => id != null);
    const sourced = enters.filter((e) => e.source?.status === "matched" && e.source?.excerpt
      && Number.isInteger(e.source?.startLine) && e.source.startLine > 0
      && ["verified", "observed_unattested"].includes(e.sourceBinding ?? e.source_binding));
    const interactions = events.filter((e) => e.interaction != null);
    return { complete: d.completion === "complete", rootCount: roots.length,
      rootHasNoParent: roots.length === 1 && parents(roots[0]).length === 0,
      outcomeObserved: d.outcome?.kind === "responded" && Number.isInteger(d.outcome?.httpStatus),
      httpStatus: Number.isInteger(d.outcome?.httpStatus) ? d.outcome.httpStatus : null,
      expressFrames: enters.filter((e) => String(e.symbol).startsWith("express.")).length,
      // Count affected events once, even when both recorded relationships are unresolved.
      orphanParents: events.filter((e) => parents(e).some((id) => !ids.has(id))).length,
      sourcedFrames: sourced.length, interactions: interactions.length,
      linkedInteractions: interactions.filter((e) => parent(e) && ids.has(parent(e))).length,
      limitations: Array.isArray(d.limitations) ? d.limitations.length : null };
  });
  return { recordings: rows.length, complete: rows.filter((r) => r.complete).length,
    oneRoot: rows.filter((r) => r.rootCount === 1 && r.rootHasNoParent).length,
    outcomes: rows.filter((r) => r.outcomeObserved).length,
    expressRecordings: rows.filter((r) => r.expressFrames > 0).length,
    sourcedRecordings: rows.filter((r) => r.sourcedFrames > 0).length,
    interactions: rows.reduce((n, r) => n + r.interactions, 0),
    linkedInteractions: rows.reduce((n, r) => n + r.linkedInteractions, 0),
    orphanParents: rows.reduce((n, r) => n + r.orphanParents, 0), rows };
}

// Compare persisted event evidence privately. The two transports spell some keys
// differently but share the same nested source, bindings, gap and navigation types.
export function commonEvent(e) {
  return { sequence: e.sequence, kind: e.kind, symbol: e.symbol ?? null,
    eventId: e.eventId ?? e.event_id ?? null, parentEventId: e.parentEventId ?? e.parent_event_id ?? null,
    asyncParentEventId: e.asyncParentEventId ?? e.async_parent_event_id ?? null,
    frameId: e.frameId ?? e.frame_id ?? null, parentFrameId: e.parentFrameId ?? e.parent_frame_id ?? null,
    asyncParentFrameId: e.asyncParentFrameId ?? e.async_parent_frame_id ?? null,
    depth: e.depth ?? null, line: e.line ?? null, monotonicNs: e.monotonicNs ?? e.monotonic_ns ?? null,
    bindings: e.bindings, gap: e.gap ?? null, navigation: e.navigation,
    fieldTruncations: (e.fieldTruncations ?? e.field_truncations)?.map((item) => ({
      field: item.field, originalBytes: item.originalBytes ?? item.original_bytes, representation: item.representation,
    })),
    interaction: e.interaction ?? null, exception: e.exception ?? null,
    sourceBinding: e.sourceBinding ?? e.source_binding ?? null, source: e.source ?? null };
}

export function parity(cli, api) {
  const keys = Object.keys(cli).sort();
  return keys.length > 0 && canonicalJson(keys) === canonicalJson(Object.keys(api).sort())
    && keys.every((id) => cli[id].completion === api[id].completion
      && canonicalJson(cli[id].outcome) === canonicalJson(api[id].outcome)
      && canonicalJson(cli[id].events.map(commonEvent)) === canonicalJson(api[id].events.map(commonEvent)));
}

const STAGE = /^(?:(?:baseline|instrumented):(?:database_readiness|network_admitted|application_readiness|scenario_workload|driver_finish|cleanup|leg)|same_run_inputs|same_installed_payload|(?:baseline-installed|installed):(?:package-verifier|extract|install|verify-install|runtime-packages|version|bootstrap|scan|installed_analyzer_result|app_spawn|app_shutdown|capture_notice_check|persisted_readback|application_early_exit|driver|finish|(?:init|list|show|catalog-reconciliation)-[0-9]+))$/;
const count = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 1_000_000;

function publicStages(stages) {
  if (!Array.isArray(stages) || stages.length > 10000) return null;
  const counts = { passed: 0, failed: 0, unreached: 0 };
  for (const row of stages) {
    if (!row || typeof row !== "object" || Array.isArray(row)
      || Object.keys(row).some((key) => !["name", "status", "exitCode", "signal"].includes(key))
      || typeof row.name !== "string" || row.name.length > 100 || !STAGE.test(row.name)
      || !Object.hasOwn(counts, row.status)
      || ("exitCode" in row && row.exitCode !== null && (!Number.isInteger(row.exitCode) || row.exitCode < 0 || row.exitCode > 255))
      || ("signal" in row && ![null, "SIGTERM", "SIGKILL", "spawn-error"].includes(row.signal))) return null;
    counts[row.status]++;
  }
  return counts;
}

function publicWorkload(workload, expected) {
  if (!workload || typeof workload !== "object" || Object.keys(workload).some((key) => !["passed", "rows"].includes(key))
    || typeof workload.passed !== "boolean" || !Array.isArray(workload.rows) || workload.rows.length > expected.size) return null;
  const seen = new Set();
  for (const row of workload.rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)
      || Object.keys(row).some((key) => !["id", "passed", "baselineRequests", "instrumentedRequests", "instrumentedResponses", "instrumentedTransportFailures"].includes(key))
      || !expected.has(row.id) || seen.has(row.id) || typeof row.passed !== "boolean"
      || ![row.baselineRequests, row.instrumentedRequests, row.instrumentedResponses, row.instrumentedTransportFailures].every(count)) return null;
    seen.add(row.id);
  }
  return { scenarios: workload.rows.length, passedScenarios: workload.rows.filter((row) => row.passed).length,
    passed: workload.passed && workload.rows.length === expected.size && workload.rows.every((row) => row.passed) };
}

function publicAnalyzer(analyzer) {
  if (analyzer === undefined || analyzer === null) return { status: "unreached" };
  if (typeof analyzer !== "object" || Array.isArray(analyzer)
    || Object.keys(analyzer).some((key) => !["status", "linkedCatalogRequested"].includes(key))
    || !["complete", "incomplete", "unreached"].includes(analyzer.status)
    || ("linkedCatalogRequested" in analyzer && typeof analyzer.linkedCatalogRequested !== "boolean")
    || (analyzer.status === "complete" && analyzer.linkedCatalogRequested !== true)
    || (analyzer.status === "incomplete" && analyzer.linkedCatalogRequested !== false)) return null;
  return { status: analyzer.status, ...(analyzer.status !== "unreached" ? { linkedCatalogRequested: analyzer.linkedCatalogRequested } : {}) };
}

export function boundedSummary({ stages, workload, readback, analyzer }) {
  const expected = new Set(ORDINARY_IDS);
  const stageCounts = publicStages(stages), workloadCounts = publicWorkload(workload, expected), analyzerStatus = publicAnalyzer(analyzer);
  const safe = stageCounts !== null && workloadCounts !== null && analyzerStatus !== null;
  const capture = inspectCapture(readback?.api || {});
  // No source strings, symbols, identifiers, paths, body projections, or errors
  // enter this allowlisted development receipt.
  const capturePassed = capture.recordings > 0 && capture.complete === capture.recordings
    && capture.oneRoot === capture.recordings && capture.outcomes === capture.recordings
    && capture.expressRecordings === capture.recordings && capture.orphanParents === 0;
  const requiredStages = ["baseline:network_admitted", "instrumented:network_admitted", "baseline:application_readiness", "baseline:scenario_workload", "baseline:driver_finish",
    "instrumented:application_readiness", "instrumented:scenario_workload", "instrumented:driver_finish", "baseline:cleanup", "instrumented:cleanup",
    "same_run_inputs", "same_installed_payload", "baseline-installed:app_shutdown",
    "installed:app_shutdown", "installed:capture_notice_check", "installed:persisted_readback", "installed:installed_analyzer_result"];
  const phasesPassed = stageCounts !== null && requiredStages.every((name) => stages.filter((s) => s.name === name && s.status === "passed").length === 1);
  const rows = workloadCounts ? workload.rows : [];
  const sentRequests = rows.reduce((n, r) => n + r.instrumentedRequests, 0);
  const responses = rows.reduce((n, r) => n + r.instrumentedResponses, 0);
  const transportFailures = rows.reduce((n, r) => n + r.instrumentedTransportFailures, 0);
  const countLowerBoundMet = responses > 0 && transportFailures === 0 && capture.recordings >= responses;
  return { schemaVersion: 1, kind: "directus_installed_ordinary_development", releaseAcceptance: false,
    campaignComplete: false,
    stages: stageCounts || { passed: 0, failed: 0, unreached: 0 },
    workload: workloadCounts || { scenarios: 0, passedScenarios: 0, passed: false },
    readback: { cli: Object.keys(readback?.cli || {}).length, api: Object.keys(readback?.api || {}).length,
      parity: readback ? parity(readback.cli, readback.api) : false },
    capture: { ...capture, rows: undefined }, analyzer: analyzerStatus || { status: "unreached" }, projectionValid: safe,
    requestCoverage: { scope: "ordinary-subset", sentRequests, responses, transportFailures,
      individuallyAttributed: 0, countLowerBoundMet,
      missingRecordingsLowerBound: Math.max(0, responses - capture.recordings),
      perRequestIsolation: "unverified" },
    result: safe && phasesPassed && workloadCounts.passed && countLowerBoundMet && capturePassed && readback && parity(readback.cli, readback.api)
      && stages.every((s) => s.status === "passed") ? "passed" : "failed",
    gaps: ["Development evidence only; no release acceptance or signature.",
      "Campaign-wide capture counts include readiness; no individual request or scenario attribution is claimed.",
      "Concurrent create/read request-to-recording isolation remains unverified.",
      "SQL and outbound interaction applicability must be reviewed against private events, not inferred from DB/dependency effects.",
      "Source coverage is measured; a matching frame range is not an active executed line.",
      "No capture-incomplete notice is not independent proof of a complete drain.",
      "Privacy canary probes, complete sink inventory, browser, TUI, restart, overhead and human sign-off remain unverified."] };
}
