// Scenario runner: executes scenarios in order against a live app, computes the
// semanticEffectFingerprint of each (requests + normalized bodies + DB effect) and
// writes private receipts. Never prints credentials.
import fs from "node:fs";
import path from "node:path";
import { canonicalJson, sha256Hex, Normalizer } from "./canonical.mjs";
import { Recorder } from "./http.mjs";

export async function runScenarios({ project, baseUrl, outDir, scenarios, ctxExtra = {} }) {
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const results = [];
  let allPassed = true;
  for (const sc of scenarios) {
    const norm = new Normalizer();
    const rec = new Recorder(baseUrl, norm);
    const ctx = { http: rec, norm, ...ctxExtra };
    const t0 = performance.now();
    let result;
    try {
      const out = await sc.run(ctx);
      // out: { db?: object, assertions: {name: boolean}, facts?: object }
      const failed = Object.entries(out.assertions || {}).filter(([, ok]) => !ok).map(([k]) => k);
      if (!Object.keys(out.assertions || {}).length) failed.push("no-assertions");
      const calls = rec.take();
      const db = out.db === undefined ? null : norm.value(out.db);
      const effect = {
        scenario: sc.id,
        requests: calls.map((c) => ({ label: c.label, method: c.method, route: c.route, status: c.status, body: c.normalizedBody ?? null })),
        db,
        assertions: Object.fromEntries(Object.entries(out.assertions || {}).sort()),
      };
      result = {
        id: sc.id,
        name: sc.name,
        kind: sc.kind,
        result: failed.length ? "failed" : "passed",
        failedAssertions: failed,
        requests: calls.map(({ normalizedBody, ...c }) => c),
        dbEffectDigest: db === null ? null : sha256Hex(canonicalJson(db)),
        semanticEffectFingerprint: sha256Hex(canonicalJson(effect)),
        durationMs: Math.round(performance.now() - t0),
      };
      if (failed.length) result.requestsDebug = calls.map((c) => ({ label: c.label, status: c.status, body: c.normalizedBody }));
      if (failed.length) allPassed = false;
    } catch (e) {
      allPassed = false;
      result = { id: sc.id, name: sc.name, kind: sc.kind, result: "error", error: String(e && e.message).slice(0, 500), requests: rec.take().map(({ normalizedBody, ...c }) => c), durationMs: Math.round(performance.now() - t0) };
    }
    results.push(result);
    console.log(`  [${result.result}] ${sc.id} ${result.semanticEffectFingerprint ? result.semanticEffectFingerprint.slice(0, 12) : ""} ${result.durationMs}ms`);
  }
  const summary = {
    schemaVersion: 1,
    project,
    kind: "uninstrumented_baseline_only",
    releaseAcceptance: false,
    result: allPassed ? "passed" : "failed",
    scenarioCount: results.length,
    scenarios: results,
  };
  fs.writeFileSync(path.join(outDir, "scenarios.json"), JSON.stringify(summary, null, 2) + "\n", { mode: 0o600 });
  return summary;
}

export function compareRuns(dirs) {
  const runs = dirs.map((d) => JSON.parse(fs.readFileSync(path.join(d, "scenarios.json"), "utf8")));
  const ids = runs[0].scenarios.map((s) => s.id);
  const rows = ids.map((id) => {
    const fps = runs.map((r) => r.scenarios.find((s) => s.id === id)?.semanticEffectFingerprint ?? null);
    return { id, fingerprint: fps[0], stable: fps.every((f) => f && f === fps[0]), all: fps };
  });
  return { stable: rows.every((r) => r.stable), rows };
}
