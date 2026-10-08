#!/usr/bin/env node
// Splits <baseline-dir>/scenarios.json into one evidence file per scenario plus an index
// holding the {name, baseline:{path,sha256}, semanticEffectFingerprint} rows that the
// later CAMPAIGN-* receipt attestation (tools/release/check_ledger.py) needs.
//   node export-scenarios.mjs <baseline-dir>
import fs from "node:fs";
import path from "node:path";
import { sha256Hex } from "./canonical.mjs";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: export-scenarios.mjs <baseline-dir>");
  process.exit(2);
}
const doc = JSON.parse(fs.readFileSync(path.join(dir, "scenarios.json"), "utf8"));
const out = path.join(dir, "scenario-evidence");
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
const rows = doc.scenarios.map((s) => {
  const body = JSON.stringify({ project: doc.project, kind: doc.kind, ...s }, null, 2) + "\n";
  const rel = `scenario-evidence/${s.id}.json`;
  fs.writeFileSync(path.join(dir, rel), body, { mode: 0o600 });
  return { name: s.id, baseline: { path: rel, sha256: sha256Hex(body) }, semanticEffectFingerprint: s.semanticEffectFingerprint };
});
fs.writeFileSync(path.join(dir, "scenario-index.json"), JSON.stringify({ project: doc.project, scenarios: rows }, null, 2) + "\n", { mode: 0o600 });
console.log(JSON.stringify({ project: doc.project, exported: rows.length }));
