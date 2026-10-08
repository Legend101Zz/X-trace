#!/usr/bin/env node
// Static self-check of every campaigns/node/<project>/campaign.json against the harness:
// full 40-hex SHA, https canonical URL, stable tag, >=5 scenarios, scenario ids equal to
// the ids the harness defines, license sha256 shape.   node campaigns/node/lib/check-campaign.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const base = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
let failures = 0;
const fail = (p, m) => {
  failures++;
  console.error(`FAIL ${p}: ${m}`);
};

for (const [project, factory, exportName] of [
  ["directus", "directus/harness/scenarios.mjs", "directusScenarios"],
  ["medusa", "medusa/harness/scenarios.mjs", "medusaScenarios"],
  ["vendure", "vendure/harness/scenarios.mjs", "vendureScenarios"],
]) {
  const c = JSON.parse(fs.readFileSync(path.join(base, project, "campaign.json"), "utf8"));
  if (c.project !== project) fail(project, "project mismatch");
  if (!c.upstream.canonicalUrl.startsWith("https://")) fail(project, "canonicalUrl must be https");
  if (!HEX40.test(c.upstream.sha)) fail(project, "upstream sha must be 40-hex");
  if (!c.upstream.stableTag) fail(project, "stable tag missing");
  if (c.starter?.sha && !HEX40.test(c.starter.sha)) fail(project, "starter sha must be 40-hex");
  if (!HEX64.test(c.license.sha256)) fail(project, "license sha256 must be 64-hex");
  const mod = await import(path.join(base, factory));
  const ids = mod[exportName]({ db: {}, admin: {}, sql: () => [] }).map((s) => s.id);
  const declared = c.scenarios.map((s) => s.id);
  if (declared.length < 5) fail(project, "needs >=5 scenarios");
  if (JSON.stringify(ids) !== JSON.stringify(declared)) fail(project, `scenario ids differ: harness=${ids} campaign=${declared}`);
  for (const s of c.scenarios) if (!s.expectedSeams?.length) fail(project, `${s.id}: expectedSeams missing`);
  console.log(`ok ${project}: ${declared.length} scenarios, upstream ${c.upstream.stableTag} ${c.upstream.sha.slice(0, 12)}`);
}
process.exit(failures ? 1 : 0);
