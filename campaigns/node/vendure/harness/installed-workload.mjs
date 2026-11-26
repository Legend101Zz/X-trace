// Run the original Vendure scenarios once against the already-started owned server.
// The outer campaign owns both legs, the installed launch, the seed, and recording readback.
import fs from "node:fs";
import path from "node:path";
import { runScenarios } from "../../lib/harness.mjs";
import { vendureScenarios } from "./scenarios.mjs";

// The worker test sends two mutations and up to 60 original search polls. Its
// fingerprint intentionally retains fewer HTTP samples than the live transport.
const cases = [
  ["auth-anonymous-admin-denied", 1, 1], ["auth-invalid-login", 1, 1],
  ["auth-admin-login", 2, 2], ["product-create-read-db", 2, 2],
  ["product-validation-invalid-language", 1, 1], ["product-update-persists", 2, 2],
  ["shop-order-flow", 4, 4], ["worker-search-index-job", 3, 62],
  ["concurrent-writes-and-reads", 24, 24], ["product-delete-then-gone", 2, 2],
  ["error-malformed-and-unknown", 2, 2],
];

const kinds = { baseline: "uninstrumented_baseline_only", installed: "installed_vendure_ordinary_workload" };

function need(condition) {
  if (!condition) throw new Error("Vendure workload evidence mismatch");
}

export async function runOrdinaryVendureWorkload({ leg, ownedPort, sql, admin, outDir, privacySecrets = [] }) {
  need(Object.hasOwn(kinds, leg) && Number.isInteger(ownedPort) && ownedPort > 0 && ownedPort <= 65535);
  const baseUrl = "http://127.0.0.1:" + ownedPort;
  const counts = cases.map(([id]) => ({ id, attempted: 0, responsesRead: 0, refused: 0, failed: 0 }));
  const scenarios = vendureScenarios({ sql, admin });
  need(scenarios.length === cases.length && scenarios.every((s, i) => s.id === cases[i][0]));
  fs.mkdirSync(outDir, { mode: 0o700 }); // One private directory per invocation.
  const secrets = new Set();
  const statuses = {};
  function witness(value) {
    if (typeof value === "string" && value.length >= 8) {
      need(Buffer.byteLength(value) <= 131072 && secrets.size < 2048);
      secrets.add(value);
    } else if (Array.isArray(value)) value.forEach(witness);
    else if (value && typeof value === "object") Object.values(value).forEach(witness);
  }
  witness([admin.identifier, admin.password, ...privacySecrets]);
  let current;
  const observed = scenarios.map((scenario, i) => ({
    ...scenario,
    async run(context) {
      current = counts[i];
      try {
        return await scenario.run(context);
      } finally {
        current = undefined;
      }
    },
  }));
  async function request(address, options) {
    const row = current; // Keep concurrent completions with the initiating case.
    need(row);
    row.attempted++;
    witness(options.headers?.authorization);
    if (typeof options.body === "string") {
      witness(options.body);
      let body;
      try { body = JSON.parse(options.body); } catch {}
      if (body) { witness(body.query); witness(body.variables); }
    }
    const allowed = (options.method === "POST" &&
        (address === baseUrl + "/shop-api" || address === baseUrl + "/admin-api")) ||
      (options.method === "GET" && address === baseUrl + "/xtrace-no-such-route");
    if (!allowed) {
      row.refused++;
      throw new Error("Unexpected Vendure workload operation");
    }
    try {
      const response = await fetch(address, { ...options, redirect: "error" });
      witness(response.headers.get("vendure-auth-token"));
      return {
        status: response.status, headers: response.headers,
        async text() {
          try {
            const text = await response.text();
            row.responsesRead++;
            statuses[response.status] = (statuses[response.status] || 0) + 1;
            return text;
          } catch (error) {
            row.failed++;
            throw error;
          }
        },
      };
    } catch (error) {
      row.failed++;
      throw error;
    }
  }
  const log = fs.openSync(path.join(outDir, "scenario-output.private.log"), "wx", 0o600);
  let summary;
  try {
    summary = await runScenarios({ project: "vendure", kind: kinds[leg], baseUrl, outDir,
      scenarios: observed, request, log: message => fs.writeSync(log, message + "\n") });
  } finally { fs.closeSync(log); }
  const rows = summary.scenarios.map((row, i) => {
    const [id, minimum, maximum] = cases[i];
    const transport = counts[i];
    const passed = row.id === id && row.result === "passed" && row.failedAssertions?.length === 0 &&
      typeof row.semanticEffectFingerprint === "string" && /^[0-9a-f]{64}$/.test(row.semanticEffectFingerprint) &&
      transport.attempted >= minimum && transport.attempted <= maximum &&
      transport.responsesRead === transport.attempted && !transport.refused && !transport.failed;
    return { ...transport, passed, fingerprint: passed ? row.semanticEffectFingerprint : null };
  });
  const passed = summary.result === "passed" && rows.length === cases.length && rows.every(row => row.passed);
  const receipt = { leg, passed, rows };
  fs.writeFileSync(path.join(outDir, "workload.private.json"), JSON.stringify(receipt) + "\n",
    { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(outDir, "privacy-witness.private.json"), JSON.stringify({
    values: [...secrets], statuses,
  }) + "\n", { flag: "wx", mode: 0o600 });
  return receipt;
}

// Both arguments come directly from the two awaited calls. No request or database
// content, per-request fingerprint, or raw per-scenario artifact goes into this projection.
export function compareVendureWorkloads(baseline, installed) {
  need(baseline.leg === "baseline" && installed.leg === "installed");
  need(baseline.rows.length === cases.length && installed.rows.length === cases.length);
  const rows = cases.map(([id], i) => {
    const left = baseline.rows[i], right = installed.rows[i];
    need(left.id === id && right.id === id);
    const parity = left.passed && right.passed && left.fingerprint === right.fingerprint;
    return { id, baselinePassed: left.passed, installedPassed: right.passed,
      baselineResponses: left.responsesRead, installedResponses: right.responsesRead, parity };
  });
  return { releaseAcceptance: false, parity: baseline.passed && installed.passed && rows.every(row => row.parity), rows };
}
