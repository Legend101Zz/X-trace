import { ORDINARY_IDS } from "./installed-ordinary-scope.mjs";

/** The shared scenario runner prints fingerprint fragments; this lane keeps them private. */
export async function withoutProgressOutput(run) {
  const original = console.log;
  console.log = () => {};
  try { return await run(); }
  finally { console.log = original; }
}

function envelope() {
  return { schemaVersion: 1, kind: "directus_installed_ordinary_development",
    releaseAcceptance: false, campaignComplete: false,
    fullQualification: "incomplete", deniedAddressScenario: "unreached" };
}

/** Rebuild the only public envelope; never echo private output or arbitrary properties. */
export function projectPublicOutput(raw, exitCode) {
  const expected = envelope();
  const failed = () => ({ ...expected, result: "failed", projectionValid: false });
  try {
    if (typeof raw !== "string" || Buffer.byteLength(raw) > 1024 * 1024 || !Number.isInteger(exitCode)) return failed();
    const value = JSON.parse(raw);
    const values = [value.capture?.recordings, value.workload?.scenarios, value.workload?.passedScenarios,
      value.requestCoverage?.responses, value.requestCoverage?.missingRecordingsLowerBound];
    if (value.schemaVersion !== 1 || value.kind !== expected.kind || value.releaseAcceptance !== false
      || value.campaignComplete !== false || value.projectionValid !== true || !["passed", "failed"].includes(value.result)
      || !values.every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 12_000_000)
      || (value.requestCoverage?.scope !== "ordinary-subset" || values[1] > ORDINARY_IDS.length
        || values[2] > values[1] || (value.result === "passed" && values[2] !== ORDINARY_IDS.length))
      || value.requestCoverage?.individuallyAttributed !== 0 || typeof value.readback?.parity !== "boolean") return failed();
    if (value.result === "passed" && (value.readback.parity !== true || values[3] === 0
      || values[0] < values[3] || values[4] !== 0)) return failed();
    return { ...expected, result: exitCode === 0 && value.result === "passed" ? "passed" : "failed", projectionValid: true, recordings: values[0], scenarios: values[1],
      passedScenarios: values[2], responses: values[3], missingRecordingsLowerBound: values[4],
      individuallyAttributed: 0, readbackParity: value.readback.parity };
  } catch { return failed(); }
}
