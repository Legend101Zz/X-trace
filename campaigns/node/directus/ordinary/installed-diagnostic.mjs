import { ORDINARY_IDS } from "./installed-ordinary-scope.mjs";

// Status labels and aggregate counts are the only ordinary-run diagnostics that leave the runner.
const phases = new Set(["not-started", "source-check", "leg-setup", "collision-check", "network-create",
  "network-admission", "database-container", "application-container", "member-admission", "database-routes",
  "application-routes", "write-config", "database-start", "database-readiness", "driver-start",
  "application-readiness", "scenario-workload", "scenario-evidence", "driver-finish", "cleanup"]);
const reasons = new Set(["unclassified", "unsuccessful-result", "same_run_input_drift", "network_already_exists",
  "container_already_exists", "network_identity", "isolated_network", "container_create_unconfirmed",
  "container_identity", "isolated_membership", "isolated_attachment", "local_subnet", "ipv4_route_header",
  "local_ipv4_routes", "ipv6_route_format", "local_ipv6_routes", "postgres_readiness_deadline",
  "app_container_exited", "application_readiness_deadline", "finish-container-unavailable"]);
const driverStages = new Set(["package-verifier", "extract", "install", "verify-install", "runtime-packages",
  "version", "bootstrap", "init", "scan", "installed_analyzer_result", "app_spawn", "app_shutdown",
  "capture_notice_check", "persisted_readback", "application_early_exit", "driver", "finish",
  "list", "show", "catalog-reconciliation", "unclassified"]);

export function recordHostFailure(note, reason) {
  if (note.failure === null) note.failure = { phase: note.phase, reason: reasons.has(reason) ? reason : "unclassified" };
}

// Treat the unavailable container as an unmet prerequisite. The finish command was never executed.
export function finishOrdinaryDriver(note, running, finish) {
  note.phase = "driver-finish";
  try {
    if (!running()) {
      recordHostFailure(note, "finish-container-unavailable");
      return { name: "driver_finish", status: "unreached" };
    }
  } catch (error) {
    recordHostFailure(note, error?.message);
    return { name: "driver_finish", status: "unreached" };
  }
  try {
    if (finish().status === 0) return { name: "driver_finish", status: "passed" };
    recordHostFailure(note, "unsuccessful-result");
  } catch (error) {
    recordHostFailure(note, error?.message);
  }
  return { name: "driver_finish", status: "failed" };
}

const payloadDigests = ["archiveSha256", "manifestSha256", "cliSha256", "nodePackManifestSha256", "analyzerSha256", "nodeBinarySha256"];
const payloadFields = ["sourceCommit", "platform", "nodeVersion", ...payloadDigests];

export function sameInstalledPayload(baseline, instrumented, pins) {
  const verifies = (report, mode) => {
    if (report?.mode !== mode || !Array.isArray(report.stages)) return false;
    for (const name of ["package-verifier", "extract", "install", "verify-install"]) {
      const attempts = report.stages.filter(row => row?.name === name);
      if (attempts.length !== 1 || attempts[0].status !== "passed" || attempts[0].exitCode !== 0) return false;
    }
    const id = report.identity;
    return id && typeof id === "object" && !Array.isArray(id)
      && Object.keys(id).length === payloadFields.length && payloadFields.every(key => Object.hasOwn(id, key))
      && typeof id.sourceCommit === "string" && /^[0-9a-f]{40}$/.test(id.sourceCommit)
      && ["linux-x86_64", "linux-aarch64-dev"].includes(id.platform)
      && typeof id.nodeVersion === "string" && /^v[0-9]+\.[0-9]+\.[0-9]+$/.test(id.nodeVersion)
      && payloadDigests.every(key => typeof id[key] === "string" && /^[0-9a-f]{64}$/.test(id[key]))
      && id.sourceCommit === pins.sourceCommit && id.archiveSha256 === pins.archiveSha256
      && id.platform === pins.platform && id.nodeVersion === pins.nodeVersion && id.nodeBinarySha256 === pins.nodeBinarySha256;
  };
  return Boolean(verifies(baseline, "baseline") && verifies(instrumented, "instrumented")
    && payloadFields.every(key => baseline.identity[key] === instrumented.identity[key]));
}

export function describeLeg(note, summary, driver) {
  const stages = Array.isArray(driver?.stages) ? driver.stages : null;
  function name(row) {
    if (!row) return null;
    const stage = typeof row.name === "string" ? row.name.replace(/-[0-9]+$/, "") : null;
    return driverStages.has(stage) ? stage : "unclassified";
  }
  const scenarios = summary?.scenarios;
  let workload = null;
  if (Array.isArray(scenarios) && scenarios.every(row => Array.isArray(row?.requests))) {
    const requests = scenarios.flatMap(row => row.requests);
    workload = { scenarios: scenarios.length, requests: requests.length,
      responses: requests.filter(row => Number.isInteger(row?.status) && row.status >= 100 && row.status <= 599).length };
  }
  return { phase: note.phase, failure: note.failure,
    driver: stages && { stages: stages.length, last: name(stages.at(-1)), firstFailed: name(stages.find(row => row.status === "failed")) },
    workload };
}

function publicLeg(leg) {
  const count = (n, max) => Number.isSafeInteger(n) && n >= 0 && n <= max;
  const validStage = name => name === null || driverStages.has(name);
  const { phase, failure, driver, workload } = leg;
  if (!phases.has(phase)
    || (failure !== null && (!phases.has(failure.phase) || !reasons.has(failure.reason)))
    || (driver !== null && (!count(driver.stages, 10000) || !validStage(driver.last) || !validStage(driver.firstFailed)
      || ((driver.stages === 0) !== (driver.last === null)) || (driver.stages === 0 && driver.firstFailed !== null)))
    || (workload !== null && (!count(workload.scenarios, ORDINARY_IDS.length) || !count(workload.requests, 8_000_000)
      || !count(workload.responses, workload.requests)))) throw new Error("invalid ordinary progress");
  return { phase, failure: failure && { phase: failure.phase, reason: failure.reason },
    driver: driver && { stages: driver.stages, last: driver.last, firstFailed: driver.firstFailed },
    workload: workload && { scenarios: workload.scenarios, requests: workload.requests, responses: workload.responses } };
}

export function projectProgress(progress) {
  const state = status => ["passed", "failed", "unreached"].includes(status);
  if (!state(progress.inputCheckStage) || !state(progress.payloadCheckStage)) throw new Error("invalid parity status");
  return { inputCheckStage: progress.inputCheckStage, payloadCheckStage: progress.payloadCheckStage,
    baseline: publicLeg(progress.baseline), instrumented: publicLeg(progress.instrumented) };
}
