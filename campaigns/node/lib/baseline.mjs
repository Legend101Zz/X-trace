// Orchestrates one from-reset baseline run: fresh network + containers, readiness,
// scenarios, receipts, teardown. Project code supplies buildStack() and scenarios().
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { docker, container, net, PREFIX } from "./docker.mjs";
import { runScenarios } from "./harness.mjs";
import { sha256Hex } from "./canonical.mjs";

export function randomSecret(bytes = 24) {
  // hex only: a leading "-" (base64url) would be parsed as a CLI option by `medusa user -p`.
  return crypto.randomBytes(bytes).toString("hex");
}

export async function runBaseline({ project, n, root, buildStack, scenarios, meta = {}, keep = false }) {
  const outDir = path.join(root, `baseline-${n}`);
  if (fs.existsSync(outDir)) throw new Error(`${outDir} exists; baselines are write-once (pick a new number)`);
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const tag = `b${n}`;
  const names = { net: `${PREFIX}${project}-${tag}-net`, db: `${PREFIX}${project}-${tag}-db`, app: `${PREFIX}${project}-${tag}-app`, worker: `${PREFIX}${project}-${tag}-worker`, dep: `${PREFIX}${project}-${tag}-dep` };
  const startedAt = Date.now();
  let ctx;
  let summary;
  let status = "failed";
  let failure;
  try {
    net.create(names.net);
    ctx = await buildStack({ names, outDir });
    const readyMs = Date.now() - startedAt;
    summary = await runScenarios({ project, baseUrl: ctx.baseUrl, outDir, scenarios: scenarios(ctx), ctxExtra: ctx.extra || {} });
    status = summary.result;
    fs.writeFileSync(path.join(outDir, "run.json"), JSON.stringify({ ...meta, readyMs, totalMs: Date.now() - startedAt }, null, 2) + "\n", { mode: 0o600 });
  } catch (e) {
    failure = String(e && e.message).slice(0, 800);
    console.error("baseline failed:", failure);
  } finally {
    const logs = container.logs(names.app);
    fs.writeFileSync(path.join(outDir, "app.log"), (logs.stdout || "") + (logs.stderr || ""), { mode: 0o600 });
    for (const extra of ["worker", "dep"]) {
      const l = container.logs(names[extra]);
      if ((l.stdout || l.stderr)) fs.writeFileSync(path.join(outDir, `${extra}.log`), (l.stdout || "") + (l.stderr || ""), { mode: 0o600 });
    }
    const exit = docker(["inspect", "-f", "{{.State.ExitCode}}", names.app], { allowFail: true }).stdout.trim();
    if (!keep) {
      container.rm(names.worker);
      container.rm(names.dep);
      container.rm(names.app);
      container.rm(names.db);
      net.rm(names.net);
    }
    const receipt = {
      schemaVersion: 1,
      project,
      baselineNumber: n,
      kind: "uninstrumented_baseline_only",
      releaseAcceptance: false,
      candidateSha: null,
      status,
      failure,
      appContainerExitCodeAtTeardown: exit,
      appLogSha256: sha256Hex(fs.readFileSync(path.join(outDir, "app.log"))),
      fingerprints: summary ? Object.fromEntries(summary.scenarios.map((s) => [s.id, s.semanticEffectFingerprint ?? null])) : null,
      ...meta,
    };
    fs.writeFileSync(path.join(outDir, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n", { mode: 0o600 });
    console.log(JSON.stringify({ project, baseline: n, status, scenarios: summary?.scenarioCount ?? 0 }));
  }
  if (status !== "passed") process.exitCode = 1;
  return { outDir, status };
}

export function imageId(image) {
  return docker(["image", "inspect", "-f", "{{.Id}}", image], { allowFail: true }).stdout.trim();
}
