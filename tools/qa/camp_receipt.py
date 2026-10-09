#!/usr/bin/env python3
"""Emit a campaign receipt in the evidence/v0.01 receipt shape (tools/release/check_ledger.py) as an ARTIFACT ONLY.

The receipt is marked nonRelease and unsigned; `result` is "passed" only when every recorded campaign step passed, else
"failed". It never reaches evidence/v0.01 and never carries a signature, so check_ledger can never accept it as release
evidence. Evidence references are {path, sha256} relative to the artifact directory.

  camp_receipt.py --out-dir DIR --project petclinic --requirement CAMPAIGN-PETCLINIC --candidate-sha SHA \
      --campaign campaigns/java/petclinic/campaign.json [--instrumented DIR/receipt.json] [--baseline DIR/receipt.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


def sha256_file(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ref(root: pathlib.Path, rel: str) -> dict | None:
    p = root / rel
    return {"path": rel, "sha256": sha256_file(p)} if p.is_file() else None


def build_receipt(root: pathlib.Path, project: str, requirement: str, candidate_sha: str, campaign: dict,
                  summary: dict, instrumented: dict | None, baseline: dict | None, package_sha256: str | None,
                  run_id: str) -> dict:
    steps = summary.get("steps", [])
    checks = [{"name": s["step"], "status": "passed" if s["status"] == "pass" else s["status"],
               "reached": s["status"] in ("pass", "fail"), "note": s.get("note", "")} for s in steps
              if s["status"] != "reported"]
    # reported rows (jar sha, overhead, ...) never count as passed checks but a reader must still see them
    reported = [{"name": s["step"], "note": s.get("note", "")} for s in steps if s["status"] == "reported"]
    scenarios = []
    inst_by_id = {s["id"]: s for s in (instrumented or {}).get("scenarios", [])}
    base_by_id = {s["id"]: s for s in (baseline or {}).get("scenarios", [])}
    for sc in campaign.get("scenarios", []):
        sid = sc["id"]
        i, b = inst_by_id.get(sid), base_by_id.get(sid)
        verdict = (i or {}).get("recordingVerdict")
        scenarios.append({
            "name": sid,
            "baseline": ref(root, "baseline-receipt.json"),
            "instrumented": ref(root, "instrumented-receipt.json"),
            "browser": ref(root, "browser/journeys.json"),
            "privacy": ref(root, "privacy-canary-report.json"),
            "overhead": ref(root, "overhead.json"),
            "semanticEffectFingerprint": (b or {}).get("semanticEffectFingerprint"),
            "instrumentedSemanticEffectFingerprint": (i or {}).get("semanticEffectFingerprint"),
            "recordingExpectationsPassed": bool(verdict and verdict.get("passed")),
        })
    evidence = [r for r in (ref(root, n) for n in ("summary.json", "baseline-receipt.json", "instrumented-receipt.json",
                                                   "privacy-canary-report.json", "overhead.json", "browser/journeys.json",
                                                   "tui/tui.json")) if r]
    failed = [c for c in checks if c["status"] != "passed"]
    return {
        "schemaVersion": 1, "requirementId": requirement, "kind": "campaign",
        "result": "passed" if not failed and checks else "failed",
        "nonRelease": True, "signing": "unsigned", "signatures": [],
        "notice": "NON-RELEASE diagnostic receipt emitted by CI as an artifact; not evidence for evidence/v0.01",
        "candidateSha": candidate_sha,
        "build": {"id": f"ci-run-{run_id}", "sourceSha": candidate_sha},
        "artifacts": [{"path": "package.sha256", "sha256": package_sha256}] if package_sha256 else [],
        "evidence": evidence, "checks": checks, "reported": reported, "failedChecks": [c["name"] for c in failed],
        "attestation": {"project": project, "upstream": campaign.get("upstream"), "tagException": campaign.get("tagException"),
                        "scenarios": scenarios, "artifacts": []},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--requirement", required=True)
    ap.add_argument("--candidate-sha", required=True)
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--instrumented", default="")
    ap.add_argument("--baseline", default="")
    ap.add_argument("--package-sha256", default="")
    ap.add_argument("--run-id", default="local")
    a = ap.parse_args()
    root = pathlib.Path(a.out_dir)
    summary = json.loads((root / "summary.json").read_text())
    load = lambda p: json.loads(pathlib.Path(p).read_text()) if p and pathlib.Path(p).exists() else None  # noqa: E731
    doc = build_receipt(root, a.project, a.requirement, a.candidate_sha, json.loads(pathlib.Path(a.campaign).read_text()),
                        summary, load(a.instrumented), load(a.baseline), a.package_sha256 or None, a.run_id)
    (root / "campaign-receipt.NON-RELEASE.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"campaign receipt (NON-RELEASE, unsigned): result={doc['result']} failedChecks={len(doc['failedChecks'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
