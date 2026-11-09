#!/usr/bin/env python3
"""Baseline vs instrumented request latency (p50/p95); five interleaved pairs qualify a report, with no budget.

  camp_overhead.py --manifest overhead/runs.json --out overhead.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import sys


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    k = max(1, -(-q * len(ordered) // 100))  # ceil(q * n / 100), integer q
    return ordered[min(k, len(ordered)) - 1]


def latencies(receipt: dict, key_requests: str) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    for sc in receipt.get("scenarios", []):
        out.setdefault(sc["id"], []).extend(
            r["elapsedMs"] for r in sc.get(key_requests, [])
            if type(r.get("elapsedMs")) in (int, float) and math.isfinite(r["elapsedMs"]))
    return out


def summarize(vals: list[float]) -> dict:
    return {"n": len(vals), "p50Ms": percentile(vals, 50), "p95Ms": percentile(vals, 95)}


def ratio(a, b):
    return round(b / a, 2) if a and b is not None else None


def compare(baseline: dict, instrumented: dict) -> dict:
    b = latencies(baseline, "requests")
    i = latencies(instrumented, "requests")
    rows = []
    for sid in sorted(set(b) | set(i)):
        sb, si = summarize(b.get(sid, [])), summarize(i.get(sid, []))
        rows.append({"scenario": sid, "baseline": sb, "instrumented": si,
                     "p50Ratio": ratio(sb["p50Ms"], si["p50Ms"]), "p95Ratio": ratio(sb["p95Ms"], si["p95Ms"])})
    ab = [v for sid, vs in b.items() if sid != "concurrent-isolation" for v in vs]
    ai = [v for sid, vs in i.items() if sid != "concurrent-isolation" for v in vs]
    sb, si = summarize(ab), summarize(ai)
    return {"schemaVersion": 1, "budget": None, "gated": False,
            "note": "single-threaded scenarios only in the aggregate; requests include first-hit warm-up; reported, not gated",
            "aggregate": {"baseline": sb, "instrumented": si, "p50Ratio": ratio(sb["p50Ms"], si["p50Ms"]),
                          "p95Ratio": ratio(sb["p95Ms"], si["p95Ms"])},
            "scenarios": rows}


def compare_interleaved(runs: list[dict]) -> dict:
    """Validate actual ordered run receipts; a caller-supplied repeat count alone is never evidence."""
    errors = []
    baselines, instrumented = [], []
    previous_end = 0
    paths = set()
    evidence = []
    for index, run in enumerate(runs):
        expected = "baseline" if index % 2 == 0 else "instrumented"
        start, end = run.get("startedNs"), run.get("finishedNs")
        receipt = run.get("receipt", {})
        path = run.get("receiptPath")
        if run.get("mode") != expected or run.get("repeat") != index // 2 or run.get("exitCode") != 0:
            errors.append(f"run {index}: missing, failed or not interleaved")
        if type(start) is not int or type(end) is not int or start < previous_end or end <= start:
            errors.append(f"run {index}: invalid or overlapping observed run interval")
        else:
            previous_end = end
        if not path or path in paths:
            errors.append(f"run {index}: receipt path missing or reused")
        paths.add(path)
        scenarios = receipt.get("scenarios", [])
        valid = bool(scenarios) and all(sc.get("requests") and all(
            type(r.get("elapsedMs")) in (int, float) and math.isfinite(r["elapsedMs"]) and r["elapsedMs"] >= 0
            for r in sc["requests"]) for sc in scenarios)
        if expected == "baseline":
            valid = (valid and receipt.get("instrumented") is False
                     and receipt.get("result") == "passed_baseline_only"
                     and all(sc.get("passed") is True for sc in scenarios))
            valid = valid and bool(receipt.get("pin")) and receipt.get("pin") == runs[0].get("receipt", {}).get("pin")
            baselines.append(receipt)
        else:
            api = receipt.get("api", {})
            valid = (valid and receipt.get("instrumented") is True and receipt.get("result") == "recorded"
                     and api.get("ok") is True and api.get("recordings", 0) > 0
                     and receipt.get("notes", {}).get("launcherExitCode") in (0, 143, -15)
                     and all(sc.get("scenarioChecksPassed") is True and sc.get("fingerprintEqualsBaseline") is True
                             for sc in scenarios))
            baseline = baselines[-1] if baselines else {}
            bsc = {sc["id"]: sc for sc in baseline.get("scenarios", [])}
            valid = valid and receipt.get("pin") == baseline.get("pin") and set(bsc) == {sc["id"] for sc in scenarios} and all(
                sc.get("semanticEffectFingerprint") == bsc[sc["id"]].get("semanticEffectFingerprint") and
                len(sc["requests"]) == len(bsc[sc["id"]]["requests"]) for sc in scenarios if sc["id"] in bsc)
            instrumented.append(receipt)
        if not valid:
            errors.append(f"run {index}: missing timings, failed workload checks or unmatched workload")
        canonical_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        evidence.append({**{k: run.get(k) for k in ("mode", "repeat", "startedNs", "finishedNs", "exitCode")},
                         "canonicalReceiptSha256": hashlib.sha256(canonical_receipt).hexdigest(),
                         "recordings": receipt.get("api", {}).get("recordings"),
                         "scenarios": {sid: summarize(vals) for sid, vals in latencies(receipt, "requests").items()}})
    pairs = min(len(baselines), len(instrumented))
    if not runs or len(runs) % 2:
        errors.append("incomplete baseline/instrumented pair")
    doc = compare({"scenarios": [sc for r in baselines for sc in r.get("scenarios", [])]},
                  {"scenarios": [sc for r in instrumented for sc in r.get("scenarios", [])]})
    eligible = pairs >= 5 and not errors
    doc.update({"repeats": pairs, "interleaved": not errors, "eligibleForClaim": eligible, "errors": errors, "runs": evidence})
    doc["note"] += "; canary injection, serial pacing and capture drops may affect these measurements; no unpaced-load claim"
    if not eligible:
        for row in [doc["aggregate"], *doc["scenarios"]]:
            row["p50Ratio"] = row["p95Ratio"] = None
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        manifest = json.loads(pathlib.Path(a.manifest).read_text())
        runs = []
        for entry in manifest["runs"]:
            path = pathlib.Path(entry["receiptPath"]).resolve()
            runs.append({**entry, "receiptPath": str(path), "receipt": json.loads(path.read_text())})
        doc = compare_interleaved(runs)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"overhead: inputs unavailable ({type(exc).__name__})")
        return 1
    pathlib.Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    agg = doc["aggregate"]
    print(f"overhead aggregate: baseline p50={agg['baseline']['p50Ms']}ms p95={agg['baseline']['p95Ms']}ms n={agg['baseline']['n']}; "
          f"instrumented p50={agg['instrumented']['p50Ms']}ms p95={agg['instrumented']['p95Ms']}ms n={agg['instrumented']['n']}; "
          f"ratio p50={agg['p50Ratio']} p95={agg['p95Ratio']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
