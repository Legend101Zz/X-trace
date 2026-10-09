#!/usr/bin/env python3
"""Baseline vs instrumented request latency (p50/p95), REPORTED only; no requirement sets a budget yet.

  camp_overhead.py --baseline baseline-1/receipt.json --instrumented instrumented-1/receipt.json --out overhead.json
"""
from __future__ import annotations

import argparse
import json
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
        out[sc["id"]] = [r["elapsedMs"] for r in sc.get(key_requests, []) if isinstance(r.get("elapsedMs"), (int, float))]
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--instrumented", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        doc = compare(json.loads(pathlib.Path(a.baseline).read_text()), json.loads(pathlib.Path(a.instrumented).read_text()))
    except (OSError, ValueError, KeyError) as exc:
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
