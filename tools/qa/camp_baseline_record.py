#!/usr/bin/env python3
"""Record a platform-specific pinned baseline summary from two or more baseline receipts, with provenance.

  camp_baseline_record.py --receipt r1.json --receipt r2.json --platform linux/arm64 --note "..." --out baseline-summary.<id>.json

Refuses unless every receipt passed and all agree on every scenario fingerprint (an unstable scenario is never pinned).
It writes a NEW file; existing pinned files are never overwritten (use a new name for a new baseline).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


def build(receipts: list[dict], paths: list[str], platform: str, note: str, recorded_at: str, source: dict) -> dict:
    if len(receipts) < 2:
        raise ValueError("need at least two receipts to establish stability")
    first = receipts[0]
    ids = [s["id"] for s in first["scenarios"]]
    for r in receipts:
        if r.get("result") != "passed_baseline_only":
            raise ValueError("a receipt did not pass")
        if [s["id"] for s in r["scenarios"]] != ids:
            raise ValueError("receipts disagree on scenarios")
        if r["pin"]["jarSha256"] != first["pin"]["jarSha256"]:
            raise ValueError("receipts used different jars")
    scenarios = []
    for i, sid in enumerate(ids):
        fps = {r["scenarios"][i]["semanticEffectFingerprint"] for r in receipts}
        if len(fps) != 1:
            raise ValueError(f"scenario {sid} is not stable across receipts")
        s0 = first["scenarios"][i]
        scenarios.append({"id": sid, "kind": s0["kind"], "requests": len(s0["requests"]), "checks": len(s0["checks"]),
                          "semanticEffectFingerprint": fps.pop(), "stableAcrossRuns": True})
    return {
        "schemaVersion": 1, "kind": "baseline_stability_summary_platform_pin", "project": first["project"],
        "releaseAcceptance": False, "instrumented": False,
        "pin": {"sha": first["pin"]["sha"], "jarSha256": first["pin"]["jarSha256"],
                "postgresImageDigest": first["pin"]["postgresImageDigest"], "jdkImage": first["pin"].get("jdkImage")},
        "provenance": {"platform": platform, "recordedAt": recorded_at, "note": note, "source": source,
                       "receiptSha256": [hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths],
                       "harnessSha256": first.get("harnessSha256")},
        "scenarios": scenarios,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", action="append", required=True)
    ap.add_argument("--platform", required=True)
    ap.add_argument("--note", required=True)
    ap.add_argument("--recorded-at", required=True)
    ap.add_argument("--source", default="{}", help="JSON object: where the receipts came from (run id, sha, runner)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    if out.exists():
        print("refusing to overwrite an existing pinned baseline")
        return 2
    receipts = [json.loads(pathlib.Path(p).read_text()) for p in a.receipt]
    try:
        doc = build(receipts, a.receipt, a.platform, a.note, a.recorded_at, json.loads(a.source))
    except ValueError as exc:
        print(f"not recorded: {exc}")
        return 1
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"recorded {len(doc['scenarios'])} scenarios for {a.platform} -> {out.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
