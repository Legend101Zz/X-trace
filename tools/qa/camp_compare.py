#!/usr/bin/env python3
"""Compare a fresh host baseline receipt with the tracked baseline-summary.json (informational, never gating).

Records a `reported` step with matched/total scenario fingerprint counts. The tracked baselines were made in
linux/arm64 containers, the CI run is host-mode on x86_64, so a mismatch is reported, not hidden.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--pinned", required=True)
    args = ap.parse_args()
    out = pathlib.Path(args.file)
    try:
        receipt = json.loads(pathlib.Path(args.receipt).read_text())
        pinned = json.loads(pathlib.Path(args.pinned).read_text())
    except (OSError, ValueError):
        camp_summary.record(out, args.project, "baseline-vs-pinned-fingerprints", "reported", "no receipt to compare")
        return 0
    want = {s["id"]: s["semanticEffectFingerprint"] for s in pinned.get("scenarios", [])}
    got = {s["id"]: s.get("semanticEffectFingerprint") for s in receipt.get("scenarios", [])}
    matched = sum(1 for k, v in want.items() if got.get(k) == v)
    camp_summary.record(out, args.project, "baseline-vs-pinned-fingerprints", "reported",
                        f"{matched}/{len(want)} scenario fingerprints equal the tracked arm64-container baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
