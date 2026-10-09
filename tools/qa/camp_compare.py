#!/usr/bin/env python3
"""Compare a fresh host baseline receipt with the tracked baseline-summary.json.

Records, per project:
  baseline-fingerprints-vs-pinned : `pass` when every pinned scenario fingerprint is reproduced, otherwise `fail`
                                    (gating) unless the scenario id is listed with --waive. A missing receipt fails.
  baseline-postgres-digest        : `pass` / `fail` (gating) on the pinned Postgres image digest.
  baseline-jar-sha-vs-pinned      : `reported` (informational): the host-built jar is not byte-reproducible against
                                    the container build, but the digests are always printed so the difference is visible.
The tracked baselines were made in linux/arm64 containers; the CI run is host-mode on x86_64.
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
    ap.add_argument("--waive", action="append", default=[], help="scenario id whose fingerprint mismatch is waived")
    args = ap.parse_args()
    out = pathlib.Path(args.file)
    rec = lambda step, status, note: camp_summary.record(out, args.project, step, status, note)  # noqa: E731
    try:
        receipt = json.loads(pathlib.Path(args.receipt).read_text())
        pinned = json.loads(pathlib.Path(args.pinned).read_text())
    except (OSError, ValueError):
        rec("baseline-fingerprints-vs-pinned", "fail", "no receipt to compare")
        return 0
    want = {s["id"]: s["semanticEffectFingerprint"] for s in pinned.get("scenarios", [])}
    got = {s["id"]: s.get("semanticEffectFingerprint") for s in receipt.get("scenarios", [])}
    bad = sorted(k for k, v in want.items() if got.get(k) != v)
    waived = sorted(k for k in bad if k in args.waive)
    unwaived = [k for k in bad if k not in args.waive]
    note = f"{len(want) - len(bad)}/{len(want)} equal the pinned platform baseline"
    if unwaived:
        note += "; differs: " + ",".join(unwaived)
    if waived:
        note += "; waived: " + ",".join(waived)
    rec("baseline-fingerprints-vs-pinned", "fail" if unwaived or not want else "pass", note[:200])
    rp, pp = receipt.get("pin", {}), pinned.get("pin", {})
    pg_want, pg_got = pp.get("postgresImageDigest"), rp.get("postgresImageDigest")
    rec("baseline-postgres-digest", "pass" if pg_want and pg_want == pg_got else "fail",
        f"pinned {str(pg_want)[:19]} observed {str(pg_got)[:19]}")
    jw, jg = pp.get("jarSha256"), rp.get("jarSha256")
    rec("baseline-jar-sha-vs-pinned", "reported",
        ("equal" if jw == jg else "DIFFERENT") + f": pinned {str(jw)[:12]} observed {str(jg)[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
