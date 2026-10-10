#!/usr/bin/env python3
"""Reduce an upload tree to what is safe to publish when a privacy scan found a canary.

Keeps only privacy-canary-report*.json (class names and counts, never values) and a summary.json whose step notes are
dropped (step name and status only). Everything else is deleted.

  camp_purge.py --out-dir DIR
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys

KEEP_PREFIX = "privacy-canary-report"


def purge(root: pathlib.Path) -> list[str]:
    removed = []
    summary = root / "summary.json"
    steps = []
    if summary.is_file():
        try:
            steps = [{"step": s.get("step"), "status": s.get("status"), "note": ""} for s in json.loads(summary.read_text()).get("steps", [])]
        except (ValueError, AttributeError):
            steps = []
    for p in sorted(root.iterdir()):
        if p.name.startswith(KEEP_PREFIX) and p.suffix == ".json" and p.is_file():
            continue
        if p.name == "summary.json":
            continue
        shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
        removed.append(p.name)
    summary.write_text(json.dumps({"steps": steps, "notesWithheld": "privacy scan found a canary or could not clear the tree"},
                                  indent=1, sort_keys=True) + "\n")
    return removed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()
    removed = purge(pathlib.Path(a.out_dir))
    print(f"purged {len(removed)} top-level entries; kept privacy reports and a note-free summary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
