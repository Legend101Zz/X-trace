#!/usr/bin/env python3
"""Run `xtrace export` for every format into a private directory and record the campaign step `export-formats`.

  camp_exports.py --xtrace BIN --project-dir DIR --out DIR --file SUMMARY --project P

Exit code 9 (the CLI's NotImplemented) for a format is not-implemented; any other non-zero exit, or an exit 0 that wrote
nothing, is a failure. The output directory is later scanned for privacy canaries (location class `exports`).
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary as cs  # noqa: E402

FORMATS = ("openapi", "postman", "curl", "bundle")


def judge(results: dict[str, tuple[int, int]]) -> tuple[str, str]:
    """results: format -> (exit code, bytes written). Returns (status, note)."""
    if all(code == 9 for code, _ in results.values()):
        return "not-implemented", "xtrace export exited 9 for every format (not implemented in this build)"
    bad = [f for f, (code, size) in results.items() if code != 0 or size == 0]
    if bad:
        return "fail", "; ".join(f"{f}: exit {results[f][0]}, {results[f][1]} bytes" for f in bad)
    return "pass", "all formats exported and wrote output: " + ",".join(results)


def main() -> int:
    ap = argparse.ArgumentParser()
    for n in ("xtrace", "project-dir", "out", "file", "project"):
        ap.add_argument(f"--{n}", required=True)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    results: dict[str, tuple[int, int]] = {}
    for fmt in FORMATS:
        dest = out / f"export-{fmt}"
        try:
            r = subprocess.run([a.xtrace, "export", "--project-dir", a.project_dir, "--format", fmt, "--output", str(dest)],
                               capture_output=True, text=True, timeout=120)
            code = r.returncode
        except (OSError, subprocess.SubprocessError):
            code = 127
        size = 0
        if dest.is_file():
            size = dest.stat().st_size
        elif dest.is_dir():
            size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
        results[fmt] = (code, size)
    status, note = judge(results)
    cs.record(pathlib.Path(a.file), a.project, "export-formats", status, note)
    print(f"campaign step export-formats: {status} ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
