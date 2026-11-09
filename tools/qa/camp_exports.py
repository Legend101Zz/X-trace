#!/usr/bin/env python3
"""Scan the Spring MVC catalog, then export supported formats and report bundle separately.

  camp_exports.py --xtrace BIN --project-dir DIR --analyzer BIN --out DIR --file SUMMARY --project P

Exit code 9 (the CLI's NotImplemented) for a format is not-implemented; any other non-zero exit, or an exit 0 that wrote
nothing, is a failure. The output directory is later scanned for privacy canaries (location class `exports`).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary as cs  # noqa: E402

FORMATS = ("openapi", "postman", "curl")


def judge(results: dict[str, tuple[int, int]]) -> tuple[str, str]:
    """results: format -> (exit code, bytes written). Returns (status, note)."""
    if not results:
        return "fail", "no formats attempted"
    if all(code == 9 for code, _ in results.values()):
        return "not-implemented", "xtrace export exited 9 for every format (not implemented in this build)"
    bad = [f for f, (code, size) in results.items() if code != 0 or size == 0]
    if bad:
        return "fail", "; ".join(f"{f}: exit {results[f][0]}, {results[f][1]} bytes" for f in bad)
    return "pass", "all formats exported and wrote output: " + ",".join(results)


def judge_scan(code: int, doc: dict) -> tuple[str, str]:
    data = doc.get("data", doc)
    if code != 0:
        return "fail", f"Spring MVC scan exited {code}; exports not attempted"
    if not isinstance(data, dict) or data.get("persisted") is not True or not data.get("catalogRevisionId") or not \
            isinstance(data.get("result"), dict) or not data["result"].get("operations"):
        return "fail", "scan produced no persisted catalog with operations; exports not attempted"
    return "pass", "Spring MVC analyzer persisted a catalog with operations"


def run_exports(xtrace: str, project_dir: str, analyzer: str, out: pathlib.Path) -> list[tuple[str, str, str]]:
    """Scan before exporting. Never count pre-existing output as evidence from this invocation."""
    out.mkdir(parents=True, exist_ok=True)
    try:
        scan = subprocess.run([xtrace, "scan", "--project-dir", project_dir,
                               "--source", str(pathlib.Path(project_dir) / "src/main/java"),
                               "--framework", "spring-mvc", "--analyzer", analyzer, "--json"],
                              capture_output=True, text=True, timeout=320)
        try:
            doc = json.loads(scan.stdout)
        except ValueError:
            doc = {}
        status, note = judge_scan(scan.returncode, doc if isinstance(doc, dict) else {})
    except (OSError, subprocess.SubprocessError):
        status, note = "fail", "Spring MVC scan could not complete; exports not attempted"
    steps = [("export-catalog-scan", status, note)]
    if status != "pass":
        return steps + [(f"export-{fmt}", "fail", note) for fmt in FORMATS] + [
            ("export-formats", "fail", note), ("export-bundle", "not-implemented", "CLI documents bundle as not implemented")]
    results = {}
    for fmt in (*FORMATS, "bundle"):
        dest = out / f"export-{fmt}"
        if dest.exists():
            code, size = 127, 0
        else:
            try:
                r = subprocess.run([xtrace, "export", "--project-dir", project_dir, "--format", fmt, "--output", str(dest)],
                                   capture_output=True, text=True, timeout=120)
                code = r.returncode
            except (OSError, subprocess.SubprocessError):
                code = 127
            size = dest.stat().st_size if dest.is_file() else sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
        if fmt == "bundle":
            steps.append(("export-bundle", "not-implemented" if code == 9 else "fail",
                          f"bundle: exit {code}, {size} bytes; CLI documents this format as not implemented"))
        else:
            results[fmt] = (code, size)
            st, why = judge({fmt: (code, size)})
            steps.append((f"export-{fmt}", st, why))
    status, note = judge(results)
    return steps + [("export-formats", status, note)]


def main() -> int:
    ap = argparse.ArgumentParser()
    for n in ("xtrace", "project-dir", "analyzer", "out", "file", "project"):
        ap.add_argument(f"--{n}", required=True)
    a = ap.parse_args()
    for name, status, note in run_exports(a.xtrace, a.project_dir, a.analyzer, pathlib.Path(a.out)):
        cs.record(pathlib.Path(a.file), a.project, name, status, note)
        print(f"campaign step {name}: {status} ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
