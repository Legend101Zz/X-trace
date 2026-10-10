#!/usr/bin/env python3
"""Structural lint of workflow files (stdlib + system ruby for YAML parsing).

Checks, for every workflow given: parses as YAML; top-level `permissions` exactly {contents: read} and no job-level elevation; no github.token/GITHUB_TOKEN; every `uses:` pinned to a
40-hex SHA; every actions/checkout has `persist-credentials: false`; every job has `timeout-minutes` (only
enforced for files listed with --strict-timeouts); no `secrets.` references.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

SHA_PIN = re.compile(r"@[0-9a-f]{40}(\s|$)")


def load(path: pathlib.Path):
    out = subprocess.run(["ruby", "-ryaml", "-rjson", "-e", "puts JSON.dump(YAML.load_file(ARGV[0]))", str(path)],
                         capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise ValueError("yaml parse failed")
    return json.loads(out.stdout)


def lint(path: pathlib.Path, strict_timeouts: bool) -> list[str]:
    problems: list[str] = []
    try:
        doc = load(path)
    except (ValueError, OSError):
        return [f"{path.name}: does not parse"]
    text = path.read_text()
    if doc.get("permissions") != {"contents": "read"}:
        problems.append(f"{path.name}: top-level permissions must be exactly contents: read")
    for job_id, job in (doc.get("jobs") or {}).items():
        if "permissions" in job and job["permissions"] != {"contents": "read"}:
            problems.append(f"{path.name}: job {job_id} elevates permissions")
    if re.search(r"github\.token|GITHUB_TOKEN", text):
        problems.append(f"{path.name}: references github.token or GITHUB_TOKEN")
    if re.search(r"\bsecrets\.", text):
        problems.append(f"{path.name}: references secrets")
    for m in re.finditer(r"^\s*-?\s*uses:\s*(\S.*)$", text, re.M):
        if not SHA_PIN.search(m.group(1) + " "):
            problems.append(f"{path.name}: unpinned action {m.group(1).split('@')[0]}")
    for job_id, job in (doc.get("jobs") or {}).items():
        if strict_timeouts and "timeout-minutes" not in job:
            problems.append(f"{path.name}: job {job_id} has no timeout-minutes")
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                if (step.get("with") or {}).get("persist-credentials") is not False:
                    problems.append(f"{path.name}: job {job_id} checkout lacks persist-credentials false")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--strict-timeouts", nargs="*", default=["lane.yml", "campaigns.yml", "package.yml"])
    args = ap.parse_args()
    problems: list[str] = []
    for f in args.files:
        p = pathlib.Path(f)
        problems += lint(p, p.name in args.strict_timeouts)
    for line in problems:
        print("workflow-lint:", line)
    print(f"workflow-lint: {len(args.files)} files, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
