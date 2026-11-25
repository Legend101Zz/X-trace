"""Run the candidate's real publication entry point with synthetic private inputs."""

import json
import os
from pathlib import Path
import subprocess
import sys

from verify import ANALYZER, CASES, PACKAGE, SOURCE, digest, markers


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def produce(subject, work, run_id):
    private = work / "private"
    public = work / "public"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    sentinel, hit = markers(run_id)
    for case in CASES:
        root = private / case
        root.mkdir(mode=0o700)
        write(root / "summary.json", {"project": "petclinic", "steps": [{
            "step": hit if case == "canary-hit" else "synthetic-workload",
            "status": "fail" if case == "recorded-failure" else "pass",
            "note": sentinel,
        }]})
        if case != "missing-canaries":
            write(root / "canaries.json", {"synthetic": sentinel, "staged-hit": hit})
        write(root / "definition.json", {"project": "petclinic", "upstream": {"sha": "a" * 40},
                                         "scenarios": [{"id": "synthetic-route", "raw": sentinel}]})
        write(root / "baseline.json", {"scenarios": [{"id": "synthetic-route", "passed": True}]})
        if case != "missing-evidence":
            write(root / "instrumented.json", {"scenarios": [{"id": "synthetic-route",
                  "scenarioChecksPassed": True, "recordingVerdict": {"passed": True}, "stdout": sentinel}]})
        write(root / "privacy-canary-report.json", {"clean": True, "scanned": [{"files": 5}],
                                                   "hits": [], "uncovered": [], "raw": sentinel})
        (root / "package.sha256").write_text(digest(PACKAGE) + "\n")
        (root / "analyzer.sha256").write_text(digest(ANALYZER) + "\n")
        (root / "synthetic-package.tar.gz").write_bytes(PACKAGE)
        (root / "application.log").write_text(sentinel)
        (root / "trace.xtf").write_bytes(sentinel.encode())
        (root / "tui.txt").write_text(sentinel)
        args = [sys.executable, "-B", "-m", "tools.qa.camp_publication",
                "--private", str(root), "--public", str(public / case), "--project", "petclinic",
                "--candidate", SOURCE, "--campaign", str(root / "definition.json"), "--run-id", run_id,
                "--canaries", str(root / "canaries.json"), "--baseline", str(root / "baseline.json"),
                "--instrumented", str(root / "instrumented.json")]
        with (root / "publication.log").open("wb") as log:
            result = subprocess.run(args, cwd=subject, stdout=log, stderr=log, check=False)
        expected = 0 if case in {"success", "recorded-failure"} else 1
        if result.returncode != expected:
            raise SystemExit("candidate returned an unexpected publication status")


if __name__ == "__main__":
    os.umask(0o077)
    produce(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
