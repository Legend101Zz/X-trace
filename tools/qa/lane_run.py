#!/usr/bin/env python3
"""Lane CI step runner and summary merger (stdlib only; reuses the release floor grammars).

  run   : run one command with all output kept in a private log; print only allowlisted facts
          (suite/variant/step, status, exit code, counts, allowlisted failing test ids).
  merge : combine per-step fragments and the plan into summary.json plus a sanitized step summary.

Public output is limited to values that match the release tooling grammars (test ids per
tools.release.ci_floor._valid_test_id); invalid candidates are dropped and only counted.
Run from the repository root:  python3 -B -m tools.qa.lane_run <run|merge> ...
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

from tools.release import ci_floor

MAX_FAILING = 32
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
# Variants every selected suite must report before it can be called "pass".
EXPECTED_VARIANTS = {
    "meta": ["-"],
    "rust": ["-"],
    "java": ["17", "21", "25"],
    "node": ["22", "24"],
    "web": ["-"],
    "tui": ["-"],
}
CARGO_FAIL = re.compile(r"^test (\S+) \.\.\. FAILED$")
CARGO_RESULT = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")
GRADLE_FAIL = re.compile(r"^(?:[\w$.]+\.)?(\w+) > (\w+)(?:\(.*\))?(?:\[.*\])? FAILED$")
PY_FAIL = re.compile(r"^(?:FAIL|ERROR): (\w+) \((?:[\w.]+\.)?(\w+)\.(\w+)\)")
TAP_NOT_OK = re.compile(r"^\s*not ok \d+ - (\S+)\s*$")


def parse_output(text: str) -> dict:
    failing: list[str] = []
    dropped = 0
    passed = failed = ignored = 0
    for line in text.splitlines():
        line = line.rstrip()
        cand = None
        if m := CARGO_FAIL.match(line):
            cand = m.group(1)
        elif m := GRADLE_FAIL.match(line):
            cand = f"{m.group(1)}::{m.group(2)}"
        elif m := PY_FAIL.match(line):
            cand = f"{m.group(2)}::{m.group(1)}"
        elif m := TAP_NOT_OK.match(line):
            cand = m.group(1)
        elif m := CARGO_RESULT.match(line):
            passed += int(m.group(1))
            failed += int(m.group(2))
            ignored += int(m.group(3))
        if cand is not None:
            if ci_floor._valid_test_id(cand):
                if cand not in failing:
                    failing.append(cand)
            else:
                dropped += 1
    return {
        "passed": passed, "failed": failed, "ignored": ignored,
        "failingTests": failing[:MAX_FAILING],
        "failingTruncated": max(0, len(failing) - MAX_FAILING),
        "droppedInvalidNames": dropped,
    }


def _check_name(value: str, what: str) -> str:
    if value != "-" and not SAFE_NAME.fullmatch(value):
        raise SystemExit(f"invalid {what}")
    return value


def cmd_run(args: argparse.Namespace) -> int:
    suite, variant, step = (_check_name(args.suite, "suite"), _check_name(args.variant, "variant"),
                            _check_name(args.step, "step"))
    out = pathlib.Path(args.out)
    log_dir = pathlib.Path(os.environ.get("LANE_PRIVATE_LOG_DIR") or os.environ.get("RUNNER_TEMP", "/tmp")) / "xl"
    previous_umask = os.umask(0o077)  # private log only; the wrapped command keeps the job's umask
    log_dir.mkdir(mode=0o700, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        raise SystemExit("no command")
    log_path = log_dir / f"{suite}-{variant}-{step}.log"
    with open(log_path, "wb") as log:
        os.umask(previous_umask)
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=args.cwd or None,
                              check=False, timeout=args.timeout)
    text = log_path.read_text(encoding="utf-8", errors="replace")
    facts = parse_output(text)
    status = "pass" if proc.returncode == 0 else "fail"
    frag = {"suite": suite, "variant": variant, "step": step, "status": status,
            "exitCode": proc.returncode, **facts}
    (out / f"{suite}__{variant}__{step}.json").write_text(json.dumps(frag, sort_keys=True, indent=1) + "\n")
    print(f"lane {suite}/{variant}/{step}: {status} exit={proc.returncode} passed={facts['passed']} "
          f"failed={facts['failed']} ignored={facts['ignored']}")
    for name in facts["failingTests"]:
        print(f"lane failing-test {name}")
    if facts["failingTruncated"] or facts["droppedInvalidNames"]:
        print(f"lane failing-test-overflow truncated={facts['failingTruncated']} "
              f"dropped-invalid={facts['droppedInvalidNames']}")
    if status == "fail" and os.environ.get("LANE_DIAG") == "scrubbed":
        # Opt-in (repository variable) scrubbed tail: no paths, env, hex or tokens, 160 chars per line.
        for line in text.splitlines()[-40:]:
            print("lane diag| " + ci_floor._scrub_text(line))
    return proc.returncode


def cmd_merge(args: argparse.Namespace) -> int:
    plan = json.loads(pathlib.Path(args.plan).read_text())
    frags = [json.loads(p.read_text()) for p in sorted(pathlib.Path(args.frag_dir).glob("**/*.json"))]
    results: dict[str, str] = {}
    for item in args.job_result or []:
        name, _, res = item.partition("=")
        results[name] = res
    suites_out = []
    overall_ok = True
    for name, info in plan["suites"].items():
        entry: dict = {"name": name, "plan": info.get("reason", "")}
        if info["status"] in ("skipped-by-filter", "absent"):
            entry["status"] = info["status"]
            suites_out.append(entry)
            continue
        mine = [f for f in frags if f["suite"] == name]
        variants = []
        failing: list[str] = []
        suite_ok = True
        for variant in EXPECTED_VARIANTS[name]:
            vfr = [f for f in mine if f["variant"] == variant]
            vstatus = "pass" if vfr and all(f["status"] == "pass" for f in vfr) else "fail"
            if not vfr:
                vstatus = "no-result"
            suite_ok &= vstatus == "pass"
            for f in vfr:
                failing += [f"{variant}:{t}" if variant != "-" else t for t in f["failingTests"]]
            variants.append({"variant": variant, "status": vstatus,
                             "steps": [{"step": f["step"], "status": f["status"], "passed": f["passed"],
                                        "failed": f["failed"], "ignored": f["ignored"]} for f in vfr]})
        if results.get(name) not in (None, "success"):
            suite_ok = False
        entry["status"] = "pass" if suite_ok else "fail"
        entry["variants"] = variants
        entry["failingTests"] = failing[:MAX_FAILING]
        if info.get("changedCrates") is not None:
            entry["changedCrates"] = info["changedCrates"]
        overall_ok &= suite_ok
        suites_out.append(entry)
    doc = {"schemaVersion": 1, "planMode": plan.get("mode"), "overall": "pass" if overall_ok else "fail",
           "suites": suites_out}
    pathlib.Path(args.out).write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")
    lines = ["| suite | status | detail |", "|---|---|---|"]
    for s in suites_out:
        detail = ", ".join(f"{v['variant']}={v['status']}" for v in s.get("variants", [])) or s.get("plan", "")
        lines.append(f"| {s['name']} | {s['status']} | {detail} |")
    text = "\n".join(lines) + "\n"
    print(text)
    if args.step_summary:
        with open(args.step_summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if overall_ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--suite", required=True)
    r.add_argument("--variant", default="-")
    r.add_argument("--step", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--cwd", default="")
    r.add_argument("--timeout", type=int, default=3000)
    r.add_argument("command", nargs=argparse.REMAINDER)
    m = sub.add_parser("merge")
    m.add_argument("--plan", required=True)
    m.add_argument("--frag-dir", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--step-summary", default="")
    m.add_argument("--job-result", action="append")
    args = ap.parse_args()
    return cmd_run(args) if args.cmd == "run" else cmd_merge(args)


if __name__ == "__main__":
    sys.exit(main())
