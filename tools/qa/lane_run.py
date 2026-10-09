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
PY_RAN = re.compile(r"^Ran (\d+) tests? in ")
PY_FAILED = re.compile(r"^FAILED \((?:failures=(\d+))?(?:, )?(?:errors=(\d+))?")
NODE_PASS = re.compile(r"^\S{0,2}\s*pass (\d+)$")  # node:test spec reporter summary: "ℹ pass 12"
NODE_FAIL = re.compile(r"^\S{0,2}\s*fail (\d+)$")
NODE_SKIP = re.compile(r"^\S{0,2}\s*(?:skipped|todo|cancelled) (\d+)$")
VITEST_TESTS = re.compile(r"^\s*Tests\s+(?:.*?(\d+) failed)?.*?(\d+) passed")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
TAP_NOT_OK = re.compile(r"^\s*not ok \d+ - (\S+)\s*$")


def parse_output(text: str) -> dict:
    failing: list[str] = []
    dropped = 0
    passed = failed = ignored = 0
    counted = False
    for line in ANSI.sub("", text).splitlines():
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
        elif m := PY_RAN.match(line):
            passed += int(m.group(1))
            counted = True
        elif m := PY_FAILED.match(line):
            bad = int(m.group(1) or 0) + int(m.group(2) or 0)
            failed += bad
            passed -= bad
            counted = True
        elif m := NODE_PASS.match(line):
            passed += int(m.group(1))
            counted = True
        elif m := NODE_FAIL.match(line):
            failed += int(m.group(1))
            counted = True
        elif m := NODE_SKIP.match(line):
            ignored += int(m.group(1))
        elif m := VITEST_TESTS.match(line):
            failed += int(m.group(1) or 0)
            passed += int(m.group(2))
            counted = True
        elif m := CARGO_RESULT.match(line):
            passed += int(m.group(1))
            failed += int(m.group(2))
            ignored += int(m.group(3))
            counted = True
        if cand is not None:
            if ci_floor._valid_test_id(cand):
                if cand not in failing:
                    failing.append(cand)
            else:
                dropped += 1
    return {
        "counted": counted,
        "passed": passed if counted else None, "failed": failed if counted else None,
        "ignored": ignored if counted else None,
        "failingTests": failing[:MAX_FAILING],
        "failingTruncated": max(0, len(failing) - MAX_FAILING),
        "droppedInvalidNames": dropped,
    }


def junit_counts(base: pathlib.Path, pattern: str) -> dict | None:
    """Sum JUnit XML totals (tests, failures, errors, skipped) under base; None when no report was written.

    Only integers leave this function: no test names, messages or report text are read into public output.
    """
    import xml.etree.ElementTree as ET
    total = failed = skipped = files = 0
    for path in sorted(base.glob(pattern)):
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue
        if root.tag == "testsuite":
            suites = [root]
        elif root.tag == "testsuites":
            suites = list(root.findall("testsuite"))
        else:
            continue
        files += 1
        for suite in suites:
            try:
                total += int(suite.get("tests", "0"))
                failed += int(suite.get("failures", "0")) + int(suite.get("errors", "0"))
                skipped += int(suite.get("skipped", "0"))
            except ValueError:
                continue
    if not files:
        return None
    return {"passed": max(0, total - failed - skipped), "failed": failed, "ignored": skipped}


def _check_name(value: str, what: str) -> str:
    if value != "-" and not SAFE_NAME.fullmatch(value):
        raise SystemExit(f"invalid {what}")
    return value


def _fmt(value) -> str:
    return "n/a" if value is None else str(value)


# Compiler diagnostics shown on failure (Cc-001, J-002): only rustc/clippy headline lines and repo-relative locations,
# bounded and filtered. Anything that looks like a host path, a user name or a credential is dropped and only counted.
DIAG_HEAD = re.compile(r"^(error|warning)(\[[A-Z]\d{4}\])?: (.{1,200})$")
DIAG_LOC = re.compile(r"^\s*--> (\S{1,300}):(\d+):(\d+)$")
DIAG_PATH_OK = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$")
DIAG_BAD = re.compile(r"(/home/|/Users/|/Volumes/|/tmp/|/runner|\\|token|secret|password|bearer|authorization|cookie|api[_-]?key)", re.I)
DIAG_SKIP = re.compile(r"^(warning|error): (\d+ warnings? emitted|aborting due to|could not compile|build failed|unused)", re.I)
MAX_DIAG = 20
# Test panics: only the repo-relative source location survives (never the message, which may carry data or paths).
PANIC_LOC = re.compile(r"panicked at (\S{1,300}?):(\d+):(\d+):?\s*$")


def panic_sites(text: str) -> tuple[list[str], int]:
    out: list[str] = []
    dropped = 0
    for raw in text.splitlines():
        m = PANIC_LOC.search(raw.rstrip())
        if not m:
            continue
        path = m.group(1)
        site = f"{path}:{m.group(2)}"
        if (DIAG_BAD.search(path) or ".." in path or not DIAG_PATH_OK.match(path) or path.startswith("/")
                or site in out):
            if site not in out:
                dropped += 1
            continue
        if len(out) < MAX_DIAG:
            out.append(site)
        else:
            dropped += 1
    return out, dropped


def diagnostics(text: str) -> tuple[list[str], int]:
    """(lines to print, dropped count). Pairs each `error: msg` with the `--> file:line:col` that follows it."""
    out: list[str] = []
    dropped = 0
    pending: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = DIAG_HEAD.match(line)
        if m:
            pending = None
            if m.group(1) != "error" or DIAG_SKIP.match(line):
                continue
            if DIAG_BAD.search(line):
                dropped += 1
                continue
            pending = f"{m.group(1)}{m.group(2) or ''}: {m.group(3)}"
            continue
        loc = DIAG_LOC.match(line)
        if loc and pending is not None:
            if DIAG_BAD.search(loc.group(1)) or ".." in loc.group(1) or not DIAG_PATH_OK.match(loc.group(1)):
                dropped += 1
            elif len(out) < MAX_DIAG:
                out.append(f"{pending} @ {loc.group(1)}:{loc.group(2)}:{loc.group(3)}")
            else:
                dropped += 1
            pending = None
    return out, dropped


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
        try:
            proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=args.cwd or None,
                                  check=False, timeout=args.timeout)
        except subprocess.TimeoutExpired:  # a timeout is a failed step with a fragment, never a traceback with argv
            proc = subprocess.CompletedProcess(cmd, 124)
            log.write(f"\nlane: step exceeded its {args.timeout}s timeout\n".encode())
            print(f"lane {suite}/{variant}/{step}: timeout after {args.timeout}s")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    facts = parse_output(text)
    if getattr(args, "junit_glob", ""):
        # Gradle prints no totals on success; the JUnit XML reports are the count of record for the Java suite.
        jc = junit_counts(pathlib.Path(args.cwd or "."), args.junit_glob)
        if jc is not None:
            facts.update(jc, counted=True)
    status = "pass" if proc.returncode == 0 else "fail"
    if status == "pass" and args.min_passed and facts["passed"] is None:
        status = "fail"  # a count-less pass cannot satisfy a minimum
        print(f"lane {suite}/{variant}/{step}: no test count found (minimum {args.min_passed})")
    if status == "pass" and args.min_passed and (facts["passed"] or 0) < args.min_passed:
        status = "fail"  # a test step that ran fewer tests than expected is not a pass
        print(f"lane {suite}/{variant}/{step}: fewer than {args.min_passed} tests counted")
    max_ignored = getattr(args, "max_ignored", -1)
    if status == "pass" and max_ignored >= 0 and (facts["ignored"] or 0) > max_ignored:
        status = "fail"  # a skipped or ignored test is not a pass on a no-skips row
        print(f"lane {suite}/{variant}/{step}: {facts['ignored']} ignored or skipped tests (maximum {max_ignored})")
    frag = {"suite": suite, "variant": variant, "step": step, "status": status,
            "exitCode": proc.returncode, **{k: v for k, v in facts.items() if k != "counted"}}
    (out / f"{suite}__{variant}__{step}.json").write_text(json.dumps(frag, sort_keys=True, indent=1) + "\n")
    print(f"lane {suite}/{variant}/{step}: {status} exit={proc.returncode} "
          f"passed={_fmt(facts['passed'])} failed={_fmt(facts['failed'])} ignored={_fmt(facts['ignored'])}")
    for name in facts["failingTests"]:
        print(f"lane failing-test {name}")
    if status == "fail":
        diags, ddropped = diagnostics(text)
        for d in diags:
            print(f"lane diagnostic {d}")
        if ddropped:
            print(f"lane diagnostic-overflow dropped={ddropped}")
        sites, sdropped = panic_sites(text)
        for site in sites:
            print(f"lane panic-site {site}")
        if sdropped:
            print(f"lane panic-site-overflow dropped={sdropped}")
    if facts["failingTruncated"] or facts["droppedInvalidNames"]:
        print(f"lane failing-test-overflow truncated={facts['failingTruncated']} "
              f"dropped-invalid={facts['droppedInvalidNames']}")
    return 0 if status == "pass" else (proc.returncode or 1)


def cmd_merge(args: argparse.Namespace) -> int:
    results: dict[str, str] = {}
    for item in args.job_result or []:
        name, _, res = item.partition("=")
        results[name] = res
    try:
        plan = json.loads(pathlib.Path(args.plan).read_text())
    except (OSError, ValueError):
        plan = None
    if results.get("plan") not in (None, "success"):
        plan = None
    meta = {k: os.environ.get(v, "") for k, v in (("headSha", "GITHUB_SHA"), ("runId", "GITHUB_RUN_ID"),
                                                  ("runAttempt", "GITHUB_RUN_ATTEMPT"), ("ref", "GITHUB_REF"))}
    if plan is None:
        # The plan job failed or its artifact is missing: still emit a summary, and never a passing one.
        doc = {"schemaVersion": 1, **meta, "planMode": None, "overall": "fail", "reason": "plan-unavailable",
               "suites": []}
        pathlib.Path(args.out).write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")
        text = "lane plan unavailable: no suite was evaluated\n"
        print(text)
        if args.step_summary:
            with open(args.step_summary, "a", encoding="utf-8") as fh:
                fh.write(text)
        return 1
    frags = [json.loads(p.read_text()) for p in sorted(pathlib.Path(args.frag_dir).glob("**/*.json"))]
    suites_out = []
    overall_ok = True
    for name, info in plan["suites"].items():
        entry: dict = {"name": name, "plan": info.get("reason", "")}
        if info["status"] in ("skipped-by-filter", "absent"):
            entry["status"] = info["status"]
            if info.get("forced"):
                entry["status"] = "fail"
                entry["reason"] = "suite explicitly requested but absent"
                overall_ok = False
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
                             "steps": [{"step": f["step"], "status": f["status"], "passed": f.get("passed"),
                                        "failed": f.get("failed"), "ignored": f.get("ignored")} for f in vfr]})
        if results.get(name) not in (None, "success"):
            suite_ok = False
        entry["status"] = "pass" if suite_ok else "fail"
        entry["variants"] = variants
        entry["failingTests"] = failing[:MAX_FAILING]
        if info.get("changedCrates") is not None:
            entry["changedCrates"] = info["changedCrates"]
        overall_ok &= suite_ok
        suites_out.append(entry)
    doc = {"schemaVersion": 1, **meta, "planMode": plan.get("mode"), "overall": "pass" if overall_ok else "fail",
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
    r.add_argument("--min-passed", type=int, default=0, help="fail a zero-exit step that counted fewer tests")
    r.add_argument("--max-ignored", type=int, default=-1, help="fail a zero-exit step that ignored or skipped more tests")
    r.add_argument("--junit-glob", default="", help="glob (relative to --cwd) of JUnit XML reports to count")
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
