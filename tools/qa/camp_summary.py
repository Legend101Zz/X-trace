#!/usr/bin/env python3
"""Per-job campaign summary with a fail-closed gate (stdlib only).

  record : append a step result (pass | fail | not-implemented | reported)
  exec   : run a command and record pass/fail from its exit code (output is not captured here)
  gate   : exit 1 unless every recorded step is pass/reported (not-implemented and fail are never success)

A step that did not run is never recorded as pass. `reported` is informational and never gates.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

STATUSES = ("pass", "fail", "not-implemented", "reported")


def _load(path: pathlib.Path, project: str) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {"schemaVersion": 1, "project": project, "receipt": None, "steps": []}


def _save(path: pathlib.Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")


def record(path: pathlib.Path, project: str, step: str, status: str, note: str = "") -> None:
    if status not in STATUSES:
        raise SystemExit("invalid status")
    doc = _load(path, project)
    doc["steps"] = [s for s in doc["steps"] if s["step"] != step] + [{"step": step, "status": status, "note": note[:200]}]
    _save(path, doc)


def gate(path: pathlib.Path) -> int:
    doc = _load(path, "")
    bad = [s for s in doc["steps"] if s["status"] in ("fail", "not-implemented")]
    for s in doc["steps"]:
        print(f"campaign step {s['step']}: {s['status']}" + (f" ({s['note']})" if s["note"] else ""))
    if not doc["steps"]:
        print("campaign gate: no steps recorded")
        return 1
    print(f"campaign gate: {len(bad)} incomplete or failed step(s)")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("record", "exec", "gate"):
        p = sub.add_parser(name)
        p.add_argument("--file", required=True)
        if name != "gate":
            p.add_argument("--project", required=True)
            p.add_argument("--step", required=True)
        if name == "record":
            p.add_argument("--status", required=True)
            p.add_argument("--note", default="")
        if name == "exec":
            p.add_argument("--cwd", default="")
            p.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    path = pathlib.Path(args.file)
    if args.cmd == "record":
        record(path, args.project, args.step, args.status, args.note)
        return 0
    if args.cmd == "gate":
        return gate(path)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    rc = subprocess.run(cmd, cwd=args.cwd or None, check=False).returncode
    record(path, args.project, args.step, "pass" if rc == 0 else "fail", f"exit {rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
