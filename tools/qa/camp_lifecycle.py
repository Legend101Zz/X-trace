#!/usr/bin/env python3
"""Exercise the packaged `xtrace record` then `xtrace stop` lifecycle on the campaign project and record one step.

  camp_lifecycle.py --xtrace BIN --project-dir DIR --file SUMMARY --project P

Step `lifecycle-record-stop`: pass only when `record` exits 0 and reports a daemon pid, the pid is alive afterwards,
`stop` exits 0 and that same pid is gone, and a second `stop` does not signal anything (exit code and message are kept).
Exit 9 from either command is not-implemented. The step does NOT launch an application: the full flow (record, launch
the app through the armed capture, stop) stays the separate not-implemented step `record-stop-flow`. The harness signals
nothing itself except a pid-0 liveness probe (os.kill(pid, 0)); stopping is the product's job.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary as cs  # noqa: E402


def find_pid(doc) -> int | None:
    """First integer under a key named pid / daemonPid / daemon_pid, anywhere in the JSON document."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k in ("pid", "daemonPid", "daemon_pid") and isinstance(v, int) and v > 1:
                return v
        for v in doc.values():
            r = find_pid(v)
            if r:
                return r
    elif isinstance(doc, list):
        for v in doc:
            r = find_pid(v)
            if r:
                return r
    return None


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # liveness probe only, no signal is delivered
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def parse_json(text: str):
    for line in reversed(text.splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    try:
        return json.loads(text)
    except ValueError:
        return None


def judge(xtrace: str, project_dir: str, env: dict) -> tuple[str, str]:
    def run(*a: str) -> subprocess.CompletedProcess:
        return subprocess.run([xtrace, *a, "--project-dir", project_dir, "--json"], env=env, capture_output=True, text=True, timeout=120)

    rec = run("record")
    if rec.returncode == 9:
        return "not-implemented", "xtrace record exited 9"
    if rec.returncode != 0:
        return "fail", f"xtrace record exited {rec.returncode}"
    pid = find_pid(parse_json(rec.stdout))
    if pid is None:
        run("stop")  # do not leave a daemon behind when the document cannot be read
        return "fail", "xtrace record exited 0 but reported no daemon pid"
    if not alive(pid):
        return "fail", "the daemon pid reported by xtrace record is not alive"
    stop = run("stop")
    if stop.returncode == 9:
        return "not-implemented", "xtrace stop exited 9"
    if stop.returncode != 0:
        return "fail", f"xtrace stop exited {stop.returncode}"
    for _ in range(50):
        if not alive(pid):
            break
        time.sleep(0.2)
    else:
        return "fail", "the daemon was still alive 10 s after xtrace stop exited 0"
    again = run("stop")
    return "pass", f"record exit 0 with a live daemon, stop exit 0 and the daemon is gone; second stop exited {again.returncode} (not an error check)"


def main() -> int:
    ap = argparse.ArgumentParser()
    for n in ("xtrace", "project-dir", "file", "project"):
        ap.add_argument(f"--{n}", required=True)
    a = ap.parse_args()
    try:
        status, note = judge(a.xtrace, a.project_dir, dict(os.environ))
    except (OSError, subprocess.SubprocessError) as exc:
        status, note = "fail", f"harness error {type(exc).__name__}"
    cs.record(pathlib.Path(a.file), a.project, "lifecycle-record-stop", status, note)
    print(f"campaign step lifecycle-record-stop: {status} ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
