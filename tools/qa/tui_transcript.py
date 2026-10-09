#!/usr/bin/env python3
"""Run `xtrace tui` under a real PTY and record the transcript (stdlib only, Unix).

  tui_transcript.py --xtrace BIN --project-dir DIR --out DIR [--rows 40 --cols 120 --seconds 6]

Verdicts: not-implemented (the command exits 9, the CLI's NotImplemented code), pass (exits 0 or is stopped by the
harness after drawing and the transcript names at least one recorded route), fail (anything else). The harness only
signals the child it forked, by PID.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import pathlib
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\x1b[=>]")
ROUTE = re.compile(rb"(/owners|/vets|/oups|GET |POST )")


def classify(exit_code: int | None, stopped_by_harness: bool, transcript: bytes) -> tuple[str, str]:
    text = ANSI.sub(b"", transcript)
    if exit_code == 9:
        return "not-implemented", "xtrace tui exited 9 (not implemented in this build)"
    if exit_code is None:
        return "fail", "no exit status"
    if exit_code not in (0,) and not stopped_by_harness:
        return "fail", f"exit {exit_code}"
    if not text.strip():
        return "fail", "empty transcript"
    if not ROUTE.search(text):
        return "fail", "transcript names no recorded route"
    return "pass", "transcript names a recorded route"


def run(xtrace: str, project_dir: str, seconds: float, rows: int, cols: int) -> tuple[int | None, bool, bytes]:
    pid, fd = pty.fork()
    if pid == 0:  # child
        try:
            os.execv(xtrace, [xtrace, "tui", "--project-dir", project_dir])
        finally:
            os._exit(127)  # exec failed: never let the child continue as a copy of this harness
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    buf = b""
    deadline = time.time() + seconds
    status = None
    stopped = False
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
    if status is None:  # the PTY closed (child exited) before we reaped it?
        for _ in range(10):
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = st
                break
            time.sleep(0.05)
    if status is None:
        stopped = True
        try:
            os.write(fd, b"q")
            time.sleep(0.5)
            done, st = os.waitpid(pid, os.WNOHANG)
            if not done:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                done, st = os.waitpid(pid, os.WNOHANG)
                if not done:
                    os.kill(pid, signal.SIGKILL)
                    _, st = os.waitpid(pid, 0)
            status = st
        except OSError:
            status = 0
    try:
        while True:
            r, _, _ = select.select([fd], [], [], 0.1)
            if not r:
                break
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    code = os.waitstatus_to_exitcode(status) if status is not None else None
    if code is not None and code < 0:
        code = 128 + -code
    return code, stopped, buf


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--xtrace", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rows", type=int, default=40)
    ap.add_argument("--cols", type=int, default=120)
    ap.add_argument("--seconds", type=float, default=6.0)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    code, stopped, buf = run(a.xtrace, a.project_dir, a.seconds, a.rows, a.cols)
    (out / "tui.transcript.raw").write_bytes(buf)
    (out / "tui.transcript.txt").write_bytes(ANSI.sub(b"", buf))
    verdict, reason = classify(code, stopped, buf)
    doc = {"schemaVersion": 1, "kind": "tui_pty_transcript", "exitCode": code, "stoppedByHarness": stopped,
           "bytes": len(buf), "verdict": verdict, "reason": reason, "rows": a.rows, "cols": a.cols}
    (out / "tui.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"tui transcript: {verdict} ({reason})")
    return {"pass": 0, "not-implemented": 3}.get(verdict, 1)


if __name__ == "__main__":
    sys.exit(main())
