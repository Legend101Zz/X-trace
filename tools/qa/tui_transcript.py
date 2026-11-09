#!/usr/bin/env python3
"""Run `xtrace tui` under a real PTY and record the transcript (stdlib only, Unix).

  tui_transcript.py --xtrace BIN --project-dir DIR --out DIR [--rows 40 --cols 120 --seconds 6]

Verdicts: not-implemented (the command exits 9, the CLI's NotImplemented code), pass (exits 0 or is stopped by the
harness after drawing and the transcript names at least one recorded route; the harness presses Enter once after the list drew so the opened recording's
request symbols are on screen), fail (anything else). The harness only
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
    if exit_code != 0 and not (stopped_by_harness and exit_code in (137, 143)):
        return "fail", f"exit {exit_code}"
    if not text.strip():
        return "fail", "empty transcript"
    if not ROUTE.search(text):
        return "fail", "transcript names no recorded route"
    return "pass", "transcript names a recorded route"


OPEN_KEY = b"\r"
LIST_ROW = re.compile(rb">\s+[0-9a-f]{8}-[0-9a-f-]{27}\s+(?:complete|partial|invalid)\s+\d+ events", re.I)


def list_observed(transcript: bytes) -> bool:
    text = ANSI.sub(b"", transcript)
    return b"recordings" in text.lower() and LIST_ROW.search(text) is not None


def run(xtrace: str, project_dir: str, seconds: float, rows: int, cols: int,
        open_recording: bool = True, observations: dict | None = None) -> tuple[int | None, bool, bytes]:
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv(xtrace, [xtrace, "tui", "--project-dir", project_dir])
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    buf = b""
    status = None
    opened = False
    stopped = False
    eof = False
    opened_at = None
    opened_offset = 0
    started = time.monotonic()

    def observe_until(deadline: float, interact: bool = False) -> None:
        nonlocal buf, status, opened, eof, opened_at, opened_offset
        while time.monotonic() < deadline and status is None:
            r, _, _ = select.select([] if eof else [fd], [], [], min(0.05, max(0, deadline - time.monotonic())))
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                buf += chunk
                eof = not chunk
            if interact and open_recording and not opened and list_observed(buf):
                try:
                    os.write(fd, OPEN_KEY)
                    opened = True
                    opened_at = round(time.monotonic() - started, 3)
                    opened_offset = len(buf)
                except OSError:
                    pass  # an exited child is judged from its actual wait status below
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = st
            if interact and opened and ROUTE.search(ANSI.sub(b"", buf[opened_offset:])):
                return  # route is observed; elapsed time alone never completes the transcript

    try:
        observe_until(started + seconds, interact=True)
        if status is None:
            stopped = True
            if list_observed(buf):
                try:
                    os.write(fd, b"q")
                except OSError:
                    pass
            observe_until(time.monotonic() + 0.5)
            if status is None:
                os.kill(pid, signal.SIGTERM)
                observe_until(time.monotonic() + 0.5)
            if status is None:
                os.kill(pid, signal.SIGKILL)
                _, status = os.waitpid(pid, 0)
        # Drain bytes already emitted by the exited child.
        while not eof:
            r, _, _ = select.select([fd], [], [], 0)
            if not r:
                break
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
    finally:
        os.close(fd)
    if observations is not None:
        observations.update({"listObserved": list_observed(buf), "inputSent": opened,
                             "open_after": opened_at,
                             "routeObservedAfterOpen": bool(opened and ROUTE.search(ANSI.sub(b"", buf[opened_offset:]))),
                             "accommodation": "Enter opens a recording after an observed list row; routes are checked in detail, not in the list"})
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
    observations = {}
    code, stopped, buf = run(a.xtrace, a.project_dir, a.seconds, a.rows, a.cols, observations=observations)
    (out / "tui.transcript.raw").write_bytes(buf)
    (out / "tui.transcript.txt").write_bytes(ANSI.sub(b"", buf))
    verdict, reason = classify(code, stopped, buf)
    doc = {"schemaVersion": 1, "kind": "tui_pty_transcript", "exitCode": code, "stoppedByHarness": stopped,
           "bytes": len(buf), "verdict": verdict, "reason": reason, "rows": a.rows, "cols": a.cols, "observations": observations}
    (out / "tui.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"tui transcript: {verdict} ({reason})")
    return {"pass": 0, "not-implemented": 3}.get(verdict, 1)


if __name__ == "__main__":
    sys.exit(main())
