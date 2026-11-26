"""Linux process containment for the dedicated hosted Medusa proof."""
import ctypes
import os
from pathlib import Path
import re
import signal
import time


def contain_children():
    # An orphaned grandchild, including one in another session, is reparented here.
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "could not establish child containment")


def reap_exited_group_children(group):
    """Reap already-exited children adopted into the supervisor from this process group."""
    if not isinstance(group, int) or group <= 1:
        raise ValueError("expected an owned process group")
    reaped = 0
    # The proof owns one launcher at a time. waitpid cannot reap a non-child,
    # and WNOHANG cannot wait for or signal a live member. Group absence is
    # still verified by the caller, including when this reap bound is reached.
    for _ in range(128):
        try:
            child, _ = os.waitpid(-group, os.WNOHANG)
        except ChildProcessError:
            break
        if not child:
            break
        reaped += 1
    return reaped


def verify_children_gone():
    """Reap owned exits, remove adopted live children by pidfd, and fail if recovery was needed."""
    deadline = time.monotonic() + 10
    recovered = False
    own_pid = os.getpid()
    while time.monotonic() < deadline:
        try:
            child, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            if recovered:
                raise RuntimeError("owned process cleanup required recovery")
            return
        if child:
            continue
        for task in Path(f"/proc/{own_pid}/task").glob("*/children"):
            try:
                pids = task.read_text().split()
            except FileNotFoundError:
                continue
            for value in pids:
                pid = int(value)
                try:
                    fd = os.pidfd_open(pid)
                except ProcessLookupError:
                    continue
                try:
                    status = Path(f"/proc/{pid}/status").read_text()
                    if re.search(rf"^PPid:\s+{own_pid}$", status, re.M):
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                        recovered = True
                except (FileNotFoundError, ProcessLookupError):
                    pass
                finally:
                    os.close(fd)
        time.sleep(0.05)
    raise TimeoutError("owned process absence could not be verified")
