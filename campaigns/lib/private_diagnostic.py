"""Opt-in preservation of already captured pre-receipt child stderr, never stdout."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess

LABELS = ("host-java", "installed-payload-verify", "init", "recording-list", "stop")
MAX_STDERR = 256 << 10


def mark_root_admitted(root):
    """Write the private sibling signal only after prepare_root has returned successfully."""
    directory = root.parent / "driver"
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or any(p.is_symlink() for p in directory.parents)):
        raise ValueError("admission signal requires a private driver sibling")
    observed = root.lstat()
    doc = {"schema": "xtrace-jhipster-admission/1", "admitted": True,
           "device": observed.st_dev, "inode": observed.st_ino}
    descriptor = os.open(directory / "admission.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(doc, stream, sort_keys=True)
        stream.write("\n")


def root_admitted(root):
    """Inspect only sibling admission and root metadata before trusting any root content."""
    try:
        signal = root.parent / "driver/admission.json"
        if any(p.is_symlink() for p in (signal, *signal.parents)):
            return False
        descriptor = os.open(signal, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or info.st_size > 4096):
                return False
            doc = json.loads(stream.read(4097))
        observed = root.lstat()
        return (stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.getuid() and not observed.st_mode & 0o077
                and not any(p.is_symlink() for p in root.parents)
                and doc == {"schema": "xtrace-jhipster-admission/1", "admitted": True,
                            "device": observed.st_dev, "inode": observed.st_ino})
    except (OSError, ValueError, TypeError):
        return False


def capture_failed_stderr(env, label, stderr, exit_code, *, timed_out=False):
    """Keep the actual first failing child's stderr and exit, only in a private sink."""
    value = env.get("XCAMP_PRIVATE_CHILD_STDERR_DIR")
    phase = env.get("XCAMP_DIAGNOSTIC_PHASE")
    if not value or phase not in ("baseline", "instrumented") or label not in LABELS:
        return
    try:
        root = Path(value)
        if not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents)):
            return
        info = root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return
        status = root / f"{phase}-{label}.json"
        if status.exists():
            return
        raw = stderr.encode() if isinstance(stderr, str) else stderr
        state = "unavailable" if raw is None else "oversized" if len(raw) > MAX_STDERR else "captured"
        if state == "captured":
            descriptor = os.open(root / f"{phase}-{label}.stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
        doc = {"schema": "xtrace-private-child-stderr/1", "phase": phase, "child": label,
               "exitCode": exit_code, "timedOut": timed_out, "stderrState": state}
        descriptor = os.open(status, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(doc, stream, sort_keys=True)
            stream.write("\n")
    except (OSError, TypeError, ValueError):
        # Diagnostic retention never replaces a product or campaign failure.
        return


def run_captured(args, *, env, timeout, label, text=True):
    """Use bytes under the proof driver so retained stderr preserves the child bytes."""
    retain = bool(env.get("XCAMP_PRIVATE_CHILD_STDERR_DIR"))
    try:
        result = subprocess.run(args, env=env, capture_output=True, text=text and not retain, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        capture_failed_stderr(env, label, exc.stderr, None, timed_out=True)
        raise
    if result.returncode != 0:
        capture_failed_stderr(env, label, result.stderr, result.returncode)
    if retain and text:
        for name in ("stdout", "stderr"):
            value = getattr(result, name)
            if isinstance(value, bytes):
                setattr(result, name, value.decode())
    return result
