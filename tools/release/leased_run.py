#!/usr/bin/env python3
"""Run one build or test command under both builder leases in the private cache.

Every Cargo, Gradle and npm build for the v0.01 launch goes through this runner
so that it shares the task-private cache root, takes both real leases, and is
supervised by the same process-tree ownership and global-quiescence logic as
the 23-gate floor. It is built only on the production helpers in
`private_roots` and `run_gates`; it adds no new admission, lease or process
logic of its own.

Usage:
    python3.14 -B -m tools.release.leased_run --repo <worktree> --label <new-label> \
        --cache-root <private-root> --timeout <seconds> [--wait <seconds>] \
        [--jdk-home <path>] [--expect-unittest <N>] -- <argv...>

Exit codes: 0 passed, 1 command or expectation failed, 2 invalid input or
admission failure, 3 uncertain process tree (leases retained for manual
recovery), 75 builder leases stayed busy for the whole --wait.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import subprocess
import sys
import time
from typing import Any, Callable, Sequence

if __package__:
    from . import private_roots, run_gates
else:
    import private_roots
    import run_gates


EXIT_PASSED = 0
EXIT_FAILED = 1
EXIT_INVALID = 2
EXIT_UNCERTAIN = 3
EXIT_LEASE_WAIT_EXPIRED = 75
LEASE_NAMES = ("cargo", "gradle")
LEASE_POLL_SECONDS = 15.0
MAX_LOG_BYTES = 64 * 1024 * 1024
LOG_TAIL_BYTES = 64 * 1024
LOG_NAME = "command.log"
_RAN_LINE = re.compile(r"^Ran (\d+) tests? in [0-9.]+s$")


class LeaseWaitExpired(RuntimeError):
    """Both builder leases could not be acquired within the allowed wait."""


def _is_busy(exc: BaseException) -> bool:
    return (isinstance(exc, RuntimeError) and not isinstance(exc, private_roots.AdmissionError)
            and "already owned" in str(exc))


def acquire_leases(
    leases: Sequence[run_gates.Lease],
    wait_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float | None = None,
) -> list[run_gates.Lease]:
    """Acquire every lease or none, polling while another owner holds one.

    An existing lease directory is never borrowed, broken or inspected beyond
    the production `Lease.acquire` check; this only waits for it to disappear.
    """
    poll = LEASE_POLL_SECONDS if poll_seconds is None else poll_seconds
    deadline = monotonic() + max(0.0, wait_seconds)
    while True:
        acquired: list[run_gates.Lease] = []
        busy = False
        try:
            for lease in leases:
                try:
                    private_roots.preflight_directory(lease.path, must_be_absent=True)
                except FileExistsError:
                    busy = True
                    break
            if not busy:
                for lease in leases:
                    lease.acquire()
                    if lease.borrowed or not lease.acquired:
                        raise RuntimeError("builder lease was not freshly acquired")
                    acquired.append(lease)
                return acquired
        except BaseException as exc:
            for lease in reversed(acquired):
                lease.release()
            if not _is_busy(exc):
                raise
            busy = True
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise LeaseWaitExpired("builder leases stayed busy for the whole --wait")
        sleep(min(poll, remaining))


def build_env(
    cache: pathlib.Path, scratch: pathlib.Path, base_env: dict[str, str], jdk_home: str | None,
) -> dict[str, str]:
    """The same task-scoped environment the floor uses, with per-run scratch."""
    env = dict(base_env)
    env.update({
        "CARGO_HOME": str(cache / "cargo"),
        "CARGO_TARGET_DIR": str(cache / "cargo-target"),
        "GRADLE_USER_HOME": str(cache / "gradle"),
        "NPM_CONFIG_CACHE": str(cache / "npm"),
        "PLAYWRIGHT_BROWSERS_PATH": str(cache / "playwright"),
        "XDG_CACHE_HOME": str(cache / "xdg"),
        "TMPDIR": str(scratch),
        "TMP": str(scratch),
        "TEMP": str(scratch),
        "XTRACE_TEST_SCRATCH_ROOT": str(scratch),
        "XTRACE_TEST_PRIVATE_SCRATCH": str(scratch),
    })
    if jdk_home:
        env["JAVA_HOME"] = jdk_home
        env["PATH"] = os.pathsep.join(filter(None, [str(pathlib.Path(jdk_home) / "bin"), env.get("PATH", "")]))
    return env


def parse_unittest_summary(tail: bytes) -> tuple[int | None, bool, bool]:
    """Return (tests run, plain OK, any skip/expected-failure marker)."""
    lines = tail.decode("utf-8", "replace").splitlines()
    ran: int | None = None
    result_line: str | None = None
    for index in range(len(lines) - 1, -1, -1):
        match = _RAN_LINE.match(lines[index].strip())
        if match:
            ran = int(match.group(1))
            following = [line.strip() for line in lines[index + 1:] if line.strip()]
            result_line = following[0] if following else None
            break
    marked = result_line is not None and result_line.startswith("OK (")
    return ran, result_line == "OK", marked


def _read_log_tail(log_path: pathlib.Path) -> tuple[bytes, int]:
    fd = private_roots.open_private_file_read(log_path)
    try:
        size = os.fstat(fd).st_size
        os.lseek(fd, max(0, size - LOG_TAIL_BYTES), os.SEEK_SET)
        data = bytearray()
        while len(data) < LOG_TAIL_BYTES:
            chunk = os.read(fd, LOG_TAIL_BYTES - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data), size
    finally:
        os.close(fd)


def _source_identity(repo: pathlib.Path) -> dict[str, Any]:
    """HEAD plus digests of the working tree; uncommitted edits are allowed."""
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if status.returncode:
        raise RuntimeError("cannot capture working-tree status")
    return {
        "head": run_gates._git(repo, "rev-parse", "HEAD").lower(),
        "statusSha256": hashlib.sha256(status.stdout).hexdigest(),
        "dirtyEntries": sum(1 for entry in status.stdout.split(b"\0") if entry),
        "workingTreeDigest": run_gates._tree_state_digest(repo),
    }


def _summary(label: str, decision: str, exit_code: int | None, duration: float | None,
             log_sha256: str | None, cleanup: list[str]) -> dict[str, Any]:
    return {
        "label": label, "decision": decision, "exitCode": exit_code,
        "durationSeconds": duration, "logSha256": log_sha256, "leaseCleanup": cleanup,
    }


def run(
    args: argparse.Namespace,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    out: Callable[[str], None] = print,
) -> int:
    """Execute one command under both leases; returns the runner exit code."""
    if os.name != "posix":
        raise ValueError("leased runs require a POSIX host")
    argv = list(args.argv)
    if not argv or any(not isinstance(item, str) or "\0" in item for item in argv):
        raise ValueError("a command is required after --")
    if not run_gates.LABEL_RE.fullmatch(args.label):
        raise ValueError("--label must contain only letters, digits, dot, underscore, and hyphen")
    for name in ("timeout", "wait"):
        value = getattr(args, name)
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(value) or value < 0 or (name == "timeout" and value <= 0)):
            raise ValueError(f"--{name} must be a finite number of seconds")
    expect = args.expect_unittest
    if expect is not None and (not isinstance(expect, int) or isinstance(expect, bool) or expect < 1):
        raise ValueError("--expect-unittest must be a positive integer")
    repo = pathlib.Path(args.repo).expanduser().resolve(strict=True)
    if not (repo / ".git").exists():
        raise ValueError("--repo must be a Git checkout")
    jdk_home = None
    if args.jdk_home:
        jdk_path = pathlib.Path(args.jdk_home)
        if not jdk_path.is_absolute() or not (jdk_path / "bin" / "java").is_file():
            raise ValueError("--jdk-home must be an absolute JDK directory")
        jdk_home = str(jdk_path)
    cache = private_roots.normalize_directory_path(args.cache_root)
    token = secrets.token_hex(16)  # never printed or recorded

    release_root = cache / "release-gates"
    run_dir = release_root / args.label
    logs_dir = run_dir / "logs"
    lease_root = cache / "leases"
    scratch = cache / "tmp" / f"{args.label}-scratch"
    leases = [run_gates.Lease(lease_root / name, token, args.label) for name in LEASE_NAMES]

    # Read-only admission of the root, every named child and the new label.
    private_roots.preflight_directory(cache, private_leaf=True)
    for name in run_gates.CACHE_NAMES:
        private_roots.preflight_directory(cache / name, private_leaf=True)
    private_roots.preflight_directory(release_root, private_leaf=True)
    private_roots.preflight_directory(lease_root, private_leaf=True)
    private_roots.preflight_directory(run_dir, must_be_absent=True)
    private_roots.preflight_directory(logs_dir, must_be_absent=True)
    private_roots.preflight_directory(scratch, must_be_absent=True)

    wait_started = monotonic()
    try:
        private_roots.ensure_private_directory(cache)
        for name in run_gates.CACHE_NAMES:
            private_roots.ensure_private_directory(cache / name)
        private_roots.ensure_private_directory(release_root)
        private_roots.ensure_private_directory(lease_root)
        acquired = acquire_leases(leases, args.wait, monotonic=monotonic, sleep=sleep)
    except LeaseWaitExpired as exc:
        out(json.dumps(_summary(args.label, "lease_wait_expired", None, None, None, ["not-acquired"]), sort_keys=True))
        print(f"leased run not started: {exc}", file=sys.stderr)
        return EXIT_LEASE_WAIT_EXPIRED
    waited = round(monotonic() - wait_started, 6)

    receipt: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "xtrace-leased-run",
        "label": args.label,
        "decision": "running",
        "argv0": os.path.basename(argv[0]),
        "argvCount": len(argv),
        "argvSha256": hashlib.sha256("\0".join(argv).encode("utf-8", "surrogateescape")).hexdigest(),
        "timeoutSeconds": args.timeout,
        "waitSeconds": waited,
        "cacheKeys": list(run_gates.CACHE_NAMES),
        "expectUnittest": expect,
        "jdkHomeSupplied": jdk_home is not None,
    }
    exit_code: int | None = None
    duration: float | None = None
    log_sha256: str | None = None
    runner_code = EXIT_FAILED
    retain = False
    cleanup = ["retained"] * len(acquired)
    settle_report: dict[str, Any] = {}
    try:
        roots = [cache, *(cache / name for name in run_gates.CACHE_NAMES), release_root, lease_root]
        for root in roots:
            private_roots.admit_directory(root, private_leaf=True)
        private_roots.ensure_private_directory(run_dir, must_create=True)
        private_roots.ensure_private_directory(logs_dir, must_create=True)
        private_roots.ensure_private_directory(scratch, must_create=True)
        logs_identity = private_roots.admit_directory(logs_dir, private_leaf=True)
        private_roots.admit_directory(scratch, private_leaf=True)
        env = build_env(cache, scratch, os.environ.copy(), jdk_home)
        before = _source_identity(repo)
        receipt["sourceBefore"] = before
        temp_log = logs_dir / f".{LOG_NAME}.{os.getpid()}.tmp"
        log_path = logs_dir / LOG_NAME
        attempted: BaseException | None = None
        try:
            exit_code, duration = run_gates._run(
                argv, cwd=repo, env=env, timeout=args.timeout, log_path=temp_log,
                settle_report=settle_report,
            )
        except run_gates.AttemptedGateFailure as exc:
            attempted = exc
            exit_code, duration = exc.raw_exit_code, exc.duration_seconds
            receipt["error"] = str(exc)
        except run_gates.UncertainProcessTree as exc:
            if not exc.command_started:
                raise
            exit_code, duration = exc.raw_exit_code, exc.duration_seconds
            receipt["error"] = str(exc)
            retain = True
            failed = run_gates._retain_uncertain_leases(acquired, exc)
            if failed:
                receipt["leaseRetention"] = {
                    "status": "owner records unavailable; leases retained without modification",
                    "leaseNames": failed,
                }
            runner_code = EXIT_UNCERTAIN
            receipt["decision"] = "uncertain_process_tree"
        if temp_log.exists():
            private_roots.replace_private_file(temp_log, log_path, logs_identity)
        if log_path.is_file():
            receipt["log"] = f"logs/{LOG_NAME}"
            log_sha256 = run_gates._hash_file(log_path)
            receipt["logSha256"] = log_sha256
        receipt["exitCode"] = exit_code
        receipt["durationSeconds"] = duration
        if settle_report:
            receipt["naturalExitSettle"] = settle_report
        if retain:
            pass
        elif attempted is not None:
            receipt["decision"] = "failed"
            runner_code = EXIT_FAILED
        else:
            reason = None
            tail, size = _read_log_tail(log_path)
            receipt["logBytes"] = size
            if size > MAX_LOG_BYTES:
                reason = "log-exceeded-bound"
            if exit_code != 0:
                reason = reason or "command-exit-nonzero"
            if expect is not None:
                ran, plain_ok, marked = parse_unittest_summary(tail)
                receipt["unittest"] = {"ran": ran, "ok": plain_ok, "skipOrExpectedFailureMarker": marked}
                if ran != expect or not plain_ok or marked:
                    reason = reason or "unittest-expectation-not-met"
            if reason is None:
                receipt["decision"] = "passed"
                runner_code = EXIT_PASSED
            else:
                receipt["decision"] = "failed"
                receipt["failureReason"] = reason
                runner_code = EXIT_FAILED
        receipt["sourceAfter"] = _source_identity(repo)
        receipt["sourceChangedDuringRun"] = receipt["sourceAfter"] != before
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        if isinstance(exc, run_gates.UncertainProcessTree) and exc.command_started:
            raise
        receipt["decision"] = "failed"
        receipt["error"] = (
            str(exc) if isinstance(exc, (run_gates.UncertainProcessTree, run_gates.AttemptedGateFailure))
            else type(exc).__name__
        )
        runner_code = EXIT_INVALID if isinstance(exc, (private_roots.AdmissionError, ValueError)) else EXIT_FAILED
    finally:
        if not retain:
            release_failed = False
            cleanup = []
            for lease in reversed(acquired):
                try:
                    lease.release()
                    cleanup.append("released")
                except (OSError, RuntimeError, ValueError):
                    cleanup.append("release-failed")
                    release_failed = True
            cleanup.reverse()
            if release_failed:
                receipt["decision"] = "failed"
                receipt["error"] = "builder lease release failed"
                runner_code = EXIT_UNCERTAIN
        receipt["leaseCleanup"] = cleanup
        try:
            if run_dir.is_dir():
                run_gates._atomic_json(run_dir / "receipt.json", receipt)
        except (OSError, RuntimeError, ValueError):
            receipt["receiptWriteFailed"] = True
    out(json.dumps(
        _summary(args.label, receipt["decision"], exit_code, duration, log_sha256, cleanup), sort_keys=True,
    ))
    return runner_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="worktree to run in; uncommitted edits are allowed")
    parser.add_argument("--label", required=True, help="new, never-used run label")
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--timeout", required=True, type=float, help="command timeout in seconds")
    parser.add_argument("--wait", type=float, default=0.0, help="seconds to poll for busy leases (default: do not wait)")
    parser.add_argument("--jdk-home", default=None)
    parser.add_argument("--expect-unittest", type=int, default=None, metavar="N")
    parser.add_argument("argv", nargs=argparse.REMAINDER, help="-- command and arguments")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.argv and args.argv[0] == "--":
        args.argv = args.argv[1:]
    try:
        return run(args)
    except (ValueError, private_roots.AdmissionError, FileExistsError) as exc:
        message = (
            "private cache admission failed" if isinstance(exc, private_roots.AdmissionError)
            else "run label or directory already exists" if isinstance(exc, FileExistsError)
            else str(exc)
        )
        print(f"leased run not started: {message}", file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
