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

Allowed commands: cargo, gradlew, npm, npx, node, git, java, and python3/python3.14 only as
`-B -m unittest` or `-B -m tools.release.*`; shells and launchers are refused (exit 77).
Exit codes: 0 passed, 1 command or expectation failed, 2 invalid input,
admission failure or label already used, 3 uncertain process tree (leases
retained for manual recovery) or lease release failure, 4 the receipt could not
be written, 75 a live owner held a builder lease for the whole --wait, 76 a
builder lease is retained for manual recovery (waiting cannot help).
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
import shutil
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
EXIT_RECEIPT_FAILED = 4
EXIT_LEASE_WAIT_EXPIRED = 75
EXIT_LEASE_RETAINED = 76
EXIT_COMMAND_REFUSED = 77
LEASE_NAMES = run_gates.LEASE_NAMES
LEASE_POLL_SECONDS = 15.0
MAX_LOG_BYTES = 64 * 1024 * 1024
LOG_TAIL_BYTES = 64 * 1024
LOG_NAME = "command.log"
_RAN_LINE = re.compile(r"^Ran (\d+) tests? in [0-9.]+s$")
# argv[0] basenames a leased run may execute. Launchers and shells are excluded on purpose: they
# are exactly the routes (open, launchctl, osascript, docker, systemd-run, at, cron, sh) through
# which work could reach the builder caches without being a descendant of the run, which process
# provenance cannot see (ADR 0007).
ALLOWED_COMMANDS = frozenset({"cargo", "gradlew", "npm", "npx", "node", "python3", "python3.14", "git", "java"})
PYTHON_COMMANDS = frozenset({"python3", "python3.14"})
PROVENANCE_RESIDUAL = (
    "Provenance proves a process is not a fork-tree descendant of this run, not that it cannot "
    "write the builder caches. Work delegated through LaunchServices/XPC/launchctl, systemd/docker, "
    "cron/at or a persistent build daemon is outside the threat model only because the command "
    "allowlist excludes launchers and builders run with --no-daemon."
)
# Parent environment names that reach the command. Everything else (including
# ambient credentials) is dropped; task variables are added by build_env.
ENV_ALLOWLIST = frozenset({
    "PATH", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "TZ",
    "SDKROOT", "DEVELOPER_DIR", "MACOSX_DEPLOYMENT_TARGET",
    "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "JAVA_HOME",
})
ENV_ALLOWED_PREFIXES = ("LC_",)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_WORDS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH")
# Names --pass-env refuses, each because it can load or run code of the caller's choosing inside
# every tool of the build, or redirect where tools fetch from or write to.
DENIED_ENV_NAMES = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",  # inject shared objects into every process
    "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS",  # preload scripts / module roots / trust anchors
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONINSPECT",  # run or load arbitrary Python
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS", "JAVA_HOME",  # javaagents; use --jdk-home
    "MAVEN_OPTS", "BASH_ENV", "ENV", "PS4", "IFS", "SHELLOPTS", "PROMPT_COMMAND",  # shell startup injection
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN",  # run/choose compilers and linkers
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",  # trust anchors
    "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "PATH",  # task-scoped by the runner
})
DENIED_ENV_PREFIXES = (
    "DYLD_",  # macOS dynamic-loader injection
    "CARGO_",  # build.rustc-wrapper, linkers, registries via env
    "GIT_",  # exec path, ssh command, config injection
    "GRADLE_",  # GRADLE_OPTS and friends run agents; the home is task-scoped
    "NPM_CONFIG_", "NPM_",  # registry/script-shell redirection
    "XTRACE_",  # task contract names
)
DENIED_ENV_SUFFIXES = ("_PROXY",)  # route build traffic through a caller-chosen host


class LeaseWaitExpired(RuntimeError):
    """Both builder leases stayed busy (live owner) for the whole wait."""


class LeaseRetained(RuntimeError):
    """A builder lease is retained for manual recovery; waiting cannot help."""


def _lease_requires_recovery(lease: run_gates.Lease) -> bool | None:
    """Read-only, bounded check of whether an existing lease was retained."""
    try:
        private_roots.admit_directory(lease.path, private_leaf=True)
        owner = private_roots.read_private_json(lease.path / "owner.json")
    except FileNotFoundError:
        return False
    except (OSError, RuntimeError, ValueError):
        return None
    return owner.get("requiresManualRecovery") is True


def acquire_leases(
    leases: Sequence[run_gates.Lease],
    wait_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float | None = None,
) -> list[run_gates.Lease]:
    """Acquire every lease or none, polling while a live owner holds one.

    An existing lease directory is never borrowed, broken or modified. A lease
    whose owner record says it was retained for manual recovery raises
    LeaseRetained at once (waiting cannot clear it); any other existing lease is
    polled until `wait_seconds` expires, then LeaseWaitExpired.
    """
    poll = LEASE_POLL_SECONDS if poll_seconds is None else poll_seconds
    deadline = monotonic() + max(0.0, wait_seconds)
    while True:
        acquired: list[run_gates.Lease] = []
        retained = False
        try:
            existing = []
            for lease in leases:
                try:
                    private_roots.preflight_directory(lease.path, must_be_absent=True)
                except FileExistsError:
                    existing.append(lease)
            if existing:
                retained = any(_lease_requires_recovery(lease) for lease in existing)
            else:
                for lease in leases:
                    lease.acquire()
                    if lease.borrowed or not lease.acquired:
                        raise RuntimeError("builder lease was not freshly acquired")
                    acquired.append(lease)
                return acquired
        except run_gates.LeaseBusy as exc:
            for lease in reversed(acquired):
                lease.release()
            retained = exc.requires_manual_recovery is True
        except BaseException:
            for lease in reversed(acquired):
                lease.release()
            raise
        if retained:
            raise LeaseRetained("a builder lease is retained for manual recovery")
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise LeaseWaitExpired("builder leases stayed busy for the whole --wait")
        sleep(min(poll, remaining))


def build_env(
    cache: pathlib.Path, scratch: pathlib.Path, base_env: dict[str, str], jdk_home: str | None,
    pass_env: Sequence[str] = (), home: pathlib.Path | None = None,
) -> dict[str, str]:
    """Allowlisted parent environment plus the floor's task-scoped variables.

    HOME is a private directory inside the admitted scratch, so ~/.npmrc, ~/.netrc, ~/.ssh and
    friends are not reachable and tools cannot write outside the private cache. The host HOME
    is passed only when `--pass-env HOME` asks for it explicitly.
    """
    extra = set(pass_env)
    env = {
        name: value for name, value in base_env.items()
        if (name in ENV_ALLOWLIST or name in extra or name.startswith(ENV_ALLOWED_PREFIXES)) and name != "HOME"
    }
    if "HOME" in extra and "HOME" in base_env:
        env["HOME"] = base_env["HOME"]
    elif home is not None:
        env["HOME"] = str(home)
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


class CommandRefused(RuntimeError):
    """The command is not on the leased-run allowlist."""


def check_command_allowed(argv: Sequence[str]) -> None:
    """Allow only the build tools a lane needs; refuse shells and launchers."""
    name = os.path.basename(argv[0])
    if name not in ALLOWED_COMMANDS:
        raise CommandRefused("command is not on the leased-run allowlist")
    if name in PYTHON_COMMANDS:
        head = list(argv[1:4])
        ok = len(head) >= 3 and head[0] == "-B" and head[1] == "-m" and (
            head[2] == "unittest" or head[2].startswith("tools.release.")
        )
        if not ok:
            raise CommandRefused("python is allowed only as -B -m unittest or -B -m tools.release.*")


def _validate_pass_env(names: Sequence[str]) -> list[str]:
    result = []
    for name in names:
        if not _ENV_NAME.fullmatch(name) or any(word in name for word in _SECRET_WORDS):
            raise ValueError("--pass-env must name a non-secret variable such as RUST_LOG")
        if name == "HOME":
            result.append(name)  # explicit host HOME; recorded in the receipt
            continue
        if (name in DENIED_ENV_NAMES or name.startswith(DENIED_ENV_PREFIXES)
                or name.endswith(DENIED_ENV_SUFFIXES)):
            raise ValueError("--pass-env refuses names that load code or redirect the build")
        result.append(name)
    return result


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
        ["git", *run_gates.GIT_SAFE_ARGS, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo, env=run_gates._git_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if status.returncode:
        raise RuntimeError("cannot capture working-tree status")
    return {
        "head": run_gates._git(repo, "rev-parse", "HEAD").lower(),
        "statusSha256": hashlib.sha256(status.stdout).hexdigest(),
        "dirtyEntries": sum(1 for entry in status.stdout.split(b"\0") if entry),
        "workingTreeDigest": run_gates._tree_state_digest(repo),
    }


_PATH_TEXT = re.compile(r"(?<![\w.])/(?:[\w.@+%~=:,-]*/)*[\w.@+%~=:,-]+/?")


def _safe_error(exc: BaseException) -> str:
    """First line of a runner error with paths removed and a length cap."""
    text = str(exc).splitlines()[0] if str(exc).strip() else type(exc).__name__
    return _PATH_TEXT.sub("<path>", text)[:200]


def _summary(label: str, decision: str, exit_code: int | None, duration: float | None,
             log_sha256: str | None, cleanup: list[str], receipt_written: bool | None = None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "label": label, "decision": decision, "exitCode": exit_code,
        "durationSeconds": duration, "logSha256": log_sha256, "leaseCleanup": cleanup,
    }
    if receipt_written is not None:
        summary["receiptWritten"] = receipt_written
    return summary


def _not_started(out: Callable[[str], None], label: str, decision: str, message: str, code: int) -> int:
    out(json.dumps(_summary(label, decision, None, None, None, ["not-acquired"]), sort_keys=True))
    print(f"leased run not started: {message}", file=sys.stderr)
    return code


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
    pass_env = _validate_pass_env(getattr(args, "pass_env", None) or [])
    try:
        check_command_allowed(argv)
    except CommandRefused as exc:
        return _not_started(out, args.label, "command_refused", str(exc), EXIT_COMMAND_REFUSED)
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
        return _not_started(out, args.label, "lease_wait_expired", str(exc), EXIT_LEASE_WAIT_EXPIRED)
    except LeaseRetained as exc:
        return _not_started(out, args.label, "lease_retained_manual_recovery", str(exc), EXIT_LEASE_RETAINED)
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
        "passedEnvNames": sorted(pass_env),
        "privateHome": "HOME" not in pass_env,
        "hostHomePassed": "HOME" in pass_env,
        "provenanceResidual": PROVENANCE_RESIDUAL,
    }
    exit_code: int | None = None
    duration: float | None = None
    log_sha256: str | None = None
    runner_code = EXIT_FAILED
    retain = False
    claimed = False  # this process created run_dir; only then may it write there
    cleanup = ["retained"] * len(acquired)
    settle_report: dict[str, Any] = {}
    provenance_report: dict[str, Any] = {}
    released_ok = False
    try:
        # Atomically claim the label now that the leases are held: a label
        # used by anyone while we waited is refused, never overwritten.
        private_roots.ensure_private_directory(run_dir, must_create=True)
        claimed = True
        for root in (cache, *(cache / name for name in run_gates.CACHE_NAMES), release_root, lease_root):
            private_roots.admit_directory(root, private_leaf=True)
        private_roots.ensure_private_directory(logs_dir, must_create=True)
        private_roots.ensure_private_directory(scratch, must_create=True)
        private_roots.ensure_private_directory(scratch / "home", must_create=True)
        logs_identity = private_roots.admit_directory(logs_dir, private_leaf=True)
        private_roots.admit_directory(scratch, private_leaf=True)
        private_roots.admit_directory(scratch / "home", private_leaf=True)
        run_gates._write_receipt(run_dir / "receipt.json", receipt)  # "running" marker
        env = build_env(cache, scratch, os.environ.copy(), jdk_home, pass_env, scratch / "home")
        before = _source_identity(repo)
        receipt["sourceBefore"] = before
        temp_log = logs_dir / f".{LOG_NAME}.{os.getpid()}.tmp"
        log_path = logs_dir / LOG_NAME
        attempted: BaseException | None = None
        try:
            exit_code, duration = run_gates._run(
                argv, cwd=repo, env=env, timeout=args.timeout, log_path=temp_log,
                settle_report=settle_report, max_log_bytes=MAX_LOG_BYTES,
                provenance=True, provenance_report=provenance_report,
            )
        except run_gates.AttemptedGateFailure as exc:
            attempted = exc
            exit_code, duration = exc.raw_exit_code, exc.duration_seconds
            receipt["error"] = _safe_error(exc)
        except run_gates.UncertainProcessTree as exc:
            if not exc.command_started:
                raise
            exit_code, duration = exc.raw_exit_code, exc.duration_seconds
            receipt["error"] = _safe_error(exc)
            retain = True
            runner_code = EXIT_UNCERTAIN
            receipt["decision"] = "uncertain_process_tree"
            failed = run_gates._retain_uncertain_leases(acquired, exc)
            if failed:
                receipt["leaseRetention"] = {
                    "status": "owner records unavailable; leases retained without modification",
                    "leaseNames": failed,
                }
        if settle_report:
            receipt["naturalExitSettle"] = settle_report
        if provenance_report:
            receipt["provenance"] = provenance_report
        receipt["exitCode"] = exit_code
        receipt["durationSeconds"] = duration
        if temp_log.exists():
            private_roots.replace_private_file(temp_log, log_path, logs_identity)
        if log_path.is_file():
            receipt["log"] = f"logs/{LOG_NAME}"
            log_sha256 = run_gates._hash_file(log_path)
            receipt["logSha256"] = log_sha256
        if not retain:
            if attempted is not None:
                receipt["decision"] = "failed"
                runner_code = EXIT_FAILED
            else:
                reason = None
                tail, size = _read_log_tail(log_path)
                receipt["logBytes"] = size
                if exit_code == run_gates.LOG_LIMIT_EXIT_CODE or size > MAX_LOG_BYTES:
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
        label_taken = isinstance(exc, FileExistsError) and not claimed
        if retain:
            # The retained-tree result and exit code are primary; finalization
            # trouble is only recorded.
            receipt["finalizationError"] = type(exc).__name__
        else:
            receipt["decision"] = "label_in_use" if label_taken else "failed"
            receipt["error"] = (
                _safe_error(exc) if isinstance(exc, (run_gates.UncertainProcessTree, run_gates.AttemptedGateFailure))
                else type(exc).__name__
            )
            runner_code = (
                EXIT_INVALID if label_taken or isinstance(exc, (private_roots.AdmissionError, ValueError))
                else EXIT_FAILED
            )
    finally:
        if not retain:
            cleanup = []
            for lease in reversed(acquired):
                try:
                    lease.release()
                    cleanup.append("released")
                except (OSError, RuntimeError, ValueError):
                    cleanup.append("release-failed")
            cleanup.reverse()
            released_ok = all(item == "released" for item in cleanup)
            if not released_ok:
                receipt["decision"] = "failed"
                receipt["error"] = "builder lease release failed"
                runner_code = EXIT_UNCERTAIN
        receipt["leaseCleanup"] = cleanup
    # Scratch is removed through the production admission check, only after both
    # leases were released and the run passed; failed runs keep it for diagnosis.
    receipt["scratchCleanup"] = "kept"
    if claimed and released_ok and receipt["decision"] == "passed":
        try:
            private_roots.admit_directory(scratch, private_leaf=True)
            shutil.rmtree(scratch)
            receipt["scratchCleanup"] = "removed"
        except (OSError, RuntimeError, ValueError):
            receipt["scratchCleanup"] = "remove-failed"
    receipt_written = False
    if claimed:
        try:
            run_gates._write_receipt(run_dir / "receipt.json", receipt)
            receipt_written = True
        except (OSError, RuntimeError, ValueError):
            receipt_written = False
    if claimed and not receipt_written and runner_code in (EXIT_PASSED, EXIT_FAILED):
        receipt["decision"] = "receipt_write_failed"
        runner_code = EXIT_RECEIPT_FAILED
    out(json.dumps(
        _summary(args.label, receipt["decision"], exit_code, duration, log_sha256, cleanup,
                 receipt_written if claimed else None), sort_keys=True,
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
    parser.add_argument("--pass-env", action="append", default=[], metavar="NAME",
                        help="extra non-secret parent variable to pass through (repeatable)")
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
