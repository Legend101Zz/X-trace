#!/usr/bin/env python3
"""Prepare and publish only a sanitized summary of the v0.01 Linux CI floor."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any

from tools.release import private_roots, run_gates


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_METADATA_BYTES = 64 * 1024
UTILITY_OUTPUT_LIMIT = 1024 * 1024
UTILITY_CLEANUP_SECONDS = 3.0
UTILITY_TERM_GRACE_SECONDS = 0.75
UTILITY_FINAL_SCAN_RESERVE_SECONDS = 0.35
CI_RECEIPT_JSON_BUDGET = 4096
SOURCE_COMMAND_OUTPUT_LIMIT = 64 * 1024 * 1024
SOURCE_COMMAND_TIMEOUT_SECONDS = 30.0
SOURCE_LOCK_BYTES_LIMIT = 64 * 1024 * 1024
SOURCE_LOCK_READ_SECONDS = 10.0
PRIVATE_GATE_LOG_BYTES_LIMIT = 16 * 1024 * 1024
PRIVATE_GATE_LOG_READ_SECONDS = 15.0
PRIVATE_VERSION_LOG_BYTES_LIMIT = 1024 * 1024
PRIVATE_VERSION_LOG_READ_SECONDS = 15.0
RELEASE_TEST_MODULES = (
    "tools.release.test_release_tools",
    "tools.release.test_ci_floor",
)

EXPECTED_GATE_NAMES = (
    "rust-format", "rust-clippy", "rustdoc", "java-strict",
    "node-install", "node-generate", "node-generate-check", "node-typecheck", "node-tests",
    "web-install", "web-browser-install", "web-typecheck", "web-tests", "web-api-drift",
    "web-embedded-assets", "rust-cli-spring-journey", "rust-focused", "rust-workspace",
    "rust-build", "restricted-build", "working-diff-check", "staged-diff-check", "phase-diff-check",
)

CHROMIUM_LIBRARIES = (
    "libasound.so.2", "libatk-1.0.so.0", "libatk-bridge-2.0.so.0", "libatspi.so.0",
    "libcairo.so.2", "libcups.so.2", "libdrm.so.2", "libgbm.so.1", "libglib-2.0.so.0",
    "libgobject-2.0.so.0", "libnspr4.so", "libnss3.so", "libpango-1.0.so.0",
    "libX11.so.6", "libxcb.so.1", "libXcomposite.so.1", "libXdamage.so.1", "libXext.so.6",
    "libXfixes.so.3", "libXrandr.so.2", "libxkbcommon.so.0", "libxshmfence.so.1", "libgtk-3.so.0",
)


class FloorInputError(RuntimeError):
    pass


class _EvidenceTestResult(unittest.TextTestResult):
    """Collect exact discovered test identities without parsing console prose."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.statuses: dict[str, str] = {}

    @staticmethod
    def _identity(test: unittest.case.TestCase) -> str:
        return f"{test.__class__.__module__}.{test.__class__.__qualname__}.{test._testMethodName}"

    def addSuccess(self, test: unittest.case.TestCase) -> None:
        self.statuses[self._identity(test)] = "passed"
        super().addSuccess(test)

    def addFailure(self, test: unittest.case.TestCase, err: Any) -> None:
        self.statuses[self._identity(test)] = "failed"
        super().addFailure(test, err)

    def addError(self, test: unittest.case.TestCase, err: Any) -> None:
        self.statuses[self._identity(test)] = "error"
        super().addError(test, err)

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:
        self.statuses[self._identity(test)] = "skipped"
        super().addSkip(test, reason)

    def addExpectedFailure(self, test: unittest.case.TestCase, err: Any) -> None:
        self.statuses[self._identity(test)] = "expected-failure"
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test: unittest.case.TestCase) -> None:
        self.statuses[self._identity(test)] = "unexpected-success"
        super().addUnexpectedSuccess(test)


def _utility_process_snapshot(
    *, timeout: float = 2.0, deadline: float | None = None,
) -> dict[int, tuple[int, int, str, str]]:
    """Read bounded identity facts for processes in a utility's fresh session."""
    ps = shutil.which("ps")
    if ps is None or timeout <= 0:
        raise FloorInputError
    started = time.monotonic()
    outer_deadline = deadline if deadline is not None else started + timeout + UTILITY_CLEANUP_SECONDS
    available = outer_deadline - started
    if available <= 0:
        raise FloorInputError
    reap_reserve = min(0.05, available / 3)
    probe_deadline = min(started + timeout, outer_deadline - reap_reserve)
    if probe_deadline <= started:
        raise FloorInputError
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    raw = bytearray()
    newline_count = 0
    descriptor_cleanup_error: BaseException | None = None
    try:
        process = subprocess.Popen(
            [ps, "-axo", "pid=,ppid=,pgid=,lstart=,stat="],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            close_fds=True, start_new_session=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        )
        if process.stdout is None:
            raise FloorInputError
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = probe_deadline - time.monotonic()
            if remaining <= 0:
                raise FloorInputError
            for key, _events in selector.select(remaining):
                try:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                raw.extend(chunk)
                newline_count += chunk.count(b"\n")
                if len(raw) > 1024 * 1024 or newline_count > 10000:
                    raise FloorInputError
        remaining = probe_deadline - time.monotonic()
        if remaining <= 0:
            raise FloorInputError
        if process.wait(timeout=remaining) != 0:
            raise FloorInputError
    except BaseException as original:
        cleanup_deadline = outer_deadline
        cleanup_ok = True
        if process is not None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_ok = False
            remaining = cleanup_deadline - time.monotonic()
            if remaining <= 0:
                cleanup_ok = False
            else:
                try:
                    process.wait(timeout=remaining)
                except (OSError, subprocess.SubprocessError):
                    cleanup_ok = False
        if not cleanup_ok:
            raise FloorInputError from None
        if isinstance(original, KeyboardInterrupt):
            raise original
        if isinstance(original, FloorInputError):
            raise original
        raise FloorInputError from None
    finally:
        try:
            selector.close()
        except BaseException as exc:
            descriptor_cleanup_error = exc
        if process is not None and process.stdout is not None:
            try:
                process.stdout.close()
            except BaseException as exc:
                if descriptor_cleanup_error is None:
                    descriptor_cleanup_error = exc
    if descriptor_cleanup_error is not None:
        if isinstance(descriptor_cleanup_error, KeyboardInterrupt):
            raise descriptor_cleanup_error
        raise FloorInputError from None
    try:
        lines = bytes(raw).decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        raise FloorInputError from None
    records: dict[int, tuple[int, int, str, str]] = {}
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 9 or not all(fields[index].isdigit() for index in range(3)):
            raise FloorInputError
        pid, parent, group = (int(fields[index]) for index in range(3))
        if pid <= 0 or parent < 0 or group <= 0 or pid in records:
            raise FloorInputError
        records[pid] = (parent, group, " ".join(fields[3:8]), fields[8][:1])
    if not records:
        raise FloorInputError
    return records


def _signal_utility_group_members(
    group_id: int, identities: dict[int, str], signum: int, *, deadline: float,
) -> bool:
    """Signal only members whose start identity and dedicated group still match."""
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        snapshot = _utility_process_snapshot(timeout=min(2.0, remaining), deadline=deadline)
        for pid, started_at in identities.items():
            current = snapshot.get(pid)
            if current is None or current[1] != group_id or current[2] != started_at or current[3] in {"Z", "X"}:
                continue
            if deadline - time.monotonic() <= 0:
                return False
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass
            except OSError:
                return False
        return True
    except (FloorInputError, OSError):
        return False


def _run(
    argv: list[str], *, cwd: pathlib.Path | None = None, timeout: float = 20,
    output_limit: int = UTILITY_OUTPUT_LIMIT, binary_output: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    selector = selectors.DefaultSelector()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    pending: BaseException | None = None
    code: int | None = None
    process: subprocess.Popen[bytes] | None = None
    group_id: int | None = None
    group_identities: dict[int, str] = {}
    root_identity_observed = False
    baseline: dict[int, tuple[int, int, str, str]] = {}
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FloorInputError
        baseline = _utility_process_snapshot(timeout=min(2.0, remaining), deadline=deadline)
        process = subprocess.Popen(
            argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=False, close_fds=True, start_new_session=True,
        )
        group_id = process.pid
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                raise FloorInputError
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FloorInputError
            snapshot = _utility_process_snapshot(timeout=min(2.0, remaining), deadline=deadline)
            for pid, (_parent, pgid, started_at, _state) in snapshot.items():
                prior = baseline.get(pid)
                if pgid == group_id and (prior is None or prior[2] != started_at):
                    group_identities[pid] = started_at
                    if pid == process.pid:
                        root_identity_observed = True
            for key, _events in selector.select(min(remaining, 0.05)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(chunk)
                if len(captured["stdout"]) + len(captured["stderr"]) > output_limit:
                    raise FloorInputError
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FloorInputError
        before_reap = _utility_process_snapshot(timeout=min(2.0, remaining), deadline=deadline)
        for pid, (_parent, pgid, started_at, _state) in before_reap.items():
            prior = baseline.get(pid)
            if pgid == group_id and (prior is None or prior[2] != started_at):
                group_identities[pid] = started_at
                if pid == process.pid:
                    root_identity_observed = True
        if not root_identity_observed:
            raise FloorInputError
        code = process.wait(timeout=remaining)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FloorInputError
        after_reap = _utility_process_snapshot(timeout=min(2.0, remaining), deadline=deadline)
        for pid, (_parent, pgid, started_at, _state) in after_reap.items():
            prior = baseline.get(pid)
            if pgid == group_id and (prior is None or prior[2] != started_at):
                group_identities[pid] = started_at
        if any(pid != group_id and pid in after_reap and after_reap[pid][1] == group_id
               and after_reap[pid][2] == started_at and after_reap[pid][3] not in {"Z", "X"}
               for pid, started_at in group_identities.items()):
            pending = FloorInputError()
    except BaseException as exc:
        pending = exc
    finally:
        cleanup_started = time.monotonic()
        cleanup_deadline = cleanup_started + UTILITY_CLEANUP_SECONDS
        cleanup_ok = True
        try:
            if process is not None:
                if group_id is None or not root_identity_observed:
                    try:
                        discovery_budget = min(
                            0.5,
                            cleanup_deadline - time.monotonic()
                            - UTILITY_TERM_GRACE_SECONDS - UTILITY_FINAL_SCAN_RESERVE_SECONDS,
                        )
                        if discovery_budget <= 0:
                            raise FloorInputError
                        snapshot = _utility_process_snapshot(timeout=discovery_budget, deadline=cleanup_deadline)
                        for pid, (_parent, pgid, started_at, _state) in snapshot.items():
                            prior = baseline.get(pid)
                            if pgid == group_id and (prior is None or prior[2] != started_at):
                                group_identities[pid] = started_at
                                if pid == process.pid:
                                    root_identity_observed = True
                        if not root_identity_observed:
                            cleanup_ok = False
                    except (FloorInputError, OSError):
                        cleanup_ok = False
                if group_id is not None and group_identities:
                    term_deadline = min(
                        cleanup_deadline - UTILITY_FINAL_SCAN_RESERVE_SECONDS,
                        time.monotonic() + UTILITY_TERM_GRACE_SECONDS,
                    )
                    term_signal_ok = _signal_utility_group_members(
                        group_id, group_identities, signal.SIGTERM, deadline=term_deadline,
                    )
                    cleanup_ok = term_signal_ok and cleanup_ok
                    live: list[int] = list(group_identities)
                    while time.monotonic() < term_deadline:
                        try:
                            remaining = term_deadline - time.monotonic()
                            snapshot = _utility_process_snapshot(timeout=min(0.1, remaining), deadline=term_deadline)
                        except (FloorInputError, OSError):
                            cleanup_ok = False
                            break
                        live = [pid for pid, started_at in group_identities.items()
                                if pid in snapshot and snapshot[pid][1] == group_id
                                and snapshot[pid][2] == started_at and snapshot[pid][3] not in {"Z", "X"}]
                        if not live:
                            break
                        time.sleep(min(0.025, max(0.0, term_deadline - time.monotonic())))
                    kill_deadline = cleanup_deadline - UTILITY_FINAL_SCAN_RESERVE_SECONDS
                    if live and time.monotonic() < kill_deadline:
                        kill_ok = _signal_utility_group_members(
                            group_id, group_identities, signal.SIGKILL, deadline=kill_deadline,
                        )
                        cleanup_ok = kill_ok and cleanup_ok
                    wait_deadline = cleanup_deadline - UTILITY_FINAL_SCAN_RESERVE_SECONDS
                    remaining = wait_deadline - time.monotonic()
                    if remaining <= 0:
                        cleanup_ok = False
                    else:
                        try:
                            process.wait(timeout=remaining)
                        except (OSError, subprocess.SubprocessError):
                            cleanup_ok = False
                    try:
                        remaining = cleanup_deadline - time.monotonic()
                        if remaining <= 0:
                            cleanup_ok = False
                            snapshot = {}
                        else:
                            snapshot = _utility_process_snapshot(timeout=min(2.0, remaining), deadline=cleanup_deadline)
                        if any(pid in snapshot and snapshot[pid][1] == group_id
                               and snapshot[pid][2] == started_at and snapshot[pid][3] not in {"Z", "X"}
                               for pid, started_at in group_identities.items()):
                            cleanup_ok = False
                    except (FloorInputError, OSError):
                        cleanup_ok = False
                else:
                    # The direct child is owned through Popen even when system
                    # identity scanning failed; stop that exact child, then fail
                    # closed because descendants were not accounted for.
                    try:
                        if process.poll() is None:
                            process.kill()
                        remaining = cleanup_deadline - time.monotonic()
                        if remaining <= 0:
                            cleanup_ok = False
                        else:
                            process.wait(timeout=remaining)
                    except (OSError, subprocess.SubprocessError):
                        cleanup_ok = False
                    cleanup_ok = False
                try:
                    if process.poll() is None:
                        cleanup_ok = False
                except OSError:
                    cleanup_ok = False
        except BaseException as cleanup_error:
            cleanup_ok = False
            if isinstance(cleanup_error, KeyboardInterrupt):
                pending = cleanup_error
        finally:
            for stream in ((process.stdout, process.stderr) if process is not None else ()):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as close_error:
                        cleanup_ok = False
                        if isinstance(close_error, KeyboardInterrupt):
                            pending = close_error
            try:
                selector.close()
            except BaseException as close_error:
                cleanup_ok = False
                if isinstance(close_error, KeyboardInterrupt):
                    pending = close_error
        if not cleanup_ok and not isinstance(pending, KeyboardInterrupt):
            pending = FloorInputError()
    if pending is not None:
        if isinstance(pending, KeyboardInterrupt):
            raise pending
        raise FloorInputError from None
    if code is None:
        raise FloorInputError
    stdout = bytes(captured["stdout"])
    stderr = bytes(captured["stderr"])
    if not binary_output:
        stdout = stdout.decode("utf-8", errors="replace")
        stderr = stderr.decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(argv, code, stdout, stderr)


def _read_phase_base(repo: pathlib.Path, metadata: pathlib.Path) -> str:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    try:
        fd = os.open(metadata, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = bytearray()
            while len(raw) <= MAX_METADATA_BYTES:
                chunk = os.read(fd, min(8192, MAX_METADATA_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_METADATA_BYTES:
                raise FloorInputError
        finally:
            os.close(fd)
        value = json.loads(bytes(raw).decode("utf-8", errors="strict"), object_pairs_hook=unique_keys)
    except (OSError, UnicodeError, ValueError):
        raise FloorInputError from None
    if not isinstance(value, dict):
        raise FloorInputError
    base = value.get("baselineSha")
    if not isinstance(base, str) or SHA_RE.fullmatch(base) is None:
        raise FloorInputError
    if _run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=repo).returncode != 0:
        raise FloorInputError
    if _run(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=repo).returncode != 0:
        raise FloorInputError
    return base


def _verify_tools(repo: pathlib.Path, *, expected_java: int | None, expected_node: int | None) -> None:
    required = ("python3", "git", "cargo", "rustc", "rustup", "java", "node", "npm", "lsof", "openssl", "ldconfig")
    if any(shutil.which(name) is None for name in required):
        raise FloorInputError
    gradle_wrapper = repo / "adapters/java/gradlew"
    if not gradle_wrapper.is_file() or not os.access(gradle_wrapper, os.X_OK):
        raise FloorInputError
    openssl_result = _run(["openssl", "version"])
    if openssl_result.returncode != 0:
        raise FloorInputError
    openssl = openssl_result.stdout.strip()
    if re.match(r"^OpenSSL 3\.[0-9]+\.[0-9]+(?:\s|$)", openssl) is None:
        raise FloorInputError
    rust_toolchain = _run(["rustup", "show", "active-toolchain"])
    if rust_toolchain.returncode != 0 or not rust_toolchain.stdout.strip().startswith("stable-"):
        raise FloorInputError
    if expected_node is not None:
        node_result = _run(["node", "--version"])
        if node_result.returncode != 0:
            raise FloorInputError
        node = node_result.stdout.strip()
        if re.fullmatch(r"v\d+\.\d+\.\d+", node) is None or int(node[1:].split(".", 1)[0]) != expected_node:
            raise FloorInputError
    if expected_java is not None:
        java_result = _run(["java", "-version"])
        if java_result.returncode != 0:
            raise FloorInputError
        java = java_result.stderr
        match = re.search(r'\bversion "(\d+)(?:\.|")', java)
        if match is None or int(match.group(1)) != expected_java:
            raise FloorInputError
    lsof_version = _run([shutil.which("lsof") or "lsof", "-v"], timeout=10)
    if lsof_version.returncode != 0:
        raise FloorInputError
    loader = _run(["ldconfig", "-p"], timeout=10)
    if loader.returncode != 0:
        raise FloorInputError
    available = set(re.findall(r"\b(?:lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*)\b", loader.stdout))
    if not set(CHROMIUM_LIBRARIES).issubset(available):
        raise FloorInputError


def _identity(repo: pathlib.Path, metadata: pathlib.Path, expected_head: str) -> tuple[str, str]:
    if not repo.is_absolute():
        repo = repo.absolute()
    if not metadata.is_absolute():
        metadata = repo / metadata
    if not SHA_RE.fullmatch(expected_head):
        raise FloorInputError
    head_result = _run(["git", "rev-parse", "HEAD"], cwd=repo)
    if head_result.returncode != 0:
        raise FloorInputError
    head = head_result.stdout.strip()
    if head != expected_head:
        raise FloorInputError
    status = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo)
    if status.returncode != 0 or status.stdout:
        raise FloorInputError
    base = _read_phase_base(repo, metadata)
    github_env = os.environ.get("GITHUB_ENV")
    if not github_env:
        raise FloorInputError
    with open(github_env, "a", encoding="utf-8") as stream:
        stream.write(f"XTRACE_PHASE_BASE_SHA={base}\n")
        stream.write(f"XTRACE_EXPECTED_HEAD_SHA={head}\n")
    return head, base


def _preflight_source(args: argparse.Namespace) -> int:
    repo = pathlib.Path(args.repo)
    head, base = _identity(repo, pathlib.Path(args.phase_metadata), args.expected_head)
    if shutil.which("python3") is None or shutil.which("git") is None or shutil.which("lsof") is None:
        raise FloorInputError
    openssl_result = _run(["openssl", "version"])
    if openssl_result.returncode != 0:
        raise FloorInputError
    openssl = openssl_result.stdout.strip()
    if re.match(r"^OpenSSL 3\.[0-9]+\.[0-9]+(?:\s|$)", openssl) is None:
        raise FloorInputError
    if _run([shutil.which("lsof") or "lsof", "-v"], timeout=10).returncode != 0:
        raise FloorInputError
    print(json.dumps({"sourceSha": head, "phaseBaseSha": base, "preflight": "passed"}, sort_keys=True))
    return 0


def _preflight(args: argparse.Namespace) -> int:
    repo = pathlib.Path(args.repo)
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise FloorInputError
    expected_tuple = {(17, 22): "jdk17-node22", (21, 24): "jdk21-node24"}.get(
        (args.java_major, args.node_major)
    )
    if args.tuple != expected_tuple:
        raise FloorInputError
    head, base = _identity(repo, pathlib.Path(args.phase_metadata), args.expected_head)
    _verify_tools(repo, expected_java=args.java_major, expected_node=args.node_major)
    print(json.dumps({
        "preflight": "passed", "runnerOS": "Linux", "architecture": "x86_64",
        "sourceSha": head, "phaseBaseSha": base,
        "compatibilityTuple": args.tuple,
    }, sort_keys=True))
    return 0


def _prepare_private_root(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    if not root.is_absolute() or ".." in root.parts:
        raise FloorInputError
    os.umask(0o077)
    private_roots.preflight_directory(root, must_be_absent=True)
    private_roots.ensure_private_directory(root, must_create=True)
    scratch = root / "tmp"
    private_roots.preflight_directory(scratch, must_be_absent=True)
    private_roots.ensure_private_directory(scratch, must_create=True)
    private_roots.admit_directory(root, private_leaf=True)
    private_roots.admit_directory(scratch, private_leaf=True)
    github_env = os.environ.get("GITHUB_ENV")
    if not github_env:
        raise FloorInputError
    with open(github_env, "a", encoding="utf-8") as stream:
        stream.write(f"XTRACE_TEST_SCRATCH_ROOT={scratch}\n")
        stream.write(f"XTRACE_TEST_PRIVATE_SCRATCH={scratch}\n")
        stream.write(f"TMPDIR={scratch}\n")
        stream.write(f"TMP={scratch}\n")
        stream.write(f"TEMP={scratch}\n")
        stream.write("XTRACE_PRIVATE_ROOT_ADMITTED=1\n")
    print("Private CI scratch admission passed.")
    return 0


def _summarize_tests(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    private_roots.admit_directory(root, private_leaf=True)
    scratch_value = os.environ.get("TMPDIR")
    if (not scratch_value or os.environ.get("TMP") != scratch_value
            or os.environ.get("TEMP") != scratch_value):
        raise FloorInputError
    scratch = pathlib.Path(scratch_value)
    private_roots.admit_directory(scratch, private_leaf=True)
    if pathlib.Path(tempfile.gettempdir()) != scratch:
        raise FloorInputError
    if not SHA_RE.fullmatch(args.source_sha):
        raise FloorInputError
    source_clean_before = _source_is_clean(pathlib.Path(args.repo), args.source_sha)
    suite = _load_release_test_suite()
    discovered = sorted(_suite_ids(suite))
    if not discovered or len(discovered) != len(set(discovered)):
        raise FloorInputError
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=_EvidenceTestResult)
    run_result = runner.run(suite)
    source_clean_after = _source_is_clean(pathlib.Path(args.repo), args.source_sha)
    recorded = sorted(run_result.statuses)
    tests = [{"name": name, "status": run_result.statuses[name]} for name in recorded]
    skipped = sum(item["status"] == "skipped" for item in tests)
    failed = sum(item["status"] in {"failed", "error", "expected-failure", "unexpected-success"} for item in tests)
    complete = (
        bool(discovered) and discovered == recorded and run_result.testsRun == len(discovered)
        and not run_result.errors and not run_result.failures and not run_result.unexpectedSuccesses
        and all(item["status"] == "passed" for item in tests)
        and source_clean_before and source_clean_after
    )
    result = {
        "schemaVersion": 1,
        "sourceSha": args.source_sha,
        "sourceIdentityVerified": source_clean_before and source_clean_after,
        "testScratchAdmissionVerified": True,
        "suiteModules": list(RELEASE_TEST_MODULES),
        "discoveredTestIds": discovered,
        "status": "passed" if complete and failed == 0 and skipped == 0 else "failed",
        "discoveredCount": len(discovered),
        "testCount": len(tests),
        "failedCount": failed,
        "skippedCount": skipped,
        "tests": tests,
    }
    private_roots.atomic_write_private(
        root / "release-tool-tests-summary.json",
        (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    print(json.dumps({
        "releaseToolTests": result["status"], "testCount": len(tests),
        "failedCount": failed, "skippedCount": result["skippedCount"],
        "sourceSha": args.source_sha,
    }, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


def _source_is_clean(repo: pathlib.Path, expected_head: str) -> bool:
    head = _run(["git", "rev-parse", "HEAD"], cwd=repo)
    status = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo)
    return (head.returncode == 0 and head.stdout.strip() == expected_head
            and status.returncode == 0 and not status.stdout)


def _bounded_git_output(repo: pathlib.Path, *arguments: str) -> bytes:
    """Capture finite Git output without decoding bytes used by source hashes."""
    argv = ["git", *arguments]
    result = _run(
        argv, cwd=repo, timeout=SOURCE_COMMAND_TIMEOUT_SECONDS,
        output_limit=SOURCE_COMMAND_OUTPUT_LIMIT, binary_output=True,
    )
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        raise FloorInputError
    return result.stdout


def _bounded_source_file_sha256(path: pathlib.Path) -> str:
    """Hash a regular source lockfile with finite bytes and identity checks."""
    if path.is_symlink():
        raise FloorInputError
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > SOURCE_LOCK_BYTES_LIMIT:
            raise FloorInputError
        deadline = time.monotonic() + SOURCE_LOCK_READ_SECONDS
        digest = hashlib.sha256()
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise FloorInputError
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > SOURCE_LOCK_BYTES_LIMIT:
                raise FloorInputError
            digest.update(chunk)
        after = os.fstat(fd)
        named = path.stat(follow_symlinks=False)
        identity_before = (before.st_dev, before.st_ino, before.st_uid, before.st_mode, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_size, after.st_mtime_ns)
        identity_named = (named.st_dev, named.st_ino, named.st_uid, named.st_mode, named.st_size, named.st_mtime_ns)
        if identity_before != identity_after or identity_after != identity_named:
            raise FloorInputError
        return digest.hexdigest()
    finally:
        os.close(fd)


def _source_proofs(repo: pathlib.Path, expected_head: str, phase_base: str) -> dict[str, Any]:
    """Recompute exact clean-source proofs from bounded Git and lockfile reads."""
    head = _bounded_git_output(repo, "rev-parse", "--verify", "HEAD").decode("ascii", "strict").strip()
    base = _bounded_git_output(repo, "rev-parse", "--verify", f"{phase_base}^{{commit}}").decode("ascii", "strict").strip()
    ancestry = _bounded_git_output(repo, "merge-base", "--is-ancestor", phase_base, "HEAD")
    status = _bounded_git_output(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    working = _bounded_git_output(repo, "diff", "--binary", "HEAD")
    cached = _bounded_git_output(repo, "diff", "--cached", "--binary", "HEAD")
    if head != expected_head or base != phase_base or ancestry or status or working or cached:
        raise FloorInputError
    phase_diff = _bounded_git_output(repo, "diff", "--binary", f"{phase_base}...HEAD")
    lock_names = (
        "Cargo.lock", "adapters/java/gradle.lockfile",
        "adapters/node/package-lock.json", "web/app/package-lock.json",
    )
    locks = {name: _bounded_source_file_sha256(repo / name) for name in lock_names}
    return {
        "head": head,
        "phaseBase": base,
        "workingTreeDigest": hashlib.sha256(b"\0\0").hexdigest(),
        "phaseDiffSha256": hashlib.sha256(phase_diff).hexdigest(),
        "dependencyLockSha256": locks,
    }


def _suite_ids(suite: unittest.TestSuite) -> list[str]:
    identities: list[str] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            identities.extend(_suite_ids(item))
        elif isinstance(item, unittest.case.TestCase):
            identities.append(_EvidenceTestResult._identity(item))
    return identities


def _load_release_test_suite() -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for module in RELEASE_TEST_MODULES:
        suite.addTests(loader.loadTestsFromName(module))
    return suite


def _discover_release_test_ids() -> list[str]:
    suite = _load_release_test_suite()
    identities = _suite_ids(suite)
    if not identities or len(identities) != len(set(identities)):
        raise FloorInputError
    return sorted(identities)


def _private_file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    fd = private_roots.open_private_file_read(path)
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    deadline = time.monotonic() + PRIVATE_GATE_LOG_READ_SECONDS
    total = 0
    with stream:
        while True:
            if time.monotonic() >= deadline:
                raise FloorInputError
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > PRIVATE_GATE_LOG_BYTES_LIMIT:
                raise FloorInputError
            digest.update(chunk)
    return digest.hexdigest()


def _private_log_digest_and_first_line(path: pathlib.Path) -> tuple[str, str]:
    digest = hashlib.sha256()
    fd = private_roots.open_private_file_read(path)
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    raw = bytearray()
    total = 0
    deadline = time.monotonic() + PRIVATE_VERSION_LOG_READ_SECONDS
    with stream:
        while True:
            if time.monotonic() >= deadline:
                raise FloorInputError
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > PRIVATE_VERSION_LOG_BYTES_LIMIT:
                raise FloorInputError
            digest.update(chunk)
            raw.extend(chunk)
    if not raw:
        raise FloorInputError
    return digest.hexdigest(), run_gates._first_nonempty_version_line(bytes(raw))


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _successful_settle_report(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    initial = value.get("initialIdentities")
    return (
        value.get("eligible") is True and value.get("settled") is True
        and isinstance(initial, list) and bool(initial)
        and type(value.get("initialCandidateCount")) is int
        and value["initialCandidateCount"] == len(initial)
        and value.get("latestIdentities") == []
        and type(value.get("latestCandidateCount")) is int
        and value["latestCandidateCount"] == 0
        and type(value.get("globalRescanCount")) is int and value["globalRescanCount"] > 0
        and type(value.get("pollCount")) is int and value["pollCount"] > 0
        and isinstance(value.get("waitSeconds"), (int, float))
        and not isinstance(value.get("waitSeconds"), bool)
        and 0 <= value["waitSeconds"] <= 120
        and value.get("error") is None
    )


def _sanitize_floor(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    private_roots.admit_directory(root, private_leaf=True)
    if not re.fullmatch(r"floor-[A-Za-z0-9_-]{1,96}", args.label):
        raise FloorInputError
    receipt_path = root / "release-gates" / args.label / "receipt.json"
    test_summary_path = root / "release-tool-tests-summary.json"
    tuple_is_supported = args.tuple in {"jdk17-node22", "jdk21-node24"}
    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "xtrace-v001-linux-x86_64-source-floor-summary",
        "sourceSha": args.expected_head if _valid_sha(args.expected_head) else None,
        "phaseBaseSha": args.phase_base if _valid_sha(args.phase_base) else None,
        "compatibilityTuple": args.tuple if tuple_is_supported else "unavailable",
        "architecture": "x86_64",
        "floorStatus": "unreached",
        "fullReleaseToolTests": {"status": "unavailable", "testCount": None, "skippedCount": None},
        "gateCount": 0,
        "gates": [],
        "toolVersionNamesRecordedPrivately": False,
        "rawLogs": "ephemeral owner-private job storage only; not uploaded",
        "independentRawReviewAfterJob": "unavailable; no verified private artifact facility configured",
        "packageAcceptance": "not run; requires a reviewed P07B candidate artifact",
        "releaseAcceptance": False,
    }
    gate_rows: list[dict[str, Any]] = []
    try:
        if (not tuple_is_supported or not _valid_sha(args.expected_head)
                or not _valid_sha(args.phase_base)):
            raise FloorInputError
        test_result = private_roots.read_private_json(test_summary_path)
        if not isinstance(test_result, dict):
            raise FloorInputError
        repo = pathlib.Path(args.repo)
        if not _source_is_clean(repo, args.expected_head):
            raise FloorInputError
        source_proofs = _source_proofs(repo, args.expected_head, args.phase_base)
        discovered_now = _discover_release_test_ids()
        if not _source_is_clean(repo, args.expected_head):
            raise FloorInputError
        if _source_proofs(repo, args.expected_head, args.phase_base) != source_proofs:
            raise FloorInputError
        test_rows = test_result.get("tests")
        discovered_names = test_result.get("discoveredTestIds")
        if not isinstance(test_rows, list) or not test_rows or not isinstance(discovered_names, list):
            raise FloorInputError
        test_names = [item.get("name") for item in test_rows if isinstance(item, dict)]
        test_statuses = [item.get("status") for item in test_rows if isinstance(item, dict)]
        test_count = test_result.get("testCount")
        discovered_count = test_result.get("discoveredCount")
        failed_count = test_result.get("failedCount")
        skipped_count = test_result.get("skippedCount")
        tests_match = (
            type(test_result.get("schemaVersion")) is int and test_result.get("schemaVersion") == 1
            and test_result.get("suiteModules") == list(RELEASE_TEST_MODULES)
            and test_result.get("sourceSha") == args.expected_head
            and test_result.get("sourceIdentityVerified") is True
            and test_result.get("testScratchAdmissionVerified") is True
            and discovered_names == discovered_now
            and len(discovered_names) == len(set(discovered_names))
            and isinstance(test_count, int) and not isinstance(test_count, bool)
            and isinstance(discovered_count, int) and not isinstance(discovered_count, bool)
            and test_count == discovered_count == len(test_rows) == len(test_names)
            and len(set(test_names)) == test_count
            and test_names == discovered_names
            and test_statuses == ["passed"] * test_count
            and type(failed_count) is int and failed_count == 0
            and type(skipped_count) is int and skipped_count == 0
            and test_result.get("status") == "passed"
        )
        summary["fullReleaseToolTests"] = {
            "status": "passed" if tests_match else "failed",
            "testCount": test_count if isinstance(test_count, int) and not isinstance(test_count, bool) else None,
            "skippedCount": skipped_count if type(skipped_count) is int else None,
        }
        if not tests_match:
            raise FloorInputError
        receipt = private_roots.read_private_json(
            receipt_path,
            maximum_nodes=CI_RECEIPT_JSON_BUDGET,
            maximum_commas=CI_RECEIPT_JSON_BUDGET,
        )
        if not isinstance(receipt, dict):
            raise FloorInputError
        names = [gate.name for gate in run_gates.GATES]
        if names != list(EXPECTED_GATE_NAMES) or len(names) != 23:
            raise FloorInputError
        gates = receipt.get("gates")
        if not isinstance(gates, list) or len(gates) != 23:
            raise FloorInputError
        if [item.get("name") for item in gates if isinstance(item, dict)] != list(EXPECTED_GATE_NAMES):
            raise FloorInputError
        expected_gate_by_name = {gate.name: gate for gate in run_gates.GATES}
        for item in gates:
            if not isinstance(item, dict):
                raise FloorInputError
            name = item.get("name")
            gate = expected_gate_by_name.get(name)
            exit_code = item.get("exitCode")
            if (gate is None or item.get("status") != "passed"
                    or type(exit_code) is not int or exit_code != 0):
                raise FloorInputError
            duration = item.get("durationSeconds")
            if (not isinstance(duration, (int, float)) or isinstance(duration, bool)
                    or not math.isfinite(duration) or duration < 0 or duration > 21600):
                raise FloorInputError
            expected_argv = list(gate.argv)
            expected_cwd = gate.cwd
            if gate.env == "phase-diff":
                expected_argv = ["git", "diff", "--check", f"{args.phase_base}...HEAD"]
            elif gate.env == "restricted":
                cargo = shutil.which("cargo")
                if not cargo:
                    raise FloorInputError
                expected_argv = [cargo, *gate.argv[1:]]
            if item.get("argv") != expected_argv or item.get("cwd") != expected_cwd:
                raise FloorInputError
            if (item.get("cleanupUncertain") not in {None, False}
                    or any(field in item for field in (
                        "sourceIdentityAfter", "integrityFailure", "artifactFinalization", "logHash", "reason",
                    ))):
                raise FloorInputError
            expected_log = f"logs/{name}.log"
            if item.get("log") != expected_log or not _valid_sha256(item.get("logSha256")):
                raise FloorInputError
            actual_log = receipt_path.parent / expected_log
            if _private_file_sha256(actual_log) != item["logSha256"]:
                raise FloorInputError
            if item.get("headBefore") != args.expected_head or item.get("headAfter") != args.expected_head:
                raise FloorInputError
            row_tree_before = item.get("workingTreeDigestBefore")
            row_tree_after = item.get("workingTreeDigestAfter")
            row_diff_before = item.get("phaseDiffSha256Before")
            row_diff_after = item.get("phaseDiffSha256After")
            if (not _valid_sha256(row_tree_before) or row_tree_after != row_tree_before
                    or row_tree_before != source_proofs["workingTreeDigest"]
                    or not _valid_sha256(row_diff_before) or row_diff_after != row_diff_before
                    or row_diff_before != source_proofs["phaseDiffSha256"]):
                raise FloorInputError
            settle = item.get("naturalExitSettle")
            if settle is not None and not _successful_settle_report(settle):
                raise FloorInputError
            gate_rows.append({
                "name": name, "status": "passed", "exitCode": 0,
                "durationSeconds": duration, "logSha256": item["logSha256"],
                "sourceProof": {
                    "headBefore": args.expected_head, "headAfter": args.expected_head,
                    "workingTreeDigestBefore": row_tree_before,
                    "workingTreeDigestAfter": row_tree_after,
                    "phaseDiffSha256Before": row_diff_before,
                    "phaseDiffSha256After": row_diff_after,
                },
            })
        head = receipt.get("headBefore")
        base = receipt.get("phaseBase")
        diff_before = receipt.get("phaseDiffSha256Before")
        diff_after = receipt.get("phaseDiffSha256After")
        tree_before = receipt.get("workingTreeDigestBefore")
        tree_after = receipt.get("workingTreeDigestAfter")
        head_after = receipt.get("headAfter")
        tool_versions = receipt.get("toolVersions")
        receipt_platform = receipt.get("platform")
        lock_hashes = receipt.get("dependencyLockSha256")
        decision = receipt.get("decision")
        required_versions = {name for name, _argv, _cwd in run_gates.VERSION_COMMANDS}
        if not isinstance(tool_versions, dict):
            raise FloorInputError
        version_probes = receipt.get("versionProbes")
        if not isinstance(version_probes, list) or len(version_probes) != len(run_gates.VERSION_COMMANDS):
            raise FloorInputError
        probes_by_name = {item.get("name"): item for item in version_probes if isinstance(item, dict)}
        if len(probes_by_name) != len(version_probes) or set(probes_by_name) != required_versions:
            raise FloorInputError
        for name, argv, cwd in run_gates.VERSION_COMMANDS:
            probe = probes_by_name[name]
            if (probe.get("argv") != list(argv) or probe.get("cwd") != cwd
                    or probe.get("status") != "passed" or type(probe.get("exitCode")) is not int
                    or probe.get("exitCode") != 0
                    or probe.get("cleanupUncertain") not in {None, False}
                    or any(field in probe for field in (
                        "sourceIdentityAfter", "integrityFailure", "artifactFinalization", "logHash",
                    ))
                    or not _valid_sha256(probe.get("logSha256"))
                    or probe.get("log") != f"logs/version-{name}.log"):
                raise FloorInputError
            probe_duration = probe.get("durationSeconds")
            if (not isinstance(probe_duration, (int, float)) or isinstance(probe_duration, bool)
                    or not math.isfinite(probe_duration) or probe_duration < 0 or probe_duration > 21600):
                raise FloorInputError
            probe_digest, first_line = _private_log_digest_and_first_line(receipt_path.parent / probe["log"])
            if (probe_digest != probe["logSha256"] or tool_versions.get(name) != first_line):
                raise FloorInputError
            settle = probe.get("naturalExitSettle")
            if settle is not None and not _successful_settle_report(settle):
                raise FloorInputError
        expected_java, expected_node = {
            "jdk17-node22": (17, 22), "jdk21-node24": (21, 24),
        }[args.tuple]
        java_match = re.search(r'\bversion "(\d+)', tool_versions.get("java", ""))
        node_match = re.match(r"v(\d+)\.\d+\.\d+$", tool_versions.get("node", ""))
        valid_identity = (
            type(receipt.get("schemaVersion")) is int and receipt.get("schemaVersion") == 1
            and receipt.get("label") == args.label
            and receipt.get("cacheKeys") == list(run_gates.CACHE_NAMES)
            and receipt.get("restrictedTargetKey") == f"cargo-target-restricted-{args.label}"
            and isinstance(lock_hashes, dict)
            and set(lock_hashes) == {"Cargo.lock", "adapters/java/gradle.lockfile", "adapters/node/package-lock.json", "web/app/package-lock.json"}
            and lock_hashes == source_proofs["dependencyLockSha256"]
            and not any(field in receipt for field in ("integrityFailure", "error", "leaseRetention"))
            and _valid_sha(head) and head == args.expected_head
            and head_after == head
            and _valid_sha(base) and base == args.phase_base
            and _valid_sha256(diff_before)
            and _valid_sha256(diff_after)
            and diff_after == diff_before == source_proofs["phaseDiffSha256"]
            and _valid_sha256(tree_before)
            and tree_after == tree_before == source_proofs["workingTreeDigest"]
            and isinstance(tool_versions, dict)
            and set(tool_versions) == required_versions
            and all(isinstance(tool_versions[name], str) and tool_versions[name]
                    and tool_versions[name] not in {"unavailable", "no version output"}
                    for name in required_versions)
            and java_match is not None and int(java_match.group(1)) == expected_java
            and node_match is not None and int(node_match.group(1)) == expected_node
            and isinstance(receipt_platform, dict)
            and receipt_platform.get("system") == "Linux"
            and receipt_platform.get("machine") == "x86_64"
        )
        all_passed = len(gate_rows) == len(EXPECTED_GATE_NAMES)
        if not valid_identity:
            floor_status = "invalid"
        elif decision == "checks_passed_for_review" and all_passed and summary["fullReleaseToolTests"]["status"] == "passed":
            floor_status = "checks_passed_for_review"
        elif decision == "failed":
            floor_status = "failed"
        else:
            floor_status = "invalid"
        summary.update({
            "sourceSha": head if _valid_sha(head) else summary["sourceSha"],
            "phaseBaseSha": base if _valid_sha(base) else summary["phaseBaseSha"],
            "floorStatus": floor_status,
            "gateCount": len(gate_rows),
            "gates": gate_rows,
            "toolVersionNamesRecordedPrivately": True,
        })
        if _source_proofs(repo, args.expected_head, args.phase_base) != source_proofs:
            raise FloorInputError
    except (FloorInputError, OSError, RuntimeError, ValueError, TypeError):
        summary["floorStatus"] = "invalid" if receipt_path.exists() else "unreached"
        summary["gates"] = []
        summary["gateCount"] = 0
    private_roots.atomic_write_private(
        root / "release-floor-summary.json",
        (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode(),
    )
    print(json.dumps({"floorStatus": summary["floorStatus"], "gateCount": summary["gateCount"]}, sort_keys=True))
    return 0 if summary["floorStatus"] == "checks_passed_for_review" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--repo", required=True)
    preflight.add_argument("--phase-metadata", required=True)
    preflight.add_argument("--expected-head", required=True)
    preflight.add_argument("--java-major", type=int, required=True)
    preflight.add_argument("--node-major", type=int, required=True)
    preflight.add_argument("--tuple", required=True)
    preflight.set_defaults(handler=_preflight)
    source_preflight = commands.add_parser("preflight-source")
    source_preflight.add_argument("--repo", required=True)
    source_preflight.add_argument("--phase-metadata", required=True)
    source_preflight.add_argument("--expected-head", required=True)
    source_preflight.set_defaults(handler=_preflight_source)
    prepare = commands.add_parser("prepare-private-root")
    prepare.add_argument("--root", required=True)
    prepare.set_defaults(handler=_prepare_private_root)
    summarize_tests = commands.add_parser("summarize-tests")
    summarize_tests.add_argument("--root", required=True)
    summarize_tests.add_argument("--repo", required=True)
    summarize_tests.add_argument("--source-sha", required=True)
    summarize_tests.set_defaults(handler=_summarize_tests)
    sanitize = commands.add_parser("sanitize-floor")
    sanitize.add_argument("--root", required=True)
    sanitize.add_argument("--repo", required=True)
    sanitize.add_argument("--label", required=True)
    sanitize.add_argument("--expected-head", required=True)
    sanitize.add_argument("--phase-base", required=True)
    sanitize.add_argument("--tuple", required=True)
    sanitize.set_defaults(handler=_sanitize_floor)
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (FloorInputError, private_roots.AdmissionError, OSError, RuntimeError, ValueError):
        print("release floor: preflight or receipt processing failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
