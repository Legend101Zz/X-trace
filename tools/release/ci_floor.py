#!/usr/bin/env python3
"""Prepare and publish only a sanitized summary of the v0.01 Linux CI floor."""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import platform
import re
import selectors
import signal
import shutil
import subprocess
import sys
import time
import unittest
from typing import Any

from tools.release import private_roots, run_gates


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_METADATA_BYTES = 64 * 1024
UTILITY_OUTPUT_LIMIT = 1024 * 1024
UTILITY_CLEANUP_SECONDS = 1.0
CI_RECEIPT_JSON_BUDGET = 4096
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


def _run(argv: list[str], *, cwd: pathlib.Path | None = None, timeout: float = 20) -> subprocess.CompletedProcess[str]:
    selector = selectors.DefaultSelector()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    pending: BaseException | None = None
    code: int | None = None
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=False, close_fds=True, start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        selector.close()
        raise FloorInputError from None
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                raise FloorInputError
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FloorInputError
            for key, _events in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(chunk)
                if sum(len(value) for value in captured.values()) > UTILITY_OUTPUT_LIMIT:
                    raise FloorInputError
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FloorInputError
        code = process.wait(timeout=remaining)
    except BaseException as exc:
        pending = exc
    finally:
        cleanup_ok = True
        try:
            child_running = process.poll() is None
        except OSError:
            child_running = True
            cleanup_ok = False
            pending = FloorInputError()
        if child_running:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_ok = False
            try:
                process.wait(timeout=UTILITY_CLEANUP_SECONDS)
            except (OSError, subprocess.SubprocessError):
                cleanup_ok = False
        try:
            if process.poll() is None:
                cleanup_ok = False
        except OSError:
            cleanup_ok = False
            pending = FloorInputError()
        try:
            selector.close()
        except OSError:
            cleanup_ok = False
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    cleanup_ok = False
        if not cleanup_ok:
            pending = FloorInputError()
    if pending is not None:
        if isinstance(pending, KeyboardInterrupt):
            raise pending
        raise FloorInputError from None
    if code is None:
        raise FloorInputError
    return subprocess.CompletedProcess(
        argv, code,
        bytes(captured["stdout"]).decode("utf-8", errors="replace"),
        bytes(captured["stderr"]).decode("utf-8", errors="replace"),
    )


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
        stream.write("XTRACE_PRIVATE_ROOT_ADMITTED=1\n")
    print("Private CI scratch admission passed.")
    return 0


def _summarize_tests(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root)
    private_roots.admit_directory(root, private_leaf=True)
    if not SHA_RE.fullmatch(args.source_sha):
        raise FloorInputError
    source_clean_before = _source_is_clean(pathlib.Path(args.repo), args.source_sha)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for module in RELEASE_TEST_MODULES:
        suite.addTests(loader.loadTestsFromName(module))
    discovered = sorted(_suite_ids(suite))
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
        "suiteModules": list(RELEASE_TEST_MODULES),
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


def _suite_ids(suite: unittest.TestSuite) -> list[str]:
    identities: list[str] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            identities.extend(_suite_ids(item))
        elif isinstance(item, unittest.case.TestCase):
            identities.append(_EvidenceTestResult._identity(item))
    return identities


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


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
        test_rows = test_result.get("tests")
        if not isinstance(test_rows, list) or not test_rows:
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
            and isinstance(test_count, int) and not isinstance(test_count, bool)
            and isinstance(discovered_count, int) and not isinstance(discovered_count, bool)
            and test_count == discovered_count == len(test_rows) == len(test_names)
            and len(set(test_names)) == test_count
            and all(isinstance(name, str) and name.startswith("tools.release.test_release_tools.") for name in test_names)
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
        names = [gate.name for gate in run_gates.GATES]
        if names != list(EXPECTED_GATE_NAMES) or len(names) != 23:
            raise FloorInputError
        gates = receipt.get("gates")
        if not isinstance(gates, list) or len(gates) != 23:
            raise FloorInputError
        if [item.get("name") for item in gates if isinstance(item, dict)] != list(EXPECTED_GATE_NAMES):
            raise FloorInputError
        for item in gates:
            if not isinstance(item, dict):
                raise FloorInputError
            name = item.get("name")
            status = item.get("status")
            exit_code = item.get("exitCode")
            duration = item.get("durationSeconds")
            if name not in EXPECTED_GATE_NAMES or status not in {"passed", "failed", "unreached"}:
                raise FloorInputError
            if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
                raise FloorInputError
            if duration is not None and (not isinstance(duration, (int, float)) or isinstance(duration, bool)
                                         or not math.isfinite(duration) or duration < 0 or duration > 21600):
                raise FloorInputError
            gate_rows.append({"name": name, "status": status, "exitCode": exit_code, "durationSeconds": duration})
        head = receipt.get("headBefore")
        base = receipt.get("phaseBase")
        diff_before = receipt.get("phaseDiffSha256Before")
        diff_after = receipt.get("phaseDiffSha256After")
        tree_before = receipt.get("workingTreeDigestBefore")
        tree_after = receipt.get("workingTreeDigestAfter")
        head_after = receipt.get("headAfter")
        tool_versions = receipt.get("toolVersions")
        receipt_platform = receipt.get("platform")
        decision = receipt.get("decision")
        required_versions = {"rustc", "cargo", "rustup", "java", "node", "npm", "gradle-wrapper", "python", "git"}
        valid_identity = (
            receipt.get("schemaVersion") == 1
            and receipt.get("label") == args.label
            and _valid_sha(head) and head == args.expected_head
            and head_after == head
            and _valid_sha(base) and base == args.phase_base
            and isinstance(diff_before, str) and re.fullmatch(r"[0-9a-f]{64}", diff_before)
            and isinstance(diff_after, str) and re.fullmatch(r"[0-9a-f]{64}", diff_after)
            and diff_after == diff_before
            and isinstance(tree_before, str) and re.fullmatch(r"[0-9a-f]{64}", tree_before)
            and tree_after == tree_before
            and isinstance(tool_versions, dict)
            and required_versions.issubset(tool_versions)
            and all(isinstance(tool_versions[name], str) and tool_versions[name] for name in required_versions)
            and isinstance(receipt_platform, dict)
            and receipt_platform.get("system") == "Linux"
            and receipt_platform.get("machine") == "x86_64"
        )
        all_passed = all(item["status"] == "passed" and item["exitCode"] == 0 for item in gate_rows)
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
