#!/usr/bin/env python3
"""Lane CI step runner and summary merger (stdlib only; reuses the release floor grammars).

  run   : run one command with all output kept in a private log; print only allowlisted facts
          (suite/variant/step, status, exit code, counts, allowlisted failing test ids).
  merge : combine per-step fragments and the plan into summary.json plus a sanitized step summary.

Counts and diagnostics use the release tooling grammars. Public test names and
failure locations require checkout metadata; raw logs and message prose stay private.
Run from the repository root:  python3 -B -m tools.qa.lane_run <run|merge> ...
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from collections import Counter, deque
from collections.abc import Sequence
from enum import Enum

from tools.qa import canary, store_profiles
from tools.release import ci_floor

MAX_FAILING = 32
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
# Variants every selected suite must report before it can be called "pass".
EXPECTED_VARIANTS = {
    "meta": ["-"],
    "rust": ["-"],
    "java": ["17", "21", "25"],
    "node": ["22", "24"],
    "web": ["-"],
    "tui": ["-"],
}
CARGO_FAIL = re.compile(r"^test (\S+) \.\.\. FAILED$")
CARGO_RESULT = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")
GRADLE_FAIL = re.compile(r"^(?:[\w$.]+\.)?(\w+) > (\w+)(?:\(.*\))?(?:\[.*\])? FAILED$")
PY_FAIL = re.compile(r"^(?:FAIL|ERROR): (\w+) \((?:[\w.]+\.)?(\w+)\.(\w+)\)")
PY_RAN = re.compile(r"^Ran (\d+) tests? in ")
PY_FAILED = re.compile(r"^FAILED \((?:failures=(\d+))?(?:, )?(?:errors=(\d+))?")
PY_SKIPPED = re.compile(r"^(?:OK|FAILED) \(.*\bskipped=(\d+)")  # unittest: skips (and expected failures) are ignored tests
PY_XFAIL = re.compile(r"^(?:OK|FAILED) \(.*\bexpected failures=(\d+)")
NODE_PASS = re.compile(r"^\S{0,2}\s*pass (\d+)$")  # node:test spec reporter summary: "ℹ pass 12"
NODE_FAIL = re.compile(r"^\S{0,2}\s*fail (\d+)$")
NODE_SKIP = re.compile(r"^\S{0,2}\s*(?:skipped|todo|cancelled) (\d+)$")
# vitest summary: "Tests  2 failed | 70 passed | 3 skipped | 1 todo (76)"; every count token on the line is read.
VITEST_LINE = re.compile(r"^\s*Tests\s+(?=.*\d+ (?:failed|passed|skipped|todo))")
VITEST_TOKEN = re.compile(r"(\d+) (failed|passed|skipped|todo)\b")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
TAP_NOT_OK = re.compile(r"^\s*not ok \d+ - (\S+)\s*$")


def parse_output(text: str) -> dict:
    failing: list[str] = []
    dropped = 0
    passed = failed = ignored = 0
    counted = False
    for line in ANSI.sub("", text).splitlines():
        line = line.rstrip()
        cand = None
        if m := CARGO_FAIL.match(line):
            cand = m.group(1)
        elif m := GRADLE_FAIL.match(line.strip()):
            cand = f"{m.group(1)}::{m.group(2)}"
        elif m := PY_FAIL.match(line):
            cand = f"{m.group(2)}::{m.group(1)}"
        elif m := TAP_NOT_OK.match(line):
            cand = m.group(1)
        elif m := PY_RAN.match(line):
            passed += int(m.group(1))
            counted = True
        elif (m := PY_SKIPPED.match(line)) or (m2 := PY_XFAIL.match(line)):
            # "OK (skipped=N)" / "FAILED (failures=1, skipped=N)": skipped tests are counted in "Ran N", so move
            # them from passed to ignored; the failure counts of a FAILED line are read just below.
            skipped = int(m.group(1)) if m else int(m2.group(1))
            ignored += skipped
            passed -= skipped
            if line.startswith("FAILED"):
                fm = PY_FAILED.match(line)
                bad = int(fm.group(1) or 0) + int(fm.group(2) or 0)
                failed += bad
                passed -= bad
            counted = True
        elif m := PY_FAILED.match(line):
            bad = int(m.group(1) or 0) + int(m.group(2) or 0)
            failed += bad
            passed -= bad
            counted = True
        elif m := NODE_PASS.match(line):
            passed += int(m.group(1))
            counted = True
        elif m := NODE_FAIL.match(line):
            failed += int(m.group(1))
            counted = True
        elif m := NODE_SKIP.match(line):
            ignored += int(m.group(1))
        elif VITEST_LINE.match(line):
            for count, kind in VITEST_TOKEN.findall(line):
                if kind == "failed":
                    failed += int(count)
                elif kind == "passed":
                    passed += int(count)
                else:  # skipped and todo tests are ignored tests: --max-ignored 0 must fail on them
                    ignored += int(count)
            counted = True
        elif m := CARGO_RESULT.match(line):
            passed += int(m.group(1))
            failed += int(m.group(2))
            ignored += int(m.group(3))
            counted = True
        if cand is not None:
            if ci_floor._valid_test_id(cand):
                if cand not in failing:
                    failing.append(cand)
            else:
                dropped += 1
    return {
        "counted": counted,
        "passed": passed if counted else None, "failed": failed if counted else None,
        "ignored": ignored if counted else None,
        "failingTests": failing[:MAX_FAILING],
        "failingTruncated": max(0, len(failing) - MAX_FAILING),
        "droppedInvalidNames": dropped,
    }


def junit_counts(base: pathlib.Path, pattern: str) -> dict | None:
    """Sum JUnit XML totals (tests, failures, errors, skipped) under base; None when no report was written.

    Only integers leave this function: no test names, messages or report text are read into public output.
    """
    import xml.etree.ElementTree as ET
    total = failed = skipped = files = 0
    for path in sorted(base.glob(pattern)):
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue
        if root.tag == "testsuite":
            suites = [root]
        elif root.tag == "testsuites":
            suites = list(root.findall("testsuite"))
        else:
            continue
        files += 1
        for suite in suites:
            try:
                total += int(suite.get("tests", "0"))
                failed += int(suite.get("failures", "0")) + int(suite.get("errors", "0"))
                skipped += int(suite.get("skipped", "0"))
            except ValueError:
                continue
    if not files:
        return None
    return {"passed": max(0, total - failed - skipped), "failed": failed, "ignored": skipped}


def _check_name(value: str, what: str) -> str:
    if value != "-" and not SAFE_NAME.fullmatch(value):
        raise SystemExit(f"invalid {what}")
    return value


def _fmt(value) -> str:
    return "n/a" if value is None else str(value)


# Only direct Cargo compile invocations have a structured compiler channel.
DIAG_BAD = re.compile(r"(/home/|/Users/|/Volumes/|/tmp/|/runner|\\|token|secret|password|bearer|authorization|cookie|api[_-]?key)", re.I)
MAX_DIAG = 20


def _compiler_command(command: Sequence[str]) -> bool:
    return (len(command) >= 3 and command[0] == "cargo" and command[1] in {"build", "check", "clippy"}
            and "--message-format=json" in command and "--" not in command
            and sum(arg.startswith("--message-format") for arg in command) == 1)


def diagnostics(text: str, *, command: Sequence[str] = (), metadata=None, index=None) -> tuple[list[str], int]:
    """Read Cargo JSON stdout only; mixed output never establishes provenance."""
    if not _compiler_command(command):
        return [], 0
    metadata = _checkout_metadata() if metadata is None else metadata
    index = CANARY_INDEX if index is None else index
    out = []
    dropped = 0
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(record, dict) or record.get("reason") != "compiler-message":
            continue
        message = record.get("message")
        if not isinstance(message, dict) or message.get("level") != "error":
            continue
        code = message.get("code")
        code = code.get("code") if isinstance(code, dict) else None
        spans = message.get("spans")
        if not isinstance(code, str) or not re.fullmatch(r"E[0-9]{4}", code) or not isinstance(spans, list):
            continue
        for span in spans:
            if not isinstance(span, dict) or span.get("is_primary") is not True:
                continue
            path, line_number = span.get("file_name"), span.get("line_start")
            if not isinstance(path, str) or type(line_number) is not int:
                dropped += 1
                continue
            site = metadata.location(f"{path}:{line_number}", index)
            if site == UNVERIFIED or _private(code, index) or len(out) >= MAX_DIAG:
                dropped += 1
            else:
                out.append(f"{code} @ {site}")
    return out, dropped


# Limits count serialized UTF-8 bytes, including JSON escaping and field names. The job
# budget is shared by every step writing to the same fragment directory.
MAX_EXCERPT_BYTES = 2048
MAX_JOB_EXCERPT_BYTES = 24 * 1024
MAX_PROGRESS_LINES = 12
WITHHELD = "withheld: privacy scan"
CARGO_SECTION = re.compile(r"^---- (\S+) (?:stdout|stderr) ----$")
CARGO_PANIC = re.compile(
    r"^thread '([^']+)'(?: \([0-9]+\))? panicked at (\S{1,300}):([0-9]+):([0-9]+):$")
CARGO_STATE = re.compile(r"^test (\S+) \.\.\.(?: (ok|FAILED|ignored))?$")
CARGO_RUNNING = re.compile(r"^test (\S+) has been running for over \d+ seconds$")
GRADLE_STATE = re.compile(r"^(?:[\w$.]+\.)?(\w+) > (\w+)(?:\((?P<params>[^\n]*)\))?"
                          r"(?:\[(?P<index>[^\n]*)\])? (?P<status>STARTED|PASSED|FAILED|SKIPPED)$")
JAVA_SITE = re.compile(r"^\s*at [\w.$]+\((\w+\.java:\d+)\)\s*$")
GRADLE_SHORT_SITE = re.compile(r"^[\w.$]+ at (\w+\.java:\d+)$")
UNVERIFIED = "<unverified>"
MAX_CATEGORIES = 16
MAX_PANIC_SITES = 8
# std::io::ErrorKind is non-exhaustive. Changes to this vocabulary require review.
IO_ERROR_KINDS = frozenset({
    "NotFound", "PermissionDenied", "ConnectionRefused", "ConnectionReset", "HostUnreachable",
    "NetworkUnreachable", "ConnectionAborted", "NotConnected", "AddrInUse", "AddrNotAvailable",
    "NetworkDown", "BrokenPipe", "AlreadyExists", "WouldBlock", "NotADirectory", "IsADirectory",
    "DirectoryNotEmpty", "ReadOnlyFilesystem", "FilesystemLoop", "StaleNetworkFileHandle",
    "InvalidInput", "InvalidData", "TimedOut", "WriteZero", "StorageFull", "NotSeekable",
    "QuotaExceeded", "FileTooLarge", "ResourceBusy", "ExecutableFileBusy", "Deadlock",
    "CrossesDevices", "TooManyLinks", "InvalidFilename", "ArgumentListTooLong", "Interrupted",
    "Unsupported", "UnexpectedEof", "OutOfMemory", "InProgress", "Other", "Uncategorized",
})


class UnverifiedReason(str, Enum):
    METADATA_UNAVAILABLE = "metadata-unavailable"
    NAME_NOT_DECLARED = "name-not-declared-in-head"
    PRIVACY_SCAN = "privacy-scan"
    EXCERPT_CAP = "excerpt-cap"
    AMBIGUOUS_PANIC = "ambiguous-panic-block"
    DIAGNOSTIC_THREAD = "diagnostic-thread-unverified"
    DIAGNOSTIC_NOT_FAILING = "diagnostic-thread-not-failing"
    DIAGNOSTIC_AMBIGUOUS = "diagnostic-thread-ambiguous"


# Reuse the canary scanner's encoded needles, including recognisable marker families
# when no private canary file was supplied. DIAG_BAD also guards host paths/credentials.
CANARY_INDEX = canary.build_index({"marker": "CANARY", "mixed-marker": "canary"})
PRIVATE_TEXT = re.compile(r"(?:(?<![A-Za-z0-9_./-])/[A-Za-z0-9_.-]+/|[A-Za-z]:\\|https?://|\b[\w.+-]+@[\w.-]+\.[A-Za-z]+|"
                          r"\b(?:passwd|credential|api[_-]?key)\b|\bprivate[_-])", re.I)


def _encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True).encode("utf-8")


def _private(text: str, index) -> bool:
    hits: dict = {}
    canary.scan_bytes(text.encode("utf-8"), index, hits, "ci-excerpt")
    return bool(hits or DIAG_BAD.search(text) or PRIVATE_TEXT.search(text)
                or any(ord(c) < 32 and c not in "\n\t" for c in text))


# Strip comments and literals before finding declarations, so examples and captured
# strings in test source cannot create trusted function names. Preserve offsets.
SOURCE_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|r(?P<hash>\#*)".*?"(?P=hash)'
    r'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`', re.S)
# A Rust lifetime or label is not a character literal. The general string grammar
# would swallow declarations between two lifetimes, hiding real tests from HEAD.
RUST_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|r(?P<hash>\#*)".*?"(?P=hash)'
    r'|"(?:\\.|[^"\\])*"|\'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^\'\\\n])\'', re.S)


def _source_mask(source: str, *, rust: bool = False) -> str:
    masked = list(source)
    offset = 0
    while match := (RUST_LITERAL if rust else SOURCE_LITERAL).search(source, offset):
        end = match.end()
        if match[0].startswith("/*"):
            # Rust permits nested block comments. A regex ending at the first
            # terminator could otherwise attest a declaration still in a comment.
            depth = 1
            cursor = match.start() + 2
            while depth:
                delimiter = re.search(r"/\*|\*/", source[cursor:])
                if delimiter is None:
                    cursor = len(source)
                    break
                cursor += delimiter.end()
                depth += 1 if delimiter[0] == "/*" else -1
            end = cursor
        masked[match.start():end] = ["\n" if c == "\n" else " " for c in source[match.start():end]]
        offset = end
    return "".join(masked)


def _diagnostic_variants(source: str, enums: str = "PrivateStorageError|AdmissionOperation") -> set[str]:
    """Read only variant declarations of the private-storage diagnostic enums."""
    masked = _source_mask(source, rust=True)
    variants = set()
    for enum in re.finditer(r"\benum\s+(?:" + enums + r")\s*\{", masked):
        depth = 0
        expect_variant = True
        for token in re.finditer(r"[A-Za-z_]\w*|[^\s]", masked[enum.end():]):
            word = token[0]
            if word == "}" and depth == 0:
                break
            if depth == 0 and expect_variant and re.fullmatch(r"[A-Za-z_]\w*", word):
                variants.add(word)
                expect_variant = False
            if word in "({[":
                depth += 1
            elif word in ")}]":
                depth -= 1
            elif word == "," and depth == 0:
                expect_variant = True
    return variants


class CheckoutMetadata:
    """Only regular-file blobs from the snapshotted commit can attest facts."""

    def __init__(self, sources: dict[str, str]):
        self.files: dict[str, int] = {}
        self.tests: set[str] = set()
        self.rust_tests: set[str] = set()
        self.diagnostic_variants: set[str] = set()
        self.admission_operations: set[str] = set()
        self.error_variants: set[str] = set()
        self.java_files: dict[str, list[str]] = {}
        for name, source in sources.items():
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name:
                continue
            self.files[name] = len(source.splitlines())
            if path.suffix == ".java":
                self.java_files.setdefault(path.name, []).append(name)
            self._read_tests(path, source)
            if path.suffix == ".rs" and path.parts[:3] == ("crates", "xtrace-private-storage", "src"):
                self.diagnostic_variants.update(_diagnostic_variants(source))
                self.admission_operations.update(_diagnostic_variants(source, "AdmissionOperation"))
                self.error_variants.update(_diagnostic_variants(source, "PrivateStorageError"))

    def _read_tests(self, path: pathlib.PurePosixPath, source: str) -> None:
        test_path = bool(set(path.parts) & {"test", "tests", "__tests__"})
        js_test = path.suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"} and (
            test_path or re.search(r"\.(?:test|spec)\.", path.name))
        if not (path.suffix == ".rs" and path.parts[0] == "crates"
                or path.suffix == ".java" and test_path or js_test
                or path.suffix == ".py" and path.name.startswith("test_")):
            return
        masked = _source_mask(source, rust=path.suffix == ".rs")
        if path.suffix == ".rs" and path.parts[0] == "crates":
            # Requiring a test attribute also excludes helper functions in tests/.
            declarations = list(re.finditer(
                r"#\[(?:[A-Za-z_]\w*::)?test(?:\([^]]*\))?\]\s*"
                r"(?:#\[[^]]*\]\s*)*(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\(", masked))
            self.tests.update(match[1] for match in declarations)
            # Exact libtest names include file and inline module prefixes. Never
            # attest an arbitrary prefix merely because its last component fits.
            parts = list(path.parts)
            prefix = []
            if "src" in parts:
                prefix = parts[parts.index("src") + 1:-1]
                if path.stem not in {"lib", "main", "mod"}:
                    prefix.append(path.stem)
            elif "tests" in parts and parts.index("tests") + 2 < len(parts):
                prefix = parts[parts.index("tests") + 1:-1]
                if path.stem != "mod":
                    prefix.append(path.stem)
            for match in declarations:
                scopes = []
                for token in re.finditer(r"\bmod\s+([A-Za-z_]\w*)\s*\{|[{}]", masked[:match.start()]):
                    if token[0] == "}":
                        if scopes:
                            scopes.pop()
                    else:
                        scopes.append(token[1])
                self.rust_tests.add("::".join([*prefix, *filter(None, scopes), match[1]]))
        elif path.suffix == ".java" and test_path:
            methods = re.findall(
                r"@(?:Test|ParameterizedTest|RepeatedTest|Case)\b(?:\([^)]*\))?\s*"
                r"(?:@[^\n]+\s*)*(?:(?:public|protected|private|static|final)\s+)*"
                r"void\s+([A-Za-z_]\w*)\s*\(", masked)
            self.tests.update(f"{path.stem}::{method}" for method in methods)
        elif js_test:
            for call in re.finditer(r"\b(?:test|it)(?:\.(?:only|skip))?\s*\(", masked):
                literal = re.match(r"\s*(['\"])([^\n\\]*?)\1", source[call.end():])
                if literal:
                    self.tests.add(literal[2])
        elif path.suffix == ".py" and path.name.startswith("test_"):
            try:
                tree = ast.parse(source)
            except SyntaxError:
                return
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self.tests.update(f"{node.name}::{method.name}" for method in node.body
                                      if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                                      and method.name.startswith("test_"))

    def test(self, candidate: str, index) -> str:
        # Rust module prefixes are captured output too. Publish the declared
        # function name, never a prefix that the source metadata did not attest.
        name = candidate if candidate in self.tests else candidate.rsplit("::", 1)[-1]
        return name if name in self.tests and not _private(name, index) else UNVERIFIED

    def test_unverified_reason(self, candidate: str) -> UnverifiedReason:
        """Explain a name already rejected by test(), without retaining it."""
        if not self.files:
            return UnverifiedReason.METADATA_UNAVAILABLE
        name = candidate if candidate in self.tests else candidate.rsplit("::", 1)[-1]
        if name not in self.tests:
            return UnverifiedReason.NAME_NOT_DECLARED
        return UnverifiedReason.PRIVACY_SCAN

    def location(self, candidate: str, index, *, java: bool = False) -> str:
        path, sep, line = candidate.rpartition(":")
        if not sep or not line.isascii() or not line.isdigit() or len(line) > 9:
            return UNVERIFIED
        if java and "/" not in path:
            matches = self.java_files.get(path, [])
            if len(matches) != 1:
                return UNVERIFIED
            path = matches[0]
        if (not path or path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts
                or "\\" in path or not 1 <= int(line) <= self.files.get(path, 0)):
            return UNVERIFIED
        site = f"{path}:{int(line)}"
        return UNVERIFIED if _private(site, index) else site


def _checkout_metadata() -> CheckoutMetadata:
    root = pathlib.Path(__file__).resolve().parents[2]
    try:
        # HEAD is the commit checked out by the lane. Capture its tree before
        # running the command; neither the index nor working files attest facts.
        # Object ids from this single tree listing pin every subsequent blob read.
        with subprocess.Popen(["git", "-C", str(root), "ls-tree", "-r", "-z", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            output, _ = proc.communicate()
            if proc.returncode:
                return CheckoutMetadata({})
        entries = []
        for entry in output.split(b"\0"):
            if not entry:
                continue
            header, name = entry.split(b"\t", 1)
            mode, kind, oid = header.split()
            if mode in {b"100644", b"100755"} and kind == b"blob":
                entries.append((name.decode("utf-8"), oid))
        with subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as proc:
            output, _ = proc.communicate(b"".join(oid + b"\n" for _, oid in entries))
            if proc.returncode:
                return CheckoutMetadata({})
        sources = {}
        offset = 0
        for name, oid in entries:
            end = output.index(b"\n", offset)
            actual, kind, size = output[offset:end].split()
            length = int(size)
            offset = end + 1
            if (actual != oid or kind != b"blob" or length < 0
                    or output[offset + length:offset + length + 1] != b"\n"):
                return CheckoutMetadata({})
            blob = output[offset:offset + length]
            offset += length + 1
            try:
                sources[name] = blob.decode("utf-8")
            except UnicodeError:
                continue  # binary files cannot attest source facts
        if offset != len(output):
            return CheckoutMetadata({})
    except (OSError, UnicodeError, ValueError):
        return CheckoutMetadata({})
    return CheckoutMetadata(sources)


MAX_CI_RECORDS = 256
MAX_CI_RECORD_BYTES = 2048


def _ci_diagnostics(directory: pathlib.Path | None, metadata: CheckoutMetadata, index) -> list[tuple[str, list[str | int]]]:
    """Read bounded product records. Raw output is never a diagnostic source."""
    if directory is None:
        return []
    records = []
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        root_fd = os.open(directory, flags | os.O_DIRECTORY)
        try:
            root = os.fstat(root_fd)
            if root.st_uid != os.getuid() or stat.S_IMODE(root.st_mode) != 0o700:
                return []
            fd = os.open("private-storage.jsonl", flags, dir_fd=root_fd)
        finally:
            os.close(root_fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                return []
            for _ in range(MAX_CI_RECORDS):
                raw = stream.readline(MAX_CI_RECORD_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_CI_RECORD_BYTES or not raw.endswith(b"\n"):
                    break  # never reinterpret a partial/oversize record's suffix
                try:
                    record = json.loads(raw)
                except (ValueError, UnicodeError, RecursionError):
                    continue
                if not isinstance(record, dict) or set(record) != {"thread", "error", "operation", "kind", "errno"}:
                    continue
                thread, error, operation, kind, errno = (record[key] for key in
                                                        ("thread", "error", "operation", "kind", "errno"))
                if (not isinstance(error, str) or error not in metadata.error_variants
                        or error != "Admission" or not isinstance(operation, str)
                        or operation not in metadata.admission_operations
                        or kind is not None and (not isinstance(kind, str) or kind not in IO_ERROR_KINDS)
                        or errno is not None and (type(errno) is not int or not 1 <= errno <= 200)):
                    continue
                values = [error, operation, *([kind] if kind is not None else []),
                          *([errno] if errno is not None else [])]
                if any(_private(str(value), index) for value in values):
                    continue
                name = (thread if isinstance(thread, str) and thread in metadata.rust_tests
                        and not _private(thread, index) else UNVERIFIED)
                records.append((name, values))
    except (OSError, ValueError):
        return []
    return records


def _output_parts(text: str) -> tuple[list[tuple[str, str, list[str], list[int]]], list[str]]:
    """Separate harness observations from failure bodies once, before extraction.

    Open quoted or compound values cannot introduce harness boundaries. Body lines
    are never rescanned for timeout progress, even when they look like build output.
    After a panic starts, retain the rest of the stream in the same block.
    Harness-looking lines in a payload cannot attest its end or another owner.
    """
    blocks = []
    harness = []
    name = None
    kind = "cargo"
    lines: list[str] = []
    panic_lines: list[int] = []
    quote = None
    depth = 0
    for line in ANSI.sub("", text).splitlines():
        section = CARGO_SECTION.fullmatch(line) if not quote and not depth else None
        panic = CARGO_PANIC.fullmatch(line) if not quote and not depth else None
        gradle = GRADLE_FAIL.fullmatch(line.strip()) if not quote and not depth else None
        next_name = (section[1] if section else f"{gradle[1]}::{gradle[2]}" if gradle else
                     panic[1] if panic and name is None else None)
        boundary = not quote and not depth and (
            next_name is not None or CARGO_STATE.fullmatch(line) or CARGO_RUNNING.fullmatch(line)
            or CARGO_RESULT.match(line) or line == "failures:" or line.startswith("> Task ")
            or GRADLE_STATE.fullmatch(line.strip()))
        if boundary and not panic_lines:
            if name is not None:
                blocks.append((name, kind, lines, panic_lines))
            name, lines = next_name, []
            panic_lines = []
            kind = "gradle" if gradle else "cargo"
        if name is not None:
            if panic_lines or not section and not gradle:
                if panic:
                    panic_lines.append(len(lines))
                lines.append(line)
                # Panic headers contain the thread name, not a message operand.
                if not panic:
                    escaped = False
                    for char in line:
                        if escaped:
                            escaped = False
                        elif char == "\\":
                            escaped = True
                        elif quote:
                            if char == quote:
                                quote = None
                        elif char in {'"', '`'}:
                            quote = char
                        elif char in "{[":
                            depth += 1
                        elif char in "}]":
                            depth = max(0, depth - 1)
        else:
            harness.append(line)
        # Gradle FAILED both starts a body and reports a harness observation.
        if gradle and not panic_lines:
            harness.append(line.strip())
    if name is not None:
        blocks.append((name, kind, lines, panic_lines))
    return blocks, harness


def _timeout_progress(line: str) -> tuple[str, str] | None:
    if state := CARGO_STATE.fullmatch(line):
        name, status = state.groups()
        return name, {None: "running", "ok": "ok", "FAILED": "failed"}.get(status, "ignored")
    if long := CARGO_RUNNING.fullmatch(line):
        return long[1], "running"
    if gradle := GRADLE_STATE.fullmatch(line):
        return f"{gradle[1]}::{gradle[2]}", {
            "STARTED": "running", "PASSED": "ok", "FAILED": "failed", "SKIPPED": "ignored"}[gradle["status"]]
    return None


def failure_details(text: str, timed_out: bool, *, budget: int = MAX_JOB_EXCERPT_BYTES,
                    index=None, metadata: CheckoutMetadata | None = None,
                    diagnostic_records: Sequence[tuple[str, list[str | int]]] = ()) -> dict | None:
    """Publish verified names/sites, bounded categories and counts; never prose."""
    index = CANARY_INDEX if index is None else index
    metadata = _checkout_metadata() if metadata is None else metadata
    blocks, harness = _output_parts(text)
    failures: dict[str | tuple[str], dict] = {}

    def failure(name: str, *, unattributed: UnverifiedReason | None = None) -> dict:
        # Captured names cannot collide with internal unattributed row keys.
        key = name if unattributed is None else (name,)
        if key not in failures:
            row = {"test": metadata.test(name, index), "location": UNVERIFIED,
                   "kind": "unknown", "withheldLines": 0, "category": [], "panicSites": []}
            if row["test"] == UNVERIFIED:
                row["testUnverifiedReason"] = metadata.test_unverified_reason(name).value
            if unattributed is not None:
                row.update(test=UNVERIFIED, testUnverifiedReason=unattributed.value)
            failures[key] = row
        return failures[key]

    for line in harness:
        if m := CARGO_FAIL.fullmatch(line):
            failure(m[1])["kind"] = "exit"
        elif m := GRADLE_FAIL.fullmatch(line.strip()):
            failure(f"{m[1]}::{m[2]}")["kind"] = "exit"
        elif m := PY_FAIL.match(line):
            failure(f"{m[2]}::{m[1]}")["kind"] = "exit"
        elif m := re.fullmatch(r"\s*not ok \d+ - (.+)", line):
            failure(m[1])["kind"] = "exit"
    states = [m.groups() for line in harness if (m := CARGO_STATE.fullmatch(line)) and m[2]]
    outcomes = dict(states)
    occurrences = Counter(name for name, _ in states)
    failing_threads = {name for name, status in outcomes.items() if status == "FAILED"
                       and occurrences[name] == 1 and name in metadata.rust_tests and not _private(name, index)}
    for block_number, (name, framework, lines, panic_lines) in enumerate(blocks):
        if framework == "cargo" and outcomes.get(name) in {"ok", "ignored"}:
            continue
        if panic_lines:
            header = CARGO_PANIC.fullmatch(lines[panic_lines[0]])
            header_test = metadata.test(header[1], index)
            first_line = next(i for i, line in enumerate(lines) if line.strip())
            # Even a terminal test status or a stdout section can be payload.
            # Check the entire remaining block, including quoted lines, before
            # considering a site. Even apparent footers may be message prose;
            # only a single observed message line can retain a site.
            message = []
            shaped = False
            for line in lines[panic_lines[0] + 1:]:
                shaped |= bool(re.match(r"\s*thread .*panicked at |\s*---- .* (?:stdout|stderr) ----", line))
                if not line.strip():
                    continue
                message.append(line)
            reason = None
            if len(panic_lines) != 1 or panic_lines[0] != first_line or shaped or len(message) != 1:
                reason = UnverifiedReason.AMBIGUOUS_PANIC
            elif header_test == UNVERIFIED:
                reason = metadata.test_unverified_reason(header[1])
            elif metadata.test(name, index) != header_test:
                reason = UnverifiedReason.AMBIGUOUS_PANIC
            if reason is not None:
                if name in failures:
                    failures[name]["withheldLines"] += sum(bool(line.strip()) for line in lines)
                row = failure(f"<panic-block-{block_number}>", unattributed=reason)
                row.update(kind="panic", withheldLines=sum(bool(line.strip()) for line in lines))
                continue
        # A passing should_panic test is not a failure. On timeout, retain an
        # observed panic even if its terminal harness outcome never arrived.
        if name not in failures:
            if not panic_lines:
                continue
            terminal = next((m[2] for line in reversed(lines)
                             if (m := CARGO_STATE.fullmatch(line)) and m[1] == name), None)
            if terminal in {"ok", "ignored"} or not (timed_out or terminal == "FAILED"):
                continue
            failure(name)
        row = failures[name]
        after_panic = False
        first_message = True
        java_frames = False
        for line_number, line in enumerate(lines):
            if not line.strip():
                continue
            if framework == "cargo" and line_number in panic_lines:
                after_panic = True
                first_message = True
                row["kind"] = "panic"
                header = CARGO_PANIC.fullmatch(line)
                location = metadata.location(f"{header[2]}:{header[3]}", index)
                if location != UNVERIFIED:
                    row["location"] = location
                    row["panicSites"] = [location]
                continue
            if first_message and (after_panic or framework == "gradle"):
                first_message = False
                if line.strip().startswith(("assertion ", "java.lang.AssertionError", "org.opentest4j.AssertionFailedError")):
                    row["kind"] = "assertion"
                if framework == "gradle":
                    if site := GRADLE_SHORT_SITE.fullmatch(line.strip()):
                        row["location"] = metadata.location(site[1], index, java=True)
                    # Only an immediate stack following a single-line exception
                    # headline is eligible. Never search a continuation for sites.
                    java_frames = bool(re.fullmatch(r"[\w.$]+(?:Error|Exception)(?:: [^\"`{}\[\]]*)?", line.strip()))
            elif java_frames and (site := JAVA_SITE.fullmatch(line)):
                test_file = name.split("::")[0].split("$")[0] + ".java:"
                if site[1].startswith(test_file):
                    row["location"] = metadata.location(site[1], index, java=True)
                continue
            else:
                java_frames = False
            row["withheldLines"] += 1
    # A product record attests an observation, never a test outcome or cause.
    # Exact thread matches may associate observations with independent failures.
    observations: dict[tuple[str, str | None], dict] = {}
    for name, categories in diagnostic_records[:MAX_CI_RECORDS]:
        attributed = name in failing_threads
        reason = None
        if not attributed:
            if name == UNVERIFIED:
                reason = UnverifiedReason.DIAGNOSTIC_THREAD.value
            elif occurrences[name] > 1:
                reason = UnverifiedReason.DIAGNOSTIC_AMBIGUOUS.value
            else:
                reason = UnverifiedReason.DIAGNOSTIC_NOT_FAILING.value
        key = (name if attributed else UNVERIFIED, reason)
        if key not in observations:
            row = {"test": key[0], "relevance": "unknown", "category": []}
            if reason is not None:
                row["testUnverifiedReason"] = reason
            observations[key] = row
        row = observations[key]
        for value in categories:
            if value not in row["category"] and len(row["category"]) < MAX_CATEGORIES:
                row["category"].append(value)
    rows = list(failures.values())
    for row in rows:
        # Names and locations have independent provenance; scanning can only
        # remove them. It never rebuilds or copies any part of a message.
        while len(_encoded(row)) > MAX_EXCERPT_BYTES and row["panicSites"]:
            row["panicSites"].pop()
        while len(_encoded(row)) > MAX_EXCERPT_BYTES and row["category"]:
            row["category"].pop()
        if len(_encoded(row)) > MAX_EXCERPT_BYTES:
            row.update(test=UNVERIFIED, location=UNVERIFIED,
                       testUnverifiedReason=UnverifiedReason.EXCERPT_CAP.value)
    result: dict = {"failures": rows[:MAX_FAILING], "omitted": max(0, len(rows) - MAX_FAILING)}
    if observations:
        result["observedDiagnostics"] = list(observations.values())[:MAX_FAILING]
        result["diagnosticsOmitted"] = max(0, len(observations) - MAX_FAILING)
        for row in result["observedDiagnostics"]:
            while len(_encoded(row)) > MAX_EXCERPT_BYTES and row["category"]:
                row["category"].pop()
            if len(_encoded(row)) > MAX_EXCERPT_BYTES:
                row.update(test=UNVERIFIED, testUnverifiedReason=UnverifiedReason.EXCERPT_CAP.value)
    if timed_out:
        running: dict[str, None] = {}
        unverified_running: set[str] = set()
        progress: deque[dict] = deque(maxlen=MAX_PROGRESS_LINES)
        withheld = progress_omitted = 0
        for line in harness:
            line = line.strip()
            if CARGO_RESULT.match(line) or re.fullmatch(r"running \d+ tests?", line):
                running.clear()
                unverified_running.clear()
            observation = _timeout_progress(line)
            if observation is None:
                continue
            candidate, state = observation
            name = metadata.test(candidate, index)
            if name == UNVERIFIED:
                withheld += 1
                if state == "running":
                    unverified_running.add(candidate)
                else:
                    unverified_running.discard(candidate)
                continue
            if state == "running":
                running[name] = None
            else:
                running.pop(name, None)
            if state == "ignored":
                continue
            rebuilt = {"test": name, "state": state}
            if len(_encoded(rebuilt)) > MAX_EXCERPT_BYTES:
                progress_omitted += 1
                continue
            progress_omitted += int(len(progress) == MAX_PROGRESS_LINES)
            progress.append(rebuilt)
        names = list(running)
        result["timeout"] = {"runningTests": names[:MAX_FAILING],
                             "runningOmitted": len(unverified_running) + max(0, len(names) - MAX_FAILING),
                             "basis": "last harness observation; other running tests not observed",
                             "progress": list(progress), "progressWithheld": withheld,
                             "progressOmitted": progress_omitted}
    # Preserve the timeout envelope when space runs short; drop failure rows first.
    while len(_encoded(result)) > budget:
        if result["failures"]:
            result["failures"].pop()
            result["omitted"] += 1
        elif result.get("observedDiagnostics"):
            result["observedDiagnostics"].pop()
            result["diagnosticsOmitted"] += 1
        elif result.get("timeout", {}).get("progress"):
            result["timeout"]["progress"].pop(0)
            result["timeout"]["progressOmitted"] += 1
        elif result.get("timeout", {}).get("runningTests"):
            result["timeout"]["runningTests"].pop()
            result["timeout"]["runningOmitted"] += 1
        else:
            return None
    if failures and not result["failures"] and not timed_out:
        return None
    return result


def _remaining_excerpt_budget(out: pathlib.Path, current: pathlib.Path) -> int:
    used = 0
    for path in out.glob("*.json"):
        if path == current:
            continue
        try:
            previous = json.loads(path.read_text())
            if not isinstance(previous, dict):
                return 0
            detail = previous.get("failureDetails")
        except (OSError, ValueError):
            return 0  # never reset the job budget when prior fragments cannot be read
        if detail is not None:
            used += len(_encoded(detail))
    return max(0, MAX_JOB_EXCERPT_BYTES - used)


def _excerpt_index(path: str):
    if not path:
        return CANARY_INDEX
    try:
        values = json.loads(pathlib.Path(path).read_text())
        if not isinstance(values, dict) or not values or not all(
                isinstance(v, str) and v for v in values.values()):
            return None
        return [*CANARY_INDEX, *canary.build_index(values)]
    except (OSError, ValueError):
        return None


def cmd_run(args: argparse.Namespace) -> int:
    suite, variant, step = (_check_name(args.suite, "suite"), _check_name(args.variant, "variant"),
                            _check_name(args.step, "step"))
    out = pathlib.Path(args.out)
    log_dir = pathlib.Path(os.environ.get("LANE_PRIVATE_LOG_DIR") or os.environ.get("RUNNER_TEMP", "/tmp")) / "xl"
    previous_umask = os.umask(0o077)  # private log only; the wrapped command keeps the job's umask
    log_dir.mkdir(mode=0o700, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        raise SystemExit("no command")
    log_path = log_dir / f"{suite}-{variant}-{step}.log"
    metadata = _checkout_metadata()
    diagnostic_directory = None
    child_env = os.environ.copy()
    if "XTRACE_CI_DIAG_DIR" in child_env:
        import tempfile
        diagnostic_directory = pathlib.Path(tempfile.mkdtemp(prefix="ci-diag-", dir=out))
        child_env["XTRACE_CI_DIAG_DIR"] = str(diagnostic_directory)
    timed_out = False
    with open(log_path, "wb") as log:
        os.umask(previous_umask)
        try:
            if _compiler_command(cmd):
                # Cargo JSON is stdout. stderr (including build-script output)
                # is private and cannot supply compiler facts.
                with os.fdopen(os.open(log_path.with_suffix(".stderr.log"),
                                       os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as compiler_stderr:
                    proc = subprocess.run(cmd, stdout=log, stderr=compiler_stderr, cwd=args.cwd or None,
                                          check=False, timeout=args.timeout, env=child_env)
            else:
                proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=args.cwd or None,
                                      check=False, timeout=args.timeout, env=child_env)
        except subprocess.TimeoutExpired:  # a timeout is a failed step with a fragment, never a traceback with argv
            timed_out = True
            proc = subprocess.CompletedProcess(cmd, 124)
            print(f"lane {suite}/{variant}/{step}: timeout after {args.timeout}s")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    facts = parse_output(text)
    _, harness = _output_parts(text)
    facts["failingTests"] = parse_output("\n".join(harness))["failingTests"]
    if getattr(args, "junit_glob", ""):
        # Gradle prints no totals on success; the JUnit XML reports are the count of record for the Java suite.
        jc = junit_counts(pathlib.Path(args.cwd or "."), args.junit_glob)
        if jc is not None:
            facts.update(jc, counted=True)
    status = "pass" if proc.returncode == 0 else "fail"
    if status == "pass" and args.min_passed and facts["passed"] is None:
        status = "fail"  # a count-less pass cannot satisfy a minimum
        print(f"lane {suite}/{variant}/{step}: no test count found (minimum {args.min_passed})")
    if status == "pass" and args.min_passed and (facts["passed"] or 0) < args.min_passed:
        status = "fail"  # a test step that ran fewer tests than expected is not a pass
        print(f"lane {suite}/{variant}/{step}: fewer than {args.min_passed} tests counted")
    max_ignored = getattr(args, "max_ignored", -1)
    if status == "pass" and max_ignored >= 0 and (facts["ignored"] or 0) > max_ignored:
        status = "fail"  # a skipped or ignored test is not a pass on a no-skips row
        print(f"lane {suite}/{variant}/{step}: {facts['ignored']} ignored or skipped tests (maximum {max_ignored})")
    index = _excerpt_index(getattr(args, "canaries", ""))
    if facts["failingTests"]:
        # The older summary field is part of the same public fragment. It must
        # not bypass the provenance checks applied to failureDetails.
        facts["failingTests"] = [metadata.test(name, index) if index is not None else UNVERIFIED
                                 for name in facts["failingTests"]]
    frag = {"suite": suite, "variant": variant, "step": step, "status": status,
            "exitCode": proc.returncode, **{k: v for k, v in facts.items() if k != "counted"}}
    fragment_path = out / f"{suite}__{variant}__{step}.json"
    if suite == "rust" and step == "test":
        # This path runs after success, failure and the existing command timeout.
        # Only rebuilt vocabulary/numbers leave the private profile text files.
        frag["storeProfiles"] = store_profiles.collect(out)
    if status == "fail":
        frag["timedOut"] = timed_out
        frag["failureDetails"] = (failure_details(
            text, timed_out, budget=_remaining_excerpt_budget(out, fragment_path), index=index, metadata=metadata,
            diagnostic_records=_ci_diagnostics(diagnostic_directory, metadata, index))
            if index is not None else None)
        if frag["failureDetails"] is None:
            frag["failureDetailsUnavailable"] = WITHHELD if index is None else "job excerpt cap"
    fragment_path.write_bytes(_encoded(frag) + b"\n")
    print(f"lane {suite}/{variant}/{step}: {status} exit={proc.returncode} "
          f"passed={_fmt(facts['passed'])} failed={_fmt(facts['failed'])} ignored={_fmt(facts['ignored'])}")
    for name in facts["failingTests"]:
        print(f"lane failing-test {name}")
    if status == "fail":
        diags, ddropped = diagnostics(text, command=cmd, metadata=metadata, index=index) if index is not None else ([], 0)
        for d in diags:
            print(f"lane diagnostic {d}")
        if ddropped:
            print(f"lane diagnostic-overflow dropped={ddropped}")
        for row in (frag["failureDetails"] or {}).get("failures", []):
            print("lane failure " + _encoded(row).decode("ascii"))
        for row in (frag["failureDetails"] or {}).get("observedDiagnostics", []):
            print("lane observed-diagnostic " + _encoded(row).decode("ascii"))
    if facts["failingTruncated"] or facts["droppedInvalidNames"]:
        print(f"lane failing-test-overflow truncated={facts['failingTruncated']} "
              f"dropped-invalid={facts['droppedInvalidNames']}")
    return 0 if status == "pass" else (proc.returncode or 1)


def cmd_merge(args: argparse.Namespace) -> int:
    results: dict[str, str] = {}
    for item in args.job_result or []:
        name, _, res = item.partition("=")
        results[name] = res
    try:
        plan = json.loads(pathlib.Path(args.plan).read_text())
    except (OSError, ValueError):
        plan = None
    if results.get("plan") not in (None, "success"):
        plan = None
    meta = {k: os.environ.get(v, "") for k, v in (("headSha", "GITHUB_SHA"), ("runId", "GITHUB_RUN_ID"),
                                                  ("runAttempt", "GITHUB_RUN_ATTEMPT"), ("ref", "GITHUB_REF"))}
    if plan is None:
        # The plan job failed or its artifact is missing: still emit a summary, and never a passing one.
        doc = {"schemaVersion": 1, **meta, "planMode": None, "overall": "fail", "reason": "plan-unavailable",
               "suites": []}
        pathlib.Path(args.out).write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")
        text = "lane plan unavailable: no suite was evaluated\n"
        print(text)
        if args.step_summary:
            with open(args.step_summary, "a", encoding="utf-8") as fh:
                fh.write(text)
        return 1
    frags = [json.loads(p.read_text()) for p in sorted(pathlib.Path(args.frag_dir).glob("**/*.json"))]
    suites_out = []
    overall_ok = True
    for name, info in plan["suites"].items():
        entry: dict = {"name": name, "plan": info.get("reason", "")}
        if info["status"] in ("skipped-by-filter", "absent"):
            entry["status"] = info["status"]
            if info.get("forced"):
                entry["status"] = "fail"
                entry["reason"] = "suite explicitly requested but absent"
                overall_ok = False
            suites_out.append(entry)
            continue
        mine = [f for f in frags if f["suite"] == name]
        variants = []
        failing: list[str] = []
        suite_ok = True
        for variant in EXPECTED_VARIANTS[name]:
            vfr = [f for f in mine if f["variant"] == variant]
            vstatus = "pass" if vfr and all(f["status"] == "pass" for f in vfr) else "fail"
            if not vfr:
                vstatus = "no-result"
            suite_ok &= vstatus == "pass"
            for f in vfr:
                failing += [f"{variant}:{t}" if variant != "-" else t for t in f["failingTests"]]
            variants.append({"variant": variant, "status": vstatus,
                             "steps": [{"step": f["step"], "status": f["status"], "passed": f.get("passed"),
                                        "failed": f.get("failed"), "ignored": f.get("ignored")} for f in vfr]})
        if results.get(name) not in (None, "success"):
            suite_ok = False
        entry["status"] = "pass" if suite_ok else "fail"
        entry["variants"] = variants
        entry["failingTests"] = failing[:MAX_FAILING]
        if info.get("changedCrates") is not None:
            entry["changedCrates"] = info["changedCrates"]
        overall_ok &= suite_ok
        suites_out.append(entry)
    doc = {"schemaVersion": 1, **meta, "planMode": plan.get("mode"), "overall": "pass" if overall_ok else "fail",
           "suites": suites_out}
    pathlib.Path(args.out).write_text(json.dumps(doc, sort_keys=True, indent=1) + "\n")
    lines = ["| suite | status | detail |", "|---|---|---|"]
    for s in suites_out:
        detail = ", ".join(f"{v['variant']}={v['status']}" for v in s.get("variants", [])) or s.get("plan", "")
        lines.append(f"| {s['name']} | {s['status']} | {detail} |")
    text = "\n".join(lines) + "\n"
    print(text)
    if args.step_summary:
        with open(args.step_summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if overall_ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--suite", required=True)
    r.add_argument("--variant", default="-")
    r.add_argument("--step", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--cwd", default="")
    r.add_argument("--min-passed", type=int, default=0, help="fail a zero-exit step that counted fewer tests")
    r.add_argument("--max-ignored", type=int, default=-1, help="fail a zero-exit step that ignored or skipped more tests")
    r.add_argument("--junit-glob", default="", help="glob (relative to --cwd) of JUnit XML reports to count")
    r.add_argument("--timeout", type=int, default=3000)
    r.add_argument("--canaries", default="", help="optional private canary JSON; unreadable files withhold excerpts")
    r.add_argument("command", nargs=argparse.REMAINDER)
    m = sub.add_parser("merge")
    m.add_argument("--plan", required=True)
    m.add_argument("--frag-dir", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--step-summary", default="")
    m.add_argument("--job-result", action="append")
    args = ap.parse_args()
    return cmd_run(args) if args.cmd == "run" else cmd_merge(args)


if __name__ == "__main__":
    sys.exit(main())
