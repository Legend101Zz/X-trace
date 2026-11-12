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
import math
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum

from tools.qa import canary, libtest_output, rust_timing, store_profiles
from tools.release import ci_floor, private_roots

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
    reports, text = libtest_output.partition(text)
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
    for report in reports:
        passed += report.counts[0]
        failed += report.counts[1]
        ignored += report.counts[2]
        counted = True
        for name in report.names:
            if ci_floor._valid_test_id(name):
                # The same name in different binaries denotes separate failures.
                failing.append(name)
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
MAX_TIMING_CHECKPOINT_BYTES = 1024 * 1024
WITHHELD = "withheld: privacy scan"
CARGO_SECTION = libtest_output.SECTION
CARGO_PANIC = libtest_output.PANIC
CARGO_STATE = rust_timing.TEST_STATE
CARGO_RUNNING = rust_timing.TEST_RUNNING
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


def _private(text: str, index, *, verified_identifier: bool = False) -> bool:
    """Skip text heuristics only after independent repository/vocabulary attestation.

    Canary needles and control characters are forbidden even in attested names.
    """
    hits: dict = {}
    canary.scan_bytes(text.encode("utf-8"), index, hits, "ci-excerpt")
    return bool(hits or (not verified_identifier and (DIAG_BAD.search(text) or PRIVATE_TEXT.search(text)))
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


# Share the declaration grammar between short names and full module contexts.
RUST_TEST_DECLARATION = (
    r"#\[(?:[A-Za-z_]\w*::)?test(?:\([^]]*\))?\]\s*"
    r"(?:#\[[^]]*\]\s*)*"
    r"(?:pub(?:\s*\(\s*(?:crate|self|super|in\s+(?:crate|self|super)"
    r"(?:\s*::\s*[A-Za-z_]\w*)*)\s*\))?\s+)?"
    r"(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\("
)


class CheckoutMetadata:
    """Only regular-file blobs from the snapshotted commit can attest facts."""

    def __init__(self, sources: dict[str, str]):
        self.rust_targets = rust_timing.checkout_targets(sources)
        self.files: dict[str, int] = {}
        self.tests: set[str] = set()
        self.rust_tests: set[str] = set()
        self.rust_test_owners: dict[str, set[rust_timing.Target | str]] = {}
        self.diagnostic_variants: set[str] = set()
        self.admission_operations: set[str] = set()
        self.error_variants: set[str] = set()
        self.admission_sites: set[str] = set()
        self.listing_refusals: set[str] = set()
        self.admission_objects: set[str] = set()
        self.admission_callers: set[str] = set()
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
                self.admission_sites.update(_diagnostic_variants(source, "AdmissionSite"))
                self.listing_refusals.update(_diagnostic_variants(source, "ListingRefusal"))
                if name == "crates/xtrace-private-storage/src/diagnostic.rs":
                    self.admission_objects.update(_diagnostic_variants(source, "AdmissionObject"))
                if name == "crates/xtrace-private-storage/src/caller.rs":
                    self.admission_callers.update(_diagnostic_variants(source, "AdmissionCaller"))
        self._read_rust_contexts(sources)

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
            declarations = list(re.finditer(RUST_TEST_DECLARATION, masked))
            self.tests.update(match[1] for match in declarations)
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

    def _read_rust_contexts(self, sources: dict[str, str]) -> None:
        """Resolve module edges from HEAD, never from the working filesystem.

        Literal includes inherit their caller's module. A path attribute names
        a file, not a module prefix. Keep each root's identity separately because
        identical libtest names in different binaries cannot own a thread-only
        diagnostic record.
        """
        rust = {name: source for name, source in sources.items()
                if name in self.files and name.startswith("crates/") and name.endswith(".rs")}
        roots: dict[str, set[rust_timing.Target]] = {}
        for name, source in sources.items():
            path = pathlib.PurePosixPath(name)
            if name not in self.files or path.name != "Cargo.toml" or path.parts[0] != "crates":
                continue
            try:
                crate = tomllib.loads(source).get("package", {}).get("name")
            except tomllib.TOMLDecodeError:
                continue
            for target in self.rust_targets:
                filename = str(path.parent / target.path)
                if target.crate == crate and filename in rust:
                    roots.setdefault(filename, set()).add(target)
        graph = {}
        referenced = set()
        token_pattern = re.compile(
            r"#\[\s*path\s*=|\binclude\s*!\s*\(|"
            r"\bmod\s+([A-Za-z_]\w*)\s*([;{])|[{}]|" + RUST_TEST_DECLARATION)
        for name, source in rust.items():
            path = pathlib.PurePosixPath(name)
            masked = _source_mask(source, rust=True)
            scopes = []
            tests, edges = [], []
            skip_until = 0
            for token in token_pattern.finditer(masked):
                if token.start() < skip_until:
                    continue
                inline = tuple(filter(None, scopes))
                module_dir = (path.parent if name in roots or path.stem in {"lib", "main", "mod"}
                              else path.with_suffix(""))
                destination = None
                added = inline
                if token[0].startswith("#[") and token[3]:
                    tests.append((*inline, token[3]))
                elif token[0].startswith("#["):
                    literal = re.match(r'\s*"([^"\\\n]+)"\s*\]\s*'
                                       r'(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;',
                                       source[token.end():])
                    if literal:
                        base = module_dir.joinpath(*inline) if inline else path.parent
                        destination = base / literal[1]
                        added = (*inline, literal[2])
                        skip_until = token.end() + literal.end()
                elif token[0].startswith("include"):
                    literal = re.match(r'\s*"([^"\\\n]+)"\s*\)', source[token.end():])
                    if literal:
                        destination = path.parent / literal[1]
                elif token[1]:
                    if token[2] == "{":
                        scopes.append(token[1])
                    else:
                        base = module_dir.joinpath(*inline)
                        candidates = [base / f"{token[1]}.rs", base / token[1] / "mod.rs"]
                        matches = [candidate for candidate in candidates if str(candidate) in rust]
                        if len(matches) == 1:
                            destination = matches[0]
                            added = (*inline, token[1])
                elif token[0] == "{":
                    scopes.append(None)
                elif token[0] == "}" and scopes:
                    scopes.pop()
                if (destination is not None and not destination.is_absolute()
                        and ".." not in destination.parts and "\\" not in str(destination)
                        and str(destination) in rust):
                    edges.append((str(destination), added))
                    referenced.add(str(destination))
            graph[name] = tests, edges

        visited = set()

        def walk(name, prefix, owner, active):
            if name in active:
                return  # Cycles cannot establish another module context.
            visited.add(name)
            tests, edges = graph[name]
            for suffix in tests:
                test = "::".join((*prefix, *suffix))
                self.rust_tests.add(test)
                self.rust_test_owners.setdefault(test, set()).add(owner)
            for destination, added in edges:
                walk(destination, (*prefix, *added), owner, active | {name})

        for root in sorted(roots):
            for target in roots[root]:
                walk(root, (), target, set())
        # Standalone source fixtures and modules whose parent is unavailable
        # retain conventional prefixes. Referenced files never gain a guessed
        # filename prefix alongside their resolved module names.
        for name in sorted(set(rust) - referenced - roots.keys()):
            if name in visited:
                continue
            path = pathlib.PurePosixPath(name)
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
            walk(name, tuple(prefix), name, set())

    def test(self, candidate: str, index) -> str:
        # Rust module prefixes are captured output too. Publish the declared
        # function name, never a prefix that the source metadata did not attest.
        name = candidate if candidate in self.tests else candidate.rsplit("::", 1)[-1]
        return name if name in self.tests and not _private(name, index, verified_identifier=True) else UNVERIFIED

    def rust_progress_test(self, name, binary, index) -> bool:
        """Attest the full libtest name in the observed target, including module prefixes."""
        return (index is not None and isinstance(name, str) and ci_floor._valid_test_id(name)
                and any(isinstance(owner, rust_timing.Target) and owner.public() == binary
                        for owner in self.rust_test_owners.get(name, ()))
                and not _private(name, index, verified_identifier=True))

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
        return UNVERIFIED if _private(site, index, verified_identifier=True) else site


def _checkout_metadata(root: pathlib.Path | None = None, revision: str = "HEAD") -> CheckoutMetadata:
    root = root if root is not None else pathlib.Path(__file__).resolve().parents[2]
    try:
        # HEAD is the commit checked out by the lane. Capture its tree before
        # running the command; neither the index nor working files attest facts.
        # Object ids from this single tree listing pin every subsequent blob read.
        with subprocess.Popen(["git", "-C", str(root), "ls-tree", "-r", "-z", revision],
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
# Match AdmissionContext's i64 exactly: retain every representable ancestor/child
# offset while limiting published depth to at most 20 decimal characters.
MIN_COMPONENT_DEPTH = -(2**63)
MAX_COMPONENT_DEPTH = 2**63 - 1


@dataclass
class AdmissionDiagnostic:
    thread: str
    categories: list[str | int]
    # Keep roles and JSON types: False equals 0 in Python's category deduplication.
    fields: dict[str, str | int | bool] = field(default_factory=dict)


def _open_ci_diagnostic(directory: pathlib.Path, filename: str) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    root_fd = os.open(directory, flags | os.O_DIRECTORY)
    try:
        root = os.fstat(root_fd)
        if root.st_uid != os.getuid() or stat.S_IMODE(root.st_mode) != 0o700:
            raise ValueError("CI diagnostic directory is not private")
        fd = os.open(filename, flags, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("CI diagnostic record is not private")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _ci_diagnostics(directory: pathlib.Path | None, metadata: CheckoutMetadata, index) -> list[AdmissionDiagnostic]:
    """Read bounded product records. Raw output is never a diagnostic source."""
    if directory is None:
        return []
    records = []
    try:
        with os.fdopen(_open_ci_diagnostic(directory, "private-storage.jsonl"), "rb") as stream:
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
                base_fields = {"thread", "error", "operation", "kind", "errno"}
                context_fields = {"site", "changes", "listing"}
                object_fields = {"object", "component_depth", "nlink_changed"}
                caller_fields = {"store_phase", "store_site"}
                if (not isinstance(record, dict)
                        or set(record) - object_fields - caller_fields not in (base_fields, base_fields | context_fields)
                        or set(record) & object_fields and not context_fields <= set(record)):
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
                if "site" in record:
                    site, changes, listing = (record[key] for key in ("site", "changes", "listing"))
                    if (not isinstance(site, str) or site not in metadata.admission_sites
                            or type(changes) is not int or not 0 <= changes <= 31
                            or not isinstance(listing, str) or listing not in metadata.listing_refusals):
                        continue
                    values.extend((site, changes, listing))
                fields = {key: record[key] for key in
                          ("object", "component_depth", "nlink_changed", "store_phase", "store_site") if key in record}
                if ("object" in fields and (not isinstance(fields["object"], str)
                                            or fields["object"] not in metadata.admission_objects)
                        or "component_depth" in fields and (type(fields["component_depth"]) is not int
                            or not MIN_COMPONENT_DEPTH <= fields["component_depth"] <= MAX_COMPONENT_DEPTH)
                        or "nlink_changed" in fields and type(fields["nlink_changed"]) is not bool
                        or any(key in fields and (not isinstance(fields[key], str)
                                                  or fields[key] not in metadata.admission_callers)
                               for key in ("store_phase", "store_site"))):
                    continue
                # Every value above is a declared enum, fixed vocabulary or bounded scalar.
                if any(_private(str(value), index, verified_identifier=True) for value in [*values, *fields.values()]):
                    continue
                name = (thread if isinstance(thread, str) and thread in metadata.rust_tests
                        and not _private(thread, index, verified_identifier=True) else UNVERIFIED)
                records.append(AdmissionDiagnostic(name, values, fields))
    except (OSError, ValueError):
        return []
    return records


SPRING_ORDER_WAIT_TEST = "premain_captures_real_spring_request_and_fails_open_without_leaking_canaries"
SPRING_ORDER_WAIT_TARGET = {"crate": "xtrace-cli", "targetKind": "test", "targetName": "java_premain_spring"}
SPRING_ORDER_WAIT_PHASES = {
    "successful-request": 1, "error-request": 2, "attestation-mismatch": 3, "classfile-mutation": 4,
}
SPRING_ORDER_WAIT_ROW_LIMIT = 16
SPRING_ORDER_WAIT_MAX_BYTES = 64
SPRING_ORDER_WAIT_RECORD = re.compile(rb"v1 ([a-z-]{1,32}) (0|[1-9][0-9]?) ([0-3])\n")


def spring_order_wait(directory: pathlib.Path, metadata: CheckoutMetadata, index) -> dict:
    """Rebuild a single deadline observation from the task's private diagnostic file."""
    unavailable = {"status": "unavailable"}
    if not metadata.rust_progress_test(SPRING_ORDER_WAIT_TEST, SPRING_ORDER_WAIT_TARGET, index):
        return unavailable
    try:
        with os.fdopen(_open_ci_diagnostic(directory, "spring-premain-order-wait.txt"), "rb") as stream:
            raw = stream.read(SPRING_ORDER_WAIT_MAX_BYTES + 1)
    except (OSError, ValueError):
        return unavailable
    record = SPRING_ORDER_WAIT_RECORD.fullmatch(raw)
    if record is None:
        return unavailable
    phase = record[1].decode("ascii")
    expected = SPRING_ORDER_WAIT_PHASES.get(phase)
    complete, matching = int(record[2]), int(record[3])
    if expected is None or complete > SPRING_ORDER_WAIT_ROW_LIMIT or matching > complete or matching >= expected:
        return unavailable
    if complete == 0:
        state = "no-complete-segment-rows"
    elif matching == 0:
        state = "no-matching-marker"
    else:
        state = "insufficient-matching-rows"
    result = {"status": "observed", "phase": phase, "state": state, "expectedRows": expected,
              "completeRows": complete, "completeRowsLimit": SPRING_ORDER_WAIT_ROW_LIMIT, "matchingRows": matching}
    return unavailable if _private(_encoded(result).decode("ascii"), index, verified_identifier=True) else result


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


def _rust_failure_name(name: str, metadata: CheckoutMetadata, index) -> str:
    """Complete libtest identifiers, including module prefixes, must exist in HEAD."""
    return name if name in metadata.rust_tests and not _private(name, index, verified_identifier=True) else UNVERIFIED


def _libtest_failures(report: libtest_output.Report, metadata: CheckoutMetadata, index) -> list[dict]:
    if not report.counts[1]:
        return []  # Expected panics in a successful binary are not failures.
    # Use the timing observer's target attestation, including ambiguous target
    # refusal. Neither executable paths nor thread names leave this function.
    observer = rust_timing.Observations(metadata.rust_targets,
                                       lambda value: _private(value, index, verified_identifier=True))
    observer.line(report.header, 0)
    binary = observer.active[0]
    rows = {}
    for name in report.names:
        verified = _rust_failure_name(name, metadata, index)
        row = {"test": verified, "binary": binary, "location": UNVERIFIED, "kind": "exit",
               "withheldLines": 0, "category": [], "panicSites": []}
        if verified == UNVERIFIED:
            row["testUnverifiedReason"] = (
                UnverifiedReason.PRIVACY_SCAN.value if name in metadata.rust_tests
                else UnverifiedReason.NAME_NOT_DECLARED.value if metadata.files
                else UnverifiedReason.METADATA_UNAVAILABLE.value)
        rows[name] = row
    section = None
    current = None
    ambiguous = None
    for line, allowed in zip(report.body, report.boundaries):
        if allowed and (header := CARGO_SECTION.fullmatch(line)):
            section = header[1]
            current = rows.get(section)
            continue
        if allowed and line == "failures:":
            section = current = None
            continue
        panic = CARGO_PANIC.fullmatch(line) if allowed else None
        if panic:
            # A captured section establishes ownership. Without one, even a
            # sole failure can coexist with passing tests that panic and catch
            # the unwind. Only a report with one executed test permits fallback.
            current = rows.get(section) if section is not None else (
                next(iter(rows.values())) if report.counts[:2] == (0, 1) and len(rows) == 1 else None)
            if current is None:
                if ambiguous is None:
                    ambiguous = {"test": UNVERIFIED, "binary": binary, "location": UNVERIFIED,
                                 "kind": "panic", "withheldLines": 0, "category": [], "panicSites": [],
                                 "testUnverifiedReason": UnverifiedReason.AMBIGUOUS_PANIC.value}
                current = ambiguous
            current["kind"] = "panic"
            if current is not ambiguous:
                site = metadata.location(f"{panic[2]}:{panic[3]}", index)
                if site != UNVERIFIED and site not in current["panicSites"]:
                    if len(current["panicSites"]) < MAX_PANIC_SITES:
                        current["panicSites"].append(site)
                    if current["location"] == UNVERIFIED:
                        current["location"] = site
        if current is not None and line.strip():
            current["withheldLines"] += 1
    return [*rows.values(), *([ambiguous] if ambiguous is not None else [])]


def failure_details(text: str, timed_out: bool, *, budget: int = MAX_JOB_EXCERPT_BYTES,
                    index=None, metadata: CheckoutMetadata | None = None,
                    diagnostic_records: Sequence[AdmissionDiagnostic] = ()) -> dict | None:
    """Publish verified names/sites, bounded categories and counts; never prose."""
    index = CANARY_INDEX if index is None else index
    metadata = _checkout_metadata() if metadata is None else metadata
    reports, text = libtest_output.partition(text)
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
    for report in reports:
        # Retain successful names too, including should_panic tests. Count each
        # name once per execution, rather than once per printed status line.
        completed = {match[1]: match[2] for line, allowed in zip(report.body, report.boundaries)
                     if allowed and (match := re.fullmatch(
                         r"test (\S+)(?: - should panic)? \.\.\. (ok|ignored)", line))}
        completed.update((name, "FAILED") for name in report.names)
        states.extend(completed.items())
    outcomes = dict(states)
    occurrences = Counter(name for name, _ in states)
    ambiguous_threads = {name for name, owners in metadata.rust_test_owners.items() if len(owners) > 1}
    ambiguous_threads.update(name for name, count in occurrences.items() if count > 1)
    failing_threads = {name for name, status in outcomes.items() if status == "FAILED"
                       and name not in ambiguous_threads and name in metadata.rust_tests
                       and not _private(name, index, verified_identifier=True)}
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
    observations: dict[tuple, dict] = {}
    for record in diagnostic_records[:MAX_CI_RECORDS]:
        name, categories = record.thread, record.categories
        attributed = name in failing_threads
        reason = None
        if not attributed:
            if name == UNVERIFIED:
                reason = UnverifiedReason.DIAGNOSTIC_THREAD.value
            elif name in ambiguous_threads:
                reason = UnverifiedReason.DIAGNOSTIC_AMBIGUOUS.value
            else:
                reason = UnverifiedReason.DIAGNOSTIC_NOT_FAILING.value
        # Never combine distinct verified threads or overwrite differing facts.
        # A passing diagnostic test may emit synthetic records into the same file.
        key = (name, reason, tuple(record.fields.items()))
        if key not in observations:
            row = {"test": name if attributed else UNVERIFIED, "relevance": "unknown", "category": [],
                   **record.fields}
            if reason is not None:
                row["testUnverifiedReason"] = reason
                if name != UNVERIFIED:
                    row["thread"] = name
            observations[key] = row
        row = observations[key]
        for value in categories:
            if value not in row["category"] and len(row["category"]) < MAX_CATEGORIES:
                row["category"].append(value)
    rows = [row for report in reports for row in _libtest_failures(report, metadata, index)]
    rows.extend(failures.values())
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
                row.pop("thread", None)
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
    if rows and not result["failures"] and not timed_out:
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


def publish_rust_timing(timing: dict) -> None:
    """Print the same sanitized observations stored in the step fragment."""
    for event in timing["events"]:
        print("lane rust-binary " + _encoded(event).decode("ascii"))
    for binary in timing["runningAtTimeout"]:
        print("lane rust-timeout " + _encoded(binary).decode("ascii"))
    summary = {key: value for key, value in timing.items() if key not in {"events", "runningAtTimeout"}}
    print("lane rust-timing " + _encoded(summary).decode("ascii"))


def cmd_run(args: argparse.Namespace) -> int:
    suite, variant, step = (_check_name(args.suite, "suite"), _check_name(args.variant, "variant"),
                            _check_name(args.step, "step"))
    out = pathlib.Path(args.out)
    log_dir = pathlib.Path(getattr(args, "private_log_dir", "") or os.environ.get("LANE_PRIVATE_LOG_DIR")
                           or os.environ.get("RUNNER_TEMP", "/tmp")) / "xl"
    previous_umask = os.umask(0o077)  # private log only; the wrapped command keeps the job's umask
    log_dir.mkdir(mode=0o700, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        raise SystemExit("no command")
    log_path = log_dir / f"{suite}-{variant}-{step}.log"
    recovery = os.environ.get("XTRACE_LANE_RECOVERY_DIR")
    recovery = pathlib.Path(recovery) if recovery and rust_timing.is_test_command(cmd) else None
    if recovery is not None:
        log_path = recovery / "output.log"
    metadata = _checkout_metadata()
    diagnostic_directory = None
    child_env = os.environ.copy()
    child_env.pop("XTRACE_LANE_RECOVERY_DIR", None)
    if "XTRACE_CI_DIAG_DIR" in child_env or (getattr(args, "ci_diagnostics", False) and rust_timing.is_test_command(cmd)):
        diagnostic_directory = (recovery / "diagnostics" if recovery is not None
                                else pathlib.Path(tempfile.mkdtemp(prefix="ci-diag-", dir=out)))
        child_env["XTRACE_CI_DIAG_DIR"] = str(diagnostic_directory)
    timed_out = False
    timing = None
    with open(log_path, "wb") as log:
        os.umask(previous_umask)
        try:
            if rust_timing.is_test_command(cmd):
                index = _excerpt_index(getattr(args, "canaries", ""))
                observations = rust_timing.Observations(
                    metadata.rust_targets,
                    lambda value: index is None or _private(value, index, verified_identifier=True),
                    verified_test=(None if recovery is None else
                                   lambda name, binary: metadata.rust_progress_test(name, binary, index)))
                proc, timed_out, timing = rust_timing.run(
                    cmd, log=log, cwd=args.cwd or None, env=child_env, timeout=args.timeout, observations=observations,
                    **({"checkpoint": recovery / "timing.json"} if recovery is not None else {}))
                if timed_out:
                    print(f"lane {suite}/{variant}/{step}: timeout after {args.timeout}s")
            elif _compiler_command(cmd):
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
    return finalize_run(args, cmd=cmd, log_path=log_path, metadata=metadata,
                        diagnostic_directory=diagnostic_directory, code=proc.returncode,
                        timed_out=timed_out, timing=timing)


def prepare_recovery(root: pathlib.Path, *, directory: pathlib.Path | None = None) -> pathlib.Path:
    """Keep recovery state outside the uploaded fragment glob, owned by the supervisor."""
    if directory is None:
        directory = pathlib.Path(tempfile.mkdtemp(prefix="lane-recovery-", dir=root))
    else:
        private_roots.ensure_private_directory(directory, must_create=True)
        # The store producer uses a fixed frag/ relative to XTRACE_CI_PRIVATE_ROOT.
        (directory / "frag").mkdir(mode=0o700)
    (directory / "diagnostics").mkdir(mode=0o700)
    with os.fdopen(os.open(directory / "output.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"):
        pass
    return directory


def restore_timing_checkpoint(stream, metadata, index, *, progress=False):
    raw = stream.read(MAX_TIMING_CHECKPOINT_BYTES + 1)
    if len(raw) > MAX_TIMING_CHECKPOINT_BYTES:
        raise ValueError("oversize timing checkpoint")
    checkpoint = json.loads(raw)
    if progress and (not isinstance(checkpoint, dict) or set(checkpoint) != {"started", "state"}):
        raise ValueError("invalid timing checkpoint")
    started = checkpoint["started"]
    now = time.monotonic()
    if type(started) not in (int, float) or not math.isfinite(started) or not 0 <= started <= now:
        raise ValueError("invalid checkpoint clock")
    wall = now - started
    observations = rust_timing.Observations.restore(
        checkpoint["state"], metadata.rust_targets,
        lambda value: index is None or _private(value, index, verified_identifier=True),
        verified_test=(None if not progress else lambda name, binary: metadata.rust_progress_test(name, binary, index)),
        max_wall=math.ceil(wall * 1000) / 1000 if progress else None)
    return observations, wall


def recover_timeout(args, directory: pathlib.Path, metadata: CheckoutMetadata, duration: float) -> int:
    """Called only after the outer supervisor has stopped and reaped its owned tree."""
    index = _excerpt_index(getattr(args, "canaries", ""))
    private = lambda value: index is None or _private(value, index, verified_identifier=True)
    observations = rust_timing.Observations(metadata.rust_targets, private)
    wall = duration
    basis = "supervised-wrapper; timing-checkpoint-unavailable"
    try:
        with open(directory / "timing.json", "rb") as stream:
            observations, wall = restore_timing_checkpoint(stream, metadata, index)
        basis = "cargo-start-to-supervisor-cleanup"
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        pass  # Startup may have timed out before Cargo or its first checkpoint.
    timing = observations.finish(wall, True)
    timing["wallObservation"] = basis
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    return finalize_run(args, cmd=cmd, log_path=directory / "output.log", metadata=metadata,
                        diagnostic_directory=directory / "diagnostics", code=124, timed_out=True, timing=timing)


def finalize_run(args, *, cmd, log_path, metadata, diagnostic_directory, code, timed_out, timing):
    """The normal runner and supervisor recovery share every public validation and cap."""
    suite, variant, step = (_check_name(args.suite, "suite"), _check_name(args.variant, "variant"),
                            _check_name(args.step, "step"))
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    text = log_path.read_text(encoding="utf-8", errors="replace")
    facts = parse_output(text)
    reports, remainder = libtest_output.partition(text)
    _, harness = _output_parts(remainder)
    names = parse_output("\n".join(harness))
    candidates = [(name, False) for name in names["failingTests"]]
    for report in reports:
        for name in report.names:
            if ci_floor._valid_test_id(name):
                candidates.append((name, True))
            else:
                names["droppedInvalidNames"] += 1
    facts["failingTruncated"] = names["failingTruncated"] + max(0, len(candidates) - MAX_FAILING)
    facts["droppedInvalidNames"] = names["droppedInvalidNames"]
    if getattr(args, "junit_glob", ""):
        # Gradle prints no totals on success; the JUnit XML reports are the count of record for the Java suite.
        jc = junit_counts(pathlib.Path(args.cwd or "."), args.junit_glob)
        if jc is not None:
            facts.update(jc, counted=True)
    status = "pass" if code == 0 else "fail"
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
    # The older summary field obeys the same provenance checks as failureDetails.
    facts["failingTests"] = [(_rust_failure_name(name, metadata, index) if rust else metadata.test(name, index))
                             if index is not None else UNVERIFIED for name, rust in candidates[:MAX_FAILING]]
    if facts["failed"] is not None:
        published = sum(name != UNVERIFIED for name in facts["failingTests"])
        facts["failingNamesMissing"] = max(0, facts["failed"] - published)
        facts["failingNamesExcess"] = max(0, published - facts["failed"])
    frag = {"suite": suite, "variant": variant, "step": step, "status": status,
            "exitCode": code, **{k: v for k, v in facts.items() if k != "counted"}}
    fragment_path = out / f"{suite}__{variant}__{step}.json"
    if timing is not None:
        frag["rustTiming"] = timing
    if suite == "rust" and step == "test":
        # This path runs after success, failure and the existing command timeout.
        # Only rebuilt vocabulary/numbers leave the private profile text files.
        frag["storeProfiles"] = store_profiles.collect(out)
    if status == "fail":
        frag["timedOut"] = timed_out
        if suite == "rust" and diagnostic_directory is not None and rust_timing.is_test_command(cmd):
            frag["springPremainOrderWait"] = spring_order_wait(diagnostic_directory, metadata, index)
        frag["failureDetails"] = (failure_details(
            text, timed_out, budget=_remaining_excerpt_budget(out, fragment_path), index=index, metadata=metadata,
            diagnostic_records=_ci_diagnostics(diagnostic_directory, metadata, index))
            if index is not None else None)
        if frag["failureDetails"] is None:
            frag["failureDetailsUnavailable"] = WITHHELD if index is None else "job excerpt cap"
    temporary = fragment_path.with_suffix(".tmp")
    temporary.write_bytes(_encoded(frag) + b"\n")
    temporary.replace(fragment_path)
    print(f"lane {suite}/{variant}/{step}: {status} exit={code} "
          f"passed={_fmt(facts['passed'])} failed={_fmt(facts['failed'])} ignored={_fmt(facts['ignored'])}")
    if timing is not None:
        publish_rust_timing(timing)
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
    if facts.get("failingNamesMissing") or facts.get("failingNamesExcess"):
        print(f"lane failing-test-gap missing={facts['failingNamesMissing']} excess={facts['failingNamesExcess']}")
    return 0 if status == "pass" else (code or 1)


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


def parser() -> argparse.ArgumentParser:
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
    r.add_argument("--ci-diagnostics", action="store_true", help="private diagnostics directory for a Cargo test task only")
    r.add_argument("--private-log-dir", default="", help="private parent for raw logs when the task environment is stripped")
    r.add_argument("--canaries", default="", help="optional private canary JSON; unreadable files withhold excerpts")
    r.add_argument("command", nargs=argparse.REMAINDER)
    m = sub.add_parser("merge")
    m.add_argument("--plan", required=True)
    m.add_argument("--frag-dir", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--step-summary", default="")
    m.add_argument("--job-result", action="append")
    return ap


def main() -> int:
    args = parser().parse_args()
    return cmd_run(args) if args.cmd == "run" else cmd_merge(args)


if __name__ == "__main__":
    sys.exit(main())
