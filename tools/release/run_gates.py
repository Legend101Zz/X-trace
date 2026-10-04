#!/usr/bin/env python3
"""Run v0.01 gates at a clean, exact HEAD with recoverable local logs."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pathlib
import platform
import re
import selectors
import secrets
import signal
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

if __package__:
    from . import private_roots, provenance as provenance_module
else:
    import private_roots
    import provenance as provenance_module


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CACHE_NAMES = ("cargo", "cargo-target", "gradle", "npm", "playwright", "tmp", "xdg")
LEASE_NAMES = ("cargo", "gradle")
RECEIPT_JSON_BUDGET = 4096
LOG_LIMIT_EXIT_CODE = 126
PS_BINARY = next((path for path in ("/bin/ps", "/usr/bin/ps") if pathlib.Path(path).is_file()), None)
LSOF_BINARY = next((path for path in ("/usr/sbin/lsof", "/usr/bin/lsof") if pathlib.Path(path).is_file()), None)
UNTRACKED_SCAN_BUDGET_SECONDS = 2.0
MAX_UNTRACKED_PROCESSES = 512
MAX_UNCONFIRMED_SAMPLE = 64
MAX_LSOF_OUTPUT_BYTES = 1024 * 1024
LSOF_CLEANUP_RESERVE_SECONDS = 0.3
NATURAL_EXIT_SETTLE_SECONDS = 120.0
NATURAL_EXIT_POLL_SECONDS = 1.0
NATURAL_EXIT_QUIESCENT_SECONDS = 1.0
EXPECTED_UNINSPECTABLE_SCAN = "untracked-process descriptor scan could not inspect every live candidate"
MAX_UNION_INPUT_RECORDS = MAX_UNTRACKED_PROCESSES
MAX_UNION_KEYS = MAX_UNTRACKED_PROCESSES
MAX_SETTLE_ITERATIONS = 1024
MAX_PID = 2**31 - 1
MAX_STARTED_AT_CHARS = 64
MAX_REASON_CHARS = 96
MAX_PROBE_RECORDS = 64
MAX_CLEANUP_EXCEPTION_RECORDS = 64
OWNER_RECORD_SOFT_LIMIT_BYTES = 60 * 1024


@dataclass(frozen=True)
class Gate:
    name: str
    argv: tuple[str, ...]
    cwd: str = "."
    env: str = "normal"


@dataclass(frozen=True)
class LsofProbe:
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None
    owned_probe: dict[str, Any] | None = None


@dataclass(frozen=True)
class UntrackedProcessScan:
    held: list[dict[str, Any]]
    uninspectable: list[dict[str, Any]]
    error: str | None
    candidate_count: int
    owned_probes: list[dict[str, Any]] = field(default_factory=list)
    # Exact (pid, startedAt) identities of candidates the scanner positively
    # inspected and found neither held nor unknown. Empty on any scan error.
    clean_identities: frozenset[tuple[int, str]] = frozenset()
    # Uninspectable identities positively classified as non-descendants by
    # provenance; they carry their evidence and no longer block settling.
    classified: list[dict[str, Any]] = field(default_factory=list)

    @property
    def unconfirmed(self) -> list[dict[str, Any]]:
        return self.held + self.uninspectable


@dataclass(frozen=True)
class NaturalExitSettle:
    cleared: bool
    elapsed_seconds: float
    poll_count: int
    latest_candidates: list[dict[str, Any]]
    last_error: str | None
    deadline: float
    identity_union: list[dict[str, Any]] = field(default_factory=list)
    identity_union_count: int = 0
    identity_union_truncated: bool = False


def _identity_record(record: Any) -> tuple[dict[str, Any], tuple[int, str] | None, bool]:
    """Return a bounded sanitized copy, its (pid, startedAt) key and validity.

    Never serializes or copies unbounded input: only known fields with length
    and type limits survive; anything else is reduced to a fixed marker.
    """
    if not isinstance(record, dict):
        return {"descriptorStatus": "malformed", "reason": "non-record-identity"}, None, False
    pid = record.get("pid")
    started_at = record.get("startedAt")
    valid_identity = (
        isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid <= MAX_PID
        and isinstance(started_at, str) and 0 < len(started_at.strip())
        and len(started_at) <= MAX_STARTED_AT_CHARS
    )
    status = record.get("descriptorStatus")
    status_ok = status in {"held", "uninspectable"}
    clean: dict[str, Any] = {}
    if valid_identity:
        clean["pid"] = pid
        clean["startedAt"] = started_at
    parent = record.get("observedParentPid")
    if isinstance(parent, int) and not isinstance(parent, bool) and 0 <= parent <= MAX_PID:
        clean["observedParentPid"] = parent
    clean["descriptorStatus"] = status if status_ok else "malformed"
    reason = record.get("reason")
    clean["reason"] = reason[:MAX_REASON_CHARS] if isinstance(reason, str) else "reason-unavailable"
    key = (pid, started_at) if valid_identity else None
    return clean, key, valid_identity and status_ok


@dataclass
class UnconfirmedIdentityUnion:
    """Bounded identity evidence accumulated across one natural-exit settle.

    Input size, record shape, field lengths, dedup keys, iteration and the
    retained sample are all capped before anything is stored. `count` is the
    number of distinct identities processed plus any input records that were
    refused for size (an upper bound, never an under-count). `truncated` is
    true whenever the sample does not carry every observed identity.
    """

    sample: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    truncated: bool = False
    _keys: set[Any] = field(default_factory=set)

    def add(self, candidates: Any) -> str | None:
        error: str | None = None
        if not isinstance(candidates, (list, tuple)):
            return self._admit(("malformed", "non-list"), {
                "descriptorStatus": "malformed", "reason": "non-list-identity-input",
            }) or "malformed or incomplete uninspectable process identity"
        taken = candidates[:MAX_UNION_INPUT_RECORDS]
        if len(candidates) > len(taken):
            self.count += len(candidates) - len(taken)
            self.truncated = True
            error = "settling identity input exceeded its record limit"
        for item in taken:
            clean, key, valid = _identity_record(item)
            if not valid:
                error = error or "malformed or incomplete uninspectable process identity"
                if key is None:
                    key = ("malformed", clean.get("reason"), clean["descriptorStatus"])
                else:
                    key = ("malformed-status", key)
            overflow = self._admit(key, clean)
            error = error or overflow
        if self.count > MAX_UNCONFIRMED_SAMPLE:
            self.truncated = True
        if self.truncated:
            error = error or f"settling identity union exceeded {MAX_UNCONFIRMED_SAMPLE} identities"
        return error

    def _admit(self, key: Any, clean: dict[str, Any]) -> str | None:
        if key in self._keys:
            return None
        if len(self._keys) >= MAX_UNION_KEYS:
            self.count += 1
            self.truncated = True
            return "settling identity union exceeded its dedup limit"
        self._keys.add(key)
        self.count += 1
        if len(self.sample) < MAX_UNCONFIRMED_SAMPLE:
            self.sample.append(clean)
        else:
            self.truncated = True
        return None

    def mark_incomplete(self, observed_count: int) -> None:
        self.truncated = True
        if isinstance(observed_count, int) and observed_count > self.count:
            self.count = observed_count


@dataclass
class ProbeEvidence:
    """Bounded owned descriptor-probe identities and cleanup-exception records."""

    probes: list[dict[str, Any]] = field(default_factory=list)
    probe_count: int = 0
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    exception_count: int = 0
    truncated: bool = False
    _probe_keys: set[Any] = field(default_factory=set)

    def add_probes(self, records: Any) -> None:
        if not isinstance(records, (list, tuple)):
            records = [None]
        if len(records) > MAX_PROBE_RECORDS:
            self.truncated = True
            self.probe_count += len(records) - MAX_PROBE_RECORDS
            records = records[:MAX_PROBE_RECORDS]
        for record in records:
            clean: dict[str, Any] = {}
            if isinstance(record, dict):
                for name in ("pid", "processGroupId"):
                    value = record.get(name)
                    if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_PID:
                        clean[name] = value
                started_at = record.get("startedAt")
                if isinstance(started_at, str) and len(started_at) <= MAX_STARTED_AT_CHARS:
                    clean["startedAt"] = started_at
                reason = record.get("reason")
                if isinstance(reason, str):
                    clean["reason"] = reason[:MAX_REASON_CHARS]
            if "pid" not in clean:
                clean["reason"] = clean.get("reason", "probe-record-malformed")
            key = (clean.get("pid"), clean.get("startedAt"), clean.get("processGroupId"), clean.get("reason"))
            if key in self._probe_keys:
                continue
            self._probe_keys.add(key)
            self.probe_count += 1
            if len(self.probes) < MAX_PROBE_RECORDS:
                self.probes.append(clean)
            else:
                self.truncated = True

    def add_exception(self, exc: BaseException) -> None:
        """Capture probe identities and the cleanup-exception type before absorption."""
        self.add_probes(getattr(exc, "owned_probe_processes", []) or [])
        if isinstance(exc, (UncertainProbeCleanup, InterruptedProbeCleanup)):
            self.exception_count += 1
            if len(self.exceptions) < MAX_CLEANUP_EXCEPTION_RECORDS:
                self.exceptions.append({"type": type(exc).__name__})
            else:
                self.truncated = True

    @property
    def empty(self) -> bool:
        return not (self.probe_count or self.exception_count)

    def report_fields(self) -> dict[str, Any]:
        return {
            "ownedProbeProcesses": list(self.probes),
            "ownedProbeProcessCount": self.probe_count,
            "cleanupExceptions": list(self.exceptions),
            "cleanupExceptionCount": self.exception_count,
            "probeEvidenceTruncated": self.truncated or self.probe_count > len(self.probes),
        }


def _bounded_unconfirmed(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, bool]:
    """Bound a candidate list to the sample limit with a truthful total."""
    sample = [_identity_record(item)[0] for item in records[:MAX_UNCONFIRMED_SAMPLE]]
    return sample, len(records), len(records) > MAX_UNCONFIRMED_SAMPLE


GATES: tuple[Gate, ...] = (
    Gate("rust-format", ("cargo", "fmt", "--all", "--check")),
    Gate("rust-clippy", ("cargo", "clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")),
    Gate("rustdoc", ("cargo", "doc", "--locked", "--workspace", "--all-features", "--no-deps"), env="rustdoc"),
    Gate("java-strict", ("./gradlew", "--no-daemon", "--dependency-verification", "strict", "clean", "test", "installDist", "agentDist", "fixtureBootJar"), cwd="adapters/java"),
    Gate("node-install", ("npm", "ci", "--prefix", "adapters/node")),
    Gate("node-generate", ("npm", "run", "generate", "--prefix", "adapters/node")),
    Gate("node-generate-check", ("npm", "run", "generate:check", "--prefix", "adapters/node")),
    Gate("node-typecheck", ("npm", "run", "typecheck", "--prefix", "adapters/node")),
    Gate("node-tests", ("npm", "test", "--prefix", "adapters/node")),
    Gate("web-install", ("npm", "ci", "--prefix", "web/app")),
    Gate("web-browser-install", ("./node_modules/.bin/playwright", "install", "chromium"), cwd="web/app"),
    Gate("web-typecheck", ("npm", "run", "typecheck", "--prefix", "web/app")),
    Gate("web-tests", ("npm", "test", "--prefix", "web/app")),
    Gate("web-api-drift", ("npm", "run", "check:api", "--prefix", "web/app")),
    Gate("web-embedded-assets", ("npm", "run", "check:embedded", "--prefix", "web/app")),
    Gate("rust-cli-spring-journey", ("cargo", "test", "--locked", "-p", "xtrace-cli", "--test", "java_run_spring", "--", "--test-threads=1")),
    Gate("rust-focused", ("cargo", "test", "--locked", "-p", "xtrace-application", "-p", "xtrace-store", "-p", "xtrace-cli", "--all-features", "--no-fail-fast")),
    Gate("rust-workspace", ("cargo", "test", "--locked", "--workspace", "--all-features", "--no-fail-fast")),
    Gate("rust-build", ("cargo", "build", "--locked", "--workspace", "--all-features")),
    Gate("restricted-build", ("cargo", "build", "--locked", "--workspace", "--all-features"), env="restricted"),
    Gate("working-diff-check", ("git", "diff", "--check")),
    Gate("staged-diff-check", ("git", "diff", "--cached", "--check")),
    Gate("phase-diff-check", (), env="phase-diff"),
)


class UncertainProcessTree(RuntimeError):
    """A command-owned or unconfirmed process may still write to shared builders."""

    def __init__(self, message: str, process_group_id: int):
        super().__init__(message)
        self.process_group_id = process_group_id
        self.owned_processes: dict[int, str] = {}
        self.unconfirmed_processes: list[dict[str, Any]] = []
        self.unconfirmed_process_count = 0
        self.unconfirmed_processes_truncated = False
        self.owned_probe_processes: list[dict[str, Any]] = []
        self.owned_probe_process_count = 0
        self.cleanup_exceptions: list[dict[str, Any]] = []
        self.cleanup_exception_count = 0
        self.probe_evidence_truncated = False
        self.raw_exit_code: int | None = None
        self.duration_seconds: float | None = None
        self.command_started = False


class AttemptedGateFailure(RuntimeError):
    """A command ran but failed during its final log or result handling."""

    def __init__(self, cause: BaseException, raw_exit_code: int | None, duration_seconds: float):
        super().__init__(f"gate command result could not be finalized ({type(cause).__name__})")
        self.raw_exit_code = raw_exit_code
        self.duration_seconds = duration_seconds
        self.command_started = True
        self.cleanup_uncertain = False


class LeaseBusy(RuntimeError):
    """A builder lease directory already exists and is not ours.

    `requires_manual_recovery` is True when its owner record says a failed run
    retained it, False when the record does not, and None when it is unreadable.
    """

    def __init__(self, message: str, requires_manual_recovery: bool | None = None):
        super().__init__(message)
        self.requires_manual_recovery = requires_manual_recovery


class UncertainProbeCleanup(RuntimeError):
    """An owned descriptor probe could not be confirmed drained."""

    def __init__(self, owned_probe: dict[str, Any]):
        super().__init__("owned descriptor probe could not be confirmed drained")
        self.owned_probe_processes = [owned_probe]


class InterruptedProbeCleanup(KeyboardInterrupt):
    """Keyboard interrupt whose owned descriptor probe remains uncertain."""

    def __init__(self, owned_probe: dict[str, Any]):
        super().__init__()
        self.owned_probe_processes = [owned_probe]


def _process_snapshot(*, timeout: float = 2.0) -> dict[int, tuple[int, str, str]]:
    """Return pid -> (ppid, start identity, state) using a fixed system ps."""
    if PS_BINARY is None:
        raise RuntimeError("cannot inspect process ownership: system ps is unavailable")
    if timeout <= 0:
        raise RuntimeError("process ownership scan deadline expired")
    try:
        snapshot = subprocess.run(
            [PS_BINARY, "-axo", "pid=,ppid=,lstart=,stat="],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("cannot inspect process ownership")
    if snapshot.returncode:
        raise RuntimeError("cannot inspect process ownership")
    records: dict[int, tuple[int, str, str]] = {}
    for line in snapshot.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].isdigit() and fields[1].isdigit():
            pid, ppid = int(fields[0]), int(fields[1])
            records[pid] = (ppid, " ".join(fields[2:7]), fields[7][:1])
    return records


def _track_descendants(root: tuple[int, str], owned: dict[int, str], snapshot: dict[int, tuple[int, str, str]]) -> None:
    """Remember identities still parented under any process we already own."""
    if root[0] in snapshot and snapshot[root[0]][1] == root[1]:
        owned[root[0]] = root[1]
    changed = True
    while changed:
        changed = False
        parents = {pid for pid, started_at in owned.items()
                   if pid in snapshot and snapshot[pid][1] == started_at and snapshot[pid][2] not in {"Z", "X"}}
        for pid, (ppid, started_at, state) in snapshot.items():
            if ppid in parents and pid not in owned and state not in {"Z", "X"}:
                owned[pid] = started_at
                changed = True


def _owned_processes_alive(owned: dict[int, str], snapshot: dict[int, tuple[int, str, str]]) -> list[int]:
    return [pid for pid, started_at in owned.items()
            if pid in snapshot and snapshot[pid][1] == started_at and snapshot[pid][2] not in {"Z", "X"}]


def _unconfirmed_candidates_since(
    baseline: dict[int, tuple[int, str, str]],
    owned: dict[int, str],
    snapshot: dict[int, tuple[int, str, str]],
) -> list[dict[str, Any]]:
    """Describe new live processes when descriptor ownership could not be checked."""
    return [
        {
            "pid": pid,
            "startedAt": started_at,
            "observedParentPid": ppid,
            "descriptorStatus": "uninspectable",
            "reason": "ownership-scan-did-not-complete",
        }
        for pid, (ppid, started_at, state) in sorted(snapshot.items())
        if ((baseline.get(pid) is None or baseline[pid][1] != started_at)
            and owned.get(pid) != started_at and state not in {"Z", "X"})
    ]


def _classify_settle_scan(
    scan: UntrackedProcessScan, union: UnconfirmedIdentityUnion, *, global_phase: bool,
) -> str | None:
    """Return a fail-closed reason, or None when the scan is acceptable.

    Acceptable means: only the expected scanner classification, complete
    candidate coverage, no held descriptor, no owned probe, bounded and
    well-formed identities. Union evidence is accumulated first so every
    failure path keeps what was observed.
    """
    union_error = union.add(scan.unconfirmed)
    incomplete = scan.candidate_count != len(scan.unconfirmed)
    if incomplete:
        union.mark_incomplete(scan.candidate_count)
    if scan.error not in {None, EXPECTED_UNINSPECTABLE_SCAN}:
        return scan.error
    if scan.held or scan.owned_probes:
        return (
            "global ownership rescan found a live unconfirmed candidate" if global_phase
            else "held descriptor or owned probe appeared during settling"
        )
    if union_error:
        return union_error
    if incomplete:
        return "settling scan candidate coverage is incomplete"
    if bool(scan.uninspectable) != (scan.error == EXPECTED_UNINSPECTABLE_SCAN):
        return "uninspectable scan classification is inconsistent with its candidate identities"
    return None


def _live_identities(snapshot: dict[int, tuple[int, str, str]]) -> set[tuple[int, str]]:
    return {
        (pid, started_at)
        for pid, (_ppid, started_at, state) in snapshot.items()
        if state not in {"Z", "X"}
    }


def _settle_uninspectable_candidates(
    initial: list[dict[str, Any]],
    snapshot_and_scan: Callable[[float], tuple[dict[int, tuple[int, str, str]], UntrackedProcessScan]],
    *,
    duration: float = NATURAL_EXIT_SETTLE_SECONDS,
    interval: float = NATURAL_EXIT_POLL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    identity_union: UnconfirmedIdentityUnion | None = None,
    owned_alive: Callable[[dict[int, tuple[int, str, str]]], list[int]] | None = None,
) -> NaturalExitSettle:
    """Wait boundedly until every initial PID+start identity has exited or been
    positively classified by the scanner.

    A later scan that merely lacks the identity in its unknown list never
    clears it: the identity must be absent from the live snapshot (natural
    exit) or be listed among the scanner's positively inspected identities.
    Other, later unknown identities do not block this stage; the global
    quiescence scan owns them under the same absolute deadline.

    The callback receives the absolute monotonic deadline so all scanner work
    in one poll shares the same remaining budget.
    """
    started = monotonic()
    deadline = started + max(0.0, duration)
    union = identity_union if identity_union is not None else UnconfirmedIdentityUnion()
    initial_error = union.add(initial)
    identities = {
        (candidate["pid"], candidate["startedAt"])
        for candidate in initial
        if isinstance(candidate, dict) and _identity_record(candidate)[1] is not None
    }
    latest = list(initial) if isinstance(initial, list) else []

    def result(cleared: bool, polls: int, error: str | None) -> NaturalExitSettle:
        return NaturalExitSettle(
            cleared, max(0.0, monotonic() - started), polls, latest, error, deadline,
            list(union.sample), union.count, union.truncated,
        )

    if initial_error or not identities or len(identities) != len(initial):
        return NaturalExitSettle(
            False, 0.0, 0, latest, initial_error or "initial process identity unavailable", deadline,
            list(union.sample), union.count, union.truncated,
        )
    poll_count = 0
    while True:
        remaining = deadline - monotonic()
        if remaining <= 0 or poll_count >= MAX_SETTLE_ITERATIONS:
            return result(False, poll_count, "initial uninspectable process identity survived settling deadline")
        try:
            sleep(min(max(0.01, interval), remaining))
            remaining = deadline - monotonic()
            if remaining <= 0:
                return result(False, poll_count, "initial uninspectable process identity survived settling deadline")
            snapshot, scan = snapshot_and_scan(deadline)
            poll_count += 1
        except BaseException as exc:
            return result(False, poll_count, f"settling poll failed: {type(exc).__name__}")
        latest = scan.unconfirmed
        reason = _classify_settle_scan(scan, union, global_phase=False)
        if reason is not None:
            return result(False, poll_count, reason)
        if owned_alive is not None:
            try:
                owned_now = owned_alive(snapshot)
            except BaseException as exc:
                return result(False, poll_count, f"owned process check failed: {type(exc).__name__}")
            if owned_now:
                return result(False, poll_count, "owned process appeared during settling")
        unresolved = {
            identity for identity in _live_identities(snapshot) & identities
            if identity not in scan.clean_identities
        }
        if not unresolved:
            return result(True, poll_count, None)


def _final_global_quiescence_scan(
    deadline: float,
    snapshot_and_scan: Callable[[float], tuple[dict[int, tuple[int, str, str]], UntrackedProcessScan]],
    owned_alive: Callable[[dict[int, tuple[int, str, str]]], list[int]],
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    quiescent_seconds: float = NATURAL_EXIT_QUIESCENT_SECONDS,
    identity_union: UnconfirmedIdentityUnion | None = None,
    pending_identities: set[tuple[int, str]] | None = None,
) -> tuple[bool, list[dict[str, Any]], str | None, int]:
    """Require two quiet global scans after the latest uncertainty.

    A scan is quiet only when it has no error, held descriptor, owned probe,
    unknown identity or owned live process, covers every candidate, and every
    identity ever seen unknown (plus `pending_identities`) has exited or been
    positively classified. An unknown identity that appears resets the quiet
    count; it must exit (or be classified) and then two further quiet scans
    must follow, all before the same absolute deadline. Anything still
    unresolved at the deadline fails closed.

    The callback receives the absolute monotonic deadline for the full scan.
    """
    latest: list[dict[str, Any]] = []
    union = identity_union if identity_union is not None else UnconfirmedIdentityUnion()
    pending: set[tuple[int, str]] = set(pending_identities or ())
    quiet = 0
    scan_count = 0
    churn_seen = False
    while quiet < 2:
        remaining = deadline - monotonic()
        if scan_count >= MAX_SETTLE_ITERATIONS:
            return False, latest, "global rescan iteration limit exceeded", scan_count
        if remaining <= 0:
            if churn_seen and not quiet:
                return False, latest, "settling deadline expired while an uninspectable identity remained unresolved", scan_count
            return False, latest, "settling deadline expired before global rescan", scan_count
        if quiet:
            if remaining < quiescent_seconds:
                return False, latest, "settling deadline expired before quiescent rescan", scan_count
            try:
                sleep(quiescent_seconds)
            except BaseException as exc:
                return False, latest, f"quiescent wait failed: {type(exc).__name__}", scan_count
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False, latest, "settling deadline expired during quiescent interval", scan_count
        try:
            snapshot, scan = snapshot_and_scan(deadline)
        except BaseException as exc:
            return False, latest, f"global ownership rescan failed: {type(exc).__name__}", scan_count
        scan_count += 1
        latest = list(scan.unconfirmed[:MAX_UNCONFIRMED_SAMPLE])
        reason = _classify_settle_scan(scan, union, global_phase=True)
        if monotonic() > deadline:
            return False, latest, "settling deadline exceeded during global ownership rescan", scan_count
        if reason is not None:
            return False, latest, reason, scan_count
        try:
            owned = owned_alive(snapshot)
        except BaseException as exc:
            return False, latest, f"owned process check failed: {type(exc).__name__}", scan_count
        if owned:
            return False, latest, "global ownership rescan found a live owned process", scan_count
        pending.update((item["pid"], item["startedAt"]) for item in scan.uninspectable)
        unresolved = {
            identity for identity in _live_identities(snapshot) & pending
            if identity not in scan.clean_identities
        }
        if scan.uninspectable or unresolved:
            churn_seen = True
            quiet = 0
            remaining = deadline - monotonic()
            if remaining <= 0:
                return False, latest, "settling deadline expired while an uninspectable identity remained unresolved", scan_count
            try:
                sleep(min(max(0.01, NATURAL_EXIT_POLL_SECONDS), remaining))
            except BaseException as exc:
                return False, latest, f"uninspectable wait failed: {type(exc).__name__}", scan_count
            continue
        quiet += 1
    return True, latest, None, scan_count


def _bounded_ownership_scan(
    deadline: float,
    *,
    snapshot: Callable[..., dict[int, tuple[int, str, str]]],
    descriptor_scan: Callable[..., UntrackedProcessScan],
    after_snapshot: Callable[[dict[int, tuple[int, str, str]]], None] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[dict[int, tuple[int, str, str]], UntrackedProcessScan]:
    """Run process and descriptor scans within one absolute deadline."""
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise RuntimeError("settling deadline expired before process snapshot")
    processes = snapshot(timeout=min(2.0, remaining))
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise RuntimeError("settling deadline expired before descriptor scan")
    if after_snapshot is not None:
        after_snapshot(processes)
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise RuntimeError("settling deadline expired before descriptor scan")
    scan = descriptor_scan(
        processes,
        budget_seconds=min(UNTRACKED_SCAN_BUDGET_SECONDS, remaining),
    )
    if monotonic() > deadline:
        raise RuntimeError("settling deadline exceeded during ownership scan")
    return processes, scan


def _natural_exit_settle_eligible(
    scan: UntrackedProcessScan, *, tree_confirmed_drained: bool, log_io_failed: bool,
    prior_uncertainty: bool = False,
) -> bool:
    return (
        tree_confirmed_drained
        and not log_io_failed
        and not prior_uncertainty
        and not scan.held
        and not scan.owned_probes
        and bool(scan.uninspectable)
        and scan.error == EXPECTED_UNINSPECTABLE_SCAN
        and scan.candidate_count == len(scan.unconfirmed)
        and len(scan.uninspectable) <= MAX_UNCONFIRMED_SAMPLE
        and all(
            isinstance(item, dict)
            and item.get("descriptorStatus") == "uninspectable" and _identity_record(item)[2]
            for item in scan.uninspectable
        )
    )


def _untracked_processes_since(
    baseline: dict[int, tuple[int, str, str]],
    owned: dict[int, str],
    snapshot: dict[int, tuple[int, str, str]],
    log_path: pathlib.Path,
    *,
    budget_seconds: float = UNTRACKED_SCAN_BUDGET_SECONDS,
    provenance: Any = None,
) -> UntrackedProcessScan:
    """Find processes born during the run that retain the private gate log.

    With a provenance object, an uninspectable candidate that provenance
    positively classifies as a non-descendant moves to `classified` (with its
    evidence) instead of `uninspectable`; everything else is unchanged.
    """
    started = time.monotonic()
    canonical_log_path = os.path.realpath(log_path)
    candidates: list[tuple[int, int, str]] = []
    for pid, (ppid, started_at, state) in sorted(snapshot.items()):
        baseline_record = baseline.get(pid)
        if ((baseline_record is not None and baseline_record[1] == started_at)
                or owned.get(pid) == started_at or state in {"Z", "X"}):
            continue
        candidates.append((pid, ppid, started_at))
    if not candidates:
        return UntrackedProcessScan([], [], None, 0)
    owned_probes: list[dict[str, Any]] = []

    def record(candidate: tuple[int, int, str], status: str, reason: str) -> dict[str, Any]:
        pid, ppid, started_at = candidate
        return {
            "pid": pid,
            "startedAt": started_at,
            "observedParentPid": ppid,
            "descriptorStatus": status,
            "reason": reason,
        }

    def finish(
        held_candidates: set[int],
        unknown_reasons: dict[int, str],
        scan_error: str | None,
    ) -> UntrackedProcessScan:
        remaining = budget_seconds - (time.monotonic() - started)
        if remaining <= 0:
            scan_error = scan_error or "untracked-process descriptor scan exceeded its time budget"
            still_live: dict[int, tuple[int, str, str]] = {
                pid: (ppid, started_at, "R") for pid, ppid, started_at in candidates
            }
        else:
            try:
                still_live = _process_snapshot(timeout=min(2.0, remaining))
            except RuntimeError:
                still_live = {
                    pid: (ppid, started_at, "R") for pid, ppid, started_at in candidates
                }
                scan_error = scan_error or "process identities could not be rechecked within the scan budget"
        candidates_by_pid = {pid: (ppid, started_at) for pid, ppid, started_at in candidates}
        held_records = [
            record((pid, candidates_by_pid[pid][0], started_at), "held", "private-log-descriptor-observed")
            for pid, (_ppid, started_at) in candidates_by_pid.items()
            if pid in held_candidates and pid in still_live
            and still_live[pid][1] == started_at and still_live[pid][2] not in {"Z", "X"}
        ]
        unknown_records = [
            record((pid, candidates_by_pid[pid][0], candidates_by_pid[pid][1]), "uninspectable", reason)
            for pid, reason in unknown_reasons.items()
            if pid in candidates_by_pid
            and pid in still_live
            and still_live[pid][1] == candidates_by_pid[pid][1]
            and still_live[pid][2] not in {"Z", "X"}
        ]
        classified_records: list[dict[str, Any]] = []
        if provenance is not None and unknown_records:
            classified_by_pid = provenance.classify(
                [(item["pid"], item["startedAt"]) for item in unknown_records],
                snapshot, still_live, owned, started + budget_seconds,
            )
            if classified_by_pid:
                classified_records = list(classified_by_pid.values())
                unknown_records = [item for item in unknown_records if item["pid"] not in classified_by_pid]
        total = len(held_records) + len(unknown_records)
        clean_identities: frozenset[tuple[int, str]] = frozenset()
        if scan_error is None:
            clean_identities = frozenset(
                (pid, started_at) for pid, _ppid, started_at in candidates
                if pid in still_live and still_live[pid][1] == started_at
                and still_live[pid][2] not in {"Z", "X"}
                and pid not in held_candidates and pid not in unknown_reasons
            )
        sample = (held_records + unknown_records)[:MAX_UNCONFIRMED_SAMPLE]
        if total > MAX_UNCONFIRMED_SAMPLE:
            scan_error = scan_error or "unconfirmed process sample limit exceeded"
        return UntrackedProcessScan(
            [item for item in sample if item["descriptorStatus"] == "held"],
            [item for item in sample if item["descriptorStatus"] == "uninspectable"],
            scan_error,
            total,
            owned_probes,
            clean_identities,
            classified_records[:MAX_UNCONFIRMED_SAMPLE],
        )

    if len(candidates) > MAX_UNTRACKED_PROCESSES:
        live = _process_snapshot()
        unknown = {
            pid: "candidate-limit-exceeded"
            for pid, _ppid, started_at in candidates
            if pid in live and live[pid][1] == started_at and live[pid][2] not in {"Z", "X"}
        }
        result = finish(set(), unknown, f"untracked-process inspection limit exceeded ({len(candidates)} candidates)")
        return result

    held_by: set[int] | None = None
    unknown: dict[int, str] = {}
    proc_fd_root = pathlib.Path("/proc")
    if proc_fd_root.is_dir():
        held_by = set()
        for pid, ppid, started_at in candidates:
            if time.monotonic() - started > budget_seconds:
                unknown.update({
                    candidate_pid: "descriptor-scan-time-budget-exceeded"
                    for candidate_pid, _candidate_ppid, _candidate_started_at in candidates
                    if candidate_pid not in held_by
                })
                return finish(held_by, unknown, "untracked-process descriptor scan exceeded its time budget")
            holds_log = _process_holds_log(pid, log_path)
            if holds_log is True:
                held_by.add(pid)
            elif holds_log is None:
                unknown[pid] = "descriptor-inspection-unavailable"
    elif LSOF_BINARY is not None:
        held_by = set()
        pids = [pid for pid, _ppid, _started_at in candidates]
        initial = _run_lsof_fields(
            ["-Fn", "-a", "-d", "1,2", "-p", ",".join(str(pid) for pid in pids)],
            started + budget_seconds,
        )
        if initial.owned_probe is not None:
            owned_probes.append(initial.owned_probe)
        parsed, error = _parse_lsof_fields(initial, set(pids), canonical_log_path)
        if error:
            unknown.update({pid: error for pid in pids})
            return finish(held_by, unknown, f"untracked-process descriptor scan {error}")
        seen_by, initially_held = parsed
        held_by.update(initially_held)
        missing = [pid for pid in pids if pid not in seen_by]
        if missing:
            fallback = _run_lsof_fields(
                ["-Fn", "-p", ",".join(str(pid) for pid in missing)],
                started + budget_seconds,
            )
            if fallback.owned_probe is not None:
                owned_probes.append(fallback.owned_probe)
            fallback_parsed, fallback_error = _parse_lsof_fields(fallback, set(missing), canonical_log_path)
            fallback_seen, fallback_held = fallback_parsed
            held_by.update(fallback_held)
            if fallback_error:
                unknown.update({pid: fallback_error for pid in missing})
                return finish(held_by, unknown, f"untracked-process descriptor scan {fallback_error}")
            for pid in missing:
                if pid not in fallback_seen:
                    unknown[pid] = "missing-process-record-after-all-fd-fallback"
    else:
        unknown.update({pid: "descriptor-inspection-unavailable" for pid, _ppid, _started_at in candidates})
        return finish(held_by or set(), unknown, "untracked-process descriptor inspection is unavailable")

    result = finish(held_by or set(), unknown, None)
    if result.uninspectable:
        return UntrackedProcessScan(
            result.held,
            result.uninspectable,
            "untracked-process descriptor scan could not inspect every live candidate",
            result.candidate_count,
            owned_probes,
            result.clean_identities,
            result.classified,
        )
    return result


def _run_lsof_fields(arguments: list[str], deadline: float) -> LsofProbe:
    """Run lsof with bounded wall time and combined stdout/stderr bytes."""
    if LSOF_BINARY is None:
        return LsofProbe(None, "", "", "descriptor-inspection-unavailable")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return LsofProbe(None, "", "", "time-budget-exceeded")
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            [LSOF_BINARY, *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True,
        )
    except OSError:
        selector.close()
        return LsofProbe(None, "", "", "query-could-not-start")
    except BaseException:
        selector.close()
        raise
    probe_identity: dict[str, Any] = {"pid": process.pid, "startedAt": None, "processGroupId": process.pid}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    result: LsofProbe | None = None
    pending_error: BaseException | None = None
    try:
        probe_identity["startedAt"] = _process_start_identity(
            process.pid, min(deadline, time.monotonic() + 0.15),
        )
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                raise OSError("probe output pipe unavailable")
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        exceeded = False
        timed_out = False
        query_deadline = max(time.monotonic(), deadline - LSOF_CLEANUP_RESERVE_SECONDS)
        while selector.get_map():
            remaining = query_deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _events in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if sum(len(value) for value in output.values()) > MAX_LSOF_OUTPUT_BYTES:
                    exceeded = True
                    break
            if exceeded:
                break
        if timed_out or exceeded:
            drained, cleanup_error = _terminate_lsof_process_group(process, deadline)
        else:
            drained, cleanup_error = _reap_lsof_process(process, deadline)
            if not drained:
                drained, cleanup_error = _terminate_lsof_process_group(process, deadline)
        if not drained:
            probe_identity["reason"] = cleanup_error or "probe-not-confirmed-drained"
            stdout = output["stdout"].decode("utf-8", errors="replace")
            stderr = output["stderr"].decode("utf-8", errors="replace")
            result = LsofProbe(
                process.returncode, stdout, stderr, "probe-not-confirmed-drained", probe_identity,
            )
        else:
            stdout = output["stdout"].decode("utf-8", errors="replace")
            stderr = output["stderr"].decode("utf-8", errors="replace")
            if timed_out:
                result = LsofProbe(process.returncode, stdout, stderr, "time-budget-exceeded")
            elif exceeded:
                result = LsofProbe(process.returncode, stdout, stderr, "output-limit-exceeded")
            else:
                result = LsofProbe(process.returncode, stdout, stderr)
    except OSError:
        drained, cleanup_error = _terminate_lsof_process_group(process, deadline)
        if not drained:
            probe_identity["reason"] = cleanup_error or "probe-not-confirmed-drained"
            result = LsofProbe(
                process.returncode, "", "", "probe-not-confirmed-drained", probe_identity,
            )
        else:
            result = LsofProbe(process.returncode, "", "", "query-could-not-complete")
    except BaseException as exc:
        drained, cleanup_error = _terminate_lsof_process_group(process, deadline)
        if not drained:
            probe_identity["reason"] = cleanup_error or "probe-not-confirmed-drained"
            if isinstance(exc, KeyboardInterrupt):
                pending_error = InterruptedProbeCleanup(probe_identity)
                pending_error.__cause__ = exc
            else:
                pending_error = UncertainProbeCleanup(probe_identity)
                pending_error.__cause__ = exc
        else:
            pending_error = exc

    close_error: BaseException | None = None
    for close in (
        selector.close,
        process.stdout.close if process.stdout is not None else None,
        process.stderr.close if process.stderr is not None else None,
    ):
        if close is None:
            continue
        try:
            close()
        except BaseException as exc:
            close_error = close_error or exc
    if close_error is not None:
        if isinstance(pending_error, (InterruptedProbeCleanup, UncertainProbeCleanup)):
            pass
        elif pending_error is not None:
            probe_identity["reason"] = "probe-resource-cleanup-failed"
            cleanup_type = (
                InterruptedProbeCleanup
                if isinstance(pending_error, KeyboardInterrupt)
                else UncertainProbeCleanup
            )
            wrapped = cleanup_type(probe_identity)
            wrapped.__cause__ = pending_error
            pending_error = wrapped
        elif result is not None and result.owned_probe is not None:
            # Keep the earlier uncertainty and its cause when cleanup also fails.
            pass
        else:
            probe_identity["reason"] = "probe-resource-cleanup-failed"
            result = LsofProbe(
                process.returncode, "", "", "probe-not-confirmed-drained", probe_identity,
            )
    if pending_error is not None:
        raise pending_error
    if result is None:
        probe_identity["reason"] = "probe-result-unavailable"
        return LsofProbe(process.returncode, "", "", "probe-not-confirmed-drained", probe_identity)
    return result


def _process_start_identity(pid: int, deadline: float) -> str | None:
    """Read a short process-start token for private recovery metadata."""
    if PS_BINARY is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        result = subprocess.run(
            [PS_BINARY, "-p", str(pid), "-o", "lstart="],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=min(remaining, 0.15), check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    identity = result.stdout.strip()
    return identity if result.returncode == 0 and identity and "\n" not in identity else None


def _reap_lsof_process(process: subprocess.Popen[bytes], deadline: float) -> tuple[bool, str | None]:
    """Confirm the owned lsof process exited without an unbounded wait."""
    if process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, "probe-reap-deadline-exceeded"
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            return False, "probe-reap-deadline-exceeded"
    group_state = _lsof_process_group_state(process.pid)
    if group_state is None:
        return False, "probe-process-group-state-unavailable"
    if group_state:
        return _terminate_lsof_process_group(process, deadline)
    return process.returncode is not None, None


def _terminate_lsof_process_group(
    process: subprocess.Popen[bytes], deadline: float,
) -> tuple[bool, str | None]:
    """Bound TERM/KILL and direct-child reap for this private probe group."""
    signal_errors = False
    for signum, grace in ((signal.SIGTERM, 0.05), (signal.SIGKILL, 0.15)):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        except BaseException:
            signal_errors = True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            process.wait(timeout=min(grace, remaining))
        except subprocess.TimeoutExpired:
            continue
        except BaseException:
            signal_errors = True
            continue
        if process.returncode is not None and signum == signal.SIGTERM:
            # Still signal the dedicated group to close descendant-held pipes.
            continue
    try:
        process_reaped = process.poll() is not None
    except BaseException:
        process_reaped = False
        signal_errors = True
    try:
        group_state = _lsof_process_group_state(process.pid)
    except BaseException:
        group_state = None
    if process_reaped and group_state is False:
        return True, None
    if signal_errors or group_state is None:
        return False, "probe-signal-failed"
    return False, "probe-reap-deadline-exceeded"


def _lsof_process_group_state(process_group_id: int) -> bool | None:
    """Return whether the private probe process group still exists."""
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None
    return True


def _parse_lsof_fields(
    result: LsofProbe,
    expected_pids: set[int],
    canonical_log_path: str,
) -> tuple[tuple[set[int], set[int]], str | None]:
    if result.error:
        return (set(), set()), result.error
    if result.returncode not in {0, 1}:
        return (set(), set()), "query-could-not-verify-candidates"
    if result.stderr:
        return (set(), set()), "query-reported-incomplete-inspection"
    seen: set[int] = set()
    held: set[int] = set()
    current_pid: int | None = None
    try:
        for line in result.stdout.splitlines():
            if not line:
                continue
            if line.startswith("p"):
                if not line[1:].isdigit():
                    raise ValueError
                current_pid = int(line[1:])
                if current_pid not in expected_pids:
                    raise ValueError
                seen.add(current_pid)
            elif line.startswith("n") and current_pid is not None:
                name = line[1:]
                if any(ord(character) < 32 or ord(character) == 127 for character in name):
                    raise ValueError
                if name.startswith("/"):
                    if name.endswith(" (deleted)") and os.path.normpath(name[:-10]) == canonical_log_path:
                        raise ValueError
                    if os.path.normpath(name) == canonical_log_path:
                        held.add(current_pid)
                elif "/" in name or name in {".", ".."}:
                    raise ValueError
            elif not line.startswith("f"):
                raise ValueError
    except (OSError, ValueError):
        return (set(), set()), "query-returned-malformed-fields"
    return (seen, held), None


def _process_holds_log(pid: int, log_path: pathlib.Path) -> bool | None:
    """Use inherited stdout as a practical ownership marker for escaped children."""
    expected = os.path.realpath(log_path)
    proc_fds = pathlib.Path(f"/proc/{pid}/fd")
    try:
        if not proc_fds.is_dir():
            return None
        for descriptor in proc_fds.iterdir():
            try:
                target = os.readlink(descriptor)
                if any(ord(character) < 32 or ord(character) == 127 for character in target):
                    return None
                if target.endswith(" (deleted)"):
                    if os.path.normpath(target[:-10]) == expected:
                        return None
                    continue
                if target.startswith("/") and os.path.normpath(target) == expected:
                    return True
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    continue
                return None
        return False
    except OSError:
        return None


def _signal_owned(owned: dict[int, str], sig: int) -> None:
    snapshot = _process_snapshot()
    for pid, started_at in list(owned.items()):
        current = snapshot.get(pid)
        if current is None or current[1] != started_at or current[2] in {"Z", "X"}:
            continue
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise RuntimeError("could not signal an owned gate descendant") from exc


def _stop_owned_process_tree(root: tuple[int, str], owned: dict[int, str], grace: float = 1.0) -> bool:
    try:
        snapshot = _process_snapshot()
        _track_descendants(root, owned, snapshot)
        _signal_owned(owned, signal.SIGTERM)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            snapshot = _process_snapshot()
            _track_descendants(root, owned, snapshot)
            if not _owned_processes_alive(owned, snapshot):
                return True
            time.sleep(0.05)
        snapshot = _process_snapshot()
        _track_descendants(root, owned, snapshot)
        _signal_owned(owned, signal.SIGKILL)
        deadline = time.monotonic() + grace * 3
        while time.monotonic() < deadline:
            snapshot = _process_snapshot()
            _track_descendants(root, owned, snapshot)
            if not _owned_processes_alive(owned, snapshot):
                return True
            time.sleep(0.05)
        return False
    except (OSError, RuntimeError, KeyboardInterrupt):
        return False


def _stop_and_reap_owned_tree(process: subprocess.Popen[bytes], root: tuple[int, str], owned: dict[int, str]) -> bool:
    if not _stop_owned_process_tree(root, owned):
        return False
    try:
        process.wait(timeout=1)
        return True
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        return False


def _sync_log(log: Any) -> None:
    os.fsync(log.fileno())


def _close_log(log: Any) -> None:
    log.close()


def _run(
    argv: Sequence[str], *, cwd: pathlib.Path, env: dict[str, str], timeout: int,
    log_path: pathlib.Path, settle_report: dict[str, Any] | None = None,
    max_log_bytes: int | None = None,
    provenance: bool = False,
    provenance_report: dict[str, Any] | None = None,
) -> tuple[int, float]:
    """Run one supervised command, optionally enforcing a live log-size cap.

    With `provenance`, the run arms process-provenance classification (macOS
    coalitions; Linux child-subreaper) so uninspectable processes that are
    positively not descendants stop blocking; the evidence goes to
    `provenance_report`. If the mechanism is unavailable nothing is classified.


    With `max_log_bytes`, the poll loop checks the log's size; on overflow it
    stops only this run's owned process tree through the same path as a
    timeout, returns LOG_LIMIT_EXIT_CODE, and any tree that cannot be confirmed
    drained fails closed as an uncertain process tree.
    """
    started = time.monotonic()
    fd = private_roots.create_private_file(
        log_path, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600,
    )
    code = 0
    uncertain: str | None = None
    process: subprocess.Popen[bytes] | None = None
    root_identity: tuple[int, str] | None = None
    baseline_snapshot: dict[int, tuple[int, str, str]] | None = None
    owned: dict[int, str] = {}
    tree_confirmed_drained = True
    final_ownership_scan_returned = False
    last_snapshot: dict[int, tuple[int, str, str]] | None = None
    log_io_error: BaseException | None = None
    unconfirmed_processes: list[dict[str, Any]] = []
    unconfirmed_process_count = 0
    unconfirmed_processes_truncated = False
    probe_evidence = ProbeEvidence()
    timed_out = interrupted = log_overflow = False
    prov: Any = None
    if provenance:
        prov = provenance_module.Provenance()
        prov.start()
    try:
        log = os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise

    def track(root: tuple[int, str], snapshot: dict[int, tuple[int, str, str]]) -> None:
        _track_descendants(root, owned, snapshot)
        if prov is not None:
            prov.observe(snapshot, baseline_snapshot or {}, owned)

    def write_diagnostic(payload: bytes) -> None:
        nonlocal log_io_error
        try:
            log.write(payload)
        except OSError as exc:
            if log_io_error is None:
                log_io_error = exc

    try:
        try:
            baseline_snapshot = _process_snapshot()
            process = subprocess.Popen(list(argv), cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            if prov is not None:
                prov.note_root(process.pid)
            tree_confirmed_drained = False
            deadline = time.monotonic() + timeout
            # Keep the direct child unreaped until its first ps snapshot; Popen
            # does not poll or wait implicitly, so short-lived roots remain visible.
            snapshot = _process_snapshot()
            last_snapshot = snapshot
            root_record = snapshot.get(process.pid)
            if root_record is not None:
                root_identity = (process.pid, root_record[1])
                track(root_identity, snapshot)
            while True:
                snapshot = _process_snapshot()
                last_snapshot = snapshot
                if root_identity is not None:
                    track(root_identity, snapshot)
                try:
                    code = process.wait(timeout=0.05)
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    if max_log_bytes is not None:
                        try:
                            log_size = os.fstat(log.fileno()).st_size
                        except (OSError, ValueError):
                            log_size = max_log_bytes + 1  # unreadable size fails closed
                        if log_size > max_log_bytes:
                            log_overflow = True
                            break
            if root_identity is None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        time.sleep(0.1)
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=2)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        pass
                uncertain = f"cannot identify process {process.pid} or its descendants"
            elif timed_out or interrupted or log_overflow:
                if not _stop_and_reap_owned_tree(process, root_identity, owned):
                    cause = "timed-out" if timed_out else ("log-limit-exceeded" if log_overflow else "interrupted")
                    uncertain = f"{cause} process tree rooted at {process.pid} could not be confirmed drained"
                elif log_overflow:
                    tree_confirmed_drained = True
                    code = LOG_LIMIT_EXIT_CODE
                    write_diagnostic(b"\nGate log exceeded its size limit; owned process tree drained.\n")
                elif timed_out:
                    tree_confirmed_drained = True
                    code = 124
                    write_diagnostic(
                        f"\nGate timed out after {timeout} seconds; owned process tree drained.\n".encode()
                    )
                else:
                    tree_confirmed_drained = True
                    code = 130
                    write_diagnostic(b"\nGate interrupted; owned process tree drained.\n")
            else:
                snapshot = _process_snapshot()
                track(root_identity, snapshot)
                if _owned_processes_alive(owned, snapshot):
                    if not _stop_and_reap_owned_tree(process, root_identity, owned):
                        uncertain = f"completed process tree rooted at {process.pid} could not be confirmed drained"
                    else:
                        tree_confirmed_drained = True
                        code = 125
                        write_diagnostic(
                            b"\nGate left descendant processes running; tree drained and gate failed.\n"
                        )
                else:
                    tree_confirmed_drained = True
        except KeyboardInterrupt:
            interrupted = True
            if process is not None and root_identity is not None and _stop_and_reap_owned_tree(process, root_identity, owned):
                tree_confirmed_drained = True
                code = 130
                write_diagnostic(b"\nGate interrupted; owned process tree drained.\n")
            else:
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        time.sleep(0.1)
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=2)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        pass
                uncertain = f"interrupted process tree rooted at {process.pid if process else 'unknown'} could not be confirmed drained"
        except RuntimeError as exc:
            if process is None:
                code = 127
                write_diagnostic(f"Gate could not start ({type(exc).__name__}).\n".encode())
            else:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        time.sleep(0.1)
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=2)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        pass
                uncertain = f"process ownership could not be enumerated for gate rooted at {process.pid}: {exc}"
        except OSError as exc:
            if process is None:
                code = 127
                write_diagnostic(f"Gate could not start ({type(exc).__name__}).\n".encode())
            else:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        time.sleep(0.1)
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=2)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        pass
                uncertain = f"process ownership could not be enumerated for gate rooted at {process.pid}: {type(exc).__name__}"
        if process is not None and baseline_snapshot is not None:
            try:
                final_snapshot = _process_snapshot()
                last_snapshot = final_snapshot
                if root_identity is not None:
                    track(root_identity, final_snapshot)
                scan = _untracked_processes_since(
                    baseline_snapshot, owned, final_snapshot, log_path, provenance=prov,
                )
                unconfirmed_processes = scan.unconfirmed
                unconfirmed_process_count = scan.candidate_count
                unconfirmed_processes_truncated = scan.candidate_count > len(scan.unconfirmed)
                probe_evidence.add_probes(scan.owned_probes)
                final_ownership_scan_returned = True
                settle_eligible = _natural_exit_settle_eligible(
                    scan, tree_confirmed_drained=tree_confirmed_drained,
                    log_io_failed=log_io_error is not None,
                    prior_uncertainty=uncertain is not None,
                )
                if settle_eligible and root_identity is not None:
                    initial_uninspectable = [dict(item) for item in scan.uninspectable]
                    initial_identities = {
                        (item["pid"], item["startedAt"]) for item in initial_uninspectable
                    }
                    identity_union = UnconfirmedIdentityUnion()

                    def scan_to_deadline(deadline: float) -> tuple[dict[int, tuple[int, str, str]], UntrackedProcessScan]:
                        # Evidence is captured here, before the settle and
                        # global helpers can absorb a cleanup exception into a
                        # string or treat returned probes as a plain failure.
                        try:
                            snapshot, current_scan = _bounded_ownership_scan(
                                deadline,
                                snapshot=lambda **kwargs: _process_snapshot(**kwargs),
                                descriptor_scan=lambda snapshot, **kwargs: _untracked_processes_since(
                                    baseline_snapshot, owned, snapshot, log_path, provenance=prov, **kwargs,
                                ),
                                after_snapshot=lambda snapshot: track(root_identity, snapshot),
                            )
                        except BaseException as scan_exc:
                            probe_evidence.add_exception(scan_exc)
                            raise
                        probe_evidence.add_probes(current_scan.owned_probes)
                        return snapshot, current_scan

                    settling_started = time.monotonic()
                    settled = _settle_uninspectable_candidates(
                        initial_uninspectable, scan_to_deadline,
                        identity_union=identity_union,
                        owned_alive=lambda snapshot: _owned_processes_alive(owned, snapshot),
                    )
                    report = {
                        "eligible": True,
                        "settled": False,
                        "initialIdentities": initial_uninspectable,
                        "initialCandidateCount": scan.candidate_count,
                        "latestIdentities": settled.latest_candidates[:MAX_UNCONFIRMED_SAMPLE],
                        "latestCandidateCount": len(settled.latest_candidates),
                        "initialSettleSeconds": round(settled.elapsed_seconds, 6),
                        "waitSeconds": round(settled.elapsed_seconds, 6),
                        "settleWindowSeconds": NATURAL_EXIT_SETTLE_SECONDS,
                        "deadlineRemainingSeconds": round(max(0.0, settled.deadline - time.monotonic()), 6),
                        "pollCount": settled.poll_count,
                        "globalRescanCount": 0,
                        "error": settled.last_error,
                    }
                    if settled.cleared:
                        clean_scans, latest_identities, final_scan_error, global_scan_count = (
                            _final_global_quiescence_scan(
                                settled.deadline,
                                scan_to_deadline,
                                lambda snapshot: _owned_processes_alive(owned, snapshot),
                                identity_union=identity_union,
                                pending_identities=initial_identities,
                            )
                        )
                        report["globalRescanCount"] = global_scan_count
                        report["latestIdentities"] = latest_identities
                        report["latestCandidateCount"] = len(latest_identities)
                        report["error"] = final_scan_error
                        # Complete elapsed time (initial + global settling) against
                        # the one original absolute deadline; never reset it.
                        report["waitSeconds"] = round(time.monotonic() - settling_started, 6)
                        report["deadlineRemainingSeconds"] = round(max(0.0, settled.deadline - time.monotonic()), 6)
                        if clean_scans:
                            report["settled"] = True
                            unconfirmed_processes = []
                            unconfirmed_process_count = 0
                            unconfirmed_processes_truncated = False
                            uncertain = None
                        else:
                            uncertain = "natural-exit settling did not establish a clean global ownership rescan"
                            unconfirmed_processes = list(identity_union.sample)
                            unconfirmed_process_count = identity_union.count
                            unconfirmed_processes_truncated = identity_union.truncated
                    else:
                        uncertain = "initial uninspectable process identity could not be cleared within the settling window"
                        unconfirmed_processes = list(identity_union.sample)
                        unconfirmed_process_count = max(scan.candidate_count, identity_union.count)
                        unconfirmed_processes_truncated = (
                            identity_union.truncated or unconfirmed_process_count > len(unconfirmed_processes)
                        )
                    # On success the union only repeats the initial identities plus
                    # churn that already exited; keep counts, not the list.
                    report["identityUnion"] = [] if report.get("settled") else list(identity_union.sample)
                    report["identityUnionCount"] = identity_union.count
                    report["identityUnionTruncated"] = identity_union.truncated
                    report.update(probe_evidence.report_fields())
                    if settle_report is not None:
                        settle_report.update(report)
                else:
                    if scan.error:
                        uncertain = uncertain or f"post-command ownership scan incomplete: {scan.error}"
                    if unconfirmed_processes:
                        uncertain = uncertain or (
                            "completed gate left live processes created during the command that were not "
                            "observed as owned descendants; builder leases require manual review"
                        )
                    if settle_report is not None and not probe_evidence.empty:
                        settle_report.update(probe_evidence.report_fields())
            except BaseException as exc:
                probe_evidence.add_exception(exc)
                if settle_report is not None and not probe_evidence.empty:
                    settle_report.update(probe_evidence.report_fields())
                uncertain = uncertain or f"post-command ownership scan could not be completed: {type(exc).__name__}"
                if last_snapshot is not None:
                    (unconfirmed_processes, unconfirmed_process_count,
                     unconfirmed_processes_truncated) = _bounded_unconfirmed(
                        _unconfirmed_candidates_since(baseline_snapshot, owned, last_snapshot),
                    )
        try:
            log.flush()
            _sync_log(log)
        except BaseException as exc:
            log_io_error = exc
    except BaseException as exc:
        # This catches write failures too. A spawned process is never released
        # from its lease until its complete owned tree is known to be drained.
        log_io_error = exc
    finally:
        try:
            _close_log(log)
        except BaseException as exc:
            if log_io_error is None:
                log_io_error = exc
    if prov is not None:
        prov.stop()
        if provenance_report is not None:
            provenance_report.update(prov.report())
    if log_io_error is not None and process is not None and not tree_confirmed_drained:
        if root_identity is not None and _stop_and_reap_owned_tree(process, root_identity, owned):
            tree_confirmed_drained = True
        else:
            uncertain = uncertain or f"process tree rooted at {process.pid} could not be confirmed drained after log I/O failure"
    if process is not None and not final_ownership_scan_returned:
        uncertain = uncertain or f"post-command ownership scan could not be completed: {type(log_io_error).__name__ if log_io_error else 'unknown'}"
        if baseline_snapshot is not None and last_snapshot is not None and not unconfirmed_processes:
            (unconfirmed_processes, unconfirmed_process_count,
             unconfirmed_processes_truncated) = _bounded_unconfirmed(
                _unconfirmed_candidates_since(baseline_snapshot, owned, last_snapshot),
            )
    if uncertain is not None:
        error = UncertainProcessTree(uncertain, process.pid if process else -1)
        error.owned_processes = dict(owned)
        error.unconfirmed_processes = unconfirmed_processes
        error.unconfirmed_process_count = unconfirmed_process_count
        error.unconfirmed_processes_truncated = (
            unconfirmed_processes_truncated or unconfirmed_process_count > len(unconfirmed_processes)
        )
        error.owned_probe_processes = list(probe_evidence.probes)
        error.owned_probe_process_count = probe_evidence.probe_count
        error.cleanup_exceptions = list(probe_evidence.exceptions)
        error.cleanup_exception_count = probe_evidence.exception_count
        error.probe_evidence_truncated = probe_evidence.truncated or probe_evidence.probe_count > len(probe_evidence.probes)
        error.raw_exit_code = process.returncode if process is not None else None
        error.duration_seconds = round(time.monotonic() - started, 6)
        error.command_started = process is not None
        raise error
    if log_io_error is not None:
        if process is not None:
            raise AttemptedGateFailure(
                log_io_error, process.returncode, round(time.monotonic() - started, 6),
            ) from log_io_error
        raise log_io_error
    return code, round(time.monotonic() - started, 6)


def _hash_file(path: pathlib.Path) -> str:
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
    with stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo: pathlib.Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"git command failed: {args[0]}")
    return result.stdout.strip()


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _first_nonempty_version_line(raw: bytes) -> str:
    """Use the same bounded normalization for recorded version probes and review."""
    for line in raw.decode("utf-8", "replace").splitlines():
        normalized = line.strip()
        if normalized:
            return normalized[:240]
    return "no version output"


def _tree_state_digest(repo: pathlib.Path) -> str:
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    work = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    cached = subprocess.run(["git", "diff", "--cached", "--binary", "HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if status.returncode or work.returncode or cached.returncode:
        raise RuntimeError("cannot capture working-tree identity")
    pieces = [status.stdout, work.stdout, cached.stdout]
    for entry in status.stdout.split(b"\0"):
        if not entry:
            continue
        name = entry[3:].decode("utf-8", "surrogateescape")
        path = repo / name
        if path.is_symlink():
            pieces.extend((name.encode("utf-8", "surrogateescape"), os.readlink(path).encode()))
        elif path.is_file():
            pieces.extend((name.encode("utf-8", "surrogateescape"), path.read_bytes()))
    return _hash(b"\0".join(pieces))


def _phase_diff(repo: pathlib.Path, base: str) -> bytes:
    result = subprocess.run(["git", "diff", "--binary", f"{base}...HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError("cannot capture pinned phase diff")
    return result.stdout


VERSION_COMMANDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("rustc", ("rustc", "--version"), "."),
    ("cargo", ("cargo", "--version"), "."),
    ("rustup", ("rustup", "--version"), "."),
    ("java", ("java", "-version"), "."),
    ("node", ("node", "--version"), "."),
    ("npm", ("npm", "--version"), "."),
    ("gradle-wrapper", ("./gradlew", "--no-daemon", "--version"), "adapters/java"),
    ("buf", ("./node_modules/.bin/buf", "--version"), "adapters/node"),
    ("playwright", ("./node_modules/.bin/playwright", "--version"), "web/app"),
    ("python", (sys.executable, "--version"), "."),
    ("git", ("git", "--version"), "."),
)


def _versions(
    repo: pathlib.Path,
    env: dict[str, str],
    logs_dir: pathlib.Path,
    probes: list[dict[str, Any]],
    *,
    names: set[str] | None = None,
    timeout: float = 20,
    provenance: bool = False,
) -> dict[str, str]:
    versions: dict[str, str] = {}
    private_roots.ensure_private_directory(logs_dir)
    for name, argv, cwd in VERSION_COMMANDS:
        if names is not None and name not in names:
            continue
        log_name = f"version-{name}.log"
        log_path = logs_dir / log_name
        settle_report: dict[str, Any] = {}
        provenance_report: dict[str, Any] = {}
        try:
            exit_code, duration = _run(
                argv, cwd=repo / cwd, env=env, timeout=timeout, log_path=log_path,
                settle_report=settle_report, provenance=provenance, provenance_report=provenance_report,
            )
        except (UncertainProcessTree, AttemptedGateFailure) as exc:
            if not exc.command_started:
                raise
            probe: dict[str, Any] = {
                "name": name,
                "argv": list(argv),
                "cwd": cwd,
                "exitCode": exc.raw_exit_code,
                "durationSeconds": exc.duration_seconds,
                "status": "failed",
                "cleanupUncertain": isinstance(exc, UncertainProcessTree),
                "sourceIdentityAfter": "unavailable because version probe finalization failed",
            }
            if log_path.is_file():
                try:
                    probe["logSha256"] = _hash_file(log_path)
                except OSError:
                    probe["logHash"] = "unavailable"
                probe["log"] = f"logs/{log_name}"
            if settle_report:
                probe["naturalExitSettle"] = settle_report
            if provenance_report.get("classifiedCount"):
                probe["provenance"] = provenance_report
            probes.append(probe)
            raise
        try:
            raw = log_path.read_bytes()
        except OSError as exc:
            probe = {
                "name": name,
                "argv": list(argv),
                "cwd": cwd,
                "exitCode": exit_code,
                "durationSeconds": duration,
                "log": f"logs/{log_name}",
                "status": "failed",
                "sourceIdentityAfter": "unavailable because version probe log finalization failed",
            }
            try:
                probe["logSha256"] = _hash_file(log_path)
            except OSError:
                probe["logHash"] = "unavailable"
            if settle_report:
                probe["naturalExitSettle"] = settle_report
            if provenance_report.get("classifiedCount"):
                probe["provenance"] = provenance_report
            probes.append(probe)
            raise RuntimeError("version probe log could not be read") from exc
        probe = {
            "name": name,
            "argv": list(argv),
            "cwd": cwd,
            "exitCode": exit_code,
            "durationSeconds": duration,
            "log": f"logs/{log_name}",
            "logSha256": _hash(raw),
            "status": "unavailable" if exit_code == 127 else ("passed" if exit_code == 0 else "failed"),
        }
        if settle_report:
            probe["naturalExitSettle"] = settle_report
        if provenance_report.get("classifiedCount"):
            probe["provenance"] = provenance_report
        probes.append(probe)
        if exit_code == 127:
            versions[name] = "unavailable"
        elif exit_code != 0:
            raise RuntimeError(f"version probe {name} failed with exit {exit_code}")
        else:
            versions[name] = _first_nonempty_version_line(raw)
    return versions


def _restricted_env(base_env: dict[str, str], cache: pathlib.Path, label: str) -> tuple[dict[str, str], str]:
    cargo = shutil.which("cargo", path=base_env.get("PATH"))
    rustc = shutil.which("rustc", path=base_env.get("PATH"))
    if not cargo or not rustc:
        raise RuntimeError("cargo and rustc must be available before the restricted-PATH gate")
    keep = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "RUSTUP_HOME")
    env = {key: base_env[key] for key in keep if key in base_env}
    env.update({
        "PATH": "/usr/bin:/bin",
        "RUSTC": rustc,
        "CARGO_HOME": str(cache / "cargo"),
        "CARGO_TARGET_DIR": str(cache / f"cargo-target-restricted-{label}"),
        "XDG_CACHE_HOME": str(cache / "xdg"),
        "TMPDIR": str(cache / "tmp"),
        "RUSTUP_HOME": base_env.get("RUSTUP_HOME", str(pathlib.Path.home() / ".rustup")),
    })
    return env, cargo


def _atomic_write(path: pathlib.Path, data: bytes) -> None:
    private_roots.atomic_write_private(path, data)


def _atomic_json(path: pathlib.Path, value: Any) -> None:
    _atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


_SETTLE_LIST_FIELDS = ("initialIdentities", "latestIdentities", "identityUnion", "ownedProbeProcesses", "cleanupExceptions", "classifiedIdentities")


def _settle_reports(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for group in ("gates", "versionProbes"):
        for item in manifest.get(group) or []:
            for key in ("naturalExitSettle", "provenance"):
                report = item.get(key) if isinstance(item, dict) else None
                if isinstance(report, dict):
                    reports.append(report)
    return reports


def _receipt_fits(manifest: dict[str, Any]) -> bool:
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return private_roots.private_json_fits_read_limits(
        data, maximum_nodes=RECEIPT_JSON_BUDGET, maximum_commas=RECEIPT_JSON_BUDGET,
    )


def _write_receipt(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    """Write the receipt, guaranteeing it stays readable under the CI read limits.

    Oversized settle reports are compacted in stages (identity lists first cut,
    then dropped) while keeping every count and truncation flag; a receipt that
    still cannot fit is an error rather than an unreadable file.
    """
    if not _receipt_fits(manifest):
        for keep in (8, 0):
            for report in _settle_reports(manifest):
                for name in _SETTLE_LIST_FIELDS:
                    items = report.get(name)
                    if isinstance(items, list) and len(items) > keep:
                        report[name] = items[:keep]
                        report["evidenceListsCompacted"] = True
            if _receipt_fits(manifest):
                break
        else:
            raise RuntimeError("release receipt cannot be bounded to the readable limits")
    _atomic_json(path, manifest)


class Lease:
    def __init__(self, path: pathlib.Path, token: str, label: str):
        self.path = path
        self.token = token
        self.label = label
        self.acquired = False
        self.borrowed = False

    def acquire(self) -> None:
        created = False
        try:
            private_roots.ensure_private_directory(self.path, must_create=True)
            created = True
        except FileExistsError as exc:
            private_roots.admit_directory(self.path, private_leaf=True)
            owner = "unknown owner"
            recovery: bool | None = None
            try:
                data = private_roots.read_private_json(self.path / "owner.json")
                recovery = data.get("requiresManualRecovery") is True
                owner_pid = data.get("pid")
                owner_label = data.get("label")
                if (isinstance(owner_pid, int) and not isinstance(owner_pid, bool)
                        and 0 < owner_pid <= 2**31 - 1
                        and isinstance(owner_label, str) and LABEL_RE.fullmatch(owner_label)):
                    owner = f"pid {owner_pid} label {owner_label}"
                if data.get("token") == self.token:
                    self.borrowed = True
                    return
            except (OSError, RuntimeError, ValueError):
                pass
            raise LeaseBusy(
                f"release builder lease is already owned ({owner}); share the exact lease token only with a nested gate invocation",
                recovery,
            ) from exc
        if not created:
            raise LeaseBusy("release builder lease is already owned (unknown owner)")
        self.acquired = True
        try:
            _atomic_json(self.path / "owner.json", {"pid": os.getpid(), "label": self.label, "token": self.token, "startedAtEpoch": int(time.time())})
        except BaseException:
            try:
                private_roots.admit_directory(self.path, private_leaf=True)
                shutil.rmtree(self.path)
            except (OSError, RuntimeError, ValueError):
                pass
            self.acquired = False
            raise

    def release(self) -> None:
        if self.acquired and not self.borrowed:
            private_roots.admit_directory(self.path, private_leaf=True)
            shutil.rmtree(self.path)
            self.acquired = False

    def retain_for_manual_recovery(
        self,
        reason: str,
        process_group_id: int,
        owned_processes: dict[int, str],
        unconfirmed_processes: list[dict[str, Any]] | None = None,
        unconfirmed_process_count: int | None = None,
        owned_probe_processes: list[dict[str, Any]] | None = None,
        unconfirmed_processes_truncated: bool | None = None,
        cleanup_exceptions: list[dict[str, Any]] | None = None,
        cleanup_exception_count: int | None = None,
        owned_probe_process_count: int | None = None,
        probe_evidence_truncated: bool | None = None,
    ) -> None:
        """Retain the lease with bounded evidence.

        `unconfirmed_processes_truncated` is the explicit caller-supplied flag;
        when omitted (older callers) it is inferred from count > sample length.
        """
        if not self.acquired or self.borrowed:
            return
        try:
            private_roots.admit_directory(self.path, private_leaf=True)
            owner = private_roots.read_private_json(self.path / "owner.json")
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("release lease owner record failed private admission; lease retained without modification") from None
        owner["requiresManualRecovery"] = True
        owner["terminationStatus"] = reason
        owner["processGroupId"] = process_group_id
        owner["ownedProcesses"] = [{"pid": pid, "startedAt": started_at} for pid, started_at in sorted(owned_processes.items())]
        if unconfirmed_processes:
            owner["unconfirmedProcesses"] = unconfirmed_processes
        if unconfirmed_process_count is not None:
            owner["unconfirmedProcessCount"] = unconfirmed_process_count
            owner["unconfirmedProcessesTruncated"] = bool(
                unconfirmed_processes_truncated
                or unconfirmed_process_count > len(unconfirmed_processes or [])
            )
        if owned_probe_processes:
            owner["ownedProbeProcesses"] = owned_probe_processes
        if owned_probe_process_count is not None:
            owner["ownedProbeProcessCount"] = owned_probe_process_count
        if cleanup_exceptions:
            counts: dict[str, int] = {}
            for item in cleanup_exceptions[:MAX_CLEANUP_EXCEPTION_RECORDS]:
                name = item.get("type") if isinstance(item, dict) else None
                name = name[:MAX_REASON_CHARS] if isinstance(name, str) else "unknown"
                counts[name] = counts.get(name, 0) + 1
            owner["cleanupExceptions"] = counts
        if cleanup_exception_count is not None:
            owner["cleanupExceptionCount"] = cleanup_exception_count
        if probe_evidence_truncated is not None:
            owner["probeEvidenceTruncated"] = bool(
                probe_evidence_truncated
                or (owned_probe_process_count or 0) > len(owned_probe_processes or [])
            )
        _fit_owner_record(owner)
        _atomic_json(self.path / "owner.json", owner)


def _fit_owner_record(owner: dict[str, Any]) -> None:
    """Trim evidence lists until the owner record stays readable.

    The record must pass the same byte/node/comma/list limits that
    `private_roots.read_private_json` enforces, otherwise a retained lease would
    become unreadable. The largest evidence list is halved first and a truthful
    truncation flag is set for whatever is cut; lease identity fields are never
    trimmed.
    """
    flags = {
        "unconfirmedProcesses": "unconfirmedProcessesTruncated",
        "ownedProcesses": "ownedProcessesTruncated",
        "ownedProbeProcesses": "probeEvidenceTruncated",
    }
    # Run-owned probe identities are the last evidence to be trimmed.
    tiers = (("unconfirmedProcesses", "ownedProcesses"), ("ownedProbeProcesses",))

    def fits() -> bool:
        data = (json.dumps(owner, indent=2, sort_keys=True) + "\n").encode()
        return private_roots.private_json_fits_read_limits(data)

    for _ in range(64):
        if fits():
            return
        for tier in tiers:
            candidates = [
                (len(owner[name]), name == "unconfirmedProcesses", name) for name in tier
                if isinstance(owner.get(name), list) and len(owner[name]) > 1
            ]
            if candidates:
                _size, _first, name = max(candidates)
                owner[name] = owner[name][: len(owner[name]) // 2]
                owner[flags[name]] = True
                break
        else:
            break
    if not fits():
        for name, flag in flags.items():
            if isinstance(owner.get(name), list):
                owner[name] = []
                owner[flag] = True
        if not fits():
            raise RuntimeError("release lease owner record cannot be bounded; lease retained without modification")


def _retain_uncertain_leases(leases: Sequence[Lease], exc: UncertainProcessTree) -> list[str]:
    """Retain every acquired lease with the complete bounded evidence.

    Forwards the explicit unconfirmed-process truncation flag and all probe and
    cleanup-exception evidence. Returns labels whose owner record was unavailable.
    """
    failed: list[str] = []
    for lease in leases:
        try:
            lease.retain_for_manual_recovery(
                str(exc), exc.process_group_id, exc.owned_processes, exc.unconfirmed_processes,
                exc.unconfirmed_process_count, exc.owned_probe_processes,
                unconfirmed_processes_truncated=exc.unconfirmed_processes_truncated,
                cleanup_exceptions=exc.cleanup_exceptions,
                cleanup_exception_count=exc.cleanup_exception_count,
                owned_probe_process_count=exc.owned_probe_process_count,
                probe_evidence_truncated=exc.probe_evidence_truncated,
            )
        except (OSError, RuntimeError, ValueError):
            failed.append(lease.label)
    return failed


def run(args: argparse.Namespace) -> int:
    if os.name != "posix":
        raise ValueError("release gate process-tree control requires a POSIX host")
    if args.command_timeout <= 0:
        raise ValueError("--command-timeout must be a positive number of seconds")
    args.lease_token = getattr(args, "lease_token", "") or secrets.token_hex(16)
    repo = pathlib.Path(args.repo).expanduser().resolve(strict=True)
    cache = private_roots.normalize_directory_path(args.cache_root)
    if not (repo / ".git").exists():
        raise ValueError("--repo must be a Git checkout")
    if not LABEL_RE.fullmatch(args.label):
        raise ValueError("--label must contain only letters, digits, dot, underscore, and hyphen")
    if not SHA_RE.fullmatch(args.base.lower()):
        raise ValueError("--base must be a full 40-character commit SHA")
    base = args.base.lower()
    if _git(repo, "cat-file", "-t", base) != "commit":
        raise ValueError("--base must identify an immutable commit object")
    head_start = _git(repo, "rev-parse", "HEAD").lower()
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=repo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if ancestry.returncode:
        raise ValueError("pinned phase base must be an ancestor of HEAD")
    if not re.fullmatch(r"[0-9a-f]{32}", args.lease_token):
        raise ValueError("--lease-token must be 32 lowercase hexadecimal characters")

    restricted_target = cache / f"cargo-target-restricted-{args.label}"
    release_root = cache / "release-gates"
    run_dir = release_root / args.label
    logs_dir = run_dir / "logs"
    lease_root = cache / "leases"
    leases = [Lease(lease_root / name, args.lease_token, args.label) for name in LEASE_NAMES]
    # Inspect every existing named root before the first cache mutation. Missing
    # descendants are admitted through their nearest existing no-follow parent.
    private_roots.preflight_directory(cache, private_leaf=True)
    for name in CACHE_NAMES:
        private_roots.preflight_directory(cache / name, private_leaf=True)
    private_roots.preflight_directory(restricted_target, must_be_absent=True)
    private_roots.preflight_directory(release_root, private_leaf=True)
    private_roots.preflight_directory(run_dir, must_be_absent=True)
    private_roots.preflight_directory(logs_dir, must_be_absent=True)
    private_roots.preflight_directory(lease_root, private_leaf=True)
    for lease in leases:
        private_roots.preflight_directory(lease.path, private_leaf=True)

    private_roots.ensure_private_directory(cache)
    for name in CACHE_NAMES:
        private_roots.ensure_private_directory(cache / name)
    restricted_target_identity = private_roots.ensure_private_directory(restricted_target, must_create=True)
    private_roots.ensure_private_directory(release_root)
    private_roots.ensure_private_directory(run_dir, must_create=True)
    private_roots.ensure_private_directory(logs_dir, must_create=True)
    private_roots.ensure_private_directory(lease_root)
    logs_identity = private_roots.admit_directory(logs_dir, private_leaf=True)

    private_roots_to_recheck = [
        cache,
        *(cache / name for name in CACHE_NAMES),
        restricted_target,
        release_root,
        run_dir,
        logs_dir,
        lease_root,
    ]

    def recheck_private_roots() -> None:
        for private_root in private_roots_to_recheck:
            private_roots.admit_directory(private_root, private_leaf=True)

    results: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "label": args.label,
        "phaseBase": base,
        "headBefore": head_start,
        "headAfter": None,
        "workingTreeDigestBefore": None,
        "workingTreeDigestAfter": None,
        "phaseDiffSha256Before": None,
        "phaseDiffSha256After": None,
        "toolVersions": {},
        "versionProbes": [],
        "cacheKeys": list(CACHE_NAMES),
        "restrictedTargetKey": f"cargo-target-restricted-{args.label}",
        "gates": results,
        "decision": "running",
    }
    acquired_leases: list[Lease] = []
    retain_leases = False
    active_attempt: dict[str, Any] | None = None
    try:
        recheck_private_roots()
        for lease in leases:
            lease.acquire()
            acquired_leases.append(lease)
        if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
            raise RuntimeError("checkout must be clean so the receipt identifies exactly HEAD")
        diff_start = _phase_diff(repo, base)
        dirty_start = _tree_state_digest(repo)
        use_provenance = bool(getattr(args, "provenance", False))
        env = os.environ.copy()
        env.update({
            "CARGO_HOME": str(cache / "cargo"),
            "CARGO_TARGET_DIR": str(cache / "cargo-target"),
            "GRADLE_USER_HOME": str(cache / "gradle"),
            "NPM_CONFIG_CACHE": str(cache / "npm"),
            "PLAYWRIGHT_BROWSERS_PATH": str(cache / "playwright"),
            "TMPDIR": str(cache / "tmp"),
            "XDG_CACHE_HOME": str(cache / "xdg"),
            "XTRACE_TEST_SCRATCH_ROOT": str(cache / "tmp"),
            "XTRACE_TEST_PRIVATE_SCRATCH": str(cache / "tmp"),
        })
        manifest["workingTreeDigestBefore"] = dirty_start
        manifest["phaseDiffSha256Before"] = _hash(diff_start)
        recheck_private_roots()
        manifest["toolVersions"] = _versions(
            repo, env, logs_dir, manifest["versionProbes"], names={"rustc", "cargo", "rustup", "java", "node", "npm", "gradle-wrapper", "python", "git"},
            provenance=use_provenance,
        )
        manifest["toolVersions"].update({"buf": "pending node install", "playwright": "pending web install"})
        manifest["platform"] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
        manifest["dependencyLockSha256"] = {
            name: _hash((repo / name).read_bytes())
            for name in ("Cargo.lock", "adapters/java/gradle.lockfile", "adapters/node/package-lock.json", "web/app/package-lock.json")
        }
        gate_settle_reports: dict[str, dict[str, Any]] = {}
        gate_provenance_reports: dict[str, dict[str, Any]] = {}

        def run_gate_command(
            argv: list[str], *, cwd: pathlib.Path, env: dict[str, str],
            temp_log_path: pathlib.Path, log_path: pathlib.Path, gate: Gate,
            head_before: str, tree_before: str, diff_before: str,
        ) -> tuple[int, float]:
            nonlocal active_attempt
            natural_exit_settle: dict[str, Any] = {}
            provenance_evidence: dict[str, Any] = {}
            try:
                result = _run(
                    argv, cwd=cwd, env=env, timeout=args.command_timeout,
                    log_path=temp_log_path,
                    settle_report=natural_exit_settle,
                    provenance=use_provenance, provenance_report=provenance_evidence,
                )
            except (UncertainProcessTree, AttemptedGateFailure) as exc:
                if not exc.command_started:
                    raise
                active_attempt = {
                    "gate": gate,
                    "argv": list(argv),
                    "headBefore": head_before,
                    "treeBefore": tree_before,
                    "diffBefore": diff_before,
                    "tempLogPath": temp_log_path,
                    "logPath": log_path,
                    "exitCode": exc.raw_exit_code,
                    "durationSeconds": exc.duration_seconds,
                    "cleanupUncertain": isinstance(exc, UncertainProcessTree),
                    "naturalExitSettle": natural_exit_settle,
                    "provenance": provenance_evidence,
                    "headAfter": None,
                    "treeAfter": None,
                    "diffAfter": None,
                }
                raise
            if natural_exit_settle:
                # Normal gate receipts include settling evidence after the
                # command result and final global scan have completed.
                gate_settle_reports[gate.name] = natural_exit_settle
            active_attempt = {
                "gate": gate,
                "argv": list(argv),
                "headBefore": head_before,
                "treeBefore": tree_before,
                "diffBefore": diff_before,
                "tempLogPath": temp_log_path,
                "logPath": log_path,
                "exitCode": result[0],
                "durationSeconds": result[1],
                "cleanupUncertain": False,
                "naturalExitSettle": natural_exit_settle,
                "provenance": provenance_evidence,
                "headAfter": None,
                "treeAfter": None,
                "diffAfter": None,
            }
            return result

        for index, gate in enumerate(GATES):
            recheck_private_roots()
            head_now = _git(repo, "rev-parse", "HEAD").lower()
            tree_before = _tree_state_digest(repo)
            diff_before = _hash(_phase_diff(repo, base))
            if head_now != head_start or tree_before != dirty_start or diff_before != _hash(diff_start):
                results.extend({"name": later.name, "status": "unreached", "reason": "source identity changed before gate"} for later in GATES[index:])
                manifest["integrityFailure"] = "source identity changed before gate"
                break
            gate_env = dict(env)
            argv = list(gate.argv)
            if gate.env == "rustdoc":
                gate_env["RUSTDOCFLAGS"] = "-D warnings"
            log_name = f"{gate.name}.log"
            log_path = logs_dir / log_name
            temp_log_path = logs_dir / f".{log_name}.{os.getpid()}.tmp"
            if gate.env == "restricted":
                gate_env, cargo_path = _restricted_env(os.environ.copy(), cache, args.label)
                if shutil.which("protoc", path=gate_env["PATH"]):
                    _atomic_write(log_path, b"protoc is present on restricted PATH; build not run\n")
                    code, duration = 1, 0.0
                    argv = ["protoc absence check", *gate.argv]
                else:
                    target = pathlib.Path(gate_env["CARGO_TARGET_DIR"])
                    private_roots.admit_empty_directory(target, restricted_target_identity)
                    argv = [cargo_path, *gate.argv[1:]]
                    code, duration = run_gate_command(
                        argv, cwd=repo, env=gate_env, temp_log_path=temp_log_path,
                        log_path=log_path, gate=gate, head_before=head_now,
                        tree_before=tree_before, diff_before=diff_before,
                    )
            elif gate.env == "phase-diff":
                argv = ["git", "diff", "--check", f"{base}...HEAD"]
                code, duration = run_gate_command(
                    argv, cwd=repo, env=gate_env, temp_log_path=temp_log_path,
                    log_path=log_path, gate=gate, head_before=head_now,
                    tree_before=tree_before, diff_before=diff_before,
                )
            else:
                code, duration = run_gate_command(
                    argv, cwd=repo / gate.cwd, env=gate_env, temp_log_path=temp_log_path,
                    log_path=log_path, gate=gate, head_before=head_now,
                    tree_before=tree_before, diff_before=diff_before,
                )
            if temp_log_path.exists():
                private_roots.replace_private_file(temp_log_path, log_path, logs_identity)
            head_after = _git(repo, "rev-parse", "HEAD").lower()
            active_attempt["headAfter"] = head_after
            tree_after = _tree_state_digest(repo)
            active_attempt["treeAfter"] = tree_after
            diff_after = _hash(_phase_diff(repo, base))
            active_attempt["diffAfter"] = diff_after
            entry = {
                "name": gate.name,
                "argv": argv,
                "cwd": gate.cwd,
                "exitCode": code,
                "durationSeconds": duration,
                "log": f"logs/{log_name}",
                "logSha256": _hash_file(log_path),
                "headBefore": head_now,
                "headAfter": head_after,
                "workingTreeDigestBefore": tree_before,
                "workingTreeDigestAfter": tree_after,
                "phaseDiffSha256Before": diff_before,
                "phaseDiffSha256After": diff_after,
                "status": "passed" if code == 0 else "failed",
            }
            if gate.name in gate_settle_reports:
                entry["naturalExitSettle"] = gate_settle_reports[gate.name]
            if active_attempt is not None and active_attempt.get("provenance", {}).get("classifiedCount"):
                entry["provenance"] = active_attempt["provenance"]
            if (entry["headAfter"] != head_start or entry["workingTreeDigestAfter"] != dirty_start
                    or entry["phaseDiffSha256After"] != _hash(diff_start)):
                entry["status"] = "failed"
                entry["integrityFailure"] = "source identity changed during gate"
                code = code or 1
            results.append(entry)
            active_attempt = None
            if gate.name == "node-install" and code == 0:
                recheck_private_roots()
                manifest["toolVersions"].update(_versions(repo, env, logs_dir, manifest["versionProbes"], names={"buf"}, provenance=use_provenance))
            if gate.name == "web-install" and code == 0:
                recheck_private_roots()
                manifest["toolVersions"].update(_versions(repo, env, logs_dir, manifest["versionProbes"], names={"playwright"}, provenance=use_provenance))
            manifest["headAfter"] = entry["headAfter"]
            manifest["gates"] = results
            manifest["decision"] = "running" if code == 0 else "failed"
            recheck_private_roots()
            _write_receipt(run_dir / "receipt.json", manifest)
            print(f"{'PASS' if code == 0 else 'FAIL'} {gate.name} (exit {code}; log {log_name})", flush=True)
            if code != 0:
                for later in GATES[index + 1:]:
                    results.append({"name": later.name, "status": "unreached", "reason": f"stopped after {gate.name} failed"})
                break
        if not results:
            results.extend({"name": gate.name, "status": "unreached", "reason": "gate run did not start"} for gate in GATES)
        head_end = _git(repo, "rev-parse", "HEAD").lower()
        diff_end = _phase_diff(repo, base)
        dirty_end = _tree_state_digest(repo)
        manifest.update({"headAfter": head_end, "workingTreeDigestAfter": dirty_end, "phaseDiffSha256After": _hash(diff_end), "gates": results})
        if head_end != head_start:
            manifest.update({"decision": "failed", "integrityFailure": "HEAD changed during gate run"})
        elif dirty_end != dirty_start:
            manifest.update({"decision": "failed", "integrityFailure": "working tree changed during gate run"})
        elif _hash(diff_end) != _hash(diff_start):
            manifest.update({"decision": "failed", "integrityFailure": "pinned phase diff changed during gate run"})
        elif len(results) == len(GATES) and all(item.get("status") == "passed" for item in results):
            manifest["decision"] = "checks_passed_for_review"
        else:
            manifest["decision"] = "failed"
        _write_receipt(run_dir / "receipt.json", manifest)
        print(f"Decision: {manifest['decision']} ({sum(item.get('status') != 'unreached' for item in results)}/{len(GATES)} gates reached)")
        return 0 if manifest["decision"] == "checks_passed_for_review" else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        uncertain_command = isinstance(exc, UncertainProcessTree) and exc.command_started
        # Lease retention is a consequence of the primary process-tree result,
        # not of whether its diagnostic artifacts can still be admitted.
        if uncertain_command:
            retain_leases = True
        lease_retention_errors: list[str] = []
        if active_attempt is not None:
            attempt = active_attempt
            gate = attempt["gate"]
            temp_log_path: pathlib.Path = attempt["tempLogPath"]
            log_path: pathlib.Path = attempt["logPath"]
            actual_log: pathlib.Path | None = None
            artifact_finalization_failed = False
            if temp_log_path.is_file():
                try:
                    private_roots.replace_private_file(temp_log_path, log_path, logs_identity)
                    actual_log = log_path
                except (OSError, RuntimeError, ValueError):
                    artifact_finalization_failed = True
                    if temp_log_path.is_file():
                        actual_log = temp_log_path
                    elif log_path.is_file():
                        actual_log = log_path
            elif log_path.is_file():
                actual_log = log_path
            entry: dict[str, Any] = {
                "name": gate.name,
                "argv": attempt["argv"],
                "cwd": gate.cwd,
                "exitCode": attempt["exitCode"],
                "durationSeconds": attempt["durationSeconds"],
                "headBefore": attempt["headBefore"],
                "headAfter": attempt["headAfter"],
                "workingTreeDigestBefore": attempt["treeBefore"],
                "workingTreeDigestAfter": attempt["treeAfter"],
                "phaseDiffSha256Before": attempt["diffBefore"],
                "phaseDiffSha256After": attempt["diffAfter"],
                "status": "failed",
                "cleanupUncertain": attempt["cleanupUncertain"],
                "sourceIdentityAfter": "unavailable because gate command finalization failed",
            }
            if artifact_finalization_failed:
                entry["artifactFinalization"] = "unavailable after private admission or filesystem error"
            if actual_log is not None:
                entry["log"] = f"logs/{actual_log.name}"
                try:
                    entry["logSha256"] = _hash_file(actual_log)
                except (OSError, RuntimeError, ValueError):
                    entry["logHash"] = "unavailable"
                    entry["artifactFinalization"] = "log hash unavailable after private admission or filesystem error"
            if attempt["naturalExitSettle"]:
                entry["naturalExitSettle"] = attempt["naturalExitSettle"]
            if attempt.get("provenance", {}).get("classifiedCount"):
                entry["provenance"] = attempt["provenance"]
            results.append(entry)
            active_attempt = None
            manifest["headAfter"] = None
            manifest["workingTreeDigestAfter"] = None
            manifest["phaseDiffSha256After"] = None
        if uncertain_command:
            lease_retention_errors.extend(_retain_uncertain_leases(acquired_leases, exc))
        manifest["decision"] = "failed"
        manifest["error"] = str(exc)
        if lease_retention_errors:
            manifest["leaseRetention"] = {
                "status": "owner records unavailable; leases retained without modification",
                "leaseNames": lease_retention_errors,
            }
        try:
            manifest["headAfter"] = _git(repo, "rev-parse", "HEAD").lower()
        except RuntimeError:
            pass
        completed = {item.get("name") for item in results}
        manifest["gates"] = results + [
            {"name": gate.name, "status": "unreached", "reason": "precondition or gate runner error"}
            for gate in GATES if gate.name not in completed
        ]
        try:
            _write_receipt(run_dir / "receipt.json", manifest)
        except (OSError, RuntimeError, ValueError):
            pass
        print(f"release gates failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if not retain_leases:
            for lease in reversed(acquired_leases):
                lease.release()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Git checkout to gate")
    parser.add_argument("--base", required=True, help="full immutable phase-base commit SHA")
    parser.add_argument("--label", required=True, help="unique phase/run label")
    parser.add_argument("--cache-root", required=True, help="explicit local cache and raw-log root")
    parser.add_argument("--lease-token", default="", help="shared 32-hex token for an explicitly nested invocation")
    parser.add_argument("--command-timeout", type=int, default=7200, help="per-command timeout in seconds")
    parser.add_argument("--no-provenance", dest="provenance", action="store_false", default=True,
                        help="disable process-provenance classification of uninspectable processes")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"release gates not accepted: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
