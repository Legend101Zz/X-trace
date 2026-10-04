#!/usr/bin/env python3
"""Positive classification of uninspectable processes by provenance.

An unprivileged runner cannot read the descriptor table of other users' processes,
so such a process stays an "uninspectable" unknown. Provenance supplies a positive,
structural reason that one of them is NOT a descendant of the supervised run, with
no UID or process-name rule and no privilege:

- macOS: processes carry a resource coalition id (`proc_pidinfo(PROC_PIDCOALITIONINFO)`)
  that is inherited across fork/exec and survives reparenting to launchd. A process whose
  coalition id is readable and differs from every coalition the run started in is
  `non-descendant-coalition`.
- Linux: while a command runs the runner is a child subreaper
  (`prctl(PR_SET_CHILD_SUBREAPER)`), so every orphaned descendant reparents to the runner and
  keeps a parent chain that reaches it. A process that was never in the observed descendant
  set and whose parent chain (in two independent snapshots) does not reach the runner, with a
  consistent start time, is `non-descendant-subreaper`.

Anything unreadable, inconsistent, equal to the run's coalition, overflowed, or on a host where
the mechanism is unavailable is NOT classified and stays uncertain (fail closed).
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

CLASS_COALITION = "non-descendant-coalition"
CLASS_SUBREAPER = "non-descendant-subreaper"
PROC_PIDCOALITIONINFO = 20
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
MAX_DESCENDANT_IDENTITIES = 4096
MAX_CHAIN_HOPS = 64
MAX_PENDING_ORPHANS = 1024
MAX_EVIDENCE_RECORDS = 64
ORPHAN_ADOPT_SECONDS = 0.5
FACTS_TIMEOUT_SECONDS = 1.0

Snapshot = dict[int, tuple[int, str, str]]


def read_coalition_id(pid: int) -> int | None:
    """Resource coalition id of `pid` via libproc, or None when unreadable/unsupported."""
    if sys.platform != "darwin":
        return None
    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        buffer = (ctypes.c_uint64 * 5)()
        size = libc.proc_pidinfo(int(pid), PROC_PIDCOALITIONINFO, 0, ctypes.byref(buffer), ctypes.sizeof(buffer))
    except (OSError, AttributeError, ValueError, TypeError):
        return None
    if size != ctypes.sizeof(buffer):
        return None
    return int(buffer[0])


def set_child_subreaper(enabled: bool) -> bool:
    """Set and verify PR_SET_CHILD_SUBREAPER for this process; False on any failure."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1 if enabled else 0, 0, 0, 0) != 0:
            return False
        value = ctypes.c_int(-1)
        if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(value), 0, 0, 0) != 0:
            return False
        return value.value == (1 if enabled else 0)
    except (OSError, AttributeError, ValueError, TypeError):
        return False


def read_process_facts(pids: Sequence[int], deadline: float) -> dict[int, tuple[int, str]]:
    """uid and normalized start time for pids via one bounded `ps`; empty on any failure."""
    ps = next((path for path in ("/bin/ps", "/usr/bin/ps") if os.path.isfile(path)), None)
    remaining = deadline - time.monotonic()
    if ps is None or not pids or remaining <= 0:
        return {}
    try:
        result = subprocess.run(
            [ps, "-o", "pid=,uid=,lstart=", "-p", ",".join(str(int(pid)) for pid in pids)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            timeout=min(FACTS_TIMEOUT_SECONDS, remaining), check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    facts: dict[int, tuple[int, str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 7 and fields[0].isdigit() and fields[1].isdigit():
            facts[int(fields[0])] = (int(fields[1]), " ".join(fields[2:7]))
    return facts


def chain_reaches(snapshot: Snapshot, pid: int, target: int) -> bool | None:
    """True if pid's parent chain reaches `target`, False if it ends at a root, None if inconsistent."""
    seen: set[int] = set()
    current = pid
    for _ in range(MAX_CHAIN_HOPS):
        record = snapshot.get(current)
        if record is None:
            return None
        parent = record[0]
        if parent == target:
            return True
        if parent <= 1:
            return False
        if parent in seen or parent == current:
            return None
        if parent not in snapshot:
            return None
        seen.add(current)
        current = parent
    return None


@dataclass
class ClassifiedEvidence:
    """Bounded record of classified identities with truthful totals."""

    sample: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    truncated: bool = False
    by_class: dict[str, int] = field(default_factory=dict)
    _keys: set[tuple[int, str]] = field(default_factory=set)

    def add(self, record: dict[str, Any]) -> None:
        key = (record["pid"], record["startedAt"])
        if key in self._keys:
            return
        if len(self._keys) < 4 * MAX_EVIDENCE_RECORDS:
            self._keys.add(key)
        else:
            self.truncated = True
        self.count += 1
        label = str(record.get("classification"))
        self.by_class[label] = self.by_class.get(label, 0) + 1
        if len(self.sample) < MAX_EVIDENCE_RECORDS:
            self.sample.append(dict(record))
        else:
            self.truncated = True

    def report(self) -> dict[str, Any]:
        return {
            "classifiedIdentities": list(self.sample),
            "classifiedCount": self.count,
            "classifiedByClass": dict(self.by_class),
            "classifiedTruncated": self.truncated,
        }


class Provenance:
    """Per-command provenance state; every dependency is injectable for tests."""

    def __init__(
        self,
        *,
        platform: str | None = None,
        runner_pid: int | None = None,
        uid: int | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        coalition_reader: Callable[[int], int | None] = read_coalition_id,
        subreaper_setter: Callable[[bool], bool] = set_child_subreaper,
        facts_reader: Callable[[Sequence[int], float], dict[int, tuple[int, str]]] = read_process_facts,
        reaper: Callable[[int, int], Any] | None = None,
    ) -> None:
        platform = sys.platform if platform is None else platform
        self.mode = "coalition" if platform == "darwin" else "subreaper" if platform.startswith("linux") else None
        self.runner_pid = os.getpid() if runner_pid is None else runner_pid
        self.uid = os.getuid() if uid is None else uid
        self._monotonic = monotonic
        self._coalition_reader = coalition_reader
        self._subreaper_setter = subreaper_setter
        self._facts_reader = facts_reader
        self._reaper = reaper if reaper is not None else self._default_reap
        self.available = False
        self.unavailable_reason = "unsupported-platform" if self.mode is None else "not-started"
        self.run_coalitions: set[int] = set()
        self.overflowed = False
        self.evidence = ClassifiedEvidence()
        self._descendants: set[tuple[int, str]] = set()
        self._pending: dict[int, tuple[str, float]] = {}
        self._adopted: dict[int, str] = {}
        self._subreaper_on = False

    @staticmethod
    def _default_reap(pid: int, flags: int) -> Any:
        return os.waitpid(pid, flags)

    def start(self) -> bool:
        """Arm the mechanism before the command starts; False means no classification."""
        if self.mode == "coalition":
            coalition = self._coalition_reader(self.runner_pid)
            if coalition is None:
                self.unavailable_reason = "coalition-unreadable"
                return False
            self.run_coalitions = {coalition}
            self.available = True
            self.unavailable_reason = ""
        elif self.mode == "subreaper":
            if not self._subreaper_setter(True):
                self.unavailable_reason = "prctl-failed"
                return False
            self._subreaper_on = True
            self.available = True
            self.unavailable_reason = ""
        return self.available

    def note_root(self, pid: int) -> None:
        """macOS: the command's own coalition also counts as the run's (never narrows it)."""
        if self.mode == "coalition" and self.available:
            coalition = self._coalition_reader(pid)
            if coalition is not None:
                self.run_coalitions.add(coalition)

    def stop(self) -> None:
        if self._subreaper_on:
            self._subreaper_setter(False)
            self._subreaper_on = False

    def observe(self, snapshot: Snapshot, baseline: Snapshot, owned: dict[int, str]) -> None:
        """Linux: record every process whose parent chain reaches the runner; adopt orphans.

        An orphan (direct child of the runner, not in the baseline) seen continuously for
        ORPHAN_ADOPT_SECONDS becomes an owned descendant so the existing drain rules apply;
        zombies of adopted orphans are reaped. Nothing is ever signaled here.
        """
        if self.mode != "subreaper" or not self.available:
            return
        now = self._monotonic()
        seen_orphans: set[int] = set()
        for pid, (ppid, started_at, state) in snapshot.items():
            if pid == self.runner_pid:
                continue
            baseline_record = baseline.get(pid)
            if baseline_record is not None and baseline_record[1] == started_at:
                continue
            if chain_reaches(snapshot, pid, self.runner_pid) is not True:
                continue
            if len(self._descendants) >= MAX_DESCENDANT_IDENTITIES:
                if (pid, started_at) not in self._descendants:
                    self.overflowed = True
                continue
            self._descendants.add((pid, started_at))
            if ppid != self.runner_pid:
                continue
            if state in {"Z", "X"}:
                if self._adopted.get(pid) == started_at:
                    self._reap(pid)
                continue
            if owned.get(pid) == started_at:
                continue
            seen_orphans.add(pid)
            first = self._pending.get(pid)
            if first is None or first[0] != started_at:
                if len(self._pending) < MAX_PENDING_ORPHANS:
                    self._pending[pid] = (started_at, now)
                else:
                    self.overflowed = True
            elif now - first[1] >= ORPHAN_ADOPT_SECONDS:
                owned[pid] = started_at
                self._adopted[pid] = started_at
        for pid in [pid for pid in self._pending if pid not in seen_orphans]:
            del self._pending[pid]

    def _reap(self, pid: int) -> None:
        try:
            self._reaper(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass

    def _record(self, pid: int, started_at: str, parent: int, uid: int, classification: str,
                extra: dict[str, Any]) -> dict[str, Any]:
        record = {
            "pid": pid, "startedAt": started_at, "observedParentPid": parent,
            "classification": classification, "uidClass": "same" if uid == self.uid else "other",
        }
        record.update(extra)
        return record

    def classify(
        self,
        unknowns: Sequence[tuple[int, str]],
        scan_snapshot: Snapshot,
        fresh_snapshot: Snapshot,
        owned: dict[int, str],
        deadline: float,
    ) -> dict[int, dict[str, Any]]:
        """Classify uninspectable identities; absent from the result means still uncertain."""
        if not self.available or self.overflowed or not unknowns:
            return {}
        facts = self._facts_reader([pid for pid, _started in unknowns], deadline)
        result: dict[int, dict[str, Any]] = {}
        for pid, started_at in unknowns:
            fact = facts.get(pid)
            fresh = fresh_snapshot.get(pid)
            original = scan_snapshot.get(pid)
            if (fact is None or fresh is None or original is None or fact[1] != started_at
                    or fresh[1] != started_at or original[1] != started_at
                    or fresh[2] in {"Z", "X"} or owned.get(pid) == started_at):
                continue
            uid, _start = fact
            if self.mode == "coalition":
                first = self._coalition_reader(pid)
                second = self._coalition_reader(pid)
                if first is None or first != second or first in self.run_coalitions:
                    continue
                again = self._facts_reader([pid], deadline).get(pid)
                if again is None or again[1] != started_at:
                    continue
                result[pid] = self._record(
                    pid, started_at, fresh[0], uid, CLASS_COALITION,
                    {"coalitionId": first, "runCoalitionIds": sorted(self.run_coalitions)[:4]},
                )
            elif self.mode == "subreaper":
                if (pid, started_at) in self._descendants:
                    continue
                if chain_reaches(scan_snapshot, pid, self.runner_pid) is not False:
                    continue
                if chain_reaches(fresh_snapshot, pid, self.runner_pid) is not False:
                    continue
                result[pid] = self._record(pid, started_at, fresh[0], uid, CLASS_SUBREAPER, {})
        for record in result.values():
            self.evidence.add(record)
        return result

    def report(self) -> dict[str, Any]:
        report = {
            "mode": self.mode, "available": self.available, "overflowed": self.overflowed,
            "unavailableReason": self.unavailable_reason, "adoptedOrphanCount": len(self._adopted),
        }
        report.update(self.evidence.report())
        return report
