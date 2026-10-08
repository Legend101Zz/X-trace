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
FACTS_TIMEOUT_SECONDS = 1.0
PROBE_EXCLUSION_SECONDS = 5.0
MAX_PROBE_REGISTRY = 256

# The runner's own short-lived helpers (ps, lsof) are direct children of the runner.
# They are registered by pid when spawned and again when they finish, so adoption can
# exclude exactly them by identity (never by timing): a daemon is never mistaken for one.
_PROBES: dict[int, float] = {}


def register_probe(pid: int) -> None:
    _PROBES[pid] = time.monotonic()
    if len(_PROBES) > MAX_PROBE_REGISTRY:
        for old in sorted(_PROBES, key=_PROBES.__getitem__)[: len(_PROBES) - MAX_PROBE_REGISTRY]:
            del _PROBES[old]


def recent_probe_pids(window: float = PROBE_EXCLUSION_SECONDS) -> set[int]:
    cutoff = time.monotonic() - window
    return {pid for pid, when in _PROBES.items() if when >= cutoff}


def probe_run(argv: Sequence[str], *, timeout: float, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """`subprocess.run` for the runner's own text probes, registering the child's pid."""
    process = subprocess.Popen(
        list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env,
    )
    register_probe(process.pid)
    try:
        output, _ = process.communicate(timeout=timeout)
    except BaseException:
        process.kill()
        try:
            process.communicate(timeout=1.0)
        except (subprocess.SubprocessError, OSError):
            pass
        raise
    finally:
        register_probe(process.pid)
    return subprocess.CompletedProcess(list(argv), process.returncode, output, None)

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


# macOS kinfo_proc (sys/sysctl.h), arm64 and x86_64 alike, 648 bytes: struct extern_proc kp_proc first.
# extern_proc: p_un.__p_starttime (struct timeval {long tv_sec; int tv_usec}) at offset 0 (tv_sec 8 bytes,
# tv_usec 4 bytes at 8), p_vmspace at 16, p_sigacts at 24, int p_flag at 32, char p_stat at 36,
# pid_t p_pid at 40. Checked on arm64 macOS 26 against `ps -o lstart` for pid 1 and the caller.
KINFO_PROC_SIZE = 648
KINFO_PROC_START_SEC_OFFSET = 0
KINFO_PROC_PID_OFFSET = 40


def _read_kinfo_proc_darwin(pid: int) -> bytes | None:
    """sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}) record; unprivileged, works for other users' processes."""
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    mib = (ctypes.c_int * 4)(1, 14, 1, int(pid))  # CTL_KERN, KERN_PROC, KERN_PROC_PID
    buffer = ctypes.create_string_buffer(KINFO_PROC_SIZE)
    size = ctypes.c_size_t(KINFO_PROC_SIZE)
    if libc.sysctl(mib, 4, buffer, ctypes.byref(size), None, 0) != 0:
        return None
    return bytes(buffer)[:size.value]


def start_epoch_from_kinfo_proc(raw: bytes | None, pid: int) -> float | None:
    """Start time from a kinfo_proc record; None unless the record is exactly sized and names `pid`."""
    if raw is None or len(raw) != KINFO_PROC_SIZE:
        return None
    if int.from_bytes(raw[KINFO_PROC_PID_OFFSET:KINFO_PROC_PID_OFFSET + 4], "little", signed=True) != int(pid):
        return None
    seconds = int.from_bytes(raw[KINFO_PROC_START_SEC_OFFSET:KINFO_PROC_START_SEC_OFFSET + 8], "little", signed=True)
    return float(seconds) if seconds > 0 else None


def read_process_start_epoch(pid: int, kinfo_reader: Callable[[int], bytes | None] | None = None) -> float | None:
    """Process start time as epoch seconds from the kernel, not from `ps lstart` text.

    macOS: proc_pidinfo(PROC_PIDTBSDINFO) pbi_start_tvsec, which is denied for other users' processes;
    then the sysctl KERN_PROC_PID kinfo_proc p_starttime (what `ps` uses). Linux: /proc/<pid>/stat starttime
    ticks plus the boot time. None when unreadable. Free of local-time (DST) ambiguity.
    """
    try:
        if sys.platform == "darwin":
            if kinfo_reader is None:
                libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
                buffer = ctypes.create_string_buffer(136)
                if libc.proc_pidinfo(int(pid), 3, 0, buffer, 136) == 136:
                    raw = bytes(buffer)
                    if int.from_bytes(raw[12:16], "little") != int(pid):
                        return None
                    return float(int.from_bytes(raw[120:128], "little"))
            return start_epoch_from_kinfo_proc((kinfo_reader or _read_kinfo_proc_darwin)(int(pid)), pid)
        if sys.platform.startswith("linux"):
            with open(f"/proc/{int(pid)}/stat", "rb") as stream:
                text = stream.read(4096).decode("ascii", "replace")
            fields = text[text.rindex(")") + 2:].split()
            ticks = int(fields[19])
            with open("/proc/stat", "rb") as stream:
                boot = next(int(line.split()[1]) for line in stream.read(65536).decode("ascii", "replace").splitlines()
                            if line.startswith("btime "))
            return boot + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, StopIteration, AttributeError, TypeError, ctypes.ArgumentError):
        return None
    return None


def parse_start(value: str) -> float | None:
    """Epoch seconds for a `ps lstart` string (local time), or None when unparsable or ambiguous.

    A wall-clock time inside the repeated DST fall-back hour maps to two epochs; that is
    refused (None) rather than guessed, so it can never make a later process look older.

    Exactly two English orders are accepted: month-first (`Sun Sep 27 09:43:13 2026`, the C locale)
    and day-first (`Sun 27 Sep 09:43:13 2026`, e.g. en_AU, which the inherited-environment `ps`
    snapshot uses). The month is a name and the day a number, so they cannot be confused. Anything
    else (other languages, typos, numeric-only) is None. The `ps` environment and the stored
    identity strings must NOT be changed to match: retained owner records and receipts hold the
    locale form as written, and identities are compared as exact (pid, string) pairs, so probing
    in another locale would make a live recorded process look as if its start differs (exited).
    """
    parsed = None
    text = " ".join(value.split())
    for layout in ("%a %b %d %H:%M:%S %Y", "%a %d %b %H:%M:%S %Y"):
        try:
            parsed = time.strptime(text, layout)
            break
        except ValueError:
            continue
    if parsed is None:
        return None
    try:
        candidates = set()
        for isdst in (0, 1):
            moment = time.mktime(parsed[:8] + (isdst,))
            local = time.localtime(moment)
            if local[:6] == parsed[:6]:
                candidates.add(moment)
        if len(candidates) != 1:
            return None
        return candidates.pop()
    except (ValueError, OverflowError):
        return None


def same_start_instant(left: str, right: str) -> bool:
    """True only if both `lstart` strings parse to one unambiguous epoch each and the epochs are equal.

    Used where one side comes from a `LC_ALL=C` probe and the other from the inherited locale; it is
    exactly as strict as string equality within one locale (1-second resolution). Unparsable or
    DST-ambiguous on either side is not equal, so the process stays uncertain.
    """
    first, second = parse_start(left), parse_start(right)
    return first is not None and second is not None and first == second


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


def parse_ps_uid(text: str) -> int | None:
    """uid from `ps -o uid=` text, or None.

    macOS `ps` prints some uids signed (`nobody` is uid_t 4294967294, shown as -2). A decimal in
    [-2**31, -1] is read as its unsigned 32-bit value; anything else outside [0, 2**32 - 1] or not
    a plain decimal is refused.
    """
    body = text[1:] if text.startswith("-") else text
    if not (body.isascii() and body.isdigit()) or len(body) > 11:
        return None
    value = int(text)
    if -(2**31) <= value <= -1:
        return value & 0xFFFFFFFF
    return value if 0 <= value <= 0xFFFFFFFF else None


def read_process_facts(pids: Sequence[int], deadline: float) -> dict[int, tuple[int, str]]:
    """uid and normalized start time for pids via one bounded `ps`; empty on any failure."""
    ps = next((path for path in ("/bin/ps", "/usr/bin/ps") if os.path.isfile(path)), None)
    remaining = deadline - time.monotonic()
    if ps is None or not pids or remaining <= 0:
        return {}
    try:
        result = probe_run(
            [ps, "-o", "pid=,uid=,lstart=", "-p", ",".join(str(int(pid)) for pid in pids)],
            timeout=min(FACTS_TIMEOUT_SECONDS, remaining), env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    facts: dict[int, tuple[int, str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        uid = parse_ps_uid(fields[1]) if len(fields) >= 7 else None
        if uid is not None and fields[0].isdigit():
            facts[int(fields[0])] = (uid, " ".join(fields[2:7]))
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
        self._adopted: dict[int, str] = {}
        self._subreaper_on = False
        self._subreaper_was_set = False

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
            self._subreaper_was_set = True
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

        With the subreaper set, every live, non-baseline direct child of the runner other
        than the runner's own registered probes is provably part of this run (a reparented
        orphan or the command root). Each is adopted into `owned` at once, with no grace
        period, so the existing owned-tree drain rules apply (a live adopted orphan after the
        command ends is drained or fails closed). Zombies of adopted orphans are reaped. Nothing
        is ever signaled here.
        """
        if self.mode != "subreaper" or not self.available:
            return
        probes = recent_probe_pids()
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
            if ppid != self.runner_pid:
                self._descendants.add((pid, started_at))
                continue
            if state in {"Z", "X"}:
                if self._adopted.get(pid) == started_at:
                    self._reap(pid)
                continue
            if pid in probes and owned.get(pid) != started_at:
                continue  # the runner's own ps/lsof helper
            self._descendants.add((pid, started_at))
            if owned.get(pid) != started_at:
                owned[pid] = started_at
                self._adopted[pid] = started_at

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
            if (fact is None or fresh is None or original is None or not same_start_instant(fact[1], started_at)
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
                if again is None or not same_start_instant(again[1], started_at):
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

    def facts(self) -> dict[str, Any]:
        """Small, durable facts about this run's provenance (kept in owner records and receipts)."""
        return {
            "mode": self.mode, "available": self.available,
            "runCoalitionIds": sorted(self.run_coalitions)[:8], "subreaper": self._subreaper_was_set,
        }

    def report(self) -> dict[str, Any]:
        report = {
            "mode": self.mode, "available": self.available, "overflowed": self.overflowed,
            "unavailableReason": self.unavailable_reason, "adoptedOrphanCount": len(self._adopted),
            "runCoalitionIds": sorted(self.run_coalitions)[:8], "subreaper": self._subreaper_was_set,
        }
        report.update(self.evidence.report())
        return report
