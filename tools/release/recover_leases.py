#!/usr/bin/env python3
"""Bounded manual recovery of retained builder leases.

A failed supervised run retains both builder leases (`requiresManualRecovery`) because it
could not prove that nothing it started can still write the shared caches. This tool applies
the documented manual-recovery protocol, with production APIs only (`private_roots`,
`run_gates`, `provenance`), and removes the two lease directories only when every recorded
identity is gone or provably not a descendant, two complete global scans find nothing
unproven, and every admission, inode and record-hash check holds. It never signals a process,
never uses privilege, and never exempts anything by UID or name. The failed receipt is only
read, never modified.

    python3.14 -B -m tools.release.recover_leases --cache-root <root> --label <label> \
        --receipt <root>/release-gates/<label>/receipt.json
        [--execute --confirm-label <label>]

Default is a dry run that writes a sanitized `recovery-plan-<utc>.json` and prints a summary.
Exit codes: 0 allowed (dry run) or recovered, 1 refused, 2 invalid input or admission failure,
3 recovery started but did not complete (inspect by hand).

Classification of a live identity (each non-exited identity must be classified in every
observation):
- exited: pid absent, a different start time, or a zombie.
- non-descendant-predates-run: it started before the run's lease was taken (a process cannot
  descend from a run that did not exist yet).
- non-descendant-ancestor-predates-run (macOS only): a live ancestor (other than launchd) started
  before the run. macOS has no subreaper, so a descendant of the run only ever reparents to
  launchd; every other ancestor of a descendant is itself a descendant and younger than the run.
- non-descendant-coalition (macOS): ADR 0007's resource-coalition rule against the run's
  coalition ids persisted by the run itself (owner records and receipt); recovery is refused
  when they are absent (`no-persisted-provenance`).
Everything else stays uncertain and blocks recovery.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import pathlib
import stat
import sys
import time
from typing import Any, Callable, Sequence

if __package__:
    from . import private_roots, provenance, run_gates
else:
    import private_roots
    import provenance
    import run_gates

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_INVALID = 2
EXIT_PARTIAL = 3
OBSERVATIONS = 3
OBSERVATION_GAP_SECONDS = 2.0
SCAN_COUNT = 2
SCAN_GAP_SECONDS = 2.0
MAX_IDENTITIES = 512
MAX_LIST_RECORDS = 64
MAX_UNCERTAIN_SAMPLE = 64
# A process counts as predating the run only with a wide margin: it absorbs `ps` second resolution,
# local-time (DST) ambiguity and small wall-clock steps. Larger or unreliable skews fail closed.
START_TOLERANCE_SECONDS = 300.0
START_SOURCE_AGREEMENT_SECONDS = 2.0
# Owner records of one run may differ in `startedAtEpoch` by at most this much. Runs since the
# one-epoch fix write an identical value; records written before it stamped each lease at its own
# acquisition, and private-root admission (ACL probes on macOS) takes seconds, so the observed skew
# is a few seconds. 120 s leaves wide headroom yet stays well inside START_TOLERANCE_SECONDS.
# Larger skews fail closed.
MAX_OWNER_EPOCH_SKEW_SECONDS = 120.0
MAX_RUN_COALITION_IDS = 8
MAX_RECEIPT_WALK_NODES = 20000
MAX_FILE_BYTES = 65536
IDENTITY_LIST_KEYS = (
    "ownedProcesses", "unconfirmedProcesses", "ownedProbeProcesses",
    "initialIdentities", "latestIdentities", "identityUnion",
)
TRUNCATION_FLAGS = (
    "unconfirmedProcessesTruncated", "probeEvidenceTruncated", "ownedProcessesTruncated",
    "identityUnionTruncated", "evidenceListsCompacted",
)
BUILDER_NAMES = frozenset({
    "cargo", "rustc", "rustdoc", "rustfmt", "clippy-driver", "cargo-clippy", "gradle", "gradlew",
    "java", "node", "npm", "npx", "ld", "clang", "cc",
})


class Refused(RuntimeError):
    """The evidence does not allow recovery; carries fixed reason codes."""

    def __init__(self, reasons: Sequence[str]):
        super().__init__(", ".join(reasons))
        self.reasons = list(reasons)


class InvalidInput(RuntimeError):
    """Arguments or admission are unusable."""


def parse_start(value: str) -> float | None:
    """Epoch seconds for a `ps lstart` string in either English order; see provenance.parse_start."""
    return provenance.parse_start(value)


class Context:
    """Every external dependency, injectable for tests."""

    def __init__(self, **overrides: Any) -> None:
        self.platform: str = sys.platform
        self.uid: int = os.getuid()
        self.self_pid: int = os.getpid()
        self.sleep: Callable[[float], None] = time.sleep
        self.monotonic: Callable[[], float] = time.monotonic
        self.now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(datetime.timezone.utc)
        self.snapshot: Callable[[], dict[int, tuple[int, str, str]]] = run_gates._process_snapshot
        self.coalition_reader: Callable[[int], int | None] = provenance.read_coalition_id
        self.facts_reader: Callable[..., dict[int, tuple[int, str]]] = provenance.read_process_facts
        self.start_reader: Callable[[int], float | None] = provenance.read_process_start_epoch
        self.inventory: Callable[[], list[tuple[int, str]]] = _read_inventory
        self.lsof: Callable[[list[str]], list[dict[str, Any]]] = _lsof_paths
        self.__dict__.update(overrides)


def _read_inventory() -> list[tuple[int, str]]:
    """(pid, executable basename) for every process: the ordinary executable inventory."""
    ps = run_gates.PS_BINARY
    if ps is None:
        return []
    try:
        result = provenance.probe_run([ps, "-axo", "pid=,comm="], timeout=5.0)
    except (OSError, ValueError, Exception):  # noqa: BLE001 - supporting evidence only
        return []
    rows: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            rows.append((int(parts[0]), os.path.basename(parts[1].strip())))
    return rows


def _lsof_paths(paths: list[str]) -> list[dict[str, Any]]:
    """Which pids hold each directory open (as fd or cwd). Empty output is not negative proof."""
    results: list[dict[str, Any]] = []
    for path in paths:
        probe = run_gates._run_lsof_fields(["-nP", "-F", "p", "--", path], time.monotonic() + 10.0)
        pids: list[int] = []
        if probe.error is None and probe.returncode in (0, 1):
            for line in probe.stdout.splitlines():
                if line.startswith("p") and line[1:].isdigit():
                    pids.append(int(line[1:]))
        error = probe.error or (None if probe.returncode in (0, 1) else "lsof-unusable")
        results.append({"path": path, "pids": sorted(set(pids))[:MAX_LIST_RECORDS], "error": error})
    return results


def _utc_stamp(moment: datetime.datetime) -> str:
    return moment.strftime("%Y%m%dT%H%M%SZ")


def _file_facts(path: pathlib.Path) -> dict[str, Any]:
    """dev, inode, size, sha256 and bytes of a private regular file read through the production reader."""
    fd = private_roots.open_private_file_read(path)
    try:
        info = os.fstat(fd)
        data = bytearray()
        while len(data) <= MAX_FILE_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise InvalidInput("record-too-large")
    return {"dev": info.st_dev, "ino": info.st_ino, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": bytes(data)}


def _public_facts(facts: dict[str, Any]) -> dict[str, Any]:
    return {key: facts[key] for key in ("dev", "ino", "size", "sha256")}


class Layout:
    def __init__(self, cache: pathlib.Path, label: str) -> None:
        self.cache = cache
        self.label = label
        self.release_root = cache / "release-gates"
        self.run_dir = self.release_root / label
        self.lease_root = cache / "leases"
        self.receipt = self.run_dir / "receipt.json"
        self.leases = {name: self.lease_root / name for name in run_gates.LEASE_NAMES}

    def directories(self) -> list[pathlib.Path]:
        return [self.cache, *(self.cache / name for name in run_gates.CACHE_NAMES),
                self.release_root, self.run_dir, self.lease_root, *self.leases.values()]


def admit_all(layout: Layout) -> dict[str, tuple[int, int]]:
    """Fresh private admission of the root, every child, the run directory and both leases."""
    identities: dict[str, tuple[int, int]] = {}
    for directory in layout.directories():
        key = "<root>" if directory == layout.cache else str(directory.relative_to(layout.cache))
        try:
            identities[key] = private_roots.admit_directory(directory, private_leaf=True)
        except private_roots.AdmissionError as exc:
            raise InvalidInput(f"admission-failed:{directory.name or 'root'}:{getattr(exc, 'reason', '')}") from None
        except OSError:
            raise InvalidInput(f"admission-failed:{directory.name or 'root'}") from None
    return identities


def read_records(layout: Layout) -> dict[str, Any]:
    """Owner records (never their token) and the failed receipt, with stability facts."""
    owners: dict[str, dict[str, Any]] = {}
    facts: dict[str, dict[str, Any]] = {}
    for name, lease in layout.leases.items():
        try:
            listing = sorted(os.listdir(lease))
        except OSError:
            raise InvalidInput(f"lease-unreadable:{name}") from None
        if listing != ["owner.json"]:
            raise Refused(["lease-has-extra-files"])
        try:
            owner = private_roots.read_private_json(lease / "owner.json")
            facts[name] = _file_facts(lease / "owner.json")
        except private_roots.AdmissionError:
            raise Refused(["owner-record-unreadable"]) from None
        owners[name] = owner
    try:
        receipt = private_roots.read_private_json(
            layout.receipt, maximum_nodes=run_gates.RECEIPT_JSON_BUDGET, maximum_commas=run_gates.RECEIPT_JSON_BUDGET,
        )
        receipt_facts = _file_facts(layout.receipt)
    except private_roots.AdmissionError:
        raise Refused(["receipt-unreadable"]) from None
    return {"owners": owners, "ownerFacts": facts, "receipt": receipt, "receiptFacts": receipt_facts}


def _valid_epoch(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value > 0)


def _agreed_run_start_epoch(owners: dict[str, dict[str, Any]], reasons: list[str]) -> float | None:
    """The run-start epoch all owner records agree on, or None (and a refusal reason).

    Identical epochs are accepted as before. Records written before the one-epoch fix may differ
    slightly; they are accepted only when provably from the same run: identical pid, label and
    lease token (equality only; the token is never printed, logged or stored) and epochs within
    MAX_OWNER_EPOCH_SKEW_SECONDS. The EARLIEST epoch is returned: it is the conservative choice
    for the "predates the run" test (a process must have started before the earliest possible
    run start, with the margin, to be cleared as foreign) and for the global scan window.
    """
    values = [owner.get("startedAtEpoch") for owner in owners.values()]
    if not values or not all(_valid_epoch(value) for value in values):
        reasons.append("owner-records-disagree")
        return None
    if len(set(values)) > 1:
        tokens = [owner.get("token") for owner in owners.values()]
        labels = {owner.get("label") for owner in owners.values()}
        pids = {owner.get("pid") for owner in owners.values()}
        same_run = (
            len(pids) == 1 and len(labels) == 1
            and all(isinstance(token, str) and token for token in tokens) and len(set(tokens)) == 1
            and all(owner.get("requiresManualRecovery") is True for owner in owners.values())
            and max(values) - min(values) <= MAX_OWNER_EPOCH_SKEW_SECONDS
        )
        if not same_run:
            reasons.append("owner-records-disagree")
            return None
    return float(min(values))


def check_records(layout: Layout, records: dict[str, Any]) -> dict[str, Any]:
    """Label, retention and agreement checks; returns the shared owner facts."""
    reasons: list[str] = []
    owners = records["owners"]
    receipt = records["receipt"]
    for name, owner in owners.items():
        if owner.get("label") != layout.label:
            reasons.append("label-mismatch")
        if owner.get("requiresManualRecovery") is not True:
            reasons.append("not-retained")
    pids = {owner.get("pid") for owner in owners.values()}
    if len(pids) != 1:
        reasons.append("owner-records-disagree")
    epoch = _agreed_run_start_epoch(owners, reasons)
    if receipt.get("label") != layout.label:
        reasons.append("receipt-label-mismatch")
    if receipt.get("decision") not in {"failed", "uncertain_process_tree"}:
        reasons.append("receipt-not-failed")
    owner_pid = next(iter(pids)) if len(pids) == 1 else None
    if not isinstance(owner_pid, int) or isinstance(owner_pid, bool) or owner_pid <= 0 or epoch is None:
        reasons.append("owner-records-disagree")
    if reasons:
        raise Refused(sorted(set(reasons)))
    return {"ownerPid": owner_pid, "runStartEpoch": float(epoch)}


def _identities_from(value: Any, source: str, found: dict[tuple[int, str], set[str]],
                     truncated: list[str], budget: list[int], depth: int = 0) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > 8:
        raise Refused(["evidence-overflow"])
    if isinstance(value, dict):
        for flag in TRUNCATION_FLAGS:
            if value.get(flag) is True:
                truncated.append(flag)
        for key, item in value.items():
            if key in IDENTITY_LIST_KEYS and isinstance(item, list):
                for record in item[:MAX_LIST_RECORDS]:
                    pid, start = (record.get("pid"), record.get("startedAt")) if isinstance(record, dict) else (None, None)
                    if (isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
                            and isinstance(start, str) and 0 < len(start) <= 64):
                        found.setdefault((pid, start), set()).add(f"{source}:{key}")
                if len(item) > MAX_LIST_RECORDS:
                    truncated.append(f"{key}-over-{MAX_LIST_RECORDS}")
            elif isinstance(item, (dict, list)):
                _identities_from(item, source, found, truncated, budget, depth + 1)
    elif isinstance(value, list):
        for item in value[:MAX_IDENTITIES]:
            if isinstance(item, (dict, list)):
                _identities_from(item, source, found, truncated, budget, depth + 1)


def collect_identities(records: dict[str, Any]) -> tuple[dict[tuple[int, str], set[str]], list[str]]:
    """Every recorded identity (owner records and the receipt's evidence), bounded and deduplicated."""
    found: dict[tuple[int, str], set[str]] = {}
    truncated: list[str] = []
    budget = [MAX_RECEIPT_WALK_NODES]
    for name, owner in records["owners"].items():
        _identities_from(owner, f"owner-{name}", found, truncated, budget)
    _identities_from(records["receipt"], "receipt", found, truncated, budget)
    if len(found) > MAX_IDENTITIES:
        raise Refused(["evidence-overflow"])
    return found, sorted(set(truncated))


def persisted_coalition_ids(records: dict[str, Any]) -> list[int]:
    """Coalition ids the run itself recorded (owner records and receipt provenance), authoritative."""
    found: set[int] = set()

    def take(value: Any) -> None:
        if isinstance(value, list):
            found.update(item for item in value if type(item) is int and 0 < item < 2**63)

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            take(value.get("runCoalitionIds"))
            for item in value.values():
                if isinstance(item, (dict, list)):
                    walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:MAX_IDENTITIES]:
                walk(item, depth + 1)

    for owner in records["owners"].values():
        walk(owner)
    walk(records["receipt"])
    if len(found) > MAX_RUN_COALITION_IDS:
        raise Refused(["evidence-overflow"])
    return sorted(found)


def require_persisted_provenance(records: dict[str, Any]) -> list[int]:
    """Recovery needs the run's own provenance facts; there is no operator-supplied substitute.

    Both owner records must carry `provenance` with `available` true and either a subreaper fact
    (Linux) or at least one persisted run coalition id (macOS). A retained lease without them (a run
    from before these facts were recorded, or one where provenance was unavailable) is refused: the
    run's coalition cannot be established independently, so nothing may be cleared by it.
    """
    for owner in records["owners"].values():
        facts = owner.get("provenance")
        if not isinstance(facts, dict) or facts.get("available") is not True:
            raise Refused(["no-persisted-provenance"])
        ids = [value for value in (facts.get("runCoalitionIds") or []) if type(value) is int and 0 < value < 2**63]
        if not ids and facts.get("subreaper") is not True:
            raise Refused(["no-persisted-provenance"])
    ids = persisted_coalition_ids(records)
    return ids


class Classifier:
    def __init__(self, ctx: Context, run_start: float, coalitions: Sequence[int]) -> None:
        self.ctx = ctx
        self.run_start = run_start
        self.coalitions = list(coalitions)
        self.mac = ctx.platform == "darwin"

    def _coalition_classifier(self) -> provenance.Provenance | None:
        if not (self.mac and self.coalitions):
            return None
        item = provenance.Provenance(
            platform="darwin", runner_pid=-1, uid=self.ctx.uid,
            coalition_reader=self.ctx.coalition_reader, facts_reader=self.ctx.facts_reader,
        )
        item.run_coalitions = set(self.coalitions)
        item.available = True
        return item

    def start_epoch(self, pid: int, start: str) -> float | None:
        """Kernel start time, cross-checked against the `ps` text; None when unreadable or they disagree."""
        text_epoch = parse_start(start)
        kernel_epoch = self.ctx.start_reader(pid)
        if kernel_epoch is None or text_epoch is None:
            return None
        if abs(kernel_epoch - text_epoch) > START_SOURCE_AGREEMENT_SECONDS:
            return None
        return kernel_epoch

    def predates(self, start: str, pid: int | None = None) -> bool:
        epoch = self.start_epoch(pid, start) if pid is not None else parse_start(start)
        return epoch is not None and epoch < self.run_start - START_TOLERANCE_SECONDS

    def ancestor_predating(self, pid: int, snapshot: dict[int, tuple[int, str, str]]) -> tuple[int, str] | None:
        if not self.mac:
            return None
        current, seen = pid, set()
        for _ in range(provenance.MAX_CHAIN_HOPS):
            record = snapshot.get(current)
            if record is None:
                return None
            parent = record[0]
            if parent <= 1 or parent in seen:
                return None
            parent_record = snapshot.get(parent)
            if parent_record is None:
                return None
            if self.predates(parent_record[1], parent) and parent_record[2] not in {"Z", "X"}:
                return parent, parent_record[1]
            seen.add(current)
            current = parent
        return None

    def classify_many(self, items: Sequence[tuple[int, str]], snapshot: dict[int, tuple[int, str, str]]
                      ) -> dict[tuple[int, str], tuple[str, dict[str, Any]]]:
        """Class and evidence for each (pid, start): exited, a non-descendant-* class, or uncertain."""
        result: dict[tuple[int, str], tuple[str, dict[str, Any]]] = {}
        remaining: list[tuple[int, str]] = []
        for pid, start in items:
            record = snapshot.get(pid)
            if record is None or record[1] != start or record[2] in {"Z", "X"}:
                result[(pid, start)] = ("exited", {})
            elif self.predates(start, pid):
                result[(pid, start)] = ("non-descendant-predates-run", {})
            else:
                ancestor = self.ancestor_predating(pid, snapshot)
                if ancestor is not None:
                    result[(pid, start)] = ("non-descendant-ancestor-predates-run",
                                            {"ancestorPid": ancestor[0], "ancestorStartedAt": ancestor[1]})
                else:
                    remaining.append((pid, start))
        classifier = self._coalition_classifier()
        classified = (
            classifier.classify(remaining, snapshot, snapshot, {}, self.ctx.monotonic() + 10.0)
            if classifier is not None and remaining else {}
        )
        for pid, start in remaining:
            if pid in classified:
                evidence = {key: classified[pid][key] for key in ("uidClass", "coalitionId", "runCoalitionIds") if key in classified[pid]}
                result[(pid, start)] = (classified[pid]["classification"], evidence)
            else:
                result[(pid, start)] = ("uncertain", {"reason": "no-positive-evidence"})
        return result


def _descendants_of(live: set[int], snapshot: dict[int, tuple[int, str, str]]) -> int:
    reached = set(live)
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _start, state) in snapshot.items():
            if pid not in reached and ppid in reached and state not in {"Z", "X"}:
                reached.add(pid)
                changed = True
    return len(reached - live)


def _own_tree(ctx: Context, snapshot: dict[int, tuple[int, str, str]]) -> set[int]:
    tree = {ctx.self_pid} | provenance.recent_probe_pids()
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _start, _state) in snapshot.items():
            if pid not in tree and ppid in tree:
                tree.add(pid)
                changed = True
    return tree


def _gap(ctx: Context, started: float, seconds: float) -> None:
    remaining = seconds - (ctx.monotonic() - started)
    while remaining > 0:
        ctx.sleep(remaining)
        remaining = seconds - (ctx.monotonic() - started)


def _is_owned(sources: set[str]) -> bool:
    return any(item.endswith((":ownedProcesses", ":ownedProbeProcesses")) for item in sources)


def observe(ctx: Context, classifier: Classifier, identities: Sequence[tuple[int, str]],
            sources: dict[tuple[int, str], set[str]], owner_pid: int, epoch: float) -> dict[str, Any]:
    """Three observations at least two seconds apart of every recorded identity."""
    per_identity: dict[tuple[int, str], list[tuple[str, dict[str, Any]]]] = {key: [] for key in identities}
    summaries: list[dict[str, Any]] = []
    for index in range(OBSERVATIONS):
        started = ctx.monotonic()
        snapshot = ctx.snapshot()
        classes = classifier.classify_many(list(identities), snapshot)
        live = {pid for (pid, start), (cls, _e) in classes.items() if cls != "exited"}
        for key, outcome in classes.items():
            if _is_owned(sources[key]) and outcome[0].startswith("non-descendant"):
                # An identity the run recorded as owned is a descendant by definition: only a
                # verified exit may clear it, never a heuristic.
                outcome = ("uncertain", {"reason": "owned-identity-live"})
            per_identity[key].append(outcome)
        owner_record = snapshot.get(owner_pid)
        owner_start = (classifier.start_epoch(owner_pid, owner_record[1]) or parse_start(owner_record[1])) if owner_record else None
        owner_live = bool(owner_record and owner_record[2] not in {"Z", "X"}
                          and (owner_start is None or owner_start <= epoch + START_SOURCE_AGREEMENT_SECONDS))
        inventory = ctx.inventory()
        summaries.append({
            "matching": len(live), "descendants": _descendants_of(live, snapshot),
            "ownerPidLive": owner_live,
            "visibleBuilderCount": sum(1 for _pid, name in inventory if name in BUILDER_NAMES),
        })
        if index + 1 < OBSERVATIONS:
            _gap(ctx, started, OBSERVATION_GAP_SECONDS)
    final: list[dict[str, Any]] = []
    for (pid, start), outcomes in per_identity.items():
        kinds = [cls for cls, _e in outcomes]
        live_outcomes = [(cls, ev) for cls, ev in outcomes if cls != "exited"]
        if not live_outcomes:
            status, evidence = "exited", {}
        elif all(cls.startswith("non-descendant") for cls, _ev in live_outcomes):
            status, evidence = live_outcomes[0]
        else:
            status, evidence = "uncertain", {"observed": sorted(set(kinds))}
        final.append({"pid": pid, "startedAt": start, "sources": sorted(sources[(pid, start)])[:4],
                      "classification": status, "evidence": evidence})
    return {"identities": final, "observations": summaries}


def global_scans(ctx: Context, classifier: Classifier) -> list[dict[str, Any]]:
    """Two complete scans at least two seconds apart: every live process born since the run began."""
    scans: list[dict[str, Any]] = []
    for index in range(SCAN_COUNT):
        started = ctx.monotonic()
        snapshot = ctx.snapshot()
        own = _own_tree(ctx, snapshot)
        candidates = []
        for pid, (_ppid, start, state) in snapshot.items():
            if pid in own or state in {"Z", "X"}:
                continue
            if classifier.predates(start, pid):
                continue
            candidates.append((pid, start))
        classes = classifier.classify_many(candidates, snapshot)
        uncertain = [(key, outcome) for key, outcome in classes.items() if outcome[0] == "uncertain"]
        facts = ctx.facts_reader([pid for (pid, _s), _o in uncertain[:MAX_UNCERTAIN_SAMPLE]], ctx.monotonic() + 5.0) if uncertain else {}
        sample = [{"pid": pid, "startedAt": start, "uidClass": ("same" if facts.get(pid, (None,))[0] == ctx.uid else "other") if pid in facts else "unknown"}
                  for (pid, start), _o in uncertain[:MAX_UNCERTAIN_SAMPLE]]
        by_class: dict[str, int] = {}
        for _key, (cls, _ev) in classes.items():
            by_class[cls] = by_class.get(cls, 0) + 1
        scans.append({"candidateCount": len(candidates), "byClass": by_class,
                      "uncertainCount": len(uncertain), "uncertain": sample, "clean": not uncertain})
        if index + 1 < SCAN_COUNT:
            _gap(ctx, started, SCAN_GAP_SECONDS)
    return scans


def lsof_check(ctx: Context, layout: Layout) -> dict[str, Any]:
    paths = [str(path) for path in (layout.cache, layout.lease_root, *layout.leases.values(),
                                    *(layout.cache / name for name in ("cargo", "gradle", "cargo-target", "tmp")))]
    snapshot = ctx.snapshot()
    own = _own_tree(ctx, snapshot)
    holders: set[int] = set()
    errors = 0
    for item in ctx.lsof(paths):
        errors += 1 if item.get("error") else 0
        holders.update(pid for pid in item.get("pids", []) if pid not in own)
    return {"queried": len(paths), "errors": errors, "holderPids": sorted(holders)[:MAX_LIST_RECORDS],
            "holderCount": len(holders),
            "note": "supporting evidence only: an empty result is not negative proof"}


def evaluate(ctx: Context, layout: Layout) -> dict[str, Any]:
    """Run every check once and return the evaluation (never mutates anything)."""
    admissions = admit_all(layout)
    records = read_records(layout)
    shared = check_records(layout, records)
    identities, truncated = collect_identities(records)
    coalitions = require_persisted_provenance(records)
    coalition_sources = ["persisted"] if coalitions else ["persisted-subreaper-only"]
    classifier = Classifier(ctx, shared["runStartEpoch"], coalitions)
    observed = observe(ctx, classifier, sorted(identities), identities, shared["ownerPid"], shared["runStartEpoch"])
    scans = global_scans(ctx, classifier)
    lsof = lsof_check(ctx, layout)
    # Stability: re-admit and re-read after all observations.
    admissions_after = admit_all(layout)
    records_after = read_records(layout)
    stable = (
        admissions == admissions_after
        and {n: _public_facts(f) for n, f in records["ownerFacts"].items()}
        == {n: _public_facts(f) for n, f in records_after["ownerFacts"].items()}
        and _public_facts(records["receiptFacts"]) == _public_facts(records_after["receiptFacts"])
    )
    reasons: list[str] = []
    if not stable:
        reasons.append("records-unstable")
    if any(item["classification"] == "uncertain" for item in observed["identities"]):
        reasons.append("identity-uncertain")
    if any(obs["ownerPidLive"] for obs in observed["observations"]):
        reasons.append("owner-live")
    if not all(scan["clean"] for scan in scans):
        reasons.append("scan-uncertain")
    if lsof["holderCount"]:
        reasons.append("lsof-holder")
    return {
        "records": records, "records_after": records_after, "admissions": admissions,
        "owner": shared, "identities": observed["identities"], "observations": observed["observations"],
        "scans": scans, "lsof": lsof, "truncatedEvidence": truncated,
        "runCoalitionIds": coalitions, "runCoalitionSources": coalition_sources,
        "reasons": reasons, "allowed": not reasons,
    }


def build_plan(layout: Layout, evaluation: dict[str, Any], moment: datetime.datetime, mode: str, own_coalition: int | None) -> dict[str, Any]:
    """Sanitized plan: no token, no paths, no raw owner or receipt content."""
    counts: dict[str, int] = {}
    for item in evaluation["identities"]:
        counts[item["classification"]] = counts.get(item["classification"], 0) + 1
    return {
        "schemaVersion": 1, "kind": "xtrace-lease-recovery-plan", "label": layout.label,
        "createdUtc": _utc_stamp(moment), "mode": mode,
        "decision": "recovery-allowed" if evaluation["allowed"] else "recovery-refused",
        "refusalReasons": evaluation["reasons"],
        "runStartEpoch": int(evaluation["owner"]["runStartEpoch"]),
        "runCoalitionIds": evaluation["runCoalitionIds"], "runCoalitionSources": evaluation["runCoalitionSources"],
        "toolSessionCoalitionId": own_coalition,
        "notice": ("Provenance proves non-descent in the fork tree, not that nothing can write the caches: a "
                   "pre-existing daemon or work delegated through launchd/XPC/docker/cron is outside it, and an "
                   "empty lsof result is weak (it sees only exact directory handles)."),
        "ownerRecords": {name: _public_facts(facts) for name, facts in evaluation["records"]["ownerFacts"].items()},
        "failedReceipt": _public_facts(evaluation["records"]["receiptFacts"]),
        "recordedIdentityCount": len(evaluation["identities"]), "identityClassCounts": counts,
        "identities": evaluation["identities"][:MAX_IDENTITIES],
        "evidenceTruncated": evaluation["truncatedEvidence"],
        "observations": evaluation["observations"], "globalScans": evaluation["scans"],
        "lsofSupportingEvidence": evaluation["lsof"],
        "protocol": {"observations": OBSERVATIONS, "observationGapSeconds": OBSERVATION_GAP_SECONDS,
                     "globalScans": SCAN_COUNT, "scanGapSeconds": SCAN_GAP_SECONDS},
    }


def _write_new(path: pathlib.Path, data: bytes) -> None:
    """Create a new private file (exclusive) through the production API and fsync it."""
    fd = private_roots.create_private_file(path, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_lease(layout: Layout, name: str, expected: dict[str, Any], lease_identity: tuple[int, int]) -> None:
    """Unlink owner.json and rmdir the lease, bound to the identities that were checked.

    Everything after the lease directory is opened happens through that directory descriptor:
    the owner record is re-read and hashed from a descriptor opened relative to it (regular file,
    one link), then unlinked by name relative to the same descriptor. No by-path re-read.
    """
    lease = layout.leases[name]
    private_roots.admit_directory(lease, private_leaf=True)
    root_fd = os.open(layout.lease_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != tuple(lease_identity) or sorted(os.listdir(fd)) != ["owner.json"]:
                raise Refused(["records-unstable"])
            file_fd = os.open("owner.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                file_info = os.fstat(file_fd)
                if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1
                        or file_info.st_size > MAX_FILE_BYTES):
                    raise Refused(["records-unstable"])
                data = os.read(file_fd, MAX_FILE_BYTES + 1)
            finally:
                os.close(file_fd)
            current = {"dev": file_info.st_dev, "ino": file_info.st_ino, "size": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()}
            if current != expected:
                raise Refused(["records-unstable"])
            os.unlink("owner.json", dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def redact_owner_record(raw: bytes) -> bytes:
    """The owner record for the archive with the lease token replaced by its sha256."""
    try:
        record = json.loads(raw)
    except ValueError:
        return b'{"unparsable": true}\n'
    if isinstance(record, dict) and "token" in record:
        token = record["token"]
        record["token"] = "sha256:" + hashlib.sha256(str(token).encode()).hexdigest()
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()


def execute(ctx: Context, layout: Layout, evaluation: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """Archive privately, remove both leases, verify, and write manual-recovery.json."""
    moment = ctx.now()
    archive = layout.run_dir / f"manual-recovery-{_utc_stamp(moment)}"
    private_roots.ensure_private_directory(archive, must_create=True)
    private_roots.admit_directory(archive, private_leaf=True)
    names = list(run_gates.LEASE_NAMES)
    originals = {name: evaluation["records"]["ownerFacts"][name] for name in names}
    for name in names:
        _write_new(archive / f"owner-{name}-token-redacted.json", redact_owner_record(originals[name]["bytes"]))
    _write_new(archive / "failed-receipt.json", evaluation["records"]["receiptFacts"]["bytes"])
    _write_new(archive / "recovery-plan.json", (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode())
    archived = {
        "ownerArchive": "token-redacted",
        "originalOwnerSha256": {name: originals[name]["sha256"] for name in names},
        "failedReceiptSha256": evaluation["records"]["receiptFacts"]["sha256"],
    }
    removed: list[str] = []
    failure: str | None = None
    try:
        for name in names:
            _remove_lease(layout, name, _public_facts(originals[name]), evaluation["admissions"][f"leases/{name}"])
            removed.append(name)
    except (Refused, OSError, private_roots.AdmissionError) as exc:
        failure = type(exc).__name__
    both_absent = all(not os.path.lexists(layout.leases[name]) for name in names)
    receipt_unmodified: bool | None
    try:
        receipt_unmodified = _file_facts(layout.receipt)["sha256"] == evaluation["records"]["receiptFacts"]["sha256"]
    except (OSError, InvalidInput, private_roots.AdmissionError):
        receipt_unmodified = None  # could not be re-read; reported honestly, never assumed
    complete = failure is None and both_absent and receipt_unmodified is True
    result = {
        "schemaVersion": 1, "kind": "xtrace-lease-manual-recovery", "label": layout.label,
        "recoveredUtc": _utc_stamp(moment), "removedLeases": removed, "bothPathsAbsent": both_absent,
        "failure": failure, "originalDecision": evaluation["records"]["receipt"].get("decision"),
        "failedReceiptUnmodified": receipt_unmodified,
        "status": "complete" if complete else ("partial" if removed else "failed-before-removal"),
        "archive": archived, "privilegeUsed": False, "signalsSent": 0,
    }
    data = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    result["manualRecoverySha256"] = hashlib.sha256(data).hexdigest()
    result["complete"] = complete
    try:
        _write_new(archive / "manual-recovery.json", data)
    except OSError:
        result["manualRecoveryWritten"] = False
        result["complete"] = False
    return result


def run(args: argparse.Namespace, ctx: Context | None = None, out: Callable[[str], None] = print) -> int:
    ctx = ctx or Context()
    if not run_gates.LABEL_RE.fullmatch(args.label):
        raise InvalidInput("label-invalid")
    cache = private_roots.normalize_directory_path(args.cache_root)
    layout = Layout(cache, args.label)
    if pathlib.Path(args.receipt) != layout.receipt:
        raise InvalidInput("receipt-path-mismatch")
    execute_mode = bool(args.execute)
    if execute_mode and args.confirm_label != args.label:
        raise InvalidInput("confirm-label-mismatch")
    if not execute_mode and args.confirm_label:
        raise InvalidInput("confirm-label-needs-execute")
    mode = "execute" if execute_mode else "dry-run"
    own_coalition = ctx.coalition_reader(ctx.self_pid) if ctx.platform == "darwin" else None
    try:
        evaluation = evaluate(ctx, layout)
    except Refused as exc:
        out(json.dumps({"label": args.label, "mode": mode, "decision": "recovery-refused", "refusalReasons": exc.reasons}, sort_keys=True))
        return EXIT_REFUSED
    plan = build_plan(layout, evaluation, ctx.now(), mode, own_coalition)
    summary = {"label": args.label, "mode": mode, "decision": plan["decision"], "refusalReasons": plan["refusalReasons"],
               "recordedIdentityCount": plan["recordedIdentityCount"], "identityClassCounts": plan["identityClassCounts"],
               "globalScanUncertain": [scan["uncertainCount"] for scan in plan["globalScans"]],
               "lsofHolderCount": plan["lsofSupportingEvidence"]["holderCount"], "toolSessionCoalitionId": own_coalition}
    if not execute_mode:
        plan_bytes = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
        for attempt in range(1, 10):
            plan_path = layout.run_dir / (
                f"recovery-plan-{plan['createdUtc']}.json" if attempt == 1 else f"recovery-plan-{plan['createdUtc']}-{attempt}.json"
            )
            try:
                _write_new(plan_path, plan_bytes)
                break
            except FileExistsError:
                continue
        else:
            raise InvalidInput("plan-file-exists")
        summary["planFile"] = plan_path.name
        out(json.dumps(summary, sort_keys=True))
        return EXIT_OK if evaluation["allowed"] else EXIT_REFUSED
    if not evaluation["allowed"]:
        out(json.dumps(summary, sort_keys=True))
        return EXIT_REFUSED
    result = execute(ctx, layout, evaluation, plan)
    summary.update({"removedLeases": result["removedLeases"], "bothPathsAbsent": result["bothPathsAbsent"],
                    "manualRecoverySha256": result["manualRecoverySha256"], "complete": result["complete"]})
    out(json.dumps(summary, sort_keys=True))
    return EXIT_OK if result["complete"] else EXIT_PARTIAL


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache-root", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--receipt", required=True, help="the failed run's receipt.json (read only)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="default: evaluate and write a plan only")
    mode.add_argument("--execute", action="store_true", help="remove the leases if every check holds")
    parser.add_argument("--confirm-label", default=None, help="must equal --label with --execute")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except InvalidInput as exc:
        print(f"lease recovery not started: {exc}", file=sys.stderr)
        return EXIT_INVALID
    except (private_roots.AdmissionError, ValueError, FileExistsError, OSError) as exc:
        print(f"lease recovery not started: {type(exc).__name__}", file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
