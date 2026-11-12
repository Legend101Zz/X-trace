"""Private floor checkpoints and their independent diagnostic summary."""
from __future__ import annotations

import json
import os
import pathlib

from tools.qa import lane_run, store_profiles
from tools.release import private_roots

CHECKPOINT_NAME = "gate-progress.json"
MAX_GATE_CHECKPOINT_BYTES = 4096
RUST_TEST_GATES = frozenset({"rust-cli-spring-journey", "rust-focused", "rust-workspace"})
SOURCE_FIELDS = ("head", "phaseBase", "workingTreeDigest", "phaseDiffSha256")
COMMAND_OBSERVATIONS = ("selected", "started", "completed")
UNAVAILABLE = {"status": "unavailable"}


def rust_directory(run_dir: pathlib.Path, gate: str) -> pathlib.Path:
    return run_dir / f"rust-progress-{gate}"


class GateCheckpoint:
    """The supervisor writes at most three snapshots per gate, outside the upload glob."""

    def __init__(self):
        self.gates = {}

    def __call__(self, run_dir, gate, state, source):
        self.gates[gate] = state
        payload = lane_run._encoded({
            "version": 1, "label": run_dir.name, "source": source, "gates": list(self.gates.items()),
        }) + b"\n"
        if len(payload) <= MAX_GATE_CHECKPOINT_BYTES:
            try:
                private_roots.atomic_write_private(run_dir / CHECKPOINT_NAME, payload)
            except (OSError, private_roots.AdmissionError):
                pass  # Diagnostics cannot decide a gate's outcome.


def _rust_progress(directory, metadata, index):
    try:
        with os.fdopen(private_roots.open_private_file_read(directory / "timing.json"), "rb") as stream:
            observations, _ = lane_run.restore_timing_checkpoint(stream, metadata, index, progress=True)
        return observations.progress()
    except (private_roots.AdmissionError, OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        return UNAVAILABLE


def _profiles(directory, index):
    try:
        private_roots.admit_directory(directory)
        for profile in store_profiles.PROFILES:
            for suffix in ("active", "progress"):
                path = directory / f"store-{profile}-{suffix}.txt"
                if os.path.lexists(path):
                    os.close(private_roots.open_private_file_read(path))
        facts = store_profiles.collect(directory)
    except (OSError, private_roots.AdmissionError):
        return UNAVAILABLE
    if not facts or lane_run._private(lane_run._encoded(facts).decode("ascii"), index, verified_identifier=True):
        return UNAVAILABLE
    return {"status": "observed", "profiles": facts}


def _spring_order_wait(directory, metadata, index):
    try:
        private_roots.admit_directory(directory)
    except (OSError, private_roots.AdmissionError):
        return UNAVAILABLE
    return lane_run.spring_order_wait(directory / "diagnostics", metadata, index)


def collect(checkpoint, repo, source_proofs, expected_gates):
    """Rebuild diagnostics from a verified source and its private supervisor state."""
    with os.fdopen(private_roots.open_private_file_read(checkpoint), "rb") as stream:
        raw = stream.read(MAX_GATE_CHECKPOINT_BYTES + 1)
    if not private_roots.private_json_fits_read_limits(raw, maximum_bytes=MAX_GATE_CHECKPOINT_BYTES):
        return UNAVAILABLE
    record = json.loads(raw)
    run_dir = checkpoint.parent
    if (not isinstance(record, dict) or set(record) != {"version", "label", "source", "gates"}
            or type(record["version"]) is not int or record["version"] != 1
            or record["label"] != run_dir.name
            or record["source"] != {key: source_proofs[key] for key in SOURCE_FIELDS}):
        return UNAVAILABLE
    rows = record["gates"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= len(expected_gates):
        return UNAVAILABLE

    states = {}
    for position, (gate, row) in enumerate(zip(expected_gates, rows)):
        if (not isinstance(row, list) or len(row) != 2 or row[0] != gate
                or row[1] not in COMMAND_OBSERVATIONS
                or (position < len(rows) - 1 and row[1] != "completed")):
            return UNAVAILABLE
        states[gate] = row[1]

    last_gate = next(reversed(states))
    result = {
        "status": "observed",
        "lastObservedGate": last_gate,
        "commandObservation": states[last_gate],
        "lastCommandStart": next((gate for gate in reversed(states) if states[gate] != "selected"), None),
        "lastCommandCompletion": next((gate for gate in reversed(states) if states[gate] == "completed"), None),
        "rustGates": {},
    }
    rust_gates = [gate for gate in states if gate in RUST_TEST_GATES]
    if rust_gates:
        metadata = lane_run._checkout_metadata(repo, source_proofs["head"])
        index = lane_run.CANARY_INDEX
        for gate in rust_gates:
            directory = rust_directory(run_dir, gate)
            started = states[gate] != "selected"
            result["rustGates"][gate] = {
                "rustProgress": _rust_progress(directory, metadata, index) if started else UNAVAILABLE,
                "storeProfiles": _profiles(directory / "frag", index) if started else UNAVAILABLE,
                "springPremainOrderWait": _spring_order_wait(directory, metadata, index) if started else UNAVAILABLE,
            }
    return result
