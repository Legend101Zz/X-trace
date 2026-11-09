#!/usr/bin/env python3
"""Bounded, allowlisted recording skeletons for failed Petclinic campaign judges.

Reads private API snapshots, never copies them. Missing fields stay null. Counts
describe events in the saved snapshot, not proof that capture was complete.
The workflow scans these files with canary.py before uploading them.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import canary  # noqa: E402

MAX_BYTES = 512 * 1024  # per step; at most twelve step files
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_FILES = 800
MAX_RECORDINGS = 128
MAX_EVENTS = 1024
MAX_EVENTS_PER_RECORDING = 128

# Only observed, exact templates from the pinned harness are publishable. Never
# normalize an observed concrete path into a template or echo an unknown path.
ROUTES = frozenset(("/", "/owners", "/owners/find", "/owners/new", "/owners/{ownerId}",
                    "/owners/{ownerId}/edit", "/owners/{ownerId}/pets/new",
                    "/owners/{ownerId}/pets/{petId}/visits/new", "/vets", "/vets.html", "/oups"))
KINDS = frozenset("unspecified request_update frame_enter frame_exit frame_throw line_cursor value_snapshot "
                  "database_start database_end outbound_http_start outbound_http_end async_link exception response gap".split())
GAP_REASONS = frozenset("unspecified line_budget value_budget throttle queue_full correlation_lost class_not_transformed "
                        "module_loaded_before_arm source_map_absent handled_exception_unobserved "
                        "child_process_not_instrumented bootstrap_consumed".split())
GAP_CODES = {"xtrace.capture.gap": "queue", "xtrace.capture.gap.recording-cap": "event_cap",
             "xtrace.capture.gap.not-transformed": "untransformed",
             "xtrace.capture.gap.writer-memory": "memory", "xtrace.capture.gap.recording-admission": "admission",
             "xtrace.capture.gap.frame-limit": "frame_limit",
             "xtrace.capture.gap.frame-limit.started": "start_frame_limit",
             "xtrace.capture.gap.frame-limit.finished": "finish_frame_limit",
             "xtrace.capture.gap.line-budget": "line_budget",
             "xtrace.capture.handler_unresolved": "handler_unresolved"}
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
JAVA_SYMBOL = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.(?:[A-Za-z_$][\w$]*|<init>|<clinit>)", re.ASCII)
# These prefixes classify layers only; they never authenticate symbol text.
FRAMEWORK_PACKAGES = (
    "java", "javax", "jdk",
    "org.springframework", "org.hibernate",
    "org.apache.catalina", "org.apache.coyote", "org.apache.tomcat",
    "jakarta",
)
REQUEST = re.compile(r"http\.request (?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (.+)")
RESPONSE = re.compile(r"http\.response (?:[1-5][0-9]{2}|unavailable)")

FLOW_SOURCES = {
    "record-stop-flow": ("api-record-stop", "api-live-record-stop/1", "api-live-record-stop/2", "api-live-record-stop/3"),
    "restart-reopen": ("api-after-restart", "api-before-restart"),
    "partial-recording-reopen": ("api-partial",),
    "active-line-frames": ("api-focused",), "frame-values": ("api-focused",),
    "focused-canary-injection": ("api-focused",), "focused-redaction-control": ("api-focused",),
    "focused-value-control": ("api-focused",), "standard-no-values": ("api-standard",),
}
INSTRUMENTED_STEPS = ("recordings-per-scenario", "source-identity", "api-json-artifact")
FLOW_BEFORE = {"record-stop-flow": "api-before-record-stop", "partial-recording-reopen": "api-before-partial",
               **{step: "api-focused/before" for step in FLOW_SOURCES if "focused" in FLOW_SOURCES[step][0]},
               "standard-no-values": "api-standard/before"}


def load(path: pathlib.Path):
    """Bound input reads and do not follow symlinks into other private data."""
    try:
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            return None
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        return json.loads(data) if len(data) <= MAX_INPUT_BYTES else None
    except (OSError, ValueError):
        return None


def enum(value, choices):
    return value if isinstance(value, str) and value in choices else None


def number(value, low=0, high=(1 << 64) - 1):
    return value if type(value) is int and low <= value <= high else None


def identifier(value):
    return value if isinstance(value, str) and UUID.fullmatch(value) else None


def decimal(value):
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value) and int(value) < 1 << 64 else None


def drop_counts(value):
    if not isinstance(value, dict):
        return None
    return {key: decimal(count) for key, count in value.items()
            if isinstance(key, str) and re.fullmatch(r"[0-9]{1,3}", key) and int(key) <= 255}


def incomplete(value):
    """Only store-generated tokens, never arbitrary producer or exception text."""
    if not isinstance(value, list):
        return None
    pattern = r"(?:persisted_status:(?:recording|finalizing|partial|invalid)|gap_event_sequence:[0-9]{1,20}|" \
              r"durable_tail_pending:[0-9]{1,20}\.\.[0-9]{1,20}|verification_budget_exceeded)"
    return [item if isinstance(item, str) and re.fullmatch(pattern, item) else None for item in value[:32]]


def event_kind(value):
    if not isinstance(value, str):
        return "unrecognized"
    return enum(value.removeprefix("recording_event_kind:"), KINDS) or "unrecognized"


def safe_symbol(value):
    """Keep allowlisted HTTP metadata; replace Java text with a layer and hash.

    Layers are naming heuristics, not proof that a class or member was built.
    No Java symbol is authenticated by the private API snapshot.
    """
    if not isinstance(value, str) or len(value) > 256:
        return None
    request = REQUEST.fullmatch(value)
    if request:
        return value if request[1] in ROUTES else None
    if RESPONSE.fullmatch(value):
        return value
    if JAVA_SYMBOL.fullmatch(value):
        declaring_class = value.rsplit(".", 1)[0]
        layer = "other"
        if declaring_class.startswith("org.springframework.samples.petclinic."):
            class_name = declaring_class.rsplit(".", 1)[-1]
            for suffix in ("Controller", "Service", "Repository"):
                if class_name.endswith(suffix):
                    layer = suffix.lower()
                    break
        elif any(declaring_class.startswith(package + ".") for package in FRAMEWORK_PACKAGES):
            layer = "framework"
        return f"withheld:{layer}:sha256:" + hashlib.sha256(value.encode()).hexdigest()
    return None


def recording(doc: dict) -> dict:
    """Copy only structural fields; line is never filled from a method extent."""
    events = doc.get("events")
    available = isinstance(events, list) and "_http" not in doc
    events = events if available else []
    outcome = doc.get("outcome")
    outcome = outcome if isinstance(outcome, dict) else {}
    route = None
    rows = []
    for event in events:
        if not isinstance(event, dict):
            continue
        kind = event_kind(event.get("kind"))
        symbol = safe_symbol(event.get("symbol"))
        request = REQUEST.fullmatch(symbol or "")
        if kind == "request_update" and request:
            route = route or request[1]
        if len(rows) < MAX_EVENTS_PER_RECORDING:
            seq = event.get("sequence")
            rows.append({"kind": kind,
                         "sequence": seq if isinstance(seq, str) and re.fullmatch(r"[0-9]{1,20}", seq) else None,
                         "frameId": identifier(event.get("frameId")),
                         "parentFrameId": identifier(event.get("parentFrameId")), "symbol": symbol,
                         "line": number(event.get("line"), 1, (1 << 32) - 1) if kind == "line_cursor" else None})
            if kind == "gap":
                gap = event.get("gap")
                gap = gap if isinstance(gap, dict) else {}
                rows[-1]["gap"] = {"reason": enum(gap.get("reason"), GAP_REASONS),
                                   **{key: decimal(gap.get(key)) for key in ("count", "firstSequence", "lastSequence")}}
                raw_symbol = event.get("symbol")
                rows[-1]["captureGapCode"] = GAP_CODES.get(raw_symbol) if isinstance(raw_symbol, str) else None
    return {"recordingId": identifier(doc.get("recordingId")),
            "status": enum(doc.get("status"), ("recording", "finalizing", "complete", "partial", "invalid")),
            "completion": enum(doc.get("completion"), ("complete", "partial", "invalid", "unavailable")),
            "durationNs": decimal(doc.get("durationNs")),
            "dropCountsByPriority": drop_counts(doc.get("dropCountsByPriority")),
            "incompleteEvidence": incomplete(doc.get("incompleteEvidence")),
            "incompleteEvidenceOmitted": max(0, len(doc["incompleteEvidence"]) - 32)
                if isinstance(doc.get("incompleteEvidence"), list) else 0,
            "routeTemplate": route,
            "outcome": {"kind": enum(outcome.get("kind"), ("responded", "exception_propagated", "client_aborted", "unobserved")),
                        "httpStatus": number(outcome.get("httpStatus"), 100, 599)},
            "eventsAvailable": available, "eventsObserved": len(events),
            "eventCountsByKind": dict(sorted(Counter(event_kind(e.get("kind")) if isinstance(e, dict) else "unrecognized"
                                                    for e in events).items())),
            "events": rows, "eventsOmitted": len(events) - len(rows)}


def encoded(doc: dict) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def proxy_diagnostics(path: pathlib.Path, needles: list[bytes]) -> dict:
    """Session metadata only: these rows do not attribute a call to a recording."""
    rows = []
    result = {"scope": "session metadata; no per-request attribution", "rows": rows, "available": False,
              "inputTruncated": False, "rowsOmitted": 0, "producerMayBeCapped": False}
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        return result
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
    except OSError:
        return result
    result["available"] = True
    result["inputTruncated"] = len(raw) > MAX_INPUT_BYTES
    observed = 0
    for line in raw[:MAX_INPUT_BYTES].splitlines():
        if not line.startswith(b'{"code":"XTR-JAVA-PROXY-DIAGNOSTIC",') or len(line) > 1024:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        observed += 1
        row = {"result": enum(doc.get("result"), ("transformed", "transform_failed", "resolved", "no_declaration", "resolution_failed"))}
        for key in ("proxyHash", "invocationHash", "declarationHash"):
            value = doc.get(key)
            row[key] = value if isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) else None
        # Apply the same canary needles even to hashes and fixed labels.
        if any(n in encoded(row) for n in needles):
            continue
        if len(rows) < 128:
            rows.append(row)
        else:
            result["rowsOmitted"] += 1
    result["producerMayBeCapped"] = observed >= 128
    return result


def skeleton(step: str, roots: list[pathlib.Path], needles: list[bytes], excluded: frozenset[str] = frozenset(),
             proxy: dict | None = None) -> dict:
    """Keep all event-kind counts even when event rows hit the output cap.

    Repeated ids in different snapshots are retained: a before/after comparison
    must not erase the very completion change a worker needs to diagnose.
    Snapshot numbers refer to the fixed source order, never to a private path.
    """
    result = {"schemaVersion": 1, "step": step,
              "scope": "saved API snapshots only; missing fields are not observed; counts do not prove complete capture",
              "limits": {"bytes": MAX_BYTES, "files": MAX_FILES, "recordings": MAX_RECORDINGS,
                         "events": MAX_EVENTS, "eventsPerRecording": MAX_EVENTS_PER_RECORDING},
              "recordings": [], "filesUnreadable": 0, "inputTruncated": False,
              "recordingsOmitted": 0, "stringsWithheld": 0, "evidenceAvailable": False}
    if proxy is not None:
        result["proxyDiagnostics"] = proxy
    remaining = MAX_EVENTS
    files_seen = 0
    for snapshot, root in enumerate(roots):
        # Root files (the final read) precede live probe subdirectories.
        paths = sorted(root.rglob("recording-*.json"), key=lambda p: (len(p.parts), str(p))) if root.is_dir() else []
        seen = set()
        for path in paths:
            rid = path.stem.removeprefix("recording-")
            if rid in excluded or rid in seen:
                continue
            if files_seen == MAX_FILES:
                result["inputTruncated"] = True
                break
            files_seen += 1
            if len(result["recordings"]) == MAX_RECORDINGS:
                result["recordingsOmitted"] += 1
                continue
            doc = load(path)
            if not isinstance(doc, dict):
                result["filesUnreadable"] += 1
                continue
            seen.add(rid)
            row = recording(doc)
            # Canary-shaped text can be syntactically valid as a symbol or id.
            # Apply the scanner's own raw/encoded needles to every output string.
            def scrub(value):
                if isinstance(value, str) and any(n in value.encode() for n in needles):
                    result["stringsWithheld"] += 1
                    return None
                if isinstance(value, dict):
                    return {k: scrub(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [scrub(v) for v in value]
                return value
            row = scrub(row)
            row["snapshot"] = snapshot
            keep = min(len(row["events"]), remaining)
            row["eventsOmitted"] += len(row["events"]) - keep
            row["events"] = row["events"][:keep]
            remaining -= keep
            result["recordings"].append(row)
    result["evidenceAvailable"] = bool(result["recordings"])
    # Explicit byte bound in addition to structural limits, keeping metadata for
    # every admitted recording before discarding event rows from the tail.
    while len(encoded(result)) > MAX_BYTES:
        row = next((r for r in reversed(result["recordings"]) if r["events"]), None)
        if row is not None:
            row["events"].pop()
            row["eventsOmitted"] += 1
        elif result["recordings"]:
            result["recordings"].pop()
            result["recordingsOmitted"] += 1
            result["evidenceAvailable"] = bool(result["recordings"])
        elif proxy is not None and proxy["rows"]:
            proxy["rows"].pop()
            proxy["rowsOmitted"] += 1
        else:
            raise ValueError("diagnostic envelope exceeds byte cap")
    return result


def write_failures(summary: pathlib.Path, instrumented: pathlib.Path, flows: pathlib.Path,
                   out: pathlib.Path, canaries: dict[str, str]) -> int:
    doc = load(summary)
    steps = {s["step"]: s.get("status") for s in (doc or {}).get("steps", [])}
    needles = [raw for _, _, raw in canary.build_index(canaries)]
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for step in (*INSTRUMENTED_STEPS, *FLOW_SOURCES):
        if steps.get(step) in ("pass", "reported"):
            continue
        roots = [flows / name for name in FLOW_SOURCES[step]] if step in FLOW_SOURCES else [instrumented / "api"]
        before = None
        if step in FLOW_BEFORE:
            before = flows / FLOW_BEFORE[step]
        elif step in INSTRUMENTED_STEPS:
            before = instrumented / "boundary-before"
        excluded = frozenset(p.stem.removeprefix("recording-") for p in before.glob("recording-*.json")) if before else frozenset()
        proxy = proxy_diagnostics(instrumented / "application.log", needles) if step in INSTRUMENTED_STEPS else None
        report = skeleton(step, roots, needles, excluded, proxy)
        if len(encoded(report)) > MAX_BYTES:
            raise ValueError("diagnostic size cap exceeded")
        (out / f"{step}.json").write_bytes(encoded(report))
        written += 1
    # Always nonempty, so required scan coverage works even on a green campaign.
    (out / "index.json").write_bytes(encoded({"schemaVersion": 1, "failedSteps": written}))
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("summary", "instrumented", "flows", "out", "canaries"):
        ap.add_argument(f"--{name}", required=True, type=pathlib.Path)
    args = ap.parse_args()
    canaries = load(args.canaries)
    if not isinstance(canaries, dict) or not canaries:
        print("campaign diagnostics: private canary file unavailable")
        return 1
    count = write_failures(args.summary, args.instrumented, args.flows, args.out, canaries)
    print(f"campaign diagnostics: {count} failed step skeleton(s) written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
