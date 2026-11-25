"""Bounded private readback and finite evidence for the Medusa development journey."""
from collections import Counter
import re
from uuid import UUID


class EvidenceError(ValueError):
    """Missing or contradictory development evidence."""


def require(ok):
    if not ok:
        raise EvidenceError("Medusa evidence condition failed")


def recording_id(value):
    require(isinstance(value, str))
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise EvidenceError("invalid recording ID") from exc
    require(str(parsed) == value and parsed.version == 7)
    return value


def pages(load, rows_key, cursor_key, *, limit, max_rows):
    """Follow every continuation and reject any page that cannot prove forward progress."""
    cursor = None
    cursors = set()
    for _ in range(40):
        doc = load(cursor)
        require(isinstance(doc, dict) and rows_key in doc and cursor_key in doc)
        rows = doc[rows_key]
        require(isinstance(rows, list) and len(rows) <= limit and all(isinstance(row, dict) for row in rows))
        max_rows -= len(rows)
        require(max_rows >= 0)
        next_cursor = doc[cursor_key]
        require(next_cursor is None or (
            isinstance(next_cursor, str) and 0 < len(next_cursor) <= 4096
            and next_cursor not in cursors and bool(rows)))
        yield doc
        if next_cursor is None:
            return
        cursors.add(next_cursor)
        cursor = next_cursor
    raise EvidenceError("page bound exhausted")


def keys(paged, rows_key, key):
    ids = []
    for doc in paged:
        ids.extend(recording_id(row.get(key)) for row in doc[rows_key])
    require(len(ids) == len(set(ids)))
    return set(ids)


def detail(paged, rid, *, api):
    id_key = "recordingId" if api else "recording_id"
    completion = None
    outcome = None
    events = []
    previous = -1
    for doc in paged:
        require(doc.get(id_key) == rid and doc.get("completion") in ("complete", "partial", "unavailable"))
        if completion is None:
            completion = doc["completion"]
            outcome = doc.get("outcome")
        require(doc["completion"] == completion and "outcome" in doc and doc["outcome"] == outcome)
        for raw in doc["events"]:
            sequence = raw.get("sequence")
            require(isinstance(sequence, str) and re.fullmatch(r"[0-9]{1,20}", sequence) is not None)
            require(int(sequence) > previous)
            previous = int(sequence)
            # These are persisted fields with stable shared semantics, independent of display navigation.
            fields = ("kind", "symbol", "interaction", "exception")
            require(all(key in raw for key in fields) and isinstance(raw["kind"], str))
            event = {key: raw[key] for key in fields}
            event["sequence"] = sequence
            for camel, snake in (("eventId", "event_id"), ("parentEventId", "parent_event_id"),
                                 ("asyncParentEventId", "async_parent_event_id"),
                                 ("frameId", "frame_id"), ("sourceBinding", "source_binding")):
                key = camel if api else snake
                require(key in raw)
                event[camel] = raw[key]
            events.append(event)
    return {"completion": completion, "outcome": outcome, "events": events}


def workload(baseline, installed, expected):
    """Compare every original scenario and count private HTTP outcomes without emitting them."""
    require(len(expected) == 11 and len(set(expected)) == len(expected))
    counts = Counter()
    consecutive = {}
    for report in (baseline, installed):
        require(isinstance(report, dict) and report.get("project") == "medusa"
                and report.get("scenarioCount") == len(expected))
        cases = report.get("scenarios")
        require(isinstance(cases, list) and [case.get("id") for case in cases] == expected)
        receipts = []
        for case in cases:
            requests = case.get("requests")
            require(isinstance(requests, list) and 0 < len(requests) <= 100)
            status = [row.get("status") for row in requests]
            require(all(type(code) is int and (code == 0 or 100 <= code <= 599) for code in status))
            digest = case.get("semanticEffectFingerprint")
            receipts.append((case.get("result") == "passed" and 0 not in status
                             and isinstance(digest, str) and re.fullmatch("[a-f0-9]{64}", digest) is not None,
                             digest, status))
        if report is baseline:
            consecutive = receipts
    require(len(consecutive) == len(receipts))
    counts.update(code for _, _, statuses in receipts for code in statuses)
    concurrency = receipts[expected.index("concurrent-writes-and-reads")][2]
    return {
        "matched": sum(a[0] and b[0] and a[1] == b[1] for a, b in zip(consecutive, receipts)),
        "expected": len(expected), "requests": counts.total(), "transportFailures": counts[0],
        "concurrentRequests": len(concurrency), "concurrentResponses": sum(code != 0 for code in concurrency),
    }, counts


def capture(details, readiness_id, http):
    """Readiness has its own durable ID. Status parity is aggregate, without per-request attribution."""
    require(readiness_id in details)
    statuses = Counter()
    counts = dict(recordings=0, complete=0, requestRoots=0, expressHandlers=0, responded=0,
                  absentOutcome=0, orphanParents=0)
    for rid, row in details.items():
        if rid == readiness_id:
            continue
        counts["recordings"] += 1
        if row["completion"] == "complete":
            counts["complete"] += 1
        entries = [event for event in row["events"] if event["kind"] == "recording_event_kind:frame_enter"]
        roots = [event for event in entries if event["symbol"] == "node:http.Server.request"]
        ids = {event["eventId"] for event in row["events"] if event["eventId"] is not None}
        counts["requestRoots"] += int(len(roots) == 1 and roots[0]["eventId"] is not None
                                      and roots[0]["parentEventId"] is None)
        counts["expressHandlers"] += any((event["symbol"] or "").startswith("express.handler:") for event in entries)
        counts["orphanParents"] += sum(event["parentEventId"] is not None and event["parentEventId"] not in ids
                                      for event in row["events"])
        outcome = row["outcome"] or {}
        status = outcome.get("httpStatus")
        if outcome.get("kind") == "responded" and type(status) is int and 100 <= status <= 599:
            counts["responded"] += 1
            statuses[status] += 1
        else:
            counts["absentOutcome"] += 1
    counts["responseStatusMultisetMatches"] = bool(http) and statuses == http
    counts["passed"] = (counts["recordings"] > 0 and counts["complete"] == counts["recordings"]
                        and counts["requestRoots"] == counts["recordings"] and counts["expressHandlers"] > 0
                        and counts["absentOutcome"] == 0 and counts["orphanParents"] == 0
                        and counts["responseStatusMultisetMatches"])
    return counts
