"""Bounded, value-free observations from one recording detail, not causal attribution."""

KINDS = ("request_update", "frame_enter", "frame_exit", "frame_throw", "line_cursor", "value_snapshot",
         "database_start", "database_end", "outbound_http_start", "outbound_http_end", "async_link",
         "exception", "response", "gap")
GAPS = ("line_budget", "value_budget", "throttle", "queue_full", "correlation_lost",
        "class_not_transformed", "module_loaded_before_arm", "source_map_absent",
        "handled_exception_unobserved", "child_process_not_instrumented", "bootstrap_consumed")
LIMIT = 1000


def _number(value):
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    if type(value) is int and 0 <= value <= 2**64 - 1:
        return value
    return None


def _bucket(value):
    number = _number(value)
    return "unavailable" if number is None else ("zero" if number == 0 else "positive")


def project(doc, *, whole):
    """Never emit identifiers, arbitrary strings, values or per-request attribution."""
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list):
        return None
    events = doc["events"]
    kinds = dict.fromkeys((*KINDS, "other"), 0)
    gaps = dict.fromkeys((*GAPS, "other"), 0)
    malformed = False
    gap_missing = False
    for event in events[:LIMIT]:
        if not isinstance(event, dict):
            malformed = True
            continue
        kind = event.get("kind")
        if isinstance(kind, str):
            kind = kind.removeprefix("recording_event_kind:")
        kinds[kind if isinstance(kind, str) and kind in KINDS else "other"] += 1
        gap_missing |= "gap" not in event
        gap = event.get("gap")
        if isinstance(gap, dict):
            reason = gap.get("reason")
            gaps[reason if isinstance(reason, str) and reason in GAPS else "other"] += 1
        elif gap is not None:
            malformed = True
    outcome = doc.get("outcome")
    capacity = doc.get("capacity")
    terminal = (isinstance(outcome, dict) and outcome.get("kind") in
                ("responded", "exception_propagated", "client_aborted", "unobserved"))
    capacity_count = (capacity.get("capacityDroppedEvents", capacity.get("capacity_dropped_events"))
                      if isinstance(capacity, dict) else None)
    capacity_valid = isinstance(capacity, dict) and _number(capacity_count) is not None
    drops = doc.get("dropCountsByPriority", doc.get("drop_counts_by_priority"))
    session = doc.get("sessionContext", doc.get("session_context"))
    rejected = session.get("rejectedRequests", session.get("rejected_requests")) if isinstance(session, dict) else None
    positive = None
    # The store serializes an absent terminal finish's priority map as an empty object.
    if ((terminal or capacity_valid) and isinstance(drops, dict) and len(drops) <= 256
            and all(_number(v) is not None for v in drops.values())):
        positive = sum(_number(v) > 0 for v in drops.values())
    return {
        "scope": "whole-recording" if whole and len(events) <= LIMIT and not malformed else "partial-window",
        "terminal": "observed" if terminal else "unavailable",
        "capacity": "observed" if capacity_valid else "unavailable",
        "capacityDrops": _bucket(capacity_count) if capacity_valid else "unavailable",
        "positiveDropBuckets": positive,
        "sessionRejectedRequests": _bucket(rejected),
        "sessionScope": "session-wide-not-recording-attribution",
        "eventKinds": kinds,
        "gapReasons": gaps,
        "gapCoverage": "unavailable" if gap_missing or malformed else "observed-window",
        "unknown": ["partial-cause", "refusal-attribution", "session-counter-causality", "session-queue-counter"],
    }


def valid(value):
    """Admit only the closed projection before it crosses the public boundary."""
    keys = {"scope", "terminal", "capacity", "capacityDrops", "positiveDropBuckets",
            "sessionRejectedRequests", "sessionScope", "eventKinds", "gapReasons", "gapCoverage", "unknown"}
    if not isinstance(value, dict) or set(value) != keys:
        return False
    if (value["scope"] not in ("whole-recording", "partial-window")
            or value["terminal"] not in ("observed", "unavailable")
            or value["capacity"] not in ("observed", "unavailable")
            or value["capacityDrops"] not in ("zero", "positive", "unavailable")
            or ((value["capacity"] == "unavailable") != (value["capacityDrops"] == "unavailable"))
            or value["sessionRejectedRequests"] not in ("zero", "positive", "unavailable")
            or value["sessionScope"] != "session-wide-not-recording-attribution"
            or value["gapCoverage"] not in ("unavailable", "observed-window")
            or value["unknown"] != ["partial-cause", "refusal-attribution", "session-counter-causality", "session-queue-counter"]):
        return False
    positive = value["positiveDropBuckets"]
    if positive is not None and (type(positive) is not int or not 0 <= positive <= 256
                                 or value["terminal"] == value["capacity"] == "unavailable"):
        return False
    for key, names in (("eventKinds", KINDS), ("gapReasons", GAPS)):
        counts = value[key]
        if (not isinstance(counts, dict) or set(counts) != set((*names, "other"))
                or any(type(n) is not int or not 0 <= n <= LIMIT for n in counts.values())
                or sum(counts.values()) > LIMIT):
            return False
    return True
