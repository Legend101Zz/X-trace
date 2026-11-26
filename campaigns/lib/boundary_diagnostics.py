"""Count-only diagnostics for ordered live recording boundaries.

These manifests describe observations at one read. They never allocate a recording,
authorize an optional pre-dispatch root, or participate in boundary acceptance.
"""
import re
from collections import Counter

METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE")
READ_STAGES = ("list", "detail", "snapshot")
READ_REASONS = ("deadline", "transport", "http-status", "schema", "duplicate-identity",
                "cursor", "page-limit", "recording-limit", "io-error", "unavailable")
INITIAL_STATES = ("not-reached", "verified", "viewer-start", "viewer-auth", "read")
PHASE_STATES = ("verified", "initial-unverified", "prior-unverified", "read", "deadline", "strict-serial")
SNAPSHOT_V1_FIELDS = (
    "listedNewRecordings", "newRecordings", "namedMatched", "optionalNamed", "missingNamed", "capacityRejected",
    "unexpectedRoots", "unclassifiedRecordings", "unreadRecordings", "routeLess",
)
SNAPSHOT_V2_FIELDS = SNAPSHOT_V1_FIELDS + (
    "unassignedRecordings", "assignedPartialRecordings", "overmatchedRequests",
    "unmatchedSentRequests", "unaccountedRequests", "excessAccountedRequests",
)
MAX_COUNT = 1_000_000


def _root(detail):
    events = detail.get("events", [])
    if not isinstance(events, list) or any(not isinstance(row, dict) for row in events):
        return {}
    roots = [row for row in events if row.get("kind") == "recording_event_kind:request_update"]
    return roots[0] if len(roots) == 1 else {}


def _route_less(detail, root):
    symbol = root.get("symbol")
    prefix = "http.request "
    method = symbol.removeprefix(prefix) if isinstance(symbol, str) and symbol.startswith(prefix) else None
    interaction, outcome = root.get("interaction"), detail.get("outcome")
    if (method not in METHODS or root.get("fieldTruncations")
            or not isinstance(interaction, dict) or interaction.get("kind") != "interaction_kind:framework"
            or interaction.get("driver") != "servlet" or interaction.get("method") != method
            or interaction.get("path") not in (None, "")
            or detail.get("completion") not in ("complete", "partial")
            or any(event.get("kind") not in ("recording_event_kind:request_update",
                                            "recording_event_kind:response", "recording_event_kind:gap")
                   for event in detail["events"])):
        return None
    completion = detail["completion"]
    if outcome is None and completion == "partial":
        return completion, method, "unavailable", None
    if isinstance(outcome, dict):
        kind, status = outcome.get("kind"), outcome.get("httpStatus")
        if _outcome(completion, kind, status) and kind != "unavailable":
            return completion, method, kind, status
    return None


def _outcome(completion, kind, status):
    return ((kind == "responded" and type(status) is int and 400 <= status <= 599)
            or (kind == "unobserved" and status is None)
            or (completion == "partial" and kind == "unavailable" and status is None))


def snapshot(details, listing, before, boundary):
    named, optional = set(boundary["recordingIds"]), set(boundary.get("optionalRootIds", []))
    fresh = set(details) - set(before)
    listed = ({row["recordingId"] for row in listing} - set(before)) if listing is not None else fresh
    unread = {rid for rid in fresh if "_detailReadGap" in details[rid] or "_http" in details[rid]}
    counts = Counter()
    route_less = Counter()
    matched, observed_optional = set(), set()
    for rid in fresh - unread:
        detail = details[rid]
        root = _root(detail)
        observed = _route_less(detail, root)
        if observed:
            route_less[observed] += 1
        elif isinstance(root.get("symbol"), str) and re.fullmatch(r"http\.request [A-Z]+ /\S*", root["symbol"]):
            if rid in named:
                matched.add(rid)
            elif rid in optional:
                observed_optional.add(rid)
            else:
                counts["unexpectedRoots"] += 1
        else:
            counts["unclassifiedRecordings"] += 1
    return {"listedNewRecordings": len(listed), "newRecordings": len(fresh),
            "namedMatched": len(matched), "optionalNamed": len(observed_optional),
            "missingNamed": sum(max(0, row["requests"] - len(matched.intersection(row["recordingIds"])))
                                for row in boundary["routes"]),
            "capacityRejected": boundary["capacityDrops"], "unreadRecordings": len(unread),
            "unassignedRecordings": len(fresh - named - optional),
            "assignedPartialRecordings": len(boundary["partialRecordingIds"]),
            "overmatchedRequests": sum(max(0, -row["missing"]) for row in boundary["routes"]),
            "unmatchedSentRequests": abs(boundary["requests"] - sum(row["requests"] for row in boundary["routes"])),
            "unaccountedRequests": max(0, boundary["unaccounted"]),
            "excessAccountedRequests": max(0, -boundary["unaccounted"]),
            **{key: counts[key] for key in ("unexpectedRoots", "unclassifiedRecordings")},
            "routeLess": [{"completion": completion, "method": method, "outcome": outcome,
                           "httpStatus": status, "recordings": count}
                          for (completion, method, outcome, status), count in sorted(route_less.items())]}


def _count(value, *, maximum=MAX_COUNT):
    return type(value) is int and 0 <= value <= maximum


def _read_failure(row):
    return (isinstance(row, dict) and set(row) == {"stage", "reason"}
            and row["stage"] in READ_STAGES and row["reason"] in READ_REASONS)


def _snapshot(row, version):
    fields = SNAPSHOT_V1_FIELDS if version == 1 else SNAPSHOT_V2_FIELDS
    if (not isinstance(row, dict) or set(row) != set(fields)
            or not all(_count(row[key]) for key in fields if key != "routeLess")
            or not isinstance(row["routeLess"], list) or len(row["routeLess"]) > 400):
        return False
    seen, counted = set(), 0
    for bucket in row["routeLess"]:
        if (not isinstance(bucket, dict)
                or set(bucket) != {"completion", "method", "outcome", "httpStatus", "recordings"}
                or bucket["completion"] not in ("complete", "partial") or bucket["method"] not in METHODS
                or not _count(bucket["recordings"]) or bucket["recordings"] == 0):
            return False
        kind, status = bucket["outcome"], bucket["httpStatus"]
        if not _outcome(bucket["completion"], kind, status):
            return False
        key = (bucket["completion"], bucket["method"], kind, status)
        if key in seen:
            return False
        seen.add(key)
        counted += bucket["recordings"]
    if version == 2 and (row["unassignedRecordings"] > row["newRecordings"]
            or row["assignedPartialRecordings"] > row["newRecordings"] - row["unassignedRecordings"]
            or (row["unaccountedRequests"] and row["excessAccountedRequests"])):
        return False
    return row["listedNewRecordings"] >= row["newRecordings"] == counted + sum(row[key] for key in (
        "namedMatched", "optionalNamed", "unexpectedRoots", "unclassifiedRecordings", "unreadRecordings"))


def _complete_snapshot(phase):
    complete, poll = phase["lastComplete"], phase["lastCompletePoll"]
    if (complete is None) != (poll is None):
        return False
    if complete is not None and (
            phase["snapshot"] is None or not _count(poll, maximum=phase["snapshotPoll"])
            or not poll or not _snapshot(complete, 2)
            or complete["listedNewRecordings"] != complete["newRecordings"] or complete["unreadRecordings"] != 0
            or (poll == phase["snapshotPoll"] and complete != phase["snapshot"])):
        return False
    if phase["status"] in ("verified", "strict-serial"):
        return poll == phase["polls"]
    if phase["status"] == "read":
        return bool(phase["polls"]) and poll != phase["polls"]
    return True


def projection(value):
    """Check the complete closed manifest before letting any of its values leave the runner."""
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "initial", "phases"}:
        return None
    initial, phases = value["initial"], value["phases"]
    version = value["schemaVersion"]
    if (type(version) is not int or version not in (1, 2)
            or not isinstance(initial, dict) or set(initial) != {"status", "failure"}
            or initial["status"] not in INITIAL_STATES
            or (not _read_failure(initial["failure"]) if initial["status"] == "read"
                else initial["failure"] is not None)
            or not isinstance(phases, list) or len(phases) > 3
            or (initial["status"] == "not-reached" and phases)):
        return None
    if len(phases) == 0 and initial["status"] != "not-reached":
        return None
    fields = {"ordinal", "kind", "status", "polls", "failure", "snapshot", "snapshotPoll"}
    if version == 2:
        fields.update(("lastComplete", "lastCompletePoll"))
    for index, phase in enumerate(phases):
        if (not isinstance(phase, dict) or set(phase) != fields
                or type(phase["ordinal"]) is not int or phase["ordinal"] != index + 1
                or phase["kind"] != ("serial", "burst", "serial")[index]
                or phase["status"] not in PHASE_STATES or not _count(phase["polls"])
                or (not _read_failure(phase["failure"]) if phase["status"] == "read"
                    else phase["failure"] is not None)
                or ((phase["snapshot"] is None) != (phase["snapshotPoll"] is None))
                or (phase["snapshot"] is not None and (not _count(phase["snapshotPoll"], maximum=phase["polls"])
                    or not phase["snapshotPoll"] or not _snapshot(phase["snapshot"], version)))
                or (phase["status"] in ("verified", "strict-serial") and phase["snapshot"] is None)
                or (version == 2 and not _complete_snapshot(phase))
                or (phase["status"] == "strict-serial" and phase["kind"] != "serial")):
            return None
        if index == 0 and initial["status"] != "verified":
            expected = "initial-unverified"
        elif index and phases[index - 1]["status"] != "verified":
            expected = "prior-unverified"
        else:
            expected = None
        if (phase["status"] in ("prior-unverified", "initial-unverified") if expected is None
                else phase["status"] != expected or phase["polls"] != 0 or phase["snapshot"] is not None):
            return None
    first = next((phase["ordinal"] for phase in phases if phase["status"] != "verified"), None)
    return {**value, "firstUnverifiedPhase": first}
