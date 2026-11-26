"""Finite first-incomplete evidence from the existing Fineract API and CLI reads."""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import uuid

import installed_java

PAGE_LIMIT = 1000
MAX_PAGES = 40
MARKER_LIMIT = 32
MARKER_CLASSES = ("persisted-partial", "persisted-invalid", "verification-budget", "gap-event", "pending-tail", "other")
KINDS = ("request_update", "frame_enter", "frame_exit", "frame_throw", "line_cursor", "value_snapshot",
         "database_start", "database_end", "outbound_http_start", "outbound_http_end", "async_link",
         "exception", "response", "gap", "other")
GAPS = ("line_budget", "value_budget", "throttle", "queue_full", "correlation_lost", "class_not_transformed",
        "module_loaded_before_arm", "source_map_absent", "handled_exception_unobserved",
        "child_process_not_instrumented", "bootstrap_consumed", "other")
COMPLETIONS = ("complete", "partial", "invalid", "unavailable")
OUTCOMES = ("responded", "exception_propagated", "client_aborted", "unobserved")
MISSING = object()
API_EVIDENCE = "_fineractDetailEvidence"


def uuid_value(value):
    try:
        return isinstance(value, str) and len(value) == 36 and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def decimal(value):
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        number = int(value)
        if number < 2**64:
            return number
    return None


def cursor_for(project, rid, end):
    data = uuid.UUID(project).bytes + uuid.UUID(rid).bytes + end.to_bytes(8, "big")
    return "v1." + base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def field(snake, api):
    first, *rest = snake.split("_")
    return first + "".join(piece.capitalize() for piece in rest) if api else snake


def checked_events(events, previous):
    if not isinstance(events, list):
        raise ValueError("invalid evidence event carrier")
    for event in events:
        number = decimal(event.get("sequence")) if isinstance(event, dict) else None
        if number is None or number <= previous:
            raise ValueError("invalid evidence event order")
        previous = number
    return previous


def listed_range(page, row, after, *, api):
    """Keep the range from this transport's list response, separately from detail evidence."""
    project = page.get(field("project_id", api))
    rid = row.get(field("recording_id", api))
    if (not uuid_value(project) or not uuid_value(rid)
            or type(page.get(field("schema_version", api))) is not int or page[field("schema_version", api)] != 3
            or type(page.get("limit")) is not int or page["limit"] != (200 if api else 100)
            or page.get("after", MISSING) != after):
        return None
    count = decimal(row.get(field("event_count", api)))
    first = row.get(field("first_sequence", api), MISSING)
    last = row.get(field("last_sequence", api), MISSING)
    if count == 0 and first is None and last is None:
        return project, rid, 0, None, None
    first, last = decimal(first), decimal(last)
    if count is None or not count or first is None or last is None or first > last:
        return None
    return project, rid, count, first, last


class LiveDetails(dict):
    """Keep first wire replies alongside the ordinary flattened JSON mapping in memory only."""

    def __init__(self):
        super().__init__()
        self.first_pages = {}


class DetailPages:
    """Track provenance separately from the collection's original verdict."""

    def __init__(self, *, api, listed):
        self.api, self.listed = api, listed
        self.total, self.first, self.recording = 0, None, None
        self.count, self.last, self.project, self.next = 0, -1, None, None
        self.rejected = False
        self.marker_state = "observed"
        self.markers = dict.fromkeys(MARKER_CLASSES, 0)
        self.marker_count = 0

    def add(self, doc, rid, cursor):
        if self.rejected:
            return False
        project = doc.get(field("project_id", self.api))
        rows = doc.get("events")
        next_cursor = doc.get(field("next_cursor", self.api), MISSING)
        try:
            if (not uuid_value(project) or not uuid_value(rid) or (self.project is not None and project != self.project)
                    or doc.get(field("recording_id", self.api)) != rid
                    or type(doc.get(field("schema_version", self.api))) is not int
                    or doc[field("schema_version", self.api)] != 3
                    or type(doc.get("limit")) is not int or doc["limit"] != PAGE_LIMIT
                    or doc.get("cursor", MISSING) != cursor or self.next != cursor
                    or doc.get("projection") != "full" or doc.get(field("anchor_frame_id", self.api), MISSING) is not None
                    or not isinstance(rows, list) or len(rows) > PAGE_LIMIT or (cursor is not None and not rows)
                    or self.count >= MAX_PAGES):
                raise ValueError("invalid evidence page binding")
            last = checked_events(rows, self.last)
            if (doc.get(field("first_sequence", self.api), MISSING) != (rows[0]["sequence"] if rows else None)
                    or doc.get(field("last_sequence", self.api), MISSING) != (rows[-1]["sequence"] if rows else None)
                    or (next_cursor is not None and (not rows or next_cursor != cursor_for(project, rid, last)))):
                raise ValueError("invalid evidence page range")
        except ValueError:
            self.rejected = True
            return False
        if self.count == 0 and rows:
            self.first = decimal(rows[0]["sequence"])
        self.count += 1
        self.total += len(rows)
        self.recording = rid
        self.last, self.project, self.next = last, project, next_cursor
        if self.api:
            self.add_markers(doc.get(field("incomplete_evidence", self.api), MISSING))
        return True

    def add_markers(self, markers):
        if self.marker_state == "malformed":
            return
        if markers is MISSING:
            self.marker_state = "missing"
        elif (not isinstance(markers, list) or len(markers) > 4096
              or any(not isinstance(marker, str) for marker in markers)):
            self.marker_state = "malformed"
        elif self.marker_state == "observed":
            available = max(0, MARKER_LIMIT - self.marker_count)
            for marker in markers[:available]:
                self.markers[marker_kind(marker)] += 1
            self.marker_count += len(markers)

    def marker_evidence(self):
        observed = self.marker_state == "observed"
        return {"state": self.marker_state, "counts": self.markers if observed else None,
                "truncated": self.marker_count > MARKER_LIMIT if observed else None}

    def covers_list(self):
        return (self.count > 0 and self.next is None and not self.rejected
                and self.listed == (self.project, self.recording, self.total, self.first,
                                    self.last if self.total else None))

    def api_evidence(self, gap, session_in_detail):
        if self.rejected:
            return {"read": "rejected"}
        if not self.count:
            return {"read": "unavailable"}
        coverage = "partial-window" if gap else ("whole-recording" if self.covers_list() else "terminal-window")
        return {"read": coverage, "pages": self.count,
                "markers": self.marker_evidence(), "sessionInDetail": session_in_detail}


def marker_kind(marker):
    fixed = {"persisted_status:partial": "persisted-partial", "persisted_status:invalid": "persisted-invalid",
             "verification_budget_exceeded": "verification-budget"}
    if len(marker) <= 64:
        if marker in fixed:
            return fixed[marker]
        gap = re.fullmatch(r"gap_event_sequence:([1-9][0-9]{0,19})", marker)
        if gap and decimal(gap[1]) is not None:
            return "gap-event"
        tail = re.fullmatch(r"durable_tail_pending:([1-9][0-9]{0,19})\.\.([1-9][0-9]{0,19})", marker)
        if tail:
            first, last = map(decimal, tail.groups())
            if first is not None and last is not None and first <= last:
                return "pending-tail"
    return "other"


def enum_value(value, known):
    if value is MISSING:
        return "missing"
    if value is None:
        return "unavailable"
    if not isinstance(value, str):
        return "malformed"
    return value if value in known else "unrecognized"


def counter(doc, name, *, nullable_object=False, nullable_value=False):
    if doc is MISSING:
        return "missing"
    if doc is None and nullable_object:
        return "unavailable"
    if not isinstance(doc, dict):
        return "malformed"
    value = doc.get(name, MISSING)
    if value is MISSING:
        return "missing"
    if value is None and nullable_value:
        return "unavailable"
    number = decimal(value)
    return "malformed" if number is None else ("positive" if number else "zero")


def capture(doc, markers, scope, *, api, session_in_detail=True):
    """Bucket observed data without retaining identities, offsets, status codes or values."""
    events = doc["events"]
    event_kinds = dict.fromkeys(KINDS, 0)
    gap_reasons = dict.fromkeys(GAPS, 0)
    gap_problems = set()
    for event in events[:PAGE_LIMIT]:
        kind = event.get("kind")
        kind = kind.removeprefix("recording_event_kind:") if isinstance(kind, str) else None
        event_kinds[kind if kind in KINDS else "other"] += 1
        gap = event.get("gap", MISSING)
        if gap is MISSING:
            gap_problems.add("missing")
        elif isinstance(gap, dict):
            reason = gap.get("reason")
            gap_reasons[reason if isinstance(reason, str) and reason in GAPS else "other"] += 1
        elif gap is not None:
            gap_problems.add("malformed")
    outcome = doc.get("outcome", MISSING)
    if isinstance(outcome, dict):
        outcome = enum_value(outcome.get("kind", MISSING), OUTCOMES)
    else:
        outcome = "malformed" if outcome not in (MISSING, None) else enum_value(outcome, OUTCOMES)
    # Nested application structs retain their camelCase serde shape in both transports.
    capacity = counter(doc.get("capacity", MISSING), "capacityDroppedEvents", nullable_object=True)
    session_context = doc.get(field("session_context", api), MISSING) if session_in_detail else MISSING
    session = counter(session_context, "rejectedRequests", nullable_value=True)
    drops = doc.get(field("drop_counts_by_priority", api), MISSING)
    positives = None
    if drops is MISSING:
        drop_state = "missing"
    elif (not isinstance(drops, dict) or len(drops) > 256
          or any(decimal(key) is None or int(key) >= 2**32
                 or counter(drops, key) not in ("zero", "positive") for key in drops)):
        drop_state = "malformed"
    elif outcome not in OUTCOMES and capacity not in ("zero", "positive"):
        # An absent Finish can serialize as an empty map. Do not infer zero from it.
        drop_state = "unavailable"
    else:
        drop_state = "observed"
        positives = sum(counter(drops, key) == "positive" for key in drops)
    gap_status = "malformed" if "malformed" in gap_problems else "missing" if gap_problems else "observed"
    terminal = "observed" if outcome in OUTCOMES or capacity in ("zero", "positive") else "unavailable"
    from fineract_phase_evidence import metadata
    return {"duration": metadata(doc, api=api)["duration"],
            "markers": markers, "completion": enum_value(doc.get("completion", MISSING), COMPLETIONS),
            "terminal": terminal,
            "outcome": outcome, "capacityDrops": capacity, "sessionRejectedRequests": session,
            "dropBuckets": {"state": drop_state, "positive": positives},
            "eventKinds": event_kinds, "gapReasons": gap_reasons if gap_status == "observed" else None,
            "gapState": gap_status,
            "eventScope": scope if len(events) <= PAGE_LIMIT else "bounded-prefix"}


def read_api(api, rid, project, maximum, *, expected_request=None):
    """Read one exact earlier saved detail from the admitted final API sink."""
    try:
        installed_java.private_dir(api)
        fd = os.open(api / f"recording-{rid}.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or info.st_nlink != 1 or info.st_size > maximum):
                return "rejected", None
            raw = stream.read(maximum + 1)
            if len(raw) > maximum:
                return "rejected", None
            doc = json.loads(raw)
    except FileNotFoundError:
        return "missing", None
    except (OSError, ValueError, RecursionError):
        return "rejected", None
    if not isinstance(doc, dict) or doc.get("recordingId") != rid:
        return "rejected", None
    evidence = doc.get(API_EVIDENCE)
    if not isinstance(evidence, dict):
        return "unavailable", None
    state = evidence.get("read")
    if state in ("rejected", "unavailable") and set(evidence) == {"read"}:
        return state, None
    if (state not in ("whole-recording", "terminal-window", "partial-window")
            or set(evidence) != {"read", "pages", "markers", "sessionInDetail"}
            or type(evidence["pages"]) is not int or not 1 <= evidence["pages"] <= MAX_PAGES
            or type(evidence["sessionInDetail"]) is not bool
            or not valid_markers(evidence["markers"]) or doc.get("projectId") != project
            or not isinstance(doc.get("events"), list) or len(doc["events"]) > PAGE_LIMIT * evidence["pages"]
            or "_http" in doc or ("_detailReadGap" in doc) != (state == "partial-window")
            or (state != "partial-window" and doc.get("nextCursor", MISSING) is not None)):
        return "rejected", None
    try:
        checked_events(doc["events"], -1)
    except ValueError:
        return "rejected", None
    if expected_request is not None:
        roots = [row.get("symbol") for row in doc["events"] if row.get("kind") == "recording_event_kind:request_update"]
        if roots != [expected_request]:
            return "rejected", None
    return state, capture(doc, evidence["markers"], state, api=True, session_in_detail=evidence["sessionInDetail"])


def unavailable_pair(cli_read):
    return {"cliRead": cli_read, "apiRead": "unavailable", "cli": None, "api": None}


def first_pair(api, rid, pages, doc, maximum):
    if pages.rejected:
        return unavailable_pair("rejected")
    scope = "whole-recording" if pages.count == 1 and pages.covers_list() else "one-page"
    pages.add_markers(doc.get("incomplete_evidence", MISSING))
    state, paired = read_api(api, rid, pages.project, maximum)
    return {"cliRead": scope, "apiRead": state, "cli": capture(doc, pages.marker_evidence(), scope, api=False),
            "api": paired}


def valid_counts(doc, keys, bound):
    return (isinstance(doc, dict) and set(doc) == set(keys)
            and all(type(n) is int and 0 <= n <= bound for n in doc.values()) and sum(doc.values()) <= bound)


def valid_markers(value):
    if not isinstance(value, dict) or set(value) != {"state", "counts", "truncated"}:
        return False
    state, counts, truncated = value["state"], value["counts"], value["truncated"]
    if state in ("missing", "malformed"):
        return counts is None and truncated is None
    return (state == "observed" and type(truncated) is bool and valid_counts(counts, MARKER_CLASSES, MARKER_LIMIT)
            and (not truncated or sum(counts.values()) == MARKER_LIMIT))


def valid_capture(value, scope):
    keys = {"markers", "completion", "terminal", "outcome", "capacityDrops", "sessionRejectedRequests", "dropBuckets",
            "eventKinds", "gapReasons", "gapState", "eventScope"}
    unknown = ("missing", "unavailable", "malformed", "unrecognized")
    counters = ("zero", "positive", "missing", "unavailable", "malformed")
    if (not isinstance(value, dict) or set(value) not in (keys, keys | {"duration"}) or not valid_markers(value["markers"])
            or value["completion"] not in (*COMPLETIONS, *unknown) or value["outcome"] not in (*OUTCOMES, *unknown)
            or ("duration" in value and value["duration"] not in ("present", "null", "missing", "malformed"))
            or value["capacityDrops"] not in counters or value["sessionRejectedRequests"] not in counters
            or value["terminal"] != ("observed" if value["outcome"] in OUTCOMES
                                     or value["capacityDrops"] in ("zero", "positive") else "unavailable")
            or value["eventScope"] not in (scope, "bounded-prefix")
            or not valid_counts(value["eventKinds"], KINDS, PAGE_LIMIT)
            or (value["eventScope"] == "bounded-prefix" and sum(value["eventKinds"].values()) != PAGE_LIMIT)):
        return False
    gaps = value["gapReasons"]
    if value["gapState"] == "observed":
        if not valid_counts(gaps, GAPS, sum(value["eventKinds"].values())):
            return False
    elif value["gapState"] not in ("missing", "malformed") or gaps is not None:
        return False
    buckets = value["dropBuckets"]
    if not isinstance(buckets, dict) or set(buckets) != {"state", "positive"}:
        return False
    if buckets["state"] == "observed":
        return (type(buckets["positive"]) is int and 0 <= buckets["positive"] <= 256
                and (value["outcome"] in OUTCOMES or value["capacityDrops"] in ("zero", "positive")))
    if buckets["state"] == "unavailable" and value["terminal"] == "observed":
        return False
    return buckets["state"] in ("missing", "unavailable", "malformed") and buckets["positive"] is None


def public_pair(pair):
    from fineract_phase_evidence import valid
    if not isinstance(pair, dict) or set(pair) not in ({"cliRead", "apiRead", "cli", "api"},
                                                     {"cliRead", "apiRead", "cli", "api", "phaseEvidence"}):
        return None
    if "phaseEvidence" in pair and not valid(pair["phaseEvidence"]):
        return None
    cli_state, api_state, cli, api = (pair[key] for key in ("cliRead", "apiRead", "cli", "api"))
    if cli_state in ("rejected", "unavailable"):
        if api_state != "unavailable" or cli is not None or api is not None:
            return None
    elif cli_state not in ("whole-recording", "one-page") or not valid_capture(cli, cli_state):
        return None
    if cli is None and "phaseEvidence" in pair:
        phase = pair["phaseEvidence"]
        if phase["liveState"] != "unavailable" or phase["stopState"] != "unavailable":
            return None
    if cli is not None:
        markers = cli["markers"]
        if (cli["eventScope"] == "bounded-prefix" or
                (markers["state"] == "observed" and not sum(markers["counts"].values()))):
            return None
    if api_state in ("whole-recording", "terminal-window", "partial-window"):
        if not valid_capture(api, api_state):
            return None
    elif api_state not in ("missing", "rejected", "unavailable") or api is not None:
        return None
    same_scope = cli is not None and api is not None and cli["eventScope"] == api["eventScope"] == "whole-recording"
    categories = None
    if (same_scope and all(side["markers"]["state"] == "observed" and not side["markers"]["truncated"]
                           for side in (api, cli))):
        categories = sum(api["markers"]["counts"][key] > 0 and cli["markers"]["counts"][key] > 0
                         for key in MARKER_CLASSES if key != "other")
    return {**pair, "comparisonScope": "both-whole" if same_scope else (
                "different-or-bounded-windows" if api is not None else "unavailable"),
            "observationPhases": "earlier-saved-api-later-cli" if api is not None else None,
            "sharedKnownMarkerCategories": categories, "sessionScope": "session-wide",
            "identityScope": "same-recording-not-client-attribution" if api is not None else "unavailable",
            "terminalMeaning": "persisted-terminal-metadata-not-adapter-finish",
            "recoveryMeaning": "not-listed-does-not-exclude-earlier-recovery"}
