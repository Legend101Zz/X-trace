"""Strict fixture-only binding of each installed list/detail page to the query that obtained it."""
import base64
import datetime
import re
import uuid

from verify_fixture import require

LIST_LIMIT, DETAIL_LIMIT = 1, 2
MAX_PAGES = 64


def name(field, api):
    first, *tail = field.split("_")
    return first + "".join(t.capitalize() for t in tail) if api else field


def valid_id(value):
    try:
        return isinstance(value, str) and len(value) == 36 and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def decimal(value):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "decimal field")
    number = int(value)
    require(number < 2**64, "decimal range")
    return number


def opened(value):
    # The store uses the same six-digit UTC form for ordering and for serialization.
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value),
            "recording opening instant")
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")


def common(doc, api, project_id, limit):
    require(isinstance(doc, dict) and valid_id(project_id) and doc[name("project_id", api)] == project_id
            and type(doc[name("schema_version", api)]) is int and doc[name("schema_version", api)] == 3
            and type(doc["limit"]) is int and doc["limit"] == limit, "page project or limit")


def list_pages(fetch, api, project_id):
    after, previous, seen = None, None, {}
    for number in range(1, MAX_PAGES + 1):
        doc = fetch(after)
        common(doc, api, project_id, LIST_LIMIT)
        rows = doc["recordings"]
        require(doc["after"] == after and isinstance(rows, list) and len(rows) <= LIST_LIMIT
                and (after is None or rows), "recording list range")
        for row in rows:
            require(isinstance(row, dict), "recording list row")
            rid = row[name("recording_id", api)]
            instant = opened(row[name("opened_at", api)])
            require(valid_id(rid) and rid not in seen, "duplicate or invalid recording ID")
            key = (instant, rid)
            require(previous is None or key < previous, "recording list order")
            count = decimal(row[name("event_count", api)])
            first, last = row[name("first_sequence", api)], row[name("last_sequence", api)]
            if count:
                require(decimal(first) <= decimal(last), "listed sequence range")
            else:
                require(first is None and last is None, "empty recording sequence range")
            seen[rid] = (instant, count, first, last)
            previous = key
        next_after = doc[name("next_after", api)]
        if next_after is None:
            return seen, number
        require(len(rows) == LIST_LIMIT and next_after == rows[-1][name("recording_id", api)]
                and next_after != after, "recording continuation")
        after = next_after
    raise ValueError("recording list pagination bound")


def bound_cursor(project_id, rid, sequence):
    # RecordingRead v1 cursors encode the two UUIDs followed by a big-endian u64 sequence.
    raw = uuid.UUID(project_id).bytes + uuid.UUID(rid).bytes + sequence.to_bytes(8, "big")
    return "v1." + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def checked_detail_pages(fetch, api, project_id, rid):
    cursor, previous = None, -1
    for number in range(1, MAX_PAGES + 1):
        doc = fetch(cursor)
        common(doc, api, project_id, DETAIL_LIMIT)
        rows = doc["events"]
        require(valid_id(rid) and doc[name("recording_id", api)] == rid and doc["cursor"] == cursor
                and isinstance(rows, list) and len(rows) <= DETAIL_LIMIT and (cursor is None or rows),
                "detail identity or range")
        for event in rows:
            require(isinstance(event, dict), "detail event")
            seq = decimal(event["sequence"])
            require(seq > previous, "detail event order")
            previous = seq
        require(doc[name("first_sequence", api)] == (rows[0]["sequence"] if rows else None)
                and doc[name("last_sequence", api)] == (rows[-1]["sequence"] if rows else None),
                "detail sequence range")
        incomplete = doc[name("incomplete_evidence", api)]
        require(doc["completion"] in ("complete", "partial", "invalid", "unavailable")
                and (doc["outcome"] is None or isinstance(doc["outcome"], dict))
                and isinstance(incomplete, list) and all(isinstance(code, str) for code in incomplete),
                "detail completion evidence")
        nxt = doc[name("next_cursor", api)]
        if nxt is not None:
            require(rows and nxt == bound_cursor(project_id, rid, previous), "detail continuation")
        yield doc
        if nxt is None:
            return
        cursor = nxt
    raise ValueError("recording detail pagination bound")


def detail_pages(fetch, api, project_id, rid, event_count, listed_range):
    pages = list(checked_detail_pages(fetch, api, project_id, rid))
    for page in pages[1:]:
        for key in ("completion", "outcome", name("incomplete_evidence", api)):
            require(page[key] == pages[0][key], "post-shutdown recording evidence drift")
    events = [event for page in pages for event in page["events"]]
    require(len(events) == event_count, "listed and collected event counts differ")
    endpoints = (events[0]["sequence"], events[-1]["sequence"]) if events else (None, None)
    require(endpoints == listed_range, "listed and collected sequence endpoints")
    return {**pages[0], "events": events}, len(pages)
