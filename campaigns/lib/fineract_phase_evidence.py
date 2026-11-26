"""Same-recording live/stop observations; terminal metadata is not adapter Finish proof."""
from __future__ import annotations

import json
import os
import stat

import fineract_detail_evidence as detail
import installed_java

OFFICE_LIST_ROUTE = "/fineract-provider/api/v1/offices"
MAX_RECORDINGS = 400
MAX_BYTES = 1 << 20
AXES = {"terminalMetadata": ("present", "absent", "unknown"),
        "duration": ("present", "null", "missing", "malformed"),
        "completion": ("complete", "partial", "invalid", "unknown")}


def metadata(doc, *, api):
    """Project presence only. Missing adapter outcomes can be synthesized as unobserved."""
    outcome, capacity = doc.get("outcome", detail.MISSING), doc.get("capacity", detail.MISSING)
    if ((isinstance(outcome, dict) and outcome.get("kind") in detail.OUTCOMES)
            or (isinstance(capacity, dict) and detail.decimal(capacity.get("capacityDroppedEvents")) is not None)):
        terminal = "present"
    elif outcome is None and capacity is None:
        terminal = "absent"
    else:
        terminal = "unknown"
    duration = doc.get(detail.field("duration_ns", api), detail.MISSING)
    duration_state = ("missing" if duration is detail.MISSING else "null" if duration is None
                      else "present" if detail.decimal(duration) is not None else "malformed")
    return {"terminalMetadata": terminal, "duration": duration_state,
            "completion": doc.get("completion") if doc.get("completion") in AXES["completion"] else "unknown"}


def valid_metadata(value):
    return isinstance(value, dict) and set(value) == set(AXES) and all(value[k] in values for k, values in AXES.items())


def write_private(path, value):
    installed_java.private_dir(path.parent)
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(payload) > MAX_BYTES:
        raise ValueError("phase evidence exceeds bound")
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(payload)


def read_private(path):
    installed_java.private_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > MAX_BYTES):
            raise ValueError("unsafe phase evidence")
        payload = stream.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            raise ValueError("phase evidence exceeds bound")
        return json.loads(payload)


def save_live(path, observed, poll):
    """Save only the already cached on-time complete poll, after the boundary decision."""
    records = []
    if observed is not None:
        details, listing, _ = observed
        if (type(poll) is not int or not 1 <= poll <= 1_000_000 or not isinstance(listing, list)
                or len(details) > MAX_RECORDINGS or len(listing) != len(details) or {row.get("recordingId") for row in listing} != set(details)):
            raise ValueError("invalid complete live snapshot")
        for rid, doc in details.items():
            project = doc.get("projectId")
            if (not detail.uuid_value(rid) or doc.get("recordingId") != rid or not detail.uuid_value(project)
                    or doc.get("schemaVersion") != 3 or doc.get("projection") != "full"
                    or "_detailReadGap" in doc or "_http" in doc):
                raise ValueError("unbound live detail")
            records.append({"project": project, "recording": rid, "metadata": metadata(doc, api=True)})
    elif poll is not None:
        raise ValueError("unpaired live poll")
    write_private(path, {"schema": 1, "poll": poll, "records": records})


def live_office_window(doc, page):
    """Project the actual first response only after this snapshot's timed work."""
    if page is None:
        return {"read": "unavailable", "capture": None}
    if not isinstance(page, dict) or page.get("projectId") != doc["projectId"]:
        return {"read": "rejected", "capture": None}
    wire = detail.DetailPages(api=True, listed=None)
    if not wire.add(page, doc["recordingId"], None):
        return {"read": "rejected", "capture": None}
    window = page["events"]
    roots = [row.get("symbol") for row in window if row.get("kind") == "recording_event_kind:request_update"]
    if (roots != ["http.request GET " + OFFICE_LIST_ROUTE]
            or any(not isinstance(row.get("kind"), str) or not row["kind"].startswith("recording_event_kind:")
                   for row in window)):
        return {"read": "rejected", "capture": None}
    # The legacy distinct-string census describes a single-page read. Wire occurrences
    # below also cover a first response with continuation and preserve repeated markers.
    single_page = page["nextCursor"] is None
    markers = page.get("incompleteEvidence", detail.MISSING) if single_page else detail.MISSING
    if single_page and wire.marker_state == "observed":
        markers = list(dict.fromkeys(markers))
    distinct = detail.DetailPages(api=True, listed=None)
    distinct.add_markers(markers)
    projected = detail.capture(page, distinct.marker_evidence(), "retained-first-page", api=True,
                               session_in_detail=False)
    for event in window:
        gap = event.get("gap", detail.MISSING)
        if event["kind"] != "recording_event_kind:gap" and gap is not None and gap is not detail.MISSING:
            projected.update(gapState="malformed", gapReasons=None)
            break
        if event["kind"] == "recording_event_kind:gap" and gap is None and projected["gapState"] == "observed":
            projected.update(gapState="missing", gapReasons=None)
    return {"read": "retained-first-page", "capture": projected,
            "markerScope": "retained-single-page-strings" if single_page else "withheld-across-pages",
            "firstPageMarkers": wire.marker_evidence()}


def valid_live_window(value, live):
    if not isinstance(value, dict):
        return False
    if value.get("read") in ("unavailable", "rejected"):
        return set(value) == {"read", "capture"} and value["capture"] is None
    if (set(value) != {"read", "capture", "markerScope", "firstPageMarkers"} or value["read"] != "retained-first-page"
            or not detail.valid_markers(value["firstPageMarkers"])
            or value["markerScope"] not in ("retained-single-page-strings", "withheld-across-pages")):
        return False
    projection = value["capture"]
    if not detail.valid_capture(projection, value["read"]):
        return False
    distinct, original = projection["markers"], value["firstPageMarkers"]
    if value["markerScope"] == "retained-single-page-strings":
        if distinct["state"] != original["state"]:
            return False
        if original["state"] == "observed" and not original["truncated"]:
            if distinct["truncated"]:
                return False
            for key, count in original["counts"].items():
                unique = distinct["counts"][key]
                if unique > count or bool(unique) != bool(count):
                    return False
    return (projection["eventScope"] == value["read"] and projection["completion"] == live["completion"]
            and projection["eventKinds"]["request_update"] == 1
            and (projection["gapState"] != "observed" or sum(projection["gapReasons"].values()) == projection["eventKinds"]["gap"])
            and (value["markerScope"] != "withheld-across-pages" or projection["markers"]["state"] == "missing")
            and (projection["terminal"] == "observed") == (live["terminalMetadata"] == "present")
            and projection.get("duration") == live["duration"] and projection["sessionRejectedRequests"] == "missing")


def save_office_read(capture, observed, poll):
    """Select the existing ordinary office-list route in the retained first serial poll."""
    if observed is None:
        return
    details, _, boundary = observed
    rows = [row for row in boundary.get("routes", []) if (row["method"], row["route"]) == ("GET", OFFICE_LIST_ROUTE)]
    if len(rows) != 1 or rows[0]["requests"] != 1 or rows[0]["recordings"] != 1 or rows[0]["missing"] != 0:
        return
    ids = rows[0]["recordingIds"]
    if not isinstance(ids, list) or len(ids) != 1 or not detail.uuid_value(ids[0]):
        return
    rid = ids[0]
    if (rid not in boundary["recordingIds"] or rid not in boundary["partialRecordingIds"]
            or rid in boundary.get("optionalRootIds", ())):
        return
    doc = details[rid]
    roots = [event for event in doc["events"] if event.get("kind") == "recording_event_kind:request_update"]
    if (len(roots) != 1 or roots[0].get("symbol") != "http.request GET " + OFFICE_LIST_ROUTE
            or doc["completion"] != "partial" or doc["recordingId"] != rid or not detail.uuid_value(doc["projectId"])):
        return
    page = details.first_pages.get(rid) if isinstance(details, detail.LiveDetails) else None
    write_private(capture / "phase-1-api/office-list-partial.json",
                  {"poll": poll, "project": doc["projectId"], "recording": rid, "window": live_office_window(doc, page)})


def stop_projection(result):
    """Retain only exact identities from the existing stop result; never infer recovery."""
    raw = result.stdout
    if not isinstance(raw, (str, bytes)) or len(raw) > MAX_BYTES:
        raise ValueError("unavailable stop document")
    doc = json.loads(raw)
    keys = {"kind", "project_id", "pid", "runtime_session_id", "was_running", "recovered_recordings"}
    if (not isinstance(doc, dict) or set(doc) != keys or doc["kind"] not in ("stopped", "stop_not_running")
            or not detail.uuid_value(doc["project_id"]) or type(doc["was_running"]) is not bool
            or result.returncode not in (0, 3, 10) or not isinstance(doc["recovered_recordings"], list)
            or len(doc["recovered_recordings"]) > MAX_RECORDINGS):
        raise ValueError("invalid stop document")
    no_identity = doc["pid"] is None and doc["runtime_session_id"] is None
    retained_identity = (type(doc["pid"]) is int and 0 < doc["pid"] < 2**32
                         and detail.uuid_value(doc["runtime_session_id"]))
    if doc["kind"] == "stop_not_running":
        # Both stale-record branches retain the real recorded identity; absent-record does not.
        if doc["was_running"] or not (no_identity or retained_identity):
            raise ValueError("inconsistent stop state")
    elif not doc["was_running"] or not retained_identity:
        raise ValueError("inconsistent running stop state")
    rows = doc["recovered_recordings"]
    if any(not isinstance(row, dict) or set(row) != {"recording_id", "persisted_events", "completion"}
           or not detail.uuid_value(row["recording_id"]) or detail.decimal(row["persisted_events"]) is None
           or row["completion"] not in ("complete", "partial", "invalid", "failed") for row in rows):
        raise ValueError("invalid recovery row")
    expected_exit = 3 if doc["kind"] == "stop_not_running" and rows else (
        10 if any(row["completion"] == "failed" for row in rows) else 0)
    if result.returncode != expected_exit:
        raise ValueError("inconsistent recovery exit")
    ids = [row["recording_id"] for row in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate recovery identity")
    return {"schema": 1, "project": doc["project_id"], "recordings": [{"recording": row["recording_id"], "completion": row["completion"]} for row in rows]}


def save_stop(path, result):
    write_private(path, stop_projection(result))


def save_deferred(capture, observation, stop):
    """Run after receipt measurements and final API collection, outside all phase clocks."""
    if len(observation) == 1:
        observed, poll = observation[0]
        try:
            save_live(capture / "phase-1-api/fineract-phase.json", observed, poll)
        except (OSError, ValueError, TypeError, RecursionError):
            pass  # Missing diagnostics cannot change the already written receipt or verdict.
        else:
            try:
                save_office_read(capture, observed, poll)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
                pass  # This optional selector never prevents the independent stop projection.
    try:
        save_stop(capture / "fineract-stop.json", stop)
    except (OSError, ValueError, TypeError, RecursionError):
        pass  # Unavailable recovery evidence is never proof of no recovery.


def correlate(capture, project, rid):
    """Never transfer a phase-group count or another recording's observation to this record."""
    out = {"liveState": "unavailable", "livePhase": None, "livePoll": None, "live": None,
           "stopState": "unavailable", "recoveredCount": None, "selectedRecovery": "unknown", "selectedRecoveryResult": None}
    if not detail.uuid_value(project) or not detail.uuid_value(rid):
        return out
    available = False
    for ordinal in (1,):
        try:
            doc = read_private(capture / f"phase-{ordinal}-api/fineract-phase.json")
        except FileNotFoundError:
            continue
        except (OSError, ValueError, RecursionError):
            out["liveState"] = "rejected"
            break
        if (not isinstance(doc, dict) or set(doc) != {"schema", "poll", "records"} or type(doc["schema"]) is not int
                or doc["schema"] != 1 or not isinstance(doc["records"], list) or len(doc["records"]) > MAX_RECORDINGS
                or (doc["poll"] is None and doc["records"])
                or (doc["poll"] is not None and (type(doc["poll"]) is not int or not 1 <= doc["poll"] <= 1_000_000))):
            out["liveState"] = "rejected"
            break
        records = doc["records"]
        if (any(not isinstance(row, dict) or set(row) != {"project", "recording", "metadata"}
                or not detail.uuid_value(row["project"]) or not detail.uuid_value(row["recording"])
                or not valid_metadata(row["metadata"]) for row in records)
                or len({row["recording"] for row in records}) != len(records)):
            out["liveState"] = "rejected"
            break
        available |= doc["poll"] is not None
        match = [row for row in records if row["recording"] == rid]
        if match:
            if match[0]["project"] != project:
                out["liveState"] = "rejected"
            else:
                out.update(liveState="observed", livePhase=ordinal, livePoll=doc["poll"], live=match[0]["metadata"])
            break
    else:
        if available:
            out["liveState"] = "not-observed"
    try:
        doc = read_private(capture / "fineract-stop.json")
        if (not isinstance(doc, dict) or set(doc) != {"schema", "project", "recordings"}
                or type(doc["schema"]) is not int or doc["schema"] != 1 or doc["project"] != project
                or not isinstance(doc["recordings"], list) or len(doc["recordings"]) > MAX_RECORDINGS
                or any(not isinstance(row, dict) or set(row) != {"recording", "completion"}
                       or not detail.uuid_value(row["recording"])
                       or row["completion"] not in ("complete", "partial", "invalid", "failed")
                       for row in doc["recordings"])
                or len({row["recording"] for row in doc["recordings"]}) != len(doc["recordings"])):
            raise ValueError("invalid private stop projection")
        selected = [row for row in doc["recordings"] if row["recording"] == rid]
        out.update(stopState="observed", recoveredCount=len(doc["recordings"]),
                   selectedRecovery="listed" if selected else "not-listed",
                   selectedRecoveryResult=selected[0]["completion"] if selected else None)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, RecursionError):
        out["stopState"] = "rejected"
    return out


def valid(value):
    keys = {"liveState", "livePhase", "livePoll", "live", "stopState", "recoveredCount", "selectedRecovery", "selectedRecoveryResult"}
    if not isinstance(value, dict) or set(value) != keys:
        return False
    if value["liveState"] == "observed":
        if (type(value["livePhase"]) is not int or value["livePhase"] != 1
                or type(value["livePoll"]) is not int or not 1 <= value["livePoll"] <= 1_000_000
                or not valid_metadata(value["live"])):
            return False
    elif (value["liveState"] not in ("unavailable", "not-observed", "rejected")
          or any(value[k] is not None for k in ("livePhase", "livePoll", "live"))):
        return False
    if value["stopState"] == "observed":
        return (type(value["recoveredCount"]) is int and 0 <= value["recoveredCount"] <= MAX_RECORDINGS
                and value["selectedRecovery"] in ("listed", "not-listed")
                and ((value["selectedRecovery"] == "listed" and value["recoveredCount"] > 0
                      and value["selectedRecoveryResult"] in ("complete", "partial", "invalid", "failed"))
                     or (value["selectedRecovery"] == "not-listed" and value["selectedRecoveryResult"] is None)))
    return (value["stopState"] in ("unavailable", "rejected") and value["recoveredCount"] is None
            and value["selectedRecovery"] == "unknown" and value["selectedRecoveryResult"] is None)
