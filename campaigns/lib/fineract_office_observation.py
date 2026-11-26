"""Observe one ordinary office collection read from two complete, project-bound snapshots."""
from __future__ import annotations

from dataclasses import dataclass

import re
import fineract_detail_evidence as detail
import fineract_phase_evidence as phase
from campaigns.java.fineract.harness.recording_evidence import OFFICE_RESOURCE, symbol_matches


ROOT = "http.request GET " + phase.OFFICE_LIST_ROUTE
PREFIX = "recording_event_kind:"


@dataclass(frozen=True)
class Inventory:
    project: str
    ranges: dict


def inventory(project, pages):
    """Accept the list replies received in one read, in wire order, including an empty list."""
    if not isinstance(pages, (list, tuple)) or not 1 <= len(pages) <= 20 or not detail.uuid_value(project):
        raise ValueError("unbound recording list")
    ranges, seen = {}, set()
    after = None
    for index, page in enumerate(pages):
        if (index >= 20 or (index and after is None) or not isinstance(page, dict)
                or page.get("projectId") != project or type(page.get("schemaVersion")) is not int
                or page["schemaVersion"] != 3 or type(page.get("limit")) is not int or page["limit"] != 200
                or page.get("after", detail.MISSING) != after or not isinstance(page.get("recordings"), list)):
            raise ValueError("unbound recording list")
        rows = page["recordings"]
        if len(rows) > 200 or (after is not None and not rows):
            raise ValueError("invalid recording list window")
        for row in rows:
            span = detail.listed_range(page, row, after, api=True) if isinstance(row, dict) else None
            if span is None or span[1] in ranges or len(ranges) >= 400:
                raise ValueError("invalid recording list range")
            ranges[span[1]] = span
        after = page.get("nextAfter", detail.MISSING)
        if after is not None:
            if len(rows) != 200 or after != rows[-1]["recordingId"] or after in seen:
                raise ValueError("invalid recording list continuation")
            seen.add(after)
    if after is not None:
        raise ValueError("unfinished recording list")
    return Inventory(project, ranges)


def _bound_events(rid, span, doc):
    """Recheck the actual aggregate against that poll's listing and authenticated detail census."""
    evidence = doc.get(detail.API_EVIDENCE) if isinstance(doc, dict) else None
    if (not isinstance(evidence, dict) or evidence.get("read") != "whole-recording"
            or type(evidence.get("pages")) is not int or not 1 <= evidence["pages"] <= detail.MAX_PAGES
            or doc.get("completion") not in detail.COMPLETIONS or not detail.valid_markers(evidence.get("markers"))
            or doc.get("recordingId") != rid
            or doc.get("projectId") != span[0] or doc.get("nextCursor", detail.MISSING) is not None
            or "_detailReadGap" in doc or "_http" in doc):
        return None
    events = doc.get("events")
    if not isinstance(events, list) or not len(events) == span[2] <= detail.PAGE_LIMIT * evidence["pages"]:
        return None
    try:
        last = detail.checked_events(events, -1)
    except ValueError:
        return None
    actual = (detail.decimal(events[0]["sequence"]), last) if events else (None, None)
    if (actual != span[3:] or any(not isinstance(row.get("kind"), str)
                                  or not row["kind"].startswith(PREFIX) for row in events)):
        return None
    return events


def observe(before, current, snapshot):
    """Return a private selected ID separately from the finite, identity-free public observation."""
    if (before.project != current.project or not before.ranges.keys() <= current.ranges.keys()
            or not isinstance(snapshot, dict) or snapshot.get("ok") is not True
            or not isinstance(snapshot.get("details"), detail.LiveDetails)
            or set(snapshot["details"]) != current.ranges.keys()):
        return None, {"selection": "unbound"}
    fresh = current.ranges.keys() - before.ranges.keys()
    if not fresh:
        return None, {"selection": "not-observed"}
    candidates = []
    for rid in fresh:
        doc = snapshot["details"][rid]
        events = _bound_events(rid, current.ranges[rid], doc)
        if events is None:
            return None, {"selection": "unbound"}
        roots = [e.get("symbol") for e in events if e["kind"] == PREFIX + "request_update"]
        # Frameworks can record templates instead of concrete paths. Another
        # such root might also describe this GET, so it cannot exclude a match.
        if (len(roots) != 1 or not isinstance(roots[0], str)
                or not re.fullmatch(r"http\.request [A-Z]+ /(?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*)?", roots[0])):
            return None, {"selection": "ambiguous"}
        if roots[0] == ROOT:
            candidates.append((rid, doc, events))
    if len(candidates) != 1:
        return None, {"selection": "ambiguous" if candidates else "not-observed"}
    rid, doc, events = candidates[0]
    first = snapshot["details"].first_pages.get(rid)
    if not isinstance(first, dict) or not isinstance(first.get("events"), list) or first["events"] != events[:len(first["events"])]:
        return None, {"selection": "unbound"}
    window = phase.live_office_window(doc, first)
    state = phase.metadata(doc, api=True)
    # A genuinely open detail has completion unavailable; the V3 partial-record selector
    # deliberately has no separate admission rule for that state. Do not force a terminal.
    if window.get("read") != "retained-first-page":
        return None, {"selection": "unbound"}
    projected_state = {**state, "completion": doc.get("completion")}
    if not phase.valid_live_window(window, projected_state):
        return None, {"selection": "unbound"}
    outcome = first.get("outcome")
    status = outcome.get("httpStatus") if isinstance(outcome, dict) else None
    gaps = [e for e in events if e["kind"] == PREFIX + "gap"]
    reasons = dict.fromkeys(detail.GAPS, 0)
    for row in gaps:
        gap = row.get("gap")
        reason = gap.get("reason") if isinstance(gap, dict) else None
        if not isinstance(reason, str):
            reasons = None
            break
        reasons[reason if reason in reasons else "other"] += 1
    public = {"selection": "unique-new-office-root", "wholeEvents": len(events),
              "responses": sum(e["kind"] == PREFIX + "response" for e in events),
              "gaps": len(gaps), "gapReasons": reasons,
              "resourceEnters": sum(e["kind"] == PREFIX + "frame_enter"
                                    and symbol_matches(e, OFFICE_RESOURCE + "retrieveOffices") for e in events),
              "http200": status == 200 if type(status) is int and 100 <= status <= 599 else None,
              "firstWirePage": window, "terminalMetadata": state["terminalMetadata"]}
    return rid, public


def after_stop(capture, project, rid, stop_result, api_limit):
    """Join the explicit stop's result and existing final API read independently."""
    if not detail.uuid_value(project) or not detail.uuid_value(rid):
        return {"recovery": "unbound", "result": None, "finalApiRead": "unavailable", "finalApi": None}
    recovery, completion = "unavailable", None
    if stop_result is not None:
        try:
            private = phase.stop_projection(stop_result)
            if private["project"] != project:
                raise ValueError("different stop project")
            selected = next((r for r in private["recordings"] if r["recording"] == rid), None)
            recovery = "listed" if selected else "not-listed"
            completion = selected["completion"] if selected else None
        except (TypeError, AttributeError, KeyError, ValueError, RecursionError):
            recovery = "rejected"
    from installed_sinks import MAX_OUTPUT
    if type(api_limit) is not int or not 0 < api_limit <= MAX_OUTPUT:
        raise ValueError("invalid final API byte limit")
    try:
        state, final = detail.read_api(capture / "api", rid, project, api_limit, expected_request=ROOT)
        if final is not None and not detail.valid_capture(final, state):
            state, final = "rejected", None
    except (TypeError, AttributeError, KeyError, ValueError, RecursionError):
        state, final = "rejected", None
    return {"recovery": recovery, "result": completion, "finalApiRead": state, "finalApi": final}
