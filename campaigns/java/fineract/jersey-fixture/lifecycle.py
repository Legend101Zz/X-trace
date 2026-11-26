"""One ordinary mapped read, observed before release, live terminal and owned stop."""
import http.client
import threading
import time
import uuid

from observation import APPLY, SERVICE, LIFECYCLE, api_reader, cli_reader
from pages import checked_detail_pages, decimal, detail_pages, list_pages, name, valid_id
from verify_fixture import require


def snapshot(read, api, project_id, rid):
    ids, _ = list_pages(lambda cursor: read(None, cursor), api, project_id)
    require(rid in ids, "lifecycle recording missing")
    _, count, first, last = ids[rid]
    return detail_pages(lambda cursor: read(rid, cursor), api, project_id, rid, count, (first, last))[0]


def paired(cli, api, project_id, rid):
    observed = snapshot(api, True, project_id, rid)
    raw = snapshot(cli, False, project_id, rid)
    for field in ("status", "completion", "outcome", "capacity", "duration_ns", "drop_counts_by_priority",
                  "incomplete_evidence"):
        require(raw[field] == observed[name(field, True)], "lifecycle CLI API terminal parity")
    for left, right in zip(raw["events"], observed["events"], strict=True):
        for field in ("sequence", "event_id", "frame_id", "parent_event_id", "monotonic_ns", "kind", "symbol",
                      "interaction"):
            require(left[field] == right[name(field, True)], "lifecycle CLI API event parity")
    return observed


def finite(detail):
    responses = sum(e["kind"] == "recording_event_kind:response" for e in detail["events"])
    gaps = sum(e["kind"] == "recording_event_kind:gap" for e in detail["events"])
    drops = detail["dropCountsByPriority"]
    require(isinstance(drops, dict), "lifecycle drop inventory")
    positive = sum(decimal(value) > 0 for value in drops.values())
    outcome = detail["outcome"]
    require(outcome is None or isinstance(outcome, dict), "lifecycle outcome shape")
    require(detail["status"] in {"recording", "finalizing", "complete", "partial", "invalid"}
            and detail["completion"] in {"unavailable", "complete", "partial", "invalid"}, "lifecycle terminal enums")
    require(outcome is None or outcome.get("kind") in {"responded", "exception_propagated", "client_aborted", "unobserved"},
            "lifecycle outcome enum")
    if detail["durationNs"] is not None:
        decimal(detail["durationNs"])
    return {"status": detail["status"], "completion": detail["completion"], "events": len(detail["events"]),
            "responses": responses, "gaps": gaps, "positiveDropBuckets": positive,
            "durationPresent": detail["durationNs"] is not None,
            "outcome": "unavailable" if outcome is None else outcome.get("kind"),
            "capacityPresent": detail["capacity"] is not None}


def resource_enter_observed(read, project_id, rid):
    # While the handler is blocked, earlier events may still be arriving. Discover the
    # actual resource entry using validated pages before binding a stationary full read.
    pages = checked_detail_pages(lambda cursor: read(rid, cursor), True, project_id, rid)
    for page in pages:
        require(page["completion"] == "unavailable" and page["outcome"] is None,
                "lifecycle closed before release")
        if any(event["kind"] == "recording_event_kind:frame_enter" and event["symbol"] == "Items.lifecycle"
               for event in page["events"]):
            return True
    return False


def require_preserved_prefix(prefix, terminal):
    require(len(prefix) <= len(terminal), "lifecycle prefix shortened")
    indexed_fields = ("frameId", "parentFrameId", "asyncParentFrameId", "depth")
    derived = {*indexed_fields, "navigation"}
    for before, after in zip(prefix, terminal):
        # The sealed segment supplies frame metadata that the open journal can lack.
        # Never overwrite a previously observed value. Navigation is recomputed at read time.
        for field in indexed_fields:
            old, new = before[field], after[field]
            for value in (old, new):
                if value is not None:
                    valid = type(value) is int and value >= 0 if field == "depth" else (
                        valid_id(value) and uuid.UUID(value).version == 7)
                    require(valid, "lifecycle frame index metadata")
            require(old is None or old == new, "lifecycle indexed fact changed")
        require(isinstance(before["navigation"], dict) and isinstance(after["navigation"], dict),
                "lifecycle event navigation missing")
        require({k: v for k, v in before.items() if k not in derived}
                == {k: v for k, v in after.items() if k not in derived}, "lifecycle recorded event changed")


def require_prefix_links(frames):
    chain = [frames[symbol] for symbol in (SERVICE, APPLY, "Items.lifecycle")]
    ids = [frame["eventId"] for frame in chain]
    require(all(isinstance(value, str) and value for value in ids) and len(set(ids)) == len(ids)
            and chain[1]["parentEventId"] == ids[0] and chain[2]["parentEventId"] == ids[1],
            "lifecycle actual application prefix linkage")


def require_on_time(deadline):
    require(time.monotonic() < deadline, "lifecycle observation deadline")


def observe(proc, control, canaries, project_id, client, cli, project, env, progress):
    # All HTTP and live observation work shares the existing 15-second request budget.
    deadline = time.monotonic() + 15
    client.deadline = deadline
    api = api_reader(client, canaries)
    read_cli = cli_reader(cli, project, env, canaries, deadline=deadline)
    while True:
        require(proc.poll() is None and time.monotonic() < deadline, "lifecycle baseline deadline or launcher exit")
        baseline, _ = list_pages(lambda cursor: api(None, cursor), True, project_id)
        require(len(baseline) <= 4, "lifecycle baseline inventory")
        if len(baseline) == 4 and all(api(rid, None)["completion"] != "unavailable" for rid in baseline):
            break
        threading.Event().wait(min(0.05, max(0, deadline - time.monotonic())))
    connection = http.client.HTTPConnection("127.0.0.1", int((control / "port").read_text()),
                                            timeout=max(0.001, deadline - time.monotonic()))
    result = {}

    def request():
        try:
            connection.connect()
            wire = connection.sock
            wire.settimeout(max(0.001, deadline - time.monotonic()))
            connection.request("GET", f"/scope/effective/groups/{canaries[0]}/lifecycle?q={canaries[1]}",
                               headers={"X-Fixture-Marker": canaries[2]})
            wire.settimeout(max(0.001, deadline - time.monotonic()))
            response = connection.getresponse()
            wire.settimeout(max(0.001, deadline - time.monotonic()))
            body = response.read(65537)
            require(response.status == 200 and body == b"released", "lifecycle normal HTTP response")
            result["passed"] = True
        except Exception as error:
            result["error"] = error
        finally:
            connection.close()

    worker = threading.Thread(target=request, name="fixture-mapped-read")
    worker.start()
    try:
        progress["phase"] = "lifecycle-live-prefix"
        while True:
            require(proc.poll() is None and time.monotonic() < deadline, "lifecycle prefix deadline or launcher exit")
            if "error" in result:
                raise result["error"]
            ids, _ = list_pages(lambda cursor: api(None, cursor), True, project_id)
            added = ids.keys() - baseline.keys()
            require(len(added) <= 1, "unexpected lifecycle recording inventory")
            if added and (control / "entered").is_file():
                rid = next(iter(added))
                if resource_enter_observed(api, project_id, rid):
                    prefix = paired(read_cli, api, project_id, rid)
                    break
            threading.Event().wait(min(0.05, max(0, deadline - time.monotonic())))
        roots = [e for e in prefix["events"] if e["kind"] == "recording_event_kind:request_update"]
        require(len(roots) == 1 and roots[0]["symbol"] == "http.request GET " + LIFECYCLE
                and roots[0]["interaction"]["driver"] == "jersey", "lifecycle actual mapped request")
        for symbol in (SERVICE, APPLY, "Items.lifecycle"):
            require(sum(e["kind"] == "recording_event_kind:frame_enter" and e["symbol"] == symbol
                        for e in prefix["events"]) == 1, "lifecycle unique executed frame")
        frames = {e["symbol"]: e for e in prefix["events"] if e["kind"] == "recording_event_kind:frame_enter"}
        require_prefix_links(frames)
        report = finite(prefix)
        progress["lifecycle"] = {"prefix": report}
        require(report["status"] in {"recording", "finalizing"} and report["completion"] == "unavailable"
                and not report["responses"] and not report["durationPresent"] and not report["capacityPresent"]
                and prefix["outcome"] is None, "lifecycle open prefix evidence")
        require_on_time(deadline)
        (control / "release").touch(exist_ok=False)
        worker.join(max(0, deadline - time.monotonic()))
        require(not worker.is_alive(), "lifecycle HTTP deadline")
        if "error" in result:
            raise result["error"]
        require(result.get("passed") is True, "lifecycle HTTP result missing")
        progress["responsesVerified"] += 1
        progress["phase"] = "lifecycle-live-terminal"
        while True:
            require(proc.poll() is None and time.monotonic() < deadline, "lifecycle terminal deadline or launcher exit")
            candidate = api(rid, None)
            if candidate["completion"] != "unavailable":
                terminal = paired(read_cli, api, project_id, rid)
                break
            threading.Event().wait(min(0.05, max(0, deadline - time.monotonic())))
        report = finite(terminal)
        progress["lifecycle"]["liveTerminal"] = report
        require(report["status"] == report["completion"] == "complete" and report["responses"] == 1
                and not report["gaps"] and not report["positiveDropBuckets"] and report["durationPresent"]
                and report["outcome"] == "responded" and terminal["outcome"]["httpStatus"] == 200
                and not terminal["incompleteEvidence"], "lifecycle live complete response")
        responses = [e for e in terminal["events"] if e["kind"] == "recording_event_kind:response"]
        require(responses[0]["interaction"]["driver"] == "jersey", "lifecycle live response provenance")
        require_preserved_prefix(prefix["events"], terminal["events"])
        require(proc.poll() is None, "lifecycle terminal appeared after launcher exit")
        require_on_time(deadline)
        return rid, terminal
    finally:
        # Release only this request's barrier, even when observation failed. No new request is sent.
        (control / "release").touch(exist_ok=True)
        worker.join(max(0, deadline - time.monotonic()))
        client.deadline = None


def after_stop(live, details, progress):
    rid, before = live
    require(rid in details, "lifecycle identity absent after owned stop")
    after = details[rid]
    for field in ("status", "completion", "outcome", "capacity", "durationNs", "dropCountsByPriority",
                  "incompleteEvidence", "events"):
        require(before[field] == after[field], "lifecycle evidence changed after owned stop")
    progress["lifecycle"]["afterStop"] = finite(after)
