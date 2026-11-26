"""Check a complete authenticated fixture read against the same installed CLI event pages."""
import json
import subprocess
import time

from urllib.parse import urlencode

from pages import DETAIL_LIMIT, LIST_LIMIT, detail_pages, list_pages
from verify_fixture import require

SERVICE = "org.glassfish.jersey.servlet.ServletContainer.service"
APPLY = "org.glassfish.jersey.server.model.ResourceMethodInvoker.apply"
ITEM = "/scope/effective/groups/{group}/items/{id}"
LIFECYCLE = "/scope/effective/groups/{group}/lifecycle"
DEFERRED = "/scope/effective/groups/{group}/deferred"


def cli_reader(cli, project, env, canaries, *, deadline=None):
    def read(rid, cursor):
        args = ["list"] if rid is None else ["show", rid]
        args += ["--project-dir", str(project), "--limit", str(LIST_LIMIT if rid is None else DETAIL_LIMIT)]
        if cursor is not None:
            args += ["--after" if rid is None else "--cursor", cursor]
        remaining = 60 if deadline is None else deadline - time.monotonic()
        require(remaining > 0, "fixture CLI read deadline")
        result = subprocess.run([cli, "recording", *args], env=env, capture_output=True, check=True, timeout=min(60, remaining))
        require(all(c.encode() not in result.stdout for c in canaries), "fixture input visible in CLI")
        return json.loads(result.stdout)
    return read


def api_reader(client, canaries):
    def read(rid, cursor):
        path = "/api/v1/recordings" if rid is None else "/api/v1/recordings/" + rid
        query = {"limit": LIST_LIMIT if rid is None else DETAIL_LIMIT}
        if cursor is not None:
            query["after" if rid is None else "cursor"] = cursor
        status, doc = client.get(path + "?" + urlencode(query))
        require(status == 200 and isinstance(doc, dict), "viewer read failed")
        rendered = json.dumps(doc)
        require(all(c not in rendered for c in canaries), "fixture input visible in viewer API")
        return doc
    return read


def compare_inventory(cli, api, project_id, supported):
    cli_ids, cli_lists = list_pages(lambda after: cli(None, after), False, project_id)
    api_ids, api_lists = list_pages(lambda after: api(None, after), True, project_id)
    expected = 5 if supported else 1
    require(list(cli_ids.items()) == list(api_ids.items()) and len(api_ids) == expected
            and cli_lists == api_lists == expected, "installed recording list inventory")
    details, count, matched_pages = {}, 0, (0, 0)
    for rid, (_, event_count, first_sequence, last_sequence) in api_ids.items():
        listed_range = (first_sequence, last_sequence)
        raw, cli_pages = detail_pages(lambda cursor: cli(rid, cursor), False, project_id, rid, event_count, listed_range)
        detail, api_pages = detail_pages(lambda cursor: api(rid, cursor), True, project_id, rid, event_count, listed_range)
        require(api_pages == cli_pages and raw["outcome"] == detail["outcome"]
                and raw["completion"] == detail["completion"] and raw["incomplete_evidence"] == detail["incompleteEvidence"],
                "CLI and API completion parity")
        for event, observed in zip(raw["events"], detail["events"], strict=True):
            for src, dest in (("sequence", "sequence"), ("event_id", "eventId"), ("frame_id", "frameId"),
                              ("parent_event_id", "parentEventId"), ("monotonic_ns", "monotonicNs"),
                              ("kind", "kind"), ("symbol", "symbol"), ("interaction", "interaction")):
                require(event[src] == observed[dest], "CLI event parity")
            count += 1
            if observed["kind"] == "recording_event_kind:request_update" and observed["symbol"] == "http.request GET " + ITEM:
                matched_pages = (api_pages, cli_pages)
        details[rid] = detail
    require(min(matched_pages) >= 2 if supported else matched_pages == (0, 0), "mapped GET multipage evidence")
    counts = {"comparedEvents": count, "apiListPages": api_lists, "cliListPages": cli_lists,
              "mappedApiDetailPages": matched_pages[0], "mappedCliDetailPages": matched_pages[1]}
    return details, counts


class OutcomeMismatch(ValueError):
    """Carry only the fixed comparison that failed. Exclude exception and event payloads."""

    def __init__(self, request_class, expected_kind, expected_status, kind, status):
        super().__init__("HTTP outcome evidence")
        kinds = ("responded", "exception_propagated", "client_aborted", "unobserved")
        self.evidence = {"requestClass": request_class, "expectedKind": expected_kind,
                         "expectedStatus": expected_status,
                         "observedKind": kind if kind in kinds else "unavailable",
                         "observedStatus": status if status is None or type(status) is int and 100 <= status <= 599
                         else "unavailable"}


def judge(details, version):
    supported = version == "3.1.11"
    expected = {"http.request GET": (403, None, "filter-refusal")}
    if supported:
        expected.update({f"http.request GET {ITEM}": (200, "read", "mapped-read"),
                         f"http.request GET {LIFECYCLE}": (200, "lifecycle", "mapped-read-lifecycle"),
                         f"http.request POST {ITEM}": (404, None, "conversion"),
                         f"http.request GET {DEFERRED}": (None, "deferred", "deferred")})
    observed = set()
    for detail in details.values():
        events = detail["events"]
        roots = [e for e in events if e["kind"] == "recording_event_kind:request_update"]
        require(len(roots) == 1, "one request identity per recording")
        symbol = roots[0]["symbol"]
        require(symbol in expected and symbol not in observed, "unexpected or duplicate recording")
        observed.add(symbol)
        status, method, request_class = expected[symbol]
        route = symbol != "http.request GET"
        driver = "jersey" if route else "servlet"
        require(roots[0]["interaction"]["driver"] == driver, "request framework provenance")
        responses = [e for e in events if e["kind"] == "recording_event_kind:response"]
        require(len(responses) == 1 and responses[0]["interaction"]["driver"] == driver, "response provenance")
        outcome = detail["outcome"] if isinstance(detail["outcome"], dict) else {}
        expected_kind = "responded" if status else "unobserved"
        kind, recorded_status = outcome.get("kind"), outcome.get("httpStatus", "unavailable")
        if kind != expected_kind or type(recorded_status) is not type(status) or recorded_status != status:
            raise OutcomeMismatch(request_class, expected_kind, status, kind, recorded_status)
        require(detail["completion"] == "complete" and not detail["incompleteEvidence"], "capture completion")
        enters = [e for e in events if e["kind"] == "recording_event_kind:frame_enter"]
        services = [e for e in enters if e["symbol"] == SERVICE]
        invokers = [e for e in enters if e["symbol"] == APPLY]
        resources = [e for e in enters if e["symbol"] in {"Items.read", "Items.convert", "Items.deferred", "Items.context", "Items.lifecycle"}]
        require(len(services) == len(invokers) == int(route), "executed Jersey entry inventory")
        require(not any(e["symbol"] in {"jakarta.servlet.http.HttpServlet.service", "javax.servlet.http.HttpServlet.service"}
                        for e in enters), "unexecuted parent service recorded")
        require([e["symbol"] for e in resources] == (["Items." + method] if method else []),
                "executed resource inventory")
        if route:
            require(services[0]["eventId"] and invokers[0]["eventId"]
                    and invokers[0]["parentEventId"] == services[0]["eventId"]
                    and int(services[0]["monotonicNs"]) <= int(invokers[0]["monotonicNs"]),
                    "observed service to invoker parent")
            require(all(e["source"] is None for e in (services[0], invokers[0])), "invented framework source")
            for frame in resources:
                require(frame["parentEventId"] == invokers[0]["eventId"], "observed invoker to resource parent")
                source = frame.get("source") or {}
                require(source.get("status") == "matched" and source.get("path", "").endswith("fixture/jersey/Items.java")
                        and frame["sourceBinding"] in {"verified", "observed_unattested"}, "fixture resource source")
    require(observed == expected.keys(), "required recording inventory")
    return len(observed)
