"""Fineract's original workload requirements, judged only from persisted observations.

JDBC acceptance deliberately retains the existing campaign method/table policy.
An execute/executeBatch method is never guessed to be an SQL verb. Concurrency
route counts are group evidence; they cannot establish individual isolation.
"""
from collections import Counter
import base64
from http.client import HTTPException
import json
from urllib.parse import quote

import xcamp

import xinstr

APP_PACKAGE = "org.apache.fineract"
SOURCE_ROOT = "fineract-provider/src/main/java"
BASE = "/fineract-provider/api/v1"
CLIENTS = BASE + "/clients"
CLIENT = CLIENTS + "/{clientId}"
OFFICES = BASE + "/offices"
OFFICE = OFFICES + "/{officeId}"
CLIENT_RESOURCE = APP_PACKAGE + ".portfolio.client.api.ClientsApiResource."
OFFICE_RESOURCE = APP_PACKAGE + ".organisation.office.api.OfficesApiResource."
COMMAND = "PortfolioCommandSourceWritePlatformService.logCommandSource"


def expect(label, method, route, statuses, handler=None, *, count=1, jdbc=(), command=False,
           exception=None, pre_dispatch=False):
    return dict(label=label, method=method, route=route, statuses=statuses, handler=handler,
                minCount=count, jdbc=jdbc, command=command, exception=exception, preDispatch=pre_dispatch,
                mapper=not pre_dispatch and any(status >= 400 for status in statuses))


def client(label, method, statuses, handler, *, collection=False, **kw):
    return expect(label, method, CLIENTS if collection else CLIENT, statuses, CLIENT_RESOURCE + handler, **kw)


READ = (("select", "m_client"),)
CREATE = (("insert", "m_client"),)
EXPECT = {
    "denied-without-valid-credentials": [
        expect("anonymous clients", "GET", CLIENTS, (401,), pre_dispatch=True),
        expect("invalid credentials", "GET", CLIENTS, (401,), pre_dispatch=True),
        expect("anonymous create", "POST", CLIENTS, (401,), pre_dispatch=True),
    ],
    "authenticated-seed-read": [
        expect("GET " + OFFICES, "GET", OFFICES, (200,), OFFICE_RESOURCE + "retrieveOffices", jdbc=(("select", "m_office"),)),
        expect("GET " + OFFICES + "/1", "GET", OFFICE, (200,), OFFICE_RESOURCE + "retrieveOffice", jdbc=(("select", "m_office"),)),
        client("client list (empty tenant)", "GET", (200,), "retrieveAll", collection=True, jdbc=READ),
    ],
    "client-create-read-roundtrip": [
        client("create client", "POST", (200,), "create", collection=True, command=True, jdbc=CREATE),
        client("read client", "GET", (200,), "retrieveOne", jdbc=READ),
    ],
    "client-validation-errors": [
        client("missing names", "POST", (400,), "create", collection=True,
               exception="PlatformApiDataValidationException"),
        client("unknown office", "POST", tuple(range(400, 500)), "create", collection=True),
        # Malformed JSON may be refused before the resource method; no handler is invented.
        expect("malformed json", "POST", CLIENTS, tuple(range(400, 500))),
    ],
    "client-update": [
        client("update client", "PUT", (200,), "update", command=True, jdbc=(("update", "m_client"),)),
        client("read updated", "GET", (200,), "retrieveOne", jdbc=READ),
    ],
    "client-activate-command": [
        client("activate client", "POST", (200,), "activate", command=True, jdbc=(("update", "m_client"),)),
        client("read activated", "GET", (200,), "retrieveOne", jdbc=READ),
        client("activate twice", "POST", tuple(range(400, 500)), "activate", command=True),
    ],
    "concurrent-isolation": [
        client(None, "POST", (200,), "create", collection=True, count=12, command=True, jdbc=CREATE),
        client(None, "GET", (200,), "retrieveOne", count=12, jdbc=READ),
        expect(None, "GET", OFFICE, (200,), OFFICE_RESOURCE + "retrieveOffice", count=16, jdbc=(("select", "m_office"),)),
    ],
    "delete-and-not-found": [
        client("create doomed client", "POST", (200,), "create", collection=True, command=True, jdbc=CREATE),
        client("delete client", "DELETE", (200,), "delete", command=True, jdbc=(("delete", "m_client"),)),
        client("read deleted client", "GET", (404,), "retrieveOne", jdbc=READ),
        client("read unknown client", "GET", (404,), "retrieveOne", jdbc=READ),
        client("delete active client", "DELETE", tuple(range(400, 500)), "delete", command=True),
    ],
}
PRE_DISPATCH = frozenset((sid, row["label"]) for sid, rows in EXPECT.items() for row in rows if row["preDispatch"])
LITERALS = frozenset(row["route"] for rows in EXPECT.values() for row in rows if "{" not in row["route"])


def matches(request, rule):
    return request["request"]["method"] == rule["method"] and xinstr._path_matches(
        request["request"]["path"], rule["route"], LITERALS)


def source_matches(event, qualified):
    relative = qualified.rsplit(".", 1)[0].replace(".", "/") + ".java"
    return (xinstr.source_ok(event) and xinstr.binding_state(event) == "ok"
            and (event["source"]["path"] == relative or event["source"]["path"].endswith("/" + relative)))


def symbol_matches(event, qualified):
    return event.get("symbol") == qualified or (
        event.get("symbol") == ".".join(qualified.rsplit(".", 2)[-2:]) and source_matches(event, qualified))


def descendants(events, anchors):
    """Require recorded parent links; adjacency never establishes command ownership."""
    anchors = {id(event) for event in anchors}
    by_frame = {e["frameId"]: e for e in events if e.get("frameId")}
    by_event = {e["eventId"]: e for e in events if e.get("eventId")}
    children = []
    for child in events:
        seen, parent = {id(child)}, child
        while parent := by_frame.get(parent.get("parentFrameId")) or by_event.get(parent.get("parentEventId")):
            if id(parent) in seen:
                break
            if id(parent) in anchors:
                children.append(child)
                break
            seen.add(id(parent))
    return children


def enters_from(events):
    return [e for e in events if str(e.get("kind", "")).endswith("frame_enter")]


def inspect(detail, rule, status):
    if xinstr.detail_read_incomplete(detail):
        return ["recording-detail-incomplete"], False, False
    events = detail.get("events", [])
    problems = []
    root = xinstr.request_info(detail) == (rule["method"], rule["route"]) and sum(
        bool(xinstr.REQUEST_SYMBOL.fullmatch(e.get("symbol") or "")) for e in events) == 1
    if not any(e.get("symbol") in ("jakarta.servlet.http.HttpServlet.service", "javax.servlet.http.HttpServlet.service") for e in enters_from(events)):
        problems.append("servlet-invocation-seam-unobserved")
    if not root:
        problems.append("exact-route-root-unobserved")
    has_status = (xinstr.recording_http_status(detail) == status
                  and (detail.get("outcome") or {}).get("kind") == "responded")
    if not has_status:
        problems.append("terminal-http-status-unobserved")
    if detail.get("completion") != "complete" or detail.get("incompleteEvidence"):
        problems.append("recording-incomplete")
    enters = [e for e in events if str(e.get("kind", "")).endswith("frame_enter")]
    handler = rule["handler"]
    has_source = False
    frames = []
    if handler:
        frames = [e for e in enters if symbol_matches(e, handler)]
        if not frames:
            problems.append("jersey-resource-method-unobserved")
        has_source = any(source_matches(e, handler) for e in frames)
        if not has_source:
            problems.append("resource-source-unobserved")
        # A resource frame alone does not prove the exact ADR 0005 invocation seam.
        if not any(e.get("symbol") == "org.glassfish.jersey.server.model.ResourceMethodInvoker.apply" for e in enters):
            problems.append("jersey-invocation-seam-unobserved")
    if rule["preDispatch"] and any(str(e.get("symbol", "")).startswith(CLIENT_RESOURCE) for e in enters):
        problems.append("unexpected-resource-on-denial")
    scoped = descendants(enters, frames)
    if rule["command"] and not any(
            str(e.get("symbol", "")).endswith(COMMAND) and xinstr.source_ok(e)
            and xinstr.binding_state(e) == "ok" for e in scoped):
        problems.append("command-pipeline-unobserved")
    if handler == CLIENT_RESOURCE + "create" and rule["command"] and not any(
            str(e.get("symbol", "")).endswith("ClientWritePlatformService.createClient")
            and xinstr.source_ok(e) and xinstr.binding_state(e) == "ok" for e in scoped):
        problems.append("client-write-service-unobserved")
    if rule["mapper"] and not any(
            "ExceptionMapper" in str(e.get("symbol", "")) and str(e.get("symbol", "")).endswith(".toResponse")
            for e in enters):
        problems.append("jersey-exception-mapper-unobserved")
    if rule["exception"] and not any(
            str(e.get("kind", "")).endswith("frame_throw")
            and ((e.get("exception") or {}).get("exceptionType") or "").rsplit(".", 1)[-1] == rule["exception"] for e in events):
        problems.append("exception-type-unobserved")
    jdbc = [e["interaction"] for e in events if str(e.get("kind", "")).endswith("database_start")
            and isinstance(e.get("interaction"), dict)
            and e["interaction"].get("kind") == "interaction_kind:database"
            and e["interaction"].get("driver") in ("pgjdbc", "postgresql")]
    if rule["jdbc"] and not jdbc:
        problems.append("pgjdbc-boundary-unobserved")
    for verb, table in rule["jdbc"]:
        if not any(row.get("method") == verb and row.get("table") == table for row in jdbc):
            problems.append("required-sql-operation-unobserved")
    return sorted(set(problems)), root and has_status, root and has_source


def allocations(phase, details):
    allocated = {}
    if not phase.boundary["verified"]:
        return allocated
    # Include observed optional denial roots, but never use a missing denial to
    # repair recordable-route loss. Tied times or route-count differences refuse attribution.
    ids = [*phase.boundary["recordingIds"], *phase.boundary.get("optionalRootIds", [])]
    requests = [(result["id"], q) for result in phase.results for q in result["requests"]]
    shapes = {(q["request"]["method"], row["route"]) for _, q in requests
              for rows in EXPECT.values() for row in rows if matches(q, row)}
    for method, route in shapes:
        rule = dict(method=method, route=route)
        sent = [(sid, q["label"]) for sid, q in requests if matches(q, rule)]
        recorded = list(dict.fromkeys(rid for rid in ids if rid in details
                                     and xinstr.request_info(details[rid]) == (method, route)))
        times = [xinstr.recording_time(details[rid]) for rid in recorded]
        if len(sent) == len(recorded) and (len(times) == 1 or None not in times and len(set(times)) == len(times)):
            allocated.update(zip(sent, sorted(recorded, key=lambda rid: xinstr.recording_time(details[rid]))))
    return allocated


def judge(details, expectations, phases, probes):
    verdicts, groups, statuses, sources = {}, [], set(), set()
    for phase in phases:
        allocated = allocations(phase, details) if phase.kind == "serial" else {}
        for result in phase.results:
            items, covered = [], Counter()
            for rule in expectations[result["id"]]:
                sent = [(i, q) for i, q in enumerate(result["requests"]) if matches(q, rule)
                        and (phase.kind == "burst" or q["label"] == rule["label"])]
                covered.update(i for i, _ in sent)
                problems = []
                if len(sent) != rule["minCount"]:
                    problems.append("workload-request-count-mismatch")
                if any(q["response"]["status"] not in rule["statuses"] for _, q in sent):
                    problems.append("workload-http-status-mismatch")
                ids = []
                if phase.kind == "serial":
                    rid = allocated.get((result["id"], rule["label"]))
                    if rid is not None:
                        ids = [rid]
                    else:
                        problems.append("recording-attribution-unavailable")
                else:
                    row = next((r for r in phase.boundary["routes"] if (r["method"], r["route"]) ==
                                (rule["method"], rule["route"])), {})
                    ids = [rid for rid in row.get("recordingIds", []) if rid in details]
                    if not phase.boundary["verified"]:
                        problems.append("burst-boundary-unverified")
                    if len(ids) != rule["minCount"]:
                        problems.append("burst-route-count-mismatch")
                for rid in ids:
                    wanted = sent[0][1]["response"]["status"] if phase.kind == "serial" and sent else rule["statuses"][0]
                    found, status, source = inspect(details[rid], rule, wanted)
                    problems.extend(found)
                    if status:
                        statuses.add(rid)
                    if source:
                        sources.add(rid)
                item = {"label": rule["label"], "method": rule["method"], "route": rule["route"],
                        "recordingsMatchingRoute": len(ids), "recordingsWithStatus": len(set(ids) & statuses),
                        "recordingsWithSource": len(set(ids) & sources), "problems": sorted(set(problems)),
                        "passed": bool(ids) and not problems}
                if phase.kind == "burst":
                    groups.append({**item, "evidenceScope": "burst-route-group"})
                    item = {**item, "passed": False, "problems": [*item["problems"], "individual-isolation-unobserved"]}
                items.append(item)
            problems = [] if covered == Counter(range(len(result["requests"]))) else ["workload-expectation-coverage-mismatch"]
            verdicts[result["id"]] = dict(passed=bool(items) and not problems and all(i["passed"] for i in items),
                                           expectations=items, problems=problems, frameSymbols=[])
    for sid in expectations.keys() - verdicts.keys():
        verdicts[sid] = dict(passed=False, expectations=[], problems=["scenario-unreached"], frameSymbols=[])
    return verdicts, groups, statuses, sources, judge_probes(details, phases, probes)


PROBES = (
    ("authorization", "GET", CLIENTS, ("authorization-header",)),
    ("cookie-query-body", "POST", CLIENTS, ("cookie-header", "query-token", "json-body-password")),
    ("authenticated-read", "GET", OFFICES, ("cookie-header", "query-token")),
    ("authenticated-validation", "POST", CLIENTS, ("json-body-password",)),
)
PROBE_STATUSES = {"authorization": 401, "cookie-query-body": 401,
                  "authenticated-read": 200, "authenticated-validation": 400}
RECORDABLE_PROBES = frozenset(("authenticated-read", "authenticated-validation"))


def inject_probes(base, canaries):
    """Add isolated denied and authenticated probes after the unchanged workloads.

    The authenticated validation payload has no names, so it cannot create a
    client. The response must prove that it reached normal request processing;
    any different status or missing recording remains a failed probe.
    """
    responses = []
    for name, method, route, surfaces in PROBES:
        headers = {"Fineract-Platform-TenantId": "default"}
        body, path = None, route
        if name == "authorization":
            headers["Authorization"] = canaries["authorization-header"]
        elif name == "cookie-query-body":
            headers.update(Cookie=canaries["cookie-header"], **{"Content-Type": "application/json"})
            path += "?xt_token=" + quote(canaries["query-token"], safe="")
            body = json.dumps({"password": canaries["json-body-password"]}).encode()
        else:
            # Documented upstream demo credentials, independent of the synthetic
            # invalid Authorization canary. Never retain either header value.
            headers["Authorization"] = "Basic " + base64.b64encode(b"mifos:password").decode()
            if name == "authenticated-read":
                headers["Cookie"] = canaries["cookie-header"]
                path += "?xt_token=" + quote(canaries["query-token"], safe="")
            else:
                headers["Content-Type"] = "application/json"
                body = json.dumps({"officeId": 1, "active": False,
                                   "password": canaries["json-body-password"]}).encode()
        try:
            response = xcamp.http_request(base, method, path, headers=headers, body=body)
            responses.append(dict(label=name, status=response["status"], surfaces=list(surfaces)))
        except (OSError, HTTPException, ValueError) as exc:
            responses.append(dict(label=name, status=None, surfaces=[], transportError=type(exc).__name__))
    # This hook is reached only after Stack.up reported a healthy instrumented child.
    responses.append(dict(label="environment", status=None, surfaces=["env-var"]))
    return responses


def judge_probes(details, phases, probes):
    isolated = bool(phases) and all(phase.boundary["verified"] for phase in phases)
    before = set(phases[-1].boundary["snapshotIds"]) if isolated else set()
    by_label = {name: [p for p in probes if isinstance(p, dict) and p.get("label") == name]
                for name, *_ in PROBES}
    output = []
    for name, method, route, surfaces in PROBES:
        rows = by_label[name]
        probe = rows[0] if len(rows) == 1 else dict(label=name, status=None, surfaces=[])
        expected_status = PROBE_STATUSES[name]
        problems = []
        if probe.get("status") != expected_status or probe.get("surfaces") != list(surfaces):
            problems.append("probe-delivery-unobserved")
        hits = [detail for rid, detail in details.items() if rid not in before
                and xinstr.request_info(detail) == (method, route)
                and xinstr.recording_http_status(detail) == expected_status] if isolated else []
        if len(hits) != 1:
            problems.append("probe-recording-attribution-unavailable")
        else:
            handler = (OFFICE_RESOURCE + "retrieveOffices" if name == "authenticated-read" else
                       CLIENT_RESOURCE + "create" if name == "authenticated-validation" else None)
            problems.extend(inspect(hits[0], expect(name, method, route, (expected_status,), handler,
                                                   pre_dispatch=name not in RECORDABLE_PROBES), expected_status)[0])
        output.append(dict(**probe, recordings=len(hits), recordingScope=("authenticated-resource" if name in RECORDABLE_PROBES
                           else "pre-dispatch-only"), problems=sorted(set(problems)), passed=not problems))
    environment = [p for p in probes if isinstance(p, dict) and p.get("label") == "environment"]
    delivered = len(environment) == 1 and environment[0].get("surfaces") == ["env-var"]
    output.append(dict(label="environment", status=None, surfaces=["env-var"] if delivered else [],
                       passed=delivered, problems=[] if delivered else ["environment-delivery-unobserved"]))
    return output
