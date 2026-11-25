"""Recording expectations for the pinned JHipster source and unchanged baseline requests."""
from collections import Counter
from http.client import HTTPException
import json
from urllib.parse import quote

import xcamp
import xinstr

APP_PACKAGE = "io.github.jhipster.sample"
REST_PACKAGE = APP_PACKAGE + ".web.rest."
REPOSITORY_PACKAGE = APP_PACKAGE + ".repository."
SOURCE_ROOT = "src/main/java"
AUTH = "/api/authenticate"
ACCOUNT = "/api/account"
USERS = "/api/admin/users"
BANK = "/api/bank-accounts"
BANK_ID = BANK + "/{id}"
OP = "/api/operations"
OP_ID = OP + "/{id}"
LABEL = "/api/labels"
LABEL_ID = LABEL + "/{id}"


def expect(label, method, route, statuses, handler=None, *, count=1, repository=(), jdbc=(), pre_dispatch=False,
           refused_handler=None, exception=None, repository_anchor=None):
    return {"label": label, "method": method, "route": route, "statuses": statuses, "handler": handler,
            "minCount": count, "repository": repository, "jdbc": jdbc, "preDispatch": pre_dispatch,
            "refusedHandler": refused_handler, "exception": exception, "repositoryAnchor": repository_anchor}


AUTH_HANDLER = "AuthenticateController.authorize"
ACCOUNT_HANDLER = "AccountResource.getAccount"
BANK_CREATE = "BankAccountResource.createBankAccount"
BANK_READ = "BankAccountResource.getBankAccount"
BANK_UPDATE = "BankAccountResource.updateBankAccount"
# BankAccountResource.java at the campaign's pinned upstream commit imports this exact type.
BANK_ALERT = REST_PACKAGE + "errors.BadRequestAlertException"
EXCEPTION_TYPE_UNOBSERVED = "controller-exception-type-unobserved"
EXCEPTION_LINK_UNOBSERVED = "controller-exception-link-unobserved"
USER_REPO = (REPOSITORY_PACKAGE + "UserRepository.findOneWithAuthoritiesByLogin",)
BANK_REPO = (REPOSITORY_PACKAGE + "BankAccountRepository.findOneWithEagerRelationships",)
OP_REPO = (REPOSITORY_PACKAGE + "OperationRepository.findOneWithEagerRelationships",)
# The proxy sink persists Method.getDeclaringClass(). These declarations in
# Spring Data 4.1.1 identify the API call, but do not identify the proxy receiver.
CRUD = "org.springframework.data.repository.CrudRepository."
PAGE_FIND_ALL = "org.springframework.data.repository.PagingAndSortingRepository.findAll"
MANAGED_USERS = APP_PACKAGE + ".service.UserService.getAllManagedUsers"
USER_SELECT = (("select", "jhi_user"),)
BANK_INSERT = (("insert", "bank_account"),)
BANK_SELECT = (("select", "bank_account"),)


def login(label="login admin", status=200, count=1, *, cold=False):
    # UserRepository caches lookups by login. The initial attempts for each
    # seeded user are cold, but the warmed workload need not issue SQL again.
    return expect(label, "POST", AUTH, (status,), AUTH_HANDLER, count=count,
                  repository=USER_REPO, jdbc=USER_SELECT if cold else ())


EXPECT = {
    "anonymous-and-invalid-login-denied": [
        expect("GET /api/bank-accounts", "GET", BANK, (401,), pre_dispatch=True,
               refused_handler="BankAccountResource.getAllBankAccounts"),
        expect("GET /api/admin/users", "GET", USERS, (401,), pre_dispatch=True,
               refused_handler="UserResource.getAllUsers"),
        login("login invalid", 401, cold=True),
    ],
    "admin-and-user-authentication": [
        login(),
        expect("GET /api/account", "GET", ACCOUNT, (200,), ACCOUNT_HANDLER, repository=USER_REPO),
        expect("GET /api/admin/users", "GET", USERS, (200,), "UserResource.getAllUsers",
               repository=(PAGE_FIND_ALL,), repository_anchor=MANAGED_USERS, jdbc=USER_SELECT),
        login("login user", cold=True),
        expect("admin endpoint as ROLE_USER", "GET", USERS, (403,), pre_dispatch=True,
               refused_handler="UserResource.getAllUsers"),
    ],
    "account-create-read-roundtrip": [
        login(),
        expect("create account", "POST", BANK, (201,), BANK_CREATE,
               repository=(CRUD + "save",), jdbc=BANK_INSERT),
        expect("get account", "GET", BANK_ID, (200,), BANK_READ, repository=BANK_REPO, jdbc=BANK_SELECT),
    ],
    "account-validation-errors": [
        login(),
        expect("account without name", "POST", BANK, (400,), refused_handler=BANK_CREATE),
        expect("account with preset id", "POST", BANK, (400,), BANK_CREATE, exception=BANK_ALERT),
        expect("malformed json", "POST", BANK, tuple(range(400, 500)), refused_handler=BANK_CREATE),
    ],
    "account-update-and-missing": [
        login(),
        expect("update account", "PUT", BANK_ID, (200,), BANK_UPDATE,
               repository=(CRUD + "existsById", CRUD + "save"),
               jdbc=(("update", "bank_account"),)),
        expect("get updated", "GET", BANK_ID, (200,), BANK_READ, repository=BANK_REPO, jdbc=BANK_SELECT),
        expect("update missing", "PUT", BANK_ID, (400, 404), BANK_UPDATE,
               repository=(CRUD + "existsById",), jdbc=BANK_SELECT, exception=BANK_ALERT),
    ],
    "operation-with-relations": [
        login(),
        expect("create label", "POST", LABEL, (201,), "LabelResource.createLabel",
               repository=(CRUD + "save",), jdbc=(("insert", "label"),)),
        expect("create operation", "POST", OP, (201,), "OperationResource.createOperation",
               repository=(CRUD + "save",), jdbc=(("insert", "operation"), ("insert", "rel_operation__label"))),
        expect("get operation", "GET", OP_ID, (200,), "OperationResource.getOperation",
               repository=OP_REPO, jdbc=(("select", "operation"),)),
    ],
    "concurrent-isolation": [
        login(None, count=13),
        expect(None, "GET", ACCOUNT, (200,), ACCOUNT_HANDLER, count=12, repository=USER_REPO),
        expect(None, "POST", BANK, (201,), BANK_CREATE, count=12,
               repository=(CRUD + "save",), jdbc=BANK_INSERT),
        expect(None, "GET", BANK_ID, (200,), BANK_READ, count=12, repository=BANK_REPO, jdbc=BANK_SELECT),
    ],
    "delete-and-not-found": [
        login(),
        expect("delete operation", "DELETE", OP_ID, (204,), "OperationResource.deleteOperation",
               repository=(CRUD + "deleteById",), jdbc=(("delete", "operation"),)),
        expect("get deleted operation", "GET", OP_ID, (404,), "OperationResource.getOperation",
               repository=OP_REPO, jdbc=(("select", "operation"),)),
        expect("delete label", "DELETE", LABEL_ID, (204,), "LabelResource.deleteLabel",
               repository=(CRUD + "deleteById",), jdbc=(("delete", "label"),)),
        expect("get unknown account", "GET", BANK_ID, (404,), BANK_READ, repository=BANK_REPO, jdbc=BANK_SELECT),
    ],
}

PRE_DISPATCH = frozenset((sid, e["label"]) for sid, checks in EXPECT.items() for e in checks if e["preDispatch"])
LITERALS = frozenset(e["route"] for checks in EXPECT.values() for e in checks if "{" not in e["route"])


def matches_source(event, qualified):
    relative = qualified.rsplit(".", 1)[0].replace(".", "/") + ".java"
    return (xinstr.source_ok(event) and xinstr.binding_state(event) == "ok"
            and event["source"]["path"] in (relative, f"{SOURCE_ROOT}/{relative}"))

def simple_symbol(qualified):
    return ".".join(qualified.rsplit(".", 2)[-2:])


def app_frame(event, qualified):
    """A short display symbol needs the pinned source path as its identity evidence."""
    return (event.get("symbol") == qualified or
            (event.get("symbol") == simple_symbol(qualified) and matches_source(event, qualified)))


def descendants(enters, anchors):
    """Follow observed frame and event links within this recording."""
    anchors = {id(event) for event in anchors}
    by_frame = {e["frameId"]: e for e in enters if e.get("frameId")}
    by_event = {e["eventId"]: e for e in enters if e.get("eventId")}
    descendants = []
    for child in enters:
        seen = {id(child)}
        event = child
        while parent := by_frame.get(event.get("parentFrameId")) or by_event.get(event.get("parentEventId")):
            if id(parent) in seen:
                break
            if id(parent) in anchors:
                descendants.append(child)
                break
            seen.add(id(parent))
            event = parent
    return descendants


def postgres_boundary(ev):
    interaction = ev.get("interaction")
    if (str(ev.get("kind", "")).endswith("database_start") and isinstance(interaction, dict)
            and interaction.get("kind") == "interaction_kind:database"
            and interaction.get("driver") in ("pgjdbc", "postgresql")):
        return interaction
    return None


def controller_exception_problem(detail, handler, anchors, exception_type, exact_root):
    events = detail.get("events", [])
    throws = [ev for ev in events if ev.get("kind") == "recording_event_kind:frame_throw"]
    typed = [ev for ev in throws if isinstance(ev.get("exception"), dict)
             and ev["exception"].get("exceptionType") == exception_type]
    if not typed:
        return EXCEPTION_TYPE_UNOBSERVED
    if (not exact_root or detail.get("nextCursor") is not None
            or detail.get("completion") != "complete" or detail.get("incompleteEvidence")
            or any(ev.get("kind") == "recording_event_kind:gap" or ev.get("gap") is not None for ev in events)
            or len(anchors) != 1):
        return EXCEPTION_LINK_UNOBSERVED

    anchor, = anchors
    event_id = anchor.get("eventId")
    roots = [index for index, ev in enumerate(events) if ev.get("kind") == "recording_event_kind:request_update"]
    anchor_index = next(index for index, ev in enumerate(events) if ev is anchor)
    event_counts = Counter(ev["eventId"] for ev in events if isinstance(ev.get("eventId"), str))
    if (not isinstance(event_id, str) or not event_id or event_counts[event_id] != 1
            or len(roots) != 1 or roots[0] >= anchor_index
            or not xinstr.REQUEST_SYMBOL.fullmatch(events[roots[0]].get("symbol") or "")
            or anchor.get("fieldTruncations")):
        return EXCEPTION_LINK_UNOBSERVED

    # FRAME_THROW has its own event/frame identity. The adapter links it directly to the
    # throwing method's entry event, so a matching display symbol or a frame ID alone is insufficient.
    linked = [ev for ev in throws if ev.get("parentEventId") == event_id]
    if len(linked) != 1:
        return EXCEPTION_LINK_UNOBSERVED
    throwing, = linked
    throw_id = throwing.get("eventId")
    throw_frame = throwing.get("frameId")
    parent_frame = throwing.get("parentFrameId")
    anchor_frame = anchor.get("frameId")
    if (not any(ev is throwing for ev in typed)
            or not any(ev is throwing for ev in events[anchor_index + 1:])
            or not isinstance(throw_id, str) or not throw_id or event_counts[throw_id] != 1
            or throwing.get("symbol") not in (handler, simple_symbol(handler))
            or (throwing.get("source") is not None and not matches_source(throwing, handler))
            or (throw_frame is not None and throw_frame == anchor_frame)
            or (parent_frame is not None and parent_frame != anchor_frame)
            or throwing.get("asyncParentEventId") or throwing.get("asyncParentFrameId")
            or throwing.get("fieldTruncations")):
        return EXCEPTION_LINK_UNOBSERVED
    return None


def inspect(detail, rule, status, *, recording_id=None):
    """Evaluate only persisted evidence from the same recording as the route."""
    if (xinstr.detail_read_incomplete(detail)
            or (rule["exception"] and recording_id is not None and detail.get("recordingId") != recording_id)):
        return ["recording-detail-incomplete"], False, False
    problems = []
    request_roots = sum(bool(xinstr.REQUEST_SYMBOL.fullmatch(ev.get("symbol") or ""))
                        for ev in detail.get("events", []))
    exact_root = xinstr.request_info(detail) == (rule["method"], rule["route"]) and request_roots == 1
    if not exact_root:
        problems.append("exact-route-root-unobserved")
    observed_status = (xinstr.recording_http_status(detail) == status
                       and (detail.get("outcome") or {}).get("kind") == "responded")
    if not observed_status:
        problems.append("terminal-http-status-unobserved")
    if detail.get("completion") != "complete" or detail.get("incompleteEvidence"):
        problems.append("recording-incomplete")
    handler = REST_PACKAGE + rule["handler"] if rule["handler"] else None
    enters = [ev for ev in detail.get("events", []) if str(ev.get("kind", "")).endswith("frame_enter")]
    sourced = False
    anchors = []
    if handler:
        handler_frames = [ev for ev in enters if app_frame(ev, handler)]
        if not handler_frames:
            problems.append("controller-frame-unobserved")
        anchors = [ev for ev in handler_frames if matches_source(ev, handler)]
        sourced = bool(anchors)
        if not sourced:
            problems.append("controller-source-unobserved")
    if rule["refusedHandler"]:
        refused = REST_PACKAGE + rule["refusedHandler"]
        if any(app_frame(ev, refused) for ev in enters):
            problems.append("unexpected-controller-frame")
        elif any(ev.get("symbol") == simple_symbol(refused) for ev in enters):
            problems.append("refused-controller-identity-unresolved")
    if rule["exception"]:
        problem = controller_exception_problem(
            detail, handler, anchors, rule["exception"], exact_root)
        if problem:
            problems.append(problem)
    if rule["repository"]:
        scoped = descendants(enters, anchors)
        if repository_anchor := rule["repositoryAnchor"]:
            services = [ev for ev in scoped if app_frame(ev, repository_anchor) and matches_source(ev, repository_anchor)]
            scoped = descendants(scoped, services)
        for symbol in rule["repository"]:
            candidates = [ev for ev in scoped if ev.get("symbol") == symbol]
            if not candidates:
                problems.append(f"repository-declaration-unobserved-in-handler({symbol})")
            elif symbol.startswith(REPOSITORY_PACKAGE) and not any(matches_source(ev, symbol) for ev in candidates):
                problems.append(f"repository-source-unobserved({symbol})")
    if rule["jdbc"]:
        jdbc = [interaction for ev in detail.get("events", []) if (interaction := postgres_boundary(ev)) is not None]
        if not jdbc:
            problems.append("postgresql-boundary-unobserved")
        for verb, table in rule["jdbc"]:
            if not any(i.get("method") == verb and i.get("table") == table for i in jdbc):
                problems.append(f"jdbc-operation-unobserved({verb} {table})")
    elif rule["route"] == BANK and rule["method"] == "POST":
        # Argument/payload validation and idexists fail before the account repository writes.
        if any(ev.get("symbol") == CRUD + "save" for ev in enters) or any(
                i.get("table") == "bank_account" and i.get("method") in ("insert", "update")
                for ev in detail.get("events", []) if (i := postgres_boundary(ev)) is not None):
            problems.append("unexpected-bank-account-write-frame-or-interaction")
    return problems, exact_root and observed_status, exact_root and sourced


def route_matches(request, rule):
    return (request["request"]["method"] == rule["method"]
            and xinstr._path_matches(request["request"]["path"], rule["route"], LITERALS))


def serial_allocations(phase, details):
    """Match paced requests by order within exact, isolated route counts."""
    if not phase.boundary["verified"]:
        return {}
    allocated = {}
    for row in phase.boundary["routes"]:
        requests = []
        for result in phase.results:
            sid = result["id"]
            requests.extend((sid, q["label"]) for q in result["requests"]
                            if (sid, q["label"]) not in PRE_DISPATCH and route_matches(q, row))
        ids = row["recordingIds"]
        if len(requests) != len(ids) or not all(rid in details for rid in ids):
            continue
        times = [xinstr.recording_time(details[rid]) for rid in ids]
        if len(ids) > 1 and (None in times or len(set(times)) != len(ids)):
            continue
        ordered = sorted(ids, key=lambda rid: xinstr.recording_time(details[rid]))
        if len(set(requests)) == len(requests):
            allocated.update(zip(requests, ordered))
    return allocated


def pre_dispatch_recording(phase, details, rule, status):
    if not phase.boundary["verified"]:
        return None
    matches = [rid for rid in phase.boundary.get("optionalRootIds", []) if rid in details
               and xinstr.request_info(details[rid]) == (rule["method"], rule["route"])
               and xinstr.recording_http_status(details[rid]) == status]
    return matches[0] if len(matches) == 1 else None


def item(rule, problems, *, attribution, recordings=0, statuses=0, sources=0):
    return {"label": rule["label"], "method": rule["method"], "route": rule["route"],
            "expectedStatuses": list(rule["statuses"]), "attribution": attribution, "passed": not problems,
            "expectedRepositoryDeclarations": list(rule["repository"]),
            "recordingsMatchingRoute": recordings, "recordingsWithStatus": statuses,
            "recordingsWithSource": sources, "problems": problems}


def judge(details, expectations, phases, probes):
    status_ids, source_ids = set(), set()
    verdicts, groups = {}, []

    def observed(rid, rule, status):
        problems, has_status, has_source = inspect(details[rid], rule, status, recording_id=rid)
        if has_status:
            status_ids.add(rid)
        if has_source:
            source_ids.add(rid)
        return problems, int(has_status), int(has_source)

    for phase in phases:
        allocation = serial_allocations(phase, details) if phase.kind == "serial" else {}
        for result in phase.results:
            sid = result["id"]
            requests = result["requests"]
            rules = expectations[sid]
            items = []
            checked_requests = Counter()
            for rule in rules:
                group_scope = phase.kind == "burst"
                indices = [i for i, q in enumerate(requests) if route_matches(q, rule)
                           and (group_scope or q["label"] == rule["label"])]
                checked_requests.update(indices)
                expected = [requests[i] for i in indices]
                problems = []
                if len(expected) != rule["minCount"]:
                    problems.append("workload-request-count-mismatch")
                if any(q["response"]["status"] not in rule["statuses"] for q in expected):
                    problems.append("workload-http-status-mismatch")
                if group_scope:
                    row = next((r for r in phase.boundary["routes"]
                                if (r["method"], r["route"]) == (rule["method"], rule["route"])), {})
                    ids = row.get("recordingIds", [])
                    matched = [rid for rid in ids if rid in details]
                    group_problems = list(problems)
                    if not phase.boundary["verified"]:
                        group_problems.append("burst-boundary-unverified")
                    if len(matched) != rule["minCount"] or len(matched) != len(ids):
                        group_problems.append("burst-route-count-mismatch")
                    if phase.boundary["capacityDrops"]:
                        group_problems.append("burst-capacity-drops")
                    counts = Counter()
                    for rid in matched:
                        found, _, _ = observed(rid, rule, rule["statuses"][0])
                        counts.update(set(found))
                    group_problems.extend(sorted(counts))
                    groups.append({"evidenceScope": "burst-route-group", "requests": len(expected),
                                   "problemRecordings": dict(counts), **item(
                                       rule, group_problems, attribution="route-counts",
                                       recordings=len(matched), statuses=len(set(matched) & status_ids),
                                       sources=len(set(matched) & source_ids))})
                    problems.append("individual-request-and-principal-attribution-unobserved")
                    items.append(item(rule, problems, attribution="ambiguous"))
                    continue
                if rule["preDispatch"]:
                    rid = pre_dispatch_recording(phase, details, rule, expected[0]["response"]["status"]) if expected else None
                    if rid is None:
                        problems.append("pre-dispatch-servlet-root-unobserved" if expected else "pre-dispatch-request-unreached")
                        items.append(item(rule, problems, attribution="external-http-only" if expected else "unavailable"))
                        continue
                else:
                    rid = allocation.get((sid, rule["label"]))
                if not expected or rid is None:
                    problems.append("recording-attribution-unavailable")
                    items.append(item(rule, problems, attribution="unavailable"))
                    continue
                issues, status, source = observed(rid, rule, expected[0]["response"]["status"])
                items.append(item(rule, [*problems, *issues], attribution="serial-boundary-order",
                                  recordings=1, statuses=status, sources=source))
            problems = ["workload-requests-without-exact-expectations"] if (
                checked_requests != Counter(range(len(requests)))) else []
            verdicts[sid] = {"passed": bool(items) and not problems and all(i["passed"] for i in items),
                             "expectations": items, "problems": problems, "checkedRequests": len(checked_requests),
                             "recordingsAttributed": sum(i["recordingsMatchingRoute"] for i in items),
                             "frameSymbols": sorted({rule["handler"] for rule, row in zip(rules, items)
                                                     if rule["handler"] and row["recordingsWithSource"]})}
    for sid in expectations.keys() - verdicts.keys():
        verdicts[sid] = {"passed": False, "expectations": [], "problems": ["scenario-unreached"],
                         "checkedRequests": 0, "recordingsAttributed": 0, "frameSymbols": []}
    return verdicts, groups, status_ids, source_ids, judge_probes(details, phases, probes)


PROBES = (
    ("authorization", "GET", ACCOUNT, ("authorization-header",), None),
    ("cookie-query-body", "POST", AUTH, ("cookie-header", "query-token", "json-body-password"), AUTH_HANDLER),
)


def inject_probes(base, canaries):
    """Send isolated denied requests; original anonymous and JWT traffic is untouched."""
    responses = []
    for name, method, route, surfaces, _ in PROBES:
        headers = {}
        path = route
        body = None
        if name == "authorization":
            headers["Authorization"] = canaries["authorization-header"]
        else:
            headers = {"Cookie": canaries["cookie-header"], "Content-Type": "application/json"}
            path += "?xt_token=" + quote(canaries["query-token"], safe="")
            body = json.dumps({"username": "admin", "password": canaries["json-body-password"],
                               "rememberMe": False}).encode()
        try:
            response = xcamp.http_request(base, method, path, headers=headers, body=body)
            responses.append({"label": name, "status": response["status"], "surfaces": list(surfaces)})
        except (OSError, HTTPException, ValueError) as exc:
            responses.append({"label": name, "status": None, "surfaces": [], "transportError": type(exc).__name__})
    return responses


def judge_probes(details, phases, probes):
    isolated = bool(phases) and all(phase.boundary["verified"] for phase in phases)
    seen = set(phases[-1].boundary["snapshotIds"]) if isolated else set()
    by_label = {p["label"]: p for p in probes}
    verdicts = []
    for name, method, route, _, handler in PROBES:
        result = by_label.get(name, {"label": name, "status": None, "surfaces": []})
        problems = []
        if result["status"] != 401:
            problems.append("probe-denial-unobserved")
        hits = [d for rid, d in details.items() if rid not in seen and xinstr.request_info(d) == (method, route)] \
            if isolated else []
        if len(hits) != 1:
            problems.append("probe-recording-unattributed")
        else:
            problems.extend(inspect(hits[0], expect(name, method, route, (401,), handler,
                                                    refused_handler=None if handler else ACCOUNT_HANDLER), 401)[0])
        verdicts.append({**result, "recordings": len(hits), "problems": problems, "passed": not problems})
    verdicts.append({"label": "environment", "surfaces": ["env-var"] if phases else [],
                     "passed": bool(phases), "problems": [] if phases else ["application-startup-unreached"]})
    return verdicts
