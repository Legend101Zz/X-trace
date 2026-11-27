#!/usr/bin/env python3
"""JHipster sample app campaign harness (baseline + instrumented/overhead/flows). See petclinic/harness/run.py for usage."""
import concurrent.futures
import json
import os
import pathlib
import re
import shlex
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "lib"))
import xcamp  # noqa: E402
import xinstr  # noqa: E402

CAMP, PROJ, SRC = xcamp.load_campaign(__file__)
HERE = pathlib.Path(__file__).resolve()
JAR = SRC / CAMP["build"]["artifact"]
IMAGE = CAMP["runtime"]["buildImage"]
# Synthetic, campaign-only signing secret (64 bytes, base64) - never an upstream or real secret.
JWT_SECRET = "eHRyYWNlLWNhbXBhaWduLXN5bnRoZXRpYy1qd3Qtc2VjcmV0LW5vdC1mb3ItcHJvZHVjdGlvbi11c2UtMDEyMzQ1Njc4OWFiY2RlZg=="


def build() -> int:
    xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"])
    xcamp.docker("volume", "create", "xtrace-camp-m2")
    rc = xcamp.docker_build("jhipster", SRC, IMAGE, CAMP["build"]["command"],
                            {"xtrace-camp-m2": "/root/.m2"}, PROJ / "work" / "build.log", mem="4g")
    if rc == 0:
        print("jar sha256", xcamp.sha256_file(JAR))
    return rc


def make_stack(run_id: str) -> xcamp.Stack:
    return xcamp.Stack(
        project="jhipster", jdk_image=IMAGE, jar=JAR, run_id=run_id, app_port=8080,
        # Prod suppresses Spring INFO. Boot 4 reports the actual port only after bind;
        # retain this specific signal for port-zero discovery in host runs.
        app_args=["--spring.profiles.active=prod", "--server.port={APPPORT}", "--server.address={BINDADDR}",
                  "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"],
        env={"SPRING_DATASOURCE_URL": "jdbc:postgresql://{DBHOST}:{DBPORT}/jhipsterSampleApplication",
             "SPRING_DATASOURCE_USERNAME": "jhipsterSampleApplication", "SPRING_DATASOURCE_PASSWORD": "campaign-synthetic",
             "JHIPSTER_SECURITY_AUTHENTICATION_JWT_BASE64_SECRET": JWT_SECRET},
        java_opts=["-Xmx1g", "-Dxtrace.agent.recordingDiagnostics=true"], db_name="jhipsterSampleApplication", db_user="jhipsterSampleApplication",
        db_password="campaign-synthetic", ready_path="/management/health", ready_timeout=360,
        ready_ok=lambda st, body: st == 200 and '"UP"' in body)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def login(c, user="admin", pw="admin", label=None):
    r = c.http("POST", "/api/authenticate", json_body={"username": user, "password": pw, "rememberMe": False},
               label=label or f"login {user}")
    tok = None
    if r["status"] == 200:
        tok = json.loads(r["text"]).get("id_token")
    return r, tok


def ensure_login(c):
    r, tok = login(c)
    c.check("admin authenticates (200 + id_token)", r["status"] == 200 and bool(tok))
    return tok


def s_unauth(c):
    r = c.http("GET", "/api/bank-accounts")
    c.check("anonymous business request -> 401", r["status"] == 401, str(r["status"]))
    r = c.http("GET", "/api/admin/users")
    c.check("anonymous admin request -> 401", r["status"] == 401, str(r["status"]))
    r, tok = login(c, "admin", "wrong-password", label="login invalid")
    c.check("invalid synthetic login -> 401", r["status"] == 401 and tok is None, str(r["status"]))
    c.sql("no-accounts-created", "select count(*) from bank_account")
    c.check("db untouched by denied requests", c.db["no-accounts-created"] == [["0"]])


def s_login_and_account(c):
    tok = ensure_login(c)
    r = c.http("GET", "/api/account", headers=bearer(tok))
    c.check("GET /api/account returns admin", r["status"] == 200 and json.loads(r["text"]).get("login") == "admin")
    c.sql("authorities", "select u.login,ua.authority_name from jhi_user u join jhi_user_authority ua on ua.user_id=u.id "
          "where u.login in ('admin','user') order by 1,2")
    c.check("seeded admin has ROLE_ADMIN in db", ["admin", "ROLE_ADMIN"] in c.db["authorities"])
    r = c.http("GET", "/api/admin/users", headers=bearer(tok))
    c.check("admin lists users (200)", r["status"] == 200)
    # non-admin user is denied the admin endpoint
    r2, utok = login(c, "user", "user", label="login user")
    c.check("synthetic user authenticates", r2["status"] == 200 and bool(utok))
    r3 = c.http("GET", "/api/admin/users", headers=bearer(utok), label="admin endpoint as ROLE_USER")
    c.check("ROLE_USER denied admin endpoint (403)", r3["status"] == 403, str(r3["status"]))


def s_account_crud(c):
    tok = ensure_login(c)
    h = bearer(tok)
    r = c.http("POST", "/api/bank-accounts", headers=h, json_body={"name": "Campaign Checking", "balance": 42.5}, label="create account")
    c.check("create account -> 201", r["status"] == 201, str(r["status"]))
    acct = json.loads(r["text"]) if r["status"] == 201 else {}
    aid = acct.get("id")
    c.check("created account has id", isinstance(aid, int))
    ID = [(rf"/bank-accounts/{aid}\b", "/bank-accounts/<ID>"), (rf'"id"\s*:\s*{aid}\b', '"id":<ID>')] if aid else []
    r = c.http("GET", f"/api/bank-accounts/{aid}", headers=h, label="get account", norm=ID)
    c.check("read-back equals created", r["status"] == 200 and json.loads(r["text"]).get("name") == "Campaign Checking")
    c.sql("account-row", "select name,balance::text from bank_account order by name")
    c.check("db row present", c.db["account-row"] == [["Campaign Checking", "42.50"]], str(c.db.get("account-row")))
    STATE["account"] = aid


def s_validation(c):
    tok = ensure_login(c)
    h = bearer(tok)
    r = c.http("POST", "/api/bank-accounts", headers=h, json_body={"balance": 1}, label="account without name")
    c.check("missing required name -> 400", r["status"] == 400, str(r["status"]))
    r = c.http("POST", "/api/bank-accounts", headers=h, json_body={"id": 99, "name": "Preset Id", "balance": 1}, label="account with preset id")
    c.check("client-supplied id rejected -> 400", r["status"] == 400, str(r["status"]))
    r = c.http("POST", "/api/bank-accounts", headers=h, body="{not json", label="malformed json")
    c.check("malformed body -> 4xx", 400 <= r["status"] < 500, str(r["status"]))
    c.sql("invalid-rows", "select count(*) from bank_account where name in ('Preset Id')")
    c.check("db unchanged by invalid input", c.db["invalid-rows"] == [["0"]])


def s_update(c):
    tok = ensure_login(c)
    h = bearer(tok)
    aid = STATE["account"]
    r = c.http("PUT", f"/api/bank-accounts/{aid}", headers=h, json_body={"id": aid, "name": "Campaign Checking v2", "balance": 77.25}, label="update account",
               norm=[(rf"/bank-accounts/{aid}\b", "/bank-accounts/<ID>")])
    c.check("update -> 200", r["status"] == 200, str(r["status"]))
    r = c.http("GET", f"/api/bank-accounts/{aid}", headers=h, label="get updated", norm=[(rf'"id"\s*:\s*{aid}\b', '"id":<ID>')])
    c.check("next read shows update", json.loads(r["text"]).get("balance") in (77.25, "77.25"))
    c.sql("updated-row", "select name,balance::text from bank_account order by name")
    c.check("db has updated row", c.db["updated-row"] == [["Campaign Checking v2", "77.25"]], str(c.db.get("updated-row")))
    r = c.http("PUT", "/api/bank-accounts/424242", headers=h, json_body={"id": 424242, "name": "Ghost", "balance": 1}, label="update missing")
    c.check("update of unknown id -> 400/404", r["status"] in (400, 404), str(r["status"]))


def s_operation_relations(c):
    tok = ensure_login(c)
    h = bearer(tok)
    aid = STATE["account"]
    l1 = json.loads(c.http("POST", "/api/labels", headers=h, json_body={"label": "synthetic-food"}, label="create label")["text"])
    op = c.http("POST", "/api/operations", headers=h, label="create operation",
                json_body={"date": "2026-02-03T10:00:00Z", "description": "synthetic lunch", "amount": 12.5,
                           "bankAccount": {"id": aid}, "labels": [{"id": l1["id"]}]})
    c.check("create operation -> 201", op["status"] == 201, str(op["status"]))
    opid = json.loads(op["text"]).get("id")
    r = c.http("GET", f"/api/operations/{opid}", headers=h, label="get operation")
    c.check("operation reads back with account relation", r["status"] == 200 and json.loads(r["text"]).get("bankAccount", {}).get("id") == aid)
    c.sql("operation-join", "select o.description,o.amount::text,b.name,l.label from operation o join bank_account b on b.id=o.bank_account_id "
          "left join rel_operation__label rl on rl.operation_id=o.id left join label l on l.id=rl.label_id order by 1")
    c.check("db join shows operation/account/label", c.db["operation-join"] == [["synthetic lunch", "12.50", "Campaign Checking v2", "synthetic-food"]], str(c.db.get("operation-join")))
    STATE["operation"] = opid
    STATE["label"] = l1["id"]


def s_concurrent(c):
    c.norm_extra.extend([(r"/api/bank-accounts/\d+", "/api/bank-accounts/<ID>"), (r'"id"\s*:\s*\d+', '"id":<ID>')])
    tok = ensure_login(c)
    h = bearer(tok)

    def make(i):
        name = f"Parallel {i:02d}"
        r = c.http("POST", "/api/bank-accounts", headers=h, json_body={"name": name, "balance": i + 0.5}, label=f"create {name}")
        if r["status"] != 201:
            return False
        aid = json.loads(r["text"])["id"]
        r2 = c.http("GET", f"/api/bank-accounts/{aid}", headers=h, label=f"reopen {name}")
        d = json.loads(r2["text"])
        return d.get("name") == name and float(d.get("balance")) == i + 0.5

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        oks = list(pool.map(make, range(12)))
        # concurrent authenticated reads of the same seeded user must not cross-contaminate
        def who(i):
            user = ("admin", "admin") if i % 2 == 0 else ("user", "user")
            _, t = login(c, *user, label=f"login {user[0]} #{i}")
            r = c.http("GET", "/api/account", headers=bearer(t), label=f"account as {user[0]} #{i}")
            return json.loads(r["text"]).get("login") == user[0]
        whos = list(pool.map(who, range(12)))
    c.check("12 concurrent create+reopen each see their own account", all(oks))
    c.check("12 concurrent mixed-user logins each see their own principal", all(whos))
    c.sql("parallel-rows", "select name,balance::text from bank_account where name like 'Parallel %' order by name")
    c.check("db has 12 distinct parallel rows", len(c.db["parallel-rows"]) == 12)


def s_delete_missing(c):
    tok = ensure_login(c)
    h = bearer(tok)
    opid, aid, lid = STATE["operation"], STATE["account"], STATE["label"]
    r = c.http("DELETE", f"/api/operations/{opid}", headers=h, label="delete operation")
    c.check("delete operation -> 204", r["status"] == 204, str(r["status"]))
    r = c.http("GET", f"/api/operations/{opid}", headers=h, label="get deleted operation")
    c.check("deleted operation -> 404", r["status"] == 404, str(r["status"]))
    r = c.http("DELETE", f"/api/labels/{lid}", headers=h, label="delete label")
    c.check("delete label -> 204", r["status"] == 204, str(r["status"]))
    r = c.http("GET", "/api/bank-accounts/777777", headers=h, label="get unknown account")
    c.check("unknown account -> 404", r["status"] == 404, str(r["status"]))
    c.sql("op-count", "select (select count(*) from operation),(select count(*) from label)")
    c.check("db rows removed", c.db["op-count"] == [["0", "0"]], str(c.db.get("op-count")))


STATE: dict = {}
SCENARIOS = [
    xcamp.Scenario("anonymous-and-invalid-login-denied", "Unauthenticated + invalid credentials denied; DB untouched", "auth", s_unauth),
    xcamp.Scenario("admin-and-user-authentication", "JWT login, account read, role check (ROLE_USER denied admin API)", "auth", s_login_and_account),
    xcamp.Scenario("account-create-read-roundtrip", "Create bank account, read back, DB row", "db-write-read", s_account_crud),
    xcamp.Scenario("account-validation-errors", "Missing name / preset id / malformed JSON rejected, DB unchanged", "validation", s_validation),
    xcamp.Scenario("account-update-and-missing", "Update persists to next read + DB; unknown id error path", "db-write-read", s_update),
    xcamp.Scenario("operation-with-relations", "Operation with account + label relations (multi-table write/join)", "business", s_operation_relations),
    xcamp.Scenario("concurrent-isolation", "12 parallel create+reopen and 12 mixed-principal logins; no cross-association", "concurrency", s_concurrent),
    xcamp.Scenario("delete-and-not-found", "Delete operation/label then 404 paths; DB cleanup", "error", s_delete_missing),
]


def baseline(out):
    os.environ.pop("XCAMP_LAUNCH_PREFIX", None)
    return xcamp.run_baseline(project="jhipster", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR),
                              "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                              "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
                              make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=[],
                              adaptations=CAMP["configAdaptations"], harness_files=[HERE])


CRUD = "org.springframework.data.repository.CrudRepository"
LIST_CRUD = "org.springframework.data.repository.ListCrudRepository"
PAGING_REPO = "org.springframework.data.repository.PagingAndSortingRepository"
JPA_REPO = "org.springframework.data.jpa.repository.JpaRepository"
REPO_BASES = [CRUD, LIST_CRUD, PAGING_REPO, JPA_REPO]
AUTH_HINTS = {"controller": "AuthenticateController"}
USER_HINTS = {"service": "UserService", "repository": ["UserRepository", *REPO_BASES]}
BANK_HINTS = {"controller": "BankAccountResource", "repository": ["BankAccountRepository", *REPO_BASES]}
LABEL_HINTS = {"controller": "LabelResource", "repository": ["LabelRepository", *REPO_BASES]}
OP_HINTS = {"controller": "OperationResource", "repository": ["OperationRepository", *REPO_BASES]}

EXPECT = {
    "anonymous-and-invalid-login-denied": [
        # Pre-dispatch Spring Security 401s occur in the servlet filter chain before any controller frame.
        {"method": "GET", "route": "/api/bank-accounts", "status": 401, "layers": [], "sourceOptional": True},
        {"method": "GET", "route": "/api/admin/users", "status": 401, "layers": [], "sourceOptional": True},
        {"method": "POST", "route": "/api/authenticate", "status": 401, "layers": ["controller"],
         "layerHints": AUTH_HINTS},
    ],
    "admin-and-user-authentication": [
        {"method": "POST", "route": "/api/authenticate", "statuses": [200, 200], "layers": ["controller"],
         "layerHints": AUTH_HINTS},
        {"method": "GET", "route": "/api/account", "status": 200, "layers": ["controller", "service", "repository"],
         "layerHints": {"controller": "AccountResource", **USER_HINTS}},
        {"method": "GET", "route": "/api/admin/users", "statuses": [200, 403],
         "layers": ["controller", "service", "repository"],
         "layerHints": {"controller": "UserResource", **USER_HINTS}},
    ],
    "account-create-read-roundtrip": [
        {"method": "POST", "route": "/api/authenticate", "status": 200, "layers": ["controller"],
         "layerHints": AUTH_HINTS},
        {"method": "POST", "route": "/api/bank-accounts", "status": 201, "layers": ["controller", "repository"],
         "layerHints": BANK_HINTS},
        {"method": "GET", "route": "/api/bank-accounts/{id}", "status": 200, "layers": ["controller", "repository"],
         "layerHints": BANK_HINTS},
    ],
    "account-validation-errors": [
        {"method": "POST", "route": "/api/authenticate", "status": 200, "layers": ["controller"],
         "layerHints": AUTH_HINTS},
        {"method": "POST", "route": "/api/bank-accounts", "statuses": [400, 400, 415], "layers": ["controller"],
         "layerHints": {"controller": "BankAccountResource"}},
    ],
    "account-update-and-missing": [
        {"method": "POST", "route": "/api/authenticate", "status": 200, "layers": ["controller"],
         "layerHints": AUTH_HINTS},
        {"method": "PUT", "route": "/api/bank-accounts/{id}", "statuses": [200, 400], "layers": ["controller", "repository"],
         "layerHints": BANK_HINTS},
        {"method": "GET", "route": "/api/bank-accounts/{id}", "status": 200, "layers": ["controller", "repository"],
         "layerHints": BANK_HINTS},
    ],
    "operation-with-relations": [
        {"method": "POST", "route": "/api/authenticate", "status": 200, "layers": ["controller"],
         "layerHints": AUTH_HINTS},
        {"method": "POST", "route": "/api/labels", "status": 201, "layers": ["controller", "repository"],
         "layerHints": LABEL_HINTS},
        {"method": "POST", "route": "/api/operations", "status": 201, "layers": ["controller", "repository"],
         "layerHints": OP_HINTS},
        {"method": "GET", "route": "/api/operations/{id}", "status": 200, "layers": ["controller", "repository"],
         "layerHints": OP_HINTS},
    ],
    "concurrent-isolation": [
        {"method": "POST", "route": "/api/authenticate", "status": 200, "layers": ["controller"],
         "layerHints": AUTH_HINTS, "minCount": 13},
        {"method": "POST", "route": "/api/bank-accounts", "status": 201, "layers": ["controller"],
         "layerHints": {"controller": "BankAccountResource"}, "minCount": 12},
        {"method": "GET", "route": "/api/bank-accounts/{id}", "status": 200, "layers": ["controller"],
         "layerHints": {"controller": "BankAccountResource"}, "minCount": 12},
        {"method": "GET", "route": "/api/account", "status": 200, "layers": ["controller"],
         "layerHints": {"controller": "AccountResource"}, "minCount": 12},
    ],
    "delete-and-not-found": [
        {"method": "POST", "route": "/api/authenticate", "status": 200, "layers": ["controller"],
         "layerHints": AUTH_HINTS},
        {"method": "DELETE", "route": "/api/operations/{id}", "status": 204, "layers": ["controller", "repository"],
         "layerHints": OP_HINTS},
        {"method": "GET", "route": "/api/operations/{id}", "status": 404, "layers": ["controller", "repository"],
         "layerHints": OP_HINTS},
        {"method": "DELETE", "route": "/api/labels/{id}", "status": 204, "layers": ["controller", "repository"],
         "layerHints": LABEL_HINTS},
        {"method": "GET", "route": "/api/bank-accounts/{id}", "status": 404, "layers": ["controller", "repository"],
         "layerHints": BANK_HINTS},
    ],
}

APP_PACKAGE = "io.github.jhipster.sample"
SOURCE_ROOT = "src/main/java"


def instrumented(out: pathlib.Path | None = None, baseline_receipt: pathlib.Path | None = None) -> int:
    """One reset-to-finish run with the app launched by the PACKAGED `xtrace run`, then judged through the read API."""
    need = {k: os.environ.get(k, "") for k in ("XCAMP_XTRACE", "XCAMP_AGENT", "XCAMP_DATA_HOME")}
    missing = [k for k, v in need.items() if not v]
    if missing or os.environ.get("XCAMP_APP_MODE") != "host":
        print("instrumented needs XCAMP_APP_MODE=host and " + ", ".join(missing or ["(all set)"]))
        return 2
    xtrace, agent = need["XCAMP_XTRACE"], need["XCAMP_AGENT"]
    os.environ["XCAMP_LAUNCH_PREFIX"] = " ".join(shlex.quote(x) for x in
        [xtrace, "run", "--project-dir", str(SRC), "--java-agent", agent,
         "--app-package", APP_PACKAGE, "--source-root", SOURCE_ROOT, "--"])
    canaries = None
    if os.environ.get("XCAMP_CANARY_FILE"):
        canaries = json.loads(pathlib.Path(os.environ["XCAMP_CANARY_FILE"]).read_text())
    n = 1
    while (PROJ / f"instrumented-{n}").exists():
        n += 1
    out = out or PROJ / f"instrumented-{n}"
    baseline_receipt = baseline_receipt or (pathlib.Path(os.environ["XCAMP_BASELINE_RECEIPT"]) if os.environ.get("XCAMP_BASELINE_RECEIPT") else None)
    r = xinstr.run_instrumented(
        project="jhipster", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR), "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                                  "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
        make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=[], expectations=EXPECT, xtrace=xtrace,
        project_dir=SRC, data_home=pathlib.Path(need["XCAMP_DATA_HOME"]), adaptations=CAMP["configAdaptations"],
        canaries=canaries, baseline_receipt=baseline_receipt, harness_files=[HERE, pathlib.Path(xinstr.__file__)],
        extra_canary_paths=[("POST", "/api/authenticate")], skip_canary_auth_paths=("/api/authenticate",))
    print(json.dumps({"result": r["result"], "api": r["api"], "problemClasses": r["problemClasses"]}))
    return 0 if r["result"] == "recorded" else 1


def overhead() -> int:
    """Five fresh baseline/instrumented pairs, in that order; no retry of a failed repeat."""
    root = pathlib.Path(os.environ["XCAMP_OVERHEAD_DIR"])
    root.mkdir(parents=True, exist_ok=False)
    runs = []
    manifest = root / "runs.json"
    for repeat in range(5):
        baseline_receipt = root / f"baseline-{repeat}" / "receipt.json"
        for mode in ("baseline", "instrumented"):
            dest = root / f"{mode}-{repeat}"
            started = time.time_ns()
            if mode == "baseline":
                result = baseline(dest)
                rc = 0 if result["result"] == "passed_baseline_only" else 1
            else:
                rc = instrumented(dest, baseline_receipt)
            runs.append({"mode": mode, "repeat": repeat, "startedNs": started, "finishedNs": time.time_ns(),
                         "receiptPath": str((dest / "receipt.json").resolve()), "exitCode": rc})
            manifest.write_text(json.dumps({"runs": runs}, indent=1, sort_keys=True) + "\n")
            if rc != 0:
                return rc
    return 0


def flows() -> int:
    """Lifecycle and focused-capture flows (record/stop, restart, interrupted recording, lines, values); writes flows-<n>/flows.json."""
    need = {k: os.environ.get(k, "") for k in ("XCAMP_XTRACE", "XCAMP_AGENT", "XCAMP_DATA_HOME")}
    missing = [k for k, v in need.items() if not v]
    if missing or os.environ.get("XCAMP_APP_MODE") != "host":
        print("flows needs XCAMP_APP_MODE=host and " + ", ".join(missing or ["(all set)"]))
        return 2
    import xflows
    n = 1
    while (PROJ / f"flows-{n}").exists():
        n += 1
    out = PROJ / f"flows-{n}"
    out.mkdir(parents=True)
    results = xflows.Flows(xtrace=need["XCAMP_XTRACE"], agent=need["XCAMP_AGENT"], project_dir=SRC,
                           data_home=pathlib.Path(need["XCAMP_DATA_HOME"]), out_dir=out, make_stack=make_stack,
                           app_package=APP_PACKAGE, source_root=SOURCE_ROOT, project="jhipster").run_all()
    (out / "flows.json").write_text(json.dumps({"schemaVersion": 1, "kind": "campaign_flows", "steps": results}, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "overhead":
        sys.exit(overhead())
    if len(sys.argv) > 1 and sys.argv[1] == "instrumented":
        sys.exit(instrumented())
    if len(sys.argv) > 1 and sys.argv[1] == "flows":
        sys.exit(flows())
    sys.exit(xcamp.main_cli("jhipster", build, baseline, PROJ))
