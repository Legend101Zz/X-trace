#!/usr/bin/env python3
"""Apache Fineract campaign harness (baseline + instrumented/overhead/flows). See petclinic/harness/run.py for usage."""
import base64
import concurrent.futures
import json
import os
import pathlib
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
BASE = "/fineract-provider/api/v1"
TENANT = {"Fineract-Platform-TenantId": "default"}
# Fineract's documented demo credentials (upstream seed). The Authorization header is redacted in receipts.
AUTH = {"Authorization": "Basic " + base64.b64encode(b"mifos:password").decode()}
BAD_AUTH = {"Authorization": "Basic " + base64.b64encode(b"xtrace:invalid").decode()}
H = {**TENANT, **AUTH}
DATE_FMT = {"dateFormat": "dd MMMM yyyy", "locale": "en"}
# Server-generated dates / ids that vary by wall clock.
NORM = [(r"\[\s*20\d\d,\s*\d{1,2},\s*\d{1,2}(?:,\s*\d{1,2}){0,3}\s*\]", "<DATE-ARRAY>"),
        (r'"(?:createdOn|updatedOn|submittedOnDate|timeline)"\s*:\s*"[^"]*"', '"<DATE-FIELD>":""')]


def build() -> int:
    xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"])
    xcamp.docker("volume", "create", "xtrace-camp-gradle")
    rc = xcamp.docker_build("fineract", SRC, IMAGE, CAMP["build"]["command"],
                            {"xtrace-camp-gradle": "/root/.gradle", str(PROJ / "work"): "/out"},
                            PROJ / "work" / "build.log", mem="7g", timeout=7200)
    if rc == 0:
        print("jar sha256", xcamp.sha256_file(JAR))
    return rc


def make_stack(run_id: str) -> xcamp.Stack:
    return xcamp.Stack(
        project="fineract", jdk_image=IMAGE, jar=JAR, run_id=run_id, app_port=8080, app_mem="3g",
        app_args=["--server.address={BINDADDR}"],
        env={"FINERACT_SERVER_PORT": "{APPPORT}", "FINERACT_SERVER_SSL_ENABLED": "false",
             "FINERACT_HIKARI_JDBC_URL": "jdbc:postgresql://{DBHOST}:{DBPORT}/fineract_tenants",
             "FINERACT_HIKARI_USERNAME": "root", "FINERACT_HIKARI_PASSWORD": "postgres",
             "FINERACT_DEFAULT_TENANTDB_HOSTNAME": "{DBHOST}", "FINERACT_DEFAULT_TENANTDB_PORT": "{DBPORT}",
             "FINERACT_DEFAULT_TENANTDB_NAME": "fineract_default",
             "FINERACT_DEFAULT_TENANTDB_UID": "root", "FINERACT_DEFAULT_TENANTDB_PWD": "postgres"},
        java_opts=["-Xmx2g", "-Dxtrace.agent.recordingDiagnostics=true"], db_name="fineract_tenants", effect_db="fineract_default", db_user="root", db_password="postgres",
        extra_db_init=["CREATE DATABASE fineract_default"], ready_timeout=900,
        ready_path="/fineract-provider/actuator/health", ready_ok=lambda st, body: st == 200 and '"UP"' in body)


def jbody(r):
    try:
        return json.loads(r["text"])
    except ValueError:
        return None


def client_payload(first, last, **extra):
    return {"firstname": first, "lastname": last, "officeId": 1, "active": False, "legalFormId": 1,
            "locale": "en", "dateFormat": "dd MMMM yyyy", "submittedOnDate": "01 January 2025", **extra}


CLIENT_SQL = "select display_name,status_enum::text,office_id::text,legal_form_enum::text from m_client where display_name like '{p}%' order by display_name"
STATE: dict = {}


def s_denied(c):
    r = c.http("GET", f"{BASE}/clients", headers=TENANT, label="anonymous clients")
    c.check("no credentials -> 401", r["status"] == 401, str(r["status"]))
    r = c.http("GET", f"{BASE}/clients", headers={**TENANT, **BAD_AUTH}, label="invalid credentials")
    c.check("invalid credentials -> 401", r["status"] == 401, str(r["status"]))
    r = c.http("POST", f"{BASE}/clients", headers=TENANT, json_body=client_payload("Denied", "Anon"), label="anonymous create")
    c.check("anonymous write -> 401", r["status"] == 401, str(r["status"]))
    c.sql("no-denied-rows", "select count(*) from m_client where lastname='Anon'")
    c.check("db untouched by denied write", c.db["no-denied-rows"] == [["0"]])


def s_seed_read(c):
    r = c.http("GET", f"{BASE}/offices", headers=H)
    offices = jbody(r) or []
    c.check("authenticated office list contains seeded head office", r["status"] == 200 and any(o.get("id") == 1 for o in offices))
    r = c.http("GET", f"{BASE}/offices/1", headers=H)
    c.check("office 1 readable", r["status"] == 200 and (jbody(r) or {}).get("id") == 1)
    r = c.http("GET", f"{BASE}/clients?limit=5", headers=H, label="client list (empty tenant)")
    c.check("empty client list 200", r["status"] == 200)
    c.sql("seed-office", "select id::text,name from m_office order by id")
    c.check("db has head office row", len(c.db["seed-office"]) >= 1)


def s_create_read(c):
    r = c.http("POST", f"{BASE}/clients", headers=H, json_body=client_payload("Xtrace", "Baseline"), label="create client")
    body = jbody(r) or {}
    c.check("create client -> 200 with clientId", r["status"] == 200 and isinstance(body.get("clientId"), int), str(r["status"]))
    cid = body.get("clientId")
    STATE["client"] = cid
    ID = [(rf"/clients/{cid}\b", "/clients/<ID>"), (rf'"(?:clientId|resourceId|id|subResourceId)"\s*:\s*{cid}\b', '"id":<ID>')]
    r = c.http("GET", f"{BASE}/clients/{cid}", headers=H, label="read client", norm=ID)
    d = jbody(r) or {}
    c.check("read-back displayName", r["status"] == 200 and d.get("displayName") == "Xtrace Baseline")
    c.sql("created-client", CLIENT_SQL.format(p="Xtrace"))
    c.check("db has pending client", c.db["created-client"] == [["Xtrace Baseline", "100", "1", "1"]], str(c.db.get("created-client")))


def s_validation(c):
    r = c.http("POST", f"{BASE}/clients", headers=H, json_body={"officeId": 1, "active": False, "legalFormId": 1, "locale": "en"}, label="missing names")
    c.check("missing name -> 400", r["status"] == 400, str(r["status"]))
    r = c.http("POST", f"{BASE}/clients", headers=H, json_body=client_payload("Bad", "Office", officeId=987654), label="unknown office")
    c.check("unknown office -> 4xx", 400 <= r["status"] < 500, str(r["status"]))
    r = c.http("POST", f"{BASE}/clients", headers=H, body="{broken", label="malformed json")
    c.check("malformed JSON -> 4xx", 400 <= r["status"] < 500, str(r["status"]))
    c.sql("no-invalid-rows", "select count(*) from m_client where lastname in ('Office')")
    c.check("db unchanged by invalid input", c.db["no-invalid-rows"] == [["0"]])


def s_update(c):
    cid = STATE["client"]
    r = c.http("PUT", f"{BASE}/clients/{cid}", headers=H, json_body={"firstname": "Xtrace", "lastname": "Updated"}, label="update client",
               norm=[(rf"/clients/{cid}\b", "/clients/<ID>"), (rf'"(?:clientId|resourceId)"\s*:\s*{cid}\b', '"id":<ID>')])
    c.check("update -> 200", r["status"] == 200, str(r["status"]))
    r = c.http("GET", f"{BASE}/clients/{cid}", headers=H, label="read updated", norm=[(rf'"(?:clientId|resourceId|id)"\s*:\s*{cid}\b', '"id":<ID>')])
    c.check("next read shows update", (jbody(r) or {}).get("displayName") == "Xtrace Updated")
    c.sql("updated-client", CLIENT_SQL.format(p="Xtrace"))
    c.check("db has updated name", c.db["updated-client"] == [["Xtrace Updated", "100", "1", "1"]], str(c.db.get("updated-client")))


def s_activate(c):
    cid = STATE["client"]
    r = c.http("POST", f"{BASE}/clients/{cid}?command=activate", headers=H, label="activate client",
               json_body={"activationDate": "02 January 2025", **DATE_FMT},
               norm=[(rf"/clients/{cid}\b", "/clients/<ID>"), (rf'"(?:clientId|resourceId)"\s*:\s*{cid}\b', '"id":<ID>')])
    c.check("activate command -> 200", r["status"] == 200, str(r["status"]))
    r = c.http("GET", f"{BASE}/clients/{cid}", headers=H, label="read activated", norm=[(rf'"(?:clientId|resourceId|id)"\s*:\s*{cid}\b', '"id":<ID>')])
    d = jbody(r) or {}
    c.check("status is Active", (d.get("status") or {}).get("value") == "Active", str(d.get("status")))
    r = c.http("POST", f"{BASE}/clients/{cid}?command=activate", headers=H, label="activate twice",
               json_body={"activationDate": "03 January 2025", **DATE_FMT})
    c.check("second activation rejected (4xx)", 400 <= r["status"] < 500, str(r["status"]))
    c.sql("activated-client", CLIENT_SQL.format(p="Xtrace"))
    c.check("db status_enum=300 (active)", c.db["activated-client"] == [["Xtrace Updated", "300", "1", "1"]], str(c.db.get("activated-client")))


def s_concurrent(c):
    ID_ANY = [(r'"(?:clientId|resourceId|id|subResourceId)"\s*:\s*\d+', '"id":<ID>'), (r"/clients/\d+", "/clients/<ID>"),
              (r'"accountNo"\s*:\s*"\d+"', '"accountNo":"<ACCT>"'),
              (r'"savingsProductName"\s*:\s*"\d+"', '"savingsProductName":"<N>"'),  # upstream echoes a sequence number here
              (r'"displayName"\s*:\s*"Parallel \d+"', '"displayName":"<NAME>"')]
    c.norm_extra.extend(ID_ANY)

    def make(i):
        name = f"{i:02d}"
        r = c.http("POST", f"{BASE}/clients", headers=H, json_body=client_payload("Parallel", name), label=f"create Parallel {name}")
        cid = (jbody(r) or {}).get("clientId")
        if r["status"] != 200 or not cid:
            return False
        r2 = c.http("GET", f"{BASE}/clients/{cid}", headers=H, label=f"reopen Parallel {name}")
        return (jbody(r2) or {}).get("displayName") == f"Parallel {name}"

    def read_seeded(i):
        r = c.http("GET", f"{BASE}/offices/1", headers=H, label=f"office read #{i}")
        return (jbody(r) or {}).get("id") == 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        made = list(pool.map(make, range(12)))
        reads = list(pool.map(read_seeded, range(16)))
    c.check("12 concurrent create+reopen each see their own client", all(made))
    c.check("16 concurrent office reads all correct", all(reads))
    c.sql("parallel-clients", CLIENT_SQL.format(p="Parallel"))
    c.check("db has 12 distinct parallel clients", len(c.db["parallel-clients"]) == 12)


def s_delete_missing(c):
    # Create a fresh pending client to delete (the first one is active now and cannot be deleted).
    r = c.http("POST", f"{BASE}/clients", headers=H, json_body=client_payload("Doomed", "Client"), label="create doomed client")
    cid = (jbody(r) or {}).get("clientId")
    c.check("doomed client created", r["status"] == 200 and bool(cid))
    NORM_ID = [(rf"/clients/{cid}\b", "/clients/<ID>"), (rf'"(?:clientId|resourceId|id)"\s*:\s*{cid}\b', '"id":<ID>')]
    r = c.http("DELETE", f"{BASE}/clients/{cid}", headers=H, label="delete client", norm=NORM_ID)
    c.check("delete pending client -> 200", r["status"] == 200, str(r["status"]))
    r = c.http("GET", f"{BASE}/clients/{cid}", headers=H, label="read deleted client", norm=NORM_ID)
    c.check("deleted client -> 404", r["status"] == 404, str(r["status"]))
    r = c.http("GET", f"{BASE}/clients/99999999", headers=H, label="read unknown client")
    c.check("unknown client -> 404", r["status"] == 404, str(r["status"]))
    r = c.http("DELETE", f"{BASE}/clients/{STATE['client']}", headers=H, label="delete active client",
               norm=[(rf"/clients/{STATE['client']}\b", "/clients/<ID>")])
    c.check("delete of active client rejected (4xx)", 400 <= r["status"] < 500, str(r["status"]))
    c.sql("doomed-gone", CLIENT_SQL.format(p="Doomed"))
    c.check("db has no Doomed client", c.db["doomed-gone"] == [])


SCENARIOS = [
    xcamp.Scenario("denied-without-valid-credentials", "No/invalid Basic credentials denied on read and write; DB untouched", "auth", s_denied),
    xcamp.Scenario("authenticated-seed-read", "Authenticated seeded office/client reads", "business", s_seed_read),
    xcamp.Scenario("client-create-read-roundtrip", "Create client, read back, DB row", "db-write-read", s_create_read),
    xcamp.Scenario("client-validation-errors", "Missing names / unknown office / malformed JSON rejected; DB unchanged", "validation", s_validation),
    xcamp.Scenario("client-update", "Update persists to next read and DB", "db-write-read", s_update),
    xcamp.Scenario("client-activate-command", "Command pipeline: activate then reject second activation", "business", s_activate),
    xcamp.Scenario("concurrent-isolation", "12 parallel create+reopen and 16 parallel reads; no cross-association", "concurrency", s_concurrent),
    xcamp.Scenario("delete-and-not-found", "Delete pending client, 404 paths, active-delete rejected", "error", s_delete_missing),
]


def baseline(out):
    os.environ.pop("XCAMP_LAUNCH_PREFIX", None)
    return xcamp.run_baseline(project="fineract", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR),
                              "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                              "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
                              make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=NORM,
                              adaptations=CAMP["configAdaptations"], harness_files=[HERE])


CRUD = "org.springframework.data.repository.CrudRepository"
JPA_REPO = "org.springframework.data.jpa.repository.JpaRepository"
OFFICE_READ = {
    "controller": "OfficesApiResource",
    "service": ["OfficeReadPlatformServiceImpl", "OfficeReadPlatformService"],
}
CLIENT_READ = {
    "controller": "ClientsApiResource",
    "service": ["ClientReadPlatformServiceImpl", "ClientReadPlatformService"],
}
CLIENT_WRITE_SERVICES = [
    "PortfolioCommandSourceWritePlatformServiceImpl",
    "SynchronousCommandProcessingService",
    "ClientWritePlatformServiceJpaRepositoryImpl",
]
CLIENT_WRITE = {
    "controller": "ClientsApiResource",
    "service": CLIENT_WRITE_SERVICES,
    "repository": ["ClientRepository", "ClientRepositoryWrapper", "PortfolioCommandSourceRepository", CRUD, JPA_REPO],
}

EXPECT = {
    "denied-without-valid-credentials": [
        # Pre-dispatch Spring Security BasicAuthenticationFilter 401s occur before Jersey dispatch (sendError(401)).
        {"method": "GET", "route": f"{BASE}/clients", "statuses": [401, 401], "layers": [], "sourceOptional": True,
         "preDispatch": True, "allowUnobserved": True},
        {"method": "POST", "route": f"{BASE}/clients", "status": 401, "layers": [], "sourceOptional": True,
         "preDispatch": True, "allowUnobserved": True},
    ],
    "authenticated-seed-read": [
        {"method": "GET", "route": f"{BASE}/offices", "status": 200, "layers": ["controller", "service"],
         "layerHints": OFFICE_READ},
        {"method": "GET", "route": f"{BASE}/offices/{{officeId}}", "status": 200, "layers": ["controller", "service"],
         "layerHints": OFFICE_READ},
        {"method": "GET", "route": f"{BASE}/clients", "status": 200, "layers": ["controller", "service"],
         "layerHints": CLIENT_READ},
    ],
    "client-create-read-roundtrip": [
        {"method": "POST", "route": f"{BASE}/clients", "status": 200, "layers": ["controller", "service", "repository"],
         "layerHints": CLIENT_WRITE},
        {"method": "GET", "route": f"{BASE}/clients/{{clientId}}", "status": 200, "layers": ["controller", "service"],
         "layerHints": CLIENT_READ},
    ],
    "client-validation-errors": [
        {"method": "POST", "route": f"{BASE}/clients", "statuses": [400, 404, 415], "layers": ["controller", "service"],
         "layerHints": {"controller": "ClientsApiResource", "service": CLIENT_WRITE_SERVICES}},
    ],
    "client-update": [
        {"method": "PUT", "route": f"{BASE}/clients/{{clientId}}", "status": 200,
         "layers": ["controller", "service", "repository"], "layerHints": CLIENT_WRITE},
        {"method": "GET", "route": f"{BASE}/clients/{{clientId}}", "status": 200, "layers": ["controller", "service"],
         "layerHints": CLIENT_READ},
    ],
    "client-activate-command": [
        {"method": "POST", "route": f"{BASE}/clients/{{clientId}}", "statuses": [200, 403],
         "layers": ["controller", "service", "repository"], "layerHints": CLIENT_WRITE},
        {"method": "GET", "route": f"{BASE}/clients/{{clientId}}", "status": 200, "layers": ["controller", "service"],
         "layerHints": CLIENT_READ},
    ],
    "concurrent-isolation": [
        {"method": "POST", "route": f"{BASE}/clients", "status": 200, "layers": ["controller"],
         "layerHints": {"controller": "ClientsApiResource"}, "minCount": 12},
        {"method": "GET", "route": f"{BASE}/clients/{{clientId}}", "status": 200, "layers": ["controller"],
         "layerHints": {"controller": "ClientsApiResource"}, "minCount": 12},
        {"method": "GET", "route": f"{BASE}/offices/{{officeId}}", "status": 200, "layers": ["controller"],
         "layerHints": {"controller": "OfficesApiResource"}, "minCount": 16},
    ],
    "delete-and-not-found": [
        {"method": "POST", "route": f"{BASE}/clients", "status": 200,
         "layers": ["controller", "service", "repository"], "layerHints": CLIENT_WRITE},
        {"method": "DELETE", "route": f"{BASE}/clients/{{clientId}}", "statuses": [200, 403],
         "layers": ["controller", "service", "repository"], "layerHints": CLIENT_WRITE},
        {"method": "GET", "route": f"{BASE}/clients/{{clientId}}", "statuses": [404, 404],
         "layers": ["controller", "service"], "layerHints": CLIENT_READ},
    ],
}

APP_PACKAGE = "org.apache.fineract"
SOURCE_ROOT = "fineract-provider/src/main/java"


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
        project="fineract", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR), "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                                  "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
        make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=NORM, expectations=EXPECT, xtrace=xtrace,
        project_dir=SRC, data_home=pathlib.Path(need["XCAMP_DATA_HOME"]), adaptations=CAMP["configAdaptations"],
        canaries=canaries, baseline_receipt=baseline_receipt, harness_files=[HERE, pathlib.Path(xinstr.__file__)],
        extra_canary_paths=[("POST", f"{BASE}/clients")])
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
                           app_package=APP_PACKAGE, source_root=SOURCE_ROOT, project="fineract").run_all()
    (out / "flows.json").write_text(json.dumps({"schemaVersion": 1, "kind": "campaign_flows", "steps": results}, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "overhead":
        sys.exit(overhead())
    if len(sys.argv) > 1 and sys.argv[1] == "instrumented":
        sys.exit(instrumented())
    if len(sys.argv) > 1 and sys.argv[1] == "flows":
        sys.exit(flows())
    sys.exit(xcamp.main_cli("fineract", build, baseline, PROJ))
