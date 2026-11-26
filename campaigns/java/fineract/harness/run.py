#!/usr/bin/env python3
"""Pinned Apache Fineract baseline and private installed development instrumentation."""
import base64
import concurrent.futures
import json
import os
import pathlib
import re
import sys
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "lib"))
import xcamp  # noqa: E402
import fineract_phase_evidence  # noqa: E402
import xinstr  # noqa: E402
import installed_java  # noqa: E402
import recording_evidence  # noqa: E402

CAMP, PROJ, SRC = xcamp.load_campaign(__file__)
HERE = pathlib.Path(__file__).resolve()
JAR = SRC / CAMP["build"]["artifact"]
IMAGE = CAMP["runtime"]["buildImage"]
POSTGRES_IMAGE = CAMP["runtime"]["databaseImage"]
POSTGRES_DIGEST = POSTGRES_IMAGE.split("@", 1)[1]
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


def make_stack(run_id: str, launch_prefix: tuple[str, ...] = ()) -> xcamp.Stack:
    return xcamp.Stack(
        project="fineract", jdk_image=IMAGE, jar=JAR, run_id=run_id, app_port=8080, app_mem="3g",
        app_args=["--server.address={BINDADDR}", "--server.port={APPPORT}",
                  "--logging.level.org.springframework.boot.web.embedded.tomcat.TomcatWebServer=INFO"],
        env={"FINERACT_SERVER_PORT": "{APPPORT}", "FINERACT_SERVER_SSL_ENABLED": "false",
             "FINERACT_HIKARI_JDBC_URL": "jdbc:postgresql://{DBHOST}:{DBPORT}/fineract_tenants",
             "FINERACT_HIKARI_USERNAME": "root", "FINERACT_HIKARI_PASSWORD": "postgres",
             "FINERACT_DEFAULT_TENANTDB_HOSTNAME": "{DBHOST}", "FINERACT_DEFAULT_TENANTDB_PORT": "{DBPORT}",
             "FINERACT_DEFAULT_TENANTDB_NAME": "fineract_default",
             "FINERACT_DEFAULT_TENANTDB_UID": "root", "FINERACT_DEFAULT_TENANTDB_PWD": "postgres"},
        java_opts=["-Xmx2g"], db_name="fineract_tenants", effect_db="fineract_default", db_user="root", db_password="postgres",
        extra_db_init=["CREATE DATABASE fineract_default"], ready_timeout=900,
        db_image=POSTGRES_IMAGE, launch_prefix=launch_prefix,
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


def read_seeded_office_list(c):
    """Ordinary first read shared by the full seed scenario and the one-office diagnostic."""
    r = c.http("GET", f"{BASE}/offices", headers=H)
    offices = jbody(r) or []
    c.check("authenticated office list contains seeded head office", r["status"] == 200 and any(o.get("id") == 1 for o in offices))


def s_seed_read(c):
    read_seeded_office_list(c)
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


def runtime_dependencies():
    """Observe the pinned framework/driver artifacts in the actual built boot JAR."""
    expected = {"jersey-server": CAMP["runtime"]["jersey"].split(" ", 1)[0],
                "jersey-common": CAMP["runtime"]["jersey"].split(" ", 1)[0],
                "tomcat-embed-core": CAMP["runtime"]["tomcat"], "postgresql": CAMP["runtime"]["pgjdbc"],
                "spring-boot": CAMP["runtime"]["springBoot"]}
    observed = {}
    with zipfile.ZipFile(JAR) as jar:
        for name, version in expected.items():
            entries = [entry for entry in jar.infolist() if re.fullmatch(
                r"BOOT-INF/lib/" + re.escape(name) + r"-([0-9][^/]*)\.jar", entry.filename)]
            if len(entries) != 1 or entries[0].filename != f"BOOT-INF/lib/{name}-{version}.jar" or entries[0].file_size > 64 << 20:
                raise ValueError("built framework dependency differs from development pin")
            observed[name] = {"version": version, "sha256": xcamp.sha256_bytes(jar.read(entries[0]))}
    return observed


def source_pin():
    pin = {**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR),
           "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
           "postgresImageDigest": POSTGRES_DIGEST, "jdkImage": IMAGE,
           "license": CAMP["license"], "developmentPin": True, "runtimeDependencies": runtime_dependencies(),
           "historicalPlatform": CAMP["runtime"]["platform"], "actualPlatform": xcamp.PLATFORM}
    if os.environ.get("XCAMP_APP_MODE") == "host":
        installed_java.clean_checkout(HERE.parents[4], os.environ["XCAMP_PRODUCT_SHA"])
        pin["hostJava"] = installed_java.java_identity(pathlib.Path(os.environ["XCAMP_JAVA"]), CAMP["runtime"]["jdk"])
        pin["hostRunBindingSha256"] = installed_java.host_binding()
        pin["runtimeDatabaseImageId"] = xcamp.image_id(POSTGRES_IMAGE)
        pin["databaseRepoDigest"] = xcamp.image_digest(POSTGRES_IMAGE)
        archive = installed_java.private_file(pathlib.Path(os.environ["XCAMP_PACKAGE_ARCHIVE"]))
        pin["packageArchiveSha256"] = xcamp.sha256_file(archive)
        if pin["packageArchiveSha256"] != os.environ["XCAMP_PACKAGE_SHA256"]:
            raise ValueError("baseline archive identity differs")
    return pin


def baseline(out):
    if os.environ.get("XCAMP_LAUNCH_PREFIX") or xcamp.REQUEST_HOOK is not None:
        raise ValueError("baseline requires an uninstrumented, unmodified workload")
    STATE.clear()
    return xcamp.run_baseline(project="fineract", pin=source_pin(), make_stack=make_stack,
                              scenarios=SCENARIOS, out_dir=out, norm_extra=NORM,
                              adaptations=CAMP["configAdaptations"], harness_files=[HERE])


def instrumented():
    required = ("XCAMP_INSTALL_PREFIX", "XCAMP_PACKAGE_ARCHIVE", "XCAMP_PACKAGE_SHA256", "XCAMP_PRODUCT_SHA",
                "XCAMP_JAVA", "XCAMP_DATA_HOME", "XCAMP_BASELINE_RECEIPT", "XCAMP_CANARY_FILE", "TMPDIR")
    if (any(not os.environ.get(key) for key in required) or os.environ.get("XCAMP_APP_MODE") != "host"
            or xcamp.PLATFORM != "linux/amd64" or os.environ.get("XCAMP_LAUNCH_PREFIX")):
        raise ValueError("installed hosted campaign environment unavailable")
    root = installed_java.private_dir(pathlib.Path(os.environ["XTRACE_CAMPAIGN_ROOT"]))
    project = installed_java.private_dir(PROJ)
    if not project.is_relative_to(root) or SRC.resolve(strict=True).parent != project:
        raise ValueError("source and receipts escaped the private campaign root")
    installed_java.private_dir(pathlib.Path(os.environ["TMPDIR"]))
    data = installed_java.private_dir(pathlib.Path(os.environ["XCAMP_DATA_HOME"]))
    prefix = installed_java.private_dir(pathlib.Path(os.environ["XCAMP_INSTALL_PREFIX"]))
    archive = installed_java.private_file(pathlib.Path(os.environ["XCAMP_PACKAGE_ARCHIVE"]))
    out = project / "instrumented-1"
    # A single fresh attempt: rerunning an unexplained red cannot replace its receipt.
    out.mkdir(mode=0o700, exist_ok=False)
    cli, agent, package = installed_java.installed_package(prefix, archive, os.environ["XCAMP_PACKAGE_SHA256"],
                                                         os.environ["XCAMP_PRODUCT_SHA"], out / "verified-package")
    pin = source_pin()
    tracked = json.loads((HERE.parents[1] / "baseline-summary.json").read_text())
    fingerprints, historic, baseline_digest = installed_java.checked_baseline(
        pathlib.Path(os.environ["XCAMP_BASELINE_RECEIPT"]), pin, tracked, [sc.id for sc in SCENARIOS], "fineract")
    canaries = json.loads(installed_java.private_file(pathlib.Path(os.environ["XCAMP_CANARY_FILE"])).read_text())
    keys = ("authorization-header", "cookie-header", "query-token", "json-body-password", "env-var")
    if (not isinstance(canaries, dict) or any(not isinstance(canaries.get(k), str) or not canaries[k] for k in keys)
            or len({canaries[k] for k in keys}) != len(keys)):
        raise ValueError("distinct private canaries unavailable")
    launch = (cli, "run", "--project-dir", str(SRC), "--java-agent", agent,
              "--app-package", recording_evidence.APP_PACKAGE, "--source-root", recording_evidence.SOURCE_ROOT,
              "--capture-depth", "standard", "--")
    STATE.clear()
    receipt = xinstr.run_instrumented(
        project="fineract", pin={**pin, "installedPackage": package, "trackedBaselineMatches": historic,
                                 "runBoundBaselineReceiptSha256": baseline_digest},
        make_stack=lambda run_id: make_stack(run_id, launch), scenarios=SCENARIOS, out_dir=out / "capture",
        norm_extra=NORM, expectations=recording_evidence.EXPECT, xtrace=cli, project_dir=SRC, data_home=data,
        adaptations=CAMP["configAdaptations"], canaries=canaries, baseline_receipt=None, extra_canary_paths=[],
        baseline_fingerprints=fingerprints,
        harness_files=[HERE, pathlib.Path(recording_evidence.__file__), pathlib.Path(installed_java.__file__),
                       pathlib.Path(xinstr.__file__), pathlib.Path(xinstr.boundary_diagnostics.__file__),
                       pathlib.Path(fineract_phase_evidence.__file__),
                       pathlib.Path(xcamp.__file__)],
        ordered_campaign=xinstr.OrderedCampaign(recording_evidence.PRE_DISPATCH, recording_evidence.inject_probes,
                                                recording_evidence.judge, fineract_phase=True))
    # Final sink scans are performed after this process closes all capture outputs.
    return 0 if receipt["result"] == "recorded" and all(historic.values()) else 1


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:] == ["instrumented"]:
        sys.exit(instrumented())
    sys.exit(xcamp.main_cli("fineract", build, baseline, PROJ))
