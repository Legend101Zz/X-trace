#!/usr/bin/env python3
"""Spring Petclinic campaign harness (PREPARATION, uninstrumented baseline).

  XTRACE_CAMPAIGN_ROOT=<private root> python3 run.py build      # build jar in ephemeral JDK17 container
  XTRACE_CAMPAIGN_ROOT=<private root> python3 run.py baseline    # one reset-to-finish baseline run
  XTRACE_CAMPAIGN_ROOT=<private root> python3 run.py compare     # fingerprint stability across baseline-N dirs

Stack: eclipse-temurin:17 (java -jar) + postgres:18.3 (profile `postgres`, upstream's own
synthetic seed from db/postgres/data.sql), all on a private Docker network, prefix xtrace-camp-.
"""
import concurrent.futures
import json
import os
import pathlib
import re
import shlex
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "lib"))
import xcamp  # noqa: E402
import xinstr  # noqa: E402

CAMP, PROJ, SRC = xcamp.load_campaign(__file__)
HERE = pathlib.Path(__file__).resolve()
JAR = SRC / CAMP["build"]["artifact"]
IMAGE = CAMP["runtime"]["buildImage"]


def build() -> int:
    xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"])
    xcamp.docker("volume", "create", "xtrace-camp-m2")
    # Config-only adaptation: checkstyle/spring-javaformat are source-style gates, skipped to avoid
    # a lint dependency fetch; tests skipped (preparation, not acceptance). Logs live outside src/.
    rc = xcamp.docker_build("petclinic", SRC, IMAGE,
        "./mvnw -B -ntp -DskipTests -Dcheckstyle.skip=true -Dspring-javaformat.skip=true package",
        {"xtrace-camp-m2": "/root/.m2"}, PROJ / "work" / "build.log")
    if rc == 0:
        print("jar sha256", xcamp.sha256_file(JAR))
    return rc


def make_stack(run_id: str) -> xcamp.Stack:
    return xcamp.Stack(
        project="petclinic", jdk_image=IMAGE, jar=JAR, run_id=run_id, app_port=8080,
        app_args=["--server.port={APPPORT}"],
        env={"SPRING_PROFILES_ACTIVE": "postgres", "POSTGRES_URL": "jdbc:postgresql://{DBHOST}:{DBPORT}/petclinic",
             "POSTGRES_USER": "petclinic", "POSTGRES_PASS": "petclinic"},
        java_opts=["-Xmx768m"], db_name="petclinic", db_user="petclinic", db_password="petclinic",
        ready_path="/actuator/health", ready_ok=lambda st, body: st == 200 and '"UP"' in body)


def owner_form(first, last, tel="6085550100", addr="1 Synthetic Way", city="Testville"):
    return {"firstName": first, "lastName": last, "address": addr, "city": city, "telephone": tel}


OWNER_SQL = ("select first_name,last_name,address,city,telephone from owners "
             "where last_name like '{p}%' order by last_name,first_name")
ID_NORM = [(r"/owners/\d+", "/owners/<ID>")]
# The upstream visit form renders `min=<tomorrow>` (today + 1 day) on every re-render, so the rejected past-dated visit page
# changes with the calendar. Root cause of the pet-and-visit-flow fingerprint drift (2026-10-09); normalized, not hidden.
DATE_NORM = [(r'min="\d{4}-\d{2}-\d{2}"', 'min="<TOMORROW>"')]
STATE: dict = {}


def s_search(c):
    r = c.http("GET", "/owners?lastName=Davis")
    c.check("200 list of two Davis owners", r["status"] == 200 and r["text"].count("Davis") >= 2, r["text"][:80])
    c.sql("seed-davis", OWNER_SQL.format(p="Davis"))
    c.check("db has exactly two Davis rows", len(c.db["seed-davis"]) == 2)
    r = c.http("GET", "/vets", headers={"Accept": "application/json"})
    c.check("vets JSON lists seeded vets", r["status"] == 200 and "Leary" in r["text"])


def s_create(c):
    r = c.http("POST", "/owners/new", form=owner_form("Ada", "Campaign"))
    loc = xcamp.loc_path(r["headers"].get("location", ""))
    c.check("302 redirect to new owner", r["status"] == 302 and re.fullmatch(r"/owners/\d+", loc) is not None, loc)
    STATE["owner_path"] = loc
    r2 = c.http("GET", loc or "/owners/11")
    c.check("owner page shows created data", r2["status"] == 200 and "Campaign" in r2["text"] and "Testville" in r2["text"])
    c.sql("created-owner", OWNER_SQL.format(p="Campaign"))
    c.check("db has the created owner", len(c.db["created-owner"]) == 1)


def s_validation(c):
    r = c.http("POST", "/owners/new", form=owner_form("", "Invalid", tel="abc"))
    c.check("200 form re-rendered with errors", r["status"] == 200 and "has-error" in r["text"] or "must not be blank" in r["text"] or "Telephone" in r["text"])
    c.check("no redirect", "location" not in r["headers"])
    c.sql("invalid-owner-rows", OWNER_SQL.format(p="Invalid"))
    c.check("db unchanged by invalid submit", c.db["invalid-owner-rows"] == [])


def s_pet_visit(c):
    path = STATE["owner_path"]
    r = c.http("POST", f"{path}/pets/new", form={"name": "Rex", "birthDate": "2020-01-02", "type": "dog"}, norm=ID_NORM)
    c.check("pet created 302", r["status"] == 302, str(r["status"]))
    dup = c.http("POST", f"{path}/pets/new", form={"name": "Rex", "birthDate": "2020-01-02", "type": "dog"}, label="duplicate pet", norm=ID_NORM)
    c.check("duplicate pet name rejected (200 form)", dup["status"] == 200 and "already in use" in dup["text"])
    c.sql("pet-before-visit", "select p.name,p.birth_date::text,t.name from pets p join types t on t.id=p.type_id "
          "join owners o on o.id=p.owner_id where o.last_name='Campaign' order by p.name")
    pet_id = c.stack.psql("select p.id from pets p join owners o on o.id=p.owner_id where o.last_name='Campaign' and p.name='Rex'")[0][0]
    past = c.http("POST", f"{path}/pets/{pet_id}/visits/new", form={"date": "2020-01-05", "description": "past visit"},
                  label="past-dated visit", norm=ID_NORM + [(r"/pets/\d+", "/pets/<ID>")] + DATE_NORM)
    c.check("past-dated visit rejected (200 form, no redirect)", past["status"] == 200 and "location" not in past["headers"])
    r = c.http("POST", f"{path}/pets/{pet_id}/visits/new", form={"date": "2099-01-05", "description": "synthetic checkup"},
               norm=ID_NORM + [(r"/pets/\d+", "/pets/<ID>")])
    c.check("visit created 302", r["status"] == 302, str(r["status"]))
    c.sql("visit-rows", "select v.visit_date::text,v.description from visits v join pets p on p.id=v.pet_id "
          "join owners o on o.id=p.owner_id where o.last_name='Campaign' order by v.visit_date")
    c.check("visit persisted", c.db["visit-rows"] == [["2099-01-05", "synthetic checkup"]])
    page = c.http("GET", path, norm=ID_NORM)
    c.check("owner page shows pet and visit", "Rex" in page["text"] and "synthetic checkup" in page["text"])


def s_edit(c):
    path = STATE["owner_path"]
    r = c.http("POST", f"{path}/edit", form=owner_form("Ada", "Campaign", city="Editburg", tel="6085550101"), norm=ID_NORM)
    c.check("edit redirects 302", r["status"] == 302, str(r["status"]))
    page = c.http("GET", path, norm=ID_NORM)
    c.check("edited city visible on next request", "Editburg" in page["text"])
    c.sql("edited-owner", OWNER_SQL.format(p="Campaign"))
    c.check("db reflects edit", c.db["edited-owner"][0][3] == "Editburg")


def s_missing(c):
    r = c.http("GET", "/owners/999999")
    c.check("missing owner -> 500 error page", r["status"] == 500, str(r["status"]))
    c.sql("no-such-owner", "select count(*) from owners where id=999999")
    c.check("db has no such owner", c.db["no-such-owner"] == [["0"]])


def s_crash(c):
    r = c.http("GET", "/oups")
    c.check("/oups -> 500", r["status"] == 500, str(r["status"]))


def s_concurrent(c):
    c.norm_extra.append((r"/owners/\d+", "/owners/<ID>"))
    c.norm_extra.append((r'href="\d+/', 'href="<ID>/'))  # page emits relative links like 15/edit
    seeded = {1: "George Franklin", 2: "Betty Davis", 3: "Eduardo Rodriquez", 4: "Harold Davis", 5: "Peter McTavish",
              6: "Jean Coleman", 7: "Jeff Black", 8: "Maria Escobito", 9: "David Schroeder", 10: "Carlos Estaban"}

    def read(i):
        oid = (i % 10) + 1
        r = c.http("GET", f"/owners/{oid}", label=f"read owner {oid} #{i}")
        first, last = seeded[oid].split()
        return first in r["text"] and last in r["text"] and all(v.split()[1] not in r["text"] for k, v in seeded.items() if v.split()[1] != last and v.split()[1] != "Black")

    def create(i):
        name = f"Parallel{i:02d}"
        r = c.http("POST", "/owners/new", form=owner_form("Conc", name), label=f"create {name}")
        loc = xcamp.loc_path(r["headers"].get("location", ""))
        r2 = c.http("GET", loc, label=f"reopen {name}") if loc else {"text": ""}
        return r["status"] == 302 and name in r2["text"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        reads = list(pool.map(read, range(30)))
        creates = list(pool.map(create, range(10)))
    c.check("30 concurrent reads each show only their own owner", all(reads))
    c.check("10 concurrent creates each reopen their own record", all(creates))
    c.sql("parallel-owners", "select first_name,last_name from owners where last_name like 'Parallel%' order by last_name")
    c.check("db has 10 distinct parallel owners", len(c.db["parallel-owners"]) == 10)


SCENARIOS = [
    xcamp.Scenario("search-seeded", "Owner search + vets JSON over seeded database", "business", s_search),
    xcamp.Scenario("owner-create-roundtrip", "Create owner, redirect, reopen, DB row", "db-write-read", s_create),
    xcamp.Scenario("owner-validation-error", "Invalid owner rejected, DB unchanged", "validation", s_validation),
    xcamp.Scenario("pet-and-visit-flow", "Add pet (+duplicate rejection) and visit, multi-table write", "business", s_pet_visit),
    xcamp.Scenario("owner-edit", "Edit owner, effect visible on next request and in DB", "db-write-read", s_edit),
    xcamp.Scenario("missing-owner-error", "Unknown owner id raises -> 500 error page", "error", s_missing),
    xcamp.Scenario("controller-crash-path", "/oups deliberate RuntimeException", "error", s_crash),
    xcamp.Scenario("concurrent-isolation", "30 parallel reads + 10 parallel creates; no cross-association", "concurrency", s_concurrent),
]


def baseline(out):
    return xcamp.run_baseline(project="petclinic", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR),
                              "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                              "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
                              make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=[],
                              adaptations=CAMP["configAdaptations"], harness_files=[HERE])


# Per-scenario expectations on the RECORDINGS (route, HTTP outcome, controller/repository frames, source identity).
# Petclinic has no service layer: its controllers call Spring Data repositories directly, so no `service` frame is required.
OWN = {"controller": "OwnerController", "repository": "OwnerRepository"}
EXPECT = {
    "search-seeded": [
        {"method": "GET", "route": "/owners", "status": 200, "layers": ["controller", "repository"], "layerHints": OWN},
        {"method": "GET", "route": "/vets", "status": 200, "layers": ["controller", "repository"],
         "layerHints": {"controller": "VetController", "repository": "VetRepository"}}],
    "owner-create-roundtrip": [
        {"method": "POST", "route": "/owners/new", "status": 302, "layers": ["controller", "repository"], "layerHints": OWN},
        {"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": ["controller", "repository"], "layerHints": OWN}],
    "owner-validation-error": [
        {"method": "POST", "route": "/owners/new", "status": 200, "layers": ["controller"], "layerHints": OWN}],
    "pet-and-visit-flow": [
        {"method": "POST", "route": "/owners/{ownerId}/pets/new", "status": 302, "layers": ["controller", "repository"],
         "layerHints": {"controller": "PetController", "repository": "OwnerRepository"}},
        {"method": "POST", "route": "/owners/{ownerId}/pets/{petId}/visits/new", "status": 302, "layers": ["controller", "repository"],
         "layerHints": {"controller": "VisitController", "repository": "OwnerRepository"}}],
    "owner-edit": [
        {"method": "POST", "route": "/owners/{ownerId}/edit", "status": 302, "layers": ["controller", "repository"], "layerHints": OWN}],
    "missing-owner-error": [
        {"method": "GET", "route": "/owners/{ownerId}", "status": 500, "layers": ["controller", "repository"], "layerHints": OWN}],
    "controller-crash-path": [
        {"method": "GET", "route": "/oups", "status": 500, "layers": ["controller"], "layerHints": {"controller": "CrashController"}}],
    "concurrent-isolation": [
        {"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": ["controller"], "layerHints": OWN, "minCount": 30},
        {"method": "POST", "route": "/owners/new", "status": 302, "layers": ["controller"], "layerHints": OWN, "minCount": 10}],
}


def instrumented() -> int:
    """One reset-to-finish run with the app launched by the PACKAGED `xtrace run`, then judged through the read API."""
    need = {k: os.environ.get(k, "") for k in ("XCAMP_XTRACE", "XCAMP_AGENT", "XCAMP_DATA_HOME")}
    missing = [k for k, v in need.items() if not v]
    if missing or os.environ.get("XCAMP_APP_MODE") != "host":
        print("instrumented needs XCAMP_APP_MODE=host and " + ", ".join(missing or ["(all set)"]))
        return 2
    xtrace, agent = need["XCAMP_XTRACE"], need["XCAMP_AGENT"]
    os.environ["XCAMP_LAUNCH_PREFIX"] = " ".join(shlex.quote(x) for x in
        [xtrace, "run", "--project-dir", str(SRC), "--java-agent", agent, "--"])
    canaries = None
    if os.environ.get("XCAMP_CANARY_FILE"):
        canaries = json.loads(pathlib.Path(os.environ["XCAMP_CANARY_FILE"]).read_text())
    n = 1
    while (PROJ / f"instrumented-{n}").exists():
        n += 1
    out = PROJ / f"instrumented-{n}"
    baseline_receipt = pathlib.Path(os.environ["XCAMP_BASELINE_RECEIPT"]) if os.environ.get("XCAMP_BASELINE_RECEIPT") else None
    r = xinstr.run_instrumented(
        project="petclinic", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR), "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                                  "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
        make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=[], expectations=EXPECT, xtrace=xtrace,
        project_dir=SRC, data_home=pathlib.Path(need["XCAMP_DATA_HOME"]), adaptations=CAMP["configAdaptations"],
        canaries=canaries, baseline_receipt=baseline_receipt, harness_files=[HERE, pathlib.Path(xinstr.__file__)],
        extra_canary_paths=[("POST", "/owners/new")])
    print(json.dumps({"result": r["result"], "api": r["api"], "problemClasses": r["problemClasses"]}))
    return 0 if r["result"] == "recorded" else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "instrumented":
        sys.exit(instrumented())
    sys.exit(xcamp.main_cli("petclinic", build, baseline, PROJ))
