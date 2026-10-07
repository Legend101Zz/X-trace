#!/usr/bin/env python3
"""JHipster sample app campaign harness (PREPARATION, uninstrumented baseline). See petclinic/harness/run.py for usage."""
import concurrent.futures
import pathlib
import re
import sys
import json

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "lib"))
import xcamp  # noqa: E402

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
        app_args=["--spring.profiles.active=prod", "--server.port={APPPORT}"],
        env={"SPRING_DATASOURCE_URL": "jdbc:postgresql://{DBHOST}:{DBPORT}/jhipsterSampleApplication",
             "SPRING_DATASOURCE_USERNAME": "jhipsterSampleApplication", "SPRING_DATASOURCE_PASSWORD": "campaign-synthetic",
             "JHIPSTER_SECURITY_AUTHENTICATION_JWT_BASE64_SECRET": JWT_SECRET},
        java_opts=["-Xmx1g"], db_name="jhipsterSampleApplication", db_user="jhipsterSampleApplication",
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
    return xcamp.run_baseline(project="jhipster", pin={**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR),
                              "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
                              "postgresImageDigest": xcamp.POSTGRES_DIGEST, "jdkImage": IMAGE},
                              make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=[],
                              adaptations=CAMP["configAdaptations"], harness_files=[HERE])


if __name__ == "__main__":
    sys.exit(xcamp.main_cli("jhipster", build, baseline, PROJ))
