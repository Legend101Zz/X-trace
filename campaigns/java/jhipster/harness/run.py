#!/usr/bin/env python3
"""Pinned JHipster backend workload, baseline and installed instrumented run."""
import concurrent.futures
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "lib"))
import xcamp  # noqa: E402
import xinstr  # noqa: E402
import evidence  # noqa: E402
import private_diagnostic  # noqa: E402

CAMP, PROJ, SRC = xcamp.load_campaign(__file__)
HERE = pathlib.Path(__file__).resolve()
JAR = SRC / CAMP["build"]["artifact"]
IMAGE = CAMP["runtime"]["buildImage"]
POSTGRES_IMAGE = CAMP["runtime"]["databaseImage"]
POSTGRES_DIGEST = POSTGRES_IMAGE.split("@", 1)[1]
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


def make_stack(run_id: str, launch_prefix: tuple[str, ...] = ()) -> xcamp.Stack:
    return xcamp.Stack(
        project="jhipster", jdk_image=IMAGE, jar=JAR, run_id=run_id, app_port=8080,
        # Prod suppresses Spring INFO. Boot 4 reports the actual port only after bind;
        # retain this specific signal for port-zero discovery in both owned host runs.
        app_args=["--spring.profiles.active=prod", "--server.port={APPPORT}", "--server.address={BINDADDR}",
                  "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"],
        env={"SPRING_DATASOURCE_URL": "jdbc:postgresql://{DBHOST}:{DBPORT}/jhipsterSampleApplication",
             "SPRING_DATASOURCE_USERNAME": "jhipsterSampleApplication", "SPRING_DATASOURCE_PASSWORD": "campaign-synthetic",
             "JHIPSTER_SECURITY_AUTHENTICATION_JWT_BASE64_SECRET": JWT_SECRET},
        java_opts=["-Xmx1g"], db_name="jhipsterSampleApplication", db_user="jhipsterSampleApplication",
        db_password="campaign-synthetic", db_image=POSTGRES_IMAGE, launch_prefix=launch_prefix,
        ready_path="/management/health", ready_timeout=360,
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


def source_pin():
    pin = {**CAMP["upstream"], "jarSha256": xcamp.sha256_file(JAR),
           "git": xcamp.git_pin_check(SRC, CAMP["upstream"]["sha"]),
           "postgresImageDigest": POSTGRES_DIGEST, "jdkImage": IMAGE}
    if os.environ.get("XCAMP_APP_MODE") == "host":
        pin["hostJava"] = host_java_identity()
        pin["hostRunBindingSha256"] = hosted_run_binding()
    return pin


def host_java_identity():
    """Observe the configured host executable and runtime with the stack's option policy."""
    java = pathlib.Path(os.environ["XCAMP_JAVA"])
    if not java.is_absolute():
        raise ValueError("XCAMP_JAVA must identify the host JDK executable by absolute path")
    java = java.resolve(strict=True)
    env = {k: v for k, v in os.environ.items() if k not in xcamp.JAVA_OPTIONS_ENV}
    result = private_diagnostic.run_captured([str(java), "-XshowSettings:properties", "-version"], env=env,
                                             text=True, timeout=30, label="host-java")
    names = {"java.specification.version", "java.runtime.version", "java.vm.name", "java.vendor", "os.name", "os.arch"}
    properties = {}
    for line in ((result.stdout or "") + (result.stderr or "")).splitlines():
        key, _, val = line.strip().partition(" = ")
        if key in names and 0 < len(val) <= 120 and val.isprintable():
            properties[key] = val
    if (result.returncode != 0 or properties.keys() != names
            or properties["java.specification.version"] != str(CAMP["runtime"]["jdk"])):
        raise ValueError("JHipster host runtime did not report the pinned Java major")
    return {"properties": properties, "executableSha256": xcamp.sha256_file(java),
            "jdkReleaseSha256": xcamp.sha256_file(java.parents[1] / "release")}


def hosted_run_binding():
    """Bind the job IDs to the Linux boot where baseline and instrumented workloads run."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None
    fields = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
    identity = {k: os.environ.get(k) for k in fields}
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not all(identity.values()) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id):
        raise ValueError("GitHub job and Linux boot identity unavailable")
    return xcamp.sha256_json({**identity, "bootId": boot_id})


def baseline(out):
    if os.environ.get("XCAMP_LAUNCH_PREFIX"):
        raise ValueError("JHipster baseline requires an uninstrumented JVM")
    STATE.clear()
    return xcamp.run_baseline(project="jhipster", pin=source_pin(),
                              make_stack=make_stack, scenarios=SCENARIOS, out_dir=out, norm_extra=[],
                              adaptations=CAMP["configAdaptations"], harness_files=[HERE])


def private_dir(path):
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("campaign directory must be owned by the runner and private")
    return path


def private_json_path(path):
    path = path.resolve(strict=True)
    private_dir(path.parent)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("campaign input must be an owner-only file")
    return path


def package_inventory(current, manifest):
    files = {}
    for row in manifest["files"]:
        rel = row["path"]
        path = pathlib.PurePosixPath(rel)
        digest, size = row["sha256"], row["size"]
        if (path.is_absolute() or not path.parts or ".." in path.parts or path.as_posix() != rel
                or rel in files or not xcamp.HEX64.fullmatch(digest) or type(size) is not int or size < 0
                or not re.fullmatch(r"[^\x00-\x1f\x7f\\]+", rel)):
            raise ValueError("invalid campaign package manifest inventory")
        files[rel] = (digest, size)
    installed = {}
    for directory, dirs, names in os.walk(current, followlinks=False):
        folder = pathlib.Path(directory)
        if any((folder / d).is_symlink() for d in dirs):
            raise ValueError("symbolic directory in installed package")
        for name in names:
            path = folder / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("non-regular entry in installed package")
            installed[path.relative_to(current).as_posix()] = info.st_size
    expected_sizes = {rel: size for rel, (_, size) in files.items()}
    return files, installed, expected_sizes


def installed_package(prefix, archive, package_sha, source_sha):
    """Bind the hosted job's verified archive and installed payload to their actual bytes."""
    if not xcamp.HEX64.fullmatch(package_sha) or xcamp.sha256_file(archive) != package_sha:
        raise ValueError("campaign package archive digest mismatch")
    rel_manifest = "share/xtrace/PACKAGE-MANIFEST.json"
    rel_inventory = "share/xtrace/payload.sha256"
    metadata = {}
    tops = set()
    with tarfile.open(archive, mode="r|gz") as tar:
        for member in tar:
            top, _, rel = member.name.partition("/")
            if rel not in (rel_manifest, rel_inventory):
                continue
            if rel in metadata or not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("campaign package archive metadata is ambiguous or invalid")
            tops.add(top)
            with tar.extractfile(member) as stream:
                metadata[rel] = stream.read()
    if len(tops) != 1 or set(metadata) != {rel_manifest, rel_inventory}:
        raise ValueError("campaign package archive metadata unavailable")
    current = (prefix / "current").resolve(strict=True)
    root = (prefix / "versions").resolve(strict=True)
    if current.parent != root or root.parent != prefix:
        raise ValueError("installed version is outside the verified prefix")
    manifest = json.loads(metadata[rel_manifest])
    if (manifest.get("schema") != "xtrace-package-manifest/1" or manifest.get("platform") != "linux-x86_64"
            or tops != {f"xtrace-{manifest.get('version')}-linux-x86_64"}
            or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or manifest.get("sourceCommit") != source_sha):
        raise ValueError("installed package source revision or platform mismatch")
    xtrace = prefix / "bin/xtrace"
    agent = current / "share/xtrace/packs/java/agent/xtrace-java-agent.jar"
    analyzer = current / "share/xtrace/analyzers/java/bin/xtrace-java-static"
    if xtrace.resolve(strict=True) != current / "bin/xtrace" or not all(os.access(p, os.X_OK) for p in (xtrace, analyzer)):
        raise ValueError("installed campaign CLI or analyzer unavailable")
    files, installed, expected_sizes = package_inventory(current, manifest)
    expected_sizes[rel_manifest] = len(metadata[rel_manifest])
    if installed != expected_sizes or any((current / rel).read_bytes() != data for rel, data in metadata.items()):
        raise ValueError("installed package paths or metadata differ from the archive manifest")
    inventory_sha = xcamp.sha256_bytes(metadata[rel_inventory])
    expected_rows = {rel: digest for rel, (digest, _) in files.items() if rel != rel_inventory}
    payload_rows = {}
    for line in metadata[rel_inventory].decode().splitlines():
        row = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if row is None or row[2] in payload_rows:
            raise ValueError("invalid campaign package checksum inventory")
        payload_rows[row[2]] = row[1]
    if payload_rows != expected_rows or files[rel_inventory][0] != inventory_sha:
        raise ValueError("installer checksum inventory does not cover the archive manifest")
    installer = current / "install.sh"
    if xcamp.sha256_file(installer) != expected_rows["install.sh"]:
        raise ValueError("installed verifier differs from the archive manifest")
    verification = private_diagnostic.run_captured(["sh", str(installer), "verify", "--prefix", str(prefix)],
                                                   env=dict(os.environ), text=False, timeout=120,
                                                   label="installed-payload-verify")
    if verification.returncode != 0:
        raise ValueError("installer did not verify the complete package payload")
    return str(xtrace), str(agent), {
        "archiveSha256": package_sha, "sourceCommit": source_sha,
        "payloadInventorySha256": inventory_sha, "payloadFilesVerified": len(payload_rows),
        "cliSha256": expected_rows["bin/xtrace"],
        "agentSha256": expected_rows[agent.relative_to(current).as_posix()],
        "analyzerLauncherSha256": expected_rows[analyzer.relative_to(current).as_posix()],
    }


def checked_baseline(path, pin):
    """Require the passing baseline from this job, Linux boot, JVM and built JAR."""
    raw = path.read_bytes()
    baseline_doc = json.loads(raw)
    tracked = json.loads((HERE.parents[1] / "baseline-summary.json").read_text())
    baseline_pin = baseline_doc.get("pin", {})
    tracked_pin = tracked.get("pin", {})
    expected_ids = [scenario.id for scenario in SCENARIOS]
    rows = baseline_doc.get("scenarios", [])
    ref = tracked.get("scenarios", [])
    observed_java = pin["hostJava"]["properties"]
    if (not pin.get("hostRunBindingSha256") or observed_java["os.name"] != "Linux" or observed_java["os.arch"] != "amd64"
            or baseline_doc.get("result") != "passed_baseline_only" or baseline_doc.get("instrumented") is not False
            or baseline_doc.get("project") != "jhipster" or baseline_doc.get("appMode") != "host"
            or any(baseline_pin.get(k) != pin[k] for k in (
                "sha", "git", "jarSha256", "postgresImageDigest", "hostJava", "hostRunBindingSha256"))
            or any(tracked_pin.get(k) != pin[k] for k in ("sha", "postgresImageDigest"))
            or [row.get("id") for row in rows] != expected_ids or [row.get("id") for row in ref] != expected_ids
            or any(row.get("passed") is not True or not row.get("checks")
                   or len(row.get("requests", [])) != expected["requests"] or len(row["checks"]) != expected["checks"]
                   or any(check.get("passed") is not True for check in row["checks"])
                   or not xcamp.HEX64.fullmatch(row.get("semanticEffectFingerprint", "")) for row, expected in zip(rows, ref))):
        raise ValueError("baseline must be complete and passing with this job, boot, JVM, JAR, source and database")
    fingerprints = {row["id"]: row["semanticEffectFingerprint"] for row in rows}
    tracked_matches = {row["id"]: fingerprints[row["id"]] == row["semanticEffectFingerprint"] for row in ref}
    return fingerprints, tracked_matches, xcamp.sha256_bytes(raw)


def instrumented():
    required = ("XCAMP_INSTALL_PREFIX", "XCAMP_PACKAGE_ARCHIVE", "XCAMP_PACKAGE_SHA256", "XCAMP_PRODUCT_SHA",
                "XCAMP_JAVA", "XCAMP_DATA_HOME", "XCAMP_BASELINE_RECEIPT", "XCAMP_CANARY_FILE", "TMPDIR")
    missing = [name for name in required if not os.environ.get(name)]
    if (missing or os.environ.get("XCAMP_APP_MODE") != "host" or xcamp.PLATFORM != "linux/amd64"
            or os.environ.get("XCAMP_LAUNCH_PREFIX")):
        print("instrumented requires host mode with XCAMP_PLATFORM=linux/amd64 and no inherited launch prefix",
              file=sys.stderr)
        if missing:
            print("Missing environment: " + ", ".join(missing), file=sys.stderr)
        return 2
    try:
        private_root = private_dir(pathlib.Path(os.environ["XTRACE_CAMPAIGN_ROOT"]))
        project_root = private_dir(PROJ)
        if not project_root.is_relative_to(private_root) or SRC.resolve(strict=True).parent != project_root:
            raise ValueError("JHipster checkout and receipts must remain under the private campaign root")
        private_dir(pathlib.Path(os.environ["TMPDIR"]))
        data_home = private_dir(pathlib.Path(os.environ["XCAMP_DATA_HOME"]))
        baseline_path = private_json_path(pathlib.Path(os.environ["XCAMP_BASELINE_RECEIPT"]))
        canary_path = private_json_path(pathlib.Path(os.environ["XCAMP_CANARY_FILE"]))
        canaries = json.loads(canary_path.read_text())
        canary_keys = ("authorization-header", "cookie-header", "query-token", "json-body-password", "env-var")
        if (not isinstance(canaries, dict) or any(not isinstance(canaries.get(k), str) or not canaries[k]
                                                  for k in canary_keys)
                or len({canaries[k] for k in canary_keys}) != len(canary_keys)):
            raise ValueError("campaign canary file lacks distinct values for the exercised surfaces")
        prefix = pathlib.Path(os.environ["XCAMP_INSTALL_PREFIX"]).resolve(strict=True)
        xtrace, agent, package = installed_package(prefix, pathlib.Path(os.environ["XCAMP_PACKAGE_ARCHIVE"]),
                                                    os.environ["XCAMP_PACKAGE_SHA256"], os.environ["XCAMP_PRODUCT_SHA"])
        pin = source_pin()
        baseline_fingerprints, tracked_matches, baseline_digest = checked_baseline(baseline_path, pin)
    except (OSError, subprocess.SubprocessError, tarfile.TarError, TypeError, ValueError, KeyError, RuntimeError) as exc:
        # File and process errors may embed runner-local paths or sensitive input.
        private_preparation_traceback()
        print(f"JHipster instrumented preparation failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    launch = (xtrace, "run", "--project-dir", str(SRC), "--java-agent", agent, "--app-package", evidence.APP_PACKAGE,
              "--source-root", evidence.SOURCE_ROOT, "--capture-depth", "standard", "--")
    STATE.clear()
    n = 1
    while (PROJ / f"instrumented-{n}").exists():
        n += 1
    receipt = xinstr.run_instrumented(
        project="jhipster", pin={**pin, "installedPackage": package, "trackedBaselineMatches": tracked_matches,
                                 "runBoundBaselineReceiptSha256": baseline_digest},
        make_stack=lambda run_id: make_stack(run_id, launch), scenarios=SCENARIOS, out_dir=project_root / f"instrumented-{n}",
        norm_extra=[], expectations=evidence.EXPECT, xtrace=xtrace, project_dir=SRC, data_home=data_home,
        adaptations=CAMP["configAdaptations"], canaries=canaries, baseline_receipt=None, extra_canary_paths=[],
        baseline_fingerprints=baseline_fingerprints,
        harness_files=[HERE, pathlib.Path(evidence.__file__), pathlib.Path(xinstr.__file__), pathlib.Path(xcamp.__file__),
                       pathlib.Path(xinstr.boundary_diagnostics.__file__)],
        ordered_campaign=xinstr.OrderedCampaign(evidence.PRE_DISPATCH, evidence.inject_probes, evidence.judge))
    print(json.dumps({"result": receipt["result"], "workloadsPassed": receipt["workloadsPassed"],
                      "sameRunnerBaselineMatched": receipt["baselineMatched"],
                      "trackedBaselineMatched": all(tracked_matches.values()), "problemClasses": receipt["problemClasses"]}))
    return 0 if receipt["result"] == "recorded" and all(tracked_matches.values()) else 1


def private_preparation_traceback():
    """Retain setup diagnosis only in an explicitly opted-in owner-only file sink."""
    if os.environ.get("XCAMP_PRIVATE_PREPARATION_TRACEBACK") != "1":
        return
    try:
        info = os.fstat(sys.stderr.fileno())
        if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077:
            traceback.print_exc(file=sys.stderr)
    except (OSError, ValueError):
        pass


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1:] == ["instrumented"]:
        sys.exit(instrumented())
    sys.exit(xcamp.main_cli("jhipster", build, baseline, PROJ))
