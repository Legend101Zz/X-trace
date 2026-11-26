"""Focused hosted proof of one installed CLI lifecycle on an actual Spring recording."""
import contextlib
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid

REPO = Path.cwd()
ROOT = Path(os.environ["RUNNER_TEMP"]) / "xp121"
PRIVATE = ROOT / "private"
LOG = ROOT / "logs"
PUBLIC = ROOT / "public/counts.json"
PROJECT = PRIVATE / "project"
PREFIX = PRIVATE / "prefix"
PAYLOAD = PREFIX / "current"
CLI = PREFIX / "bin/xtrace"
AGENT = "share/xtrace/packs/java/agent/xtrace-java-agent.jar"
ANALYZER = "share/xtrace/analyzers/java/bin/xtrace-java-static"
MANIFEST = "share/xtrace/PACKAGE-MANIFEST.json"
PRODUCT = os.environ["PRODUCT"]
TREE = os.environ["PRODUCT_TREE"]
MERGE = "1c7a62cf2ed52450edbe50a7ffdd8e389ae7c7ab"
EXERCISE = "7d1bdf4b1fa114a6381cc9cf4cef973b8a51c2c3"
ANALYZER_COMMIT = "f8a1f02f153013e467e34965c00748edb23e1626"
ENV = dict(os.environ, XTRACE_DATA_HOME=str(PRIVATE / "data"))
for name in ("XTRACE_JAVA_ANALYZER", "XTRACE_NODE_ANALYZER", "XTRACE_JAVA_AGENT", "XTRACE_JAVA_PACK",
             "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
    ENV.pop(name, None)
sys.path.insert(0, str(REPO / "campaigns/lib"))
import xcamp
import xinstr

STAGES = ("identity", "build-archive", "verify-dist", "verify-archive", "fresh-install", "verify-installed",
          "verify-installed-directory", "verify-payload", "build-spring", "initialize", "scan-controller",
          "read-catalog", "empty-recordings", "spring-ready", "ordinary-request", "complete-recording",
          "spring-stopped", "guard-listener", "observed-binding", "plan", "review", "deny-missing-consent",
          "approve", "restore-show", "stable-recording", "zero-connections", "owned-cleanup")
REPORT = dict(kind="installed-exercise-no-send", schemaVersion=1, releaseAcceptance=False,
              sourceFixtureRunId=45769503267, sourceFixtureProduct=EXERCISE, sourceSha=PRODUCT,
              sourceTree=TREE, wrapperSha=os.environ["GITHUB_SHA"], runId=int(os.environ["GITHUB_RUN_ID"]),
              status="failed", stage="identity", stages=dict.fromkeys(STAGES, "unreached"),
              commandExit=None, failure=None, archiveSha256=None, genuineRecordingCount=None,
              consentedItems=None, observedQueuedConnections=None)

def need(value):
    if not value:
        raise ValueError("proof condition failed")

def write():
    tmp = PUBLIC.with_suffix(".tmp")
    tmp.write_text(json.dumps(REPORT, sort_keys=True) + "\n")
    tmp.replace(PUBLIC)

@contextlib.contextmanager
def stage(name):
    need(name in STAGES and REPORT["stages"][name] == "unreached")
    REPORT.update(stage=name, commandExit=None)
    REPORT["stages"][name] = "attempted"
    write()
    yield
    REPORT["stages"][name] = "passed"
    write()

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO).decode().strip()

def identity():
    need(all(re.fullmatch("[0-9a-f]{40}", s) for s in (PRODUCT, TREE, REPORT["wrapperSha"])))
    need(git("rev-parse", "HEAD") == PRODUCT and git("rev-parse", "HEAD^{tree}") == TREE)
    need(git("show", "-s", "--format=%P", MERGE).split() == [EXERCISE, ANALYZER_COMMIT])
    need(git("rev-parse", MERGE + "^{tree}") == "4f4b97dbd13663a23cc1de5b3f5ed6e4c247ff1c")
    # The coordinator supplies one reviewed installer-only correction over the fixed integration.
    need(git("show", "-s", "--format=%P", PRODUCT) == MERGE)
    expected_patch = os.environ["INSTALLER_PATCH_SHA256"]
    patch = subprocess.check_output(["git", "diff", "--full-index", "--binary", MERGE, PRODUCT])
    need(patch and re.fullmatch("[0-9a-f]{64}", expected_patch)
         and hashlib.sha256(patch).hexdigest() == expected_patch)
    need(not git("status", "--porcelain", "--untracked-files=all"))

def command(label, argv, *, cwd=REPO, timeout=180, expected=0, read_json=False):
    out, err = LOG / (label + ".out"), LOG / (label + ".err")
    with out.open("wb") as stdout, err.open("wb") as stderr:
        result = subprocess.run([str(item) for item in argv], env=ENV, cwd=cwd, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr, timeout=timeout, check=False)
    REPORT["commandExit"] = result.returncode
    if expected == "refused":
        need(result.returncode != 0 and out.stat().st_size == 0)
        out = err
    else:
        need(result.returncode == expected)
    if read_json:
        need(0 < out.stat().st_size <= 8 << 20)
        return json.loads(out.read_bytes())

def package():
    platform = PRIVATE / "dist/linux-x86_64"
    with stage("build-archive"):
        command("build", ["python3", "-B", "packaging/build.py", "--platform", "linux-x86_64",
                          "--work", PRIVATE / "build", "--out", platform.parent], timeout=3300)
        archive, = platform.glob("*.tar.gz")
        need(archive.name == "xtrace-0.0.1-linux-x86_64.tar.gz")
        REPORT["archiveSha256"] = sha(archive)
    with stage("verify-dist"):
        command("distribution", ["sh", "packaging/install.sh", "verify-dist", platform])
    def verify(label, target):
        doc = command(label, ["python3", "-B", "packaging/verify_package.py", target,
                              "--repo", REPO, "--run-binary"], read_json=True)
        need(doc["ok"] is True and doc["package"]["sourceCommit"] == PRODUCT and doc["package"]["packTrust"] == "unsigned")
        rows = doc["checks"]
        need(rows and all(r["ok"] is True for r in rows)
             and [r["ok"] for r in rows if r["check"] == "java_analyzer_executable"] == [True])
    with stage("verify-archive"):
        verify("archive-check", archive)
        extracted = PRIVATE / "extracted"
        extracted.mkdir(mode=0o700)
        spec = importlib.util.spec_from_file_location("package_verifier", REPO / "packaging/verify_package.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        dist = verifier.resolve_root(archive, extracted)
    with stage("fresh-install"):
        need(not PREFIX.exists())
        command("install", ["sh", dist / "install.sh", "--prefix", PREFIX, "--data-home", ENV["XTRACE_DATA_HOME"]])
    with stage("verify-installed"):
        command("official-verify", ["sh", PAYLOAD / "install.sh", "verify", "--prefix", PREFIX])
    with stage("verify-installed-directory"):
        verify("installed-dir", PAYLOAD)
    with stage("verify-payload"):
        need(sha(archive) == REPORT["archiveSha256"] and CLI.resolve(strict=True) == (PAYLOAD / "bin/xtrace").resolve(strict=True))
        need((PAYLOAD / ANALYZER).stat().st_mode & 0o777 == 0o755)
        for path in (MANIFEST, "bin/xtrace", AGENT, ANALYZER):
            need(sha(dist / path) == sha(PAYLOAD / path))
        manifest = json.loads((PAYLOAD / MANIFEST).read_bytes())
        for row in manifest["files"]:
            if row["path"].startswith("share/xtrace/analyzers/java/"):
                need(sha(PAYLOAD / row["path"]) == row["sha256"])
        REPORT.update(manifestSha256=sha(PAYLOAD / MANIFEST), installedCliSha256=sha(CLI),
                      installedAnalyzerSha256=sha(PAYLOAD / ANALYZER), installedAgentSha256=sha(PAYLOAD / AGENT))
    with stage("build-spring"):
        command("fixture", ["./gradlew", "--no-daemon", "--dependency-verification", "strict", "fixtureBootJar"],
                cwd=REPO / "adapters/java", timeout=900)
        fixture = REPO / "adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar"
        need(fixture.is_file())
        REPORT["fixtureSha256"] = sha(fixture)
        identity()
        return fixture

class Owned:
    def __init__(self, name, args, extractor):
        self.name, self.args, self.extractor = name, args, extractor
        self.events = queue.Queue(maxsize=1)
        self.drained = False
    def __enter__(self):
        with (LOG / (self.name + ".stderr")).open("xb") as err:
            self.child = subprocess.Popen(list(map(str, self.args)), cwd=PROJECT, env=ENV, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=err, start_new_session=True)
        def drain():
            signaled = False
            try:
                with self.child.stdout as pipe, (LOG / (self.name + ".stdout")).open("xb") as out:
                    for line in iter(lambda: pipe.readline(65537), b""):
                        need(len(line) <= 65536 and out.tell() + len(line) <= 4 << 20)
                        out.write(line)
                        value = self.extractor(line.decode("utf-8", "replace"))
                        if value is not None and not signaled:
                            self.events.put(value)
                            signaled = True
                    self.drained = True
            finally:
                if not signaled:
                    self.events.put(None)
        self.drain = threading.Thread(target=drain, daemon=True)
        self.drain.start()
        return self
    def ready(self):
        value = self.events.get(timeout=60)
        need(value is not None and self.child.poll() is None)
        return value
    def stop(self):
        if self.child.poll() is None:
            self.child.terminate()
        try:
            code = self.child.wait(timeout=25)
        except subprocess.TimeoutExpired:
            if self.child.poll() is None:
                os.killpg(self.child.pid, signal.SIGKILL)
            self.child.wait(timeout=5)
            raise
        self.drain.join(timeout=5)
        need(not self.drain.is_alive() and self.drained)
        return code
    def __exit__(self, *exc):
        if self.child.poll() is None or self.drain.is_alive():
            self.stop()

def query(label, *args, expected=0, timeout=60):
    return command(label, [CLI, *args, "--project-dir", PROJECT], read_json=True, expected=expected, timeout=timeout)

def exactly_one_id(value):
    need(isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 7)
    return value

def recording():
    until = time.monotonic() + 30
    while time.monotonic() < until:
        rows = query("read-list", "recording", "list", "--limit", "200", timeout=max(0.01, until-time.monotonic()))
        need(rows["next_after"] is None and len(rows["recordings"]) <= 1)
        if not rows["recordings"] or rows["recordings"][0]["completion"] != "complete":
            continue
        rid = exactly_one_id(rows["recordings"][0]["recording_id"])
        doc = query("read-detail", "recording", "show", rid, "--limit", "200", timeout=max(0.01, until-time.monotonic()))
        events = doc["events"]
        need(doc["recording_id"] == rid and doc["completion"] == "complete" and doc["next_cursor"] is None
             and doc["incomplete_evidence"] == [] and doc["outcome"]["kind"] == "responded"
             and doc["outcome"]["httpStatus"] == 201 and 1 < len(events) <= 200)
        need(any(event.get("symbol") == "OrderController.create" and event.get("kind") == "recording_event_kind:frame_enter"
                 for event in events))
        ordered = [event["sequence"] for event in events]
        need(all(isinstance(s, str) and re.fullmatch("[0-9]+", s) for s in ordered)
             and all(int(a) < int(b) for a, b in zip(ordered, ordered[1:])) and time.monotonic() <= until)
        return rid, events
    raise TimeoutError("recording did not finalize")

def api(client, path):
    code, doc = client.get(path)
    need(code == 200 and doc["nextCursor"] is None)
    return doc["items"]

def endpoint(client, op, rid, event_count):
    observed, = api(client, "/api/v1/endpoints?limit=50")
    need((observed["operationId"], observed["applicationComponent"], observed["binding"], observed["method"],
          observed["routeTemplate"], observed["observation"], observed["observationPolicy"]) ==
         (op["operationId"], "spring-fixture", "default", "POST", "/orders", "observed", "spring-orders-v1"))
    linked, = api(client, "/api/v1/endpoints/" + op["operationId"] + "/recordings?limit=50")
    need((linked["operationId"], linked["recordingId"], linked["completion"], linked["status"],
          linked["observationPolicy"], linked["unmatchedReason"], linked["incompleteEvidence"], linked["eventCount"]) ==
         (op["operationId"], rid, "complete", "complete", "spring-orders-v1", None, [], str(event_count)))
    return exactly_one_id(observed["projectId"])

def lifecycle(port, project_id, revision, op, rid):
    target = {"base_url": f"http://127.0.0.1:{port}", "operator_owned_development": True}
    supplied = {"source": "operator", "content_type": "application/json", "content": '{"description":"ordinary draft"}'}
    request = dict(revision_id=revision, operation_id=op["operationId"], selected_operation_version_id=op["operationVersionId"],
                   recording_id=rid, target=target, inputs=[], body=supplied, lifetime_seconds=900)
    inp = PRIVATE / "input.json"
    inp.write_text(json.dumps(request))
    def exercise(label, *args, expected=0):
        return query(label, "exercise", *args, "--json", expected=expected)
    def check(doc, phase):
        need(doc["kind"] == "exercise_plan_review" and doc["project_id"] == project_id
             and doc["phase"]["phase"] == phase and doc["expired"] is False
             and doc["ready_for_approval"] is (phase == "reviewed") and doc["execution_available"] is False
             and type(doc["requests_sent"]) is int and doc["requests_sent"] == 0
             and doc["result"] == {"status":"unavailable","reason":"executor_not_implemented"}
             and doc["inputs"] == [] and doc["body"] == supplied and doc["target"] == target)
        need(doc["observed_recording"] == {"operation_id":op["operationId"], "recording_id":rid,
             "catalog_revision_id":None, "operation_version_id":None, "version_evidence":"not_observed"})
        selection = doc["selected_catalog_operation"]
        catalog = selection["catalog"]
        need(selection["selection_basis"] == "operator_selected_catalog_version" and selection["operation_id"] == op["operationId"]
             and (catalog["revision_id"], catalog["operation_version_id"], catalog["method"], catalog["route_template"],
                  catalog["application_component"], catalog["binding_key"]) ==
             (revision, op["operationVersionId"], "POST", "/orders", "spring-fixture", "default"))
        item, = doc["preview"]["items"]
        need(item["operation_id"] == op["operationId"] and item["effect"] == "mutating"
             and item["selected"] is True and item["needs_approval"] is True
             and doc["preview"]["items_needing_approval"] == 1)
        return doc["plan_id"], doc["plan_hash"], item["item_id"]
    with stage("plan"):
        created = exercise("plan", "plan", "--input", inp)
        pid, digest, item = check(created, "draft")
        need(exactly_one_id(pid) and re.fullmatch("[0-9a-f]{64}", digest)
             and str(uuid.UUID(item)) == item and uuid.UUID(item).version == 8)
    with stage("review"):
        need(check(exercise("review", "review", "--plan-hash", digest), "reviewed") == (pid, digest, item))
    with stage("deny-missing-consent"):
        args = ["approve", "--plan-id", pid, "--plan-hash", digest, "--confirm-owned-development-target"]
        denied = exercise("missing-item", *args, expected="refused")
        need(denied["code"] == "XTR-EXERCISE-APPROVAL")
        need(check(exercise("after-deny", "show", "--plan-hash", digest), "reviewed") == (pid, digest, item))
    with stage("approve"):
        approved = exercise("approve", *args, "--item", item)
        need(check(approved, "approved") == (pid, digest, item) and approved["phase"]["item_ids"] == [item])
        REPORT["consentedItems"] = 1
    with stage("restore-show"):
        need(exercise("show", "show", "--plan-hash", digest) == approved)

def journey(fixture):
    with stage("initialize"):
        PROJECT.mkdir(mode=0o700)
        path = Path("src/main/java/dev/xtrace/fixture/OrderController.java")
        (PROJECT / path.parent).mkdir(parents=True, mode=0o700)
        shutil.copyfile(REPO / "adapters/java/spring-fixture" / path, PROJECT / path)
        command("init", [CLI, "init", "--project-dir", PROJECT])
    with stage("scan-controller"):
        scan = query("scan", "scan", "--source", PROJECT / "src/main/java", "--framework", "spring-mvc",
                     "--application-component", "spring-fixture", "--binding-key", "default", "--json")
        revision = exactly_one_id(scan["catalogRevisionId"])
        result = scan["result"]
        need(scan["persisted"] is True and result["completion"] == "complete" and result["rejectedClaims"] == 0
             and result["incompleteReasons"] == [] and result["claimCount"] == 1)
    with stage("read-catalog"):
        catalog = query("catalog", "catalog", "list", "--revision", revision, "--json")
        op, = catalog["operations"]
        need(catalog["revision"]["completion"] == "complete" and catalog["revision"]["revisionId"] == revision)
        need((op["method"], op["routeTemplate"], op["bindingKey"], op["applicationComponent"], op["handlerConflict"]) ==
             ("POST", "/orders", "default", "spring-fixture", False))
        exactly_one_id(op["operationId"])
        need(isinstance(op["operationVersionId"], str) and op["operationVersionId"])
    with stage("empty-recordings"):
        initial = query("before", "recording", "list")
        need(initial["recordings"] == [] and initial["next_after"] is None)
    with contextlib.ExitStack() as stack:
        with stage("spring-ready"):
            spring = stack.enter_context(Owned("spring", [
                CLI, "run", "--project-dir", PROJECT, "--java-agent", PAYLOAD / AGENT,
                "--app-package", "dev.xtrace.fixture", "--source-root", "src/main/java",
                "--observed-endpoint-policy", "spring-orders-v1", "--application-component", "spring-fixture",
                "--binding-key", "default", "--", Path(ENV["JAVA_HOME"])/"bin/java", "-jar", fixture,
                "--server.port=0", "--server.address=127.0.0.1",
                "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"], xcamp.spring_bound_port))
            port = spring.ready()
        with stage("ordinary-request"):
            response = xcamp.http_request(f"http://127.0.0.1:{port}", "POST", "/orders",
                headers={"Content-Type": "application/json"},
                body=b'{"description":"ordinary captured order","bodyCanary":"","errorCanary":""}', timeout=10)
            need(response["status"] == 201 and json.loads(response["body"]) == {"status":"created"})
        with stage("complete-recording"):
            rid, events = recording()
            REPORT["genuineRecordingCount"] = 1
        with stage("spring-stopped"):
            need(spring.stop() == 143 and b"XTR-RUN-CAPTURE-INCOMPLETE" not in (LOG / "spring.stderr").read_bytes())
        with stage("guard-listener"):
            # Exclusively occupy the just-released owned target port throughout every CLI plan command.
            # Never reply to a connection. Any pending connection at the end falsifies zero-send.
            guard = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            guard.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            guard.bind(("127.0.0.1", port))
            guard.listen(8)
            guard.setblocking(False)
        with stage("observed-binding"):
            viewer = stack.enter_context(Owned("viewer", [CLI, "open", "--project-dir", PROJECT,
                                               "--viewer", "--no-browser"], xinstr.parse_readiness))
            ready = viewer.ready()
            need(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", ready["origin"]))
            token = xinstr.bootstrap_token(ready["url"])
            need(token and ready["url"].startswith(ready["origin"] + "/"))
            client = xinstr.ViewerClient(ready["origin"])
            client.exchange(token)
            project_id = endpoint(client, op, rid, len(events))
        lifecycle(port, project_id, revision, op, rid)
        with stage("stable-recording"):
            need(viewer.child.poll() is None)
            need(recording() == (rid, events) and endpoint(client, op, rid, len(events)) == project_id)
        with stage("zero-connections"):
            try:
                conn, _ = guard.accept()
            except BlockingIOError as err:
                need(err.errno in (errno.EAGAIN, errno.EWOULDBLOCK))
                REPORT["observedQueuedConnections"] = 0
            else:
                conn.close()
                REPORT["observedQueuedConnections"] = 1
                raise ValueError("unexpected connection")
    with stage("owned-cleanup"):
        need(viewer.child.poll() is not None and guard.fileno() == -1 and spring.child.returncode == 143)

def main():
    old = os.umask(0o077)
    need(old == 0o077)
    try:
        with stage("identity"):
            identity()
        journey(package())
        need(len(REPORT["stages"]) == 27 and all(x == "passed" for x in REPORT["stages"].values())
             and REPORT["genuineRecordingCount"] == REPORT["consentedItems"] == 1
             and REPORT["observedQueuedConnections"] == 0)
        REPORT.update(status="passed", stage="complete", commandExit=0)
    except Exception as e:
        REPORT["failure"] = "timeout" if isinstance(e, (subprocess.TimeoutExpired, TimeoutError, queue.Empty)) else (
            "io" if isinstance(e, OSError) else "evidence")
        with (LOG / "failure.private").open("x") as stream:
            traceback.print_exc(file=stream)
        raise
    finally:
        write()

if __name__ == "__main__":
    main()
