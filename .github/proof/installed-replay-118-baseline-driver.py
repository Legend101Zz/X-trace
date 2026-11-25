"""Hosted-only installed replay proof. All diagnostics and frames remain runner-private."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid

from tools.release.private_roots import admit_directory, atomic_write_private
from campaigns.lib import xcamp, xinstr


ROOT = Path(os.environ["PROOF_ROOT"])
REPO = Path.cwd()
PROOF = Path(os.environ["PROOF_SCRIPTS"])
SOURCE = os.environ["PRODUCT"]
TREE = os.environ["PRODUCT_TREE"]
ASSETS = os.environ["EXPECTED_UI_MANIFEST_SHA256"]
ENV = dict(os.environ, XTRACE_DATA_HOME=str(ROOT / "data-home"))
for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "XTRACE_JAVA_AGENT", "XTRACE_JAVA_PACK",
            "XTRACE_NODE_ANALYZER", "XTRACE_JAVA_ANALYZER"):
    ENV.pop(key, None)
STAGES = ("identity", "package", "verify-dist", "verify-archive", "install", "verify-install",
          "fixture", "chromium", "clean-source", "spring-init", "spring-readiness", "spring-request",
          "spring-recording", "spring-shutdown", "viewer-fine", "viewer-coarse", "frame-coverage", "complete")
SIZES = {320: 640, 736: 900, 1024: 768, 1280: 900, 1440: 900}
POINTERS = ("fine", "coarse")
LEGACY_STATES = ("filter", "goto", "jump", "tools", "playback", "speed")
ASSET_PATHS = ("index.html", "app.js", "index.css", "assets/fonts/chivo-latin-400-normal.woff2",
               "assets/fonts/chivo-latin-600-normal.woff2", "assets/fonts/azeret-mono-latin-400-normal.woff2")
REPORT = {"schemaVersion": 1, "kind": "installed-spring-replay-118-baseline", "status": "failed", "stage": "identity",
          "releaseAcceptance": False, "sourceSha": SOURCE, "sourceTree": TREE, "uiManifestSha256": ASSETS,
          "archiveSha256": None, "installedCliSha256": None, "installedAgentSha256": None,
          "springResponse201": False, "completeRecordings": 0, "eventCount": 0, "servedAssets": 0,
          "fine": False, "coarse": False, "existingFrames": 0}


def need(condition):
    if not condition:
        raise RuntimeError("proof condition failed")


def checkpoint(stage):
    need(stage in STAGES)
    REPORT["stage"] = stage
    atomic_write_private(ROOT / "safe" / "report.json", (json.dumps(REPORT, sort_keys=True) + "\n").encode())


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity():
    need(re.fullmatch("[0-9a-f]{40}", SOURCE) and re.fullmatch("[0-9a-f]{40}", TREE)
         and re.fullmatch("[0-9a-f]{64}", ASSETS))
    for revision, expected in (("HEAD", SOURCE), ("HEAD^{tree}", TREE)):
        need(subprocess.check_output(["git", "rev-parse", revision], text=True).strip() == expected)
    need(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"]))


def command(stage, args, *, cwd=REPO, timeout=3000):
    checkpoint(stage)
    with (ROOT / "logs" / (stage + ".stdout")).open("xb") as out, (ROOT / "logs" / (stage + ".stderr")).open("xb") as err:
        subprocess.run(args, cwd=cwd, env=ENV, stdout=out, stderr=err, check=True, timeout=timeout)


def query(args, timeout=10):
    result = subprocess.run(args, cwd=REPO, env=ENV, capture_output=True, check=True, timeout=timeout)
    need(len(result.stdout) <= 16 * 1024 * 1024)
    return json.loads(result.stdout)


def verified_ui(directory):
    manifest = directory / "assets.sha256"
    need(digest(manifest) == ASSETS)
    rows = {}
    for line in manifest.read_text().splitlines():
        sha, name = line.split("  ")
        need(re.fullmatch("[0-9a-f]{64}", sha) and name in ASSET_PATHS and name not in rows)
        member = directory / (name.removeprefix("assets/") if name.startswith("assets/") else name)
        need(member.is_file() and not member.is_symlink() and digest(member) == sha)
        rows[name] = sha
    need(set(rows) == set(ASSET_PATHS))
    return rows


class OwnedProcess:
    def __init__(self, label, args):
        self.label = label
        self.errors = ROOT / "logs" / (label + ".stderr")
        with self.errors.open("xb") as err:
            self.child = subprocess.Popen(args, cwd=REPO, env=ENV, stdout=subprocess.PIPE, stderr=err, start_new_session=True)
        self.messages = queue.Queue(maxsize=1)
        self.drain = None
        self.drain_ok = False

    def __enter__(self):
        return self

    def ready(self, extract, timeout):
        def read():
            reported = False
            with (ROOT / "logs" / (self.label + ".stdout")).open("xb") as out, self.child.stdout as stream:
                try:
                    for line in iter(lambda: stream.readline(65537), b""):
                        need(len(line) <= 65536 and out.tell() + len(line) <= 4 * 1024 * 1024)
                        out.write(line)
                        if not reported:
                            value = extract(line.decode("utf-8", "replace"))
                            if value is not None:
                                self.messages.put(value)
                                reported = True
                    self.drain_ok = True
                finally:
                    if not reported:
                        self.messages.put(None)
        self.drain = threading.Thread(target=read, daemon=True)
        self.drain.start()
        value = self.messages.get(timeout=timeout)
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
        if self.drain:
            self.drain.join(timeout=5)
            need(not self.drain.is_alive() and self.drain_ok)
        return code

    def __exit__(self, *_):
        if self.child.poll() is None or (self.drain and self.drain.is_alive()):
            self.stop()


def list_args(cli, project):
    return [str(cli), "recording", "list", "--project-dir", str(project), "--limit", "200"]


def expected_recording(cli, project):
    wait_until = time.monotonic() + 30
    while time.monotonic() < wait_until:
        listing = query(list_args(cli, project), timeout=max(0.1, min(5, wait_until - time.monotonic())))
        rows = listing["recordings"]
        need(listing["next_after"] is None and len(rows) <= 1)
        if len(rows) == 1 and rows[0]["completion"] == "complete":
            rid = rows[0]["recording_id"]
            need(str(uuid.UUID(rid)) == rid and uuid.UUID(rid).version == 7)
            detail = query([str(cli), "recording", "show", rid, "--limit", "200", "--project-dir", str(project)])
            need(detail["recording_id"] == rid and detail["completion"] == "complete" and detail["next_cursor"] is None
                 and detail["outcome"]["kind"] == "responded" and detail["outcome"]["httpStatus"] == 201)
            events = detail["events"]
            need(1 < len(events) <= 200 and any("OrderController.create" in (event["symbol"] or "") for event in events))
            sequences = [event["sequence"] for event in events]
            need(all(isinstance(item, str) and re.fullmatch("[0-9]+", item) for item in sequences)
                 and all(int(a) < int(b) for a, b in zip(sequences, sequences[1:])))
            return rid, sequences
        time.sleep(0.1)
    raise TimeoutError("recording deadline")


def served_assets(origin, rows):
    need(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", origin))
    connection = http.client.HTTPConnection("127.0.0.1", int(origin.rsplit(":", 1)[1]), timeout=10)
    try:
        for name, sha in rows.items():
            connection.request("GET", "/" if name == "index.html" else "/" + name)
            response = connection.getresponse()
            payload = response.read(20 * 1024 * 1024 + 1)
            need(response.status == 200 and len(payload) <= 20 * 1024 * 1024 and hashlib.sha256(payload).hexdigest() == sha)
    finally:
        connection.close()


def check_frames(directory, names):
    need({p.name for p in directory.iterdir()} == set(names))
    for name, size in names.items():
        path = directory / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o777 == 0o600
             and info.st_nlink == 1 and 33 <= info.st_size <= 20 * 1024 * 1024)
        with path.open("rb") as stream:
            header = stream.read(24)
        need(header[:16] == b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
             and (int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")) == size)


def run():
    identity()
    rows = verified_ui(REPO / "crates/xtrace-daemon/assets/ui")
    command("package", ["python3", "-B", "packaging/build.py", "--out", str(ROOT / "dist"),
                        "--work", str(ROOT / "build"), "--platform", "linux-x86_64"])
    archives = list((ROOT / "dist/linux-x86_64").glob("xtrace-*-linux-x86_64.tar.gz"))
    need(len(archives) == 1)
    archive = archives[0]
    REPORT["archiveSha256"] = digest(archive)
    command("verify-dist", ["sh", "packaging/install.sh", "verify-dist", str(archive.parent)])
    command("verify-archive", ["python3", "-B", "packaging/verify_package.py", str(archive), "--repo", str(REPO), "--run-binary"])
    extracted = ROOT / "extracted"
    extracted.mkdir(mode=0o700)
    verifier = importlib.util.spec_from_file_location("replay_package_verifier", REPO / "packaging/verify_package.py")
    verifier_module = importlib.util.module_from_spec(verifier)
    verifier.loader.exec_module(verifier_module)
    distribution = verifier_module.resolve_root(archive, extracted)
    manifest = Path("share/xtrace/PACKAGE-MANIFEST.json")
    need(json.loads((distribution / manifest).read_bytes())["sourceCommit"] == SOURCE)
    prefix = ROOT / "fresh installed prefix"
    need(not prefix.exists())
    command("install", ["sh", str(distribution / "install.sh"), "--prefix", str(prefix), "--data-home", ENV["XTRACE_DATA_HOME"]])
    command("verify-install", ["sh", str(prefix / "current/install.sh"), "verify", "--prefix", str(prefix)])
    payload = prefix / "current"
    cli = prefix / "bin/xtrace"
    agent_name = Path("share/xtrace/packs/java/agent/xtrace-java-agent.jar")
    agent = (payload / agent_name).resolve(strict=True)
    need(cli.resolve(strict=True) == (payload / "bin/xtrace").resolve(strict=True))
    need(digest(payload / manifest) == digest(distribution / manifest)
         and digest(cli) == digest(distribution / "bin/xtrace")
         and digest(agent) == digest(distribution / agent_name))
    need(verified_ui(payload / "share/xtrace/web") == rows)
    REPORT.update(installedCliSha256=digest(cli), installedAgentSha256=digest(agent))
    command("fixture", ["./gradlew", "--no-daemon", "--dependency-verification", "strict", "fixtureBootJar"], cwd=REPO / "adapters/java")
    fixture = REPO / "adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar"
    java = Path(ENV["JAVA_HOME"]) / "bin/java"
    need(fixture.is_file() and java.is_file() and digest(archive) == REPORT["archiveSha256"])
    command("chromium", ["npm", "exec", "--", "playwright", "install", "chromium"], cwd=REPO / "web/app")
    checkpoint("clean-source")
    identity()

    project = ROOT / "Spring project"
    project.mkdir(mode=0o700)
    shutil.copytree(REPO / "adapters/java/spring-fixture/src/main/java", project / "src/main/java")
    command("spring-init", [str(cli), "init", "--project-dir", str(project)])
    need(query(list_args(cli, project))["recordings"] == [])
    checkpoint("spring-readiness")
    with OwnedProcess("spring", [str(cli), "run", "--project-dir", str(project), "--java-agent", str(agent),
                                  "--app-package", "dev.xtrace.fixture", "--source-root", "src/main/java",
                                  "--observed-endpoint-policy", "spring-orders-v1", "--application-component", "spring-fixture",
                                  "--binding-key", "default", "--", str(java), "-jar", str(fixture), "--server.port=0",
                                  "--server.address=127.0.0.1", "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"]) as spring:
        port = spring.ready(xcamp.spring_bound_port, 45)
        checkpoint("spring-request")
        response = xcamp.http_request(f"http://127.0.0.1:{port}", "POST", "/orders",
                                     headers={"Content-Type": "application/json"},
                                     body=b'{"description":"synthetic replay fixture","bodyCanary":"safe","errorCanary":""}', timeout=10)
        need(response["status"] == 201)
        REPORT["springResponse201"] = True
        checkpoint("spring-recording")
        rid, sequences = expected_recording(cli, project)
        checkpoint("spring-shutdown")
        need(spring.stop() == 143 and b"XTR-RUN-CAPTURE-INCOMPLETE" not in spring.errors.read_bytes())
    with socket.socket() as connection:
        connection.settimeout(2)
        need(connection.connect_ex(("127.0.0.1", port)) != 0)
    need(expected_recording(cli, project) == (rid, sequences))
    REPORT.update(completeRecordings=1, eventCount=len(sequences))

    shots = ROOT / "shots"
    driver = (PROOF / "installed-replay-118-baseline-browser.mjs").read_bytes()
    for pointer in POINTERS:
        checkpoint("viewer-" + pointer)
        with OwnedProcess("viewer-" + pointer, [str(cli), "open", "--project-dir", str(project), "--viewer", "--no-browser"]) as viewer:
            ready = viewer.ready(xinstr.parse_readiness, 60)
            served_assets(ready["origin"], rows)
            receipt_id = os.urandom(32).hex()
            context = ROOT / "private" / (pointer + "-context.json")
            result = ROOT / "private" / (pointer + "-result.json")
            jump_receipt = ROOT / "private" / (pointer + "-jumps.json")
            atomic_write_private(context, json.dumps({"pointer": pointer, **ready, "recordingId": rid, "sequences": sequences,
                                                      "shots": str(shots), "result": str(result), "jumpReceipt": str(jump_receipt),
                                                      "sourceSha": SOURCE, "receiptId": receipt_id}).encode())
            with (ROOT / "logs" / (pointer + "-browser.stdout")).open("xb") as out, (ROOT / "logs" / (pointer + "-browser.stderr")).open("xb") as err:
                subprocess.run(["node", "--input-type=module", "-", str(context)], cwd=REPO / "web/app",
                               env=ENV, input=driver, stdout=out, stderr=err, timeout=480, check=True)
            need(json.loads(result.read_bytes()) == {"schema": 1, "pointer": pointer, "sourceSha": SOURCE,
                                                    "receiptId": receipt_id, "existing": 30})
            jump = json.loads(jump_receipt.read_bytes())
            need(jump["sourceSha"] == SOURCE and jump["receiptId"] == receipt_id
                 and all(cell["status"] == "pass" for cell in jump["viewports"] if cell["pointer"] == pointer)
                 and sum(cell["pointer"] == pointer for cell in jump["viewports"]) == 5)
            need(viewer.stop() in (0, 143))
        REPORT[pointer] = True
        REPORT["servedAssets"] += len(rows)

    checkpoint("frame-coverage")
    existing = {f"viewer-replay-{state}-{pointer}-{w}-viewport.png": (w, h)
                for w, h in SIZES.items() for pointer in POINTERS for state in LEGACY_STATES}
    check_frames(shots / "existing", existing)
    REPORT.update(status="passed", existingFrames=len(existing))
    checkpoint("complete")


if __name__ == "__main__":
    import traceback
    os.umask(0o077)
    admit_directory(ROOT)
    need(all((ROOT / name).is_dir() for name in ("logs", "private", "shots", "safe")))
    if not (re.fullmatch("[0-9a-f]{40}", SOURCE) and re.fullmatch("[0-9a-f]{40}", TREE) and re.fullmatch("[0-9a-f]{64}", ASSETS)):
        raise SystemExit(1)
    checkpoint("identity")
    try:
        run()
    except Exception:
        with (ROOT / "logs/driver-exception.stderr").open("x") as diagnostics:
            traceback.print_exc(file=diagnostics)
        checkpoint(REPORT["stage"])
        raise SystemExit(1)
