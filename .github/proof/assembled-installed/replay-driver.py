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
from common import compact_replay


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
REPORT = {"schemaVersion": 1, "kind": "installed-spring-replay-assembled", "status": "failed", "stage": "identity",
          "releaseAcceptance": False, "sourceSha": SOURCE, "sourceTree": TREE, "uiManifestSha256": ASSETS,
          "archiveSha256": None, "installedCliSha256": None, "installedAgentSha256": None,
          "springResponse201": False, "completeRecordings": 0, "eventCount": 0, "servedAssets": 0,
          "fine": False, "coarse": False, "existingFrames": 0, "compactOpenFrames": 0, "desktopInlineFrames": 0, "phoneMoreFrames": 0, "jumpCells": []}


def need(condition):
    if not condition:
        raise RuntimeError("proof condition failed")


def checkpoint(stage):
    need(stage in STAGES)
    REPORT["stage"] = stage
    atomic_write_private(ROOT / "safe" / "report.json", (json.dumps(compact_replay(REPORT), sort_keys=True) + "\n").encode())


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


def expected_recording(cli, project, *, other_ids=frozenset()):
    wait_until = time.monotonic() + 30
    while time.monotonic() < wait_until:
        listing = query(list_args(cli, project), timeout=max(0.1, min(5, wait_until - time.monotonic())))
        rows = listing["recordings"]
        ids = {row["recording_id"] for row in rows}
        need(listing["next_after"] is None and len(ids) == len(rows) and other_ids <= ids
             and len(rows) <= 1 + len(other_ids))
        fresh = [row for row in rows if row["recording_id"] not in other_ids]
        if fresh and fresh[0]["completion"] == "complete":
            rid = fresh[0]["recording_id"]
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
    from common import load_package, binding
    shared = load_package()
    prefix = Path(shared['prefix'])
    cli = prefix / 'bin/xtrace'
    agent = prefix / 'current/share/xtrace/packs/java/agent/xtrace-java-agent.jar'
    fixture = Path(shared['fixture'])
    java = Path(ENV['JAVA_HOME']) / 'bin/java'
    REPORT.update(binding(shared))
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
        observed = {}
        for _ in range(2):
            response = xcamp.http_request(f"http://127.0.0.1:{port}", "POST", "/orders",
                                         headers={"Content-Type": "application/json"},
                                         body=b'{"description":"synthetic replay fixture","bodyCanary":"safe","errorCanary":""}', timeout=10)
            need(response["status"] == 201)
            checkpoint("spring-recording")
            recording, ordered = expected_recording(cli, project, other_ids=set(observed))
            observed[recording] = ordered
        rid, other_rid = observed
        sequences = observed[rid]
        REPORT["springResponse201"] = True
        checkpoint("spring-shutdown")
        need(spring.stop() == 143 and b"XTR-RUN-CAPTURE-INCOMPLETE" not in spring.errors.read_bytes())
    with socket.socket() as connection:
        connection.settimeout(2)
        need(connection.connect_ex(("127.0.0.1", port)) != 0)
    for recording, ordered in observed.items():
        need(expected_recording(cli, project, other_ids=set(observed) - {recording}) == (recording, ordered))
    REPORT.update(completeRecordings=2, eventCount=len(sequences), refreshedCells=0, tabletSwitchCells=0, phoneKeyboardSwitches=0)

    shots = ROOT / "shots"
    driver = (PROOF / "replay-browser.mjs").read_bytes()
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
                                                      "otherRecordingId": other_rid, "otherSequences": observed[other_rid],
                                                      "shots": str(shots), "result": str(result), "jumpReceipt": str(jump_receipt),
                                                      "sourceSha": SOURCE, "receiptId": receipt_id}).encode())
            with (ROOT / "logs" / (pointer + "-browser.stdout")).open("xb") as out, (ROOT / "logs" / (pointer + "-browser.stderr")).open("xb") as err:
                subprocess.run(["node", "--input-type=module", "-", str(context)], cwd=REPO / "web/app",
                               env=ENV, input=driver, stdout=out, stderr=err, timeout=480, check=True)
            need(json.loads(result.read_bytes()) == {"schema": 1, "pointer": pointer, "sourceSha": SOURCE,
                                                    "receiptId": receipt_id, "existing": 30, "compactOpen": 3, "desktopInline": 2, "phoneMore": 1, "tabletSwitches": 1, "phoneKeyboardSwitches": 2, "refreshedWidths": sorted(SIZES)})
            REPORT["refreshedCells"] += len(SIZES)
            REPORT["tabletSwitchCells"] += 1
            REPORT["phoneKeyboardSwitches"] += 2
            jump = json.loads(jump_receipt.read_bytes())
            need(jump["sourceSha"] == SOURCE and jump["receiptId"] == receipt_id
                 and all(cell["status"] == "pass" for cell in jump["viewports"] if cell["pointer"] == pointer)
                 and sum(cell["pointer"] == pointer for cell in jump["viewports"]) == 5)
            cells = [cell for cell in jump['viewports'] if cell['pointer'] == pointer]
            need({(cell['width'], cell['height']) for cell in cells} == set(SIZES.items()))
            for cell in cells:
                need([item['kind'] for item in cell['jumps']] == ['gap', 'exception', 'database', 'http'])
                projected = {'width': cell['width'], 'pointer': pointer, 'kinds': []}
                for item in cell['jumps']:
                    count = item['observedCount']
                    need(type(count) is int and 0 <= count <= 100000)
                    kind = {'kind': item['kind'], 'observedCount': count}
                    for direction in ('next', 'previous'):
                        evidence = item[direction]
                        need(set(evidence) == {'targetAvailable', 'activated', 'absenceReasonChecked'})
                        need(type(evidence['targetAvailable']) is bool)
                        need(type(evidence['activated']) is int and type(evidence['absenceReasonChecked']) is int)
                        need((evidence['activated'], evidence['absenceReasonChecked']) ==
                             ((1, 0) if evidence['targetAvailable'] else (0, 1)))
                        kind[direction] = dict(evidence)
                    projected['kinds'].append(kind)
                REPORT['jumpCells'].append(projected)
            need(viewer.stop() in (0, 143))
        REPORT[pointer] = True
        REPORT["servedAssets"] += len(rows)

    checkpoint("frame-coverage")
    existing = {f"viewer-replay-{state}-{pointer}-{w}-viewport.png": (w, h)
                for w, h in SIZES.items() for pointer in POINTERS for state in LEGACY_STATES}
    compact = {f"viewer-replay-compact-tools-open-{pointer}-{w}-viewport.png": (w, h)
               for w, h in SIZES.items() if w < 1280 for pointer in POINTERS}
    check_frames(shots / "existing", existing)
    desktop = {f"viewer-replay-desktop-tools-inline-{pointer}-{w}-viewport.png": (w, h)
               for w, h in SIZES.items() if w >= 1280 for pointer in POINTERS}
    phone = {f"viewer-phone-more-{pointer}-320-viewport.png": (320, 640) for pointer in POINTERS}
    check_frames(shots / "compact-open", compact | desktop | phone)
    load_package()
    REPORT.update(status="passed", existingFrames=len(existing), compactOpenFrames=len(compact), desktopInlineFrames=len(desktop), phoneMoreFrames=len(phone))
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
