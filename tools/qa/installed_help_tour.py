"""One installed Linux archive, empty project, and real Spring Help tour."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import Request, urlopen


def check(condition):
    if not condition:
        raise RuntimeError("installed tour condition failed")


def bounded_run(args, env, *, input_bytes=None):
    return subprocess.run(
        args, env=env, input=input_bytes, capture_output=True, check=True, timeout=120,
    ).stdout


def start(args, env):
    return subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
            raise RuntimeError("child did not stop")
    if child.stdout is not None:
        child.stdout.close()


def find_ready(child, parse):
    check(child.stdout is not None)
    deadline = time.monotonic() + 45
    buffer = b""
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            data = os.read(child.stdout.fileno(), 8192)
            if not data:
                break
            buffer += data
            check(len(buffer) <= 65_536)
            lines = buffer.split(b"\n")
            buffer = lines.pop()
            for line in lines:
                value = parse(line)
                if value is not None:
                    return value
    raise RuntimeError("readiness not observed")


def viewer_url(line):
    try:
        ready = json.loads(line)
    except ValueError:
        return None
    url = ready.get("url") if isinstance(ready, dict) else None
    return url if isinstance(url, str) and re.fullmatch(r"http://127\.0\.0\.1:[0-9]+/#token=[^\s]+", url) else None


def spring_port(line):
    match = re.search(rb"Tomcat started on port ([0-9]+) \(http\)", line)
    return int(match[1]) if match else None


def browse(binary, project, env, recording_id=None):
    viewer = start([binary, "open", "--project-dir", project, "--viewer", "--no-browser"], env)
    try:
        context = {"url": find_ready(viewer, viewer_url), "widths": [320, 1440], "recordingId": recording_id}
        script = Path(__file__).resolve().parents[2] / "web/app/scripts/first-recording-journey.mjs"
        receipt = bounded_run(["node", script], env, input_bytes=json.dumps(context).encode())
        expected = (b"recorded Spring Help tour passed" if recording_id
                    else b"first recording and Help tour passed")
        check(expected in receipt)
    finally:
        stop(viewer)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--spring-fixture", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    args = parser.parse_args()
    stage = "admit archive and private scratch"
    try:
        check(re.fullmatch(r"[0-9a-f]{40}", args.source_sha))
        check(args.scratch.is_dir() and args.scratch.stat().st_mode & 0o077 == 0)
        check(args.spring_fixture.is_file())
        build = json.loads((args.dist / "build-info.json").read_bytes())
        check(build["sourceCommit"] == args.source_sha and build["platform"] == "linux-x86_64")
        archives = list(args.dist.glob("xtrace-*-linux-x86_64.tar.gz"))
        check(len(archives) == 1 and archives[0].name == build["archive"])
        archive_hash = sha256(archives[0])
        check(archive_hash == build["archiveSha256"])
        env = dict(os.environ)
        root_dir = Path(__file__).resolve().parents[2]
        bounded_run(["sh", root_dir / "packaging/install.sh", "verify-dist", args.dist], env)
        with tempfile.TemporaryDirectory(dir=args.scratch, prefix="tour-") as scratch:
            root = Path(scratch)
            unpacked = root / "unpacked"
            unpacked.mkdir(mode=0o700)
            with tarfile.open(archives[0], "r:gz") as archive:
                archive.extractall(unpacked, filter="data")
            products = list(unpacked.iterdir())
            check(len(products) == 1 and products[0].is_dir())
            manifest = json.loads((products[0] / "share/xtrace/PACKAGE-MANIFEST.json").read_bytes())
            check(manifest["sourceCommit"] == args.source_sha and manifest["platform"] == "linux-x86_64")
            stage = "install and verify archive payload"
            prefix, project, data, temp = (root / name for name in ("install", "project", "data", "temp"))
            for private in (project, data, temp):
                private.mkdir(mode=0o700)
            env.update(TMPDIR=str(temp), XTRACE_DATA_HOME=str(data))
            bounded_run(["sh", products[0] / "install.sh", "--prefix", prefix, "--data-home", data], env)
            product = (prefix / "current").resolve()
            bounded_run(["sh", product / "install.sh", "verify", "--prefix", prefix], env)
            binary = product / "bin/xtrace"
            agent = product / "share/xtrace/packs/java/agent/xtrace-java-agent.jar"
            check(binary.is_file() and agent.is_file())
            same_binary = next(entry for entry in manifest["files"] if entry["path"] == "bin/xtrace")
            binary_hash = sha256(binary)
            check(binary_hash == same_binary["sha256"])

            stage = "fresh installed project"
            bounded_run([binary, "init", "--project-dir", project], env)
            browse(binary, project, env)

            stage = "capture real Spring request with installed binary and agent"
            app = start([binary, "run", "--project-dir", project, "--java-agent", agent,
                         "--observed-endpoint-policy", "spring-orders-v1",
                         "--application-component", "spring-fixture", "--binding-key", "default",
                         "--", "java", "-jar", args.spring_fixture, "--server.port=0",
                         "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"], env)
            try:
                port = find_ready(app, spring_port)
                request = Request(f"http://127.0.0.1:{port}/orders?probe=INSTALLED_TOUR_PRIVATE_QUERY",
                                  data=b'{"description":"installed tour","bodyCanary":"INSTALLED_TOUR_PRIVATE_BODY"}',
                                  headers={"Content-Type": "application/json"}, method="POST")
                with urlopen(request, timeout=10) as response:
                    check(response.status == 201)
            finally:
                stop(app)

            stage = "verify real linked recording and installed Help"
            page = json.loads(bounded_run([binary, "recording", "list", "--project-dir", project, "--limit", "1"], env))
            check(len(page["recordings"]) == 1 and page["next_after"] is None)
            row = page["recordings"][0]
            check(row["status"] in ("complete", "partial") and int(row["event_count"]) > 0)
            browse(binary, project, env, row["recording_id"])
        print(json.dumps({"archiveSha256": archive_hash, "installedBinarySha256": binary_hash,
                          "sourceSha": args.source_sha,
                          "widths": [320, 1440], "freshProject": "pass", "springCapture": "pass",
                          "installedHelpTour": "pass"}))
    except (Exception, KeyboardInterrupt):
        print(f"Installed Help tour failed during {stage}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
