"""Same-archive, ordinary loopback Jersey version-control fixture for hosted development proof."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit

from observation import api_reader, cli_reader, compare_inventory, judge
from pages import list_pages
from verify_fixture import require, verify_fixture

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "campaigns/lib"))
import installed_java
import xcamp
import xinstr


def workload(proc, root, canaries):
    deadline = time.monotonic() + 90
    while not (root / "port").is_file():
        require(proc.poll() is None and time.monotonic() < deadline, "fixture readiness")
        time.sleep(0.05)
    text = (root / "port").read_text()
    require(re.fullmatch(r"[1-9][0-9]{0,4}", text) and 1 <= int(text) <= 65535, "fixture listen port")
    group, query, header = canaries
    prefix = f"/scope/effective/groups/{group}"
    for method, path, status, content in (
        ("GET", prefix + "/items/31", 200, b"found"),
        ("POST", prefix + "/items/invalid", 404, None),
        ("GET", prefix + "/deferred", 200, b"resumed"),
        ("GET", "/scope/effective/refused", 403, None),
        # Tomcat preserves the inbound spelling of the context path while its deployment is canonical.
        ("GET", f"/%73cope/effective/groups/{group}/context", 200, b"different context path"),
    ):
        connection = http.client.HTTPConnection("127.0.0.1", int(text), timeout=15)
        try:
            connection.request(method, path + "?q=" + query, headers={"X-Fixture-Marker": header})
            response = connection.getresponse()
            body = response.read(65537)
            require(response.status == status and len(body) <= 65536, "fixture HTTP response")
            if content is not None:
                require(body == content, "fixture resource response body")
        finally:
            connection.close()


def leg(root, jar, version, cli, agent, java):
    root.mkdir(mode=0o700)
    project, control = root / "project", root / "control"
    project.mkdir(mode=0o700)
    control.mkdir(mode=0o700)
    shutil.copytree(HERE / "src", project / "src")
    fixture = project / "fixture.jar"
    shutil.copyfile(jar, fixture)
    _, probe_inputs = verify_fixture(fixture, version)
    env = {k: v for k, v in os.environ.items() if k not in xcamp.JAVA_OPTIONS_ENV}
    for name, folder in (("XTRACE_DATA_HOME", "data"), ("TMPDIR", "tmp"), ("HOME", "home")):
        path = root / folder
        path.mkdir(mode=0o700)
        env[name] = str(path)
    init = subprocess.run([cli, "init", "--project-dir", str(project), "--display-name", "Jersey fixture"],
                   env=env, check=True, capture_output=True, timeout=120)
    project_id = json.loads(init.stdout)["project_id"]
    canaries = tuple(secrets.token_hex(16) for _ in range(3))
    read_cli = cli_reader(cli, project, env, canaries)
    require(list_pages(lambda cursor: read_cli(None, cursor), False, project_id) == ({}, 1),
            "fresh installed fixture project")
    cmd = [cli, "run", "--project-dir", str(project), "--java-agent", agent, "--capture-depth", "standard",
           "--app-package", "fixture.jersey", "--source-root", "src/main/java", "--",
           str(java), "-Dxtrace.jersey.probeEvidence=true", "-Dfixture.control=" + str(control), "-jar", str(fixture),
           "--server.address=127.0.0.1", "--server.port=0", "--server.servlet.context-path=/scope",
           "--spring.jersey.application-path=/effective"]
    with (root / "launch.log").open("xb") as log:
        proc = subprocess.Popen(cmd, cwd=project, env=env, stdout=log, stderr=log)
        try:
            workload(proc, control, canaries)
        finally:
            (control / "stop").touch(exist_ok=False)
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=30)
                raise
        require(proc.returncode == 0, "installed recording shutdown")

    messages = {
        "observationNotices": "Jersey dispatch identity or route observation unavailable",
        "unqualifiedNotices": "Jersey framework class image or bundle identity did not qualify",
        "probeFailureNotices": "Jersey framework probe installation unavailable",
        "applicationProbeNotices": "application invocation probes unavailable; recordings remain partial; application continues",
    }
    codes = {json.dumps({"code": "XTR-JAVA-INSTRUMENTATION", "message": message},
                        separators=(",", ":")).encode(): key for key, message in messages.items()}
    notices = dict.fromkeys(messages, 0)
    supported = version == "3.1.11"
    expected_decisions = (dict.fromkeys(probe_inputs, "qualified") if supported else
                          {"service": "version-excluded", "component": "image-and-version-excluded",
                           "invoker": "version-excluded"})
    decisions = {}
    with (root / "launch.log").open("rb") as stream:
        for line in stream:
            line = line.rstrip(b"\r\n")
            key = codes.get(line)
            if key is not None:
                notices[key] += 1
            if line.startswith(b"XTRACE-JERSEY-PROBE/1 "):
                _, target, decision, image, manifest = line.decode("ascii").split()
                require(target in probe_inputs and target not in decisions
                        and (image, manifest) == probe_inputs[target], "actual target image and origin manifest")
                decisions[target] = decision
    require(decisions == expected_decisions, "individual Jersey probe version decisions")
    require(notices == {"observationNotices": int(supported), "unqualifiedNotices": int(not supported),
                        "probeFailureNotices": 0, "applicationProbeNotices": 0}, "process-level probe notices")
    viewer, ready = xinstr.start_viewer(cli, project, env, root / "viewer.log")
    try:
        url = urlsplit(ready["origin"])
        require(url.scheme == "http" and url.hostname == "127.0.0.1" and url.port
                and ready["url"].startswith(ready["origin"] + "/"), "viewer loopback origin")
        token = xinstr.bootstrap_token(ready["url"])
        require(token, "viewer credential missing")
        client = xinstr.ViewerClient(ready["origin"])
        client.exchange(token)
        details, counts = compare_inventory(read_cli, api_reader(client, canaries), project_id, supported)
    finally:
        if viewer.poll() is None:
            viewer.terminate()
        viewer.wait(timeout=30)
    return {"httpResponses": 5, "recordings": judge(details, version), "probeDecisions": decisions, **notices, **counts}


def main():
    parser = argparse.ArgumentParser()
    for name in ("root", "prefix", "archive", "java", "supported", "unsupported"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--archive-sha", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = installed_java.private_dir(args.root)
    require(not any(root.iterdir()), "fixture evidence directory must be fresh")
    stage = "package"
    report = {"status": "failed", "releaseAcceptance": False, "legs": {}}
    try:
        installed_java.clean_checkout(REPO, args.source_sha)
        installed_java.java_identity(args.java, 21)
        cli, agent, identity = installed_java.installed_package(
            args.prefix, args.archive, args.archive_sha, args.source_sha, root / "extracted")
        report.update(archiveSha256=identity["archiveSha256"], sourceSha=identity["sourceCommit"])
        stage = "fixture-identity"
        require(verify_fixture(args.supported, "3.1.11")[0] == verify_fixture(args.unsupported, "3.1.10")[0],
                "application class bytes differ between the two real fixtures")
        for jar, version in ((args.supported, "3.1.11"), (args.unsupported, "3.1.10")):
            stage = "installed-jersey-" + version
            report["legs"][version] = leg(root / version, jar, version, cli, agent, args.java)
        stage, report["status"] = "complete", "passed"
    except Exception:
        # Keep exception text, command output and any bootstrap material out of the public receipt.
        import traceback
        with (root / "private-error.log").open("x") as stream:
            traceback.print_exc(file=stream)
    report["stage"] = stage
    (root / "counts.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
