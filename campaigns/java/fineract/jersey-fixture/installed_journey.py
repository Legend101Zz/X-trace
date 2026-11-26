"""Same-archive, ordinary loopback Jersey version-control fixture for hosted development proof."""
import argparse
from contextlib import contextmanager
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
import traceback
from urllib.parse import urlsplit

from observation import OutcomeMismatch, api_reader, cli_reader, compare_inventory, judge
from pages import list_pages
import lifecycle
from verify_fixture import require, verify_fixture

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / "campaigns/lib"))
import installed_java
import xcamp
import xinstr


def failure_site(error):
    # Source is pinned by the hosted wrapper. Only a reviewed file label and line number
    # leave the private traceback; exception text and frame locals can contain fixture input.
    files = {HERE / name: name for name in ("installed_journey.py", "observation.py", "pages.py", "verify_fixture.py", "lifecycle.py")}
    files[REPO / "campaigns/lib/xinstr.py"] = "xinstr.py"
    site = None
    for frame, line in traceback.walk_tb(error.__traceback__):
        label = files.get(Path(frame.f_code.co_filename))
        if label and frame.f_code is not require.__code__:
            site = {"file": label, "line": line}
    return site


@contextmanager
def cleanup(progress, phase):
    # Capture the primary operation even when releasing its process also fails.
    unwinding = sys.exc_info()[1] is not None
    if not unwinding:
        progress["phase"] = phase
    try:
        yield
    except Exception:
        if not unwinding:
            raise
        progress["cleanupFailure"] = phase


def workload(proc, root, canaries, progress):
    progress["phase"] = "fixture-readiness"
    deadline = time.monotonic() + 90
    while not (root / "port").is_file():
        require(proc.poll() is None, "fixture exited before readiness")
        require(time.monotonic() < deadline, "fixture readiness deadline")
        time.sleep(0.05)
    text = (root / "port").read_text()
    require(re.fullmatch(r"[1-9][0-9]{0,4}", text) and 1 <= int(text) <= 65535, "fixture listen port")
    progress["phase"] = "http-workload"
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
            if response.status != status:
                progress["differentHttpStatus"] = response.status if 100 <= response.status <= 599 else None
                raise ValueError("fixture HTTP status")
            require(len(body) <= 65536, "fixture HTTP response size")
            if content is not None:
                require(body == content, "fixture resource response body")
        finally:
            connection.close()
        progress["responsesVerified"] += 1


def stop_recording(proc, marker):
    try:
        marker.touch(exist_ok=False)
        proc.wait(timeout=60)
    except BaseException as primary:
        # A failed marker cannot arrange cooperative shutdown. Keep both failures if release fails.
        try:
            xinstr.stop_process_group(proc, wait=30)
        except Exception as release:
            raise xcamp.CleanupFailure((primary, release), proc) from primary
        raise
    require(proc.returncode == 0, "installed recording shutdown")


def leg(root, jar, version, cli, agent, java, progress):
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
    progress["phase"] = "project-init"
    init = subprocess.run([cli, "init", "--project-dir", str(project), "--display-name", "Jersey fixture"],
                   env=env, check=True, capture_output=True, timeout=120)
    project_id = json.loads(init.stdout)["project_id"]
    canaries = tuple(secrets.token_hex(16) for _ in range(3))
    read_cli = cli_reader(cli, project, env, canaries)
    progress["phase"] = "empty-cli-inventory"
    require(list_pages(lambda cursor: read_cli(None, cursor), False, project_id) == ({}, 1),
            "fresh installed fixture project")
    cmd = [cli, "run", "--project-dir", str(project), "--java-agent", agent, "--capture-depth", "standard",
           "--app-package", "fixture.jersey", "--source-root", "src/main/java", "--",
           str(java), "-Dxtrace.jersey.probeEvidence=true", "-Dfixture.control=" + str(control), "-jar", str(fixture),
           "--server.address=127.0.0.1", "--server.port=0", "--server.servlet.context-path=/scope",
           "--spring.jersey.application-path=/effective"]
    live = None
    progress["phase"] = "installed-launch"
    with (root / "launch.log").open("xb") as log:
        proc = subprocess.Popen(cmd, cwd=project, env=env, stdout=log, stderr=log)
        try:
            workload(proc, control, canaries, progress)
            if version == "3.1.11":
                progress["phase"] = "lifecycle-viewer-readiness"
                live_viewer, live_ready = xinstr.start_viewer(cli, project, env, root / "live-viewer.log")
                try:
                    origin = urlsplit(live_ready["origin"])
                    require(origin.scheme == "http" and origin.hostname == "127.0.0.1" and origin.port
                            and live_ready["url"].startswith(live_ready["origin"] + "/"), "live viewer loopback origin")
                    live_client = xinstr.ViewerClient(live_ready["origin"])
                    token = xinstr.bootstrap_token(live_ready["url"])
                    require(token, "live viewer credential missing")
                    live_client.exchange(token)
                    live = lifecycle.observe(proc, control, canaries, project_id, live_client,
                                             cli, project, env, progress)
                finally:
                    with cleanup(progress, "live-viewer-shutdown"):
                        xinstr.stop_process_group(live_viewer, wait=30)
        finally:
            with cleanup(progress, "recording-shutdown"):
                stop_recording(proc, control / "stop")

    progress["phase"] = "probe-inputs"
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
    decisions = progress["probeDecisions"]
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
                require(decision in {"qualified", "version-excluded", "image-excluded", "image-and-version-excluded"},
                        "unexpected Jersey decision label")
                decisions[target] = decision
    progress["phase"] = "probe-decisions"
    require(decisions == expected_decisions, "individual Jersey probe version decisions")
    progress["phase"] = "probe-notices"
    require(notices == {"observationNotices": int(supported), "unqualifiedNotices": int(not supported),
                        "probeFailureNotices": 0, "applicationProbeNotices": 0}, "process-level probe notices")
    progress["phase"] = "viewer-readiness"
    viewer, ready = xinstr.start_viewer(cli, project, env, root / "viewer.log")
    try:
        progress["phase"] = "viewer-auth"
        url = urlsplit(ready["origin"])
        require(url.scheme == "http" and url.hostname == "127.0.0.1" and url.port
                and ready["url"].startswith(ready["origin"] + "/"), "viewer loopback origin")
        token = xinstr.bootstrap_token(ready["url"])
        require(token, "viewer credential missing")
        client = xinstr.ViewerClient(ready["origin"])
        client.exchange(token)
        progress["phase"] = "recording-inventory"
        details, counts = compare_inventory(read_cli, api_reader(client, canaries), project_id, supported)
    finally:
        with cleanup(progress, "viewer-shutdown"):
            xinstr.stop_process_group(viewer, wait=30)
    progress["phase"] = "recording-judgment"
    recordings = judge(details, version)
    if live is not None:
        lifecycle.after_stop(live, details, progress)
    return {"httpResponses": progress["responsesVerified"], "recordings": recordings, "probeDecisions": decisions,
            **notices, **counts}


def observe_legs(root, fixtures, cli, agent, java, report):
    for jar, version in fixtures:
        progress = {"phase": "fixture-setup", "responsesVerified": 0, "differentHttpStatus": None,
                    "probeDecisions": {}, "failureSite": None, "cleanupFailure": None, "outcomeMismatch": None}
        report["legProgress"][version] = progress
        try:
            report["legs"][version] = leg(root / version, jar, version, cli, agent, java, progress)
        except Exception as error:
            progress["failureSite"] = failure_site(error)
            if isinstance(error, OutcomeMismatch):
                progress["outcomeMismatch"] = error.evidence
            with (root / ("private-error-" + version + ".log")).open("x") as stream:
                traceback.print_exc(file=stream)
        else:
            progress["phase"] = "complete"


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
    report = {"status": "failed", "releaseAcceptance": False, "legs": {}, "legProgress": {}}
    try:
        installed_java.clean_checkout(REPO, args.source_sha)
        installed_java.java_identity(args.java, 21)
        cli, agent, identity = installed_java.installed_package(
            args.prefix, args.archive, args.archive_sha, args.source_sha, root / "extracted")
        report.update(archiveSha256=identity["archiveSha256"], sourceSha=identity["sourceCommit"])
        stage = "fixture-identity"
        require(verify_fixture(args.supported, "3.1.11")[0] == verify_fixture(args.unsupported, "3.1.10")[0],
                "application class bytes differ between the two real fixtures")
        stage = "installed-legs"
        observe_legs(root, ((args.supported, "3.1.11"), (args.unsupported, "3.1.10")),
                     cli, agent, args.java, report)
        if set(report["legs"]) == {"3.1.11", "3.1.10"}:
            stage, report["status"] = "complete", "passed"
    except Exception:
        # Keep exception text, command output and any bootstrap material out of the public receipt.
        with (root / "private-error.log").open("x") as stream:
            traceback.print_exc(file=stream)
    report["stage"] = stage
    (root / "counts.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
