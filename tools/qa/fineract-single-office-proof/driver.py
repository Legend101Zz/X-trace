"""Hosted single ordinary seeded office read through the official installed X-trace package."""
from contextlib import contextmanager
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import time

from receipt import check, checkpoint, qualifies, valid

ROOT = Path(os.environ["PROOF"])
REPO = Path.cwd().resolve()
HARNESS = REPO / "campaigns/java/fineract/harness"
sys.path[:0] = [str(REPO), str(HARNESS), str(REPO / "campaigns/lib")]
import installed_java
import fineract_detail_evidence as detail
import fineract_office_observation as observer
from campaigns.java.fineract.harness.installed import InstalledCampaign
from campaigns.java.fineract.harness import privacy
import xcamp
from transport import StartupDeadline, deadline, OfficeRead, release_process, viewer
from installed_sinks import MAX_OUTPUT


class Progress:
    def __init__(self):
        self.doc = valid(json.loads((ROOT / "checkpoint.json").read_bytes()))
        self.locked = None
        self.stop = None

    def save(self):
        checkpoint(ROOT, self.doc)

    @contextmanager
    def doing(self, key, section="phases"):
        row = self.doc[section]
        check(row[key] == "unreached")
        row[key] = "started"
        self.save()
        try:
            yield
        except BaseException:
            row[key] = "failed"
            raise
        else:
            row[key] = "passed"
        finally:
            self.save()

    def release(self, key, operation):
        with self.doing(key, "release"):
            return operation()


def close_viewer(proc, key, progress):
    with progress.doing(key, "release"):
        row = progress.doc["viewerShutdown"][key]
        code = proc.poll()
        if code is not None:
            row.update(state="early-exit", exitCode=code)
            raise RuntimeError("viewer already exited")
        # This is the unreaped direct child; no other waiter can reap or reuse its PID.
        # Send directly so a vanished process isn't mistaken for a successful signal.
        try:
            os.kill(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            row.update(state="signal-raced-exit", exitCode=proc.poll())
            raise
        except OSError:
            row.update(state="signal-error", exitCode=proc.poll())
            raise
        row["state"] = "term-sent"
        progress.save()
        try:
            code = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            row.update(state="wait-expired", exitCode=proc.poll())
            raise
        row.update(state="exit-after-term", exitCode=code)
        check(code == 0)


def setup(progress):
    root = ROOT / "run"
    with progress.doing("setup"):
        installed_java.private_dir(ROOT)
        root.mkdir(mode=0o700)
        for rel in ("console", "package", "unpacked", "home", "data", "tmp", "child-stderr", "campaign",
                    "campaign/java", "campaign/java/fineract", "capture"):
            (root / rel).mkdir(mode=0o700)
        (ROOT / "driver").mkdir(mode=0o700)
        privacy.mark_admitted(root)
        check(privacy.admitted(root))
        archive = ROOT / "dist/linux-x86_64/xtrace-0.0.1-linux-x86_64.tar.gz"
        package_sha = installed_java.private_file(ROOT / "package.sha256").read_text().strip()
        driver = InstalledCampaign(root, archive, package_sha,
                                   os.environ["PRODUCT"], Path(os.environ["JAVA_HOME"]) / "bin/java")
        # Keep wrapper/tool streams private and avoid ambient Java injection.
        os.environ.clear()
        os.environ.update(driver.env)
        check(xcamp.PLATFORM == "linux/amd64" and xcamp.REQUEST_HOOK is None)
        check(driver.prerequisites() == 0)
    for stage, operation in (("archive", driver.verify_archive), ("install", driver.install),
                             ("checkout", driver.checkout_upstream), ("tag-license", driver.source_verify),
                             ("database-image", lambda: driver.command(["docker", "pull", "--platform", "linux/amd64",
                                                                         driver.campaign["runtime"]["databaseImage"]])),
                             ("bootjar", driver.build_upstream)):
        with progress.doing(stage):
            check(operation() == 0)
    with progress.doing("identities"):
        from campaigns.java.fineract.harness import run
        pin = run.source_pin()
        image = driver.campaign["runtime"]["databaseImage"]
        check(pin["sha"] == "d5636847ac556c30b437254c353f05526d172b97" and pin["stableTag"] == "1.15.0"
              and pin["tagObjectSha"] == "9e76f088db71a4458b68f7855b03b21d23b86f1c"
              and pin["runtimeDatabaseImageId"].startswith("sha256:") and
              pin["databaseRepoDigest"].split("@")[-1] == image.split("@")[1] and
              pin["actualPlatform"] == "linux/amd64" and pin["hostJava"]["properties"]["os.name"] == "Linux"
              and len(pin["runtimeDependencies"]) == 5)
        cli, agent, package = installed_java.installed_package(driver.prefix, driver.archive, driver.package_sha,
                                                               driver.source_sha, root / "verified-payload")
        check(package["sourceCommit"] == driver.source_sha and package["archiveSha256"] == pin["packageArchiveSha256"])
        (root / "identities.json").write_text(json.dumps({"app": pin, "package": package}))
    return driver, run, cli, agent


def make_stack(run, cli, agent):
    launch = (cli, "run", "--project-dir", str(run.SRC), "--java-agent", agent,
              "--app-package", run.recording_evidence.APP_PACKAGE, "--source-root", run.recording_evidence.SOURCE_ROOT,
              "--capture-depth", "standard", "--")
    stack = run.make_stack("office-" + os.environ["GITHUB_RUN_ID"], launch)
    check(stack.mode == "host" and stack.jar == run.JAR and not stack._owned.containers
          and stack._owned.network is None and stack._proc is None)
    stack.env["XTRACE_DATA_HOME"] = os.environ["XCAMP_DATA_HOME"]
    # Preserve startup probes and their native boundaries while bounding an in-flight probe.
    for method, budget in (("_wait_db", 90), ("_wait_ready", 900)):
        original = getattr(stack, method)
        def bounded(original=original, budget=budget):
            with deadline(time.monotonic() + budget, error=StartupDeadline):
                return original()
        setattr(stack, method, bounded)
    return stack


def release_stack(stack, progress):
    """Retain #127's fresh creation IDs. Removal is allowed only after observed exit."""
    if stack._proc is not None:
        def launcher():
            was_running = stack._proc.poll() is None
            exit_code = release_process(stack._proc, 90)
            progress.doc["launcherExit"] = exit_code
            check(was_running and exit_code in (0, 143))
        try:
            progress.release("launcher", launcher)
        finally:
            # Keep the app's dependency live if the direct launcher has not exited.
            if stack._proc.poll() is not None:
                release_database(stack, progress)
    else:
        release_database(stack, progress)


def release_database(stack, progress):
    owner = stack._owned
    check(len(owner.containers) <= 1)
    if owner.containers:
        ident = owner.containers[0]
        def close_db():
            # --timeout=-1 disables Docker's escalation. The outer CLI call is bounded;
            # timeout leaves the container unremoved and its state unknown.
            xcamp.docker("stop", "--timeout=-1", ident, timeout=90)
            state = json.loads(xcamp.docker("inspect", "--format", "{{json .State}}", ident, timeout=15).stdout)
            check(state.get("Status") == "exited" and state.get("Running") is False and state.get("OOMKilled") is False
                  and type(state.get("ExitCode")) is int and state["ExitCode"] == 0)
        progress.release("databaseExit", close_db)
        with progress.doing("databaseRemove", "release"):
            result = xcamp.docker("rm", "-v", ident, timeout=15)
            check(result.stdout.strip() == ident)
            owner.containers.remove(ident)
    if owner.network is not None:
        # The shared owner's network cleanup is ID-bound; its container inventory is now empty.
        check(not owner.containers)
        progress.release("networkRemove", owner.cleanup)
        check(owner.network is None)


def project_live(row):
    wire = row["firstWirePage"]["capture"]
    kinds = wire["eventKinds"]
    return {"completion": wire["completion"], "terminal": row["terminalMetadata"], "drops": wire["capacityDrops"],
            "dropBucketState": wire["dropBuckets"]["state"], "positiveDropBuckets": wire["dropBuckets"]["positive"],
            "firstEvents": sum(kinds.values()), "firstResponses": kinds["response"], "firstGaps": kinds["gap"],
            "firstDatabaseStarts": kinds["database_start"], "firstDatabaseEnds": kinds["database_end"],
            **{k: row[k] for k in ("wholeEvents", "responses", "gaps", "resourceEnters", "gapReasons", "http200")}}


def poll(client, stack, before, project, capture, end, progress):
    doc = progress.doc
    while time.monotonic() < end:
        if stack._proc.poll() is not None:
            doc["lastPoll"] = "launcher-exited"
            break
        try:
            current, snap = client.snapshot(capture / "live", project, end)
            if current is not None:
                rid, row = observer.observe(before, current, snap)
        except TimeoutError:
            doc["selectionUnresolved"] = True
            doc["lastPoll"] = "deadline"
            break
        except (ValueError, OSError, RecursionError):
            doc["lastPoll"] = "incomplete"
            doc["selectionUnresolved"] = True
            break
        if time.monotonic() >= end:
            doc["selectionUnresolved"] = True
            doc["lastPoll"] = "deadline"
            break
        if stack._proc.poll() is not None:
            doc["lastPoll"] = "launcher-exited"
            break
        if current is None:
            doc["selectionUnresolved"] = True
            doc["lastPoll"] = "incomplete"
            break
        doc["pollsCompleted"] += 1
        doc["lastPoll"] = row["selection"]
        if rid is not None:
            if progress.locked is None:
                progress.locked = rid
            if rid != progress.locked:
                doc["identityConflict"] = True
                break
            doc["selected"] = project_live(row)
            progress.save()
            if doc["selected"]["terminal"] == "present" and doc["selected"]["completion"] != "unavailable":
                break
        elif progress.locked is not None:
            # Retain the first identity, even if a later complete poll cannot resolve it.
            doc["selectionUnresolved"] = True
            break
        try:
            stack._proc.wait(timeout=min(0.1, max(0, end - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
    progress.save()
    check(progress.locked is not None and not doc["identityConflict"] and not doc["selectionUnresolved"]
          and doc["lastPoll"] != "launcher-exited")


def live_and_release(cli, stack, run, project, capture, progress):
    try:
        with progress.doing("startup"):
            # Stack.up() owns a forced cleanup fallback. This driver supplies the sole
            # cleanup for the unchanged startup body, including partial startup.
            stack._up()
            check(stack._proc is not None and stack._proc.poll() is None)
        with viewer(cli, run.SRC, capture / "live-viewer.log",
                    lambda proc: close_viewer(proc, "liveViewer", progress)) as client:
            with progress.doing("before"):
                before, _ = client.snapshot(capture / "before", project, time.monotonic() + 60)
                check(before is not None and stack._proc.poll() is None)
            end = time.monotonic() + 60
            with progress.doing("office"):
                run.read_seeded_office_list(OfficeRead(stack, run, end, progress.doc, progress.save))
                check(time.monotonic() < end)
            with progress.doing("poll"):
                poll(client, stack, before, project, capture, end, progress)
    finally:
        release_stack(stack, progress)


def explicit_stop(cli, run, project, progress):
    with progress.doing("explicit-stop"):
        progress.stop = subprocess.run([cli, "stop", "--project-dir", str(run.SRC)], capture_output=True, timeout=60)
        try:
            result = observer.phase.stop_projection(progress.stop)
            check(result["project"] == project)
        except (ValueError, KeyError, TypeError):
            progress.doc["stopResult"] = "rejected"
            raise
        progress.doc["stopResult"] = "validated"
        if progress.locked:
            rows = [x for x in result["recordings"] if x["recording"] == progress.locked]
            progress.doc["sameIdRecovery"] = "listed" if rows else "not-listed"
            progress.doc["recoveredCompletion"] = rows[0]["completion"] if rows else None


def final_read(cli, run, project, capture, progress):
    if not progress.locked:
        return
    with progress.doing("final-read"):
        with viewer(cli, run.SRC, capture / "final-viewer.log",
                    lambda proc: close_viewer(proc, "finalViewer", progress)) as client:
            inv, _ = client.snapshot(capture / "api", project, time.monotonic() + 60, paired=False)
            check(inv is not None and progress.locked in inv.ranges)
        evidence = observer.after_stop(capture, project, progress.locked, progress.stop, MAX_OUTPUT)
        doc = progress.doc
        doc["sameIdRecovery"] = evidence["recovery"]
        doc["recoveredCompletion"] = evidence["result"]
        doc["finalApiRead"] = evidence["finalApiRead"]
        if evidence["finalApi"] is not None:
            doc["finalCompletion"] = evidence["finalApi"]["completion"]
        check(evidence["finalApiRead"] == "whole-recording")


def main():
    os.umask(0o077)
    progress = Progress()
    driver, run, cli, agent = setup(progress)
    capture = driver.root / "capture"
    with progress.doing("init"):
        result = subprocess.run([cli, "init", "--project-dir", str(run.SRC), "--display-name", "campaign"],
                                check=True, timeout=120, capture_output=True)
        project = json.loads(result.stdout)["project_id"]
        check(detail.uuid_value(project))
    stack = make_stack(run, cli, agent)
    try:
        live_and_release(cli, stack, run, project, capture, progress)
    finally:
        if stack._proc is not None and stack._proc.poll() is not None:
            try:
                explicit_stop(cli, run, project, progress)
            finally:
                final_read(cli, run, project, capture, progress)
    check(qualifies(progress.doc))


if __name__ == "__main__":
    main()
