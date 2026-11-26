#!/usr/bin/env python3
"""Bounded hosted #105 proof using the installed CLI/agent and real Spring fixture.

Raw HTTP, API, CLI and process output stays private. This qualifies neither the
JHipster campaign nor a ledger row; route-less inventory never repairs attribution.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import queue
import shutil
import subprocess
import sys
import time
import threading
import traceback

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "campaigns/lib"))
import boundary_diagnostics  # noqa: E402
import collect_sinks  # noqa: E402
from campaigns.java.jhipster.harness import partial_provenance  # noqa: E402
from detail_pages import bound_page_end  # noqa: E402
import installed  # noqa: E402
import xcamp  # noqa: E402
import xinstr  # noqa: E402

CHECKS = ("archive-verified", "fresh-install-verified", "installed-bytes-verified",
          "owned-spring-bound-port", "initial-api-empty", "mapped-request-complete",
          "committed-filter-403", "route-less-inventory-exact", "strict-attribution-preserved",
          "post-stop-api-exact", "cli-list-show-complete", "same-recording-paginated-provenance")


def require(ok):
    if not ok:
        raise ValueError("focused fixture assertion failed")


class FixtureInstall(installed.InstalledCampaign):
    """Reuse the package verifier and installer, without upstream campaign work."""

    def prerequisites(self):
        require(sys.platform == "linux" and self.env.get("GITHUB_ACTIONS") == "true")
        require(re.fullmatch(r"[0-9a-f]{40}", self.source_sha) is not None)
        require(re.fullmatch(r"[0-9a-f]{64}", self.package_sha) is not None)
        require(self.java.is_absolute() and self.java.is_file() and os.access(self.java, os.X_OK))
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
        require(revision == self.source_sha and installed.digest(self.input_archive) == self.package_sha)
        shutil.copyfile(self.input_archive, self.archive)
        require(installed.digest(self.archive) == self.package_sha)
        return 0


def wait_port(process, path, deadline):
    """Drain the owned startup pipe and wait on its explicit bound-port signal."""
    observed = queue.Queue(maxsize=1)

    def drain():
        announced = False
        try:
            with path.open("xb") as log:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    port = xcamp.spring_bound_port(line.decode("utf-8", "replace"))
                    if port is not None and not announced:
                        observed.put(port)
                        announced = True
        except OSError:
            pass
        finally:
            if not announced:
                observed.put(None)

    threading.Thread(target=drain, daemon=True).start()
    try:
        port = observed.get(timeout=max(0, deadline - time.monotonic()))
    except queue.Empty:
        raise TimeoutError("owned Spring startup deadline") from None
    require(port is not None and process.poll() is None)
    return port


def terminal_pair(api):
    return len(api["details"]) == 2 and all(d.get("completion") == "complete" for d in api["details"].values())


def last_read_counts(api):
    """Return only the last returned read's finite labels and counts. A raised call has no read."""
    if not isinstance(api, dict):
        return None
    listed, details, failure = api.get("recordings"), api.get("details"), api.get("readFailure")
    counts = None
    if isinstance(details, dict) and len(details) <= 400:
        counts = dict.fromkeys(("complete", "partial", "invalid", "unavailable", "other"), 0)
        for detail in details.values():
            state = detail.get("completion") if isinstance(detail, dict) else None
            counts[state if isinstance(state, str) and state in counts else "other"] += 1
    observed_failure = None
    if isinstance(failure, dict):
        stage, reason = failure.get("stage"), failure.get("reason")
        if stage in boundary_diagnostics.READ_STAGES and reason in boundary_diagnostics.READ_REASONS:
            observed_failure = {"stage": stage, "reason": reason}
    return {"ok": api.get("ok") if type(api.get("ok")) is bool else None,
            "listed": len(listed) if isinstance(listed, list) and len(listed) <= 400 else None,
            "detailCompletion": counts, "readFailure": observed_failure}


def read_until(client, directory, predicate, deadline, progress):
    client.deadline = deadline
    started, returned, last = 0, 0, None
    try:
        while time.monotonic() < deadline:
            started += 1
            progress["stage"] = "collect-api"
            last = xinstr.collect_api(client, directory)
            returned = started
            progress["stage"] = "require-api-read"
            require(last["ok"])
            progress["stage"] = "check-terminal-pair"
            if predicate(last):
                # A poll can start on time while its final read or validation runs late.
                if time.monotonic() <= deadline:
                    return last
                break
        progress["stage"] = "terminal-pair-deadline"
        raise TimeoutError("focused API observation deadline")
    finally:
        client.deadline = None
        # No projection work inside the observation loop or extension of its deadline.
        progress.update(pollsStarted=started if started <= 1_000_000 else None,
                        lastReturnedPoll=returned if returned <= 1_000_000 else None,
                        lastRead=last_read_counts(last))


EXPECTED_REFUSAL = {
    "listedNewRecordings": 2, "newRecordings": 2, "namedMatched": 1, "optionalNamed": 0,
    "missingNamed": 0, "capacityRejected": 0, "unexpectedRoots": 0, "unclassifiedRecordings": 0,
    "unreadRecordings": 0, "routeLess": [
        {"completion": "complete", "method": "GET", "outcome": "responded", "httpStatus": 403,
         "recordings": 1}],
    # Only the mapped POST can be assigned. The observed route-less GET remains unassigned.
    "unassignedRecordings": 1, "assignedPartialRecordings": 0, "overmatchedRequests": 0,
    "unmatchedSentRequests": 0, "unaccountedRequests": 0, "excessAccountedRequests": 0,
}


def verify_refusal_boundary(client, directory, sent, expected, optional, deadline, summary):
    progress = {"stage": "collect-api", "pollsStarted": 0, "lastReturnedPoll": 0, "lastRead": None,
                "snapshotMatches": None, "strictFacts": None}
    summary["post403"] = progress
    api = read_until(client, directory, terminal_pair, deadline, progress)
    progress["stage"] = "strict-accounting"
    strict = xinstr.burst_accounting(api["details"], sent, expected, {}, optional_roots=optional)
    progress["stage"] = "snapshot"
    snapshot = boundary_diagnostics.snapshot(api["details"], api["recordings"], {}, strict)
    progress["stage"] = "require-inventory"
    # These diagnostic keys are fixed. No returned routes, identifiers or unexpected fields escape.
    progress["snapshotMatches"] = {
        "fieldSet": set(snapshot) == set(EXPECTED_REFUSAL),
        # Reuse the producer's closed v2 schema before copying any actual buckets.
        "routeLess": snapshot["routeLess"] if boundary_diagnostics._snapshot(snapshot, 2) else None,
        "mismatched": [key for key, want in EXPECTED_REFUSAL.items() if snapshot.get(key) != want],
        "counts": {key: value for key, value in snapshot.items() if key in EXPECTED_REFUSAL and key != "routeLess"
                   and type(value) is int and 0 <= value <= boundary_diagnostics.MAX_COUNT},
    }
    require(snapshot == EXPECTED_REFUSAL)
    summary["checks"]["route-less-inventory-exact"] = "passed"
    progress["stage"] = "require-strict-exclusion"
    progress["strictFacts"] = {"unverified": strict["verified"] is False,
                               "noOptionalIds": strict["optionalRootIds"] == [],
                               "oneNamed": type(strict["recordingCount"]) is int and strict["recordingCount"] == 1}
    require(all(progress["strictFacts"].values()))
    summary["checks"]["strict-attribution-preserved"] = "passed"
    progress["stage"] = "complete"
    return api, strict, snapshot


def compare_mapped_pages(root, api, cli_rows, detail_limit):
    mapped = [rid for rid, detail in api["details"].items()
              if xinstr.recording_matches(detail, "POST", "/orders")]
    require(len(mapped) == 1)
    rid = mapped[0]
    state, _, api_doc = collect_sinks.paired_api_detail(root / "post-stop-api", rid)
    require(state == "complete-read" and api_doc is not None and api_doc["_verifiedDetailPages"] >= 2)
    require(api_doc.get("_allDetailMarkerListsEmpty") is True)
    metadata = [row for row in api["recordings"] if row.get("recordingId") == rid]
    require(len(metadata) == 1)
    index = cli_rows.index(rid)
    files = sorted((root / "sinks/cli").glob(f"detail-{index:03d}-*.stdout"))
    require(2 <= len(files) <= collect_sinks.MAX_PAGES)
    events, seen = [], set()
    previous, cursor, first = -1, None, None
    for page, path in enumerate(files):
        require(path.name == f"detail-{index:03d}-{page:02d}.stdout")
        doc = json.loads(path.read_bytes())
        previous = bound_page_end(doc, "recording_id", rid, cursor, detail_limit, previous)
        require(doc.get("incomplete_evidence") == [] and doc["events"])
        if first is None:
            first = doc
        events.extend(doc["events"])
        cursor = doc["next_cursor"]
        if page == len(files) - 1:
            require(cursor is None)
        else:
            require(isinstance(cursor, str) and cursor and cursor not in seen)
            seen.add(cursor)
    require([(e["sequence"], e["kind"]) for e in events]
            == [(e["sequence"], e["kind"]) for e in api_doc["events"]])
    # Both readers use the same detail query. The post-stop list counts durable segment
    # metadata independently, so a shared omission must still fail this fixture.
    inventory = metadata[0]
    require(inventory.get("eventCount") == str(len(events))
            and inventory.get("firstSequence") == events[0]["sequence"]
            and inventory.get("lastSequence") == events[-1]["sequence"])
    api_observation = partial_provenance.project(api_doc, whole=True)
    cli_observation = partial_provenance.project({**first, "events": events}, whole=True)
    require(partial_provenance.valid(cli_observation) and cli_observation == api_observation
            and cli_observation["scope"] == "whole-recording"
            and cli_observation["eventKinds"]["request_update"] > 0
            and cli_observation["eventKinds"]["response"] > 0)
    return {"apiPages": api_doc["_verifiedDetailPages"], "cliPages": len(files), "comparedEvents": len(events)}


def prove(candidate, fixture, summary):
    root, env, project = candidate.root, candidate.env, candidate.source
    # Source is copied to the fresh private project; no upstream application is patched.
    project.mkdir(mode=0o700)
    shutil.copytree(REPO / "adapters/java/spring-fixture/src/main/java", project / "src/main/java")
    env["XTRACE_CAMPAIGN_ROOT"] = str(root / "campaign")
    os.environ["XTRACE_CAMPAIGN_ROOT"] = env["XTRACE_CAMPAIGN_ROOT"]
    # Reuse the full inventory binding already used by the installed campaign.
    import run as campaign_run
    xtrace, agent, package = campaign_run.installed_package(
        candidate.prefix, candidate.archive, candidate.package_sha, candidate.source_sha)
    (root / "installed-identity.json").write_text(json.dumps({
        "package": package, "fixtureSha256": installed.digest(fixture),
        "fixturePath": str(fixture), "cliPath": xtrace, "agentPath": agent,
        "projectPath": str(project)}) + "\n")
    summary["checks"]["installed-bytes-verified"] = "passed"
    require(candidate.command([xtrace, "init", "--project-dir", str(project),
                               "--display-name", "focused fixture"]) == 0)
    launcher = viewer = None
    sent = [("mapped", "POST", "/orders")]
    expected = {"mapped": [{"method": "POST", "route": "/orders"}]}
    optional = (("GET", "/__fixture/refusal/committed/probe", 403),)
    try:
        with (root / "console/spring.stderr").open("wb") as err:
            launcher = subprocess.Popen(
                [xtrace, "run", "--project-dir", str(project), "--java-agent", agent,
                 "--app-package", "dev.xtrace.fixture", "--source-root", "src/main/java",
                 "--capture-depth", "standard", "--", str(candidate.java), "-jar", str(fixture),
                 "--server.port=0", "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"],
                cwd=project, env=env, stdout=subprocess.PIPE, stderr=err, start_new_session=True)
        port = wait_port(launcher, root / "console/spring.stdout", time.monotonic() + 60)
        summary["checks"]["owned-spring-bound-port"] = "passed"
        viewer, ready = xinstr.start_viewer(xtrace, project, env, root / "console/viewer.stderr")
        client = xinstr.ViewerClient(ready["origin"])
        token = xinstr.bootstrap_token(ready["url"])
        require(token is not None)
        client.exchange(token)
        initial = xinstr.collect_api(client, root / "initial-api")
        require(initial["ok"] and not initial["recordings"] and not initial["details"])
        summary["checks"]["initial-api-empty"] = "passed"
        response = xcamp.http_request(f"http://127.0.0.1:{port}", "POST", "/orders",
                                     headers={"Content-Type": "application/json"},
                                     body=b'{"description":"synthetic","bodyCanary":"","errorCanary":""}', timeout=10)
        require(response["status"] == 201)
        boundary = xinstr.wait_burst_boundary(client, root / "mapped-api", sent, expected, {},
                                              time.monotonic() + 30, require_complete=True, diagnose=True)
        require(boundary["verified"] and boundary["recordingCount"] == 1 and boundary["capacityDrops"] == 0)
        summary["checks"]["mapped-request-complete"] = "passed"
        response = xcamp.http_request(f"http://127.0.0.1:{port}", "GET",
                                     "/__fixture/refusal/committed/probe", timeout=10)
        require(response["status"] == 403)
        summary["checks"]["committed-filter-403"] = "passed"
        try:
            api, strict, snapshot = verify_refusal_boundary(
                client, root / "campaign/java/jhipster/instrumented-1/api", sent, expected, optional,
                time.monotonic() + 30, summary)
        except Exception as error:
            if "post403" in summary:
                kinds = ((TimeoutError, "deadline"), (OSError, "io"), (KeyError, "missing-field"),
                         (TypeError, "type"), (ValueError, "validation"))
                summary["post403"]["failure"] = next(
                    (label for cls, label in kinds if isinstance(error, cls)), "other")
            raise
        (root / "boundary-private.json").write_text(json.dumps({"mapped": boundary, "strict": strict,
                                                               "snapshot": snapshot}) + "\n")
        summary["inventory"] = snapshot
        # Signal only the launcher we own. Its handler forwards shutdown and drains the daemon.
        launcher.terminate()
        require(launcher.wait(timeout=15) == 143)
        final = xinstr.collect_api(client, root / "post-stop-api", verified_detail_limit=2)
        require(final["ok"] and set(final["details"]) == set(api["details"]) and terminal_pair(final))
        summary["checks"]["post-stop-api-exact"] = "passed"
    finally:
        for process in (viewer, launcher):
            if process is not None:
                xinstr.stop_process_group(process)
    require(collect_sinks.collect(root, list_limit=1, detail_limit=2))
    status = json.loads((root / "sinks/cli-status.json").read_text())
    require(status["recordings"] == 2 and status["completedDetails"] == 2
            and status["listCommands"] == 2 and status["detailCommands"] >= 3)
    cli_rows = [row["recording_id"] for path in sorted((root / "sinks/cli").glob("list-*.stdout"))
                for row in json.loads(path.read_bytes())["recordings"]]
    require(set(cli_rows) == set(api["details"]))
    summary["checks"]["cli-list-show-complete"] = "passed"
    summary["pairedRead"] = compare_mapped_pages(root, final, cli_rows, 2)
    summary["checks"]["same-recording-paginated-provenance"] = "passed"
    summary["cli"] = {key: status[key] for key in ("listCommands", "detailCommands", "recordings", "completedDetails")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--public-out", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    summary = {"schema": "xtrace-focused-boundary-fixture/1", "releaseAcceptance": False,
               "checks": dict.fromkeys(CHECKS, "unreached"), "inventory": None, "cli": None, "status": "failed"}
    try:
        root = args.private_root.absolute()
        installed.prepare_root(root)
        require(args.fixture.is_absolute() and args.fixture.is_file())
        candidate = FixtureInstall(root, args.archive, args.package_sha256, args.source_sha, args.java)
        with (root / "console/focused.stdout").open("w") as out, \
                (root / "console/focused.stderr").open("w") as err:
            from contextlib import redirect_stdout, redirect_stderr
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    require(candidate.prerequisites() == 0 and candidate.verify_archive() == 0)
                    summary["sourceSha"] = candidate.source_sha
                    summary["archiveSha256"] = candidate.package_sha
                    summary["checks"]["archive-verified"] = "passed"
                    require(candidate.install() == 0)
                    require(candidate.command(["sh", str(candidate.prefix / "current/install.sh"), "verify",
                                               "--prefix", str(candidate.prefix)]) == 0)
                    summary["checks"]["fresh-install-verified"] = "passed"
                    prove(candidate, args.fixture, summary)
                    summary["status"] = "passed"
                except Exception:
                    traceback.print_exc()
    except Exception:
        # Early path/argument/admission failures have no authorized raw output channel.
        pass
    args.public_out.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.public_out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
    print("Focused boundary fixture: " + summary["status"])
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
