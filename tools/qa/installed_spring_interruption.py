"""Verify recovery of an interrupted request from an installed Spring launch."""

import argparse
import http.client
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from catalog_link_journey import Journey, JourneyFailure, require


def wait_for(check, label):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.05)
    raise JourneyFailure(label)


def persistent_frames(window):
    return {(event["event_id"], event["kind"], event["symbol"])
            for event in window["events"] if event["event_id"] is not None}


def interrupt(journey, classpath):
    require(journey.cli.resolve(strict=True)
            == (journey.installed_prefix / "current/bin/xtrace").resolve(strict=True),
            "installed_launcher")
    agent = (journey.installed_prefix
             / "current/share/xtrace/packs/java/agent/xtrace-java-agent.jar").resolve(strict=True)
    journey.call("init", "init")
    args = [journey.cli, "run", "--project-dir", journey.project, "--java-agent", agent,
            "--app-package", "dev.xtrace.interruptfixture", "--", "java", "-cp", classpath,
            "dev.xtrace.interruptfixture.SpringInterruptedFixture", "--server.address=127.0.0.1",
            "--server.port=0", "--logging.level.root=WARN"]
    stdout, stderr = journey.root / "app.log", journey.root / "app.stderr"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        supervisor = subprocess.Popen(args, env=journey.env, stdin=subprocess.DEVNULL,
                                      stdout=out, stderr=err)
    connection = None
    try:
        def ready():
            require(supervisor.poll() is None, "supervisor_exited_early")
            return re.search(rb"^INTERRUPT_READY ([0-9]{1,5}) ([0-9]+)$",
                             stdout.read_bytes(), re.MULTILINE)

        port, app_pid = map(int, wait_for(ready, "readiness_timeout").groups())
        require(0 < port <= 65535 and app_pid > 1, "fixture_identity")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request("GET", "/held?private=" + journey.seed)
        wait_for(lambda: b"\nINTERRUPT_HELD\n" in stdout.read_bytes(), "handler_never_held")

        def durable():
            rows = journey.call("read_open_recordings", "recording", "list")["recordings"]
            if not rows or int(rows[0]["event_count"]) == 0:
                return None
            require(len(rows) == 1 and rows[0]["status"] == "recording", "one_open_recording")
            recording = rows[0]["recording_id"]
            window = journey.call("read_open_recording", "recording", "show", recording)
            facts = persistent_frames(window)
            expected = any(kind == "recording_event_kind:frame_enter" and symbol == "SpringInterruptedFixture.hold"
                           for _, kind, symbol in facts)
            if not expected:
                return None
            require(window["outcome"] is None and window["duration_ns"] is None,
                    "open_request_had_terminal_facts")
            return recording, facts

        recording, facts = wait_for(durable, "held_recording_not_durable")
        # Linux pins the target process identity across parent verification and the signal.
        pidfd = os.pidfd_open(app_pid)
        try:
            parent = re.search(r"^PPid:\s+([0-9]+)$", Path(f"/proc/{app_pid}/status").read_text(),
                               re.MULTILINE)
            require(parent and int(parent[1]) == supervisor.pid and supervisor.poll() is None,
                    "jvm_is_not_the_owned_child")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        finally:
            os.close(pidfd)
        require(supervisor.wait(timeout=25) == 137, "interrupted_supervisor_exit")
    finally:
        if connection is not None:
            connection.close()
        if supervisor.poll() is None:
            supervisor.send_signal(signal.SIGTERM)
            try:
                supervisor.wait(timeout=15)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait(timeout=5)
        require(journey.seed.encode() not in stdout.read_bytes() + stderr.read_bytes(),
                "application_canary")
    return recording, facts


def verify_partial(journey, recording, facts):
    prior = journey.call("read_after_jvm_interruption", "recording", "show", recording)
    require(prior["status"] in ("recording", "partial"), "interruption_hid_the_recording")
    started = None
    try:
        started = journey.call("restart_installed", "restart")
        require(started["kind"] == "restarted", "real_restart")
        if prior["status"] == "recording":
            recovered = started["stopped"]["recovered_recordings"]
            require([(row["recording_id"], row["completion"]) for row in recovered]
                    == [(recording, "partial")], "restart_recovered_exact_recording")
        window = journey.call("read_recovered_recording", "recording", "show", recording)
        require(window["recording_id"] == recording and window["status"] == "partial"
                and window["completion"] == "partial" and window["incomplete_evidence"]
                and window["outcome"] is None and window["duration_ns"] is None,
                "partial_became_complete_or_lost_evidence")
        require(facts <= persistent_frames(window), "acknowledged_frames_lost")
        require(not any(event["kind"] == "recording_event_kind:response"
                        for event in window["events"]), "response_was_invented")
    finally:
        journey.call("stop_installed", "stop", allow_not_running=started is None)
    reopened = journey.call("reopen_after_stop", "recording", "show", recording)
    require(reopened["completion"] == "partial" and reopened["recording_id"] == recording
            and facts <= persistent_frames(reopened), "reopen_lost_partial_evidence")
    print("Installed Spring JVM interruption: one stable partial recording, held frame preserved, no HTTP finish")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("prefix", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("classpath")
    args = parser.parse_args()
    try:
        test = Journey(args.workspace, args.prefix / "bin/xtrace", args.root, "spring-mvc", args.prefix)
        recording, facts = interrupt(test, args.classpath)
        verify_partial(test, recording, facts)
    except JourneyFailure as error:
        raise SystemExit(f"Installed Spring interruption failed: {error}") from None
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, http.client.HTTPException) as error:
        raise SystemExit(f"Installed Spring interruption failed: {type(error).__name__}") from None
