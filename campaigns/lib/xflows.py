"""Product lifecycle and focused-capture flows for the Java campaigns (stdlib only).

Four flows, each against the PACKAGED `xtrace`, each judged only from what the product itself reports (CLI JSON documents and
the local read API, schema/xtp-client/openapi.yaml). Nothing here is a relabelled skip: a flow that cannot reach its
observation fails with the reason.

  record-stop-flow          xtrace record -> app started with the armed one-shot bootstrap -> requests -> xtrace stop;
                            the recordings are persisted (complete) and readable.
  restart-reopen            xtrace restart; every earlier recording still reads back identically.
  partial-recording-reopen  a request is held open mid-capture, the app is killed (a pid this harness started), xtrace stop
                            seals what was left open; the interrupted recording reopens as partial, never as complete.
  active-line-frames / frame-values
                            `xtrace run --capture-depth focused`; line_cursor events carry an observed line distinct from
                            the method extent, and frame events carry captured bindings.
  focused-canary-injection / focused-redaction-control / focused-value-control / standard-no-values
                            each request has its own completed recording. Secret-shaped lastName values must be redacted;
                            ordinary lastName Strings are captured only in focused mode. Standard capture records no values.

Focused capture records ordinary String arguments and locals, including business parameters, when neither their names nor
their contents match the redaction rules. Exception messages receive content-pattern redaction only. Metadata exclusion
and a clean secret-canary scan alone do not prove value redaction; the separate business controls must pass too.

The judge_* functions are pure and unit-tested (test_xflows.py); the run_* functions drive real processes.
"""
from __future__ import annotations

import json
from contextlib import ExitStack
import os
import pathlib
import secrets
import shlex
import signal
import socket
import subprocess
import time
from typing import Any, Callable

import xinstr

PRIVACY_STEPS = ("focused-canary-injection", "focused-redaction-control", "focused-value-control", "standard-no-values")
STEP_NAMES = ("record-stop-flow", "restart-reopen", "partial-recording-reopen", "active-line-frames", "frame-values", *PRIVACY_STEPS)

# Labels and route templates contain no injected values. The two search controls
# share a route, so each must finish persisting before the next request is sent.
FOCUSED_REQUESTS = {
    "owner": ("GET", "/owners/{ownerId}"), "search": ("GET", "/owners"), "vets": ("GET", "/vets"),
    "form": ("POST", "/owners/new"), "secret": ("GET", "/owners"), "plain": ("GET", "/owners"),
}


class CanaryEvidenceError(RuntimeError):
    """A probe lacks recording evidence; messages contain no request values."""


# ------------------------------------------------------------------ helpers --
def parse_doc(text: str) -> Any:
    """Parse the CLI's single JSON document; never mistake an inner scalar for the response."""
    try:
        return json.loads(text)
    except ValueError:
        return None


def find_key(doc: Any, key: str) -> Any:
    """First value stored under `key` anywhere in the JSON document (the CLI may wrap its payload)."""
    if isinstance(doc, dict):
        if key in doc:
            return doc[key]
        for v in doc.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(doc, list):
        for v in doc:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # liveness probe only, no signal is delivered
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_gone(pid: int, seconds: float = 10.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if not pid_alive(pid):
            return True
        time.sleep(0.2)
    return not pid_alive(pid)


def cli(xtrace: str, args: list[str], env: dict, timeout: float = 120.0) -> tuple[int, Any]:
    r = subprocess.run([xtrace, *args], env=env, capture_output=True, text=True, timeout=timeout)
    return r.returncode, parse_doc(r.stdout) if r.stdout.strip() else parse_doc(r.stderr)


def list_ids(xtrace: str, project_dir: pathlib.Path, env: dict) -> set[str]:
    ids: set[str] = set()
    after = None
    for _ in range(20):
        args = ["recording", "list", "--project-dir", str(project_dir), "--limit", "200"] + (["--after", after] if after else [])
        rc, doc = cli(xtrace, args, env)
        if rc != 0 or not isinstance(doc, dict):
            raise RuntimeError(f"recording list exited {rc}")
        rows = find_key(doc, "recordings") or []
        ids.update(r["recording_id"] for r in rows if isinstance(r, dict) and r.get("recording_id"))
        after = find_key(doc, "next_after")
        if not after or not rows:
            break
    return ids


def read_api(xtrace: str, project_dir: pathlib.Path, env: dict, out_dir: pathlib.Path) -> dict[str, Any]:
    """All recordings and event windows through the product's own read API (a fresh viewer process)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    viewer = None
    try:
        viewer, ready = xinstr.start_viewer(xtrace, project_dir, env, out_dir / "viewer.log")
        client = xinstr.ViewerClient(ready["origin"])
        token = xinstr.bootstrap_token(ready["url"])
        if not token:
            raise RuntimeError("no bootstrap token in viewer url")
        client.exchange(token)
        return xinstr.collect_api(client, out_dir)
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}", "recordings": [], "details": {}}
    finally:
        if viewer is not None:
            xinstr.stop_process_group(viewer)


def completion_of(detail: dict) -> str | None:
    c = detail.get("completion")
    return c if isinstance(c, str) else None


def event_count(detail: dict) -> int:
    return len(detail.get("events", []))


# ------------------------------------------------------------------- judges --
def judge_record_stop(*, record_rc: int, record_doc: Any, served: dict[str, int | None], stop_rc: int, daemon_gone: bool,
                      new_details: dict[str, dict], wanted: list[tuple[str, str]]) -> tuple[str, str]:
    if record_rc == 9:
        return "not-implemented", "xtrace record exited 9"
    if record_rc != 0:
        return "fail", f"xtrace record exited {record_rc}"
    if not find_key(record_doc, "bootstrap_path"):
        return "fail", "xtrace record exited 0 but printed no bootstrap_path to launch the application with"
    bad = {p: s for p, s in served.items() if s != 200}
    if bad:
        return "fail", f"the application armed by xtrace record did not answer: {json.dumps(bad, sort_keys=True)}"
    if stop_rc != 0:
        return "fail", f"xtrace stop exited {stop_rc}"
    if not daemon_gone:
        return "fail", "the record daemon was still alive 10 s after xtrace stop exited 0"
    missing, not_complete = [], []
    for method, route in wanted:
        hits = [d for d in new_details.values() if xinstr.recording_matches(d, method, route)]
        if not hits:
            missing.append(f"{method} {route}")
        elif not any(completion_of(d) == "complete" and event_count(d) > 0 for d in hits):
            not_complete.append(f"{method} {route}")
    if missing or not_complete:
        parts = []
        if missing:
            parts.append("no persisted recording for " + ", ".join(missing))
        if not_complete:
            parts.append("recorded but not complete for " + ", ".join(not_complete))
        return "fail", f"{len(new_details)} new recordings after stop; " + "; ".join(parts)
    return "pass", (f"record armed one launch, {len(served)} requests answered 200, stop exited 0 and the daemon is gone; "
                    f"{len(new_details)} new recordings persisted and readable, complete for {len(wanted)} requested routes")


def judge_restart_reopen(*, restart_rc: int, restart_doc: Any, started_alive: bool, before: dict[str, tuple[str | None, int]],
                         after_details: dict[str, dict], stop_rc: int) -> tuple[str, str]:
    if restart_rc == 9:
        return "not-implemented", "xtrace restart exited 9"
    if restart_rc != 0:
        return "fail", f"xtrace restart exited {restart_rc}"
    if not before:
        return "fail", "no earlier recording existed to reopen (the preceding flow produced none)"
    if not started_alive:
        return "fail", "xtrace restart exited 0 but the daemon it reported is not alive"
    changed, gone = [], []
    for rid, (completion, count) in before.items():
        d = after_details.get(rid)
        if d is None:
            gone.append(rid[:8])
        elif completion_of(d) != completion or event_count(d) != count:
            changed.append(f"{rid[:8]} ({completion},{count})->({completion_of(d)},{event_count(d)})")
    if gone or changed:
        return "fail", (f"{len(before)} recordings before restart; missing after: {','.join(gone) or 'none'}; "
                        f"changed: {'; '.join(changed) or 'none'}")
    readable = [d for rid, d in after_details.items() if rid in before and xinstr.request_info(d)]
    if not readable:
        return "fail", "the reopened recordings carry no readable request event"
    if stop_rc != 0:
        return "fail", f"xtrace stop after restart exited {stop_rc}"
    return "pass", (f"restart exited 0 with a live daemon; all {len(before)} earlier recordings read back with the same completion "
                    f"and event count; {len(readable)} show their request route")


def judge_partial(*, record_rc: int, stop_rc: int | None, stop_doc: Any, control_details: list[dict], new_details: dict[str, dict],
                  stalled: tuple[str, str], stalled_id: str | None = None) -> tuple[str, str]:
    if record_rc == 9 or stop_rc == 9:
        return "not-implemented", "xtrace record/stop exited 9"
    if record_rc != 0:
        return "fail", f"xtrace record exited {record_rc}"
    if stop_rc is None:
        return "fail", "xtrace stop was not invoked: record supplied no launch bootstrap"
    if stop_rc not in (0, 10):  # 10 = a recording could not be sealed (documented as partial success)
        return "fail", f"xtrace stop exited {stop_rc}"
    if not [d for d in control_details if completion_of(d) == "complete"]:
        return "fail", "control requests (answered before the interruption) produced no complete recording"
    if stalled_id is None:
        return "fail", f"no observed open recording for {stalled[0]} {stalled[1]} before interruption"
    partial = {rid: d for rid, d in new_details.items()
               if rid == stalled_id and completion_of(d) == "partial" and xinstr.recording_matches(d, *stalled)}
    looks_complete = [rid[:8] for rid, d in new_details.items()
                      if completion_of(d) == "complete" and xinstr.recording_matches(d, *stalled)]
    if looks_complete:
        return "fail", f"the interrupted request {stalled[0]} {stalled[1]} reopens as complete ({','.join(looks_complete)})"
    if not partial:
        recovered = find_key(stop_doc, "recovered_recordings")
        return "fail", (f"the observed interrupted recording did not reopen as partial ({len(new_details)} new recordings; "
                        f"stop reported {len(recovered) if isinstance(recovered, list) else 'no'} recovered)")
    no_evidence = [rid[:8] for rid, d in partial.items() if not d.get("incompleteEvidence") and not d.get("incomplete")]
    unread = [rid[:8] for rid, d in partial.items() if event_count(d) == 0]
    if no_evidence:
        return "fail", f"partial recordings state no incomplete evidence: {','.join(no_evidence)}"
    if unread:
        return "fail", f"partial recordings read back with no events: {','.join(unread)}"
    return "pass", (f"{len(partial)} recording(s) reopen as partial with incomplete evidence and readable events after the application "
                    f"was killed mid-request; the interrupted request never reads as complete")


def _line_events(details: list[dict]) -> list[tuple[dict, dict]]:
    out = []
    for d in details:
        sources = {ev["frameId"]: ev.get("source") for ev in d.get("events", [])
                   if ev.get("frameId") and str(ev.get("kind", "")).endswith("frame_enter")}
        for ev in d.get("events", []):
            if str(ev.get("kind", "")).endswith("line_cursor"):
                # Every cursor has its own frame id and one-line source range. Only its
                # observed parent method's FRAME_ENTER supplies a method extent.
                source = sources.get(ev.get("parentFrameId"))
                out.append((ev, source if isinstance(source, dict) else {}))
    return out


def line_parent_gaps(details: list[dict]) -> dict[str, int]:
    """Count observed parent failures without guessing a method from cursor source or symbols."""
    counts: dict[str, int] = {}
    for detail in details:
        by_id = {ev["frameId"]: ev for ev in detail.get("events", []) if ev.get("frameId")}
        for ev in detail.get("events", []):
            if not str(ev.get("kind", "")).endswith("line_cursor"):
                continue
            parent = by_id.get(ev.get("parentFrameId"))
            if parent is None:
                reason = "parent-not-observed"
            elif not str(parent.get("kind", "")).endswith("frame_enter"):
                reason = "parent-is-not-method-entry"
            elif not isinstance(parent.get("source"), dict) or type(parent["source"].get("startLine")) is not int or parent["source"]["startLine"] < 1:
                reason = "parent-method-extent-unavailable"
            else:
                continue
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def judge_active_line(details: list[dict]) -> tuple[str, str]:
    if not details:
        return "fail", "no focused recording was read back"
    lines = _line_events(details)
    if not lines:
        gaps = sum(1 for d in details for ev in d.get("events", []) if str(ev.get("symbol") or "").endswith("gap.not-transformed"))
        return "fail", (f"{len(details)} focused recordings carry no line_cursor event"
                        + (f"; the product declares gap.not-transformed {gaps} time(s)" if gaps else "; no gap is declared either"))
    bad = [ev for ev, _ in lines if not (type(ev.get("line")) is int and ev["line"] >= 1)]
    if bad:
        return "fail", f"{len(bad)} line_cursor events carry no observed line number"
    with_extent = [(ev, src) for ev, src in lines if type(src.get("startLine")) is int and src["startLine"] >= 1]
    if len(with_extent) != len(lines):
        return "fail", (f"{len(lines) - len(with_extent)} line events have no enclosing method extent through parentFrameId; "
                        + json.dumps(line_parent_gaps(details), sort_keys=True))
    outside = [ev for ev, src in with_extent if ev["line"] < src["startLine"] or
               (type(src.get("endLine")) is int and ev["line"] > src["endLine"])]
    moving = [ev for ev, src in with_extent if ev["line"] != src["startLine"]]
    if outside:
        return "fail", f"{len(outside)} observed lines fall outside their frame's method extent"
    if not moving:
        return "fail", f"all {len(with_extent)} line events equal the method start line (an extent, not an executed line)"
    return "pass", (f"{len(lines)} line_cursor events with observed lines; {len(moving)} differ from their method start line "
                    f"and stay inside the available extent bounds")


def judge_frame_values(details: list[dict]) -> tuple[str, str]:
    if not details:
        return "fail", "no focused recording was read back"
    states: dict[str, int] = {}
    captured = []
    for d in details:
        for ev in d.get("events", []):
            for b in ev.get("bindings") or []:
                v = b.get("value") if isinstance(b, dict) else None
                st = v.get("state") if isinstance(v, dict) else None
                states[str(st)] = states.get(str(st), 0) + 1
                if st == "captured" and isinstance(b.get("name"), str) and b["name"] and \
                        isinstance(v.get("preview"), str) and v["preview"] and isinstance(v.get("shape"), str):
                    captured.append(b)
    if not captured:
        return "fail", (f"no event carries a captured binding with name, shape and preview in {len(details)} focused recordings; "
                        f"binding states seen: {json.dumps(states, sort_keys=True)}")
    return "pass", (f"{len(captured)} captured bindings with name, shape and preview across {len(details)} focused recordings; "
                    f"states: {json.dumps(states, sort_keys=True)}")


def judge_canary_recordings(served: dict, attributed: dict[str, str], details: dict[str, dict], wanted: dict) -> tuple[str, str]:
    """Every probe needs its own completed recording, still readable after shutdown."""
    if set(served) != set(wanted) or set(attributed) != set(wanted) or len(set(attributed.values())) != len(wanted):
        return "fail", "not every canary request has a distinct attributed recording"
    for label, (method, route) in wanted.items():
        detail = details.get(attributed[label], {})
        if served[label] != 200 or completion_of(detail) != "complete" or not xinstr.recording_matches(detail, method, route) \
                or xinstr.recording_http_status(detail) != 200:
            return "fail", f"{label}: request or attributed completed recording unavailable"
    return "pass", f"all {len(wanted)} canary requests have distinct completed recordings, including the form POST when focused"


def judge_redaction(detail: dict, canaries: dict[str, str]) -> tuple[str, str]:
    if any(value in json.dumps(detail) for value in canaries.values()):
        return "fail", "raw secret canary observed in focused recording"
    bindings = [b for ev in detail.get("events", []) for b in ev.get("bindings") or []]
    if not any(str(b.get("name", "")).lower() == "lastname" and b.get("value", {}).get("state") == "redacted"
               and b["value"].get("ruleId") == "content.secret_pattern" for b in bindings):
        return "fail", "lastName content redaction was not observed in the secret probe recording"
    return "pass", "lastName is redacted by content.secret_pattern; strict secret-canary scan is also required"


def judge_value_control(details: dict[str, dict], recording_id: str, marker: str) -> tuple[str, str]:
    # Permit the marker only in captured lastName previews in its own recording.
    # Removing those slots lets us detect a marker echoed into unrelated API fields.
    rest = json.loads(json.dumps(details))
    observed = 0
    for rid, detail in rest.items():
        for ev in detail.get("events", []):
            for binding in ev.get("bindings") or []:
                value = binding.get("value", {})
                if rid == recording_id and str(binding.get("name", "")).lower() == "lastname" \
                        and value.get("state") == "captured" and value.get("preview") == marker:
                    observed += 1
                    value["preview"] = ""
    if not observed or marker in json.dumps(rest):
        return "fail", "plain business marker must appear only as a captured lastName binding in its own focused recording"
    return "pass", "plain lastName marker observed only as captured bindings; focused Strings that match no redaction rule are recorded"


def judge_standard_values(details: dict[str, dict], canaries: dict[str, str]) -> tuple[str, str]:
    if not details or any(ev.get("bindings") for d in details.values() for ev in d.get("events", [])):
        return "fail", "standard probe has no recording or contains value bindings"
    if any(value in json.dumps(details) for value in canaries.values()):
        return "fail", "raw canary observed during standard capture"
    return "pass", "standard business-parameter probe has no value bindings; strict zero-hit canary scan is also required"


# ------------------------------------------------------------------ drivers --
def _get(base: str, path: str) -> int | None:
    import xcamp
    try:
        return xcamp.http_request(base, "GET", path, timeout=30)["status"]
    except Exception:
        return None


def _paced_gets(base: str, paths: list[str], gap: float = 0.6) -> dict[str, int | None]:
    out = {}
    for p in paths:
        time.sleep(gap)
        out[p] = _get(base, p)
    return out


def focused_requests(base: str, canaries: dict[str, str], observe: Callable[[str, str, str, float], None],
                     marker: str) -> dict[str, int | None]:
    """Exercise focused bindings with the campaign canaries; never persist the injected request values here."""
    import urllib.parse
    import xcamp
    hook = xinstr.canary_hook(canaries)
    requests = [(label, "GET", path, {}, None) for label, path in
                (("owner", "/owners/1"), ("search", "/owners?lastName=Davis"), ("vets", "/vets"))]
    # Invalid ordinary business fields re-render the form without creating an owner.
    form = urllib.parse.urlencode({"firstName": "", "lastName": "Invalid", "address": "123 Test St",
                                   "city": "Testville", "telephone": "abc"}).encode()
    requests.append(("form", "POST", "/owners/new", {"Content-Type": "application/x-www-form-urlencoded"}, form))
    for label, value in (("secret", canaries["focused-business-secret"]), ("plain", marker)):
        requests.append((label, "GET", "/owners?" + urllib.parse.urlencode({"lastName": value}), {}, None))
    served = {}
    for label, method, path, headers, body in requests:
        path, headers, body = hook(method, path, headers, body)
        deadline = time.monotonic() + 30.0  # HTTP and persistence share the existing request budget
        try:
            served[label] = xcamp.http_request(base, method, path, headers=headers, body=body, timeout=30)["status"]
        except Exception:
            served[label] = None
        observe(label, method, FOCUSED_REQUESTS[label][1], deadline)
    return served


def wait_canary_recording(client: xinstr.ViewerClient, out_dir: pathlib.Path, before: dict, method: str, route: str,
                          deadline: float) -> tuple[str, dict]:
    """Observe one newly completed route before admitting the next probe; never retry a request."""
    client.deadline = deadline
    try:
        while time.monotonic() < deadline:
            api = xinstr.collect_api(client, out_dir)
            if not api["ok"]:
                raise CanaryEvidenceError("canary recording read failed")
            hits = {rid: d for rid, d in api["details"].items() if rid not in before and xinstr.recording_matches(d, method, route)}
            if len(hits) > 1:
                raise CanaryEvidenceError("canary request recording is ambiguous")
            if len(hits) == 1:
                rid, detail = next(iter(hits.items()))
                # Completion describes the persisted prefix too. An open recording has no
                # terminal proof yet; only lifecycle status says when waiting must stop.
                pending = detail.get("status") in ("recording", "finalizing")
                if not pending and completion_of(detail) == "complete" and xinstr.recording_http_status(detail) == 200 \
                        and time.monotonic() <= deadline:
                    return rid, api["details"]
                if not pending and completion_of(detail) in ("partial", "invalid", "unavailable"):
                    raise CanaryEvidenceError(canary_incomplete_note(detail))
    finally:
        client.deadline = None
    raise CanaryEvidenceError("canary request has no attributable completed recording within its request budget")


def canary_incomplete_note(detail: dict) -> str:
    """Explain terminal loss using bounded protocol facts, never symbols, messages or values."""
    reasons = {"class_not_transformed", "queue_full", "line_budget", "value_budget", "throttle", "correlation_lost"}
    counts: dict[str, int] = {}
    for event in detail.get("events", [])[:1000]:
        if not str(event.get("kind", "")).endswith("gap"):
            continue
        gap = event.get("gap")
        if not isinstance(gap, dict):
            continue
        reason = gap.get("reason")
        if not isinstance(reason, str) or reason not in reasons:
            reason = "unrecognized"
        count = gap.get("count")
        if isinstance(count, str) and len(count) <= 20 and count.isascii() and count.isdecimal() \
                and int(count) < 1 << 64:
            counts[reason] = min((1 << 64) - 1, counts.get(reason, 0) + int(count))
    status = detail.get("status")
    if status not in ("recording", "finalizing", "complete", "partial", "invalid"):
        status = "unrecognized"
    losses = ", ".join(f"{reason}={count}" for reason, count in sorted(counts.items())) or "none in snapshot"
    return f"canary request recording is not complete (status={status}; observed gaps: {losses})"


def _fail(exc: BaseException) -> tuple[str, str]:
    return "fail", f"harness error {type(exc).__name__}: {str(exc)[:120]}"


class Flows:
    """One instance per campaign run; `results` maps step name -> {status, note}."""

    def __init__(self, *, xtrace: str, agent: str, project_dir: pathlib.Path, data_home: pathlib.Path, out_dir: pathlib.Path,
                 make_stack: Callable[[str], Any], app_package: str, source_root: str):
        self.xtrace, self.agent, self.project_dir, self.out_dir = xtrace, agent, project_dir, out_dir
        self.make_stack, self.app_package, self.source_root = make_stack, app_package, source_root
        self.env = {**os.environ, "XTRACE_DATA_HOME": str(data_home)}
        os.environ["XTRACE_DATA_HOME"] = str(data_home)
        self.results: dict[str, dict[str, str]] = {}
        self.run_tag = out_dir.name.replace("flows-", "f") + str(int(time.time()) % 100000)
        self.launches = 0

    def _set(self, step: str, verdict: tuple[str, str]) -> None:
        self.results[step] = {"status": verdict[0], "note": verdict[1]}
        print(f"  [{verdict[0].upper()}] {step}: {verdict[1]}", flush=True)

    def _stack(self, launch_prefix: str, java_opts_head: list[str]) -> Any:
        self.launches += 1
        os.environ["XCAMP_LAUNCH_PREFIX"] = launch_prefix
        stack = self.make_stack(f"{self.run_tag}{self.launches}")
        stack.java_opts = [*java_opts_head, *stack.java_opts]
        return stack

    def _capture_flags(self) -> list[str]:
        return ["--app-package", self.app_package, "--source-root", self.source_root]

    def _stop_daemon_quietly(self) -> None:
        try:
            cli(self.xtrace, ["stop", "--project-dir", str(self.project_dir), "--json"], self.env, timeout=60)
        except Exception:
            pass

    def _record(self, command: str = "record", *, timeout: float = 120.0) -> tuple[int, Any, str]:
        args = [command, "--project-dir", str(self.project_dir), "--json"]
        if command in ("record", "restart"):
            args += self._capture_flags()
        result = subprocess.run([self.xtrace, *args], env=self.env, capture_output=True, text=True, timeout=timeout)
        rc = result.returncode
        body = result.stdout if result.stdout.strip() else result.stderr
        doc = parse_doc(body)
        return rc, doc, str(find_key(doc, "bootstrap_path") or "")

    # -- flow A --
    def _recorded_gets(self, stack: Any, paths: list[str], wanted: list[tuple[str, str]]) -> dict[str, int | None]:
        """Observe capture before stop, within each HTTP request's existing 30 s budget."""
        import xcamp
        dest = self.out_dir / "api-live-record-stop"
        dest.mkdir(parents=True, exist_ok=True)
        viewer, ready = xinstr.start_viewer(self.xtrace, self.project_dir, self.env, dest / "viewer.log")
        try:
            client = xinstr.ViewerClient(ready["origin"])
            client.exchange(xinstr.bootstrap_token(ready["url"]))
            initial = xinstr.collect_api(client, dest / "before")
            if not initial["ok"]:
                raise CanaryEvidenceError("cannot snapshot recordings before record-stop requests")
            before, served = initial["details"], {}
            for path, (method, route) in zip(paths, wanted, strict=True):
                deadline = time.monotonic() + 30.0
                served[path] = xcamp.http_request(stack.base, method, path, timeout=30)["status"]
                _, before = wait_canary_recording(client, dest / str(len(served)), before, method, route, deadline)
            return served
        finally:
            xinstr.stop_process_group(viewer)

    def record_stop(self) -> dict[str, tuple[str, int]]:
        paths = ["/owners?lastName=Davis", "/vets", "/owners/1"]
        wanted = [("GET", "/owners"), ("GET", "/vets"), ("GET", "/owners/{ownerId}")]
        api0 = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-before-record-stop")
        if not api0["ok"]:
            self._set("record-stop-flow", ("fail", f"read API unavailable before record: {api0['reason']}"))
            return {}
        before_ids = set(api0["details"])
        rc, doc, bootstrap = self._record()
        served: dict[str, int | None] = {}
        stop_rc, gone, new = -1, False, {}
        stack = None
        try:
            if rc == 0 and bootstrap:
                stack = self._stack("", [f"-javaagent:{self.agent}={bootstrap}"])
                stack.up()
                served = self._recorded_gets(stack, paths, wanted)
                pid = find_key(doc, "pid")
                stop_rc, _, _ = self._record("stop", timeout=90)
                gone = isinstance(pid, int) and wait_gone(pid)
        finally:
            if stack is not None:
                stack.down()
            self._stop_daemon_quietly()
        if rc == 0 and bootstrap and stop_rc == 0:
            api = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-record-stop")
            new = {k: v for k, v in api["details"].items() if k not in before_ids}
            if not api["ok"]:
                self._set("record-stop-flow", ("fail", f"read API unavailable after stop: {api['reason']}"))
                return {}
        self._set("record-stop-flow", judge_record_stop(record_rc=rc, record_doc=doc, served=served, stop_rc=stop_rc,
                                                        daemon_gone=gone, new_details=new, wanted=wanted))
        return {rid: (completion_of(d), event_count(d)) for rid, d in new.items()}

    # -- flow B --
    def restart_reopen(self) -> None:
        api0 = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-before-restart")
        before = {rid: (completion_of(d), event_count(d)) for rid, d in api0["details"].items()}
        rc, doc, _ = self._record("restart")
        started = find_key(find_key(doc, "started"), "pid") if rc == 0 else None
        alive = isinstance(started, int) and pid_alive(started)
        api1 = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-after-restart") if rc == 0 else api0
        stop_rc, _, _ = self._record("stop", timeout=90)
        if not api0["ok"] or (rc == 0 and not api1["ok"]):
            self._set("restart-reopen", ("fail", f"read API unavailable: {api0['reason'] or api1['reason']}"))
            return
        self._set("restart-reopen", judge_restart_reopen(restart_rc=rc, restart_doc=doc, started_alive=alive, before=before,
                                                         after_details=api1["details"], stop_rc=stop_rc))

    # -- flow C --
    def partial(self) -> None:
        api0 = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-before-partial")
        if not api0["ok"]:
            self._set("partial-recording-reopen", ("fail", f"read API unavailable before record: {api0['reason']}"))
            return
        before_ids = set(api0["details"])
        rc, doc, bootstrap = self._record()
        stack, sock = None, None
        barriers = ExitStack()
        stop_rc, stop_doc = None, None
        stalled_id = None
        observation_error = None
        try:
            if rc == 0 and bootstrap:
                stack = self._stack("", [f"-javaagent:{self.agent}={bootstrap}"])
                stack.up()
                _paced_gets(stack.base, ["/vets", "/owners?lastName=Davis"])
                # Hold the insert inside the handler. An incomplete form body can block in
                # a servlet filter before the MVC capture seam is ever reached.
                barriers.enter_context(stack.hold_owner_writes())
                sock = socket.create_connection(("127.0.0.1", stack.host_port), timeout=10)
                body = b"firstName=Held&lastName=Interrupted&address=Street&city=Town&telephone=0123456789"
                sock.sendall(b"POST /owners/new HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                             + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                deadline = time.monotonic() + 3.0

                def query(args: list[str]) -> dict:
                    result = subprocess.run([self.xtrace, "recording", *args, "--project-dir", str(self.project_dir)],
                                            env=self.env, capture_output=True, text=True, timeout=30)
                    if result.returncode != 0:
                        raise RuntimeError(f"recording {args[0]} exited {result.returncode}")
                    return json.loads(result.stdout)

                while time.monotonic() < deadline:
                    after = None
                    for _ in range(20):
                        page = query(["list", "--limit", "200"] + (["--after", after] if after else []))
                        for row in page["recordings"]:
                            rid = row["recording_id"]
                            if rid in before_ids or row["status"] != "recording":
                                continue
                            detail = query(["show", rid, "--limit", "1000"])
                            if detail.get("status") == "recording" and xinstr.recording_matches(detail, "POST", "/owners/new"):
                                stalled_id = rid
                                break
                        after = page.get("next_after")
                        if stalled_id is not None or not after:
                            break
                    if stalled_id is not None:
                        break
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                if stalled_id is None:
                    observation_error = "no observed open recording for POST /owners/new before the interruption deadline"
                else:
                    proc = getattr(stack, "_proc", None)
                    if proc is None or proc.poll() is not None:
                        raise RuntimeError("the observed stalled request has no live application process to interrupt")
                    os.kill(proc.pid, signal.SIGKILL)  # the application pid this harness started, nothing else
                    proc.wait(timeout=30)
        finally:
            if sock is not None:
                sock.close()
            barriers.close()
            if stack is not None:
                stack.down()
            if rc == 0 and bootstrap:
                stop_rc, stop_doc, _ = self._record("stop", timeout=90)
            self._stop_daemon_quietly()
        if rc != 0 or not bootstrap:
            self._set("partial-recording-reopen", judge_partial(record_rc=rc, stop_rc=stop_rc, stop_doc=stop_doc,
                                                                control_details=[], new_details={}, stalled=("POST", "/owners/new")))
            return
        # Save the readback even when the held request was not observed. The
        # failed judge still needs structural evidence of what capture produced.
        api = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-partial")
        if observation_error:
            self._set("partial-recording-reopen", ("fail", observation_error))
            return
        if not api["ok"]:
            self._set("partial-recording-reopen", ("fail", f"read API unavailable after the interruption: {api['reason']}"))
            return
        new = {k: v for k, v in api["details"].items() if k not in before_ids}
        controls = [d for d in new.values() if xinstr.recording_matches(d, "GET", "/vets")
                    or xinstr.recording_matches(d, "GET", "/owners")]
        self._set("partial-recording-reopen", judge_partial(record_rc=rc, stop_rc=stop_rc, stop_doc=stop_doc, control_details=controls,
                                                            new_details=new, stalled=("POST", "/owners/new"), stalled_id=stalled_id))

    # -- flow D --
    def _privacy_capture(self, mode: str, canaries: dict[str, str], marker: str = "") -> tuple[dict, dict, dict, str]:
        import urllib.parse
        import xcamp
        os.environ["XTRACE_CANARY_ENV"] = canaries["env-var"]
        before_ids = list_ids(self.xtrace, self.project_dir, self.env)
        prefix = " ".join(shlex.quote(x) for x in
                          [self.xtrace, "run", "--project-dir", str(self.project_dir), "--java-agent", self.agent,
                           "--capture-depth", mode, *self._capture_flags(), "--"])
        stack = self._stack(prefix, [])
        viewer, served, attributed, error = None, {}, {}, ""
        dest = self.out_dir / f"api-{mode}"
        try:
            stack.up()
            dest.mkdir(parents=True, exist_ok=True)
            viewer, ready = xinstr.start_viewer(self.xtrace, self.project_dir, self.env, dest / "boundary-viewer.log")
            client = xinstr.ViewerClient(ready["origin"])
            client.exchange(xinstr.bootstrap_token(ready["url"]))
            initial = xinstr.collect_api(client, dest / "before")
            if not initial["ok"]:
                raise CanaryEvidenceError("cannot snapshot recordings before privacy probes")
            before = initial["details"]

            def observe(label: str, method: str, route: str, deadline: float) -> None:
                nonlocal before
                rid, before = wait_canary_recording(client, dest / label, before, method, route, deadline)
                attributed[label] = rid

            if mode == "focused":
                served = focused_requests(stack.base, canaries, observe, marker)
            else:
                path = "/owners?" + urllib.parse.urlencode({"lastName": canaries["query-token"]})
                path, headers, body = xinstr.canary_hook(canaries)("GET", path, {}, None)
                deadline = time.monotonic() + 30.0
                served["standard"] = xcamp.http_request(stack.base, "GET", path, headers=headers, body=body, timeout=30)["status"]
                observe("standard", "GET", "/owners", deadline)
        except CanaryEvidenceError as exc:
            error = str(exc)
        except Exception as exc:
            error = f"privacy capture failed: {type(exc).__name__}"  # exception text could contain a probe value
        finally:
            try:
                stack.down()
            finally:
                if viewer is not None:
                    xinstr.stop_process_group(viewer)
        api = read_api(self.xtrace, self.project_dir, self.env, dest)
        if not api["ok"]:
            error = "privacy capture read API unavailable"
        new = {k: d for k, d in api["details"].items() if k not in before_ids}
        return served, attributed, new, error

    def _canaries(self, steps: tuple[str, ...]) -> dict | None:
        path = os.environ.get("XCAMP_CANARY_FILE")
        if not path:
            for step in steps:
                self._set(step, ("fail", "privacy capture requires the campaign canary file"))
            return None
        return json.loads(pathlib.Path(path).read_text())

    def focused(self) -> None:
        steps = ("active-line-frames", "frame-values", *PRIVACY_STEPS[:3])
        canaries = self._canaries(steps)
        if canaries is None:
            return
        marker = "XTplain." + secrets.token_hex(8)  # ordinary String; deliberately outside the secret-canary set
        served, attributed, new, error = self._privacy_capture("focused", canaries, marker)
        verdict = ("fail", error) if error else judge_canary_recordings(served, attributed, new, FOCUSED_REQUESTS)
        self._set("focused-canary-injection", verdict)
        if verdict[0] != "pass":
            for step in steps:
                if step != "focused-canary-injection":
                    self._set(step, verdict)
            return
        self._set("active-line-frames", judge_active_line(list(new.values())))
        self._set("frame-values", judge_frame_values(list(new.values())))
        self._set("focused-redaction-control", judge_redaction(new[attributed["secret"]], canaries))
        self._set("focused-value-control", judge_value_control(new, attributed["plain"], marker))

    def standard(self) -> None:
        canaries = self._canaries(("standard-no-values",))
        if canaries is None:
            return
        served, attributed, new, error = self._privacy_capture("standard", canaries)
        verdict = ("fail", error) if error else judge_canary_recordings(served, attributed, new, {"standard": ("GET", "/owners")})
        self._set("standard-no-values", judge_standard_values(new, canaries) if verdict[0] == "pass" else verdict)

    def run_all(self) -> dict[str, dict[str, str]]:
        for name, fn in (("record-stop-flow", self.record_stop), ("restart-reopen", self.restart_reopen),
                         ("partial-recording-reopen", self.partial), ("focused", self.focused), ("standard-no-values", self.standard)):
            try:
                fn()
            except Exception as exc:
                for step in ("active-line-frames", "frame-values") if name == "focused" else (name,):
                    if step not in self.results:
                        self._set(step, _fail(exc))
        self._set("flow-accommodations", ("reported", "record-stop and privacy requests observe completed recordings within each request budget; partial-flow controls use pace_seconds=0.6; its complete form submission waits behind an acknowledged database write barrier"))
        self._set("privacy-scope", ("reported", "focused capture records ordinary String arguments and locals, including business parameters, unless name, type or content rules redact them; exception messages use content-pattern redaction only; metadata exclusion alone does not prove value redaction"))
        self.results.setdefault("focused-canary-injection", {"status": "fail", "note": "focused canary requests did not complete"})
        for step in STEP_NAMES:
            self.results.setdefault(step, {"status": "fail", "note": "flow did not run"})
        return self.results
