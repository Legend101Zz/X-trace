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

The judge_* functions are pure and unit-tested (test_xflows.py); the run_* functions drive real processes.
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import signal
import socket
import subprocess
import time
from typing import Any, Callable

import xinstr

STEP_NAMES = ("record-stop-flow", "restart-reopen", "partial-recording-reopen", "active-line-frames", "frame-values")


# ------------------------------------------------------------------ helpers --
def parse_doc(text: str) -> Any:
    """The last JSON document in `text` (the CLI prints one document); None when there is none."""
    for line in reversed([ln for ln in text.splitlines() if ln.strip()]):
        try:
            return json.loads(line)
        except ValueError:
            continue
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


def judge_partial(*, record_rc: int, stop_rc: int, stop_doc: Any, control_details: list[dict], new_details: dict[str, dict],
                  stalled: tuple[str, str]) -> tuple[str, str]:
    if record_rc == 9 or stop_rc == 9:
        return "not-implemented", "xtrace record/stop exited 9"
    if record_rc != 0:
        return "fail", f"xtrace record exited {record_rc}"
    if stop_rc not in (0, 10):  # 10 = a recording could not be sealed (documented as partial success)
        return "fail", f"xtrace stop exited {stop_rc}"
    if not [d for d in control_details if completion_of(d) == "complete"]:
        return "fail", "control requests (answered before the interruption) produced no complete recording"
    partial = {rid: d for rid, d in new_details.items() if completion_of(d) == "partial"}
    looks_complete = [rid[:8] for rid, d in new_details.items()
                      if completion_of(d) == "complete" and xinstr.recording_matches(d, *stalled)]
    if looks_complete:
        return "fail", f"the interrupted request {stalled[0]} {stalled[1]} reopens as complete ({','.join(looks_complete)})"
    if not partial:
        recovered = find_key(stop_doc, "recovered_recordings")
        return "fail", (f"no recording reopened as partial after the interruption ({len(new_details)} new recordings; "
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
        sources = {ev.get("frameId"): ev.get("source") for ev in d.get("events", [])
                   if str(ev.get("kind", "")).endswith("frame_enter") and isinstance(ev.get("source"), dict)}
        for ev in d.get("events", []):
            if str(ev.get("kind", "")).endswith("line_cursor"):
                out.append((ev, sources.get(ev.get("frameId")) or ev.get("source") or {}))
    return out


def judge_active_line(details: list[dict]) -> tuple[str, str]:
    if not details:
        return "fail", "no focused recording was read back"
    lines = _line_events(details)
    if not lines:
        gaps = sum(1 for d in details for ev in d.get("events", []) if str(ev.get("symbol") or "").endswith("gap.not-transformed"))
        return "fail", (f"{len(details)} focused recordings carry no line_cursor event"
                        + (f"; the product declares gap.not-transformed {gaps} time(s)" if gaps else "; no gap is declared either"))
    bad = [ev for ev, _ in lines if not (isinstance(ev.get("line"), int) and ev["line"] >= 1)]
    if bad:
        return "fail", f"{len(bad)} line_cursor events carry no observed line number"
    with_extent = [(ev, src) for ev, src in lines if isinstance(src.get("startLine"), int)]
    if with_extent:
        outside = [ev for ev, src in with_extent if isinstance(src.get("endLine"), int)
                   and not src["startLine"] <= ev["line"] <= src["endLine"]]
        moving = [ev for ev, src in with_extent if ev["line"] != src["startLine"]]
        if outside:
            return "fail", f"{len(outside)} observed lines fall outside their frame's method extent"
        if not moving:
            return "fail", f"all {len(with_extent)} line events equal the method start line (an extent, not an executed line)"
        return "pass", (f"{len(lines)} line_cursor events with observed lines; {len(moving)} differ from their method start line "
                        f"and stay inside the extent")
    distinct = {ev["line"] for ev, _ in lines}
    if len(distinct) < 2:
        return "fail", "line events carry one distinct line and no method extent to compare it with"
    return "pass", f"{len(lines)} line_cursor events with {len(distinct)} distinct observed lines (no method extent on the frames)"


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
        out[p] = _get(base, p)
        time.sleep(gap)
    return out


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

    def _record(self) -> tuple[int, Any, str]:
        rc, doc = cli(self.xtrace, ["record", "--project-dir", str(self.project_dir), "--json", *self._capture_flags()], self.env)
        return rc, doc, str(find_key(doc, "bootstrap_path") or "")

    # -- flow A --
    def record_stop(self) -> dict[str, tuple[str, int]]:
        paths = ["/owners?lastName=Davis", "/vets", "/owners/1"]
        wanted = [("GET", "/owners"), ("GET", "/vets"), ("GET", "/owners/{ownerId}")]
        before_ids = list_ids(self.xtrace, self.project_dir, self.env)
        rc, doc, bootstrap = self._record()
        served: dict[str, int | None] = {}
        stop_rc, gone, new = -1, False, {}
        stack = None
        try:
            if rc == 0 and bootstrap:
                stack = self._stack("", [f"-javaagent:{self.agent}={bootstrap}"])
                stack.up()
                served = _paced_gets(stack.base, paths)
                pid = find_key(doc, "pid")
                stop_rc, _ = cli(self.xtrace, ["stop", "--project-dir", str(self.project_dir), "--json"], self.env, timeout=90)
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
        rc, doc = cli(self.xtrace, ["restart", "--project-dir", str(self.project_dir), "--json", *self._capture_flags()], self.env)
        started = find_key(find_key(doc, "started"), "pid") if rc == 0 else None
        alive = isinstance(started, int) and pid_alive(started)
        api1 = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-after-restart") if rc == 0 else api0
        stop_rc, _ = cli(self.xtrace, ["stop", "--project-dir", str(self.project_dir), "--json"], self.env, timeout=90)
        if not api0["ok"] or (rc == 0 and not api1["ok"]):
            self._set("restart-reopen", ("fail", f"read API unavailable: {api0['reason'] or api1['reason']}"))
            return
        self._set("restart-reopen", judge_restart_reopen(restart_rc=rc, restart_doc=doc, started_alive=alive, before=before,
                                                         after_details=api1["details"], stop_rc=stop_rc))

    # -- flow C --
    def partial(self) -> None:
        before_ids = list_ids(self.xtrace, self.project_dir, self.env)
        rc, doc, bootstrap = self._record()
        stack, sock = None, None
        stop_rc, stop_doc = -1, None
        try:
            if rc == 0 and bootstrap:
                stack = self._stack("", [f"-javaagent:{self.agent}={bootstrap}"])
                stack.up()
                _paced_gets(stack.base, ["/vets", "/owners?lastName=Davis"])
                # A request whose body never finishes: the handler is entered, the recording is open, the response never comes.
                sock = socket.create_connection(("127.0.0.1", stack.host_port), timeout=10)
                sock.sendall(b"POST /owners/new HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                             b"Content-Length: 4096\r\nConnection: close\r\n\r\nfirstName=Held&lastName=Interrupted")
                time.sleep(3.0)
                proc = getattr(stack, "_proc", None)
                if proc is not None and proc.poll() is None:
                    os.kill(proc.pid, signal.SIGKILL)  # the application pid this harness started, nothing else
                    proc.wait(timeout=30)
                time.sleep(2.0)
        finally:
            if sock is not None:
                sock.close()
            if stack is not None:
                stack.down()
            if rc == 0 and bootstrap:
                stop_rc, stop_doc = cli(self.xtrace, ["stop", "--project-dir", str(self.project_dir), "--json"], self.env, timeout=90)
            self._stop_daemon_quietly()
        if rc != 0 or not bootstrap:
            self._set("partial-recording-reopen", judge_partial(record_rc=rc, stop_rc=stop_rc, stop_doc=stop_doc,
                                                                control_details=[], new_details={}, stalled=("POST", "/owners/new")))
            return
        api = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-partial")
        if not api["ok"]:
            self._set("partial-recording-reopen", ("fail", f"read API unavailable after the interruption: {api['reason']}"))
            return
        new = {k: v for k, v in api["details"].items() if k not in before_ids}
        controls = [d for d in new.values() if xinstr.recording_matches(d, "GET", "/vets")
                    or xinstr.recording_matches(d, "GET", "/owners")]
        self._set("partial-recording-reopen", judge_partial(record_rc=rc, stop_rc=stop_rc, stop_doc=stop_doc, control_details=controls,
                                                            new_details=new, stalled=("POST", "/owners/new")))

    # -- flow D --
    def focused(self) -> None:
        before_ids = list_ids(self.xtrace, self.project_dir, self.env)
        prefix = " ".join(shlex.quote(x) for x in
                          [self.xtrace, "run", "--project-dir", str(self.project_dir), "--java-agent", self.agent,
                           "--capture-depth", "focused", *self._capture_flags(), "--"])
        stack = self._stack(prefix, [])
        try:
            stack.up()
            served = _paced_gets(stack.base, ["/owners/1", "/owners?lastName=Davis", "/vets"])
        finally:
            stack.down()
        api = read_api(self.xtrace, self.project_dir, self.env, self.out_dir / "api-focused")
        if not api["ok"] or any(s != 200 for s in served.values()):
            why = f"read API unavailable: {api['reason']}" if not api["ok"] else f"requests not answered 200: {json.dumps(served)}"
            for step in ("active-line-frames", "frame-values"):
                self._set(step, ("fail", why))
            return
        new = [d for k, d in api["details"].items() if k not in before_ids]
        self._set("active-line-frames", judge_active_line(new))
        self._set("frame-values", judge_frame_values(new))

    def run_all(self) -> dict[str, dict[str, str]]:
        for name, fn in (("record-stop-flow", self.record_stop), ("restart-reopen", self.restart_reopen),
                         ("partial-recording-reopen", self.partial), ("focused", self.focused)):
            try:
                fn()
            except Exception as exc:
                for step in ("active-line-frames", "frame-values") if name == "focused" else (name,):
                    if step not in self.results:
                        self._set(step, _fail(exc))
        for step in STEP_NAMES:
            self.results.setdefault(step, {"status": "fail", "note": "flow did not run"})
        return self.results
