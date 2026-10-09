"""Instrumented-run support for the Java campaigns (stdlib only).

The harness starts the application through the PACKAGED launcher (`xtrace run --project-dir P --java-agent A --
java -jar ...`, passed as XCAMP_LAUNCH_PREFIX), runs the pinned scenarios, then reads the persisted recordings back
through the product's own read API (`xtrace open --viewer --no-browser`) and judges them against per-scenario
expectations. Nothing here weakens a check: whatever the product cannot show yet is reported as a failed expectation
with a reason code, never skipped.
"""
from __future__ import annotations

import http.client
import json
import os
import pathlib
import re
import signal
import subprocess
import time
from typing import Any, Callable

# matched against the class part of a frame symbol such as `OwnerController.findOwner`
LAYER_PATTERNS = {
    "controller": re.compile(r"Controller|Resource$"),
    "service": re.compile(r"Service"),
    "repository": re.compile(r"Repository|Dao$"),
}


# ------------------------------------------------------------------ stats ----
def percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile (q in 0..100); None for an empty sample."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-int(round(q * len(ordered) * 1000)) // 100000))  # ceil(q/100 * n) without float drift
    return ordered[min(rank, len(ordered)) - 1]


def latency_summary(values: list[float]) -> dict[str, Any]:
    return {"n": len(values), "p50Ms": percentile(values, 50), "p95Ms": percentile(values, 95),
            "meanMs": round(sum(values) / len(values), 2) if values else None}


# --------------------------------------------------------------- viewer ------
def parse_readiness(line_or_text: str) -> dict[str, str] | None:
    """Find the viewer readiness document (origin + url) in the CLI's stdout, wrapped or not."""
    for raw in line_or_text.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            doc = json.loads(raw)
        except ValueError:
            continue
        found = _find_readiness(doc)
        if found:
            return found
    return None


def _find_readiness(doc: Any) -> dict[str, str] | None:
    if isinstance(doc, dict):
        if isinstance(doc.get("url"), str) and isinstance(doc.get("origin"), str):
            return {"origin": doc["origin"], "url": doc["url"]}
        for v in doc.values():
            r = _find_readiness(v)
            if r:
                return r
    elif isinstance(doc, list):
        for v in doc:
            r = _find_readiness(v)
            if r:
                return r
    return None


def bootstrap_token(url: str) -> str | None:
    m = re.search(r"#(?:.*?[?&])?(?:token=)?([A-Za-z0-9_-]{43})(?:$|&)", url)
    return m.group(1) if m else None


class ViewerClient:
    """Minimal same-origin client for the local read API (headers per openapi.yaml)."""

    def __init__(self, origin: str):
        self.origin = origin.rstrip("/")
        u = re.match(r"^http://([^:/]+):(\d+)$", self.origin)
        if not u:
            raise ValueError("viewer origin must be http://127.0.0.1:<port>")
        self.host, self.port = u.group(1), int(u.group(2))
        self.cookie: str | None = None

    def _req(self, method: str, path: str, body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
        h = {"Host": f"{self.host}:{self.port}", "Sec-Fetch-Site": "same-origin", "X-XTrace-Client": "viewer-v1",
             "Accept": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if method == "POST":
            h["Origin"] = self.origin
            h["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data
        finally:
            conn.close()

    def exchange(self, token: str) -> None:
        st, hdrs, data = self._req("POST", "/api/v1/auth/exchange", json.dumps({"token": token}).encode())
        if st != 200:
            raise RuntimeError(f"viewer token exchange failed: HTTP {st}")
        sc = hdrs.get("set-cookie", "")
        self.cookie = sc.split(";", 1)[0] if sc else None
        if not self.cookie:
            raise RuntimeError("viewer exchange returned no session cookie")

    def get(self, path: str) -> tuple[int, Any]:
        st, _, data = self._req("GET", path)
        try:
            return st, json.loads(data.decode("utf-8", "replace"))
        except ValueError:
            return st, {"_nonJson": True, "bytes": len(data)}


def start_viewer(xtrace: str, project_dir: pathlib.Path, env: dict[str, str], log: pathlib.Path,
                 timeout: float = 60.0) -> tuple[subprocess.Popen, dict[str, str]]:
    import select
    with open(log, "wb") as errlog:  # the child holds its own descriptor; this handle does not leak
        proc = subprocess.Popen([xtrace, "open", "--project-dir", str(project_dir), "--viewer", "--no-browser"],
                                stdout=subprocess.PIPE, stderr=errlog, env=env, text=True, start_new_session=True)
    deadline = time.time() + timeout
    assert proc.stdout is not None
    while time.time() < deadline:
        # select first: a viewer that is alive but silent must not block past the deadline
        ready_fds, _, _ = select.select([proc.stdout], [], [], 1.0)
        if not ready_fds:
            if proc.poll() is not None:
                raise RuntimeError(f"viewer exited early with {proc.returncode}")
            continue
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError(f"viewer exited early with {proc.returncode}")
            continue
        ready = parse_readiness(line)
        if ready:
            return proc, ready
    stop_process_group(proc)
    raise RuntimeError("viewer readiness line not seen")


def stop_process_group(proc: subprocess.Popen, wait: float = 15.0) -> None:
    """Signal only the process group this harness started."""
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=wait)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass


def collect_api(client: ViewerClient, out_dir: pathlib.Path, max_recordings: int = 400) -> dict[str, Any]:
    """Read the project's recordings and full event windows through the API. Raw JSON is saved under out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    listing: list[dict] = []
    after = None
    pages = 0
    while pages < 20:
        q = "/api/v1/recordings?limit=200" + (f"&after={after}" if after else "")
        st, doc = client.get(q)
        (out_dir / f"recordings-page-{pages}.json").write_text(json.dumps(doc, indent=1, sort_keys=True))
        if st != 200:
            return {"ok": False, "reason": f"recordings list HTTP {st}", "recordings": [], "details": {}}
        listing += doc.get("recordings", [])
        after = doc.get("nextAfter")
        pages += 1
        if not after or len(listing) >= max_recordings:
            break
    details: dict[str, dict] = {}
    for rec in listing[:max_recordings]:
        rid = rec["recordingId"]
        events: list[dict] = []
        cursor = None
        first: dict | None = None
        for _ in range(40):
            st, doc = client.get(f"/api/v1/recordings/{rid}?limit=1000" + (f"&cursor={cursor}" if cursor else ""))
            if st != 200:
                first = first or {"_http": st, "events": []}
                break
            first = first or {k: v for k, v in doc.items() if k != "events"}
            events += doc.get("events", [])
            cursor = doc.get("nextCursor")
            if not cursor:
                break
        d = dict(first or {})
        d["events"] = events
        d.setdefault("recordingId", rid)
        if rec.get("openedAt") is not None:  # kept for time-window attribution of recordings to scenarios
            d.setdefault("_openedAt", rec["openedAt"])
        details[rid] = d
        (out_dir / f"recording-{rid}.json").write_text(json.dumps(d, indent=1, sort_keys=True))
    return {"ok": True, "reason": "", "recordings": listing, "details": details}


# --------------------------------------------------------------- analysis ----
def _strings(obj: Any, depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v, depth + 1)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v, depth + 1)]
    return []


def route_regex(template: str) -> re.Pattern[str]:
    parts = re.split(r"(\{[^}/]+\})", template)
    return re.compile("^" + "".join("[^/?#]+" if p.startswith("{") else re.escape(p) for p in parts) + r"/?(?:\?.*)?$")


REQUEST_SYMBOL = re.compile(r"^http\.request ([A-Z]+) (\S+)$")
RESPONSE_SYMBOL = re.compile(r"^http\.response (\d{3})$")


def request_info(detail: dict) -> tuple[str, str] | None:
    """(method, route) from the boundary request event: its symbol reads `http.request GET /owners/{ownerId}`."""
    for ev in detail.get("events", []):
        m = REQUEST_SYMBOL.match(ev.get("symbol") or "")
        if m:
            return m.group(1), m.group(2)
    return None


def response_event_status(detail: dict) -> int | None:
    """Status printed by the boundary response event (`http.response 200`); `http.response unavailable` gives None."""
    for ev in detail.get("events", []):
        m = RESPONSE_SYMBOL.match(ev.get("symbol") or "")
        if m:
            return int(m.group(1))
    return None


def layer_frames(detail: dict, layer: str, name_hint: str | None = None) -> list[dict]:
    pat = LAYER_PATTERNS[layer]
    out = []
    for ev in detail.get("events", []):
        if not str(ev.get("kind", "")).endswith("frame_enter"):
            continue
        sym = ev.get("symbol") or ""
        if pat.search(sym.split(".", 1)[0]) and (name_hint is None or name_hint in sym):
            out.append(ev)
    return out


def recording_http_status(detail: dict) -> int | None:
    """Adapter-observed outcome if present, else the boundary response event's status (reported as such)."""
    o = detail.get("outcome")
    if isinstance(o, dict) and isinstance(o.get("httpStatus"), int):
        return o["httpStatus"]
    return response_event_status(detail)


def recording_matches(detail: dict, method: str, route: str, literal_routes: frozenset = frozenset()) -> bool:
    """Method equal and route equal. A recorded template (contains `{`) matches only by equality; a recorded literal path
    matches a template by pattern unless that literal is itself one of the campaign's literal routes (so a recorded
    `GET /owners/new` never satisfies `GET /owners/{ownerId}`)."""
    info = request_info(detail)
    if not info or info[0] != method:
        return False
    recorded = info[1].split("?", 1)[0].rstrip("/") or "/"
    want = route.rstrip("/") or "/"
    if "{" in recorded:
        return recorded == want
    if "{" not in want:
        return recorded == want
    if recorded in literal_routes:
        return False
    return bool(route_regex(route).match(info[1]))


def recording_time(detail: dict) -> float | None:
    """Wall-clock seconds the recording opened: `openedAt` (RFC 3339) if the API gave it, else the UUIDv7 millisecond prefix."""
    import datetime as _dt
    v = detail.get("_openedAt") or detail.get("openedAt")
    if isinstance(v, str):
        try:
            return _dt.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    rid = str(detail.get("recordingId") or detail.get("_id") or "")
    m = re.match(r"^(?:rec[-_])?([0-9a-f]{8})-?([0-9a-f]{4})-?7[0-9a-f]{3}-", rid)
    if m:
        return int(m.group(1) + m.group(2), 16) / 1000.0
    return None


def source_ok(ev: dict) -> bool:
    s = ev.get("source")
    return isinstance(s, dict) and isinstance(s.get("path"), str) and s["path"].endswith((".java", ".kt")) and \
        isinstance(s.get("startLine"), int) and s["startLine"] >= 1 and s.get("status") == "matched"


ACCEPTED_BINDINGS = ("verified", "observed_unattested")


def binding_state(ev: dict) -> str:
    """`ok` / `bad` / `missing` for the source binding of one event. `sourceBinding` is a required Event field in
    schema/xtp-client/openapi.yaml, so an absent field is a contract violation, never an acceptable binding."""
    s = ev.get("source") if isinstance(ev.get("source"), dict) else {}
    for holder in (ev, s):
        for key in ("sourceBinding", "binding"):
            v = holder.get(key)
            if isinstance(v, str):
                norm = v.lower().replace("source_binding_", "").replace("-", "_")
                return "ok" if norm in ACCEPTED_BINDINGS else "bad"
    return "missing"


def layer_source_ok(detail: dict, layers: list[str], hints: dict) -> tuple[bool, str | None]:
    """(a matched source on the layer frame with an acceptable binding, else why not: `unacceptable` | `missing` | None)."""
    frames = [ev for layer in layers for ev in layer_frames(detail, layer, hints.get(layer))]
    if not frames:  # no layer expectation: fall back to any frame event
        frames = [ev for ev in detail.get("events", []) if str(ev.get("kind", "")).endswith("frame_enter")]
    with_src = [ev for ev in frames if source_ok(ev)]
    if any(binding_state(ev) == "ok" for ev in with_src):
        return True, None
    states = {binding_state(ev) for ev in with_src}
    return False, ("unacceptable" if "bad" in states else "missing" if "missing" in states else None)


def _path_matches(path: str, want_route: str, literal_routes: frozenset) -> bool:
    """Same collision rule as recording_matches, for a concrete request path the harness sent."""
    p = path.split("?", 1)[0].rstrip("/") or "/"
    want = want_route.rstrip("/") or "/"
    if "{" not in want:
        return p == want
    if p in literal_routes:
        return False
    return bool(route_regex(want_route).match(path))


def analyze(details: dict[str, dict], expectations: dict[str, list[dict]],
            sent: list[tuple[str | None, str, str]] | None = None) -> dict[str, Any]:
    """expectations: scenario id -> [{method, route, status, layers[], minCount}]. Returns a verdict per scenario.

    Attribution is by ORDER, never by wall clock (a recording's openedAt tracks ingestion, not the request). `sent` is the
    harness's ordered request log [(scenario id | None for non-scenario traffic such as the canary requests, method,
    path)]. For one expectation (method, route) the product must have recorded exactly as many matching recordings as the
    harness sent matching requests; then recordings sorted by time are consumed in request order and each scenario judges
    only the recordings of its own requests. Any other count cannot be attributed and is reported as
    `attribution-ambiguous` (never guessed). Without `sent` every scenario is judged campaign-wide and says so."""
    literal_routes = frozenset((e["route"].rstrip("/") or "/") for exps in expectations.values() for e in exps if "{" not in e["route"])
    verdicts: dict[str, Any] = {}
    for sid, exps in expectations.items():
        items = []
        attributed_total = 0
        for e in exps:
            matched_all = [d for d in details.values() if recording_matches(d, e["method"], e["route"], literal_routes)]
            problems: list[str] = []
            attribution = "campaign-wide"
            matched = matched_all
            if sent is not None:
                attribution = "order"
                reqs = [r for r in sent if r[1] == e["method"] and _path_matches(r[2], e["route"], literal_routes)]
                mine = [i for i, r in enumerate(reqs) if r[0] == sid]
                times = [recording_time(d) for d in matched_all]
                if not matched_all:
                    matched = []
                elif len(matched_all) != len(reqs):
                    matched = []
                    problems.append(f"attribution-ambiguous(recordings {len(matched_all)}, requests {len(reqs)})")
                elif any(t is None for t in times):
                    matched = []
                    problems.append("attribution-ambiguous(recording time unknown)")
                else:
                    order = sorted(range(len(matched_all)), key=lambda i: (times[i], i))
                    matched = [matched_all[order[i]] for i in mine]
            attributed_total += len(matched)
            with_status = [d for d in matched if recording_http_status(d) == e["status"]]
            need = e.get("minCount", 1)
            if problems:
                pass
            elif not matched:
                problems.append("no-recording-for-route")
            else:
                seen = sorted({str(recording_http_status(d)) for d in matched})
                if not with_status:
                    problems.append(f"http-outcome-mismatch(expected {e['status']}, saw {','.join(seen)})")
                elif len(with_status) < need:
                    problems.append(f"count-below-minimum(need {need}, have {len(with_status)})")
            unobserved = [d for d in with_status if (d.get("outcome") or {}).get("kind") not in ("responded", "exception")]
            if with_status and unobserved:
                problems.append("outcome-unobserved")
            layer_report = {}
            for layer in e.get("layers", []):
                hint = e.get("layerHints", {}).get(layer)
                have = [d for d in with_status if layer_frames(d, layer, hint)]
                layer_report[layer] = {"recordingsWithFrame": len(have), "of": len(with_status)}
                if with_status and not have:
                    problems.append(f"no-{layer}-frame")
            hints = e.get("layerHints", {})
            src, why = [], set()
            for d in with_status:
                ok, w = layer_source_ok(d, e.get("layers", []), hints)
                if ok:
                    src.append(d)
                elif w:
                    why.add(w)
            if with_status and not src:
                problems.append("source-binding-unacceptable" if "unacceptable" in why else
                                "source-binding-missing" if "missing" in why else "no-source-file-line")
            items.append({"method": e["method"], "route": e["route"], "expectedStatus": e["status"], "attribution": attribution,
                          "recordingsMatchingRoute": len(matched), "recordingsWithStatus": len(with_status),
                          "layers": layer_report, "recordingsWithSource": len(src), "problems": problems,
                          "passed": not problems})
        verdicts[sid] = {"passed": all(i["passed"] for i in items), "expectations": items,
                         "attribution": "order" if sent is not None else "campaign-wide",
                         "recordingsAttributed": attributed_total}
    return verdicts


def problem_classes(verdicts: dict[str, Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in verdicts.values():
        for i in v["expectations"]:
            for p in i["problems"]:
                key = p.split("(")[0]
                out[key] = out.get(key, 0) + 1
    return out


# ------------------------------------------------------------ canaries -------
def canary_hook(canaries: dict[str, str]) -> Callable[..., tuple]:
    """REQUEST_HOOK adding Authorization, Cookie, a query token and a form password to every scenario request."""
    import urllib.parse

    def hook(method: str, path: str, headers: dict, raw: Any) -> tuple:
        h = dict(headers)
        h["Authorization"] = canaries["authorization-header"]
        h["Cookie"] = canaries["cookie-header"]
        p = path + ("&" if "?" in path else "?") + "xt_token=" + urllib.parse.quote(canaries["query-token"], safe="")
        r = raw
        if method == "POST" and raw is not None and h.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
            r = raw + b"&password=" + urllib.parse.quote(canaries["json-body-password"], safe="").encode()
        return p, h, r
    return hook


def send_canary_requests(base: str, canaries: dict[str, str], paths: list[tuple[str, str]]) -> list[dict]:
    """Extra non-scenario requests carrying a JSON body password; the responses are not judged."""
    import xcamp
    out = []
    for method, path in paths:
        body = json.dumps({"username": "xt-canary-user", "password": canaries["json-body-password"]}).encode()
        try:
            r = xcamp.http_request(base, method, path, headers={"Content-Type": "application/json",
                                   "Authorization": canaries["authorization-header"],
                                   "Cookie": canaries["cookie-header"]}, body=body)
            out.append({"method": method, "path": path, "status": r["status"]})
        except Exception as exc:  # recorded, not fatal: the canary scan decides
            out.append({"method": method, "path": path, "error": type(exc).__name__})
    return out


# ------------------------------------------------------------ orchestration --
def run_instrumented(*, project: str, pin: dict[str, Any], make_stack: Callable[[str], Any], scenarios: list[Any],
                     out_dir: pathlib.Path, norm_extra: list, expectations: dict[str, list[dict]], xtrace: str,
                     project_dir: pathlib.Path, data_home: pathlib.Path, adaptations: list[str],
                     canaries: dict[str, str] | None, baseline_receipt: pathlib.Path | None,
                     extra_canary_paths: list[tuple[str, str]], harness_files: list[pathlib.Path]) -> dict[str, Any]:
    """Launch (via XCAMP_LAUNCH_PREFIX = xtrace run ... --), run scenarios, stop, read recordings back, judge."""
    import xcamp
    out_dir.mkdir(parents=True, exist_ok=False)
    env = {**os.environ, "XTRACE_DATA_HOME": str(data_home)}
    data_home.mkdir(parents=True, exist_ok=True)
    notes: dict[str, Any] = {}
    init = subprocess.run([xtrace, "init", "--project-dir", str(project_dir), "--display-name", "campaign"],
                          env=env, capture_output=True, text=True, timeout=120)
    notes["init"] = {"exitCode": init.returncode}
    if init.returncode != 0:
        raise RuntimeError(f"xtrace init failed with exit {init.returncode}")
    if canaries:
        xcamp.REQUEST_HOOK = canary_hook(canaries)
        os.environ["XTRACE_CANARY_ENV"] = canaries["env-var"]
    os.environ["XTRACE_DATA_HOME"] = str(data_home)
    run_id = out_dir.name.replace("instrumented-", "i") + str(int(time.time()) % 100000)
    stack = make_stack(run_id)
    results: list[dict[str, Any]] = []
    sent_log: list[tuple[str | None, str, str]] = []
    xcamp.SENT_LOG = []
    started = time.time()
    boot_ms = None
    try:
        t0 = time.perf_counter()
        stack.up()
        boot_ms = round((time.perf_counter() - t0) * 1000)
        for sc in scenarios:
            mark = len(xcamp.SENT_LOG)
            res = xcamp.run_scenario(sc, stack, stack.base, norm_extra)
            sent_log.extend((res["id"], m, pth) for m, pth in xcamp.SENT_LOG[mark:])
            results.append(res)
            print(f"  [{'PASS' if res['passed'] else 'FAIL'}] {sc.id} {res['semanticEffectFingerprint'][:16]} {res['elapsedMs']}ms", flush=True)
        if canaries:
            notes["canaryRequests"] = send_canary_requests(stack.base, canaries, extra_canary_paths)
            sent_log.extend((None, m, pth) for m, pth in extra_canary_paths)  # non-scenario traffic, still recorded by the product
    finally:
        stack.down()  # SIGTERM to the launcher we started; `xtrace run` forwards it and drains the daemon
        try:  # after the stop, so the launcher's own closing diagnostics are in the log
            (out_dir / "application.log").write_text(stack.logs())
        except Exception:
            pass
    xcamp.REQUEST_HOOK = None
    xcamp.SENT_LOG = None
    notes["launcherExitCode"] = getattr(stack, "launcher_exit", None)

    # product lifecycle commands that exist in the CLI surface: exit code 9 means "not implemented yet"
    stop = subprocess.run([xtrace, "stop", "--project-dir", str(project_dir)], env=env, capture_output=True, text=True, timeout=60)
    notes["stopCommand"] = {"exitCode": stop.returncode, "notImplemented": stop.returncode == 9}

    api: dict[str, Any] = {"ok": False, "reason": "viewer not started", "recordings": [], "details": {}}
    verdicts: dict[str, Any] = {}
    viewer = None
    try:
        viewer, ready = start_viewer(xtrace, project_dir, env, out_dir / "viewer.log")
        client = ViewerClient(ready["origin"])
        token = bootstrap_token(ready["url"])
        if not token:
            raise RuntimeError("no bootstrap token in viewer url")
        client.exchange(token)
        api = collect_api(client, out_dir / "api")
    except Exception as exc:
        api = {"ok": False, "reason": f"{type(exc).__name__}: {str(exc)[:200]}", "recordings": [], "details": {}}
    finally:
        if viewer is not None:
            stop_process_group(viewer)
    if api["ok"]:
        verdicts = analyze(api["details"], expectations, sent_log)

    baseline_fp: dict[str, str] = {}
    if baseline_receipt and baseline_receipt.exists():
        baseline_fp = {s["id"]: s["semanticEffectFingerprint"] for s in json.loads(baseline_receipt.read_text())["scenarios"]}
    scen_out = []
    for r in results:
        v = verdicts.get(r["id"])
        scen_out.append({
            "id": r["id"], "scenarioChecksPassed": r["passed"], "semanticEffectFingerprint": r["semanticEffectFingerprint"],
            "baselineFingerprint": baseline_fp.get(r["id"]),
            "fingerprintEqualsBaseline": baseline_fp.get(r["id"]) == r["semanticEffectFingerprint"] if baseline_fp else None,
            "recordingVerdict": v, "requests": [{"label": q["label"], "status": q["response"]["status"], "elapsedMs": q["elapsedMs"]}
                                                for q in r["requests"]],
            "elapsedMs": r["elapsedMs"]})
    receipt = {
        "schemaVersion": 1, "kind": "instrumented_campaign_non_release", "project": project, "releaseAcceptance": False,
        "instrumented": True, "signed": False, "pin": pin, "syntheticDataOnly": True, "configurationAdaptations": adaptations,
        "harnessSha256": {p.name: xcamp.sha256_file(p) for p in harness_files}, "bootMs": boot_ms,
        "durationSeconds": round(time.time() - started, 1), "notes": notes,
        "api": {"ok": api["ok"], "reason": api["reason"], "recordings": len(api["recordings"])},
        "attribution": "order: recordings consumed in request order per route; unequal counts are attribution-ambiguous",
        "requestsSent": len(sent_log),
        "problemClasses": problem_classes(verdicts), "scenarios": scen_out,
        "recordingsWithSource": sum(e["recordingsWithSource"] for v in verdicts.values() for e in v["expectations"]),
        "recordingsWithStatus": sum(e["recordingsWithStatus"] for v in verdicts.values() for e in v["expectations"]),
        "result": "recorded" if api["ok"] and results else "failed",
    }
    (out_dir / "receipt.json").write_text(json.dumps(receipt, indent=1, sort_keys=True))
    return receipt
