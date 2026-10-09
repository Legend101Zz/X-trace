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

LAYER_PATTERNS = {
    "controller": re.compile(r"Controller|Resource(?:#|\.|$)|ApiResource"),
    "service": re.compile(r"Service"),
    "repository": re.compile(r"Repository|\bDao\b|Dao[#.]"),
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
    proc = subprocess.Popen([xtrace, "open", "--project-dir", str(project_dir), "--viewer", "--no-browser"],
                            stdout=subprocess.PIPE, stderr=open(log, "wb"), env=env, text=True, start_new_session=True)
    deadline = time.time() + timeout
    assert proc.stdout is not None
    while time.time() < deadline:
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


def boundary_facts(detail: dict) -> dict[str, Any]:
    """Method/route/path strings on the recording boundary plus frame symbols, as the API reports them."""
    strings: list[str] = []
    symbols: list[str] = []
    for ev in detail.get("events", []):
        strings += _strings(ev.get("interaction"))
        if ev.get("symbol"):
            symbols.append(ev["symbol"])
    return {"strings": strings, "symbols": symbols}


def layer_frames(detail: dict, layer: str, name_hint: str | None = None) -> list[dict]:
    pat = LAYER_PATTERNS[layer]
    out = []
    for ev in detail.get("events", []):
        sym = ev.get("symbol") or ""
        if pat.search(sym) and (name_hint is None or name_hint in sym):
            out.append(ev)
    return out


def recording_http_status(detail: dict) -> int | None:
    o = detail.get("outcome")
    return o.get("httpStatus") if isinstance(o, dict) else None


def recording_matches(detail: dict, method: str, route: str) -> bool:
    facts = boundary_facts(detail)
    rx = route_regex(route)
    has_method = any(s.upper() == method for s in facts["strings"]) or any(
        s.upper().startswith(method + " ") and rx.match(s[len(method) + 1:].strip()) for s in facts["strings"])
    return has_method and any(rx.match(s) or rx.match(s.split(" ", 1)[-1]) for s in facts["strings"])


def source_ok(ev: dict) -> bool:
    s = ev.get("source")
    return isinstance(s, dict) and isinstance(s.get("path"), str) and s["path"].endswith((".java", ".kt")) and \
        isinstance(s.get("startLine"), int) and s["startLine"] >= 1 and s.get("status") == "matched"


def analyze(details: dict[str, dict], expectations: dict[str, list[dict]]) -> dict[str, Any]:
    """expectations: scenario id -> [{method, route, status, layers[], minCount}]. Returns a verdict per scenario."""
    verdicts: dict[str, Any] = {}
    for sid, exps in expectations.items():
        items = []
        for e in exps:
            matched = [d for d in details.values() if recording_matches(d, e["method"], e["route"])]
            with_status = [d for d in matched if recording_http_status(d) == e["status"]]
            problems: list[str] = []
            need = e.get("minCount", 1)
            if not matched:
                problems.append("no-recording-for-route")
            elif len(with_status) < need:
                seen = sorted({str(recording_http_status(d)) for d in matched})
                problems.append(f"http-outcome-mismatch(expected {e['status']}, saw {','.join(seen)})")
            layer_report = {}
            for layer in e.get("layers", []):
                hint = e.get("layerHints", {}).get(layer)
                have = [d for d in with_status if layer_frames(d, layer, hint)]
                layer_report[layer] = {"recordingsWithFrame": len(have), "of": len(with_status)}
                if with_status and not have:
                    problems.append(f"no-{layer}-frame")
            src = [d for d in with_status if any(source_ok(ev) for ev in d.get("events", []))]
            if with_status and not src:
                problems.append("no-source-file-line")
            items.append({"method": e["method"], "route": e["route"], "expectedStatus": e["status"],
                          "recordingsMatchingRoute": len(matched), "recordingsWithStatus": len(with_status),
                          "layers": layer_report, "recordingsWithSource": len(src), "problems": problems,
                          "passed": not problems})
        verdicts[sid] = {"passed": all(i["passed"] for i in items), "expectations": items}
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
    started = time.time()
    boot_ms = None
    try:
        t0 = time.perf_counter()
        stack.up()
        boot_ms = round((time.perf_counter() - t0) * 1000)
        for sc in scenarios:
            res = xcamp.run_scenario(sc, stack, stack.base, norm_extra)
            results.append(res)
            print(f"  [{'PASS' if res['passed'] else 'FAIL'}] {sc.id} {res['semanticEffectFingerprint'][:16]} {res['elapsedMs']}ms", flush=True)
        if canaries:
            notes["canaryRequests"] = send_canary_requests(stack.base, canaries, extra_canary_paths)
    finally:
        stack.down()  # SIGTERM to the launcher we started; `xtrace run` forwards it and drains the daemon
        try:  # after the stop, so the launcher's own closing diagnostics are in the log
            (out_dir / "application.log").write_text(stack.logs())
        except Exception:
            pass
    xcamp.REQUEST_HOOK = None
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
        verdicts = analyze(api["details"], expectations)

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
        "problemClasses": problem_classes(verdicts), "scenarios": scen_out,
        "recordingsWithSource": sum(e["recordingsWithSource"] for v in verdicts.values() for e in v["expectations"]),
        "recordingsWithStatus": sum(e["recordingsWithStatus"] for v in verdicts.values() for e in v["expectations"]),
        "result": "recorded" if api["ok"] and results else "failed",
    }
    (out_dir / "receipt.json").write_text(json.dumps(receipt, indent=1, sort_keys=True))
    return receipt
