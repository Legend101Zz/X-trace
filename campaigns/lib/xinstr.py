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
from collections import Counter
from typing import Any, Callable
from urllib.parse import quote

# matched against the class part of a frame symbol such as `OwnerController.findOwner`
LAYER_PATTERNS = {
    "controller": re.compile(r"Controller|Resource$"),
    "service": re.compile(r"Service"),
    "repository": re.compile(r"Repository|Dao$"),
}

# Fixed product codes only: an error body can also contain private detail text.
READ_PROBLEM_CODES = frozenset((
    "XTR-VIEWER-QUERY-FAILED", "XTR-VIEWER-QUERY-BUSY", "XTR-PRIVATE-STORAGE-UNAVAILABLE",
    "XTR-STORE-OBJECT-IO", "XTR-STORE-OBJECT-CORRUPT", "XTR-STORE-RECORDING-QUERY-CORRUPT",
    "XTR-STORE-RECORDING-ROOT-IO", "XTR-STORE-RECORDING-ROOT-INVALID",
    "XTR-STORE-RECORDING-ROOT-PERMISSION", "XTR-STORE-RECORDING-SQLITE-IO",
    "XTR-STORE-RECORDING-SQLITE-BUSY", "XTR-STORE-RECORDING-SQLITE-INTERNAL",
    "XTR-PORT-VALIDATION", "XTR-PORT-ALREADY-EXISTS", "XTR-PORT-NOT-FOUND", "XTR-PORT-CONFLICT",
    "XTR-PORT-COMPATIBILITY", "XTR-PORT-RESOURCE", "XTR-PORT-CORRUPTION", "XTR-PORT-TRANSPORT",
    "XTR-PORT-INTERNAL",
))


def read_problem(status: int, doc: Any) -> dict[str, Any]:
    """Publish bounded failure metadata, never an API error's message or detail."""
    doc = doc if isinstance(doc, dict) else {}
    code, request_id = doc.get("code"), doc.get("requestId")
    return {"httpStatus": status, "code": code if isinstance(code, str) and code in READ_PROBLEM_CODES else None,
            "requestId": request_id if isinstance(request_id, str) and re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", request_id) else None}


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
    """Read the viewer's explicit line-delimited readiness stream, wrapped or not (not lifecycle JSON)."""
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
        self.deadline: float | None = None

    def _req(self, method: str, path: str, body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
        h = {"Host": f"{self.host}:{self.port}", "Sec-Fetch-Site": "same-origin", "X-XTrace-Client": "viewer-v1",
             "Accept": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if method == "POST":
            h["Origin"] = self.origin
            h["Content-Type"] = "application/json"
        remaining = 60.0 if self.deadline is None else self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("burst boundary budget exhausted")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=min(60.0, remaining))
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


def list_recording_ids(xtrace: str, project_dir: pathlib.Path, env: dict[str, str]) -> set[str]:
    """Snapshot persisted ids before launching, so repeated measurements judge only their own new recordings."""
    ids = set()
    after = None
    for _ in range(20):
        args = [xtrace, "recording", "list", "--project-dir", str(project_dir), "--limit", "200"]
        if after:
            args += ["--after", after]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"recording list before launch exited {result.returncode}")
        doc = json.loads(result.stdout)
        doc = doc.get("data", doc)
        rows = doc.get("recordings")
        if not isinstance(rows, list) or any(not isinstance(r, dict) or not r.get("recording_id") for r in rows):
            raise RuntimeError("recording list before launch returned invalid rows")
        ids.update(r["recording_id"] for r in rows)
        after = doc.get("next_after")
        if not after:
            return ids
    raise RuntimeError("recording snapshot exceeded the pagination bound")


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


def _next_page(doc: dict, key: str, seen: set[str], has_rows: bool) -> str | None:
    token = doc[key]
    if token is not None:
        if not has_rows or not isinstance(token, str) or not re.fullmatch(r"[!-~]+", token) or token in seen:
            raise ValueError("invalid pagination continuation")
        seen.add(token)
    return token


def detail_read_incomplete(detail: dict | None) -> bool:
    """Identify an unavailable or incomplete detail read, independent of capture completion."""
    return detail is None or "_detailReadGap" in detail or "_http" in detail


def collect_api(client: ViewerClient, out_dir: pathlib.Path, max_recordings: int = 400) -> dict[str, Any]:
    """Save observed pages and explicitly mark any listing or detail read that stops early."""
    out_dir.mkdir(parents=True, exist_ok=True)
    listing: list[dict] = []
    after = None
    seen: set[str] = set()
    listed_ids: set[str] = set()
    listed = False
    list_gap = ""
    problem = None
    live_timeout = False
    for pages in range(20):
        q = "/api/v1/recordings?limit=200" + (f"&after={quote(after, safe='')}" if after else "")
        try:
            st, doc = client.get(q)
        except (OSError, http.client.HTTPException) as exc:
            list_gap = "recordings list transport failure"
            live_timeout = isinstance(exc, TimeoutError) and client.deadline is not None
            break
        (out_dir / f"recordings-page-{pages}.json").write_text(json.dumps(doc, indent=1, sort_keys=True))
        if st != 200:
            list_gap = f"recordings list HTTP {st}"
            problem = read_problem(st, doc)
            break
        rows = doc.get("recordings") if isinstance(doc, dict) else None
        if (not isinstance(rows, list) or (after is not None and not rows)
                or any(not isinstance(row, dict) or not isinstance(row.get("recordingId"), str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]+", row["recordingId"]) for row in rows)):
            list_gap = "recordings list malformed page"
            break
        page_ids = {row["recordingId"] for row in rows}
        if len(page_ids) != len(rows) or listed_ids & page_ids:
            list_gap = "recordings list repeated recording IDs"
            break
        listed_ids.update(page_ids)
        listed = True
        listing.extend(rows)
        try:
            after = _next_page(doc, "nextAfter", seen, bool(rows))
        except (KeyError, ValueError):
            list_gap = "recordings list malformed continuation"
            break
        if len(listing) > max_recordings or (after is not None and len(listing) >= max_recordings):
            list_gap = "recordings list recording bound reached"
            break
        if after is None:
            break
    else:
        list_gap = "recordings list pagination bound reached"

    listing = listing[:max_recordings]
    details: dict[str, dict] = {}
    for rec in listing:
        if live_timeout:
            break
        rid = rec["recordingId"]
        events: list[dict] = []
        cursor = None
        seen = set()
        first: dict | None = None
        detail_gap = None
        incomplete_evidence: dict[str, None] = {}
        for _ in range(40):
            q = f"/api/v1/recordings/{rid}?limit=1000" + (f"&cursor={quote(cursor, safe='')}" if cursor else "")
            try:
                st, doc = client.get(q)
            except (OSError, http.client.HTTPException) as exc:
                detail_gap = "detail transport failure"
                live_timeout = isinstance(exc, TimeoutError) and client.deadline is not None
                break
            if st != 200:
                if first is None:
                    first = {"_http": st}
                detail_gap = f"detail HTTP {st}"
                break
            rows = doc.get("events") if isinstance(doc, dict) else None
            if (not isinstance(rows, list) or (cursor is not None and not rows)
                    or any(not isinstance(row, dict) for row in rows)
                    or doc.get("recordingId", rid) != rid):
                detail_gap = "detail malformed page"
                break
            if first is None:
                first = {k: v for k, v in doc.items() if k != "events"}
            events.extend(rows)
            if isinstance(doc.get("incompleteEvidence"), list):
                incomplete_evidence.update((code, None) for code in doc["incompleteEvidence"] if isinstance(code, str))
            try:
                cursor = _next_page(doc, "nextCursor", seen, bool(rows))
            except (KeyError, ValueError):
                detail_gap = "detail malformed continuation"
                break
            if cursor is None:
                break
        else:
            detail_gap = "detail pagination bound reached"
        d = dict(first or {})
        d["events"] = events
        if detail_gap is not None:
            d["_detailReadGap"] = detail_gap
        else:
            d["nextCursor"] = None
        if incomplete_evidence:
            d["incompleteEvidence"] = list(incomplete_evidence)
        d.setdefault("recordingId", rid)
        if "sessionContext" in rec:
            d.setdefault("sessionContext", rec["sessionContext"])
        if rec.get("openedAt") is not None:  # kept for time-window attribution of recordings to scenarios
            d.setdefault("_openedAt", rec["openedAt"])
        details[rid] = d
        (out_dir / f"recording-{rid}.json").write_text(json.dumps(d, indent=1, sort_keys=True))
    result = {"ok": listed, "reason": "" if listed else list_gap, "recordings": listing, "details": details}
    if list_gap:
        result["listReadGap"] = list_gap
    if len(details) < len(listing):
        result["detailCollectionGap"] = "recording detail read timed out before all listed IDs were read"
    if problem is not None:
        result["problem"] = problem
    return result


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
REQUEST_CORRELATION_GAP = (
    "No unique observed request-to-recording mapping. "
    "Spring MVC records method and route template only, without concrete path, query or headers. "
    "Standard capture has no argument bindings. Focused Owner form objects are unavailable. "
    "Need an allowlisted non-secret request marker "
    "retained per recording and known to the harness, or the recording id returned to the requester. "
    "Request order, recording UUIDs and openedAt supply ordering or recording identity only."
)


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


def layer_frames(detail: dict, layer: str, name_hint: str | list[str] | tuple[str, ...] | None = None) -> list[dict]:
    """Match layer classes with optional class-name or exact class.method symbol alternatives."""
    pat = LAYER_PATTERNS[layer]
    out = []
    for ev in detail.get("events", []):
        if not str(ev.get("kind", "")).endswith("frame_enter"):
            continue
        sym = ev.get("symbol") or ""
        declaring, separator, _ = sym.rpartition(".")
        simple = declaring.rsplit(".", 1)[-1]
        hints = [name_hint] if isinstance(name_hint, str) else name_hint
        if separator and pat.search(simple) and (hints is None or any(h in (declaring, simple, sym) for h in hints)):
            out.append(ev)
    return out


def recording_http_status(detail: dict) -> int | None:
    """Adapter-observed outcome if present, else the boundary response event's status (reported as such)."""
    o = detail.get("outcome")
    if isinstance(o, dict) and isinstance(o.get("httpStatus"), int):
        return o["httpStatus"]
    return response_event_status(detail)


OBSERVED_OUTCOME_KINDS = ("responded", "exception_propagated")  # product kinds: responded, exception_propagated, client_aborted, unobserved


def exception_matches(detail: dict, wanted: str | None, controller_hint: str | list[str] | None = None) -> bool:
    """Require propagation plus an observed application throw of the expected type.

    The boundary outcome may name a servlet wrapper. Only a typed FRAME_THROW on
    an observed application method establishes the application's own exception.
    """
    o = detail.get("outcome")
    if not wanted or not isinstance(o, dict) or o.get("kind") != "exception_propagated":
        return False
    symbols = {ev.get("symbol") for ev in layer_frames(detail, "controller", controller_hint)}
    for ev in detail.get("events", []):
        if not str(ev.get("kind", "")).endswith("frame_throw"):
            continue
        exc = ev.get("exception")
        typ = exc.get("exceptionType") if isinstance(exc, dict) else None
        if ev.get("symbol") in symbols and isinstance(typ, str) and (typ == wanted or typ.endswith("." + wanted)):
            return True
    return False


def outcome_matches(detail: dict, expectation: dict) -> bool:
    hint = expectation.get("layerHints", {}).get("controller")
    if expectation.get("outcome") == "exception_propagated":
        return recording_http_status(detail) is None and exception_matches(detail, expectation.get("exception"), hint)
    if "statuses" in expectation:
        return recording_http_status(detail) in expectation["statuses"]
    if recording_http_status(detail) == expectation["status"]:
        return True
    return expectation["status"] >= 500 and exception_matches(detail, expectation.get("exception"), hint)


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
    return _frame_source_ok(frames)


def _frame_source_ok(frames: list[dict]) -> tuple[bool, str | None]:
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


def capacity_counts(details: dict[str, dict]) -> dict[str, int]:
    """Session counters are repeated on recordings; never sum their copies."""
    counts: dict[str, int] = {}
    for detail in details.values():
        context = detail.get("sessionContext")
        if not isinstance(context, dict):
            continue
        session, count = context.get("runtimeSessionId"), context.get("rejectedRequests")
        if isinstance(session, str) and session and isinstance(count, str) and re.fullmatch(r"[0-9]+", count):
            counts[session] = max(counts.get(session, 0), int(count))
    return counts


def burst_accounting(details: dict[str, dict], sent: list[tuple[str | None, str, str]],
                     expectations: dict[str, list[dict]], before: dict[str, dict]) -> dict[str, Any]:
    """Account for a group's terminal recordings by route and refusals by session."""
    routes = {(e["method"], e["route"]) for exps in expectations.values() for e in exps}
    literals = frozenset(route for _, route in routes if "{" not in route)
    fresh = {rid: d for rid, d in details.items() if rid not in before}
    rows = []
    ids: set[str] = set()
    partial: set[str] = set()
    for method, route in sorted(routes):
        requests = sum(m == method and _path_matches(path, route, literals) for _, m, path in sent)
        if not requests:
            continue
        hits = {rid: d for rid, d in fresh.items() if recording_matches(d, method, route, literals)
                and d.get("completion") in ("complete", "partial")}
        ids.update(hits)
        partial.update(rid for rid, d in hits.items() if d.get("completion") == "partial")
        rows.append({"method": method, "route": route, "requests": requests, "recordings": len(hits),
                     "recordingIds": sorted(hits), "missing": requests - len(hits)})
    previous = capacity_counts(before)
    counters = capacity_counts(details)
    rejected = sum(max(0, count - previous.get(session, 0)) for session, count in counters.items())
    missing = len(sent) - len(ids) - rejected
    accounted = (missing == 0 and sum(row["requests"] for row in rows) == len(sent)
                 and all(row["missing"] >= 0 for row in rows) and set(fresh) == ids)
    return {"verified": accounted, "verifiedAt": time.time() if accounted else None,
            "recordingIds": sorted(ids), "recordingCount": len(ids), "snapshotIds": sorted(details),
            "requests": len(sent), "capacityDrops": rejected, "capacityCounts": counters,
            "partialRecordingIds": sorted(partial), "unaccounted": missing, "routes": rows}


def wait_burst_boundary(client: ViewerClient, out_dir: pathlib.Path, sent: list, expectations: dict,
                        before: dict, deadline: float, *, require_complete: bool = False) -> dict[str, Any]:
    """Poll observable read state within the caller's remaining scenario budget; no drain sleep."""
    boundary = burst_accounting({}, sent, expectations, before)
    client.deadline = deadline
    try:
        while time.monotonic() < deadline:
            api = collect_api(client, out_dir)
            if api["ok"]:
                boundary = burst_accounting(api["details"], sent, expectations, before)
            read_gap = api.get("listReadGap") or api.get("detailCollectionGap") or (api["reason"] if not api["ok"] else "")
            if not read_gap and any(detail_read_incomplete(detail) for rid, detail in api["details"].items()
                                    if rid not in before):
                read_gap = "recording detail read incomplete"
            if read_gap:
                boundary["readError"] = read_gap
                if "problem" in api:
                    boundary["readProblem"] = api["problem"]
                break
            if boundary["verified"] and time.monotonic() <= deadline:
                if require_complete and (boundary["capacityDrops"] or boundary["partialRecordingIds"]):
                    boundary["verified"] = False
                    boundary["verifiedAt"] = None
                return boundary
    except OSError:
        boundary["readError"] = "recording snapshot could not be read or saved"
    finally:
        client.deadline = None
    boundary["verified"] = False
    boundary["verifiedAt"] = None
    return boundary


def serial_frame_symbols(details: dict[str, dict], sent: list, burst: frozenset,
                         serial_boundary: dict) -> dict[str, list[str]]:
    """Inventory serial scenarios, including routes without a scenario expectation."""
    names: dict[str, set[str]] = {}
    if not serial_boundary["verified"]:
        return {}
    routes = {info for d in details.values() if (info := request_info(d)) is not None}
    literals = frozenset(route for _, route in routes if "{" not in route)
    ids = set(serial_boundary["recordingIds"])
    for method, route in routes:
        requests = [r for r in sent if r[0] is not None and r[0] not in burst
                    and r[1] == method and _path_matches(r[2], route, literals)]
        recordings = [d for rid, d in details.items() if rid in ids and request_info(d) == (method, route)]
        if not requests or len(recordings) != len(requests):
            continue
        times = [recording_time(d) for d in recordings]
        if any(t is None for t in times) or len(set(times)) != len(times):
            continue
        order = sorted(range(len(recordings)), key=lambda i: times[i])
        for request, index in zip(requests, order):
            names.setdefault(request[0], set()).update(ev["symbol"] for ev in recordings[index].get("events", [])
                                                      if str(ev.get("kind", "")).endswith("frame_enter")
                                                      and isinstance(ev.get("symbol"), str) and ev["symbol"])
    return {sid: sorted(symbols) for sid, symbols in names.items()}


def _burst_frame_evidence(matched: dict[str, dict], checks: list[dict]) -> tuple[dict, list[dict], list[str]]:
    """Count witnesses for each distinct expectation across the group, without allocating recordings."""
    signatures = set()
    for check in checks or [{}]:
        hints = check.get("layerHints", {})
        rules = []
        for layer in sorted(set(check.get("layers", []))):
            hint = hints.get(layer)
            if isinstance(hint, str):
                hint = [hint]
            rules.append((layer, None if hint is None else tuple(sorted(set(hint)))))
        signatures.add(tuple(rules))

    occurrences = Counter(rule for signature in signatures for rule in signature)
    different = len(signatures) > 1
    layer_ids: dict[str, set[str]] = {}
    missing_layers = set()
    reports = {}
    for layer, hints in occurrences:
        frame_ids, source_ids = set(), set()
        for rid, detail in matched.items():
            frames = layer_frames(detail, layer, hints)
            if frames:
                frame_ids.add(rid)
                if _frame_source_ok(frames)[0]:
                    source_ids.add(rid)
        layer_ids.setdefault(layer, set()).update(frame_ids)
        if matched and (not frame_ids or (not different and len(frame_ids) < len(matched))):
            missing_layers.add(layer)
        reports[layer, hints] = (frame_ids, source_ids)

    coverage = []
    for signature in sorted(signatures, key=str):
        # A shared layer's source cannot satisfy a different layer or hint.
        distinct_rules = [rule for rule in signature if occurrences[rule] < len(signatures)]
        if distinct_rules:
            sourced = [reports[rule][1] for rule in distinct_rules]
            source_covered = all(sourced)
        elif signature:
            sourced = [reports[rule][1] for rule in signature]
            source_covered = any(sourced)
        else:
            sourced = [{rid for rid, detail in matched.items() if layer_source_ok(detail, [], {})[0]}]
            source_covered = bool(sourced[0])
        coverage.append({
            "layers": {layer: {"hints": None if hints is None else list(hints),
                               "recordingsWithFrame": len(reports[layer, hints][0]),
                               "recordingsWithSource": len(reports[layer, hints][1])} for layer, hints in signature},
            "recordingsWithSource": len(set().union(*sourced)),
            "framesCovered": all(reports[rule][0] for rule in signature),
            "sourceCovered": source_covered,
        })

    problems = [f"no-{layer}-frame" for layer in sorted(missing_layers)]
    if different:
        problems.append("burst-frame-expectations-differ")
        if any(not item["sourceCovered"] for item in coverage):
            problems.append("burst-source-expectation-unresolved")
    layers = {layer: {"recordingsWithFrame": len(ids), "of": len(matched)} for layer, ids in sorted(layer_ids.items())}
    return layers, coverage, problems


def burst_route_evidence(details: dict[str, dict], expectations: dict[str, list[dict]],
                         burst: frozenset, boundary: dict | None, serial_boundary: dict | None,
                         evidence_ids: tuple[set[str], set[str]]) -> list[dict]:
    """Check each burst route once using its live boundary's recording IDs."""
    if boundary is None or (serial_boundary is not None and not serial_boundary["verified"]):
        return []
    serial_ids = set(serial_boundary["recordingIds"]) if serial_boundary is not None else set()
    status_ids, source_ids = evidence_ids
    groups = []
    rows = {(row["method"], row["route"]): row for row in boundary["routes"]}
    # A declaration contributes to the group even when its scenario sent no matching request.
    route_checks: dict[tuple[str, str], list[dict]] = {}
    for sid in sorted(burst):
        for e in expectations.get(sid, []):
            route_checks.setdefault((e["method"], e["route"]), []).append(e)
    for method, route in sorted(rows.keys() | route_checks.keys()):
        row = rows.get((method, route))
        requests = row["requests"] if row is not None else 0
        checks = route_checks.get((method, route), [])
        route_ids = set(row["recordingIds"]) - serial_ids if row is not None else set()
        matched = {rid: details[rid] for rid in sorted(route_ids)
                   if rid in details and not detail_read_incomplete(details[rid])}
        unread = route_ids - matched.keys()
        problems = []
        if requests != len(matched):
            problems.append(f"burst-route-count-mismatch(requests {requests}, recordings {len(matched)})")
        if unread:
            problems.append(f"burst-recording-detail-unavailable(missing {len(unread)})")
        if not matched:
            problems.append("no-recording-for-route")
        partial = route_ids.intersection(boundary["partialRecordingIds"])
        partial.update(rid for rid, d in matched.items() if d.get("completion") == "partial")
        if partial:
            problems.append("partial-recording")
        if any(d.get("incompleteEvidence") for rid, d in matched.items() if rid not in partial):
            problems.append("recording-evidence-incomplete")

        observed_kinds = (*OBSERVED_OUTCOME_KINDS, "client_aborted", "unobserved")
        outcomes = Counter()
        for detail in matched.values():
            kind = (detail.get("outcome") or {}).get("kind")
            outcomes[recording_http_status(detail), kind if kind in observed_kinds else None] += 1
        with_status = {rid for rid, d in matched.items() if any(outcome_matches(d, e) for e in checks)}
        need = sum(e.get("minCount", 1) for e in checks)
        # Requests and declarations are separate lower bounds on the same recordings.
        expected_recordings = max(requests, need)
        if checks and all("statuses" in e for e in checks):
            expected = sorted((status for e in checks for status in e["statuses"]), key=str)
            expected_recordings = max(expected_recordings, len(expected))
            observed = sorted((recording_http_status(d) for d in matched.values()), key=str)
            if Counter(expected) != Counter(observed):
                problems.append(f"http-outcome-multiset-mismatch(expected {expected}, saw {observed})")
        else:
            # Mixed expectations cannot be checked per scenario without a request mapping.
            outcome_rules = ("status", "statuses", "outcome", "exception")
            if not checks or any(any(e.get(key) != checks[0].get(key) for key in outcome_rules) for e in checks[1:]):
                problems.append("burst-outcome-expectations-differ")
            if len(with_status) != len(matched):
                problems.append(f"http-outcome-count-mismatch(expected {len(matched)}, observed {len(with_status)})")
        if len(with_status) < need:
            problems.append(f"count-below-minimum(need {need}, have {len(with_status)})")
        if any(kind not in OBSERVED_OUTCOME_KINDS for _, kind in outcomes):
            problems.append("outcome-unobserved")
        status_ids.update(with_status)

        layer_report, frame_expectations, frame_problems = _burst_frame_evidence(matched, checks)
        problems.extend(frame_problems)
        with_source = set()
        # Missing boundary IDs and unreadable details for known IDs are separate evidence gaps.
        missing = expected_recordings - len(route_ids)
        if missing > 0:
            problems.append(f"burst-boundary-recordings-missing(missing {missing})")
        source_problems = {"no-source-file-line"} if unread else set()
        for rid, detail in matched.items():
            checks_for_source = [layer_source_ok(detail, e.get("layers", []), e.get("layerHints", {}))
                                 for e in (checks or [{}])]
            if any(ok for ok, _ in checks_for_source):
                with_source.add(rid)
            else:
                states = {why for _, why in checks_for_source}
                source_problems.add("source-binding-unacceptable" if "unacceptable" in states else
                                    "source-binding-missing" if "missing" in states else "no-source-file-line")
        source_ids.update(with_source)
        problems.extend(sorted(source_problems))
        groups.append({
            "evidenceScope": "burst-route-group", "method": method, "route": route,
            "requests": requests, "recordingsMatchingRoute": len(matched),
            "partialRecordings": len(partial), "recordingsWithStatus": len(with_status),
            "outcomes": [{"httpStatus": status, "kind": kind, "recordings": count}
                         for (status, kind), count in sorted(outcomes.items(), key=str)],
            "layers": layer_report, "frameExpectations": frame_expectations,
            "recordingsWithSource": len(with_source), "problems": problems,
        })
    return groups


def analyze(details: dict[str, dict], expectations: dict[str, list[dict]],
            sent: list[tuple[str | None, str, str]] | None = None, burst: frozenset = frozenset(),
            boundary: dict[str, Any] | None = None, serial_boundary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Expect a status or an exact `statuses` multiset per route, plus layers and source evidence.

    A verified serial boundary partitions serial IDs from the later burst. Burst route evidence
    is reported by burst_route_evidence. Per-request isolation requires an observed mapping the
    read API does not supply. Without a boundary, serial routes shared with a burst also remain ambiguous.
    """
    literal_routes = frozenset((e["route"].rstrip("/") or "/") for exps in expectations.values() for e in exps if "{" not in e["route"])
    verdicts: dict[str, Any] = {}
    inventory = serial_frame_symbols(details, sent, burst, serial_boundary) \
        if sent is not None and serial_boundary is not None else None
    serial_ids = set(serial_boundary["recordingIds"]) if serial_boundary is not None else set()
    for sid in dict.fromkeys([*expectations, *sorted(burst)]):
        exps = expectations.get(sid, [])
        is_burst = sid in burst
        items = []
        attributed_total = 0
        symbols: set[str] = set()
        for e in exps:
            if is_burst:
                problems = []
                if serial_boundary is not None and not serial_boundary["verified"]:
                    problems.append("serial-boundary-not-verified")
                elif serial_boundary is not None and boundary is None:
                    problems.append("burst-boundary-not-verified")
                problems.append(f"attribution-ambiguous({REQUEST_CORRELATION_GAP})")
                items.append({"method": e["method"], "route": e["route"], "expectedStatus": e.get("status"),
                              "expectedStatuses": e.get("statuses"), "expectedOutcome": e.get("outcome"),
                              "attribution": "ambiguous", "recordingsMatchingRoute": 0, "recordingsWithStatus": 0,
                              "layers": {}, "recordingsWithSource": 0, "problems": problems, "passed": False})
                continue
            problems = []
            attribution = "campaign-wide"
            matched = [d for d in details.values() if recording_matches(d, e["method"], e["route"], literal_routes)]
            if sent is not None:
                reqs = [r for r in sent if r[1] == e["method"] and _path_matches(r[2], e["route"], literal_routes)]
                attribution = "order"
                matched_all = matched
                mine = [i for i, r in enumerate(reqs) if r[0] == sid]
                if serial_boundary is not None:
                    attribution = "verified-boundary"
                    matched = []
                    if not serial_boundary["verified"]:
                        problems.append("serial-boundary-not-verified")
                    else:
                        serial_reqs = [r for r in reqs if r[0] is not None and r[0] not in burst]
                        mine = [i for i, r in enumerate(serial_reqs) if r[0] == sid]
                        serial = [d for rid, d in details.items() if rid in serial_ids
                                  and recording_matches(d, e["method"], e["route"], literal_routes)]
                        times = [recording_time(d) for d in serial]
                        if len(serial) != len(serial_reqs):
                            problems.append(f"serial-count-mismatch(recordings {len(serial)}, requests {len(serial_reqs)})")
                        elif any(t is None for t in times) or len(set(times)) != len(times):
                            problems.append("attribution-ambiguous(recording time unknown or tied)")
                        else:
                            order = sorted(range(len(serial)), key=lambda i: times[i])
                            matched = [serial[order[i]] for i in mine]
                elif boundary is not None:
                    attribution = "verified-boundary"
                    snapshot_ids = set(boundary["snapshotIds"])
                    if not boundary["verified"]:
                        matched = []
                        problems.append("burst-boundary-not-verified(serial requests not sent)")
                    else:
                        serial_reqs = [r for r in reqs if r[0] not in burst]
                        mine = [i for i, r in enumerate(serial_reqs) if r[0] == sid]
                        serial = [d for rid, d in details.items() if rid not in snapshot_ids
                                  and recording_matches(d, e["method"], e["route"], literal_routes)]
                        times = [recording_time(d) for d in serial]
                        matched = []
                        if len(serial) != len(serial_reqs):
                            problems.append(f"serial-count-mismatch(recordings {len(serial)}, requests {len(serial_reqs)})")
                        elif any(t is None for t in times):
                            problems.append("attribution-ambiguous(recording time unknown)")
                        else:
                            order = sorted(range(len(serial)), key=lambda i: (times[i], i))
                            matched = [serial[order[i]] for i in mine]
                elif any(r[0] in burst for r in reqs):
                    matched = []
                    attribution = "ambiguous"
                    problems.append("attribution-ambiguous(burst shares route without request correlation or verified boundary; "
                                    + REQUEST_CORRELATION_GAP + ")")
                elif not matched_all:
                    matched = []
                elif len(matched_all) != len(reqs):
                    matched = []
                    problems.append(f"attribution-ambiguous(recordings {len(matched_all)}, requests {len(reqs)})")
                else:
                    times = [recording_time(d) for d in matched_all]
                    if any(t is None for t in times):
                        matched = []
                        problems.append("attribution-ambiguous(recording time unknown)")
                    else:
                        order = sorted(range(len(matched_all)), key=lambda i: (times[i], i))
                        matched = [matched_all[order[i]] for i in mine]
            attributed_total += len(matched)
            symbols.update(ev["symbol"] for d in matched for ev in d.get("events", [])
                           if str(ev.get("kind", "")).endswith("frame_enter")
                           and isinstance(ev.get("symbol"), str) and ev["symbol"])
            readable = [d for d in matched if not detail_read_incomplete(d)]
            with_status = [d for d in readable if outcome_matches(d, e)]
            need = e.get("minCount", 1)
            if problems:
                pass
            elif not matched:
                problems.append("no-recording-for-route")
            else:
                seen = sorted({str(recording_http_status(d) or (d.get("outcome") or {}).get("kind")) for d in readable})
                expected = e.get("outcome", e.get("status"))
                if "statuses" in e and Counter(recording_http_status(d) for d in readable) != Counter(e["statuses"]):
                    observed = sorted((recording_http_status(d) for d in readable), key=str)
                    problems.append(f"http-outcome-multiset-mismatch(expected {e['statuses']}, saw {observed})")
                elif not with_status:
                    problems.append(f"http-outcome-mismatch(expected {expected}, saw {','.join(seen)})")
                elif (boundary is not None or serial_boundary is not None) and len(with_status) != len(matched):
                    problems.append(f"http-outcome-count-mismatch(expected {len(matched)}, observed {len(with_status)})")
                elif len(with_status) < need:
                    problems.append(f"count-below-minimum(need {need}, have {len(with_status)})")
            if len(readable) != len(matched):
                problems.append("recording-detail-incomplete")
            if (boundary is not None or serial_boundary is not None) and any(d.get("completion") == "partial" for d in matched):
                problems.append("partial-recording")
            if any(d.get("incompleteEvidence") for d in matched):
                problems.append("recording-evidence-incomplete")
            unobserved = [d for d in with_status if (d.get("outcome") or {}).get("kind") not in OBSERVED_OUTCOME_KINDS]
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
            if any(p.startswith("attribution-ambiguous") for p in problems):
                attribution = "ambiguous"
            item = {"method": e["method"], "route": e["route"], "expectedStatus": e.get("status"),
                    "expectedStatuses": e.get("statuses"), "expectedOutcome": e.get("outcome"), "attribution": attribution,
                    "recordingsMatchingRoute": len(matched), "recordingsWithStatus": len(with_status),
                    "layers": layer_report, "recordingsWithSource": len(src), "problems": problems,
                    "passed": not problems}
            items.append(item)
        verdicts[sid] = {"passed": not is_burst and all(i["passed"] for i in items), "expectations": items,
                         "attribution": "ambiguous" if is_burst or any(i["attribution"] == "ambiguous" for i in items)
                         else "verified-boundary" if boundary is not None or serial_boundary is not None else "order" if sent is not None else "campaign-wide",
                         "recordingsAttributed": attributed_total,
                         "frameSymbols": inventory.get(sid, []) if inventory is not None else sorted(symbols)}
    return verdicts


def problem_classes(verdicts: dict[str, Any], groups: list[dict] | None = None) -> dict[str, int]:
    items = [item for v in verdicts.values() for item in v["expectations"]]
    return dict(Counter(p.split("(")[0] for item in [*items, *(groups or [])] for p in item["problems"]))


# ------------------------------------------------------------ canaries -------
CANARY_LOCATIONS = {
    "authorization-header": "Authorization header",
    "cookie-header": "Cookie header",
    "query-token": "unread query parameter xt_token; also lastName during the standard flows probe",
    "json-body-password": "request body field password",
    "env-var": "application environment variable XTRACE_CANARY_ENV",
    "focused-business-secret": "focused owner search business parameter lastName (content redaction control)",
}


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


PACE_SECONDS = 0.4  # disclosed accommodation for the agent's bounded queue; never a completion wait


def send_canary_requests(base: str, canaries: dict[str, str], paths: list[tuple[str, str]], pace: float = 0.0) -> list[dict]:
    """Extra non-scenario requests carrying a JSON body password; the responses are not judged."""
    import xcamp
    out = []
    for method, path in paths:
        if pace:
            time.sleep(pace)
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
    notes: dict[str, Any] = {"accommodations": {
        "pace_seconds": PACE_SECONDS, "drain_seconds": 0,
        "reason": "serial requests paced because the agent admits at most 8 unwritten recordings; burst remains unpaced",
        "attribution": "serial scenarios run in pinned order; burst starts only after every serial request has a complete recording",
        "correlationGap": REQUEST_CORRELATION_GAP,
    }}
    init = subprocess.run([xtrace, "init", "--project-dir", str(project_dir), "--display-name", "campaign"],
                          env=env, capture_output=True, text=True, timeout=120)
    notes["init"] = {"exitCode": init.returncode}
    if init.returncode != 0:
        raise RuntimeError(f"xtrace init failed with exit {init.returncode}")
    before_ids = list_recording_ids(xtrace, project_dir, env)
    if canaries:
        notes["canaryLocations"] = dict(CANARY_LOCATIONS)
        xcamp.REQUEST_HOOK = canary_hook(canaries)
        os.environ["XTRACE_CANARY_ENV"] = canaries["env-var"]
    os.environ["XTRACE_DATA_HOME"] = str(data_home)
    run_id = out_dir.name.replace("instrumented-", "i") + str(int(time.time()) % 100000)
    stack = make_stack(run_id)
    results: list[dict[str, Any]] = []
    sent_log: list[tuple[str | None, str, str]] = []
    xcamp.SENT_LOG = []
    xcamp.REQUEST_PACE_S = PACE_SECONDS
    boundary = None
    serial_boundary = None
    live_viewer = None
    started = time.time()
    boot_ms = None
    burst = frozenset(sc.id for sc in scenarios if sc.kind == "concurrency")
    try:
        t0 = time.perf_counter()
        stack.up()
        boot_ms = round((time.perf_counter() - t0) * 1000)
        ordered = sorted(scenarios, key=lambda sc: sc.kind == "concurrency")
        if burst:
            live_viewer, ready = start_viewer(xtrace, project_dir, env, out_dir / "boundary-viewer.log")
            live_client = ViewerClient(ready["origin"])
            live_client.exchange(bootstrap_token(ready["url"]))
            initial = collect_api(live_client, out_dir / "boundary-before")
            if not initial["ok"] or initial.get("listReadGap"):
                raise RuntimeError("cannot snapshot recordings before scenarios: "
                                   + (initial.get("listReadGap") or initial["reason"]))
            # One existing 60-second HTTP/read budget covers both phases and their accounting.
            burst_deadline = time.monotonic() + 60.0
            if ordered[0].id in burst:
                serial_boundary = burst_accounting(initial["details"], [], expectations, initial["details"])
            burst_before = initial["details"]
        for index, sc in enumerate(ordered):
            mark = len(xcamp.SENT_LOG)
            res = xcamp.run_scenario(sc, stack, stack.base, norm_extra)
            sent_log.extend((res["id"], m, pth) for m, pth in xcamp.SENT_LOG[mark:])
            results.append(res)
            print(f"  [{'PASS' if res['passed'] else 'FAIL'}] {sc.id} {res['semanticEffectFingerprint'][:16]} {res['elapsedMs']}ms", flush=True)
            if burst and sc.id not in burst and index + 1 < len(ordered) and ordered[index + 1].id in burst:
                serial_boundary = wait_burst_boundary(live_client, out_dir / "serial-boundary-api", sent_log, expectations,
                                                      initial["details"], burst_deadline, require_complete=True)
                notes["serialBoundary"] = serial_boundary
                if not serial_boundary["verified"]:
                    break
                # Serial verification forbids capacity drops, so its counters equal the initial snapshot.
                # Only IDs are needed to exclude all traffic observed before the burst.
                burst_before = {**initial["details"], **{rid: {} for rid in serial_boundary["snapshotIds"]
                                                       if rid not in initial["details"]}}
            if sc.id in burst and index + 1 == len(ordered):
                boundary = wait_burst_boundary(live_client, out_dir / "boundary-api",
                                               [r for r in sent_log if r[0] in burst], expectations,
                                               burst_before, burst_deadline)
                notes["burstBoundary"] = boundary
                if not boundary["verified"]:
                    break
        if canaries and (not burst or boundary and boundary["verified"]):
            notes["canaryRequests"] = send_canary_requests(stack.base, canaries, extra_canary_paths, pace=PACE_SECONDS)
            sent_log.extend((None, m, pth) for m, pth in extra_canary_paths)  # non-scenario traffic, still recorded by the product
    finally:
        if live_viewer is not None:
            stop_process_group(live_viewer)
        stack.down()  # SIGTERM to the launcher we started; `xtrace run` forwards it and drains the daemon
        try:  # after the stop, so the launcher's own closing diagnostics are in the log
            (out_dir / "application.log").write_text(stack.logs())
        except Exception:
            pass
        xcamp.REQUEST_HOOK = None
        xcamp.SENT_LOG = None
        xcamp.REQUEST_PACE_S = 0.0
    notes["launcherExitCode"] = getattr(stack, "launcher_exit", None)

    # product lifecycle commands that exist in the CLI surface: exit code 9 means "not implemented yet"
    stop = subprocess.run([xtrace, "stop", "--project-dir", str(project_dir)], env=env, capture_output=True, text=True, timeout=60)
    notes["stopCommand"] = {"exitCode": stop.returncode, "notImplemented": stop.returncode == 9}

    api: dict[str, Any] = {"ok": False, "reason": "viewer not started", "recordings": [], "details": {}}
    verdicts: dict[str, Any] = {}
    burst_evidence_ids: tuple[set[str], set[str]] = (set(), set())
    viewer = None
    try:
        viewer, ready = start_viewer(xtrace, project_dir, env, out_dir / "viewer.log")
        client = ViewerClient(ready["origin"])
        token = bootstrap_token(ready["url"])
        if not token:
            raise RuntimeError("no bootstrap token in viewer url")
        client.exchange(token)
        api = collect_api(client, out_dir / "api")
        api["recordings"] = [r for r in api["recordings"] if r["recordingId"] not in before_ids]
        api["details"] = {rid: d for rid, d in api["details"].items() if rid not in before_ids}
    except Exception as exc:
        api = {"ok": False, "reason": f"{type(exc).__name__}: {str(exc)[:200]}", "recordings": [], "details": {}}
    finally:
        if viewer is not None:
            stop_process_group(viewer)
    groups = burst_route_evidence(api["details"], expectations, burst, boundary, serial_boundary, burst_evidence_ids)
    if api["ok"]:
        verdicts = analyze(api["details"], expectations, sent_log, burst, boundary, serial_boundary)

    baseline_fp: dict[str, str] = {}
    if baseline_receipt and baseline_receipt.exists():
        baseline_fp = {s["id"]: s["semanticEffectFingerprint"] for s in json.loads(baseline_receipt.read_text())["scenarios"]}
    scen_out = []
    for r in results:
        v = verdicts.get(r["id"])
        scen_out.append({
            "id": r["id"], "scenarioChecksPassed": r["passed"], "semanticEffectFingerprint": r["semanticEffectFingerprint"],
            "baselineFingerprint": baseline_fp.get(r["id"]),
            "frameSymbols": v["frameSymbols"] if v else [],
            "fingerprintEqualsBaseline": baseline_fp.get(r["id"]) == r["semanticEffectFingerprint"] if baseline_fp else None,
            "recordingVerdict": v, "requests": [{"label": q["label"], "status": q["response"]["status"], "elapsedMs": q["elapsedMs"]}
                                                for q in r["requests"]],
            "elapsedMs": r["elapsedMs"]})
    completed_ids = {r["id"] for r in results}
    for sc in scenarios:
        if sc.id not in completed_ids:
            scen_out.append({"id": sc.id, "scenarioChecksPassed": False, "requests": [],
                             "frameSymbols": [],
                             "recordingVerdict": verdicts.get(sc.id), "elapsedMs": 0,
                             "notRunReason": "serial boundary was not verified"})
    workloads_passed = (len(results) == len(scenarios) and bool(results)
                        and all(r["passed"] for r in results))
    boundaries_verified = (not any(sc.kind == "concurrency" for sc in scenarios)
                           or bool(serial_boundary and serial_boundary["verified"]
                                   and boundary and boundary["verified"]))
    classes = problem_classes(verdicts, groups)
    if boundary is not None:
        # These diagnostics describe the whole burst boundary, including session-wide capacity drops.
        if boundary["capacityDrops"] or boundary["partialRecordingIds"]:
            classes["burst-drops"] = 1
        if not boundary["verified"]:
            classes["burst-boundary-not-verified"] = 1
    scenario_items = [e for sid, v in verdicts.items() if sid not in burst for e in v["expectations"]]
    incomplete_details = sum(detail_read_incomplete(api["details"].get(r["recordingId"])) for r in api["recordings"])
    receipt = {
        "schemaVersion": 1, "kind": "instrumented_campaign_non_release", "project": project, "releaseAcceptance": False,
        "instrumented": True, "signed": False, "pin": pin, "syntheticDataOnly": True, "configurationAdaptations": adaptations,
        "harnessSha256": {p.name: xcamp.sha256_file(p) for p in harness_files}, "bootMs": boot_ms,
        "durationSeconds": round(time.time() - started, 1), "notes": notes,
        "api": {"ok": api["ok"], "reason": api["reason"], "recordings": len(api["recordings"]),
                "listReadGap": api.get("listReadGap"),
                "incompleteDetails": incomplete_details},
        "attribution": "serial routes require exact counts before the verified boundary. "
                       "The burst boundary accounts for later recordings as a group. Individual burst correlation is missing.",
        "requestsSent": len(sent_log),
        "problemClasses": classes, "scenarios": scen_out, "burstRouteGroups": groups,
        "recordingsWithSource": len(burst_evidence_ids[1]) + sum(e["recordingsWithSource"] for e in scenario_items),
        "recordingsWithStatus": len(burst_evidence_ids[0]) + sum(e["recordingsWithStatus"] for e in scenario_items),
        # A successful read after shutdown cannot repair a failed live boundary or
        # turn an unreached workload into a successful interleaved overhead run.
        # The result describes collection and workload. Recording verdicts judge isolation.
        "result": "recorded" if api["ok"] and not api.get("listReadGap") and workloads_passed and boundaries_verified else "failed",
    }
    (out_dir / "receipt.json").write_text(json.dumps(receipt, indent=1, sort_keys=True))
    return receipt
