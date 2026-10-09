"""Shared, stdlib-only runner for the X-trace v0.01 external campaigns.

Everything here is PREPARATION tooling: it builds upstream projects at a
pinned SHA inside ephemeral Docker containers, starts app + database, runs
scenarios against the UNINSTRUMENTED application and records a semantic effect
fingerprint per scenario. It never patches upstream sources.

Naming rule: every container, network and volume created here is prefixed
`xtrace-camp-`. Nothing else is ever stopped, removed or pruned.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

PREFIX = "xtrace-camp-"
PLATFORM = os.environ.get("XCAMP_PLATFORM", "linux/arm64")  # CI x86_64 runners set linux/amd64
POSTGRES_IMAGE = "postgres:18.3"
POSTGRES_DIGEST = "sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------- hashing ----
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical(value))


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------ normalization ---
_NORMALIZERS = [
    (re.compile(r";jsessionid=[0-9A-Za-z._-]+", re.I), ""),
    (re.compile(r"https?://127\.0\.0\.1:\d+"), "http://<HOST>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "<JWT>"),
    (re.compile(r"(?i)(\"?(?:timestamp|createdDate|lastModifiedDate|expires_?at|iat|exp|requestId|traceId)\"?\s*[:=]\s*)\"?[^,}\s\"<]+\"?"), r"\1<VOL>"),
    (re.compile(r"(?i)(name=\"_csrf\" value=\")[^\"]+"), r"\1<CSRF>"),
]


def normalize_text(text: str, extra: list[tuple[str, str]] | None = None) -> str:
    for rx, repl in _NORMALIZERS:
        text = rx.sub(repl, text)
    for pattern, repl in extra or []:
        text = re.sub(pattern, repl, text)
    return text


def _redact_body(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    text = re.sub(r'(?i)("?(?:password|passwd|secret|token)"?\s*[:=]\s*)("[^"]*"|[^&,}\s]*)', r"\1<redacted>", text)
    return text


def load_campaign(harness_file: str) -> tuple[dict[str, Any], pathlib.Path, pathlib.Path]:
    """Returns (campaign.json, private project root, upstream checkout)."""
    here = pathlib.Path(harness_file).resolve().parent
    camp = json.loads((here.parent / "campaign.json").read_text())
    root = os.environ.get("XTRACE_CAMPAIGN_ROOT")
    if not root:
        raise SystemExit("set XTRACE_CAMPAIGN_ROOT to the private campaign cache root (contains java/<project>/src)")
    proj = pathlib.Path(root) / "java" / camp["project"]
    return camp, proj, proj / "src"


def loc_path(location: str) -> str:
    """Path+query of a Location header (drops scheme/host and ;jsessionid)."""
    parts = urllib.parse.urlsplit(location)
    path = re.sub(r";jsessionid=[^?/]*", "", parts.path, flags=re.I)
    return path + (f"?{parts.query}" if parts.query else "")


# --------------------------------------------------------------- docker ------
def _docker_env() -> dict[str, str]:
    env = dict(os.environ)
    if "DOCKER_HOST" not in env:
        out = subprocess.run(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                             capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip():
            env["DOCKER_HOST"] = out.stdout.strip()
    return env


def docker(*args: str, check: bool = True, timeout: int | None = 600, input_text: str | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, env=_docker_env(),
                          timeout=timeout, input=input_text)
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} failed rc={proc.returncode}: {proc.stderr.strip()[:800]}")
    return proc


def _guard(name: str) -> None:
    if not name.startswith(PREFIX):
        raise RuntimeError(f"refusing to touch non-campaign docker object {name!r}")


def rm_container(name: str) -> None:
    _guard(name)
    docker("rm", "-f", "-v", name, check=False)


def rm_network(name: str) -> None:
    _guard(name)
    docker("network", "rm", name, check=False)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def image_id(ref: str) -> str:
    return docker("image", "inspect", "--format", "{{.Id}}", ref).stdout.strip()


def image_digest(ref: str) -> str:
    out = docker("image", "inspect", "--format", "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}", ref).stdout.strip()
    return out


# ----------------------------------------------------------------- http ------
class _NoRedirect(http.client.HTTPConnection):
    pass


def http_request(base: str, method: str, path: str, *, headers: dict[str, str] | None = None,
                 body: bytes | None = None, timeout: float = 60.0) -> dict[str, Any]:
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    hdrs = {"Accept": "*/*", "User-Agent": "xtrace-campaign/1", "Connection": "close", **(headers or {})}
    start = time.perf_counter()
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        elapsed = time.perf_counter() - start
        return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.getheaders()},
                "body": data, "elapsedMs": round(elapsed * 1000, 2)}
    finally:
        conn.close()


# ------------------------------------------------------------ scenarios ------
# Optional (method, path, headers, body) -> (path, headers, body) applied just before sending. Default: none.
REQUEST_HOOK: Callable[[str, str, dict, Any], tuple] | None = None


@dataclass
class Ctx:
    """Per-scenario recorder handed to scenario functions."""
    stack: "Stack"
    base: str
    norm_extra: list[tuple[str, str]] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    db: dict[str, Any] = field(default_factory=dict)
    volatile_headers: tuple[str, ...] = ("date", "set-cookie", "etag", "last-modified", "expires", "x-request-id")
    keep_headers: tuple[str, ...] = ("content-type", "location", "www-authenticate", "allow")
    # Lock-free list append is safe in CPython for concurrent scenarios.

    def http(self, method: str, path: str, *, headers: dict[str, str] | None = None,
             body: bytes | str | dict | None = None, form: dict[str, str] | None = None,
             json_body: Any = None, label: str | None = None, norm: list[tuple[str, str]] | None = None) -> dict[str, Any]:
        hdrs = dict(headers or {})
        raw: bytes | None
        if form is not None:
            raw = urllib.parse.urlencode(form).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif json_body is not None:
            raw = json.dumps(json_body, sort_keys=True).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            raw = body.encode()
        else:
            raw = body  # type: ignore[assignment]
        send_path, send_hdrs, send_raw = (path, hdrs, raw)
        if REQUEST_HOOK is not None:  # instrumented runs inject privacy canaries here; labels/hashes keep the original request
            send_path, send_hdrs, send_raw = REQUEST_HOOK(method, path, hdrs, raw)
        res = http_request(self.base, method, send_path, headers=send_hdrs, body=send_raw)
        text = res["body"].decode("utf-8", "replace")
        ntext = normalize_text(text, (norm or []) + self.norm_extra)
        redacted_headers = {k: v for k, v in hdrs.items() if k.lower() not in ("authorization", "cookie")}
        rec = {
            "label": label or f"{method} {path}",
            "request": {"method": method, "path": normalize_text(path, self.norm_extra),
                        "headers": {k: ("<redacted>" if k.lower() == "authorization" else v) for k, v in sorted(redacted_headers.items())},
                        "bodySha256": sha256_bytes(raw) if raw else None,
                        "body": _redact_body(raw) if raw and len(raw) < 4096 else None,
                        "bodyBytes": len(raw) if raw else 0},
            "response": {"status": res["status"],
                         "headers": {k: normalize_text(v, self.norm_extra) for k, v in sorted(res["headers"].items()) if k in self.keep_headers},
                         "bodyBytes": len(res["body"]),
                         "rawBodySha256": sha256_bytes(res["body"]),
                         "normalizedBodySha256": sha256_bytes(ntext.encode())},
            "elapsedMs": res["elapsedMs"],
        }
        self.requests.append(rec)
        dump = os.environ.get("XCAMP_DUMP_BODIES")  # debugging aid for normalization work (private dir)
        if dump:
            d = pathlib.Path(dump)
            d.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", rec["label"])[:80]
            (d / f"{len(self.requests):04d}-{safe}.txt").write_text(ntext)
        res["text"] = text
        res["rec"] = rec
        return res

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "passed": bool(ok), "detail": detail if not ok else ""})

    def sql(self, name: str, query: str) -> list[list[str]]:
        rows = self.stack.psql(query)
        self.db[name] = rows
        return rows


@dataclass
class Scenario:
    id: str
    title: str
    kind: str          # business | validation | error | auth | db-write-read | concurrency | outbound
    fn: Callable[[Ctx], None]


def run_scenario(sc: Scenario, stack: "Stack", base: str, norm_extra: list[tuple[str, str]]) -> dict[str, Any]:
    ctx = Ctx(stack=stack, base=base, norm_extra=list(norm_extra))
    t0 = time.perf_counter()
    err = None
    try:
        sc.fn(ctx)
    except Exception as exc:  # recorded, scenario fails
        err = f"{type(exc).__name__}: {exc}"[:400]
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    # Order-independent view of requests for concurrency scenarios: sort by label.
    reqs = ctx.requests if sc.kind != "concurrency" else sorted(ctx.requests, key=lambda r: r["label"])
    semantic = {
        "scenario": sc.id,
        "kind": sc.kind,
        "responses": [{"label": r["label"], "status": r["response"]["status"],
                       "headers": r["response"]["headers"],
                       "normalizedBodySha256": r["response"]["normalizedBodySha256"]} for r in reqs],
        "checks": [{"name": c["name"], "passed": c["passed"]} for c in sorted(ctx.checks, key=lambda c: c["name"])],
        "dbEffect": ctx.db,
    }
    passed = err is None and all(c["passed"] for c in ctx.checks) and bool(ctx.checks)
    return {
        "id": sc.id, "title": sc.title, "kind": sc.kind, "passed": passed, "error": err,
        "requests": reqs, "checks": ctx.checks,
        "dbEffectSha256": sha256_json(ctx.db),
        "semanticEffectFingerprint": sha256_json(semantic),
        "elapsedMs": elapsed,
    }


# ---------------------------------------------------------------- stack ------
@dataclass
class Stack:
    """App container (+ optional Postgres container) on a private network."""
    project: str
    jdk_image: str
    jar: pathlib.Path
    app_args: list[str]
    app_port: int
    ready_path: str
    ready_ok: Callable[[int, str], bool] = lambda status, body: status == 200
    java_opts: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    db_name: str | None = None
    effect_db: str | None = None   # database used for effect queries (default db_name)
    db_user: str = "campaign"
    db_password: str = "campaign-synthetic"
    extra_db_init: list[str] = field(default_factory=list)
    ready_timeout: float = 420.0
    app_mem: str = "2g"
    run_id: str = ""
    host_port: int = 0

    def __post_init__(self) -> None:
        self.run_id = self.run_id or f"{int(time.time())}"
        self.net = f"{PREFIX}{self.project}-net-{self.run_id}"
        self.db = f"{PREFIX}{self.project}-db-{self.run_id}"
        self.app = f"{PREFIX}{self.project}-app-{self.run_id}"

    # ---- lifecycle
    mode: str = field(default_factory=lambda: os.environ.get("XCAMP_APP_MODE", "docker"))  # docker | host
    _proc: Any = None
    _logfile: pathlib.Path | None = None
    db_host_port: int = 0

    def _subst(self, value: str) -> str:
        host = self.mode == "host"
        return (value.replace("{DBHOST}", "127.0.0.1" if host else "db")
                     .replace("{DBPORT}", str(self.db_host_port) if host else "5432")
                     .replace("{BINDADDR}", "127.0.0.1" if host else "0.0.0.0")
                     .replace("{APPPORT}", str(self.host_port) if host else str(self.app_port)))

    def up(self) -> None:
        self.down()
        docker("network", "create", self.net)
        self.host_port = free_port()
        if self.db_name:
            publish = []
            if self.mode == "host":
                self.db_host_port = free_port()
                publish = ["-p", f"127.0.0.1:{self.db_host_port}:5432"]
            docker("run", "-d", "--name", self.db, "--platform", PLATFORM, "--network", self.net, "--network-alias", "db",
                   *publish,
                   "-e", f"POSTGRES_USER={self.db_user}", "-e", f"POSTGRES_PASSWORD={self.db_password}",
                   "-e", f"POSTGRES_DB={self.db_name}", "--tmpfs", "/var/lib/postgresql:rw,size=1g",
                   POSTGRES_IMAGE, "-c", "fsync=off", "-c", "max_connections=200", "-c", "timezone=UTC",
                   "-c", "log_timezone=UTC")
            self._wait_db()
            for sql in self.extra_db_init:
                self.psql(sql, db="postgres")
        env = {k: self._subst(v) for k, v in self.env.items()}
        args = [self._subst(a) for a in self.app_args]
        if self.mode == "host":
            # Host JVM (e.g. the packaged `xtrace run -- java ...` launcher on a supported platform).
            import shlex
            java = os.environ.get("XCAMP_JAVA")
            if not java:
                raise RuntimeError("XCAMP_APP_MODE=host requires XCAMP_JAVA (path to the JDK `java` binary)")
            prefix = shlex.split(os.environ.get("XCAMP_LAUNCH_PREFIX", ""))
            self._logfile = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / f"{PREFIX}{self.project}-{self.run_id}.log"
            child_env = {**os.environ, **env, "TZ": "UTC"}
            for k in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
                child_env.pop(k, None)
            with open(self._logfile, "wb") as fh:
                self._proc = subprocess.Popen(
                    [*prefix, java, "-Duser.timezone=UTC", "-Dfile.encoding=UTF-8", *self.java_opts, "-jar", str(self.jar), *args],
                    stdout=fh, stderr=subprocess.STDOUT, env=child_env, start_new_session=True)
        else:
            cmd = ["run", "-d", "--name", self.app, "--platform", PLATFORM, "--network", self.net, "--memory", self.app_mem,
                   "-p", f"127.0.0.1:{self.host_port}:{self.app_port}",
                   "-v", f"{self.jar.parent}:/app:ro", "-w", "/app", "-e", "TZ=UTC"]
            for k, v in env.items():
                cmd += ["-e", f"{k}={v}"]
            cmd += [self.jdk_image, "java", "-Duser.timezone=UTC", "-Dfile.encoding=UTF-8", *self.java_opts,
                    "-jar", f"/app/{self.jar.name}", *args]
            docker(*cmd)
        self._wait_ready()

    def down(self) -> None:
        if self._proc is not None:
            import signal
            if self._proc.poll() is None:
                try:
                    os.killpg(self._proc.pid, signal.SIGTERM)  # only the process group we started
                    self._proc.wait(timeout=30)
                except Exception:
                    try:
                        os.killpg(self._proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
            self._proc = None
        rm_container(self.app)
        rm_container(self.db)
        rm_network(self.net)

    def logs(self) -> str:
        if self.mode == "host":
            return self._logfile.read_text(errors="replace") if self._logfile and self._logfile.exists() else ""
        p = docker("logs", self.app, check=False)
        return p.stdout + p.stderr

    def _wait_db(self) -> None:
        deadline = time.time() + 90
        while time.time() < deadline:
            p = docker("exec", self.db, "pg_isready", "-U", self.db_user, "-d", self.db_name or "postgres", check=False)
            if p.returncode == 0:
                # pg_isready can pass during init restart; require a real query twice
                q = docker("exec", self.db, "psql", "-U", self.db_user, "-d", self.db_name or "postgres", "-Atc", "select 1", check=False)
                if q.stdout.strip() == "1":
                    time.sleep(1.5)
                    q = docker("exec", self.db, "psql", "-U", self.db_user, "-d", self.db_name or "postgres", "-Atc", "select 1", check=False)
                    if q.stdout.strip() == "1":
                        return
            time.sleep(1)
        raise RuntimeError("database did not become ready")

    def _wait_ready(self) -> None:
        deadline = time.time() + self.ready_timeout
        base = f"http://127.0.0.1:{self.host_port}"
        last = ""
        while time.time() < deadline:
            if self.mode == "host":
                st = "true" if self._proc is not None and self._proc.poll() is None else "false"
            else:
                st = docker("inspect", "--format", "{{.State.Running}}", self.app, check=False).stdout.strip()
            if st != "true":
                raise RuntimeError("application container exited during startup:\n" + self.logs()[-3000:])
            try:
                r = http_request(base, "GET", self.ready_path, timeout=5)
                if self.ready_ok(r["status"], r["body"].decode("utf-8", "replace")):
                    return
                last = f"status {r['status']}"
            except Exception as exc:
                last = str(exc)[:100]
            time.sleep(1)
        raise RuntimeError(f"application not ready within {self.ready_timeout}s ({last})")

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.host_port}"

    # ---- database access (read-only effect queries use the campaign role)
    def psql(self, query: str, db: str | None = None) -> list[list[str]]:
        if not self.db_name:
            return []
        p = docker("exec", self.db, "psql", "-U", self.db_user, "-d", db or self.effect_db or self.db_name, "-At", "-F", "\x1f",
                   "-v", "ON_ERROR_STOP=1", "-c", query, check=False)
        if p.returncode != 0:
            raise RuntimeError(f"psql failed: {p.stderr.strip()[:300]}")
        return [line.split("\x1f") for line in p.stdout.splitlines() if line != ""]


# ---------------------------------------------------------------- build ------
def git_pin_check(src: pathlib.Path, sha: str) -> dict[str, Any]:
    head = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(src), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout.strip()
    if head != sha:
        raise RuntimeError(f"checkout HEAD {head} != pin {sha}")
    if dirty:
        raise RuntimeError("tracked files modified in upstream checkout; business-logic patches are forbidden")
    return {"head": head, "trackedClean": True}


def docker_build(project: str, src: pathlib.Path, image: str, cmd: str, volumes: dict[str, str],
                 log: pathlib.Path, mem: str = "6g", timeout: int = 5400) -> int:
    name = f"{PREFIX}build-{project}"
    rm_container(name)
    args = ["run", "--rm", "--name", name, "--platform", PLATFORM, "--memory", mem, "-v", f"{src}:/work", "-w", "/work"]
    for vol, mount in volumes.items():
        args += ["-v", f"{vol}:{mount}"]
    args += [image, "sh", "-c", cmd]
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "wb") as fh:
        p = subprocess.run(["docker", *args], stdout=fh, stderr=subprocess.STDOUT, env=_docker_env(), timeout=timeout)
    return p.returncode


# ------------------------------------------------------------ baseline -------
def run_baseline(*, project: str, pin: dict[str, Any], make_stack: Callable[[str], Stack],
                 scenarios: list[Scenario], out_dir: pathlib.Path, norm_extra: list[tuple[str, str]],
                 adaptations: list[str], harness_files: list[pathlib.Path]) -> dict[str, Any]:
    """One reset-to-finish uninstrumented run. out_dir is a fresh baseline-<n> dir."""
    out_dir.mkdir(parents=True, exist_ok=False)
    run_id = out_dir.name.replace("baseline-", "b") + str(int(time.time()) % 100000)
    stack = make_stack(run_id)
    results: list[dict[str, Any]] = []
    started = time.time()
    boot_ms = None
    try:
        t0 = time.perf_counter()
        stack.up()
        boot_ms = round((time.perf_counter() - t0) * 1000)
        for sc in scenarios:
            res = run_scenario(sc, stack, stack.base, norm_extra)
            results.append(res)
            print(f"  [{ 'PASS' if res['passed'] else 'FAIL' }] {sc.id} {res['semanticEffectFingerprint'][:16]} {res['elapsedMs']}ms", flush=True)
        (out_dir / "application.log").write_text(stack.logs())
    finally:
        try:
            (out_dir / "application.log").write_text(stack.logs())
        except Exception:
            pass
        stack.down()
    receipt = {
        "schemaVersion": 1,
        "kind": "uninstrumented_baseline_campaign_preparation",
        "project": project,
        "releaseAcceptance": False,
        "instrumented": False,
        "appMode": stack.mode,
        "pin": pin,
        "syntheticDataOnly": True,
        "configurationAdaptations": adaptations,
        "harnessSha256": {p.name: sha256_file(p) for p in harness_files},
        "bootMs": boot_ms,
        "durationSeconds": round(time.time() - started, 1),
        "scenarios": results,
        "result": "passed_baseline_only" if results and all(r["passed"] for r in results) else "failed",
    }
    (out_dir / "receipt.json").write_text(json.dumps(receipt, indent=1, sort_keys=True))
    return receipt


def next_baseline_dir(root: pathlib.Path) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    n = 1
    while (root / f"baseline-{n}").exists():
        n += 1
    return root / f"baseline-{n}"


def compare(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [s["id"] for s in receipts[0]["scenarios"]]
    rows = []
    stable = True
    for sid in ids:
        fps = []
        for r in receipts:
            m = [s for s in r["scenarios"] if s["id"] == sid]
            fps.append(m[0]["semanticEffectFingerprint"] if m else None)
        same = len(set(fps)) == 1 and fps[0] is not None
        stable &= same
        rows.append({"id": sid, "fingerprint": fps[0] if same else None, "stable": same, "all": fps})
    return {"runs": len(receipts), "stable": stable, "scenarios": rows}


def main_cli(project: str, build: Callable[[], int], make_receipt_run: Callable[[pathlib.Path], dict[str, Any]],
             private_root: pathlib.Path) -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "build":
        return build()
    if cmd == "baseline":
        out = next_baseline_dir(private_root)
        print(f"baseline run -> {out}", flush=True)
        r = make_receipt_run(out)
        return 0 if r["result"] == "passed_baseline_only" else 1
    if cmd == "compare":
        receipts = [json.loads((d / "receipt.json").read_text()) for d in sorted(private_root.glob("baseline-*"))]
        rep = compare(receipts)
        print(json.dumps(rep, indent=1))
        return 0 if rep["stable"] else 1
    print(f"usage: {project} harness: build | baseline | compare")
    return 2
