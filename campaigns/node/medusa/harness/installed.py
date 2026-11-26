"""Hosted coordinator for two real Medusa commerce legs and installed readback."""
from contextlib import ExitStack, contextmanager
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import traceback
from urllib.parse import urlencode

from installed_capture_diagnostic import project_capture_diagnostic
from installed_evidence import EvidenceError, capture, detail, keys, pages, require, workload
from installed_process import contain_children, reap_exited_group_children, verify_children_gone


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO))
from campaigns.lib import xinstr  # noqa: E402
from tools.release.private_roots import admit_directory, atomic_write_private  # noqa: E402


CAMPAIGN = json.loads((HERE.parent / "campaign.json").read_text())
EXPECTED = [case["id"] for case in CAMPAIGN["scenarios"]]
POSTGRES = "postgres@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db"
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
PORT = 9000
MAX_DOC = 16 * 1024 * 1024
PRODUCT = os.environ.get("MEDUSA_PRODUCT_SHA", "")
TREE = os.environ.get("MEDUSA_PRODUCT_TREE", "")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def secret():
    return os.urandom(24).hex()


def private_json(path, data):
    atomic_write_private(path, (json.dumps(data, sort_keys=True) + "\n").encode())


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_DOC)
    return json.loads(path.read_bytes())


def starter_bytes(root):
    """Bind all prepared application and dependency bytes without following links."""
    inventory = hashlib.sha256()

    def visit(directory):
        for name in sorted(directory.iterdir()):
            if directory == root and name.name == ".git":
                continue
            mode = name.lstat().st_mode
            relative = str(name.relative_to(root))
            if stat.S_ISLNK(mode):
                require(name.resolve().is_relative_to(root))
                identity = os.readlink(name)
            elif stat.S_ISDIR(mode):
                identity = None
                visit(name)
            else:
                require(stat.S_ISREG(mode))
                identity = sha(name)
            inventory.update(json.dumps([relative, mode, identity], ensure_ascii=True).encode() + b"\n")

    visit(root)
    return inventory.hexdigest()


def port_vacant(port):
    with socket.socket() as peer:
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            peer.bind(("127.0.0.1", port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return False
            raise
        return True


def listener_owner(pid, port):
    value = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    require(re.fullmatch("[0-9]+", value))
    return {"pid": pid, "start": value, "port": port}


def local_transport(value):
    labels = {"attempted", "ownedResponses", "refusedRedirects", "otherFailures"}
    require(isinstance(value, dict) and set(value) == labels)
    require(all(type(value[key]) is int and 0 <= value[key] <= 100 for key in labels))
    require(value["attempted"] == sum(value[key] for key in labels - {"attempted"}))
    return {key: value[key] for key in sorted(labels)}


class LifecycleProcessExit(RuntimeError):
    def __init__(self, returncode):
        super().__init__("unexpected Medusa process exit")
        self.returncode = returncode


class ProcessStopFailure(EvidenceError):
    REASONS = frozenset({"descendant-exit-unverified", "process-group-present", "forced-cleanup"})

    def __init__(self, reason):
        super().__init__("Medusa process stop incomplete")
        self.reason = reason


HEALTH_FAILURES = {
    71: "listener-not-verified",
    72: "connection-not-verified",
    73: "accepted-socket-not-verified",
    74: "response-not-read",
    75: "redirect-refused",
    76: "health-status-mismatch",
    77: "health-body-mismatch",
}


def lifecycle_failure(phase, exc):
    """Project exceptions into finite facts without reading their messages or arguments."""
    if isinstance(exc, (LifecycleProcessExit, subprocess.CalledProcessError)):
        value = exc.returncode
        if (phase == "owned-health" and isinstance(exc, subprocess.CalledProcessError)
                and type(value) is int and value in HEALTH_FAILURES):
            return {"reason": HEALTH_FAILURES[value]}
        if type(value) is int and -127 <= value <= 255:
            return {"reason": "process-exited", "exitCode": value}
        return {"reason": "process-exited"}
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return {"reason": "deadline"}
    if phase == "stop-process" and isinstance(exc, ProcessStopFailure) and exc.reason in ProcessStopFailure.REASONS:
        return {"reason": exc.reason}
    if isinstance(exc, EvidenceError):
        return {"reason": "condition-failed"}
    if isinstance(exc, OSError):
        return {"reason": "io-or-spawn-failed"}
    if isinstance(exc, KeyboardInterrupt):
        return {"reason": "interrupted"}
    return {"reason": "unclassified"}


class Process:
    """Observe owned process readiness and preserve its streams only in private files."""

    def __init__(self, directory, command, cwd, env, *, descendants=False):
        self.stdout = directory / "server.stdout"
        self.stderr = directory / "server.stderr"
        with self.stdout.open("xb") as out, self.stderr.open("xb") as err:
            self.child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                          stdout=out, stderr=err, start_new_session=True)
        self.descendants = descendants
        self.owned_children = {}
        self.stopped = False
        self.cleaned = False
        self.reaped_group_exits = None
        self.stop_recovery_reasons = None

    def observe_children(self):
        if not self.descendants or self.child.poll() is not None:
            return
        candidates = [self.child.pid]
        visited = set()
        while candidates:
            parent = candidates.pop()
            if parent in visited:
                continue
            require(len(visited) < 128)
            visited.add(parent)
            children = set()
            for task in Path(f"/proc/{parent}/task").glob("*/children"):
                try:
                    children.update(task.read_text().split())
                except FileNotFoundError:
                    continue
            for value in children:
                pid = int(value)
                if pid in self.owned_children and not select.select([self.owned_children[pid]], [], [], 0)[0]:
                    candidates.append(pid)
                    continue
                if pid in self.owned_children:
                    continue
                try:
                    handle = os.pidfd_open(pid)
                except ProcessLookupError:
                    continue
                try:
                    status = Path(f"/proc/{pid}/status").read_text()
                    same_parent = re.search(rf"^PPid:\s+{parent}$", status, re.M)
                    parent_alive = self.child.poll() is None if parent == self.child.pid else (
                        not select.select([self.owned_children[parent]], [], [], 0)[0])
                    if same_parent and parent_alive:
                        self.owned_children[pid] = handle
                        candidates.append(pid)
                        continue
                except FileNotFoundError:
                    pass
                os.close(handle)

    def ready(self, read, seconds, *, include_stderr=False):
        deadline = time.monotonic() + seconds
        with ExitStack() as stack:
            streams = {"stdout": stack.enter_context(self.stdout.open("rb"))}
            if include_stderr:
                streams["stderr"] = stack.enter_context(self.stderr.open("rb"))
            pending = dict.fromkeys(streams, b"")
            while time.monotonic() < deadline:
                code = self.child.poll()
                if code is not None:
                    raise LifecycleProcessExit(code)
                for name, stream in streams.items():
                    buffered = pending[name] + stream.read(65536)
                    require(len(buffered) <= 4 * 1024 * 1024 and stream.tell() <= 4 * 1024 * 1024)
                    complete = buffered.split(b"\n")
                    pending[name] = complete.pop()
                    for line in complete:
                        value = read(line.decode("utf-8", "replace"))
                        if value is not None:
                            self.observe_children()
                            return value, name
                time.sleep(0.05)
        raise TimeoutError("process readiness deadline")

    def stop(self):
        if self.stopped:
            return self.child.returncode
        self.stopped = True
        recovery_reasons = self.stop_recovery_reasons = []
        try:
            try:
                self.observe_children()
            except Exception:
                traceback.print_exc()
                recovery_reasons.append("descendant-inventory-failed")
            grace_deadline = time.monotonic() + 25
            recovery_deadline = grace_deadline + 5
            if self.child.poll() is None:
                self.child.terminate()
            try:
                code = self.child.wait(timeout=max(0, grace_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                recovery_reasons.append("launcher-wait-deadline")
                if self.child.poll() is None:
                    os.killpg(self.child.pid, signal.SIGKILL)
                code = self.child.wait(timeout=max(0, recovery_deadline - time.monotonic()))

            # The launcher can exit before its children report exit. Observe all
            # owned pidfds in the time left on the original grace clock.
            pending = set(self.owned_children.values())
            while pending:
                timeout = max(0, grace_deadline - time.monotonic())
                ready, _, _ = select.select(sorted(pending), [], [], timeout)
                if not ready:
                    break
                pending.difference_update(ready)
            if pending:
                recovery_reasons.append("descendant-exit-not-yet-observed")
                for handle in sorted(pending):
                    try:
                        signal.pidfd_send_signal(handle, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                while pending:
                    timeout = max(0, recovery_deadline - time.monotonic())
                    ready, _, _ = select.select(sorted(pending), [], [], timeout)
                    if not ready:
                        raise ProcessStopFailure("descendant-exit-unverified")
                    pending.difference_update(ready)
            # After the leader exits, its dead children can still occupy the
            # group until this subreaper consumes their wait status.
            self.reaped_group_exits = reap_exited_group_children(self.child.pid)
            try:
                os.killpg(self.child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise ProcessStopFailure("process-group-present")
            self.cleaned = True
            if recovery_reasons:
                raise ProcessStopFailure("forced-cleanup")
            return code
        finally:
            for handle in self.owned_children.values():
                os.close(handle)


class Proof:
    def __init__(self, root, archive, starter):
        self.root, self.archive, self.starter = root, archive, starter
        self.backend = starter / "apps/backend"
        self.node = Path(subprocess.check_output(["node", "-p", "process.execPath"], text=True).strip()).resolve(strict=True)
        self.prefix = root / "installed Medusa probe"
        self.project = root / "capture-project"
        self.cli = self.prefix / "bin/xtrace"
        self.pack = self.prefix / "current/share/xtrace/packs/node/dist"
        self.sequence = 0
        self.env = {
            "PATH": str(self.node.parent) + os.pathsep + "/usr/bin:/bin",
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "XTRACE_DATA_HOME": str(root / "data"),
            "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
            "COREPACK_HOME": str(root / "corepack"),
            "MEDUSA_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1",
            "LANG": "C.UTF-8", "TZ": "UTC",
        }
        self.summary = {
            "schemaVersion": 1, "kind": "installed-medusa-development-120",
            "status": "failed", "releaseAcceptance": False, "sourceSha": PRODUCT, "sourceTree": TREE,
            "starterSha": CAMPAIGN["starter"]["sha"], "lockSha256": CAMPAIGN["starter"]["lockfileSha256"],
            "archiveSha256": None, "installedCliSha256": None, "nodeSha256": None, "nodePackSha256": None,
            "stages": {}, "workload": None, "capture": None, "unmatched": None,
            "localTransport": {"baseline": None, "installed": None},
            "lifecycle": {"baseline": {}, "installed": {}},
            "medusaReadinessLogStream": {"baseline": None, "installed": None},
            "reapedAdoptedGroupExits": {"baseline": None, "installed": None},
            "stopRecoveryReasons": {"baseline": None, "installed": None},
            "nodeCaptureDiagnostic": None,
            "perRequestAttribution": "unverified", "concurrentRecordingAttribution": "unverified",
        }

    def save(self):
        private_json(self.root / "safe/report.json", self.summary)

    @contextmanager
    def stage(self, name):
        self.summary["stages"][name] = "failed"
        self.save()
        try:
            yield
        except BaseException:
            self.save()
            raise
        else:
            self.summary["stages"][name] = "passed"
            self.save()

    @contextmanager
    def phase(self, leg, name):
        phases = self.summary["lifecycle"][leg]
        phases[name] = {"status": "running"}
        self.save()
        try:
            yield
        except BaseException as exc:
            phases[name] = {"status": "failed", **lifecycle_failure(name, exc)}
            self.save()
            raise
        else:
            phases[name] = {"status": "passed"}
            self.save()

    def command(self, args, *, cwd=REPO, env=None, timeout=60, fail=True):
        if args[0] == "docker":
            args = DOCKER + args[1:]
        self.sequence += 1
        stem = self.root / "logs" / str(self.sequence)
        with stem.with_suffix(".stdout").open("xb") as out, stem.with_suffix(".stderr").open("xb") as err:
            with subprocess.Popen(args, cwd=cwd, env=env or self.env, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err, start_new_session=True) as process:
                try:
                    code = process.wait(timeout=timeout)
                except BaseException:
                    # The child is still ours and unreaped at this point. Its command group shares this session.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                    raise
        if fail and code:
            raise subprocess.CalledProcessError(code, args)
        return subprocess.CompletedProcess(args, code), stem.with_suffix(".stdout")

    def text(self, args, **kwargs):
        _, out = self.command(args, **kwargs)
        require(out.stat().st_size <= MAX_DOC)
        return out.read_text()

    def json(self, args, **kwargs):
        _, out = self.command(args, **kwargs)
        return read_json(out)

    def starter_identity(self):
        git = ["git", "-C", str(self.starter)]
        revision = self.text(git + ["rev-parse", "HEAD"]).strip()
        require(revision == CAMPAIGN["starter"]["sha"])
        require(not self.text(git + ["status", "--porcelain", "--untracked-files=no"]))
        require(sha(self.starter / "pnpm-lock.yaml") == CAMPAIGN["starter"]["lockfileSha256"])
        require(sha(self.starter / "LICENSE") == CAMPAIGN["starter"]["licenseSha256"])
        return revision

    def inventory(self, name):
        result = self.root / "private" / (name + ".json")
        config = self.root / "private" / (name + "-config.json")
        private_json(config, {"mode": "package-inventory", "backend": str(self.backend), "out": str(result),
                              "version": CAMPAIGN["upstream"]["stableTag"].removeprefix("v"), "expressVersion": "4.22.2"})
        self.command([str(self.node), str(HERE / "installed-workload.mjs"), str(config)])
        return read_json(result)

    def install(self):
        with self.stage("identity"):
            require(re.fullmatch("[0-9a-f]{40}", PRODUCT) and re.fullmatch("[0-9a-f]{40}", TREE))
            require(self.text(["git", "rev-parse", "HEAD"]).strip() == PRODUCT)
            require(self.text(["git", "rev-parse", "HEAD^{tree}"]).strip() == TREE)
            require(not self.text(["git", "status", "--porcelain", "--untracked-files=all"]))
            require(self.text([str(self.node), "--version"]).strip() == "v" + CAMPAIGN["runtime"]["nodeImageVersion"])
            require(stat.S_ISSOCK(Path("/var/run/docker.sock").stat().st_mode))
            self.command(["docker", "version", "--format", "{{.Server.Version}}"])
            self.summary["nodeSha256"] = sha(self.node)
        with self.stage("package"):
            self.summary["archiveSha256"] = sha(self.archive)
            self.command(["sh", "packaging/install.sh", "verify-dist", str(self.archive.parent)])
            self.command([sys.executable, "-B", "packaging/verify_package.py", str(self.archive),
                          "--repo", str(REPO), "--run-binary"], timeout=180)
            spec = importlib.util.spec_from_file_location("medusa_package_verifier", REPO / "packaging/verify_package.py")
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            unpacked = self.root / "unpacked"
            unpacked.mkdir(mode=0o700)
            package = verifier.resolve_root(self.archive, unpacked)
            manifest = Path("share/xtrace/PACKAGE-MANIFEST.json")
            meta = read_json(package / manifest)
            require(meta["sourceCommit"] == PRODUCT and meta["version"] == "0.0.1" and meta["platform"] == "linux-x86_64")
            require(not self.prefix.exists() and sha(self.archive) == self.summary["archiveSha256"])
            self.command(["sh", str(package / "install.sh"), "--prefix", str(self.prefix),
                          "--data-home", self.env["XTRACE_DATA_HOME"]], timeout=180)
            installed = self.prefix / "current"
            self.command(["sh", str(installed / "install.sh"), "verify", "--prefix", str(self.prefix)], timeout=180)
            require(self.cli.resolve(strict=True) == (installed / "bin/xtrace").resolve(strict=True))
            require(sha(package / manifest) == sha(installed / manifest))
            require(sha(package / "bin/xtrace") == sha(self.cli))
            pack_manifest = Path("share/xtrace/packs/node/dist/manifest.sha256")
            require(sha(package / pack_manifest) == sha(installed / pack_manifest))
            self.summary.update(installedCliSha256=sha(self.cli), nodePackSha256=sha(installed / pack_manifest))
            self.command([str(self.cli), "--version"])
        with self.stage("starter"):
            self.starter_identity()
            self.command(["corepack", "prepare", f"pnpm@{CAMPAIGN['packageManager']['version']}", "--activate"], timeout=300)
            require(self.text(["corepack", "pnpm", "--version"], cwd=self.starter).strip() == CAMPAIGN["packageManager"]["version"])
            self.command(["corepack", "pnpm", "install", "--frozen-lockfile", "--filter", "@dtc/backend...",
                          "--store-dir", str(self.root / "pnpm-store")], cwd=self.starter, timeout=1800)
            self.packages = self.inventory("package-identities")
            self.entry = self.backend / "node_modules/@medusajs/cli/cli.js"
            self.entry_sha = sha(self.entry)
            self.starter_identity()
            self.prepared_sha = starter_bytes(self.starter)
            private_json(self.root / "private/prepared-input.json", {"preparedSha256": self.prepared_sha})
            self.pg_image = self.text(["docker", "image", "inspect", "-f", "{{.Id}}", POSTGRES]).strip()
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", self.pg_image))

    def database(self, db_env, cidfile, db_name, password):
        # The config travels through an owner-only env file. Docker's runtime inspect state is private.
        with db_env.open("x") as stream:
            stream.write(f"POSTGRES_USER=xtrace\nPOSTGRES_DB=medusa\nPOSTGRES_PASSWORD={password}\n")
        args = ["docker", "create", "--cidfile", str(cidfile), "--name", db_name,
                "--label", "xtrace-medusa-120", "--platform", "linux/amd64",
                "--tmpfs", "/var/lib/postgresql", "--publish", "127.0.0.1::5432", "--env-file", str(db_env), self.pg_image,
                "-c", "fsync=off", "-c", "log_statement=none"]
        result, out = self.command(args, fail=False)
        # A partial failure can still leave this owned ID. The caller obtains it before checking exit.
        cid = owned_id(cidfile)
        require(cid)
        return cid, result.returncode == 0 and out.read_text().strip() == cid

    def ready_database(self, cid):
        self.command(["docker", "start", cid])
        require(self.text(["docker", "inspect", "-f", "{{.Image}}", cid]).strip() == self.pg_image)
        end = time.monotonic() + 90
        query = ["docker", "exec", cid, "psql", "-U", "xtrace", "-d", "medusa", "-Atc", "select 1"]
        while time.monotonic() < end:
            check, _ = self.command(["docker", "exec", cid, "pg_isready", "-U", "xtrace", "-d", "medusa"],
                                    fail=False, timeout=max(0.1, min(5, end - time.monotonic())))
            if check.returncode == 0:
                first, _ = self.command(query, fail=False, timeout=max(0.1, min(5, end - time.monotonic())))
                if first.returncode == 0 and end - time.monotonic() > 1.5:
                    time.sleep(1.5)  # Retain the original entrypoint restart check.
                    second, _ = self.command(query, fail=False, timeout=max(0.1, min(5, end - time.monotonic())))
                    if second.returncode == 0:
                        return self.database_port(cid)
            time.sleep(0.5)
        raise TimeoutError("database readiness deadline")

    def database_port(self, cid):
        endpoint = self.text(["docker", "port", cid, "5432/tcp"]).strip()
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", endpoint)
        require(match and 0 < int(match[1]) <= 65535)
        return int(match[1])

    def check_health(self, directory, owner, deadline):
        config = directory / "health-input.json"
        milliseconds = min(3000, int(remaining(deadline) * 1000))
        require(milliseconds > 0)
        private_json(config, {"mode": "health", "owner": owner, "timeoutMs": milliseconds})
        self.command([str(self.node), str(HERE / "installed-workload.mjs"), str(config)],
                     timeout=remaining(deadline))

    def cli_json(self, args, timeout=30):
        return self.json([str(self.cli), "recording", *args, "--project-dir", str(self.project)], timeout=timeout)

    def list_cli(self, deadline=None):
        def request(after):
            timeout = 30 if deadline is None else min(5, deadline - time.monotonic())
            require(timeout > 0)
            return self.cli_json(["list", "--limit", "20"] + (["--after", after] if after else []), timeout)
        return list(pages(request, "recordings", "next_after", limit=20, max_rows=400))

    def ready_recording(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            listing = self.list_cli(deadline)
            ids = keys(listing, "recordings", "recording_id")
            require(len(ids) <= 1)
            rows = [row for page in listing for row in page["recordings"]]
            if len(rows) == 1 and rows[0].get("completion") == "complete":
                return next(iter(ids))
            time.sleep(0.1)
        raise TimeoutError("readiness recording deadline")

    def leg(self, name):
        notes = self.root / name
        notes.mkdir(mode=0o700)
        process, cid, ready_id = None, None, None
        diagnostic_nonce = None
        self.summary["stages"].update({f"{name}:{stage}": "unreached" for stage in
                                       ("inputs", "database", "startup", "readiness-recording", "workload", "shutdown", "cleanup")})
        self.save()
        password, admin_password = secret(), secret()
        admin = {"email": "xtrace-baseline@example.invalid", "password": admin_password}
        created = False
        db_name = f"xtrace-camp-node-medusa-120-{name}-{secret()[:16]}"
        cidfile = self.root / "private" / (name + "-postgres.cid")
        source = self.root / (name + "-starter")
        backend = source / "apps/backend"
        try:
            with self.stage(f"{name}:inputs"):
                shutil.copytree(self.starter, source, symlinks=True)
                require(starter_bytes(source) == self.prepared_sha)
            with self.stage(f"{name}:database"):
                private_json(cidfile.with_suffix(".attempt"), {"attempted": True})
                cid, created = self.database(self.root / "private" / (name + "-postgres.env"), cidfile, db_name, password)
                require(created)
                db_port = self.ready_database(cid)
            runtime_home = notes / "home"
            runtime_home.mkdir(mode=0o700)
            for subdir in ("config", "cache", "data"):
                (runtime_home / subdir).mkdir(mode=0o700)
            env = dict(self.env, HOME=str(runtime_home), XDG_CONFIG_HOME=str(runtime_home / "config"),
                       XDG_CACHE_HOME=str(runtime_home / "cache"), XDG_DATA_HOME=str(runtime_home / "data"),
                       NODE_ENV="development", HOST="127.0.0.1", PORT=str(PORT),
                       DATABASE_URL=f"postgres://xtrace:{password}@127.0.0.1:{db_port}/medusa?sslmode=disable",
                       DB_NAME="medusa", STORE_CORS="http://localhost:8000", ADMIN_CORS="http://localhost:9000",
                       AUTH_CORS="http://localhost:9000", JWT_SECRET=secret(), COOKIE_SECRET=secret(),
                       MEDUSA_DISABLE_TELEMETRY="1", DO_NOT_TRACK="1")
            medusa = [str(self.node), "./node_modules/@medusajs/cli/cli.js"]
            with self.stage(f"{name}:startup"):
                deadline = time.monotonic() + 300
                with self.phase(name, "migrate"):
                    self.command(medusa + ["db:migrate"], cwd=backend, env=env, timeout=remaining(deadline))
                with self.phase(name, "create-admin"):
                    self.command(medusa + ["user", "-e", admin["email"], "-p", admin_password],
                                 cwd=backend, env=env, timeout=remaining(deadline))
                with self.phase(name, "prelaunch-port"):
                    require(port_vacant(PORT))
                command = medusa + ["start"]
                if name == "installed":
                    with self.phase(name, "prelaunch-readback"):
                        require(not keys(self.list_cli(), "recordings", "recording_id"))
                    command = [str(self.cli), "run", "--project-dir", str(self.project), "--node-adapter",
                               str(self.pack), "--node-mode", "auto", "--", *command]
                if name == "installed" and os.environ.get("MEDUSA_CAPTURE_DIAGNOSTIC") == "1":
                    diagnostic_nonce = secret()
                    env["XTRACE_MEDUSA_CAPTURE_DIAGNOSTIC"] = diagnostic_nonce
                    self.summary["nodeCaptureDiagnostic"] = {"status": "unreached"}
                with self.phase(name, "spawn"):
                    process = Process(notes, command, backend, env, descendants=True)
                env.pop("XTRACE_MEDUSA_CAPTURE_DIAGNOSTIC", None)
                with self.phase(name, "await-readiness-log"):
                    # Medusa's pinned development reporter uses Ora, whose success line is on stderr.
                    _, stream = process.ready(medusa_ready_line, remaining(deadline), include_stderr=True)
                    self.summary["medusaReadinessLogStream"][name] = stream
                with self.phase(name, "identify-server-process"):
                    require(process.child.poll() is None)
                    if name == "installed":
                        children = [pid for pid in process.owned_children
                                    if (Path(f"/proc/{pid}") / "exe").resolve() == self.node
                                    and re.search(rf"^PPid:\s+{process.child.pid}$",
                                                  Path(f"/proc/{pid}/status").read_text(), re.M)]
                        require(len(children) == 1)
                    else:
                        children = [process.child.pid]
                    owner = listener_owner(children[0], PORT)
                with self.phase(name, "owned-health"):
                    self.check_health(notes, owner, deadline)
                with self.phase(name, "save-process-identity"):
                    private_json(notes / "process-identity.json", {"launcherPid": process.child.pid,
                                 "nodePid": children[0], "nodeSha256": self.summary["nodeSha256"]})
            if name == "installed":
                try:
                    with self.stage(f"{name}:readiness-recording"):
                        ready_id = self.ready_recording()
                except Exception:
                    traceback.print_exc()
            with self.stage(f"{name}:workload"):
                require(self.database_port(cid) == db_port)
                config = notes / "workload-input.json"
                private_json(config, {"mode": "workload", "out": str(notes), "admin": admin, "owner": owner,
                                      "db": {"container": cid, "database": "medusa", "user": "xtrace"}})
                result, _ = self.command([str(self.node), str(HERE / "installed-workload.mjs"), str(config)],
                                         timeout=900, fail=False)
                self.summary["localTransport"][name] = local_transport(read_json(notes / "local-transport.json"))
                require(result.returncode == 0 and self.summary["localTransport"][name]["ownedResponses"] == 46
                        and self.database_port(cid) == db_port)
        except Exception:
            traceback.print_exc()
        finally:
            try:
                if process:
                    with self.stage(f"{name}:shutdown"):
                        live = process.child.poll() is None
                        with self.phase(name, "stop-process"):
                            try:
                                require_code = process.stop()
                            finally:
                                self.summary["reapedAdoptedGroupExits"][name] = process.reaped_group_exits
                                self.summary["stopRecoveryReasons"][name] = process.stop_recovery_reasons
                        with self.phase(name, "check-graceful-exit"):
                            require(live)
                            if require_code != 0:
                                raise LifecycleProcessExit(require_code)
                        with self.phase(name, "shutdown-port-vacant"):
                            require(port_vacant(PORT))
                        if name == "installed":
                            with self.phase(name, "capture-drain"):
                                log = process.stderr
                                require(log.stat().st_size <= 16 * 1024 * 1024)
                                stderr = log.read_bytes()
                                self.summary["nodeCaptureDiagnostic"] = project_capture_diagnostic(stderr, diagnostic_nonce)
                                require(b"XTR-RUN-CAPTURE-INCOMPLETE" not in stderr)
            except Exception:
                traceback.print_exc()
            try:
                with self.stage(f"{name}:cleanup"):
                    cid = cid or owned_id(cidfile)
                    try:
                        if cid:
                            with self.phase(name, "remove-database"):
                                self.command(["docker", "rm", "-f", "-v", cid])
                            with self.phase(name, "check-database-absent"):
                                require(not self.text(["docker", "ps", "-aq", "--no-trunc", "--filter",
                                                       f"id={cid}"]).strip())
                    finally:
                        with self.phase(name, "check-owned-children-absent"):
                            verify_children_gone()
                    with self.phase(name, "verify-cleanup-state"):
                        require(created and (process is None or process.cleaned))
                    with self.phase(name, "cleanup-port-vacant"):
                        require(port_vacant(PORT))
            except Exception:
                traceback.print_exc()
        return ready_id, notes / "scenarios.json"

    def readback(self, readiness, expected_statuses):
        with self.stage("readback"):
            require(readiness is not None)
            listing = self.list_cli()
            cli_ids = keys(listing, "recordings", "recording_id")
            require(readiness in cli_ids)
            cli_details = {}
            for rid in sorted(cli_ids):
                read = lambda cursor: self.cli_json(["show", rid, "--limit", "100"]
                                                     + (["--cursor", cursor] if cursor else []))
                cli_details[rid] = detail(pages(read, "events", "next_cursor",
                                               limit=100, max_rows=4000), rid, api=False)

            viewer_dir = self.root / "viewer"
            viewer_dir.mkdir(mode=0o700)
            viewer = Process(viewer_dir, [str(self.cli), "open", "--project-dir", str(self.project),
                                          "--viewer", "--no-browser"], REPO, self.env)
            try:
                ready, _ = viewer.ready(xinstr.parse_readiness, 60)
                require(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", ready["origin"]))
                require(ready["url"].startswith(ready["origin"] + "/#token="))
                token = xinstr.bootstrap_token(ready["url"])
                require(token)
                port = int(ready["origin"].rsplit(":", 1)[1])
                api = Api(self, listener_owner(viewer.child.pid, port), viewer_dir)
                api.exchange(token)
                api_list = pages(lambda after: api.get("/api/v1/recordings", limit=20, after=after),
                                 "recordings", "nextAfter", limit=20, max_rows=400)
                api_ids = keys(api_list, "recordings", "recordingId")
                require(api_ids == cli_ids)
                for rid in sorted(api_ids):
                    read = lambda cursor: api.get(f"/api/v1/recordings/{rid}", limit=100, cursor=cursor)
                    require(detail(pages(read, "events", "nextCursor", limit=100, max_rows=4000),
                                   rid, api=True) == cli_details[rid])
                unmatched = list(pages(lambda cursor: api.get("/api/v1/recordings", unmatched="true", limit=20, cursor=cursor),
                                       "items", "nextCursor", limit=20, max_rows=400))
                require(keys(unmatched, "items", "recordingId") == cli_ids)
                unmatched_rows = [row for page in unmatched for row in page["items"]]
                default_reason = sum(row.get("unmatchedReason") == "observation_policy_missing" and row.get("operationId") is None
                                     and row.get("observationPolicy") is None for row in unmatched_rows)
                endpoint_rows = list(pages(lambda cursor: api.get("/api/v1/endpoints", limit=20, cursor=cursor),
                                           "items", "nextCursor", limit=20, max_rows=400))
                endpoints = sum(len(page["items"]) for page in endpoint_rows)
                self.summary["unmatched"] = {"recordings": len(unmatched_rows), "missingPolicy": default_reason,
                                             "observedEndpoints": endpoints}
                require(default_reason == len(cli_ids) and endpoints == 0)
                root = cli_details[readiness]
                require(root["completion"] == "complete" and root["outcome"]["kind"] == "responded"
                        and root["outcome"]["httpStatus"] == 200)
            finally:
                require(viewer.stop() in (0, -signal.SIGTERM))
        with self.stage("capture"):
            self.summary["capture"] = capture(cli_details, readiness, expected_statuses)
            require(self.summary["capture"]["passed"])

    def run(self):
        try:
            self.install()
        finally:
            verify_children_gone()
        self.project.mkdir(mode=0o700)
        with self.stage("init"):
            self.command([str(self.cli), "init", "--project-dir", str(self.project)])
        _, baseline = self.leg("baseline")
        ready_id, installed = self.leg("installed")
        self.summary["stages"]["workload-comparison"] = "failed"
        self.save()
        facts, statuses = workload(read_json(baseline), read_json(installed), EXPECTED)
        self.summary["workload"] = facts
        semantics_equal = facts["matched"] == facts["expected"] and facts["transportFailures"] == 0
        self.summary["stages"]["workload-comparison"] = "passed" if semantics_equal else "failed"
        self.save()
        with self.stage("input-parity"):
            self.starter_identity()
            require(self.packages == self.inventory("final-package-identities") and self.entry_sha == sha(self.entry))
            require(starter_bytes(self.starter) == self.prepared_sha)
            require(self.summary["archiveSha256"] == sha(self.archive) and self.summary["nodeSha256"] == sha(self.node))
        self.readback(ready_id, statuses)
        required = {f"{name}:{stage}" for name in ("baseline", "installed")
                    for stage in ("inputs", "database", "startup", "workload", "shutdown", "cleanup")}
        required.add("installed:readiness-recording")
        require(all(self.summary["stages"].get(name) == "passed" for name in required) and semantics_equal)
        self.summary["status"] = "passed"
        self.save()


def owned_id(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 128:
        return None
    value = path.read_text().strip()
    return value if re.fullmatch("[0-9a-f]{64}", value) else None


def medusa_ready_line(line):
    if re.search(r"\bServer is ready on port: 9000(?![0-9])", line):
        return True
    return None


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("Medusa startup deadline")
    return seconds


class Api:
    def __init__(self, proof, owner, directory):
        self.proof, self.owner, self.directory, self.number = proof, owner, directory, 0
        self.cookie = None

    def request(self, path, timeout, **credentials):
        self.number += 1
        context = self.directory / f"api-{self.number}-input.json"
        output = self.directory / f"api-{self.number}.json"
        private_json(context, {"mode": "viewer", "owner": self.owner, "path": path,
                              "timeoutMs": timeout * 1000, "out": str(output), **credentials})
        metadata = self.proof.json([str(self.proof.node), str(HERE / "installed-workload.mjs"), str(context)],
                                   timeout=timeout)
        require(metadata["status"] == 200)
        return metadata, output

    def exchange(self, token):
        metadata, _ = self.request("/api/v1/auth/exchange", 60, token=token)
        self.cookie = metadata.get("cookie")
        require(self.cookie)

    def get(self, path, **params):
        query = urlencode({key: value for key, value in params.items() if value is not None})
        _, output = self.request(path + "?" + query, 15, cookie=self.cookie)
        return read_json(output)


def stop_requested(_signal, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt("hosted supervisor requested stop")


def main():
    require(len(sys.argv) == 4 and sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true")
    require(not any(os.environ.get(key) for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "XTRACE_CAMP_DOCKER_HOST",
                                                    "XTRACE_CAMP_DOCKER_CONFIG")))
    os.umask(0o077)
    contain_children()
    signal.signal(signal.SIGTERM, stop_requested)
    root, archive, starter = (Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    admit_directory(root)
    admit_directory(starter)
    require(starter.parent == root and archive.is_relative_to(root))
    for name in ("logs", "private", "safe", "tmp", "home"):
        (root / name).mkdir(mode=0o700)
    proof = Proof(root, archive, starter)
    proof.save()
    try:
        try:
            proof.run()
        finally:
            verify_children_gone()
    except (Exception, KeyboardInterrupt):
        proof.summary["status"] = "failed"
        proof.save()
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
