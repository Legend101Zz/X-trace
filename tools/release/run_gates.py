#!/usr/bin/env python3
"""Run v0.01 gates at a clean, exact HEAD with recoverable local logs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Sequence


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CACHE_NAMES = ("cargo", "cargo-target", "gradle", "npm", "playwright", "tmp", "xdg")


@dataclass(frozen=True)
class Gate:
    name: str
    argv: tuple[str, ...]
    cwd: str = "."
    env: str = "normal"


GATES: tuple[Gate, ...] = (
    Gate("rust-format", ("cargo", "fmt", "--all", "--check")),
    Gate("rust-clippy", ("cargo", "clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")),
    Gate("rustdoc", ("cargo", "doc", "--locked", "--workspace", "--all-features", "--no-deps"), env="rustdoc"),
    Gate("java-strict", ("./gradlew", "--dependency-verification", "strict", "clean", "test", "installDist", "agentDist", "fixtureBootJar"), cwd="adapters/java"),
    Gate("node-install", ("npm", "ci", "--prefix", "adapters/node")),
    Gate("node-generate", ("npm", "run", "generate", "--prefix", "adapters/node")),
    Gate("node-generate-check", ("npm", "run", "generate:check", "--prefix", "adapters/node")),
    Gate("node-typecheck", ("npm", "run", "typecheck", "--prefix", "adapters/node")),
    Gate("node-tests", ("npm", "test", "--prefix", "adapters/node")),
    Gate("web-install", ("npm", "ci", "--prefix", "web/app")),
    Gate("web-browser-install", ("./node_modules/.bin/playwright", "install", "chromium"), cwd="web/app"),
    Gate("web-typecheck", ("npm", "run", "typecheck", "--prefix", "web/app")),
    Gate("web-tests", ("npm", "test", "--prefix", "web/app")),
    Gate("web-api-drift", ("npm", "run", "check:api", "--prefix", "web/app")),
    Gate("web-embedded-assets", ("npm", "run", "check:embedded", "--prefix", "web/app")),
    Gate("rust-cli-spring-journey", ("cargo", "test", "--locked", "-p", "xtrace-cli", "--test", "java_run_spring", "--", "--test-threads=1")),
    Gate("rust-focused", ("cargo", "test", "--locked", "-p", "xtrace-application", "-p", "xtrace-store", "-p", "xtrace-cli", "--all-features", "--no-fail-fast")),
    Gate("rust-workspace", ("cargo", "test", "--locked", "--workspace", "--all-features", "--no-fail-fast")),
    Gate("rust-build", ("cargo", "build", "--locked", "--workspace", "--all-features")),
    Gate("restricted-build", ("cargo", "build", "--locked", "--workspace", "--all-features"), env="restricted"),
    Gate("working-diff-check", ("git", "diff", "--check")),
    Gate("staged-diff-check", ("git", "diff", "--cached", "--check")),
    Gate("phase-diff-check", (), env="phase-diff"),
)


def _run(argv: Sequence[str], *, cwd: pathlib.Path, env: dict[str, str], timeout: int, log_path: pathlib.Path) -> tuple[int, float]:
    started = time.monotonic()
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    code = 0
    with os.fdopen(fd, "wb") as log:
        try:
            result = subprocess.run(list(argv), cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\nGate timed out after {timeout} seconds.\n".encode())
            code = 124
        except OSError as exc:
            log.write(f"Gate could not start ({type(exc).__name__}).\n".encode())
            code = 127
        log.flush()
        os.fsync(log.fileno())
    return code, round(time.monotonic() - started, 6)


def _hash_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo: pathlib.Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"git command failed: {args[0]}")
    return result.stdout.strip()


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree_state_digest(repo: pathlib.Path) -> str:
    status = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    work = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    cached = subprocess.run(["git", "diff", "--cached", "--binary", "HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if status.returncode or work.returncode or cached.returncode:
        raise RuntimeError("cannot capture working-tree identity")
    pieces = [status.stdout, work.stdout, cached.stdout]
    for entry in status.stdout.split(b"\0"):
        if not entry:
            continue
        name = entry[3:].decode("utf-8", "surrogateescape")
        path = repo / name
        if path.is_symlink():
            pieces.extend((name.encode("utf-8", "surrogateescape"), os.readlink(path).encode()))
        elif path.is_file():
            pieces.extend((name.encode("utf-8", "surrogateescape"), path.read_bytes()))
    return _hash(b"\0".join(pieces))


def _phase_diff(repo: pathlib.Path, base: str) -> bytes:
    result = subprocess.run(["git", "diff", "--binary", f"{base}...HEAD"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError("cannot capture pinned phase diff")
    return result.stdout


def _versions(repo: pathlib.Path, env: dict[str, str]) -> dict[str, str]:
    versions: dict[str, str] = {}
    commands = (
        ("rustc", ("rustc", "--version"), "."),
        ("cargo", ("cargo", "--version"), "."),
        ("rustup", ("rustup", "--version"), "."),
        ("java", ("java", "-version"), "."),
        ("node", ("node", "--version"), "."),
        ("npm", ("npm", "--version"), "."),
        ("gradle-wrapper", ("./gradlew", "--version"), "adapters/java"),
        ("buf", ("buf", "--version"), "."),
        ("playwright", ("./node_modules/.bin/playwright", "--version"), "web/app"),
        ("python", (sys.executable, "--version"), "."),
        ("git", ("git", "--version"), "."),
    )
    for name, argv, cwd in commands:
        try:
            result = subprocess.run(argv, cwd=repo / cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20, check=False)
            lines = result.stdout.decode("utf-8", "replace").splitlines()
            versions[name] = lines[0][:240] if lines else f"exit:{result.returncode}"
        except (OSError, subprocess.TimeoutExpired):
            versions[name] = "unavailable"
    return versions


def _restricted_env(base_env: dict[str, str], cache: pathlib.Path, label: str) -> tuple[dict[str, str], str]:
    cargo = shutil.which("cargo", path=base_env.get("PATH"))
    rustc = shutil.which("rustc", path=base_env.get("PATH"))
    if not cargo or not rustc:
        raise RuntimeError("cargo and rustc must be available before the restricted-PATH gate")
    keep = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "RUSTUP_HOME")
    env = {key: base_env[key] for key in keep if key in base_env}
    env.update({
        "PATH": "/usr/bin:/bin",
        "RUSTC": rustc,
        "CARGO_HOME": str(cache / "cargo"),
        "CARGO_TARGET_DIR": str(cache / f"cargo-target-restricted-{label}"),
        "XDG_CACHE_HOME": str(cache / "xdg"),
        "TMPDIR": str(cache / "tmp"),
        "RUSTUP_HOME": base_env.get("RUSTUP_HOME", str(pathlib.Path.home() / ".rustup")),
    })
    return env, cargo


def _atomic_write(path: pathlib.Path, data: bytes) -> None:
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            temp.unlink()
        except OSError:
            pass
        raise


def _atomic_json(path: pathlib.Path, value: Any) -> None:
    _atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


class Lease:
    def __init__(self, path: pathlib.Path, token: str, label: str):
        self.path = path
        self.token = token
        self.label = label
        self.acquired = False
        self.borrowed = False

    def acquire(self) -> None:
        try:
            self.path.mkdir(mode=0o700)
        except FileExistsError as exc:
            owner = "unknown owner"
            try:
                data = json.loads((self.path / "owner.json").read_text())
                owner = f"pid {data.get('pid', '?')} label {data.get('label', '?')}"
                if data.get("token") == self.token:
                    self.borrowed = True
                    return
            except (OSError, json.JSONDecodeError):
                pass
            raise RuntimeError(f"release builder lease is already owned ({owner}); share the exact lease token only with a nested gate invocation") from exc
        self.acquired = True
        try:
            _atomic_json(self.path / "owner.json", {"pid": os.getpid(), "label": self.label, "token": self.token, "startedAtEpoch": int(time.time())})
        except BaseException:
            shutil.rmtree(self.path, ignore_errors=True)
            self.acquired = False
            raise

    def release(self) -> None:
        if self.acquired and not self.borrowed:
            shutil.rmtree(self.path)
            self.acquired = False


def run(args: argparse.Namespace) -> int:
    args.lease_token = getattr(args, "lease_token", "") or secrets.token_hex(16)
    repo = pathlib.Path(args.repo).expanduser().resolve(strict=True)
    cache = pathlib.Path(args.cache_root).expanduser().resolve()
    if not (repo / ".git").exists():
        raise ValueError("--repo must be a Git checkout")
    if not LABEL_RE.fullmatch(args.label):
        raise ValueError("--label must contain only letters, digits, dot, underscore, and hyphen")
    if not SHA_RE.fullmatch(args.base.lower()):
        raise ValueError("--base must be a full 40-character commit SHA")
    base = args.base.lower()
    if _git(repo, "cat-file", "-t", base) != "commit":
        raise ValueError("--base must identify an immutable commit object")
    head_start = _git(repo, "rev-parse", "HEAD").lower()
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", base, "HEAD"], cwd=repo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if ancestry.returncode:
        raise ValueError("pinned phase base must be an ancestor of HEAD")
    if not re.fullmatch(r"[0-9a-f]{32}", args.lease_token):
        raise ValueError("--lease-token must be 32 lowercase hexadecimal characters")

    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o700)
    for name in CACHE_NAMES:
        (cache / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(cache / name, 0o700)
    release_root = cache / "release-gates"
    release_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(release_root, 0o700)
    run_dir = release_root / args.label
    try:
        run_dir.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise RuntimeError("run label already exists; choose a unique --label") from exc
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(mode=0o700)
    lease_root = cache / "leases"
    lease_root.mkdir(mode=0o700, exist_ok=True)
    leases = [Lease(lease_root / name, args.lease_token, args.label) for name in ("cargo", "gradle")]

    results: list[dict[str, Any]] = []
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "label": args.label,
        "phaseBase": base,
        "headBefore": head_start,
        "headAfter": None,
        "workingTreeDigestBefore": None,
        "workingTreeDigestAfter": None,
        "phaseDiffSha256Before": None,
        "phaseDiffSha256After": None,
        "toolVersions": {},
        "cacheKeys": list(CACHE_NAMES),
        "restrictedTargetKey": f"cargo-target-restricted-{args.label}",
        "gates": results,
        "decision": "running",
    }
    acquired_leases: list[Lease] = []
    try:
        for lease in leases:
            lease.acquire()
            acquired_leases.append(lease)
        if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
            raise RuntimeError("checkout must be clean so the receipt identifies exactly HEAD")
        diff_start = _phase_diff(repo, base)
        dirty_start = _tree_state_digest(repo)
        env = os.environ.copy()
        env.update({
            "CARGO_HOME": str(cache / "cargo"),
            "CARGO_TARGET_DIR": str(cache / "cargo-target"),
            "GRADLE_USER_HOME": str(cache / "gradle"),
            "NPM_CONFIG_CACHE": str(cache / "npm"),
            "PLAYWRIGHT_BROWSERS_PATH": str(cache / "playwright"),
            "TMPDIR": str(cache / "tmp"),
            "XDG_CACHE_HOME": str(cache / "xdg"),
        })
        manifest["workingTreeDigestBefore"] = dirty_start
        manifest["phaseDiffSha256Before"] = _hash(diff_start)
        manifest["toolVersions"] = _versions(repo, env)
        manifest["platform"] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
        manifest["dependencyLockSha256"] = {
            name: _hash((repo / name).read_bytes())
            for name in ("Cargo.lock", "adapters/java/gradle.lockfile", "adapters/node/package-lock.json", "web/app/package-lock.json")
        }
        for index, gate in enumerate(GATES):
            head_now = _git(repo, "rev-parse", "HEAD").lower()
            if head_now != head_start:
                results.append({"name": gate.name, "status": "unreached", "reason": "HEAD changed during gate run"})
                break
            gate_env = dict(env)
            argv = list(gate.argv)
            if gate.env == "rustdoc":
                gate_env["RUSTDOCFLAGS"] = "-D warnings"
            log_name = f"{gate.name}.log"
            log_path = logs_dir / log_name
            temp_log_path = logs_dir / f".{log_name}.{os.getpid()}.tmp"
            if gate.env == "restricted":
                gate_env, cargo_path = _restricted_env(os.environ.copy(), cache, args.label)
                if shutil.which("protoc", path=gate_env["PATH"]):
                    _atomic_write(log_path, b"protoc is present on restricted PATH; build not run\n")
                    code, duration = 1, 0.0
                    argv = ["protoc absence check", *gate.argv]
                else:
                    target = pathlib.Path(gate_env["CARGO_TARGET_DIR"])
                    target.mkdir(mode=0o700)
                    argv = [cargo_path, *gate.argv[1:]]
                    code, duration = _run(argv, cwd=repo, env=gate_env, timeout=args.command_timeout, log_path=temp_log_path)
            elif gate.env == "phase-diff":
                argv = ["git", "diff", "--check", f"{base}...HEAD"]
                code, duration = _run(argv, cwd=repo, env=gate_env, timeout=args.command_timeout, log_path=temp_log_path)
            else:
                code, duration = _run(argv, cwd=repo / gate.cwd, env=gate_env, timeout=args.command_timeout, log_path=temp_log_path)
            if temp_log_path.exists():
                os.replace(temp_log_path, log_path)
            entry = {
                "name": gate.name,
                "argv": argv,
                "cwd": gate.cwd,
                "exitCode": code,
                "durationSeconds": duration,
                "log": f"logs/{log_name}",
                "logSha256": _hash_file(log_path),
                "headBefore": head_now,
                "headAfter": _git(repo, "rev-parse", "HEAD").lower(),
                "status": "passed" if code == 0 else "failed",
            }
            results.append(entry)
            if gate.name == "web-browser-install" and code == 0:
                manifest["toolVersions"]["playwright"] = _versions(repo, env).get("playwright", "unavailable")
            manifest["headAfter"] = entry["headAfter"]
            manifest["gates"] = results
            manifest["decision"] = "running" if code == 0 else "failed"
            _atomic_json(run_dir / "receipt.json", manifest)
            print(f"{'PASS' if code == 0 else 'FAIL'} {gate.name} (exit {code}; log {log_name})", flush=True)
            if code != 0:
                for later in GATES[index + 1:]:
                    results.append({"name": later.name, "status": "unreached", "reason": f"stopped after {gate.name} failed"})
                break
        if not results:
            results.extend({"name": gate.name, "status": "unreached", "reason": "gate run did not start"} for gate in GATES)
        head_end = _git(repo, "rev-parse", "HEAD").lower()
        diff_end = _phase_diff(repo, base)
        dirty_end = _tree_state_digest(repo)
        manifest.update({"headAfter": head_end, "workingTreeDigestAfter": dirty_end, "phaseDiffSha256After": _hash(diff_end), "gates": results})
        if head_end != head_start:
            manifest.update({"decision": "failed", "integrityFailure": "HEAD changed during gate run"})
        elif dirty_end != dirty_start:
            manifest.update({"decision": "failed", "integrityFailure": "working tree changed during gate run"})
        elif _hash(diff_end) != _hash(diff_start):
            manifest.update({"decision": "failed", "integrityFailure": "pinned phase diff changed during gate run"})
        elif len(results) == len(GATES) and all(item.get("status") == "passed" for item in results):
            manifest["decision"] = "checks_passed_for_review"
        else:
            manifest["decision"] = "failed"
        _atomic_json(run_dir / "receipt.json", manifest)
        print(f"Decision: {manifest['decision']} ({sum(item.get('status') != 'unreached' for item in results)}/{len(GATES)} gates reached)")
        return 0 if manifest["decision"] == "checks_passed_for_review" else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        manifest["decision"] = "failed"
        manifest["error"] = str(exc)
        try:
            manifest["headAfter"] = _git(repo, "rev-parse", "HEAD").lower()
        except RuntimeError:
            pass
        completed = {item.get("name") for item in results}
        manifest["gates"] = results + [
            {"name": gate.name, "status": "unreached", "reason": "precondition or gate runner error"}
            for gate in GATES if gate.name not in completed
        ]
        try:
            _atomic_json(run_dir / "receipt.json", manifest)
        except OSError:
            pass
        print(f"release gates failed: {exc}", file=sys.stderr)
        return 1
    finally:
        for lease in reversed(acquired_leases):
            lease.release()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Git checkout to gate")
    parser.add_argument("--base", required=True, help="full immutable phase-base commit SHA")
    parser.add_argument("--label", required=True, help="unique phase/run label")
    parser.add_argument("--cache-root", required=True, help="explicit local cache and raw-log root")
    parser.add_argument("--lease-token", default="", help="shared 32-hex token for an explicitly nested invocation")
    parser.add_argument("--command-timeout", type=int, default=7200, help="per-command timeout in seconds")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"release gates not accepted: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
