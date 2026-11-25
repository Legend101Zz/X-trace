"""Private installed-Java campaign identity checks; no uploadable diagnostics."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import private_diagnostic
import xcamp

REPO = Path(__file__).resolve().parents[2]


def private_dir(path: Path) -> Path:
    path = path.absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError("unsafe campaign ancestor")
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("campaign directory is not owner-only")
    return path


def private_file(path: Path) -> Path:
    private_dir(path.parent)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("campaign input is not an owner-only regular file")
    return path


def clean_checkout(repo: Path, source_sha: str) -> None:
    """Use the package builder's clean checkout rule, including index and untracked files."""
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True)
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"],
                            cwd=repo, capture_output=True, text=True, check=True)
    if head.stdout.strip() != source_sha or status.stdout.strip():
        raise ValueError("product checkout is dirty or differs from the package source")


def verifier():
    spec = importlib.util.spec_from_file_location("campaign_package_verifier", REPO / "packaging/verify_package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def java_identity(java: Path, major: int) -> dict:
    if not java.is_absolute():
        raise ValueError("host Java must be absolute")
    java = java.resolve(strict=True)
    env = {k: v for k, v in os.environ.items() if k not in xcamp.JAVA_OPTIONS_ENV}
    proc = private_diagnostic.run_captured([str(java), "-XshowSettings:properties", "-version"], env=env,
                                          text=True, timeout=30, label="host-java")
    names = {"java.specification.version", "java.runtime.version", "java.vm.name", "java.vendor", "os.name", "os.arch"}
    properties = {}
    for line in ((proc.stdout or "") + (proc.stderr or "")).splitlines():
        key, _, value = line.strip().partition(" = ")
        if key in names and 0 < len(value) <= 120 and value.isprintable():
            properties[key] = value
    if proc.returncode or properties.keys() != names or properties["java.specification.version"] != str(major):
        raise ValueError("host Java does not match the campaign major")
    return {"properties": properties, "executableSha256": xcamp.sha256_file(java),
            "jdkReleaseSha256": xcamp.sha256_file(java.parents[1] / "release")}


def host_binding() -> str:
    names = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
    fields = {key: os.environ.get(key) for key in names}
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if os.environ.get("GITHUB_ACTIONS") != "true" or not all(fields.values()) or not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        raise ValueError("hosted job boot binding unavailable")
    return xcamp.sha256_json({**fields, "bootId": boot})


def installed_package(prefix: Path, archive: Path, archive_sha: str, source_sha: str, unpacked: Path) -> tuple:
    """Verify the archive, then compare every installed payload byte with its verified tree.

    The existing package verifier checks required components, all manifest hashes and
    the compiled schema. No installed executable is trusted before that archive check.
    """
    if not xcamp.HEX64.fullmatch(archive_sha) or xcamp.sha256_file(archive) != archive_sha:
        raise ValueError("archive digest mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("invalid source identity")
    package_verifier = verifier()
    report = package_verifier.verify(archive, run=False)
    if (report.get("ok") is not True or report["package"]["sourceCommit"] != source_sha
            or report["package"]["platform"] != "linux-x86_64"):
        raise ValueError("archive verification or identity mismatch")
    if package_verifier.verify(archive, repo=REPO, run=True).get("ok") is not True:
        raise ValueError("archive runtime verification failed")
    # Fresh extraction is private and uses the existing traversal/link refusal.
    unpacked.mkdir(mode=0o700, exist_ok=False)
    original = package_verifier.resolve_root(archive, unpacked)
    current = (prefix / "current").resolve(strict=True)
    versions = (prefix / "versions").resolve(strict=True)
    if current.parent != versions or versions.parent != prefix:
        raise ValueError("installed version escaped prefix")
    expected = {p.relative_to(original).as_posix(): p for p in original.rglob("*") if p.is_file()}
    observed = {}
    for folder, dirs, names in os.walk(current, followlinks=False):
        directory = Path(folder)
        if any((directory / name).is_symlink() for name in dirs):
            raise ValueError("installed symbolic directory")
        for name in names:
            path = directory / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("installed non-regular payload")
            observed[path.relative_to(current).as_posix()] = path
    if expected.keys() != observed.keys() or any(
            xcamp.sha256_file(path) != xcamp.sha256_file(observed[name]) for name, path in expected.items()):
        raise ValueError("installed payload differs from verified archive")
    cli = prefix / "bin/xtrace"
    agent = current / "share/xtrace/packs/java/agent/xtrace-java-agent.jar"
    analyzer = current / "share/xtrace/analyzers/java/bin/xtrace-java-static"
    if cli.resolve(strict=True) != current / "bin/xtrace" or not all(os.access(p, os.X_OK) for p in (cli, analyzer)):
        raise ValueError("installed launchers unavailable")
    checked = private_diagnostic.run_captured(["sh", str(current / "install.sh"), "verify", "--prefix", str(prefix)],
                                             env=dict(os.environ), text=True, timeout=120, label="installed-payload-verify")
    if checked.returncode:
        raise ValueError("installed verifier failed")
    return str(cli), str(agent), {"archiveSha256": archive_sha, "sourceCommit": source_sha,
                                 "payloadFilesVerified": len(expected), "cliSha256": xcamp.sha256_file(cli),
                                 "agentSha256": xcamp.sha256_file(agent),
                                 "analyzerLauncherSha256": xcamp.sha256_file(analyzer)}


def checked_baseline(path, pin, tracked, scenario_ids, project):
    """Require the entire same-host workload and retain historic comparison separately."""
    raw = private_file(path).read_bytes()
    doc = json.loads(raw)
    rows, reference = doc.get("scenarios", []), tracked["scenarios"]
    keys = ("sha", "git", "jarSha256", "postgresImageDigest", "hostJava", "hostRunBindingSha256",
            "runtimeDatabaseImageId", "databaseRepoDigest", "packageArchiveSha256", "runtimeDependencies")
    if (doc.get("project") != project or doc.get("result") != "passed_baseline_only"
            or doc.get("instrumented") is not False or doc.get("appMode") != "host"
            or any(doc.get("pin", {}).get(key) != pin[key] for key in keys)
            or pin["hostJava"]["properties"]["os.name"] != "Linux"
            or pin["hostJava"]["properties"]["os.arch"] != "amd64"
            or [row.get("id") for row in rows] != scenario_ids
            or [row["id"] for row in reference] != scenario_ids
            or any(tracked["pin"].get(key) != pin[key] for key in ("sha", "postgresImageDigest"))
            or any(row.get("passed") is not True or row.get("error") is not None
                   or len(row.get("requests", [])) != ref["requests"] or len(row.get("checks", [])) != ref["checks"]
                   or any(check.get("passed") is not True for check in row["checks"])
                   or not xcamp.HEX64.fullmatch(row.get("semanticEffectFingerprint", "")) for row, ref in zip(rows, reference))):
        raise ValueError("same-host baseline incomplete or identity mismatch")
    fingerprints = {row["id"]: row["semanticEffectFingerprint"] for row in rows}
    historic = {row["id"]: fingerprints[row["id"]] == row["semanticEffectFingerprint"] for row in reference}
    return fingerprints, historic, xcamp.sha256_bytes(raw)
