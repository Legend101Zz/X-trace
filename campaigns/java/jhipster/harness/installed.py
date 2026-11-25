#!/usr/bin/env python3
"""Run only the pinned JHipster campaign through a freshly installed hosted package.

All subprocess streams and failure detail remain below the private root. The phase
manifest records exact process exits, including failures before a receipt exists;
it is input to public_result.py, never an uploadable report itself.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import traceback

REPO = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "campaigns/lib"))
from private_diagnostic import mark_root_admitted  # noqa: E402
PHASES = ("prerequisite", "package-verify", "candidate-install", "installed-verify", "checkout-upstream",
          "build-upstream", "baseline", "instrumented", "collect-sinks")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def private_parent(path):
    """The product rejects writable ancestors; do not use a system temporary root."""
    for item in (path, *path.parents):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022):
            raise ValueError("unsafe hosted campaign ancestor")
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("hosted campaign parent must be private")


def prepare_root(root):
    """Accept only a fresh root or this workflow's completed private build seed."""
    private_parent(root.parent)
    if root.exists():
        private_parent(root)
        if {p.name for p in root.iterdir()} != {"build-status.json", "console"}:
            raise ValueError("hosted campaign root already contains run state")
        private_parent(root / "console")
        for path in (root / "build-status.json", *(root / "console").iterdir()):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("build seed is not an owner-only regular file")
        if {p.name for p in (root / "console").iterdir()} != {"package-build.stdout", "package-build.stderr"}:
            raise ValueError("unexpected build console seed")
        seed = json.loads((root / "build-status.json").read_text())
        if seed != {"schema": "xtrace-jhipster-build/1", "exitCode": 0}:
            raise ValueError("archive build did not complete successfully")
    else:
        root.mkdir(mode=0o700)
    for relative in ("console", "child-stderr", "package", "unpacked", "home", "data", "tmp", "campaign", "campaign/java",
                     "campaign/java/jhipster"):
        (root / relative).mkdir(mode=0o700, exist_ok=relative == "console")


class InstalledCampaign:
    def __init__(self, root, archive, package_sha, source_sha, java):
        self.root, self.input_archive = root, archive
        self.package_sha, self.source_sha, self.java = package_sha, source_sha, java
        self.archive = root / "package/archive.tar.gz"
        self.prefix = root / "installed X-trace"
        self.source = root / "campaign/java/jhipster/src"
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "XCAMP_LAUNCH_PREFIX",
                                 "XCAMP_DUMP_BODIES", "XTRACE_JAVA_ANALYZER", "XTRACE_CAMPAIGN_ROOT")}
        self.env.update({"XTRACE_CAMPAIGN_ROOT": str(root / "campaign"), "XCAMP_APP_MODE": "host",
                         "XCAMP_PLATFORM": "linux/amd64", "XCAMP_JAVA": str(java),
                         "XCAMP_INSTALL_PREFIX": str(self.prefix), "XCAMP_PACKAGE_ARCHIVE": str(self.archive),
                         "XCAMP_PACKAGE_SHA256": package_sha, "XCAMP_PRODUCT_SHA": source_sha,
                         "XCAMP_DATA_HOME": str(root / "data"), "XTRACE_DATA_HOME": str(root / "data"),
                         "XCAMP_CANARY_FILE": str(root / "canaries.json"), "TMPDIR": str(root / "tmp"),
                         "XCAMP_PRIVATE_PREPARATION_TRACEBACK": "1",
                         "XCAMP_PRIVATE_CHILD_STDERR_DIR": str(root / "child-stderr"),
                         "XCAMP_BASELINE_RECEIPT": str(root / "campaign/java/jhipster/baseline-1/receipt.json"),
                         "HOME": str(root / "home"), "TZ": "UTC"})
        self.manifest = {"schema": "xtrace-jhipster-phases/1", "sourceCommit": source_sha,
                         "packageSha256": package_sha,
                         "phases": [{"name": name, "status": "unreached", "exitCode": None} for name in PHASES]}

    def save(self):
        # A failed first write must leave phases absent, rather than a partial
        # manifest that could be mistaken for observed phase progress.
        pending = self.root / "phases.pending.json"
        with pending.open("x") as stream:
            stream.write(json.dumps(self.manifest, sort_keys=True) + "\n")
        pending.replace(self.root / "phases.json")

    def command(self, argv, *, cwd=REPO):
        # The enclosing phase owns these streams. Never buffer them for public error messages.
        return subprocess.run(argv, cwd=cwd, env=self.env, stdout=sys.stdout, stderr=sys.stderr, check=False).returncode

    def phase(self, name, operation):
        row = next(row for row in self.manifest["phases"] if row["name"] == name)
        self.env["XCAMP_DIAGNOSTIC_PHASE"] = name
        with (self.root / f"console/{name}.stdout").open("w") as out, \
                (self.root / f"console/{name}.stderr").open("w") as err:
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    code = operation()
                    if type(code) is not int:
                        raise TypeError("phase did not return a process status")
                except Exception:
                    traceback.print_exc()
                    code = 2
        row.update(status="passed" if code == 0 else "failed", exitCode=code)
        self.save()
        return code

    def prerequisites(self):
        if (sys.platform != "linux" or platform.machine() != "x86_64" or self.env.get("GITHUB_ACTIONS") != "true"
                or any(not self.env.get(k) for k in (
                    "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"))
                or not re.fullmatch(r"[0-9a-f]{40}", self.source_sha)
                or not re.fullmatch(r"[0-9a-f]{64}", self.package_sha)
                or not self.java.is_absolute() or not self.java.is_file() or not os.access(self.java, os.X_OK)):
            raise ValueError("requires Linux x86_64 GitHub job, exact product/archive identity and absolute host Java")
        actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True)
        if actual.stdout.strip() != self.source_sha:
            raise ValueError("campaign checkout differs from the package build checkout")
        for name in ("docker", "git", "sh"):
            if not shutil.which(name, path=self.env.get("PATH")):
                raise ValueError("campaign prerequisite unavailable")
        if digest(self.input_archive) != self.package_sha:
            raise ValueError("downloaded archive differs from the build job digest")
        shutil.copyfile(self.input_archive, self.archive)
        if digest(self.archive) != self.package_sha:
            raise ValueError("private archive copy differs from the build job digest")
        # The campaign harness independently observes major, vendor, JVM, executable,
        # release-file hash and boot binding again at baseline and instrumented entry.
        java = subprocess.run([str(self.java), "-XshowSettings:properties", "-version"], env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        sys.stdout.write(java.stdout)
        sys.stderr.write(java.stderr)
        if java.returncode != 0:
            return java.returncode
        if not re.search(r"(?m)^\s*java\.specification\.version = 21\s*$", java.stderr):
            raise ValueError("configured host Java did not report JDK 21")
        spec = importlib.util.spec_from_file_location("jhipster_canary", REPO / "tools/qa/canary.py")
        canary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(canary)
        (self.root / "canaries.json").write_text(json.dumps(canary.make_canaries()) + "\n")
        self.campaign = json.loads((HERE.parent / "campaign.json").read_text())
        return 0

    def verify_archive(self):
        if digest(self.archive) != self.package_sha:
            raise ValueError("private archive digest changed")
        rc = self.command([sys.executable, "-B", str(REPO / "packaging/verify_package.py"), str(self.archive),
                           "--run-binary", "--repo", str(REPO), "--out", str(self.root / "package-verification.json")])
        if rc != 0:
            return rc
        report = json.loads((self.root / "package-verification.json").read_text())
        if (report.get("ok") is not True or report.get("package", {}).get("sourceCommit") != self.source_sha
                or report["package"].get("platform") != "linux-x86_64"):
            raise ValueError("verified archive does not match the exact build identity")
        return 0

    def install(self):
        # Run the full existing verifier first; its safe extraction helper rejects
        # links/special entries and traversal before executing the packaged installer.
        if digest(self.archive) != self.package_sha or self.prefix.exists():
            raise ValueError("archive changed or install prefix is not fresh")
        spec = importlib.util.spec_from_file_location("jhipster_package_verifier", REPO / "packaging/verify_package.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        unpacked = verifier.resolve_root(self.archive, self.root / "unpacked")
        return self.command(["sh", str(unpacked / "install.sh"), "--prefix", str(self.prefix),
                             "--data-home", str(self.root / "data")])

    def run(self):
        self.save()
        operations = (
            ("prerequisite", self.prerequisites),
            ("package-verify", self.verify_archive),
            ("candidate-install", self.install),
            ("installed-verify", lambda: self.command(["sh", str(self.prefix / "current/install.sh"), "verify",
                                                       "--prefix", str(self.prefix)])),
            ("checkout-upstream", lambda: self.command(["sh", str(REPO / "tools/qa/camp_clone.sh"),
                                                       self.campaign["upstream"]["canonicalUrl"],
                                                       self.campaign["upstream"]["sha"], str(self.source)])),
            ("build-upstream", lambda: self.command(shlex.split(self.campaign["build"]["command"]), cwd=self.source)),
            ("baseline", lambda: self.command([sys.executable, "-B", str(HERE / "run.py"), "baseline"])),
            ("instrumented", lambda: self.command([sys.executable, "-B", str(HERE / "run.py"), "instrumented"])),
        )
        for name, operation in operations:
            code = self.phase(name, operation)
            if code != 0:
                if name == "instrumented":
                    self.phase("collect-sinks", lambda: self.command(
                        [sys.executable, "-B", str(HERE / "collect_sinks.py"), "--private-root", str(self.root)]))
                return code
        return self.phase("collect-sinks", lambda: self.command(
            [sys.executable, "-B", str(HERE / "collect_sinks.py"), "--private-root", str(self.root)]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--java", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        root = args.private_root.absolute()
        prepare_root(root)
        mark_root_admitted(root)
        campaign = InstalledCampaign(root, args.archive, args.package_sha256, args.source_sha, args.java)
        code = campaign.run()
    except Exception:
        # The workflow's outer sink survives rejection of the campaign root.
        # Keep setup detail only when the caller explicitly supplied a private file.
        try:
            info = os.fstat(sys.stderr.fileno())
            if (os.environ.get("XTRACE_PRIVATE_DRIVER_DIAGNOSTIC") == "1" and stat.S_ISREG(info.st_mode)
                    and info.st_uid == os.getuid() and not info.st_mode & 0o077):
                traceback.print_exc()
        except (OSError, ValueError):
            pass
        print("JHipster private runner setup failed; no campaign receipt established", file=sys.stderr)
        return 2
    print("JHipster installed campaign driver exit", code)
    return code if code >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
