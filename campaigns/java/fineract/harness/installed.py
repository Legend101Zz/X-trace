#!/usr/bin/env python3
"""Private, single-attempt Fineract installed development campaign.

This driver never uploads artifacts. Its only stdout is a fixed
status envelope; phase receipts, source identities and all subprocess streams
remain under the freshly admitted private root. A failed phase leaves later
phases unreached and is never retried automatically.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import traceback

REPO = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "campaigns/lib"))
import installed_java  # noqa: E402
import xcamp  # noqa: E402
import installed_sinks  # noqa: E402
from campaigns.java.fineract.harness import privacy  # noqa: E402

PHASES = privacy.PHASES


class InstalledCampaign:
    def __init__(self, root, archive, package_sha, source_sha, java):
        self.root, self.archive = root, root / "package/archive.tar.gz"
        self.input_archive, self.package_sha, self.source_sha, self.java = archive, package_sha, source_sha, java
        self.prefix, self.source = root / "installed X-trace", root / "campaign/java/fineract/src"
        self.campaign = json.loads((HERE.parent / "campaign.json").read_text())
        self.privacy = privacy.PrivacyEvidence(root)
        self.env = {k: v for k, v in os.environ.items() if k not in (
            *xcamp.JAVA_OPTIONS_ENV, "XCAMP_LAUNCH_PREFIX", "XCAMP_DUMP_BODIES", "XTRACE_JAVA_ANALYZER", "XTRACE_CANARY_ENV")}
        self.env.update(XTRACE_CAMPAIGN_ROOT=str(root / "campaign"), XCAMP_APP_MODE="host", XCAMP_PLATFORM="linux/amd64",
                        XCAMP_JAVA=str(java), JAVA_HOME=str(java.resolve().parents[1]),
                        XCAMP_INSTALL_PREFIX=str(self.prefix), XCAMP_PACKAGE_ARCHIVE=str(self.archive),
                        XCAMP_PACKAGE_SHA256=package_sha, XCAMP_PRODUCT_SHA=source_sha,
                        XCAMP_DATA_HOME=str(root / "data"), XTRACE_DATA_HOME=str(root / "data"),
                        XCAMP_CANARY_FILE=str(root / "canaries.json"), TMPDIR=str(root / "tmp"), HOME=str(root / "home"),
                        XCAMP_PRIVATE_CHILD_STDERR_DIR=str(root / "child-stderr"),
                        XCAMP_BASELINE_RECEIPT=str(root / "campaign/java/fineract/baseline-1/receipt.json"), TZ="UTC")
        self.manifest = dict(schema="xtrace-fineract-installed-phases/1", nonRelease=True, releaseAcceptance=False,
                             sourceCommit=source_sha, packageSha256=package_sha, sourceIdentityVerified=False,
                             privacyScope=dict(captureDepth="standard", complete=False,
                                               gaps=list(privacy.SCOPE_GAPS),
                                               excludedInputs=["canary-control", "probe-request-inputs", "verified-package-trees",
                                                               "pinned-upstream-source-and-build-inputs"]),
                             phases=[dict(name=name, status="unreached", exitCode=None) for name in PHASES])

    def save(self):
        pending = self.root / "phases.pending.json"
        with pending.open("x") as stream:
            stream.write(json.dumps(self.manifest, sort_keys=True) + "\n")
        pending.replace(self.root / "phases.json")

    def command(self, argv, *, cwd=REPO):
        installed_java.clean_checkout(REPO, self.source_sha)
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
                        raise TypeError("phase did not return process status")
                except (Exception, SystemExit):
                    traceback.print_exc()
                    code = 2
        row.update(status="passed" if code == 0 else "failed", exitCode=code)
        self.save()
        try:
            self.privacy.snapshot(name, self.manifest)
            row["privacySnapshot"] = "recorded"
        except (OSError, ValueError, TypeError):
            row["privacySnapshot"] = "not-observed"
        self.save()
        return code

    def prerequisites(self):
        if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
            raise ValueError("development campaign needs hosted Linux x86_64")
        if (not re.fullmatch(r"[0-9a-f]{40}", self.source_sha) or not xcamp.HEX64.fullmatch(self.package_sha)
                or not self.java.is_absolute() or not self.java.is_file()
                or any(not shutil.which(name) for name in ("docker", "git", "sh"))):
            raise ValueError("campaign prerequisite unavailable")
        installed_java.clean_checkout(REPO, self.source_sha)
        self.manifest["sourceIdentityVerified"] = True
        if xcamp.sha256_file(self.input_archive) != self.package_sha:
            raise ValueError("input archive digest differs")
        shutil.copyfile(self.input_archive, self.archive)
        if xcamp.sha256_file(self.archive) != self.package_sha:
            raise ValueError("private archive copy differs")
        # Generated controls stay private; later snapshots scan only produced sinks.
        spec = importlib.util.spec_from_file_location("fineract_canary", REPO / "tools/qa/canary.py")
        canary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(canary)
        (self.root / "canaries.json").write_text(json.dumps(canary.make_canaries()) + "\n")
        return 0

    def verify_archive(self):
        installed_java.clean_checkout(REPO, self.source_sha)
        if xcamp.sha256_file(self.archive) != self.package_sha:
            raise ValueError("archive changed")
        report = installed_java.verifier().verify(self.archive, run=False)
        (self.root / "package-verification.json").write_text(json.dumps(report) + "\n")
        if (report.get("ok") is not True or report["package"]["sourceCommit"] != self.source_sha
                or report["package"]["platform"] != "linux-x86_64"):
            return 1
        report = installed_java.verifier().verify(self.archive, repo=REPO, run=True)
        (self.root / "package-runtime-verification.json").write_text(json.dumps(report) + "\n")
        return 0 if report.get("ok") is True else 1

    def install(self):
        if xcamp.sha256_file(self.archive) != self.package_sha or self.prefix.exists():
            raise ValueError("archive changed or prefix is not fresh")
        unpacked = installed_java.verifier().resolve_root(self.archive, self.root / "unpacked")
        return self.command(["sh", str(unpacked / "install.sh"), "--prefix", str(self.prefix),
                             "--data-home", str(self.root / "data")])

    def source_verify(self):
        xcamp.git_pin_check(self.source, self.campaign["upstream"]["sha"])
        license = self.campaign["license"]
        files = {license["file"]: license["sha256"], **license["otherFiles"]}
        if any(xcamp.sha256_file(self.source / name) != digest for name, digest in files.items()):
            raise ValueError("upstream license identity differs")
        return 0

    def collect_sinks(self):
        installed_java.clean_checkout(REPO, self.source_sha)
        return 0 if installed_sinks.collect(self.root, "fineract", self.privacy.capture, env=self.env) else 1

    def run(self):
        self.save()
        operations = (
            ("prerequisite", self.prerequisites), ("archive-verify", self.verify_archive),
            ("candidate-install", self.install),
            ("checkout-upstream", lambda: self.command(["sh", str(REPO / "tools/qa/camp_clone.sh"),
                                                       self.campaign["upstream"]["canonicalUrl"],
                                                       self.campaign["upstream"]["sha"], str(self.source)])),
            ("source-verify", self.source_verify),
            ("database-identity", lambda: self.command(["docker", "pull", "--platform", "linux/amd64",
                                                       self.campaign["runtime"]["databaseImage"]])),
            ("build-upstream", lambda: self.command(shlex.split(self.campaign["build"]["command"]), cwd=self.source)),
            ("baseline", lambda: self.command([sys.executable, "-B", str(HERE / "run.py"), "baseline"])),
            ("instrumented", lambda: self.command([sys.executable, "-B", str(HERE / "run.py"), "instrumented"])),
        )
        for name, operation in operations:
            code = self.phase(name, operation)
            if code:
                if name == "instrumented":
                    self.phase("collect-sinks", self.collect_sinks)
                return code
        return self.phase("collect-sinks", self.collect_sinks)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--java", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    code = 2
    status = "refused"
    try:
        root = args.private_root.absolute()
        installed_java.private_dir(root.parent)
        root.mkdir(mode=0o700, exist_ok=False)
        for relative in ("console", "package", "unpacked", "home", "data", "tmp", "child-stderr", "campaign",
                         "campaign/java", "campaign/java/fineract"):
            (root / relative).mkdir(mode=0o700)
        privacy.mark_admitted(root)
        code = InstalledCampaign(root, args.archive, args.package_sha256, args.source_sha, args.java).run()
        status = "incomplete" if code else "completed-development"
    except (Exception, SystemExit):
        # Root admission can itself fail. Never echo paths, exception text or raw logs.
        pass
    print(json.dumps(dict(schema="xtrace-fineract-driver-status/1", status=status, nonRelease=True,
                          releaseAcceptance=False, publication="withheld", privacy="requires-finalization")))
    return code if code >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
