#!/usr/bin/env python3
"""Inventory private sinks and emit one allowlisted, canary-scanned status file.

Run finalization only after installed.py and its outer output files are closed.
The generated canary control and original probe inputs intentionally contain the
values under test; they are not product sinks and never enter the public output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import subprocess

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "campaigns/lib"))
import installed_java  # noqa: E402
from private_sinks import AdmittedSinks, STATUSES, valid_canaries  # noqa: E402
from tools.qa import canary  # noqa: E402
from campaigns.java.fineract.harness.recording_evidence import PROBES, PROBE_STATUSES, RECORDABLE_PROBES  # noqa: E402

PHASES = ("prerequisite", "archive-verify", "candidate-install", "checkout-upstream", "source-verify",
          "database-identity", "build-upstream", "baseline", "instrumented", "collect-sinks")
SCENARIOS = (
    ("denied-without-valid-credentials", 3, 4), ("authenticated-seed-read", 3, 4),
    ("client-create-read-roundtrip", 2, 3), ("client-validation-errors", 3, 4),
    ("client-update", 2, 3), ("client-activate-command", 3, 4),
    ("concurrent-isolation", 40, 3), ("delete-and-not-found", 5, 6),
)
REQUIRED_CANARIES = canary.KINDS[:5]
CLASSES = ("console-output", "baseline-output", "storage", "api-json", "boundary-api-json", "application-output",
           "viewer-output", "boundary-viewer-output", "launcher-output", "child-stderr", "cli-output", "recording-artifact",
           "outer-driver-output", "capture-output", "project-pointer", "campaign-metadata", "package-verification",
           "home-output", "privacy-reports", "other-generated-output", "install-receipt")
OPTIONAL_CLASSES = frozenset(("child-stderr", "home-output", "privacy-reports", "other-generated-output"))
SCOPE_GAPS = ("valid-authorization-recording-not-exercised", "environment-recording-not-exercised",
              "focused-capture-not-exercised")
SEAMS = {
    "root": ("exact-route-root-unobserved", "servlet-invocation-seam-unobserved"),
    "jersey": ("jersey-resource-method-unobserved", "jersey-invocation-seam-unobserved"),
    "source": ("resource-source-unobserved",),
    "command": ("command-pipeline-unobserved", "client-write-service-unobserved"),
    "exception": ("exception-type-unobserved", "jersey-exception-mapper-unobserved"),
    "jdbc": ("pgjdbc-boundary-unobserved", "required-sql-operation-unobserved"),
    "isolation": ("individual-isolation-unobserved", "recording-attribution-unavailable", "burst-boundary-unverified"),
}


def write(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def read(path):
    installed_java.private_file(path)
    if path.stat().st_size > 16 << 20:
        raise ValueError("private JSON bound exceeded")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("private JSON is not an object")
    return value


def maybe_read(path):
    try:
        return read(path)
    except (OSError, ValueError, TypeError):
        return None


def mark_admitted(root):
    installed_java.private_dir(root)
    directory = installed_java.private_dir(root.parent / "driver")
    observed = root.lstat()
    parent = root.parent.lstat()
    write(directory / "admission.json", dict(schema="xtrace-fineract-admission/1", device=observed.st_dev,
                                           inode=observed.st_ino, parentDevice=parent.st_dev, parentInode=parent.st_ino))


def admitted(root):
    try:
        installed_java.private_dir(root)
        doc = read(root.parent / "driver/admission.json")
        info, parent = root.lstat(), root.parent.lstat()
        return doc == dict(schema="xtrace-fineract-admission/1", device=info.st_dev, inode=info.st_ino,
                           parentDevice=parent.st_dev, parentInode=parent.st_ino)
    except (OSError, ValueError, TypeError):
        return False


def count(value):
    return min(value, 1_000_000) if type(value) is int and value >= 0 else None


def verdict(value):
    return "passed" if value is True else "failed" if value is False else "not-observed"


def phase_rows(doc):
    raw = doc.get("phases", []) if isinstance(doc, dict) and doc.get("schema") == "xtrace-fineract-installed-phases/1" else []
    result = []
    for name in PHASES:
        matches = [row for row in raw if isinstance(row, dict) and row.get("name") == name] if isinstance(raw, list) else []
        row = matches[0] if len(matches) == 1 else {}
        status, code = row.get("status"), row.get("exitCode")
        valid = (status == "unreached" and code is None or status in ("passed", "failed")
                 and type(code) is int and -255 <= code <= 255 and (status == "passed") == (code == 0))
        result.append(dict(name=name, status=status if valid else "not-observed", exitCode=code if valid else None))
    return result


def upstream_build_summary(doc, phases):
    """Project a bounded task/expected-jar verdict without console text or paths."""
    unknown = {"status": "not-observed", "commandExitCode": None}
    build = doc.get("upstreamBuild") if isinstance(doc, dict) else None
    phase = next(row for row in phases if row["name"] == "build-upstream")
    if not isinstance(build, dict) or set(build) != {"status", "commandExitCode"}:
        return unknown
    status, code = build["status"], build["commandExitCode"]
    valid_code = type(code) is int and -255 <= code <= 255
    if phase["status"] == "passed":
        valid = status == "artifact-present" and valid_code and code == 0
    elif phase["status"] == "failed":
        valid = (status == "command-failed" and valid_code and code != 0 and code == phase["exitCode"]
                 or status == "expected-jar-missing" and valid_code and code == 0 and phase["exitCode"] == 1
                 or status == "artifact-preexisting" and code is None and phase["exitCode"] == 1)
    else:
        valid = False
    return {"status": status, "commandExitCode": code} if valid else unknown


def injection_rows(probes, generated):
    """Project only fixed probe classes; a response alone never proves a probe passed."""
    probes = probes if isinstance(probes, list) else []
    output = []
    for kind in canary.KINDS:
        expected = [(label, surfaces) for label, _, _, surfaces in PROBES if kind in surfaces]
        delivered, attributed, positive = [], [], []
        for label, surfaces in expected:
            rows = [p for p in probes if isinstance(p, dict) and p.get("label") == label]
            row = rows[0] if len(rows) == 1 else {}
            delivery = (type(row.get("status")) is int and row["status"] == PROBE_STATUSES[label]
                        and row.get("surfaces") == list(surfaces))
            passed = (delivery and row.get("passed") is True and type(row.get("recordings")) is int
                      and row["recordings"] == 1 and row.get("problems") == [])
            delivered.append(delivery)
            attributed.append(passed)
            if label in RECORDABLE_PROBES:
                positive.append(passed)
        if kind == "env-var":
            rows = [p for p in probes if isinstance(p, dict) and p.get("label") == "environment"]
            delivery = (len(rows) == 1 and rows[0].get("surfaces") == [kind]
                        and rows[0].get("passed") is True and rows[0].get("problems") == [])
            output.append(dict(kind=kind, generated=generated, delivery="observed" if delivery else "not-observed",
                               recordingAttribution="not-applicable", recordableSurface="not-exercised"))
        else:
            output.append(dict(kind=kind, generated=generated,
                               delivery="observed" if delivered and all(delivered) else
                               "not-exercised" if not expected else "not-observed",
                               recordingAttribution=verdict(all(attributed)) if attributed else "not-observed",
                               recordableSurface=verdict(all(positive)) if positive else
                               "denied-only" if expected else "not-exercised"))
    return output


class PrivacyEvidence:
    def __init__(self, root):
        if not admitted(root):
            raise ValueError("campaign root was not admitted")
        self.root = root
        self.sinks = AdmittedSinks(root)
        self.outer = AdmittedSinks(root.parent)
        self.capture = root / "campaign/java/fineract/instrumented-1/capture"
        self.folder = root / "privacy"
        self.folder.mkdir(mode=0o700, exist_ok=True)

    def values(self):
        values = maybe_read(self.root / "canaries.json")
        return values if valid_canaries(values) else None

    def scan(self, phases, *, final=False):
        self.sinks.check_root()
        states = {row["name"]: row["status"] for row in phase_rows(phases)}
        root, capture = self.root, self.capture
        locations = {
            "console-output": ([root / "console"], "prerequisite", False),
            "baseline-output": ([root / "campaign/java/fineract/baseline-1"], "baseline", False),
            "storage": ([root / "data"], "instrumented", False),
            "api-json": ([capture / "api"], "instrumented", False),
            "boundary-api-json": ([capture / "boundary-before", *[capture / f"phase-{i}-api" for i in (1, 2, 3)]],
                                  "instrumented", False),
            "application-output": ([capture / "application.log"], "instrumented", False),
            "viewer-output": ([capture / "viewer.log"], "instrumented", False),
            "boundary-viewer-output": ([capture / "boundary-viewer.log"], "instrumented", False),
            "launcher-output": ([root / "tmp"], "instrumented", False),
            "child-stderr": ([root / "child-stderr"], "baseline", True),
            "cli-output": ([root / "sinks/cli"], "collect-sinks", False),
            "recording-artifact": ([root / "sinks/recordings.zip"], "collect-sinks", False),
            # Capture includes receipt.json and any future produced file, not just
            # the API page subset. The verified immutable package is outside it.
            "capture-output": ([capture], "instrumented", False),
            "project-pointer": ([root / "campaign/java/fineract/src/.xtrace"], "instrumented", False),
            "campaign-metadata": ([root / "phases.json"], "prerequisite", False),
            "package-verification": ([root / "package-verification.json", root / "package-runtime-verification.json"],
                                     "archive-verify", False),
            "install-receipt": ([root / "installed X-trace/install-receipt.json"], "candidate-install", False),
            "home-output": ([root / "home"], "prerequisite", True),
            "privacy-reports": ([root / "privacy"], "prerequisite", True),
        }
        # Known input/immutable trees are excluded explicitly. Any new top-level
        # generated output is scanned by default rather than silently forgotten.
        excluded = {"canaries.json", "package", "unpacked", "installed X-trace", "campaign", "console", "data", "tmp",
                    "child-stderr", "sinks", "privacy", "home", "phases.json", "package-verification.json",
                    "package-runtime-verification.json"}
        other, other_error = [], False
        try:
            other = [p for p in root.iterdir() if p.name not in excluded]
            # Validate every ancestor before enumerating; never follow a replaced
            # directory outside the admitted root even to discover filenames.
            for directory, known in ((root / "sinks", {"cli", "recordings.zip"}),
                                     (root / "campaign/java/fineract", {"src", "baseline-1", "instrumented-1"}),
                                     (capture.parent, {"capture", "verified-package"}),
                                     (root / "installed X-trace", {"bin", "versions", "current", "install-receipt.json"}),
                                     (root / "installed X-trace/bin", {"xtrace"})):
                if directory.exists() or directory.is_symlink():
                    installed_java.private_dir(directory)
                    other.extend(p for p in directory.iterdir() if p.name not in known)
        except (OSError, ValueError):
            other_error = True
        locations["other-generated-output"] = (other, "prerequisite", True)
        values, statuses, details = self.values(), {}, {}
        for name, (targets, phase, optional) in locations.items():
            if states[phase] in ("unreached", "not-observed") and not any(p.exists() or p.is_symlink() for p in targets):
                statuses[name] = dict(status="unreached", files=0, bytes=0, hitClasses=0)
                continue
            statuses[name], details[name] = self.sinks.scan(targets, values, optional=optional)
        if other_error:
            statuses["other-generated-output"] = dict(status="unsafe-or-bound", files=0, bytes=0, hitClasses=0)
        if final:
            statuses["outer-driver-output"], details["outer-driver-output"] = self.outer.scan(
                [root.parent / "driver"], values)
        else:
            statuses["outer-driver-output"] = dict(status="unreached", files=0, bytes=0, hitClasses=0)
        # Readability alone cannot establish complete API/CLI collection.
        receipt = maybe_read(capture / "receipt.json")
        api = receipt.get("api", {}) if isinstance(receipt, dict) else {}
        cli = maybe_read(root / "sinks/cli-status.json")
        complete_api = (isinstance(api, dict) and api.get("ok") is True and type(api.get("incompleteDetails")) is int and api["incompleteDetails"] == 0
                        and "listReadGap" in api and api["listReadGap"] is None and type(api.get("recordings")) is int and api["recordings"] > 0)
        valid_cli = (isinstance(cli, dict) and cli.get("schema") == "xtrace-fineract-cli-sinks/1"
                     and type(cli.get("recordings")) is int and cli["recordings"] > 0
                     and isinstance(cli.get("commandExits"), list) and bool(cli["commandExits"])
                     and all(type(code) is int and code == 0 for code in cli["commandExits"]))
        collection = dict(api=verdict(complete_api), cli=verdict(valid_cli and cli.get("complete") is True),
                          savedArtifact=verdict(valid_cli and cli.get("artifactComplete") is True))
        notes = receipt.get("notes") if isinstance(receipt, dict) else None
        probes = notes.get("canaryProbes", []) if isinstance(notes, dict) else []
        injection = injection_rows(probes, values is not None)
        child = statuses["child-stderr"]
        if child["status"] in ("passed", "not-produced"):
            # Reuse the established capture-report validator; only fixed counts are projected.
            from campaigns.java.jhipster.harness.public_result import child_stderr_states
            captures = child_stderr_states(root)
            child["captureStates"] = captures
            if captures["missing"] or captures["invalid"] or captures["unavailable"] or captures["oversized"]:
                child["status"] = "scan-error"
        clean = (all(row["status"] == "passed" or name in OPTIONAL_CLASSES and row["status"] == "not-produced"
                     for name, row in statuses.items()) and all(row == "passed" for row in collection.values())
                 and values is not None and all(row["delivery"] == "observed" and
                     (row["recordingAttribution"] == "passed" or row["kind"] == "env-var")
                     for row in injection if row["kind"] in REQUIRED_CANARIES)
                 and all(row["recordableSurface"] == "passed" for row in injection
                         if row["kind"] in ("cookie-header", "query-token", "json-body-password")))
        return dict(schema="xtrace-fineract-private-scan/1", clean=clean, sinks=statuses, collection=collection,
                    canaryInjection=injection, inventory=details,
                    scopeComplete=False, scopeGaps=list(SCOPE_GAPS),
                    scannerScope="raw-common-encodings-supported-containers-depth-two")

    def snapshot(self, phase, phases):
        if phase not in PHASES:
            raise ValueError("unknown phase")
        report = self.scan(phases)
        report["phase"] = phase
        write(self.folder / f"phase-{phase}.json", report)
        return report


def workload(doc, instrumented):
    valid = (isinstance(doc, dict) and doc.get("schemaVersion") == 1
             and doc.get("kind") == ("instrumented_campaign_non_release" if instrumented else "uninstrumented_baseline_campaign_preparation")
             and doc.get("project") == "fineract"
             and doc.get("instrumented") is instrumented and doc.get("releaseAcceptance") is False)
    rows = doc.get("scenarios", []) if valid else []
    output = []
    for sid, expected_requests, expected_checks in SCENARIOS:
        matches = [r for r in rows if isinstance(r, dict) and r.get("id") == sid] if isinstance(rows, list) else []
        row = matches[0] if len(matches) == 1 else {}
        requests = row.get("requests", [])
        checks = row.get("workloadChecks" if instrumented else "checks", [])
        request_count = count(len(requests)) if row and isinstance(requests, list) else None
        check_count = count(len(checks)) if row and isinstance(checks, list) else None
        checked = sum(isinstance(c, dict) and c.get("passed") is True for c in checks) if isinstance(checks, list) else None
        passed = (row.get("scenarioChecksPassed" if instrumented else "passed") is True
                  and request_count == expected_requests and check_count == checked == expected_checks)
        recording = row.get("recordingVerdict")
        output.append(dict(id=sid, workload="passed" if passed else "failed" if row else "not-observed",
                           observedRequests=request_count, observedChecks=check_count,
                           expectedRequests=expected_requests, expectedChecks=expected_checks,
                           recording=verdict(recording.get("passed")) if isinstance(recording, dict) else "not-observed",
                           baselineMatch=verdict(row.get("fingerprintEqualsBaseline")) if instrumented else "not-applicable"))
    return output


def finalize(root, public):
    installed_java.private_dir(root)
    root = root.resolve(strict=True)
    installed_java.private_dir(public.parent)
    public = public.parent.resolve(strict=True) / public.name
    if public.exists() or public.is_symlink():
        raise ValueError("public destination must be fresh")
    installed_java.private_dir(public.parent)
    if public.is_relative_to(root):
        raise ValueError("public output must be separate from private run state")
    evidence = PrivacyEvidence(root)
    phases = maybe_read(root / "phases.json")
    report = evidence.scan(phases, final=True)
    history, history_clear = [], True
    for phase in phase_rows(phases):
        previous = maybe_read(root / f"privacy/phase-{phase['name']}.json") if phase["status"] != "unreached" else None
        valid = (isinstance(previous, dict) and previous.get("schema") == "xtrace-fineract-private-scan/1"
                 and previous.get("phase") == phase["name"] and isinstance(previous.get("sinks"), dict)
                 and set(previous["sinks"]) == set(CLASSES)
                 and all(isinstance(row, dict) and row.get("status") in STATUSES for row in previous["sinks"].values()))
        statuses = {name: previous["sinks"][name]["status"] for name in CLASSES} if valid else {}
        history.append(dict(name=phase["name"], inventory="recorded" if valid else "unreached" if phase["status"] == "unreached" else "not-observed",
                            sinks=statuses))
        if phase["status"] != "unreached" and (not valid or any(status in (
                "failed", "unsafe-or-bound", "changed", "scan-error", "canaries-unavailable") for status in statuses.values())):
            history_clear = False
    report["clean"] = report["clean"] and history_clear
    report["phaseInventories"] = history
    write(root / "privacy/final-sinks.json", report)
    receipt = maybe_read(evidence.capture / "receipt.json")
    baseline = maybe_read(root / "campaign/java/fineract/baseline-1/receipt.json")
    driver = maybe_read(root.parent / "driver/status.json")
    driver_code = driver.get("exitCode") if isinstance(driver, dict) and driver.get("schema") == "xtrace-fineract-driver/1" else None
    driver_code = driver_code if type(driver_code) is int and -255 <= driver_code <= 255 else None
    source = False if isinstance(phases, dict) and phases.get("sourceIdentityVerified") is False else None
    if (isinstance(phases, dict) and phases.get("schema") == "xtrace-fineract-installed-phases/1"
            and phases.get("sourceIdentityVerified") is True and isinstance(phases.get("sourceCommit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", phases["sourceCommit"])):
        try:
            installed_java.clean_checkout(REPO, phases["sourceCommit"])
            source = True
        except (OSError, ValueError, subprocess.SubprocessError):
            source = False
    observed_phases = phase_rows(phases)
    summary = dict(schema="xtrace-fineract-installed-public/1", project="fineract", nonRelease=True,
                   releaseAcceptance=False, publication="passed", sourceIdentity=verdict(source),
                   phases=observed_phases, upstreamBuild=upstream_build_summary(phases, observed_phases),
                   baseline=workload(baseline, False), instrumented=workload(receipt, True),
                   privacy=dict(status=verdict(report["clean"]), sinks=report["sinks"], collection=report["collection"],
                                canaryInjection=report["canaryInjection"], scannerScope=report["scannerScope"],
                                scopeComplete=report["scopeComplete"], scopeGaps=report["scopeGaps"],
                                phaseInventories=report["phaseInventories"]),
                   outerDriver=dict(status="passed" if driver_code == 0 else "failed" if type(driver_code) is int else "not-observed"),
                   individualIsolation="not-observed", artifactScope="saved-api-json-only", exportBundle="not-exercised",
                   browser="unreached", tui="unreached", restart="unreached", overhead="unreached")
    problems = receipt.get("problemClasses") if isinstance(receipt, dict) else None
    summary["seamGapCounts"] = {name: min(1_000_000, sum(value for key, value in problems.items()
                                                        if key in labels and type(value) is int and value >= 0))
                                if isinstance(problems, dict) and receipt else None for name, labels in SEAMS.items()}
    if isinstance(problems, dict) and receipt:
        classified = {label for labels in SEAMS.values() for label in labels}
        summary["seamGapCounts"]["unclassified"] = min(1_000_000, sum(value for key, value in problems.items()
            if key not in classified and type(value) is int and value >= 0))
    else:
        summary["seamGapCounts"]["unclassified"] = None
    values = evidence.values()
    data = (json.dumps(summary, sort_keys=True) + "\n").encode()
    hits = {}
    if values:
        canary.scan_bytes(data, canary.build_index(values), hits, "final-public-output")
    clear = values is not None and not hits
    if not clear:
        # This constant is smaller than every validated canary needle; no private field survives.
        data = b"{}\n"
    write(root / "privacy/final-output-scan.json", dict(clean=clear, bytes=len(data),
                                                       sha256=hashlib.sha256(data).hexdigest(), hitClasses=len(hits)))
    public.mkdir(mode=0o700)
    with (public / "summary.json").open("xb") as stream:
        stream.write(data)
    complete = (all(row["status"] == "passed" for row in summary["phases"])
                and all(row["workload"] == "passed" for row in summary["baseline"])
                and all(row["workload"] == "passed" and row["recording"] == "passed" and row["baselineMatch"] == "passed"
                        for row in summary["instrumented"]))
    return clear and report["clean"] and driver_code == 0 and source is True and complete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--public-out", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        ok = finalize(args.private_root.absolute(), args.public_out.absolute())
    except (OSError, ValueError, TypeError, KeyError):
        print("Fineract status projection withheld")
        return 1
    print("Fineract status projection: " + ("complete" if ok else "gaps-or-failure"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
