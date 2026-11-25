#!/usr/bin/env python3
"""Publish only bounded JHipster counts/statuses after scanning the actual private sinks.

Raw receipts, IDs, exception text, paths and process output never enter the public tree.
The saved-recording artifact is a private ZIP of observed API JSON, not an export bundle.
"""
from __future__ import annotations

import argparse
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from tools.qa import camp_publication, canary  # noqa: E402
from campaigns.lib.private_diagnostic import root_admitted  # noqa: E402

PHASES = ("prerequisite", "package-verify", "candidate-install", "installed-verify", "checkout-upstream",
          "build-upstream", "baseline", "instrumented", "collect-sinks")
SCENARIOS = (
    ("anonymous-and-invalid-login-denied", 3, 4), ("admin-and-user-authentication", 5, 6),
    ("account-create-read-roundtrip", 3, 5), ("account-validation-errors", 4, 5),
    ("account-update-and-missing", 4, 5), ("operation-with-relations", 4, 4),
    ("concurrent-isolation", 49, 4), ("delete-and-not-found", 5, 6),
)
CANARY_KINDS = canary.KINDS[:5]
MAX_JSON_BYTES = 16 << 20
MAX_SCAN_FILES = 8192
MAX_SCAN_BYTES = 1 << 30
MAX_SCAN_FILE_BYTES = 64 << 20
MAX_COUNT = 1_000_000
DIAGNOSTIC_STATUSES = (
    "ciphertext-prepared", "not-required", "gap-recipient-unavailable", "gap-stderr-unavailable",
    "gap-stderr-oversized", "gap-encryption-failed", "gap-invalid-failure-state",
)
CHILD_STDERR_LABELS = ("host-java", "installed-payload-verify", "init", "recording-list", "stop")


def read_object(path):
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        return None, "invalid"
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            return None, "invalid"
        value = camp_publication.read(path)
        return value, "present"
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None, "invalid"


def count(value):
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def verdict(value):
    return "passed" if value is True else "failed" if value is False else "not-observed"


def phase_summary(doc):
    raw = doc.get("phases", []) if isinstance(doc, dict) and doc.get("schema") == "xtrace-jhipster-phases/1" else []
    rows = raw if isinstance(raw, list) else []
    out = []
    for name in PHASES:
        matches = [r for r in rows if isinstance(r, dict) and r.get("name") == name]
        row = matches[0] if len(matches) == 1 else {}
        code = row.get("exitCode")
        valid_exit = type(code) is int and -255 <= code <= 255
        status = row.get("status")
        valid = ((status == "passed" and valid_exit and code == 0)
                 or (status == "failed" and valid_exit and code != 0)
                 or (status == "unreached" and code is None))
        out.append({"name": name, "status": status if valid else "invalid" if row else "unreached",
                    "exitCode": code if valid_exit else None})
    return out


def receipt_summary(doc, state, instrumented):
    valid = (isinstance(doc, dict) and doc.get("project") == "jhipster"
             and doc.get("instrumented") is instrumented and doc.get("releaseAcceptance") is False)
    if not valid:
        return {"status": state if state != "present" else "invalid", "scenarios": []}
    rows = doc.get("scenarios", [])
    if not isinstance(rows, list):
        return {"status": "invalid", "scenarios": []}
    scenarios = []
    for sid, requests, checks in SCENARIOS:
        matches = [r for r in rows if isinstance(r, dict) and r.get("id") == sid]
        row = matches[0] if len(matches) == 1 else {}
        sent = row.get("requests", [])
        observed = len(sent) if isinstance(sent, list) else None
        check_rows = row.get("workloadChecks" if instrumented else "checks", [])
        check_rows = check_rows if isinstance(check_rows, list) else []
        checks_passed = sum(isinstance(c, dict) and c.get("passed") is True for c in check_rows)
        work = row.get("scenarioChecksPassed" if instrumented else "passed")
        scenarios.append({"id": sid, "expectedRequests": requests, "observedRequests": count(observed),
                          "expectedChecks": checks, "observedChecks": count(len(check_rows)),
                          "checksPassed": checks_passed, "workload": verdict(work),
                          "recording": verdict((row.get("recordingVerdict") or {}).get("passed"))
                          if isinstance(row.get("recordingVerdict", {}), dict) else "not-observed",
                          "fingerprintMatchesBaseline": verdict(row.get("fingerprintEqualsBaseline"))
                          if instrumented else "not-applicable"})
    result = doc.get("result")
    expected = "recorded" if instrumented else "passed_baseline_only"
    return {"status": "present", "result": "passed" if result == expected else "failed",
            "scenarios": scenarios}


def scan_sinks(root, values):
    project = root / "campaign" / "java" / "jhipster" / "instrumented-1"
    phase_snapshots = list(islice(project.glob("phase-*-api"), MAX_SCAN_FILES + 1))
    locations = {"storage": [root / "data"], "api-json": [project / "api"],
                 # Live boundary reads survive a failed final read and have their own availability.
                 "boundary-api-json": [project / "boundary-before", *phase_snapshots],
                 "cli-output": [root / "sinks" / "cli"],
                 "recording-artifact": [root / "sinks" / "recordings.zip"],
                 "application-output": [project / "application.log"], "viewer-output": [project / "viewer.log"],
                 "boundary-viewer-output": [project / "boundary-viewer.log"],
                 "child-stderr": [root / "child-stderr"],
                 "outer-driver-output": [root.parent / "driver/stdout", root.parent / "driver/stderr"],
                 "console-output": [root / "console"]}
    statuses = {}
    for cls, targets in locations.items():
        files = []
        invalid = len(targets) > MAX_SCAN_FILES
        visited = 0
        try:
            for target in targets:
                if invalid:
                    break
                if target.is_symlink() or any(p.is_symlink() for p in target.parents):
                    invalid = True
                elif target.is_file():
                    files.append(target)
                elif target.is_dir():
                    for path in target.rglob("*"):
                        visited += 1
                        if visited > MAX_SCAN_FILES:
                            invalid = True
                            break
                        if path.is_symlink():
                            invalid = True
                        elif path.is_file():
                            files.append(path)
                        elif not path.is_dir():
                            invalid = True
                        if len(files) > MAX_SCAN_FILES:
                            invalid = True
                            break
                if invalid:
                    break
            sizes = [p.stat().st_size for p in files]
            if (len(files) > MAX_SCAN_FILES or sum(sizes) > MAX_SCAN_BYTES
                    or any(size > MAX_SCAN_FILE_BYTES for size in sizes)):
                invalid = True
            if invalid:
                statuses[cls] = {"status": "scan-bound-or-unsafe-entry", "files": count(len(files)), "hitClasses": 0}
                continue
            if not any(sizes):
                statuses[cls] = {"status": "not-observed", "files": len(files), "hitClasses": 0}
                continue
            if not values:
                statuses[cls] = {"status": "canaries-unavailable", "files": 0, "hitClasses": 0}
                continue
            report = canary.run_scan(values, {cls: targets}, {cls: 1})
            # Detailed scanner diagnostics also contain only names/counts, but remain private.
            camp_publication.write(root / ("privacy-" + cls + ".json"), report)
            statuses[cls] = {"status": "failed" if report["hits"] else "not-observed" if report["uncovered"] else "passed",
                             "files": sum(row["files"] for row in report["scanned"]),
                             "hitClasses": len(report["hits"])}
        except (OSError, ValueError, TypeError):
            statuses[cls] = {"status": "scan-error", "files": 0, "hitClasses": 0}
    child = statuses["child-stderr"]
    captures = child_stderr_states(root)
    child["captureStates"] = captures
    child["scope"] = "captured-stderr-only"
    child["stdout"] = "not-retained-by-existing-tools"
    if child["status"] == "not-observed" and not any(captures.values()) and child["files"] == 0:
        child["status"] = "not-produced"
    elif child["status"] in ("passed", "not-observed"):
        if captures["invalid"] or captures["missing"]:
            child["status"] = "gap-child-capture-status"
        elif captures["unavailable"]:
            child["status"] = "gap-stderr-unavailable"
        elif captures["oversized"]:
            child["status"] = "gap-stderr-oversized"
    outer = statuses["outer-driver-output"]
    if outer["status"] == "not-observed" and outer["files"] == 0:
        outer["status"] = "not-produced" if driver_status(root)["status"] == "unreached" else "gap-driver-output-unavailable"
    return statuses


def child_stderr_states(root):
    """Keep capture gaps distinct from a successful run that produced no child stderr."""
    folder = root / "child-stderr"
    counts = {name: 0 for name in ("captured", "unavailable", "oversized", "missing", "invalid")}
    expected = {f"{phase}-{label}.{suffix}" for phase in ("baseline", "instrumented")
                for label in CHILD_STDERR_LABELS for suffix in ("json", "stderr")}
    try:
        if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
            counts["invalid"] = 1
            return counts
        if not folder.exists():
            return counts
        entries = list(islice(folder.iterdir(), MAX_SCAN_FILES + 1))
        counts["invalid"] = sum(path.name not in expected for path in entries)
        for phase in ("baseline", "instrumented"):
            for label in CHILD_STDERR_LABELS:
                doc, state = read_object(folder / f"{phase}-{label}.json")
                stderr = folder / f"{phase}-{label}.stderr"
                if state == "missing":
                    counts["invalid"] += int(stderr.exists() or stderr.is_symlink())
                    continue
                code = doc.get("exitCode") if doc else None
                capture = doc.get("stderrState") if doc else None
                valid = (doc and doc.get("schema") == "xtrace-private-child-stderr/1"
                         and doc.get("phase") == phase and doc.get("child") == label
                         and type(doc.get("timedOut")) is bool
                         and ((type(code) is int and -255 <= code <= 255 and code != 0)
                              or (code is None and doc["timedOut"] is True))
                         and isinstance(capture, str) and capture in ("captured", "unavailable", "oversized"))
                if not valid:
                    counts["invalid"] += 1
                else:
                    counts[capture] += 1
                    if capture == "captured" and not stderr.is_file():
                        counts["missing"] += 1
                    elif capture != "captured" and (stderr.exists() or stderr.is_symlink()):
                        counts["invalid"] += 1
    except OSError:
        counts["invalid"] += 1
    return counts


def injection_summary(instrumented, values):
    notes = instrumented.get("notes", {}) if isinstance(instrumented, dict) else {}
    probes = notes.get("canaryProbes", []) if isinstance(notes, dict) else []
    probes = probes if isinstance(probes, list) else []
    output = []
    for kind in canary.KINDS:
        rows = [p for p in probes if isinstance(p, dict) and isinstance(p.get("surfaces"), list)
                and kind in p["surfaces"]]
        delivered = any((type(p.get("status")) is int and 100 <= p["status"] <= 599)
                        or (kind == "env-var" and p.get("label") == "environment" and p.get("passed") is True)
                        for p in rows)
        output.append({"kind": kind, "generated": bool(values and kind in values),
                       "delivery": "observed" if delivered else "not-exercised" if kind not in CANARY_KINDS else "not-observed",
                       "recordingAttribution": "not-applicable" if kind == "env-var" else
                       verdict(all(p.get("passed") is True for p in rows)) if rows else "not-observed"})
    return output


def driver_status(root):
    doc, state = read_object(root.parent / "driver/status.json")
    code = doc.get("exitCode") if doc else None
    valid = (doc and doc.get("schema") == "xtrace-jhipster-driver/1"
             and type(code) is int and -255 <= code <= 255)
    return {"status": ("passed" if code == 0 else "failed") if valid
            else "unreached" if state == "missing" else "not-observed" if doc
            and doc.get("schema") == "xtrace-jhipster-driver/1" and code is None else "invalid",
            "exitCode": code if valid else None}


def outer_build_status(root):
    doc, state = read_object(root.parent / "package-build/status.json")
    code = doc.get("exitCode") if doc else None
    valid = (doc and doc.get("schema") == "xtrace-jhipster-build/1"
             and type(code) is int and -255 <= code <= 255)
    return {"status": ("passed" if code == 0 else "failed") if valid else "unreached" if state == "missing" else "invalid",
            "exitCode": code if valid else None}


def diagnostic_retention(root, *, root_available=True):
    """Project the private retention report through fixed enums and bounded numeric fields."""
    root_available = root_available and root_admitted(root)
    doc, state = read_object(root.parent / "diagnostic-status.json")
    if state == "missing" and root_available:
        doc, state = read_object(root / "diagnostic-status.json")
    external = state == "missing" and driver_status(root)["status"] == "failed"
    if external:
        doc, state = read_object(root.parent / "driver/diagnostic-status.json")
    output = {"status": "not-observed" if state == "missing" else "invalid", "phase": None,
              "exitCode": None, "retainedStderrStreams": 0,
              "deeperDiagnostics": "not-retained-by-existing-tools"}
    if (not doc or doc.get("schema") != "xtrace-jhipster-diagnostic-retention/1"
            or (not root_available and doc.get("status") not in ("not-required", "gap-invalid-failure-state")
                and not ((doc.get("phase") == "driver" and driver_status(root)["status"] == "failed")
                         or (doc.get("phase") == "package-build" and outer_build_status(root)["status"] == "failed")))):
        return output
    status, phase = doc.get("status"), doc.get("phase")
    code, streams = doc.get("exitCode"), doc.get("retainedStderrStreams")
    if not isinstance(status, str) or status not in DIAGNOSTIC_STATUSES or type(streams) is not int:
        return output
    if status in ("not-required", "gap-invalid-failure-state"):
        valid = phase is None and code is None and streams == 0
    else:
        valid = (isinstance(phase, str) and phase in ("driver", "package-build", *PHASES[:-1])
                 and type(code) is int and -255 <= code <= 255 and code != 0
                 and (1 <= streams <= 6 if status == "ciphertext-prepared" else streams == 0))
    if valid:
        output.update(status=status, phase=phase, exitCode=code, retainedStderrStreams=streams)
    return output


def build_summary(root):
    try:
        info = root.lstat()
        root_state = "available" if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                                    and not info.st_mode & 0o077 and not any(p.is_symlink() for p in root.parents)) else "unsafe"
        if root_state == "available" and not root_admitted(root):
            root_state = "unadmitted"
    except FileNotFoundError:
        root_state = "missing"
    if root_state != "available":
        # A refused root is never read. Its outer driver can still report bounded failure facts.
        return {"schema": "xtrace-jhipster-installed-public/1", "project": "jhipster", "nonRelease": True,
                "releaseAcceptance": False, "privateRoot": root_state, "outerDriver": driver_status(root),
                "diagnosticRetention": diagnostic_retention(root, root_available=False),
                "packageBuild": outer_build_status(root), "phases": phase_summary(None),
                "baseline": {"status": "not-observed", "scenarios": []},
                "instrumented": {"status": "not-observed", "scenarios": []}}, None
    phases, _ = read_object(root / "phases.json")
    base = root / "campaign" / "java" / "jhipster"
    baseline, baseline_state = read_object(base / "baseline-1" / "receipt.json")
    instrumented, instrumented_state = read_object(base / "instrumented-1" / "receipt.json")
    package, package_state = read_object(root / "package-verification.json")
    build, build_state = read_object(root / "build-status.json")
    values, _ = read_object(root / "canaries.json")
    if (not values or set(values) - set(canary.KINDS)
            or any(not isinstance(values.get(k), str) or not 12 <= len(values[k]) <= 1024 for k in CANARY_KINDS)
            or any(not isinstance(v, str) or not 12 <= len(v) <= 1024 for v in values.values())
            or len(set(values.values())) != len(values)):
        values = None
    cli, _ = read_object(root / "sinks" / "cli-status.json")
    phases_out = phase_summary(phases)
    api = instrumented.get("api", {}) if isinstance(instrumented, dict) else {}
    api = api if isinstance(api, dict) else {}
    summary = {"schema": "xtrace-jhipster-installed-public/1", "project": "jhipster", "nonRelease": True,
               "releaseAcceptance": False, "phases": phases_out,
               "expected": {"scenarios": 8, "requests": 77, "checks": 39},
               "baseline": receipt_summary(baseline, baseline_state, False),
               "instrumented": receipt_summary(instrumented, instrumented_state, True),
               "packageVerification": "passed" if isinstance(package, dict)
               and package.get("schema") == "xtrace-package-verification/1" and package.get("ok") is True
               else "failed" if package_state == "present" else package_state,
               "api": {"collection": verdict(api.get("ok")), "recordings": count(api.get("recordings")),
                       "incompleteDetails": count(api.get("incompleteDetails")),
                       "listReadGap": (False if api["listReadGap"] is None else True
                                       if isinstance(api["listReadGap"], str) and api["listReadGap"]
                                       else None) if api and "listReadGap" in api else None},
               "cli": {"collection": verdict(cli.get("complete")) if cli else "not-observed",
                       "recordings": count(cli.get("recordings")) if cli else None},
               "savedRecordingArtifact": verdict(cli.get("artifactComplete")) if cli else "not-observed",
               "artifactScope": "saved-api-json-only", "exportBundle": "not-exercised",
               "individualBurstCorrelation": "not-observed", "privacy": scan_sinks(root, values),
               "scannerScope": "raw-and-common-encodings-plus-supported-containers-depth-two"}
    summary["canaryInjection"] = injection_summary(instrumented, values)
    summary["privateRoot"] = root_state
    summary["outerDriver"] = driver_status(root)
    summary["diagnosticRetention"] = diagnostic_retention(root)
    code = build.get("exitCode") if build else None
    code_valid = type(code) is int and -255 <= code <= 255
    build_valid = build and build.get("schema") == "xtrace-jhipster-build/1" and code_valid
    summary["packageBuild"] = {"status": ("passed" if code == 0 else "failed") if build_valid
                               else "unreached" if build_state == "missing" else "invalid",
                               "exitCode": code if code_valid else None}
    summary["instrumentedChecks"] = {
        key: verdict(instrumented.get(key)) if isinstance(instrumented, dict) else "not-observed"
        for key in ("workloadsPassed", "boundariesVerified", "baselineMatched", "recordingChecksPassed")
    }
    if phases:
        for key, pattern in (("sourceCommit", r"[0-9a-f]{40}"), ("packageSha256", r"[0-9a-f]{64}")):
            value = phases.get(key)
            summary[key] = value if isinstance(value, str) and re.fullmatch(pattern, value) else None
    # Only a fixed taxonomy survives; arbitrary source problem strings never become public labels.
    problem_classes = instrumented.get("problemClasses", {}) if isinstance(instrumented, dict) else {}
    problem_classes = problem_classes if isinstance(problem_classes, dict) else {}
    taxonomy = {
        "preDispatch": lambda k: k.startswith("pre-dispatch-"),
        "postgresql": lambda k: k == "postgresql-boundary-unobserved" or k.startswith("jdbc-operation-unobserved("),
        "burst": lambda k: k.startswith("burst-") or k == "individual-request-and-principal-attribution-unobserved",
    }
    judged_rows = instrumented.get("scenarios", []) if isinstance(instrumented, dict) else []
    judge_observed = (isinstance(judged_rows, list) and any(
        isinstance(row, dict) and isinstance(row.get("recordingVerdict"), dict)
        and isinstance(row["recordingVerdict"].get("expectations"), list)
        and bool(row["recordingVerdict"]["expectations"]) for row in judged_rows))
    summary["recordingJudgement"] = "observed" if judge_observed else "not-observed"
    summary["recordingGapProblemCounts"] = {
        name: min(MAX_COUNT, sum(count(v) or 0 for k, v in problem_classes.items() if isinstance(k, str) and match(k)))
        if judge_observed else None for name, match in taxonomy.items()
    }
    summary["recordingGapCountLimit"] = MAX_COUNT
    return summary, values


def publish(root, public):
    if public.exists() or public.is_symlink():
        raise ValueError("public destination must be new")
    summary, values = build_summary(root)
    clear = False
    with tempfile.TemporaryDirectory(prefix="jhipster-public-", dir=public.parent) as temp:
        stage = Path(temp) / "output"
        stage.mkdir(mode=0o700)
        summary["publication"] = "passed"
        camp_publication.write(stage / "summary.json", summary)
        if values:
            report = canary.run_scan(values, {"upload-tree": [stage]}, {"upload-tree": 1})
            camp_publication.write(root / "privacy-final-upload.json", report)
            clear = report["clean"]
        if not clear:
            # Regenerate a constant fallback; even a digest matching an injected value is withheld.
            camp_publication.write(stage / "summary.json", {"schema": "xtrace-jhipster-installed-public/1",
                                   "project": "jhipster", "nonRelease": True, "releaseAcceptance": False,
                                   "publication": "withheld", "privacy": "final-scan-unavailable-or-failed",
                                   "packageBuild": summary["packageBuild"], "phases": summary["phases"],
                                   "diagnosticRetention": summary["diagnosticRetention"],
                                   "outerDriver": summary["outerDriver"], "privateRoot": summary["privateRoot"],
                                   "baseline": {"status": summary["baseline"]["status"]},
                                   "instrumented": {"status": summary["instrumented"]["status"]}})
        stage.rename(public)
    receipts_ok = all(summary[key].get("status") == "present" and summary[key].get("result") == "passed"
                      and all(row["workload"] == "passed" and row["observedRequests"] == row["expectedRequests"]
                              and row["observedChecks"] == row["expectedChecks"]
                              and row["checksPassed"] == row["expectedChecks"] for row in summary[key]["scenarios"])
                      for key in ("baseline", "instrumented"))
    return (clear and receipts_ok and summary["outerDriver"] == {"status": "passed", "exitCode": 0}
            and summary["packageVerification"] == "passed"
            and summary["packageBuild"]["status"] == "passed"
            and all(row["status"] == "passed" for row in summary["phases"])
            and all(row["status"] == "passed" or (name in ("child-stderr", "outer-driver-output")
                                                   and row["status"] == "not-produced")
                    for name, row in summary["privacy"].items())
            and all(value == "passed" for value in summary["instrumentedChecks"].values())
            and all(row["delivery"] == "observed" for row in summary["canaryInjection"] if row["kind"] in CANARY_KINDS)
            and summary["api"]["collection"] == "passed" and (summary["api"]["recordings"] or 0) > 0
            and summary["api"]["incompleteDetails"] == 0 and summary["api"]["listReadGap"] is False
            and summary["cli"]["collection"] == "passed" and summary["savedRecordingArtifact"] == "passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--public-out", required=True, type=Path)
    args = parser.parse_args()
    try:
        ok = publish(args.private_root, args.public_out)
    except (OSError, ValueError, TypeError, AttributeError):
        print("JHipster bounded publication failed")
        return 1
    print("JHipster bounded publication: " + ("complete" if ok else "gaps-or-failure"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
