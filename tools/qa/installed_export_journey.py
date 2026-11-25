#!/usr/bin/env python3
"""Hosted Linux installed Spring/export proof, never a release-acceptance receipt.

Requires an enclosing job's fresh official installation of the digest-pinned archive,
the matching source checkout, built Spring fixture JAR, host JDK and Playwright Chromium.
Requires host b3sum for independent logical-file BLAKE3 verification.
This command rebuilds nothing and deliberately provides no analyzer override. Example:
  python3 tools/qa/installed_export_journey.py --prefix PREFIX --package ARCHIVE \
    --package-sha256 SHA256 --source-sha SHA --repo REPO --fixture-jar JAR \
    --java ABSOLUTE_JAVA --private-dir NEW_PRIVATE_DIR --summary SAFE_SUMMARY

Raw files under --private-dir MUST NOT be uploaded. Only --summary is public-safe.
Fresh-install provenance, signatures, macOS, Postman workspace delivery and external
framework campaigns are outside this fixture journey and remain explicit assumptions.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import urllib.request
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import canary  # noqa: E402

FORMATS = (("openapi", True), ("openapi", False), ("postman", False), ("curl", False), ("bundle", False))
WIDTHS = (320, 736, 1024, 1280, 1440)
MAX_LOG = 32 * 1024 * 1024


BROWSER_SUBSTAGES = frozenset("""
viewer-start viewer-url browser-context requests-load system-theme choose-open choose-keyboard choose-format
choose-scope choose-capture choose-geometry preview-activate preview-response preview-focus
preview-content preview-inventory-keyboard preview-capture preview-command preview-geometry preview-keyboard save-activate
save-response save-download save-focus save-content save-capture save-command save-geometry
save-keyboard save-done recording-select recording-export-open recording-export-keyboard
recording-export-scope page-health
""".split())
BROWSER_CLEANUP_STAGES = frozenset(("api-evidence-write", "context-close", "viewer-stop"))
BROWSER_GLOBAL_SUBSTAGES = frozenset(("browser-launch", "viewport-setup"))
BROWSER_PROGRESS_STAGES = BROWSER_SUBSTAGES | BROWSER_CLEANUP_STAGES | BROWSER_GLOBAL_SUBSTAGES | {"row-complete", "browser-close", "complete"}
MAX_BROWSER_RECEIPT = 128 * 1024
BROWSER_CASES = {f"{scope}-{fmt}-{'yaml' if yaml else 'json'}": (scope, fmt, yaml)
                 for scope in ("all", "one") for fmt, yaml in FORMATS}


def read_bounded(path, limit=MAX_LOG):
    require(path.stat().st_size <= limit, "private-file-limit")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, "private-file-limit")
    return value


class JourneyFailure(Exception):
    """Fixed diagnostic code; arbitrary child output never becomes a public reason."""


def require(condition, code):
    if not condition:
        raise JourneyFailure(code)


API_PHASES = ("headers", "finish", "body", "bounds", "write")
API_CATEGORIES = ("response-limit", "header-limit", "request-aborted", "request-failed", "context-closed",
                  "navigation-invalidated", "finish-unavailable", "body-unavailable", "body-timeout",
                  "body-limit", "write-failed", "write-timeout", "drain-timeout", "coverage-gap")
API_RESOURCES = ("auth", "endpoints", "linked", "recordings", "detail", "preview", "save", "other")
API_COUNTS = ("requests", "responses", "jsonResponses", "nonJsonResponses", "terminalRequests",
              "abortedBeforeResponse", "teardownAborted", "activeRequests", "pendingCaptures", "bytesWritten")
API_MINIMA = {"auth": 1, "endpoints": 1, "linked": 1, "detail": 1, "preview": 10, "save": 4}


def browser_evidence_source(repo):
    """Bind the collector, including its active browser-side auth read, and the driver to the pinned source checkout."""
    return {"schemaVersion": 2, "transport": "browser-response-with-auth-clone-drain",
            "driverSha256": hashlib.sha256(read_bounded(repo / "web/app/scripts/installed-export-journey.mjs")).hexdigest(),
            "collectorSha256": hashlib.sha256(read_bounded(repo / "web/app/scripts/api-evidence.mjs")).hexdigest(),
            "visibilitySha256": hashlib.sha256(read_bounded(repo / "web/app/scripts/export-visibility.mjs")).hexdigest()}


def project_api_evidence(value, row_passed):
    """Closed numeric/categorical projection; never accept unknown text or unbalanced capture stages."""
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "status", "sealed", "counts", "phases", "resources", "failures"}
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["status"] in ("not-reached", "in-progress", "pass", "fail") and type(value["sealed"]) is bool,
            "browser-api-schema")
    counts, phases, resources, failures = (value[key] for key in ("counts", "phases", "resources", "failures"))
    def integers(group, keys, maximum=1_000_000):
        return (isinstance(group, dict) and set(group) == set(keys)
                and all(type(item) is int and 0 <= item <= maximum for item in group.values()))
    require(isinstance(counts, dict) and set(counts) == set(API_COUNTS)
            and all(type(item) is int and 0 <= item <= (4096 * MAX_LOG if key == "bytesWritten" else 1_000_000)
                    for key, item in counts.items()), "browser-api-counts")
    require(isinstance(phases, dict) and set(phases) == set(API_PHASES)
            and all(integers(group, ("started", "passed", "failed"))
                    and group["started"] >= group["passed"] + group["failed"] for group in phases.values()),
            "browser-api-phases")
    require(isinstance(resources, dict) and set(resources) == set(API_RESOURCES)
            and all(integers(group, ("responses", "written")) and group["written"] <= group["responses"] for group in resources.values())
            and integers(failures, API_CATEGORIES), "browser-api-categories")
    require(counts["requests"] == counts["terminalRequests"] + counts["activeRequests"]
            and counts["responses"] == counts["jsonResponses"] + counts["nonJsonResponses"] <= counts["requests"]
            and counts["abortedBeforeResponse"] + counts["teardownAborted"] <= counts["terminalRequests"]
            and sum(group["responses"] for group in resources.values()) == counts["jsonResponses"] == phases["headers"]["started"]
            and sum(group["written"] for group in resources.values()) == phases["write"]["passed"]
            and all(phases[following]["started"] <= phases[previous]["passed"]
                    for previous, following in zip(API_PHASES, API_PHASES[1:])), "browser-api-parity")
    failed_captures = sum(group["failed"] for group in phases.values())
    require(counts["jsonResponses"] == phases["write"]["passed"] + failed_captures + counts["pendingCaptures"]
            and (not any(failures.values()) or value["status"] == "fail"), "browser-api-parity")
    if value["status"] == "pass":
        require(value["sealed"] and not any(failures.values()) and counts["activeRequests"] == counts["pendingCaptures"] == 0
                and counts["requests"] == counts["responses"] + counts["abortedBeforeResponse"] + counts["teardownAborted"]
                and counts["jsonResponses"] == phases["write"]["passed"] <= 4096
                and all(group["started"] == group["passed"] == counts["jsonResponses"] and group["failed"] == 0 for group in phases.values()),
                "browser-api-outcome")
    if row_passed:
        require(value["status"] == "pass" and all(resources[name]["written"] >= minimum for name, minimum in API_MINIMA.items()),
                "browser-api-coverage")
    if value["status"] == "not-reached":
        require(not value["sealed"] and not any(counts.values()) and not any(failures.values()), "browser-api-outcome")
    # All keys were checked, and JSON primitives are copied so callers cannot mutate the source receipt.
    return json.loads(json.dumps(value))


HEIGHT_PROBE_CHECKS = ("viewport", "initialAction", "contentScroll", "keyboardAction", "restore")
HEIGHT_PROBE_EXPECTED = {(width, height, coarse) for width in (320, 736) for height in (450, 260) for coarse in (False, True)}


def project_height_probes(probes, rows, status):
    require(isinstance(probes, list) and len(probes) <= 8, "browser-height-probes")
    seen, passed = set(), set()
    identities = {(row["width"], row["coarse"]) for row in rows}
    for probe in probes:
        require(isinstance(probe, dict) and set(probe) == {"width", "height", "coarse", "status", "checks"}
                and type(probe["width"]) is int and type(probe["height"]) is int and type(probe["coarse"]) is bool,
                "browser-height-probe-schema")
        identity = (probe["width"], probe["height"], probe["coarse"])
        require(identity in HEIGHT_PROBE_EXPECTED and identity not in seen
                and (probe["width"], probe["coarse"]) in identities, "browser-height-probe-identity")
        seen.add(identity)
        checks = probe["checks"]
        require(probe["status"] in ("in-progress", "pass", "fail") and isinstance(checks, dict) and set(checks) == set(HEIGHT_PROBE_CHECKS)
                and all(isinstance(item, str) and item in ("not-reached", "pass", "fail") for key, item in checks.items() if key != "initialAction")
                and (checks["initialAction"] == "not-required" if probe["height"] == 260 else checks["initialAction"] in ("not-reached", "pass", "fail")),
                "browser-height-probe-checks")
        require(probe["status"] != "pass" or all(checks[key] == "pass" for key in HEIGHT_PROBE_CHECKS if key != "initialAction")
                and checks["initialAction"] == ("pass" if probe["height"] == 450 else "not-required"), "browser-height-probe-outcome")
        require(probe["status"] != "fail" or "fail" in checks.values(), "browser-height-probe-outcome")
        if probe["status"] == "pass":
            passed.add(identity)
    for row in rows:
        if row["status"] == "pass" and row["width"] in (320, 736):
            require(all((row["width"], height, row["coarse"]) in passed for height in (450, 260)), "browser-height-probe-coverage")
    require(status != "pass" or passed == HEIGHT_PROBE_EXPECTED, "browser-height-probe-coverage")
    return json.loads(json.dumps(probes))


def project_browser_receipt(receipt, expected_identity=None, expected_evidence_source=None):
    """Project partial private evidence only after validating closed, bounded fields.

    Failure stacks, URLs, DOM and commands never enter the public summary. A passed
    row counts only after its teardown, and browser teardown has its own outcome.
    """
    require(isinstance(receipt, dict) and type(receipt.get("schemaVersion")) is int and receipt["schemaVersion"] in (1, 2, 3),
            "browser-receipt-schema")
    progress = receipt["schemaVersion"] >= 2
    capture = receipt["schemaVersion"] == 3
    build_identity = None
    if progress:
        build_identity = receipt.get("identity")
        require(isinstance(build_identity, dict) and set(build_identity) == {"sourceSha", "packageSha256"}
                and isinstance(build_identity["sourceSha"], str) and re.fullmatch(r"[0-9a-f]{40}", build_identity["sourceSha"])
                and isinstance(build_identity["packageSha256"], str) and re.fullmatch(r"[0-9a-f]{64}", build_identity["packageSha256"]),
                "browser-receipt-identity")
        sequence = receipt.get("checkpointSequence")
        require(type(sequence) is int and 1 <= sequence <= 10_000_000, "browser-receipt-sequence")
    if expected_identity is not None:
        require(progress and build_identity == expected_identity, "browser-receipt-identity-parity")
    evidence_source = None
    if capture:
        evidence_source = receipt.get("apiEvidenceSource")
        require(isinstance(evidence_source, dict) and set(evidence_source) == {"schemaVersion", "transport", "driverSha256", "collectorSha256", "visibilitySha256"}
                and type(evidence_source["schemaVersion"]) is int
                and (evidence_source["schemaVersion"], evidence_source["transport"]) in (
                    (1, "passive-browser-response"), (2, "browser-response-with-auth-clone-drain"))
                and all(isinstance(evidence_source[key], str) and re.fullmatch(r"[0-9a-f]{64}", evidence_source[key])
                        for key in ("driverSha256", "collectorSha256", "visibilitySha256")), "browser-api-source")
    if expected_evidence_source is not None:
        require(capture and evidence_source == expected_evidence_source, "browser-api-source-parity")
    rows, cases = receipt.get("rows"), receipt.get("cases")
    require(isinstance(rows, list) and len(rows) <= 10 and isinstance(cases, list) and len(cases) <= 100,
            "browser-receipt-bounds")
    status, global_stage, cleanup = receipt.get("status"), receipt.get("failureSubstage"), receipt.get("browserCleanup")
    outcomes = ("pass", "fail", "in-progress", "interrupted") if progress else ("pass", "fail")
    cleanups = ("not-reached", "in-progress", "pass", "fail") if progress else ("not-reached", "pass", "fail")
    require(status in outcomes and (global_stage is None or isinstance(global_stage, str) and global_stage in BROWSER_GLOBAL_SUBSTAGES)
            and cleanup in cleanups, "browser-receipt-status")
    projected, identities = [], set()
    for row in rows:
        require(isinstance(row, dict), "browser-receipt-row")
        width, coarse = row.get("width"), row.get("coarse")
        require(type(width) is int and width in WIDTHS and type(coarse) is bool, "browser-receipt-viewport")
        identity = f"{width}-{'coarse' if coarse else 'fine'}"
        require(identity not in identities, "browser-receipt-duplicate")
        identities.add(identity)
        count, row_status = row.get("cases"), row.get("status")
        stage, case, failures = row.get("failureSubstage"), row.get("failureCase"), row.get("cleanupFailures")
        require(type(count) is int and 0 <= count <= 10 and row_status in outcomes, "browser-receipt-row-status")
        require((stage is None or isinstance(stage, str) and stage in BROWSER_SUBSTAGES)
                and (case is None or isinstance(case, str) and case in BROWSER_CASES)
                and isinstance(failures, list) and len(failures) <= 3
                and all(isinstance(item, str) and item in BROWSER_CLEANUP_STAGES for item in failures)
                and len(set(failures)) == len(failures), "browser-receipt-substage")
        require((case is None or stage is not None)
                and (row_status != "pass" or count == 10 and stage is None and not failures)
                and (row_status != "fail" or stage is not None or failures), "browser-receipt-row-outcome")
        errors = {key: row.get(key) for key in ("pageErrors", "consoleErrors", "externalRequests")}
        require(all(type(value) is int and 0 <= value <= 9_007_199_254_740_991 for value in errors.values())
                and (row_status != "pass" or not any(errors.values())), "browser-receipt-errors")
        clean = {}
        if progress:
            cleanup_status, cleanup_stage = row.get("cleanupStatus"), row.get("cleanupStage")
            require(cleanup_status in cleanups and (cleanup_stage is None or isinstance(cleanup_stage, str)
                    and cleanup_stage in BROWSER_CLEANUP_STAGES), "browser-receipt-row-cleanup")
            require((cleanup_status == "in-progress") == (cleanup_stage is not None)
                    and (cleanup_status != "pass" or not failures)
                    and (cleanup_status != "fail" or failures)
                    and (row_status != "pass" or cleanup_status == "pass"), "browser-receipt-row-cleanup")
            clean = {"cleanupStatus": cleanup_status, "cleanupStage": cleanup_stage}
        if capture:
            clean["apiEvidence"] = project_api_evidence(row.get("apiEvidence"), row_status == "pass")
        projected.append({"width": width, "coarse": coarse, "cases": count, "status": row_status,
                          "failureSubstage": stage, "failureCase": case, "cleanupFailures": list(failures), **errors, **clean})
    counts, seen = Counter(), set()
    for case in cases:
        require(isinstance(case, dict), "browser-receipt-case")
        identity, case_id = case.get("id"), case.get("caseId")
        require(isinstance(identity, str) and identity in identities and isinstance(case_id, str) and case_id in BROWSER_CASES,
                "browser-receipt-case")
        require((identity, case_id) not in seen, "browser-receipt-case-duplicate")
        seen.add((identity, case_id))
        require(type(case.get("yaml")) is bool
                and (case.get("scope"), case.get("format"), case["yaml"]) == BROWSER_CASES[case_id], "browser-receipt-case")
        counts[identity] += 1
    require(all(counts[f"{row['width']}-{'coarse' if row['coarse'] else 'fine'}"] == row["cases"] for row in projected),
            "browser-receipt-count-parity")
    require(status != "pass" or len(rows) == 10 and len(cases) == 100 and global_stage is None
            and cleanup == "pass" and all(row["status"] == "pass" for row in projected), "browser-receipt-outcome")
    current = None
    if progress:
        current = receipt.get("current")
        require(isinstance(current, dict) and set(current) == {"rowId", "caseId", "stage"}, "browser-receipt-current")
        current_row, current_case, current_stage = current["rowId"], current["caseId"], current["stage"]
        require((current_row is None or isinstance(current_row, str) and current_row in identities)
                and (current_case is None or isinstance(current_case, str) and current_case in BROWSER_CASES)
                and isinstance(current_stage, str) and current_stage in BROWSER_PROGRESS_STAGES
                and (current_case is None or current_row is not None), "browser-receipt-current")
        require(status != "pass" or current == {"rowId": None, "caseId": None, "stage": "complete"}, "browser-receipt-current")
    result = {"viewports": sum(row["status"] == "pass" for row in projected),
              "downloads": sum(row["cases"] for row in projected if row["status"] == "pass"),
              "browserCompletedCases": len(cases), "browserStatus": status, "browserFailureSubstage": global_stage,
              "browserCleanup": cleanup, "browserRows": projected}
    if progress:
        result.update(browserIdentity=dict(build_identity), browserCurrent=dict(current), browserCheckpointSequence=receipt["checkpointSequence"])
    if capture:
        result["browserApiEvidenceSource"] = dict(evidence_source)
        result["browserHeightProbes"] = project_height_probes(receipt.get("heightProbes"), projected, status)
    return result


def load_browser_receipt(path, expected_identity=None, expected_evidence_source=None):
    """Read one atomically replaced checkpoint; malformed/truncated bytes never project."""
    require(path.is_file() and not path.is_symlink(), "browser-receipt-file")
    metadata = path.stat()
    require(metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o600, "browser-receipt-permissions")
    try:
        receipt = json.loads(read_bounded(path, MAX_BROWSER_RECEIPT))
    except (ValueError, UnicodeError) as error:
        raise JourneyFailure("browser-receipt-json") from error
    projection = project_browser_receipt(receipt, expected_identity, expected_evidence_source)
    if receipt["schemaVersion"] == 3:
        for row in receipt["rows"]:
            if row["status"] != "pass":
                continue
            directory = path.parent / f"{row['width']}-{'coarse' if row['coarse'] else 'fine'}"
            require(directory.is_dir() and not directory.is_symlink(), "browser-api-files")
            info = directory.stat()
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "browser-api-files")
            count = row["apiEvidence"]["counts"]["jsonResponses"]
            total = 0
            for index in range(count):
                payload = directory / f"api-{index}.json"
                require(payload.is_file() and not payload.is_symlink(), "browser-api-files")
                info = payload.stat()
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_LOG,
                        "browser-api-files")
                total += len(read_bounded(payload))
            require(total == row["apiEvidence"]["counts"]["bytesWritten"], "browser-api-files")
    return receipt, projection


def private_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_member(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and "\\" not in name and "\0" not in name and all(part not in ("", ".", "..") for part in name.split("/"))


def blake3_bytes(value):
    """Independent host utility, not either product metadata source."""
    executable = shutil.which("b3sum")
    require(executable is not None, "b3sum-prerequisite")
    result = subprocess.run([executable, "--no-names"], input=value, capture_output=True, timeout=30, check=False)
    require(result.returncode == 0 and re.fullmatch(rb"[0-9a-f]{64}\n?", result.stdout), "b3sum-failed")
    return result.stdout.decode().strip()


def omission_groups(omissions, export_format):
    """Closed vocabulary from xtrace-export/viewer.rs; unknown labels stay other."""
    kinds = {key: key for key in ("claims", "confidence", "handler", "path_literal", "policy_digest", "request_body", "source")}
    kinds.update(example="examples", examples="examples", operation="operations", operations="operations", param="parameters")
    reasons = set("claim_count_mismatch claim_summary_mismatch claims_projection_partial claims_projection_unavailable contains_nul credential_not_embedded handler_conflict_unresolved handler_path_not_repo_relative handler_symbol_invalid header_value_has_line_break invalid_header_name no_body_example no_scenario_or_claim_example not_available_in_catalog_view optional_without_example path_param_not_in_template per_claim_confidence_unavailable per_claim_locations_unavailable secret_shaped source_end_line_unavailable source_path_not_repo_relative unknown_param_location".split())
    counts = Counter()
    for omission in omissions:
        what, reason = omission["what"], omission["reason"]
        fmt = export_format if omission["operationId"] else None
        prefix, separator, rest = what.partition(":")
        if export_format == "bundle" and separator and prefix in ("openapi", "postman", "curl"):
            fmt, what = prefix, rest
        kind = kinds.get(what.split(":", 1)[0], "other")
        reason = "duplicate_method_path" if reason.startswith("duplicate_method_path_of:") else reason if reason in reasons else "other"
        counts[(fmt, kind, reason)] += 1
    return counts


def judge_download(preview, cli, directory, download):
    """Compare genuine CLI bytes and metadata with an actual HTTP/browser download."""
    require(preview["schemaVersion"] == 1, "preview-schema")
    require(preview["revisionId"] == cli["revisionId"] == preview["approval"]["revisionId"], "revision-parity")
    require(preview["revisionOrdinal"] == cli["revisionOrdinal"], "ordinal-parity")
    require(preview["contentHash"] == cli["contentHash"], "digest-parity")
    require(re.fullmatch(r"[0-9a-f]{64}", preview["approval"]["digest"]), "approval-digest")
    require(preview["emittedOperations"] == cli["operationCount"] > 0, "operation-parity")
    require(cli["written"] is True and cli["preview"] is False, "cli-did-not-write")
    files = cli["files"]
    require(files and len(files) <= 4101 and len({file["path"] for file in files}) == len(files), "cli-inventory")
    require(all(safe_member(file["path"]) for file in files), "unsafe-cli-member")
    expected = {file["path"]: read_bounded(directory / file["path"], 16 * 1024 * 1024) for file in files}
    actual_files = {file.relative_to(directory).as_posix() for file in directory.rglob("*") if file.is_file()}
    require(actual_files == set(expected), "cli-membership")
    require(all(len(expected[file["path"]]) == file["bytes"] and re.fullmatch(r"[0-9a-f]{64}", file["blake3"]) for file in files), "cli-metadata")
    shown = preview["files"]
    require(len(shown) == len(files), "preview-inventory")
    require(preview["totalBytes"] == sum(map(len, expected.values())), "preview-size")
    require(preview["totalBytes"] <= 16 * 1024 * 1024, "logical-export-limit")
    require(Counter((file["bytes"], file["blake3"]) for file in shown) == Counter((file["bytes"], file["blake3"]) for file in files), "file-digest-parity")
    require(all(file["mode"] == 0o644 for file in shown), "preview-mode")
    named = {file["name"]: file for file in shown if file["name"] is not None}
    cli_metadata = {file["path"]: file for file in files}
    require(len(named) == sum(file["name"] is not None for file in shown), "duplicate-preview-name")
    require(all(name in expected and (named[name]["bytes"], named[name]["blake3"]) == (cli_metadata[name]["bytes"], cli_metadata[name]["blake3"]) for name in named), "preview-name")
    hidden = [file for file in shown if file["name"] is None]
    require(all(type(file["recipeOrdinal"]) is int and file["recipeOrdinal"] > 0 for file in hidden), "recipe-ordinal")
    require(len({file["recipeOrdinal"] for file in hidden}) == len(hidden), "duplicate-recipe-ordinal")
    omissions = preview["omissions"]
    require(all(type(group["count"]) is int and group["count"] > 0 for group in omissions), "omission-count")
    require(sum(group["count"] for group in omissions) == len(cli["omissions"]), "omission-parity")
    groups = {(group["format"], group["kind"], group["reason"]): group["count"] for group in omissions}
    require(len(groups) == len(omissions) and groups == omission_groups(cli["omissions"], preview["request"]["format"]), "omission-group-parity")
    require(all(blake3_bytes(expected[file["path"]]) == file["blake3"] for file in files), "file-byte-digest")
    raw = read_bounded(download, 20 * 1024 * 1024)
    if preview["request"]["format"] in ("curl", "bundle"):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            require(len(members) == len(expected) and {item.filename for item in members} == set(expected), "zip-membership")
            require(len({item.filename for item in members}) == len(members), "zip-duplicate")
            for item in members:
                require(safe_member(item.filename) and not item.is_dir(), "zip-path")
                require(item.create_system == 3 and item.external_attr >> 16 == stat.S_IFREG | 0o644, "zip-mode")
                require(item.compress_type == zipfile.ZIP_STORED and item.date_time == (1980, 1, 1, 0, 0, 0), "zip-determinism")
                require(item.file_size == len(expected[item.filename]) and archive.read(item) == expected[item.filename], "zip-bytes")
    else:
        require(len(expected) == 1 and next(iter(expected.values())) == raw, "download-bytes")
    return len(files)


class Runner:
    def __init__(self, private, env):
        self.private, self.env, self.index = private, env, 0
        self.logs = private / "commands"
        self.logs.mkdir(mode=0o700)

    def run(self, command, *, timeout=120, input_data=None):
        self.index += 1
        stem = self.logs / str(self.index)
        private_json(stem.with_suffix(".command.json"), {"argv": [str(argument) for argument in command]})
        with stem.with_suffix(".stdout").open("xb") as stdout, stem.with_suffix(".stderr").open("xb") as stderr:
            child = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL)
            if input_data is not None:
                child.stdin.write(input_data)
                child.stdin.close()
            counts = {"stdout": 0, "stderr": 0}
            limited = timed_out = False
            deadline = time.monotonic() + timeout
            mux = selectors.DefaultSelector()
            mux.register(child.stdout, selectors.EVENT_READ, ("stdout", stdout))
            mux.register(child.stderr, selectors.EVENT_READ, ("stderr", stderr))
            try:
                while mux.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    for key, _ in mux.select(min(remaining, 1)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            mux.unregister(key.fileobj)
                            continue
                        name, target = key.data
                        available = MAX_LOG - counts[name]
                        target.write(chunk[:available])
                        counts[name] += min(available, len(chunk))
                        if len(chunk) > available:
                            limited = True
                            break
                    if limited:
                        break
                if not (timed_out or limited):
                    try:
                        child.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        timed_out = True
            finally:
                if child.poll() is None:
                    child.terminate()  # The directly spawned child only; browser has its own viewer cleanup.
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                mux.close()
                child.stdout.close()
                child.stderr.close()
        private_json(stem.with_suffix(".status.json"), {"exitCode": child.returncode, "timedOut": timed_out, "outputLimited": limited})
        require(not timed_out, "command-timeout")
        require(not limited, "command-output-limit")
        require(child.returncode == 0, "command-failed")
        return read_bounded(stem.with_suffix(".stdout"))

    def cli(self, binary, project, args):
        return json.loads(self.run([str(binary), *args, "--project-dir", str(project)]))


def fixture_workload(runner, binary, agent, project, java, jar, private, values, report):
    """One real app launch; boot's bound-port line is the readiness signal."""
    command = [str(binary), "run", "--project-dir", str(project), "--java-agent", str(agent), "--observed-endpoint-policy", "spring-orders-v1",
               "--application-component", "spring-fixture", "--binding-key", "default", "--app-package", "dev.xtrace.fixture",
               "--source-root", "src/main/java", "--", str(java), "-jar", str(jar), "--server.address=127.0.0.1", "--server.port=0",
               "--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO"]
    lines = queue.Queue()
    limited = threading.Event()
    stream_failed = threading.Event()
    with (private / "spring.stdout").open("xb") as stdout, (private / "spring.stderr").open("xb") as stderr:
        child = subprocess.Popen(command, env=runner.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        private_json(private / "spring.launch.private.json", {"pid": child.pid, "argv": command})

        def read(pipe, target, ready=False):
            count = 0
            try:
                while line := pipe.readline(65536):
                    available = MAX_LOG - count
                    target.write(line[:available])
                    target.flush()
                    count += min(available, len(line))
                    if len(line) > available:
                        limited.set()
                        if child.poll() is None:
                            child.terminate()
                        break
                    if ready and b"Tomcat started on port " in line:
                        lines.put(line)
            except (OSError, ValueError):
                stream_failed.set()
            finally:
                if ready:
                    lines.put(None)

        reader = threading.Thread(target=read, args=(child.stdout, stdout, True), daemon=True)
        error_reader = threading.Thread(target=read, args=(child.stderr, stderr), daemon=True)
        reader.start()
        error_reader.start()
        try:
            try:
                line = lines.get(timeout=45)
            except queue.Empty as error:
                raise JourneyFailure("spring-readiness") from error
            require(line is not None, "spring-exited-before-ready")
            match = re.search(rb"Tomcat started on port ([1-9][0-9]*) \(http\)", line)
            require(match, "spring-port-signal")
            port = int(match[1])
            body = json.dumps({"description": "installed export journey", "bodyCanary": values["json-body-password"]}).encode()
            request = urllib.request.Request(f"http://127.0.0.1:{port}/orders?token={values['query-token']}", body,
                                             {"Content-Type": "application/json", "Authorization": values["authorization-header"], "Cookie": values["cookie-header"]})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=10) as response:
                require(response.status == 201 and json.load(response) == {"status": "created"}, "spring-workload")
                report["genuineRequests"] = 1
            # Observe persisted terminal evidence before signaling the foreground launcher.
            end = time.monotonic() + 15
            while True:
                recordings = runner.cli(binary, project, ["recording", "list"])["recordings"]
                if len(recordings) == 1 and recordings[0]["status"] == "complete":
                    break
                require(time.monotonic() < end, "spring-recording-terminal")
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)  # Only the CLI this harness started; it owns JVM forwarding.
            try:
                code = child.wait(timeout=15)
            except subprocess.TimeoutExpired as error:
                private_json(private / "spring.status.json", {"exitCode": child.poll(), "pid": child.pid, "timedOut": True})
                raise JourneyFailure("spring-shutdown-timeout") from error
            reader.join(timeout=5)
            error_reader.join(timeout=5)
            drained = not reader.is_alive() and not error_reader.is_alive()
            private_json(private / "spring.status.json", {"exitCode": code, "outputDrained": drained, "outputLimited": limited.is_set()})
            require(drained, "spring-output-drain")
            child.stdout.close()
            child.stderr.close()
    require(not limited.is_set(), "spring-output-limit")
    require(not stream_failed.is_set(), "spring-output-io")
    require(code == 143, "spring-shutdown-status")


def run(args, private, report):
    require(sys.platform == "linux", "host-platform")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha) and re.fullmatch(r"[0-9a-f]{64}", args.package_sha256), "provenance-shape")
    report.update(sourceSha=args.source_sha, packageSha256=args.package_sha256)
    repo, prefix, package, jar, java = map(Path, (args.repo, args.prefix, args.package, args.fixture_jar, args.java))
    require(all(path.is_absolute() for path in (repo, prefix, package, jar, java)), "absolute-prerequisites")
    require(package.is_file() and jar.is_file() and java.is_file() and os.access(java, os.X_OK), "prerequisites")
    require(jar.resolve() == (repo / "adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar").resolve(), "fixture-build-location")
    report["fixtureSha256"] = digest(jar)
    require(digest(package) == args.package_sha256, "archive-digest")
    env = dict(os.environ)
    # An ambient analyzer/pack override must not turn this into a source-built proof.
    for key in ("XTRACE_JAVA_ANALYZER", "XTRACE_NODE_ANALYZER", "XTRACE_JAVA_PACK", "XTRACE_JAVA_AGENT", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        env.pop(key, None)
    env["XTRACE_DATA_HOME"] = str(private / "data")
    env["JAVA_HOME"] = str(java.parent.parent)
    env["PATH"] = str(java.parent) + os.pathsep + env.get("PATH", "")
    runner = Runner(private, env)
    require(runner.run(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip() == args.source_sha, "source-revision")
    require(not runner.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"]).strip(), "source-dirty")
    installed = prefix / "current"
    binary = prefix / "bin/xtrace"
    require(binary.is_file() and binary.resolve() == (installed / "bin/xtrace").resolve(), "installed-cli")
    verifier = repo / "packaging/verify_package.py"
    reports = []
    for target in (package, installed):
        result = json.loads(runner.run([sys.executable, str(verifier), str(target), "--repo", str(repo), "--run-binary"]))
        require(result.get("ok") is True and result["package"]["sourceCommit"] == args.source_sha, "package-verification")
        reports.append(result)
    require(reports[0]["package"] == reports[1]["package"], "installed-package-parity")
    with tarfile.open(package, "r:gz") as archive:
        manifests = [item for item in archive.getmembers() if item.name.endswith("/share/xtrace/PACKAGE-MANIFEST.json") and item.isfile()]
        require(len(manifests) == 1 and manifests[0].size <= MAX_LOG, "archive-manifest")
        require(archive.extractfile(manifests[0]).read(MAX_LOG + 1) == read_bounded(installed / "share/xtrace/PACKAGE-MANIFEST.json"), "installed-manifest-parity")
    # Full manifest/payload checks above establish each installed byte; official installed verify is an additional product path.
    runner.run(["sh", str(installed / "install.sh"), "verify", "--prefix", str(prefix)])
    require(blake3_bytes(b"") == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "b3sum-known-vector")
    report["packageVerified"] = True
    project = private / "project"
    project.mkdir(mode=0o700)
    shutil.copytree(repo / "adapters/java/spring-fixture/src/main", project / "src/main")
    init = runner.cli(binary, project, ["init"])
    require(init.get("kind") == "project_initialized", "project-init")
    values = {key: value for key, value in canary.make_canaries().items() if key in ("authorization-header", "cookie-header", "query-token", "json-body-password")}
    private_json(private / "input-canaries.private.json", values)
    agent = installed / "share/xtrace/packs/java/agent/xtrace-java-agent.jar"
    require(agent.is_file(), "installed-agent")
    fixture_workload(runner, binary, agent, project, java, jar, private, values, report)
    report["genuineRequests"] = 1
    scan = runner.cli(binary, project, ["scan", "--source", str(project / "src/main/java"), "--framework", "spring-mvc", "--application-component", "spring-fixture", "--binding-key", "default", "--json"])
    require(scan.get("persisted") is True and scan.get("result", {}).get("completion") == "complete", "scan-incomplete")
    endpoints = runner.cli(binary, project, ["endpoint", "list"])["items"]
    require(len(endpoints) == 1 and endpoints[0]["method"] == "POST" and endpoints[0]["routeTemplate"] == "/orders", "observed-endpoint")
    operation = endpoints[0]["operationId"]
    catalog = runner.cli(binary, project, ["catalog", "list", "--json"])
    # Transport is HTTP-only in the domain and is absent from both CLI projections.
    # Match exposed identity facts independently of viewer resolution first. This finite
    # registered Spring /orders case reuses the persisted operation UUID; do not generalize
    # that supported alias into equality of every observed and catalog selector.
    require(catalog["revision"]["revisionId"] == scan["catalogRevisionId"], "scanned-revision-selection")
    require((endpoints[0]["applicationComponent"], endpoints[0]["binding"], endpoints[0]["observationPolicy"]) ==
            ("spring-fixture", "default", "spring-orders-v1"), "supported-observed-scope")
    matching = [item for item in catalog["operations"] if
                (item["applicationComponent"], item["bindingKey"], item["method"], item["routeTemplate"]) ==
                (endpoints[0]["applicationComponent"], endpoints[0]["binding"], endpoints[0]["method"], endpoints[0]["routeTemplate"])]
    require(len(matching) == 1, "genuine-scan-scope")
    catalog_operation = matching[0]["operationId"]
    report["supportedOrdersUuidAlias"] = catalog_operation == operation
    require(report["supportedOrdersUuidAlias"], "supported-orders-uuid-alias")
    linked = runner.cli(binary, project, ["endpoint", "recordings", operation])["items"]
    require(len(linked) == 1 and linked[0]["status"] == "complete", "genuine-recording")
    recording = linked[0]["recordingId"]
    # CLI decoding traverses the real compressed recording; raw-file scans alone cannot establish this surface.
    detail = runner.cli(binary, project, ["recording", "show", recording, "--limit", "500"])
    require("next_cursor" in detail and detail["next_cursor"] is None and bool(detail.get("events")), "recording-decoding-incomplete")
    require("OrderController.create" in json.dumps(detail), "spring-handler-not-observed")
    browser_dir = private / "browser"
    browser_dir.mkdir(mode=0o700)
    browser_input = json.dumps({"xtrace": str(binary), "projectDir": str(project), "out": str(browser_dir), "operationId": operation,
                                "catalogOperationId": catalog_operation, "recordingId": recording,
                                "identity": {"sourceSha": args.source_sha, "packageSha256": args.package_sha256}}).encode()
    browser_error = None
    try:
        runner.run(["node", str(repo / "web/app/scripts/installed-export-journey.mjs")], timeout=900, input_data=browser_input)
    except JourneyFailure as error:
        browser_error = error
    identity = {"sourceSha": args.source_sha, "packageSha256": args.package_sha256}
    browser = None
    try:
        browser, projection = load_browser_receipt(browser_dir / "browser.private.json", identity, browser_evidence_source(repo))
        report.update(projection)
    except JourneyFailure as error:
        report["browserReceiptFailure"] = str(error)
        if browser_error is None:
            raise
    if browser_error is not None:
        raise browser_error
    require(browser is not None, "browser-receipt-missing")
    expected = {(f"{width}-{pointer}", scope, fmt, yaml) for width in WIDTHS for pointer in ("fine", "coarse") for scope in ("all", "one") for fmt, yaml in FORMATS}
    observed = [(case["id"], case["scope"], case["format"], case["yaml"]) for case in browser["cases"]]
    require(browser["status"] == "pass" and len(observed) == len(expected) and set(observed) == expected, "browser-coverage")
    cli_root = private / "cli-exports"
    cli_root.mkdir(mode=0o700)
    cache = {}
    compared = 0
    for case in browser["cases"]:
        base = browser_dir / case["id"] / case["caseId"]
        preview = json.loads(read_bounded(base.with_suffix(".preview.json")))
        require(preview["catalogOperationId"] == (None if case["scope"] == "all" else catalog_operation), "catalog-scope-resolution")
        require(preview["selectedOperations"] == (len(catalog["operations"]) if case["scope"] == "all" else 1), "selected-operation-count")
        key = (preview["revisionId"], case["scope"], case["format"], case["yaml"])
        if key not in cache:
            destination = cli_root / str(len(cache))
            command = ["export", "--revision", key[0], "--format", case["format"], "--output", str(destination), "--json"]
            if case["scope"] == "one":
                command += ["--operations", catalog_operation]
            if case["yaml"]:
                command += ["--yaml"]
            cache[key] = (runner.cli(binary, project, command), destination)
        cli, destination = cache[key]
        compared += judge_download(preview, cli, destination, base.with_suffix(".download"))
        report["logicalFilesCompared"] = compared
    report["sameProjectCatalogLinked"] = True
    report.update(viewports=10, downloads=len(observed), logicalFilesCompared=compared)
    locations = {"store": [private / "data", project], "cli-and-api-output": [runner.logs], "browser": [browser_dir],
                 "exports": [cli_root], "application-output": [private / "spring.stdout", private / "spring.stderr"]}
    privacy = canary.run_scan(values, locations, {name: 1 for name in locations})
    private_json(private / "privacy.private.json", privacy)
    require(privacy["clean"], "privacy-hit-or-coverage-gap")
    report["privacySurfaces"] = len(locations)
    report["status"] = "pass"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("prefix", "package", "package-sha256", "source-sha", "repo", "fixture-jar", "java", "private-dir", "summary"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    private = Path(args.private_dir)
    owned = False
    report = {"schemaVersion": 1, "kind": "installed-spring-export-journey", "releaseEvidence": False, "status": "fail",
              "packageVerified": False, "sameProjectCatalogLinked": False, "supportedOrdersUuidAlias": None, "genuineRequests": 0, "viewports": 0, "downloads": 0,
              "logicalFilesCompared": 0, "privacySurfaces": 0,
              "privacyLimits": ["four-injected-canary-kinds-only", "listed-files-and-decoded-recording-only", "common-encodings-only", "compressed-scan-depth-two", "decompression-caps-may-truncate", "screenshots-not-ocr-scanned", "browser-dom-snapshots-at-named-phases-only"],
              "viewportHeight": 900, "scopeTransport": "http-only-domain-enum-not-exposed-in-cli",
              "assumptions": ["enclosing-job-fresh-official-install", "matching-fixture-jar-built-from-source", "unsigned-development-package", "fixture-not-external-framework-campaign"]}
    try:
        require(private.is_absolute() and not private.exists(), "private-directory-not-fresh")
        parent = private.parent.stat()
        require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, "private-parent-permissions")
        private.mkdir(mode=0o700)
        owned = True
        run(args, private, report)
    except Exception as error:
        report["reason"] = str(error) if isinstance(error, JourneyFailure) else "harness-error"
        if owned:
            (private / "failure.private.txt").write_text(traceback.format_exc())
    with Path(args.summary).open("x", encoding="utf-8") as summary:
        summary.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "downloads": report["downloads"], "reason": report.get("reason")}))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
