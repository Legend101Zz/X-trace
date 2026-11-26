#!/usr/bin/env python3
"""Publish only bounded JHipster counts/statuses after scanning the actual private sinks.

Raw receipts, IDs, exception text, paths and process output never enter the public tree.
The saved-recording artifact is a private ZIP of observed API JSON, not an export bundle.
"""
from __future__ import annotations

import argparse
from collections import Counter
from itertools import islice
import math
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lib"))
from tools.qa import camp_publication, canary  # noqa: E402
from campaigns.lib import boundary_diagnostics  # noqa: E402
from campaigns.lib.private_diagnostic import root_admitted  # noqa: E402
from campaigns.java.jhipster.harness import collect_sinks  # noqa: E402
from campaigns.java.jhipster.harness.evidence import EXPECT  # noqa: E402

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


# Fixed names from evidence.inspect/judge. Details after '(' never leave the private receipt.
RECORDING_PROBLEMS = frozenset("""
recording-detail-incomplete exact-route-root-unobserved terminal-http-status-unobserved recording-incomplete
controller-frame-unobserved controller-source-unobserved unexpected-controller-frame
refused-controller-identity-unresolved controller-exception-type-unobserved controller-exception-link-unobserved
repository-declaration-unobserved-in-handler repository-source-unobserved postgresql-boundary-unobserved
jdbc-operation-unobserved unexpected-bank-account-write-frame-or-interaction workload-request-count-mismatch
workload-http-status-mismatch burst-boundary-unverified burst-route-count-mismatch burst-capacity-drops
individual-request-and-principal-attribution-unobserved pre-dispatch-servlet-root-unobserved
pre-dispatch-request-unreached recording-attribution-unavailable workload-requests-without-exact-expectations
scenario-unreached burst-drops burst-boundary-not-verified
""".split())
SEAM_PROBLEMS = {
    "root": ("exact-route-root-unobserved",),
    "outcome": ("exact-route-root-unobserved", "terminal-http-status-unobserved"),
    "completion": ("recording-incomplete",),
    "controller": ("controller-frame-unobserved", "unexpected-controller-frame",
                   "refused-controller-identity-unresolved", "controller-exception-type-unobserved",
                   "controller-exception-link-unobserved"),
    "source": ("exact-route-root-unobserved", "controller-source-unobserved"),
    "repository": ("repository-declaration-unobserved-in-handler", "repository-source-unobserved"),
    "postgresql": ("postgresql-boundary-unobserved", "jdbc-operation-unobserved"),
    "preDispatch": ("pre-dispatch-servlet-root-unobserved", "pre-dispatch-request-unreached"),
    "requestAttribution": ("recording-attribution-unavailable", "individual-request-and-principal-attribution-unobserved"),
}


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


def valid_receipt(doc, instrumented=True):
    return (isinstance(doc, dict) and doc.get("project") == "jhipster"
            and doc.get("instrumented") is instrumented and doc.get("releaseAcceptance") is False)


def receipt_summary(doc, state, instrumented):
    valid = valid_receipt(doc, instrumented)
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


def problem_counts(raw, *, weighted=False, limit=None):
    """Normalize the producer's parameterized strings into a closed count vocabulary."""
    pairs = raw.items() if isinstance(raw, dict) else None
    if not weighted:
        pairs = ((key, 1) for key in raw) if isinstance(raw, list) else None
    if pairs is None or len(raw) > 64:
        return None
    output = {}
    for key, value in pairs:
        if not isinstance(key, str) or count(value) is None or (limit is not None and value > limit):
            return None
        name = key.split("(", 1)[0]
        name = name if name in RECORDING_PROBLEMS else "other"
        output[name] = min(MAX_COUNT, output.get(name, 0) + value)
    return output


def merge_counts(rows):
    if any(row is None for row in rows):
        return None
    output = {}
    for row in rows:
        for key, value in row.items():
            output[key] = min(MAX_COUNT, output.get(key, 0) + value)
    return output


def matching_item(rows, rule, *, burst=False):
    if not isinstance(rows, list) or len(rows) > 64:
        return None
    matches = [row for row in rows if isinstance(row, dict)
               and (row.get("label"), row.get("method"), row.get("route")) ==
               (rule["label"], rule["method"], rule["route"])]
    if len(matches) != 1:
        return None
    row = matches[0]
    return row if (isinstance(row.get("expectedStatuses"), list)
                   and all(type(status) is int for status in row["expectedStatuses"])
                   and row["expectedStatuses"] == list(rule["statuses"])
                   and row.get("expectedRepositoryDeclarations") == list(rule["repository"])
                   and (not burst or row.get("evidenceScope") == "burst-route-group")) else None


def response_labels(sid):
    """Private identities from run.py; these labels never enter the projection."""
    if sid != "concurrent-isolation":
        return {rule["label"]: index for index, rule in enumerate(EXPECT[sid])}
    labels = {"login admin": 0}
    for index in range(12):
        principal = "admin" if index % 2 == 0 else "user"
        labels.update({f"login {principal} #{index}": 0, f"account as {principal} #{index}": 1,
                       f"create Parallel {index:02d}": 2, f"reopen Parallel {index:02d}": 3})
    return labels


def response_counts(row, sid):
    sent = row.get("requests")
    labels = response_labels(sid)
    if not isinstance(sent, list) or len(sent) > len(labels):
        return None
    observed = set()
    statuses = [[] for _ in EXPECT[sid]]
    for request in sent:
        if not isinstance(request, dict) or set(request) != {"label", "status", "elapsedMs"}:
            return None
        label, status, elapsed = request["label"], request["status"], request["elapsedMs"]
        if (not isinstance(label, str) or label not in labels or label in observed
                or type(status) is not int or not 100 <= status <= 599
                or type(elapsed) not in (int, float) or not 0 <= elapsed <= sys.float_info.max or not math.isfinite(elapsed)):
            return None
        observed.add(label)
        statuses[labels[label]].append(status)
    return statuses


def inspect_problem_names(rule):
    names = {"recording-detail-incomplete", "exact-route-root-unobserved", "terminal-http-status-unobserved", "recording-incomplete"}
    if rule["handler"]:
        names.update(("controller-frame-unobserved", "controller-source-unobserved"))
    if rule["refusedHandler"]:
        names.update(("unexpected-controller-frame", "refused-controller-identity-unresolved"))
    if rule["exception"]:
        names.update(("controller-exception-type-unobserved", "controller-exception-link-unobserved"))
    names.update(f"repository-declaration-unobserved-in-handler({symbol})" for symbol in rule["repository"])
    names.update(f"repository-source-unobserved({symbol})" for symbol in rule["repository"]
                 if symbol.startswith("io.github.jhipster.sample.repository."))
    if rule["jdbc"]:
        names.add("postgresql-boundary-unobserved")
        names.update(f"jdbc-operation-unobserved({verb} {table})" for verb, table in rule["jdbc"])
    elif rule["method"] == "POST" and rule["route"] == "/api/bank-accounts":
        names.add("unexpected-bank-account-write-frame-or-interaction")
    return names


def inspected_item(row, rule, statuses_sent, *, burst=False):
    """Validate the producer's raw histogram before normalizing any problem names."""
    if not isinstance(row, dict) or statuses_sent is None:
        return None
    matched = count(row.get("recordingsMatchingRoute"))
    statuses, sources = count(row.get("recordingsWithStatus")), count(row.get("recordingsWithSource"))
    raw = row.get("problems")
    problems = problem_counts(raw)
    if (matched is None or statuses is None or sources is None or problems is None
            or len(set(raw)) != len(raw) or max(statuses, sources) > matched
            or type(row.get("passed")) is not bool or row["passed"] != (not raw)):
        return None
    inspect_names = inspect_problem_names(rule)
    context = {"workload-request-count-mismatch", "workload-http-status-mismatch"}
    context.update(("burst-boundary-unverified", "burst-route-count-mismatch", "burst-capacity-drops") if burst else
                   ("individual-request-and-principal-attribution-unobserved", "pre-dispatch-servlet-root-unobserved",
                    "pre-dispatch-request-unreached", "recording-attribution-unavailable"))
    if any(key not in inspect_names | context for key in raw):
        return None
    if (("workload-request-count-mismatch" in raw) != (len(statuses_sent) != rule["minCount"])
            or ("workload-http-status-mismatch" in raw) != any(status not in rule["statuses"] for status in statuses_sent)):
        return None
    attribution = row.get("attribution")
    if burst:
        histogram = row.get("problemRecordings")
        if (attribution != "route-counts" or type(row.get("requests")) is not int or row["requests"] != len(statuses_sent)
                or (matched != rule["minCount"] and "burst-route-count-mismatch" not in raw)
                or not isinstance(histogram, dict) or set(histogram) != set(raw) & inspect_names
                or any(type(value) is not int or not 1 <= value <= matched for value in histogram.values())):
            return None
    else:
        if (attribution not in ("serial-boundary-order", "ambiguous", "external-http-only", "unavailable")
                or matched > 1 or (matched == 1) != (attribution == "serial-boundary-order")
                or (not matched and set(raw) & inspect_names)):
            return None
        missing = {"individual-request-and-principal-attribution-unobserved", "pre-dispatch-servlet-root-unobserved",
                   "pre-dispatch-request-unreached", "recording-attribution-unavailable"}
        if ((attribution == "serial-boundary-order" and (len(statuses_sent) != 1 or set(raw) & missing))
                or (attribution == "ambiguous" and (rule["label"] is not None
                    or "individual-request-and-principal-attribution-unobserved" not in raw))
                or (attribution == "external-http-only" and (not rule["preDispatch"] or not statuses_sent
                    or "pre-dispatch-servlet-root-unobserved" not in raw))
                or (attribution == "unavailable" and not ({"recording-attribution-unavailable",
                    "pre-dispatch-request-unreached"} & set(raw)))):
            return None
        histogram = {key: 1 for key in raw if key in inspect_names} if matched else {}
    unread = histogram.get("recording-detail-incomplete", 0)
    checked = matched - unread
    if unread > matched or max(statuses, sources) > checked:
        return None
    if any(value > checked for key, value in histogram.items() if key != "recording-detail-incomplete"):
        return None
    if sum(histogram.get(name, 0) for name in (
            "controller-exception-type-unobserved", "controller-exception-link-unobserved")) > checked:
        return None
    missing_pg = histogram.get("postgresql-boundary-unobserved", 0)
    if any(histogram.get(f"jdbc-operation-unobserved({verb} {table})", 0) < missing_pg for verb, table in rule["jdbc"]):
        return None
    for source_check, observed, failures in ((False, statuses, ("exact-route-root-unobserved", "terminal-http-status-unobserved")),
                               (True, sources, ("exact-route-root-unobserved", "controller-source-unobserved"))):
        if source_check and not rule["handler"]:
            if sources != 0:
                return None
            continue
        bins = [histogram.get(key, 0) for key in failures]
        if not checked - min(checked, sum(bins)) <= observed <= checked - max(bins):
            return None
    if histogram.get("controller-frame-unobserved", 0) > histogram.get("controller-source-unobserved", 0):
        return None
    affected = problem_counts(histogram, weighted=True, limit=matched)
    return {"matched": matched, "checked": checked, "statuses": statuses,
            "sources": sources, "problems": problems, "affected": affected, "burst": burst}


def eligible(rule, seam):
    return {"root": not rule["preDispatch"], "outcome": True, "completion": True,
            "controller": bool(rule["handler"] or rule["refusedHandler"]), "source": bool(rule["handler"]),
            "repository": bool(rule["repository"]), "postgresql": bool(rule["jdbc"]),
            "preDispatch": rule["preDispatch"], "requestAttribution": True}[seam]


def satisfied(item, seam):
    if item is None or "other" in item["problems"]:
        return None
    if seam == "outcome":
        return item["statuses"]
    if seam == "source":
        return item["sources"]
    if seam == "preDispatch":
        return item["matched"] if not item["problems"] else 0
    if seam == "requestAttribution":
        return item["matched"]
    failures = [item["affected"].get(name, 0) for name in SEAM_PROBLEMS[seam]]
    if not item["burst"]:
        return max(0, item["checked"] - int(any(failures)))
    if seam in ("repository", "postgresql") and any(failures):
        return None  # Multiple declarations/operations can fail in the same recording.
    # Histogram bins overlap. With two nonzero classes, their union is unavailable.
    return max(0, item["checked"] - sum(failures)) if sum(value > 0 for value in failures) <= 1 else None


def recording_evidence_summary(doc):
    """Bounded scenario/seam diagnostics, without copying labels, symbols, SQL or IDs.

    Mandatory roots exclude three pre-dispatch denials. Burst route groups carry
    49 requests across four groups; their evidence never credits individual attribution.
    PostgreSQL observation is inferable only for inspected JDBC-eligible recordings.
    Receipt fields cannot establish that an unobserved database call was unexercised.
    """
    rows = doc.get("scenarios") if valid_receipt(doc) else None
    rows = rows if isinstance(rows, list) and len(rows) <= 64 else []
    groups = doc.get("burstRouteGroups") if valid_receipt(doc) else None
    output = []
    for sid, expected_requests, _ in SCENARIOS:
        matches = [row for row in rows if isinstance(row, dict) and row.get("id") == sid]
        row = matches[0] if len(matches) == 1 else {}
        verdict_row = row.get("recordingVerdict")
        verdict_row = verdict_row if isinstance(verdict_row, dict) else {}
        items = verdict_row.get("expectations")
        rules = EXPECT[sid]
        burst = sid == "concurrent-isolation"
        responses = response_counts(row, sid)
        top_problems = verdict_row.get("problems")
        row_valid = (responses is not None and isinstance(items, list) and len(items) <= len(rules)
                     and isinstance(top_problems, list) and len(top_problems) <= 2
                     and all(isinstance(problem, str) and problem in (
                         "scenario-unreached", "workload-requests-without-exact-expectations") for problem in top_problems)
                     and ("scenario-unreached" not in top_problems or not items and not row.get("requests")
                          and verdict_row.get("recordingsAttributed") == 0)
                     and type(verdict_row.get("checkedRequests")) is int
                     and verdict_row["checkedRequests"] == sum(map(len, responses))
                     and count(verdict_row.get("recordingsAttributed")) is not None
                     and type(verdict_row.get("passed")) is bool
                     and verdict_row["passed"] == (bool(items) and not top_problems
                          and all(isinstance(item, dict) and item.get("passed") is True for item in items)))
        if not row_valid:
            responses = None
        response_numbers = [len(values) for values in responses] if responses is not None else [None] * len(rules)
        evidence = [inspected_item(matching_item(groups if burst else items, rule, burst=burst), rule,
                                   responses[index] if responses is not None else None, burst=burst)
                    for index, rule in enumerate(rules)]
        individual = [inspected_item(matching_item(items, rule), rule, responses[index] if responses is not None else None)
                      for index, rule in enumerate(rules)]
        if burst:
            evidence = [item if individual[index] is not None else None for index, item in enumerate(evidence)]
        sent = row.get("requests") if responses is not None else None
        scenario_problems = problem_counts(verdict_row.get("problems"))
        observed_problems = [item["problems"] if item else None for item in individual]
        seams = {}
        for seam in SEAM_PROBLEMS:
            indices = [index for index, rule in enumerate(rules) if eligible(rule, seam)]
            selected = [individual[index] if seam == "requestAttribution" else evidence[index] for index in indices]
            matched = [item["matched"] if item else None for item in selected]
            checked = [item["checked"] if item else None for item in selected]
            supported = [satisfied(item, seam) for item in selected]
            total = lambda values: min(MAX_COUNT, sum(values)) if all(value is not None for value in values) else None
            # Context failures explain why this seam was not checked; failures of other
            # seams are retained in the scenario totals rather than mislabelled here.
            names = set(SEAM_PROBLEMS[seam]) | {"recording-detail-incomplete", "recording-attribution-unavailable",
                    "pre-dispatch-servlet-root-unobserved", "pre-dispatch-request-unreached",
                    "individual-request-and-principal-attribution-unobserved", "workload-request-count-mismatch",
                    "workload-http-status-mismatch", "burst-boundary-unverified", "burst-route-count-mismatch",
                    "burst-capacity-drops", "other"}
            filtered = lambda item, key: {name: value for name, value in item[key].items() if name in names} if item else None
            seam_row = {"eligibleRequests": sum(rules[index]["minCount"] for index in indices),
                        "eligibleGroups": len(indices), "observedResponses": total([response_numbers[index] for index in indices]),
                        "observedGroups": sum(item is not None for item in selected),
                        "matchedRecordings": total(matched), "knownMatchedRecordings": min(MAX_COUNT, sum(value or 0 for value in matched)),
                        "checkedRecordings": total(checked), "satisfiedRecordings": total(supported),
                        "failureClasses": merge_counts([filtered(item, "problems") for item in selected]),
                        "recordingFailureAssertions": merge_counts([filtered(item, "affected") for item in selected])}
            if seam == "postgresql":
                # This is any accepted pgjdbc/postgresql boundary, independently of whether
                # its verb/table satisfies all expected operations. No SQL is projected.
                observations = [max(0, item["checked"] - item["affected"].get("postgresql-boundary-unobserved", 0))
                                if item and "other" not in item["problems"] else None for item in selected]
                observed = total(observations)
                seam_row.update(pgjdbcObservedRecordings=observed,
                                observation="unknown" if observed is None else "not-checked" if not indices or total(checked) == 0
                                else "observed" if observed > 0 else "not-observed",
                                actualExercise="unknown-from-receipt")
            seams[seam] = seam_row
        output.append({"id": sid, "expectedRequests": expected_requests,
                       "eligibleRoots": sum(rule["minCount"] for rule in rules if not rule["preDispatch"]),
                       "optionalPreDispatchRoots": sum(rule["minCount"] for rule in rules if rule["preDispatch"]),
                       "observedResponses": count(len(sent)) if isinstance(sent, list) else None,
                       "checkedRequests": len(sent) if sent is not None and verdict_row.get("checkedRequests") == len(sent) and ("scenario-unreached" not in top_problems or not items and not row.get("requests")
                          and verdict_row.get("recordingsAttributed") == 0)
                     and type(verdict_row.get("checkedRequests")) is int else None,
                       "individualRecordingsAttributed": count(verdict_row.get("recordingsAttributed")) if all(item is not None for item in individual)
                       and verdict_row.get("recordingsAttributed") == sum(item["matched"] for item in individual) else None,
                       "recordingVerdict": verdict(verdict_row.get("passed")) if all(item is not None for item in individual)
                       and scenario_problems is not None and verdict_row.get("passed") is
                       (not scenario_problems and all(not item["problems"] for item in individual)) else "not-observed",
                       "expectationGroups": len(rules), "observedExpectationGroups": sum(item is not None for item in individual),
                       "failureClasses": merge_counts([scenario_problems, *observed_problems]),
                       "routeGroupFailureClasses": merge_counts([item["problems"] if item else None for item in evidence]) if burst else {},
                       "evidenceScope": "burst-route-groups" if burst else "serial-boundary-order",
                       "seams": seams})
    return {"countLimit": MAX_COUNT, "expectedRequests": 77, "eligibleRoots": 74,
            "optionalPreDispatchRoots": 3, "expectedBurstRoots": 49, "expectedBurstGroups": 4,
            "problemUnits": "failureClasses-count-assertions-per-group;recordingFailureAssertions-count-per-recording-assertions",
            "scenarios": output}


def aggregate_problem_counts(doc, projection):
    """A missing, partial or inconsistent aggregate is unknown, never an empty map."""
    if not valid_receipt(doc):
        return None
    raw = doc.get("problemClasses")
    rows, groups = doc.get("scenarios"), doc.get("burstRouteGroups")
    if (not isinstance(raw, dict) or len(raw) > 64 or any(not isinstance(key, str) or not key or "(" in key
            or type(value) is not int or not 1 <= value <= MAX_COUNT for key, value in raw.items())
            or not isinstance(rows, list) or len(rows) != len(SCENARIOS)
            or not isinstance(groups, list) or len(groups) != 4):
        return None
    if any(row["observedExpectationGroups"] != row["expectationGroups"]
           or row["checkedRequests"] is None or row["individualRecordingsAttributed"] is None
           or row["recordingVerdict"] == "not-observed" for row in projection["scenarios"]):
        return None
    burst = next(row for row in projection["scenarios"] if row["id"] == "concurrent-isolation")
    if burst["seams"]["root"]["observedGroups"] != 4:
        return None
    expected = Counter()
    for row in rows:
        verdict_row = row["recordingVerdict"]
        expected.update(verdict_row["problems"])
        for item in verdict_row["expectations"]:
            expected.update(problem.split("(", 1)[0] for problem in item["problems"])
    for group in groups:
        expected.update(problem.split("(", 1)[0] for problem in group["problems"])
    # xinstr also adds two session/boundary flags without per-recording histograms.
    for key in ("burst-drops", "burst-boundary-not-verified"):
        if key in raw:
            if raw[key] != 1:
                return None
            expected[key] = 1
    return dict(expected) if dict(expected) == raw else None


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


def boundary_manifest(doc):
    notes = doc.get("notes") if valid_receipt(doc) else None
    if not isinstance(notes, dict):
        return None
    manifest = boundary_diagnostics.projection(notes.get("boundaryDiagnostics"))
    observed = notes.get("orderedBoundaries")
    if (manifest is None or not isinstance(observed, list)
            or len(observed) != len(manifest["phases"])):
        return None
    for phase, original in zip(manifest["phases"], observed):
        if (not isinstance(original, dict) or original.get("kind") != phase["kind"]
                or original.get("verified") is not (phase["status"] == "verified")):
            return None
    return manifest if doc.get("boundariesVerified") is (
        bool(observed) and manifest["firstUnverifiedPhase"] is None) else None


def capture_projection(value):
    if (not isinstance(value, dict) or set(value) != {"markers", "truncated", "status", "completion"}
            or type(value["truncated"]) is not bool
            or value["status"] not in (None, *collect_sinks.LIFECYCLE_STATES)
            or value["completion"] not in (None, *collect_sinks.COMPLETION_STATES)):
        return None
    markers = value["markers"]
    if (not isinstance(markers, dict) or set(markers) != set(collect_sinks.MARKER_CLASSES)
            or any(count(n) is None for n in markers.values())
            or sum(markers.values()) > collect_sinks.MARKER_LIMIT
            or (value["truncated"] and sum(markers.values()) != collect_sinks.MARKER_LIMIT)):
        return None
    return value


def first_incomplete_projection(value):
    if (not isinstance(value, dict) or set(value) not in ({"cli", "api", "apiRead", "cliReadScope"}, {"cli", "api", "apiRead", "cliReadScope", "provenance"})
            or value["apiRead"] not in ("complete-read", "partial-read", "missing", "rejected")
            or value["cliReadScope"] not in ("whole-recording", "one-page")):
        return None
    same_scope = False
    if "provenance" in value:
        provenance = value["provenance"]
        if (not isinstance(provenance, dict) or set(provenance) != {"cli", "api"}
                or not collect_sinks.partial_provenance.valid(provenance["cli"])
                or (provenance["cli"]["scope"] == "whole-recording" and value["cliReadScope"] != "whole-recording")
                or (provenance["api"] is not None and not collect_sinks.partial_provenance.valid(provenance["api"]))
                or (provenance["api"] is not None and value["apiRead"] != "complete-read")):
            return None
        # Legacy aggregates lack proof of every page. Count-limited windows may differ, too.
        same_scope = (provenance["api"] is not None
                      and provenance["api"]["scope"] == provenance["cli"]["scope"] == "whole-recording")
    cli = capture_projection(value["cli"])
    api = capture_projection(value["api"])
    state = value["apiRead"]
    if ((value["cli"] is not None and (cli is None or not sum(cli["markers"].values())))
            or (value["api"] is not None and (api is None or state in ("missing", "rejected")))):
        return None
    return {**value, "observationPhases": "earlier-saved-api-later-cli" if state in (
                "complete-read", "partial-read") else None,
            "sameReadScope": same_scope,
            "sharedKnownCategories": (sum(cli["markers"][key] > 0 and api["markers"][key] > 0
                                          for key in collect_sinks.MARKER_CLASSES if key != "unclassified")
                                      if api is not None and cli is not None else None)}


def cli_diagnostics(doc):
    """Project the first CLI failure only from a consistent bounded collection manifest."""
    if not isinstance(doc, dict) or doc.get("schema") not in (
            "xtrace-jhipster-cli-sinks/2", "xtrace-jhipster-cli-sinks/3"):
        return None
    keys = ("listCommands", "detailCommands", "recordings", "completedDetails")
    if any(count(doc.get(key)) is None for key in keys) or type(doc.get("complete")) is not bool:
        return None
    listing, details, listed, completed = (doc[key] for key in keys)
    if (listing > collect_sinks.MAX_PAGES or details > collect_sinks.MAX_RECORDINGS * collect_sinks.MAX_PAGES
            or completed > min(details, listed) or listed > collect_sinks.MAX_RECORDINGS + 100):
        return None
    failure = doc.get("firstFailure")
    if doc["complete"]:
        if failure is not None or not (listing and 0 < completed == listed <= collect_sinks.MAX_RECORDINGS):
            return None
    else:
        if (not isinstance(failure, dict) or set(failure) != {"stage", "reason", "exitCode"}
                or failure["stage"] not in ("list", "detail") or failure["reason"] not in collect_sinks.FAILURE_REASONS
                or (failure["stage"] == "list" and (details or completed))
                or (failure["stage"] == "detail" and not (listing and details and completed < listed))
                or (failure["reason"] in ("no-recordings", "recording-limit", "duplicate-identity")
                    and failure["stage"] != "list")
                or (failure["reason"] == "incomplete-evidence" and failure["stage"] != "detail")):
            return None
        code = failure["exitCode"]
        if (not (type(code) is int and -255 <= code <= 255 and code != 0)
                if failure["reason"] == "nonzero-exit" else code is not None):
            return None
    projection = {**{key: doc[key] for key in keys}, "firstFailure": failure}
    modern = doc["schema"] == "xtrace-jhipster-cli-sinks/3"
    has_incomplete = failure is not None and failure["reason"] == "incomplete-evidence"
    if ("firstIncomplete" in doc) != (modern and has_incomplete):
        return None
    if modern and has_incomplete:
        incomplete = first_incomplete_projection(doc["firstIncomplete"])
        if incomplete is None:
            return None
        projection["firstIncomplete"] = incomplete
    return projection


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
    summary["boundaryDiagnostics"] = boundary_manifest(instrumented)
    summary["cli"]["diagnostics"] = cli_diagnostics(cli)
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
    projection = recording_evidence_summary(instrumented)
    problem_classes = aggregate_problem_counts(instrumented, projection)
    judge_observed = (valid_receipt(instrumented) and problem_classes is not None
                      and any(row["observedExpectationGroups"] > 0 for row in projection["scenarios"]))
    taxonomy = {
        "preDispatch": lambda key: key.startswith("pre-dispatch-"),
        "postgresql": lambda key: key in ("postgresql-boundary-unobserved", "jdbc-operation-unobserved"),
        "burst": lambda key: key.startswith("burst-") or key == "individual-request-and-principal-attribution-unobserved",
    }
    summary["recordingJudgement"] = "observed" if judge_observed else "not-observed"
    summary["recordingGapProblemCounts"] = {
        name: min(MAX_COUNT, sum(value for key, value in problem_classes.items() if match(key)))
        if judge_observed else None for name, match in taxonomy.items()
    }
    summary["recordingGapCountLimit"] = MAX_COUNT
    summary["recordingEvidence"] = projection
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
