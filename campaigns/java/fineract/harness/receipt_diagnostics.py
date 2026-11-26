"""Finite diagnostic projections from the installed Fineract campaign, independent of acceptance."""
import boundary_diagnostics
import fineract_detail_evidence
import installed_sinks
from campaigns.java.fineract.harness.recording_evidence import EXPECT, required_observations


def bounded(value):
    return type(value) is int and 0 <= value <= 1_000_000


def valid_capture(doc):
    return (isinstance(doc, dict) and type(doc.get("schemaVersion")) is int and doc["schemaVersion"] == 1
            and doc.get("kind") == "instrumented_campaign_non_release" and doc.get("project") == "fineract"
            and doc.get("instrumented") is True and doc.get("releaseAcceptance") is False)


def boundary_manifest(doc):
    notes = doc.get("notes") if valid_capture(doc) else None
    if not isinstance(notes, dict):
        return None
    manifest = boundary_diagnostics.projection(notes.get("boundaryDiagnostics"))
    observed = notes.get("orderedBoundaries")
    if (manifest is None or not isinstance(observed, list)
            or len(observed) != len(manifest["phases"])
            or (observed and len(observed) != 3)):
        return None
    for phase, original in zip(manifest["phases"], observed):
        if (not isinstance(original, dict) or original.get("kind") != phase["kind"]
                or original.get("verified") is not (phase["status"] == "verified")):
            return None
    return manifest if doc.get("boundariesVerified") is (
        bool(observed) and manifest["firstUnverifiedPhase"] is None) else None


def cli_diagnostics(doc):
    """Project the first CLI failure only from a consistent bounded collection manifest."""
    if not isinstance(doc, dict) or doc.get("schema") not in ("xtrace-fineract-cli-sinks/2", "xtrace-fineract-cli-sinks/3"):
        return None
    current = doc["schema"] == "xtrace-fineract-cli-sinks/3"
    keys = ("listCommands", "detailCommands", "recordings", "completedDetails")
    if any(not bounded(doc.get(key)) for key in keys) or type(doc.get("complete")) is not bool:
        return None
    listing, details, listed, completed = (doc[key] for key in keys)
    if (listing > installed_sinks.MAX_PAGES or details > installed_sinks.MAX_RECORDINGS * installed_sinks.MAX_PAGES
            or completed > min(details, listed) or listed > installed_sinks.MAX_RECORDINGS + 100):
        return None
    failure = doc.get("firstFailure")
    if doc["complete"]:
        if failure is not None or not (listing and 0 < completed == listed <= installed_sinks.MAX_RECORDINGS):
            return None
    else:
        if (not isinstance(failure, dict) or set(failure) != {"stage", "reason", "exitCode"}
                or failure["stage"] not in ("list", "detail") or failure["reason"] not in installed_sinks.FAILURE_REASONS
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
    exits = doc.get("commandExits")
    # Errors before exec can leave the final attempted command without an exit.
    if (not isinstance(exits, list) or not listing or len(exits) not in (listing + details, listing + details - 1)
            or any(type(code) is not int or code != 0 for code in exits[:-1])):
        return None
    reason = failure["reason"] if failure else None
    if len(exits) < listing + details:
        if reason not in ("deadline", "io-error") or (exits and (type(exits[-1]) is not int or exits[-1] != 0)):
            return None
    elif exits[-1] is None:
        if reason not in ("deadline", "command-timeout"):
            return None
    elif type(exits[-1]) is not int or exits[-1] != (failure["exitCode"] if reason == "nonzero-exit" else 0):
        return None
    markers = doc.get("firstEvidenceClasses")
    if markers is not None:
        if (reason != "incomplete-evidence" or not isinstance(markers, dict)
                or set(markers) != set(installed_sinks.EVIDENCE_CLASSES)
                or any(not bounded(value) for value in markers.values()) or not 0 < sum(markers.values()) <= 4096):
            return None
    result = {**{key: doc[key] for key in keys}, "firstFailure": failure, "evidenceClasses": markers}
    require_pair = current and reason == "incomplete-evidence"
    if current:
        fields = {"schema", "complete", "artifactComplete", "commandExits", "firstFailure", *keys}
        if require_pair:
            fields.update(("firstIncomplete", "firstEvidenceClasses"))
        if set(doc) != fields or type(doc["artifactComplete"]) is not bool:
            return None
    if ("firstIncomplete" in doc) != require_pair:
        return None
    if require_pair:
        pair = fineract_detail_evidence.public_pair(doc["firstIncomplete"])
        if pair is None:
            return None
        cli = pair["cli"]
        if cli is not None:
            census = cli["markers"]
            if (census["state"] == "observed") != (markers is not None):
                return None
            if markers is not None:
                counts, total = census["counts"], sum(markers.values())
                if (sum(counts.values()) != min(total, fineract_detail_evidence.MARKER_LIMIT)
                        or census["truncated"] != (total > fineract_detail_evidence.MARKER_LIMIT)):
                    return None
                # Literal categories agree between the two classifiers. Newer range
                # validation can move a legacy gap or pending-tail marker to 'other'.
                for kind in ("persisted-partial", "persisted-invalid", "verification-budget", "gap-event", "pending-tail"):
                    if counts[kind] > markers[kind]:
                        return None
                    if kind in ("persisted-partial", "persisted-invalid", "verification-budget"):
                        if not census["truncated"] and counts[kind] != markers[kind]:
                            return None
                flexible = ("other", "gap-event", "pending-tail")
                if sum(counts[k] for k in flexible) > sum(markers[k] for k in flexible):
                    return None
        result["firstIncomplete"] = pair
    return result


def scenario_observations(sid, row):
    """Count check evaluations, never inferring a successful check for an unread or unassigned recording."""
    rules = EXPECT[sid]
    verdict = row.get("recordingVerdict")
    items = verdict.get("expectations") if isinstance(verdict, dict) else None
    if not isinstance(items, list) or len(items) != len(rules):
        return None
    checks = {}
    for rule, item in zip(rules, items):
        if (not isinstance(item, dict) or any(item.get(key) != rule[key] for key in ("label", "method", "route"))):
            return None
        candidates, inspected = item.get("recordingsMatchingRoute"), item.get("inspectedDetails")
        labels = required_observations(rule)
        failures, problems = item.get("failedObservations"), item.get("problems")
        if (not bounded(candidates) or candidates > (400 if sid == "concurrent-isolation" else 1)
                or not bounded(inspected) or inspected > candidates
                or not isinstance(failures, dict) or set(failures) != set(labels)
                or not isinstance(problems, list)
                or (inspected < candidates) != ("recording-detail-incomplete" in problems)):
            return None
        for label in labels:
            failed = failures[label]
            if not bounded(failed) or failed > inspected or (failed > 0) != (label in problems):
                return None
            counts = checks.setdefault(label, dict(expectedRequests=0, candidateDetails=0, checked=0, failed=0))
            counts["expectedRequests"] += rule["minCount"]
            counts["candidateDetails"] += candidates
            counts["checked"] += inspected
            counts["failed"] += failed
    return checks


def observations(doc):
    if not valid_capture(doc) or not isinstance(doc.get("scenarios"), list):
        return None
    rows = doc["scenarios"]
    if len(rows) != len(EXPECT) or any(not isinstance(row, dict) for row in rows):
        return None
    result = []
    for sid in EXPECT:
        matches = [row for row in rows if row.get("id") == sid]
        if len(matches) != 1:
            return None
        result.append(dict(id=sid, scope="route-group" if sid == "concurrent-isolation" else "serial",
                           checks=scenario_observations(sid, matches[0])))
    return result
