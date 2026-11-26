"""Project one authenticated, finite adapter exit snapshot from private runner stderr."""
import hmac
import json
import re

from installed_evidence import require

PREFIX = b"XTR-MEDUSA-CAPTURE-DIAGNOSTIC-V4 "
COUNTERS = frozenset({
    "startAttempts", "startAccepted", "startCapacityRejected", "startOtherRejected",
    "finishPosted", "finishRejected", "eventRejected", "routeRejected",
    "startBeforeCreditNotification", "eventBeforeCreditNotification", "routeBeforeCreditNotification",
})
SCOPES = frozenset({"same-package", "different-package", "transitive-only", "entry-only", "neither"})
EXPRESS = frozenset({"not-observed", "installed", "express-not-found", "unsupported-express",
                    "unsupported-node", "install-failed", "disabled-other"})
SWITCHES = frozenset({"workerFailed", "transportFailed", "closeRequested"})
HANDLER_COUNTS = frozenset({"invoked", "withContext", "posted", "anyLayerStaged"})
FIELDS = frozenset({"nonce", "exitCode", "scope", "express", "patchedLayers", "counts",
                    "startStaged", "finishStaged", "expressEvidence", "routeFoldEvidence"}) | SWITCHES


def unique(items):
    result = dict(items)
    if len(items) != len(result):
        raise ValueError("duplicate diagnostic field")
    return result


def bounded(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def project_capture_diagnostic(log, nonce):
    if nonce is None:
        return None
    matches = re.finditer(rb"(?m)^" + re.escape(PREFIX), log)
    marker = next(matches, None)
    if marker is None:
        return {"status": "missing"}
    if next(matches, None) is not None:
        return {"status": "invalid"}
    end = log.find(b"\n", marker.end(), marker.start() + 2049)
    if end == -1:
        return {"status": "invalid"}
    try:
        obj = json.loads(log[marker.end():end], object_pairs_hook=unique)
        require(isinstance(obj, dict) and set(obj) == FIELDS)
        require(isinstance(obj["nonce"], str) and re.fullmatch("[a-f0-9]{48}", obj["nonce"]))
        require(hmac.compare_digest(obj["nonce"], nonce))
        require(obj["scope"] in SCOPES and obj["express"] in EXPRESS)
        require(bounded(obj["exitCode"], 255))
        require(all(type(obj[key]) is bool for key in SWITCHES))
        require(all(bounded(obj[key], 1_000_000) for key in ("patchedLayers", "startStaged", "finishStaged")))
        handlers = obj["expressEvidence"]
        require(isinstance(handlers, dict) and set(handlers) == HANDLER_COUNTS)
        require(all(bounded(value, 1_000_000) for value in handlers.values()))
        require(handlers["posted"] <= handlers["withContext"] <= handlers["invoked"])
        require(obj["patchedLayers"] > 0 or not any(handlers.values()))
        fold = obj["routeFoldEvidence"]
        require(isinstance(fold, dict) and set(fold) == {"batches", "events"})
        require(all(bounded(value, 1_000_000) for value in fold.values()))
        require(fold["batches"] <= fold["events"] <= 63 * fold["batches"])
        counts = obj["counts"]
        require(isinstance(counts, dict) and set(counts) == COUNTERS)
        require(all(bounded(value, 1_000_000) for value in counts.values()))
        require(counts["startAttempts"] == counts["startAccepted"] + counts["startCapacityRejected"] + counts["startOtherRejected"])
        require(obj["startStaged"] <= counts["startAccepted"])
        require(counts["startBeforeCreditNotification"] <= counts["startAccepted"])
        require(obj["finishStaged"] <= counts["finishPosted"] <= counts["startAccepted"])
    except (TypeError, ValueError, RecursionError):
        return {"status": "invalid"}
    return {"status": "observed", **{key: obj[key] for key in FIELDS - {"nonce"}}}
