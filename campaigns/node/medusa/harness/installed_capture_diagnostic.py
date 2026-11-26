"""Project one authenticated, finite adapter exit snapshot from private runner stderr."""
import hmac
import json
import re

from installed_evidence import require

PREFIX = b"XTR-MEDUSA-CAPTURE-DIAGNOSTIC-V7 "
DAEMON_PREFIX = b"XTR-MEDUSA-DAEMON-FINISH-V1 "
DAEMON_FIELDS = ("sessions", "decoded", "admitted", "ackReady", "ackQueued", "ackFlushed")
ACTIVE_WORK = frozenset(("idle", "start", "event", "route", "finish", "close", "route-start", "route-held-events"))
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
                    "startStaged", "finishStaged", "expressEvidence", "routeFoldEvidence", "finishProgress"}) | SWITCHES


def unique(items):
    result = dict(items)
    if len(items) != len(result):
        raise ValueError("duplicate diagnostic field")
    return result


def bounded(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def read_snapshot(log, nonce, prefix):
    matches = re.finditer(rb"(?m)^" + re.escape(prefix), log)
    marker = next(matches, None)
    if marker is None:
        return None
    require(next(matches, None) is None)
    end = log.find(b"\n", marker.end(), marker.start() + 2049)
    require(end >= 0)
    obj = json.loads(log[marker.end():end], object_pairs_hook=unique)
    require(isinstance(obj, dict))
    token = obj.get("nonce")
    require(isinstance(token, str) and re.fullmatch("[a-f0-9]{48}", token))
    require(hmac.compare_digest(token, nonce))
    return obj


def project_daemon_finish(log, nonce):
    if nonce is None:
        return None
    try:
        obj = read_snapshot(log, nonce, DAEMON_PREFIX)
        if obj is None:
            return {"status": "missing"}
        require(set(obj) == {*DAEMON_FIELDS, "nonce"})
        require(all(bounded(obj[key], 4095) for key in DAEMON_FIELDS))
        require(obj["sessions"] > 0 or obj["decoded"] == 0)
        require(obj["ackFlushed"] <= obj["ackQueued"] <= obj["ackReady"] <= obj["admitted"] <= obj["decoded"])
    except (TypeError, ValueError, RecursionError):
        return {"status": "invalid"}
    return {"status": "observed", **{key: obj[key] for key in DAEMON_FIELDS}}


def project_capture_diagnostic(log, nonce):
    if nonce is None:
        return None
    try:
        obj = read_snapshot(log, nonce, PREFIX)
        if obj is None:
            return {"status": "missing"}
        require(set(obj) == FIELDS)
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
        progress = obj["finishProgress"]
        if progress is None:
            require(counts["finishPosted"] >= 4096)
        else:
            require(isinstance(progress, dict) and set(progress) ==
                    {"received", "dispatched", "submitted", "written", "staged", "active"})
            require(progress["active"] in ACTIVE_WORK)
            require(all(bounded(value, 4095) for key, value in progress.items() if key != "active"))
            require(obj["finishStaged"] == progress["staged"] <= progress["written"] <= progress["submitted"]
                    <= progress["dispatched"] <= progress["received"] <= counts["finishPosted"])
    except (TypeError, ValueError, RecursionError):
        return {"status": "invalid"}
    return {"status": "observed", **{key: obj[key] for key in FIELDS - {"nonce"}}}
