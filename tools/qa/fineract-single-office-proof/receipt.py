"""Finite checkpoint for the single Fineract read; only validated fields leave the runner."""
import json
import os
from pathlib import Path
import stat


PHASES = ("setup", "package", "archive", "install", "checkout", "tag-license", "database-image",
          "bootjar", "identities", "init", "startup", "before", "office", "poll", "explicit-stop", "final-read")
STATES = ("unreached", "started", "passed", "failed")
RELEASES = ("liveViewer", "finalViewer", "launcher", "databaseExit", "databaseRemove", "networkRemove")
GAPS = ("line_budget", "value_budget", "throttle", "queue_full", "correlation_lost", "class_not_transformed",
        "module_loaded_before_arm", "source_map_absent", "handled_exception_unobserved",
        "child_process_not_instrumented", "bootstrap_consumed", "other")
TYPES = {
    "completion": ("complete", "partial", "invalid", "unavailable"),
    "terminal": ("present", "absent", "unknown"),
    "drops": ("zero", "positive", "missing", "unavailable", "malformed"),
    "dropBucketState": ("observed", "unavailable", "missing", "malformed"),
}
COUNTS = ("wholeEvents", "responses", "gaps", "resourceEnters", "firstEvents", "firstResponses",
          "firstGaps", "firstDatabaseStarts", "firstDatabaseEnds", "positiveDropBuckets")


def check(condition):
    if not condition:
        raise ValueError("fixture evidence invariant")


def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def fresh():
    return {"schema": 1, "releaseAcceptance": False, "phases": dict.fromkeys(PHASES, "unreached"),
            "release": dict.fromkeys(RELEASES, "unreached"), "businessAttempts": 0, "http200": None,
            "seedPredicate": None, "launcherExit": None, "pollsCompleted": 0,
            "lastPoll": None, "selected": None, "identityConflict": False, "selectionUnresolved": False,
            "viewerShutdown": {key: {"state": "unreached", "exitCode": None} for key in ("liveViewer", "finalViewer")},
            "stopResult": None, "sameIdRecovery": None, "finalApiRead": None,
            "finalCompletion": None, "recoveredCompletion": None}


def valid(doc):
    check(type(doc) is dict and doc.keys() == fresh().keys() and type(doc['schema']) is int and
          doc['schema'] == 1 and doc['releaseAcceptance'] is False)
    for section, keys in (("phases", PHASES), ("release", RELEASES)):
        check(type(doc[section]) is dict and set(doc[section]) == set(keys)
              and all(v in STATES for v in doc[section].values()))
    for k in ("http200", "seedPredicate"):
        check(doc[k] is None or type(doc[k]) is bool)
    check(integer(doc["businessAttempts"], 0, 1) and integer(doc["pollsCompleted"], 0, 1_000_000))
    check(doc["launcherExit"] is None or integer(doc["launcherExit"], -127, 255))
    check(doc["lastPoll"] in (None, "not-observed", "unbound", "ambiguous", "unique-new-office-root",
                                "deadline", "launcher-exited", "incomplete"))
    check(type(doc["selectionUnresolved"]) is bool)
    check(type(doc["viewerShutdown"]) is dict and set(doc["viewerShutdown"]) == {"liveViewer", "finalViewer"})
    for key, lifecycle in doc["viewerShutdown"].items():
        check(type(lifecycle) is dict and set(lifecycle) == {"state", "exitCode"})
        check(lifecycle["state"] in ("unreached", "early-exit", "signal-raced-exit", "signal-error",
                                    "term-sent", "wait-expired", "exit-after-term"))
        check(lifecycle["exitCode"] is None or integer(lifecycle["exitCode"], -127, 255))
        if doc["release"][key] == "passed":
            check(lifecycle == {"state": "exit-after-term", "exitCode": 0})
    check(type(doc["identityConflict"]) is bool and doc["stopResult"] in (None, "validated", "rejected"))
    check(doc["sameIdRecovery"] in (None, "listed", "not-listed", "unavailable", "rejected", "unbound"))
    check(doc["finalApiRead"] in (None, "whole-recording", "terminal-window", "partial-window", "missing",
                                  "unavailable", "rejected"))
    check(doc["finalCompletion"] in (None, *TYPES["completion"], "missing", "unrecognized", "malformed"))
    check(doc["recoveredCompletion"] in (None, "complete", "partial", "failed", "invalid"))
    row = doc["selected"]
    if row is not None:
        check(type(row) is dict and set(row) == {*TYPES, *COUNTS, "gapReasons", "http200"})
        check(all(row[k] in options for k, options in TYPES.items()))
        for k in COUNTS:
            if k == "positiveDropBuckets":
                check(row[k] is None or integer(row[k], 0, 256))
            else:
                check(integer(row[k], 0, 1000 if k.startswith("first") else 40000))
        check(row["http200"] is None or type(row["http200"]) is bool)
        gaps = row["gapReasons"]
        check(gaps is None or (isinstance(gaps, dict) and set(gaps) == set(GAPS)
                               and all(integer(x, 0, 40000) for x in gaps.values())
                               and sum(gaps.values()) == row["gaps"]))
    return doc


def checkpoint(root, doc):
    data = json.dumps(valid(doc), sort_keys=True).encode() + b"\n"
    check(len(data) <= 8192)
    path = root / "checkpoint.pending"
    with path.open("xb") as f:
        f.write(data)
    path.replace(root / "checkpoint.json")


def public(root):
    path = root / "checkpoint.json"
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        info = os.fstat(f.fileno())
        check(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
              and not info.st_mode & 0o077 and info.st_size <= 8192)
        doc = valid(json.loads(f.read(8193)))
    with (root / "public" / "summary.json").open("x") as f:
        json.dump(doc, f, sort_keys=True)
        f.write("\n")


def qualifies(doc):
    return (all(s == "passed" for s in doc["phases"].values()) and
            all(s == "passed" for s in doc["release"].values()) and
            doc["businessAttempts"] == 1 and doc["http200"] is True and doc["seedPredicate"] is True and
            doc["selected"] is not None and not doc["identityConflict"] and not doc["selectionUnresolved"]
            and doc["stopResult"] == "validated"
            and doc["sameIdRecovery"] in ("listed", "not-listed") and doc["finalApiRead"] == "whole-recording")


if __name__ == "__main__":
    import sys
    root = Path(os.environ["PROOF"])
    os.umask(0o077)
    if sys.argv[1:] == ["init"]:
        checkpoint(root, fresh())
    elif sys.argv[1:] == ["public"]:
        public(root)
    else:
        raise SystemExit(2)
