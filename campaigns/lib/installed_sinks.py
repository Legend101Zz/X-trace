"""Collect installed CLI pages and a private API ZIP with strict completion bounds.

Uses the same CLI contract, time/page/file bounds and saved-API artifact scope as
JHipster's collector. No export or independent request-correlation claim is made.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import resource
import subprocess
import time
import zipfile

import fineract_detail_evidence
from private_sinks import AdmittedSinks

MAX_PAGES = 40
MAX_RECORDINGS = 100
MAX_OUTPUT = 16 << 20
TOTAL_SECONDS = 180


FAILURE_REASONS = (
    "deadline", "command-timeout", "nonzero-exit", "output-limit", "io-error",
    "invalid-json", "invalid-schema", "invalid-identity", "duplicate-identity",
    "missing-cursor", "invalid-cursor", "pagination-limit", "recording-limit",
    "no-recordings", "incomplete-evidence",
)


EVIDENCE_CLASSES = ("persisted-partial", "persisted-invalid", "pending-tail", "verification-budget", "gap-event", "other")


def evidence_classes(markers):
    """Preserve category incidence without exporting sequence offsets or private strings."""
    counts = dict.fromkeys(EVIDENCE_CLASSES, 0)
    if not isinstance(markers, list) or len(markers) > 4096:
        return None
    fixed = {"persisted_status:partial": "persisted-partial", "persisted_status:invalid": "persisted-invalid",
             "verification_budget_exceeded": "verification-budget"}
    for marker in markers:
        if not isinstance(marker, str):
            return None
        category = fixed.get(marker)
        if category is None:
            if re.fullmatch(r"durable_tail_pending:[0-9]{1,20}\.\.[0-9]{1,20}", marker):
                category = "pending-tail"
            elif re.fullmatch(r"gap_event_sequence:[0-9]{1,20}", marker):
                category = "gap-event"
            else:
                category = "other"
        counts[category] += 1
    return counts


class CollectionFailure(Exception):
    def __init__(self, reason, exit_code=None):
        self.reason = reason
        self.exit_code = exit_code


def limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))


def collect(root, project, capture, *, env=None):
    admitted = AdmittedSinks(root)
    if project != "fineract" or capture != root / "campaign/java/fineract/instrumented-1/capture":
        raise ValueError("unsupported installed collector scope")
    cli = root / "installed X-trace/bin/xtrace"
    source = root / "campaign/java/fineract/src"
    output = root / "sinks/cli"
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    status = dict(schema="xtrace-fineract-cli-sinks/3", complete=False, artifactComplete=False,
                  listCommands=0, detailCommands=0, recordings=0, completedDetails=0, commandExits=[], firstFailure=None)
    env = {**(os.environ if env is None else env), "XTRACE_DATA_HOME": str(root / "data"), "TMPDIR": str(root / "tmp")}
    deadline = time.monotonic() + TOTAL_SECONDS

    def command(args, label):
        admitted.check_root()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CollectionFailure("deadline")
        stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
        # File redirection keeps raw output private even on failure or timeout.
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                result = subprocess.run([str(cli), "recording", *args, "--project-dir", str(source)],
                                        env=env, stdout=out, stderr=err, timeout=min(30, remaining),
                                        preexec_fn=limit_output)
                status["commandExits"].append(result.returncode)
            except subprocess.TimeoutExpired:
                status["commandExits"].append(None)
                raise CollectionFailure("deadline" if remaining <= 30 else "command-timeout") from None
        if result.returncode:
            raise CollectionFailure("nonzero-exit", result.returncode)
        if stdout.stat().st_size > MAX_OUTPUT or stderr.stat().st_size > MAX_OUTPUT:
            raise CollectionFailure("output-limit")
        try:
            doc = json.loads(stdout.read_bytes())
        except (ValueError, RecursionError):
            raise CollectionFailure("invalid-json") from None
        if not isinstance(doc, dict):
            raise CollectionFailure("invalid-schema")
        return doc

    stage = "list"
    first_incomplete = None
    try:
        listed_ranges, after, seen = {}, None, set()
        for page in range(MAX_PAGES):
            args = ["list", "--limit", "100"] + (["--after", after] if after else [])
            status["listCommands"] += 1
            doc = command(args, f"list-{page:02d}")
            rows = doc.get("recordings")
            if not isinstance(rows, list):
                raise CollectionFailure("invalid-schema")
            for row in rows:
                rid = row.get("recording_id") if isinstance(row, dict) else None
                if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", rid):
                    raise CollectionFailure("invalid-identity")
                if rid in listed_ranges:
                    raise CollectionFailure("duplicate-identity")
                listed_ranges[rid] = fineract_detail_evidence.listed_range(doc, row, after, api=False)
            status["recordings"] = len(listed_ranges)
            if len(listed_ranges) > MAX_RECORDINGS:
                raise CollectionFailure("recording-limit")
            if "next_after" not in doc:
                raise CollectionFailure("missing-cursor")
            after = doc["next_after"]
            if after is None:
                break
            if not isinstance(after, str) or not after or after in seen or not rows:
                raise CollectionFailure("invalid-cursor")
            seen.add(after)
        else:
            raise CollectionFailure("pagination-limit")
        if not listed_ranges:
            raise CollectionFailure("no-recordings")
        stage = "detail"
        for index, rid in enumerate(listed_ranges):
            cursor, seen = None, set()
            pages = fineract_detail_evidence.DetailPages(api=False, listed=listed_ranges[rid])
            for page in range(MAX_PAGES):
                args = ["show", rid, "--limit", "1000"] + (["--cursor", cursor] if cursor else [])
                status["detailCommands"] += 1
                doc = command(args, f"detail-{index:03d}-{page:02d}")
                if doc.get("recording_id") != rid:
                    raise CollectionFailure("invalid-identity")
                if not isinstance(doc.get("events"), list):
                    raise CollectionFailure("invalid-schema")
                if "next_cursor" not in doc:
                    raise CollectionFailure("missing-cursor")
                pages.add(doc, rid, cursor)
                if doc.get("incomplete_evidence"):
                    status["firstEvidenceClasses"] = evidence_classes(doc["incomplete_evidence"])
                    first_incomplete = (rid, pages, doc)
                    raise CollectionFailure("incomplete-evidence")
                cursor = doc["next_cursor"]
                if cursor is None:
                    status["completedDetails"] += 1
                    break
                if not isinstance(cursor, str) or not cursor or cursor in seen or not doc["events"]:
                    raise CollectionFailure("invalid-cursor")
                seen.add(cursor)
            else:
                raise CollectionFailure("pagination-limit")
        status["complete"] = True
    except CollectionFailure as error:
        status["firstFailure"] = {"stage": stage, "reason": error.reason, "exitCode": error.exit_code}
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        status["firstFailure"] = {"stage": stage, "reason": "io-error", "exitCode": None}
    if first_incomplete is not None:
        rid, pages, doc = first_incomplete
        try:
            status["firstIncomplete"] = fineract_detail_evidence.first_pair(capture / "api", rid, pages, doc, MAX_OUTPUT)
        except (OSError, ValueError, TypeError, RecursionError):
            status["firstIncomplete"] = fineract_detail_evidence.unavailable_pair("unavailable")
    try:
        inventory = admitted.inventory([capture / "api"])
        files = inventory["files"]
        if (inventory["missing"] or not files or len(files) > 1024 or inventory["bytes"] > 64 << 20
                or any(Path(row["path"]).suffix != ".json" or (root / row["path"]).parent != capture / "api" for row in files)):
            raise ValueError("API artifact input missing or beyond bound")
        with zipfile.ZipFile(root / "sinks/recordings.zip", "x", compression=zipfile.ZIP_STORED) as archive:
            for index, row in enumerate(files):
                archive.write(root / row["path"], f"api-{index:04d}.json")
        if admitted.inventory([capture / "api"]) != inventory:
            raise ValueError("API artifact inputs changed")
        status["artifactComplete"] = True
    except (OSError, ValueError, zipfile.BadZipFile):
        pass
    (root / "sinks/cli-status.json").write_text(json.dumps(status, sort_keys=True) + "\n")
    return status["complete"] and status["artifactComplete"]
