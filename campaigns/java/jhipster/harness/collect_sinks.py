#!/usr/bin/env python3
"""Read the installed CLI into private files; never print product output or identifiers."""
from __future__ import annotations

import argparse
import json
from itertools import islice
import os
from pathlib import Path
import re
import resource
import stat
import sys
import subprocess
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from campaigns.java.jhipster.harness import partial_provenance
from campaigns.lib.detail_pages import bound_page_end

MAX_RECORDINGS = 100
MAX_PAGES = 40
MAX_OUTPUT = 16 << 20
TOTAL_SECONDS = 180
FAILURE_REASONS = (
    "deadline", "command-timeout", "nonzero-exit", "output-limit", "io-error",
    "invalid-json", "invalid-schema", "invalid-identity", "duplicate-identity",
    "missing-cursor", "invalid-cursor", "pagination-limit", "recording-limit",
    "no-recordings", "incomplete-evidence",
)


MARKER_LIMIT = 32
MARKER_CLASSES = ("persisted-partial", "persisted-invalid", "verification-budget",
                  "event-gap", "pending-tail", "unclassified")
LIFECYCLE_STATES = ("recording", "finalizing", "complete", "partial", "invalid")
COMPLETION_STATES = ("complete", "partial", "invalid", "unavailable")


def marker_class(marker):
    if isinstance(marker, str) and len(marker) <= 64:
        if marker in ("persisted_status:partial", "persisted_status:invalid"):
            return "persisted-" + marker.split(":")[1]
        if marker == "verification_budget_exceeded":
            return "verification-budget"
        gap = re.fullmatch(r"gap_event_sequence:([1-9][0-9]{0,19})", marker)
        if gap and int(gap[1]) <= 2**64 - 1:
            return "event-gap"
        tail = re.fullmatch(r"durable_tail_pending:([1-9][0-9]{0,19})\.\.([1-9][0-9]{0,19})", marker)
        if tail and int(tail[1]) <= int(tail[2]) <= 2**64 - 1:
            return "pending-tail"
    return "unclassified"


def capture_evidence(doc, marker_key):
    markers = doc.get(marker_key)
    if not isinstance(markers, list):
        return None
    counts = dict.fromkeys(MARKER_CLASSES, 0)
    for marker in islice(markers, MARKER_LIMIT):
        counts[marker_class(marker)] += 1
    status, completion = doc.get("status"), doc.get("completion")
    return {"markers": counts, "truncated": len(markers) > MARKER_LIMIT,
            "status": status if status in LIFECYCLE_STATES else None,
            "completion": completion if completion in COMPLETION_STATES else None}


def paired_api_detail(api, rid):
    """Read only the earlier saved detail for the matching CLI identity."""
    path = api / f"recording-{rid}.json"
    try:
        if any(parent.is_symlink() for parent in (api, *api.parents)):
            return "rejected", None, None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > MAX_OUTPUT:
                return "rejected", None, None
            payload = stream.read(MAX_OUTPUT + 1)
            if len(payload) > MAX_OUTPUT:
                return "rejected", None, None
            doc = json.loads(payload)
    except FileNotFoundError:
        return "missing", None, None
    except (OSError, ValueError, RecursionError):
        return "rejected", None, None
    if not isinstance(doc, dict) or doc.get("recordingId") != rid or not isinstance(doc.get("events"), list):
        return "rejected", None, None
    if "_detailReadGap" in doc or "_http" in doc:
        return "partial-read", capture_evidence(doc, "incompleteEvidence") if "_http" not in doc else None, None
    if "nextCursor" not in doc or doc["nextCursor"] is not None:
        return "rejected", None, None
    pages = doc.get("_verifiedDetailPages")
    bound = type(pages) is int and 1 <= pages <= MAX_PAGES
    return "complete-read", capture_evidence(doc, "incompleteEvidence"), doc if bound else None


def paired_api_evidence(api, rid):
    """Read marker evidence, including aggregates predating per-page provenance."""
    state, markers, _ = paired_api_detail(api, rid)
    return state, markers


class CollectionFailure(Exception):
    def __init__(self, reason, exit_code=None):
        self.reason = reason
        self.exit_code = exit_code


def limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))


def collect(root: Path, *, list_limit: int = 100, detail_limit: int = 1000) -> bool:
    """Bound both pagination and wall time; partial CLI reads remain failures."""
    if (type(list_limit) is not int or not 1 <= list_limit <= 100
            or type(detail_limit) is not int or not 1 <= detail_limit <= 1000):
        raise ValueError("invalid collection page limit")
    info = root.stat()
    if root.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("collection root is not owner-only")
    output = root / "sinks" / "cli"
    output.mkdir(parents=True, mode=0o700)
    status = {"schema": "xtrace-jhipster-cli-sinks/3", "complete": False,
              "listCommands": 0, "detailCommands": 0, "recordings": 0,
              "completedDetails": 0, "commandExits": [], "firstFailure": None}
    env = {**os.environ, "XTRACE_DATA_HOME": str(root / "data"), "TMPDIR": str(root / "tmp")}
    binary = root / "installed X-trace" / "bin" / "xtrace"
    project = root / "campaign" / "java" / "jhipster" / "src"
    deadline = time.monotonic() + TOTAL_SECONDS

    def command(args, label):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CollectionFailure("deadline")
        stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
        # File redirection keeps raw output private even on failure or timeout.
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                result = subprocess.run([str(binary), "recording", *args, "--project-dir", str(project)],
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

    api = root / "campaign" / "java" / "jhipster" / "instrumented-1" / "api"
    first_incomplete = None
    stage = "list"
    try:
        ids, after, seen = [], None, set()
        for page in range(MAX_PAGES):
            args = ["list", "--limit", str(list_limit)] + (["--after", after] if after else [])
            status["listCommands"] += 1
            doc = command(args, f"list-{page:02d}")
            rows = doc.get("recordings")
            if not isinstance(rows, list):
                raise CollectionFailure("invalid-schema")
            for row in rows:
                rid = row.get("recording_id") if isinstance(row, dict) else None
                if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", rid):
                    raise CollectionFailure("invalid-identity")
                if rid in ids:
                    raise CollectionFailure("duplicate-identity")
                ids.append(rid)
            status["recordings"] = len(ids)
            if len(ids) > MAX_RECORDINGS:
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
        if not ids:
            raise CollectionFailure("no-recordings")
        stage = "detail"
        for index, rid in enumerate(ids):
            cursor, seen = None, set()
            for page in range(MAX_PAGES):
                args = ["show", rid, "--limit", str(detail_limit)] + (["--cursor", cursor] if cursor else [])
                status["detailCommands"] += 1
                doc = command(args, f"detail-{index:03d}-{page:02d}")
                if doc.get("recording_id") != rid:
                    raise CollectionFailure("invalid-identity")
                if not isinstance(doc.get("events"), list):
                    raise CollectionFailure("invalid-schema")
                if "next_cursor" not in doc:
                    raise CollectionFailure("missing-cursor")
                if "incomplete_evidence" in doc and doc["incomplete_evidence"] != []:
                    first_incomplete = rid, capture_evidence(doc, "incomplete_evidence"), (
                        page == 0 and doc["next_cursor"] is None), doc
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
        rid, evidence, cli_full_read, cli_doc = first_incomplete
        api_read, api_evidence, api_doc = paired_api_detail(api, rid)
        cli_scope_verified = cli_full_read
        if cli_full_read:
            try:
                bound_page_end(cli_doc, "recording_id", rid, None, detail_limit, -1)
            except ValueError:
                cli_scope_verified = False
        status["firstIncomplete"] = {
            "cli": evidence, "api": api_evidence, "apiRead": api_read,
            "cliReadScope": "whole-recording" if cli_scope_verified else "one-page",
            "provenance": {"cli": partial_provenance.project(cli_doc, whole=cli_scope_verified),
                           "api": partial_provenance.project(api_doc, whole=True) if api_doc else None},
        }
    artifact = root / "sinks" / "recordings.zip"
    status["artifactComplete"] = False
    try:
        files = sorted(islice(api.glob("*.json"), 1025))
        if (not files or len(files) > 1024 or api.is_symlink()
                or any(p.is_symlink() or not stat.S_ISREG(p.stat().st_mode) for p in files)
                or sum(p.stat().st_size for p in files) > 64 << 20):
            raise ValueError("API artifact input bound or evidence gap")
        # This is a private saved-recording artifact, not an export or public upload.
        with zipfile.ZipFile(artifact, "x", compression=zipfile.ZIP_STORED) as archive:
            for index, path in enumerate(files):
                archive.write(path, f"api-{index:04d}.json")
        status["artifactComplete"] = True
    except (OSError, ValueError, zipfile.BadZipFile):
        pass
    (root / "sinks" / "cli-status.json").write_text(json.dumps(status, sort_keys=True) + "\n")
    return status["complete"] and status["artifactComplete"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        ok = collect(args.private_root)
    except (OSError, ValueError):
        ok = False
    print("JHipster installed CLI collection: " + ("complete" if ok else "incomplete"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
