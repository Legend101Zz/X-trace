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
import subprocess
import time
import zipfile

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


class CollectionFailure(Exception):
    def __init__(self, reason, exit_code=None):
        self.reason = reason
        self.exit_code = exit_code


def limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))


def collect(root: Path) -> bool:
    """Bound both pagination and wall time; partial CLI reads remain failures."""
    info = root.stat()
    if root.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("collection root is not owner-only")
    output = root / "sinks" / "cli"
    output.mkdir(parents=True, mode=0o700)
    status = {"schema": "xtrace-jhipster-cli-sinks/2", "complete": False,
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
                raise CollectionFailure("command-timeout") from None
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
    try:
        ids, after, seen = [], None, set()
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
                args = ["show", rid, "--limit", "1000"] + (["--cursor", cursor] if cursor else [])
                status["detailCommands"] += 1
                doc = command(args, f"detail-{index:03d}-{page:02d}")
                if doc.get("recording_id") != rid:
                    raise CollectionFailure("invalid-identity")
                if not isinstance(doc.get("events"), list):
                    raise CollectionFailure("invalid-schema")
                if "next_cursor" not in doc:
                    raise CollectionFailure("missing-cursor")
                if doc.get("incomplete_evidence"):
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
    artifact = root / "sinks" / "recordings.zip"
    status["artifactComplete"] = False
    try:
        api = root / "campaign" / "java" / "jhipster" / "instrumented-1" / "api"
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
