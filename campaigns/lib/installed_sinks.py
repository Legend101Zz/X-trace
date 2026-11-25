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

from private_sinks import AdmittedSinks

MAX_PAGES = 40
MAX_RECORDINGS = 100
MAX_OUTPUT = 16 << 20
TOTAL_SECONDS = 180


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
    status = dict(schema="xtrace-fineract-cli-sinks/1", complete=False, artifactComplete=False,
                  listCommands=0, detailCommands=0, recordings=0, commandExits=[])
    env = {**(os.environ if env is None else env), "XTRACE_DATA_HOME": str(root / "data"), "TMPDIR": str(root / "tmp")}
    deadline = time.monotonic() + TOTAL_SECONDS

    def command(arguments, name):
        admitted.check_root()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("CLI collection deadline reached")
        with (output / f"{name}.stdout").open("xb") as stdout, (output / f"{name}.stderr").open("xb") as stderr:
            try:
                result = subprocess.run([str(cli), "recording", *arguments, "--project-dir", str(source)], env=env,
                                        stdout=stdout, stderr=stderr, timeout=min(30, remaining), preexec_fn=limit_output)
                status["commandExits"].append(result.returncode)
            except subprocess.TimeoutExpired:
                status["commandExits"].append(None)
                raise
        if result.returncode or any((output / f"{name}.{ext}").stat().st_size > MAX_OUTPUT for ext in ("stdout", "stderr")):
            raise ValueError("CLI collection failed or exceeded its output bound")
        doc = json.loads((output / f"{name}.stdout").read_bytes())
        if not isinstance(doc, dict):
            raise ValueError("CLI did not return an object")
        return doc

    try:
        ids, after, seen = [], None, set()
        for page in range(MAX_PAGES):
            status["listCommands"] += 1
            doc = command(["list", "--limit", "100"] + (["--after", after] if after else []), f"list-{page:02d}")
            rows = doc.get("recordings")
            if not isinstance(rows, list) or "next_after" not in doc:
                raise ValueError("incomplete CLI list contract")
            for row in rows:
                rid = row.get("recording_id") if isinstance(row, dict) else None
                if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", rid) or rid in ids:
                    raise ValueError("invalid or repeated recording")
                ids.append(rid)
            status["recordings"] = len(ids)
            if len(ids) > MAX_RECORDINGS:
                raise ValueError("recording count bound exceeded")
            after = doc["next_after"]
            if after is None:
                break
            if not isinstance(after, str) or not after or after in seen or not rows:
                raise ValueError("invalid CLI list continuation")
            seen.add(after)
        else:
            raise ValueError("CLI list pagination bound exceeded")
        if not ids:
            raise ValueError("no CLI recordings observed")
        for index, rid in enumerate(ids):
            cursor, seen = None, set()
            for page in range(MAX_PAGES):
                status["detailCommands"] += 1
                doc = command(["show", rid, "--limit", "1000"] + (["--cursor", cursor] if cursor else []),
                              f"detail-{index:03d}-{page:02d}")
                if (doc.get("recording_id") != rid or not isinstance(doc.get("events"), list)
                        or "next_cursor" not in doc or doc.get("incomplete_evidence")):
                    raise ValueError("incomplete CLI detail contract")
                cursor = doc["next_cursor"]
                if cursor is None:
                    break
                if not isinstance(cursor, str) or not cursor or cursor in seen or not doc["events"]:
                    raise ValueError("invalid CLI detail continuation")
                seen.add(cursor)
            else:
                raise ValueError("CLI detail pagination bound exceeded")
        status["complete"] = True
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
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
