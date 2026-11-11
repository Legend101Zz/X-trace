"""Publish only identities and counts from a structured unittest result file."""

import argparse
import json
import os
import pathlib
import re
import stat


IDENTIFIER = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", re.ASCII)
COUNTS = ("testsRun", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")
OUTCOMES = {"FAIL": "failures", "ERROR": "errors", "UNEXPECTED_SUCCESS": "unexpectedSuccesses"}


def summarize(result: dict) -> str:
    """Rebuild public output from typed fields; never accept a log as input."""
    if not isinstance(result, dict) or set(result) != {"counts", "identities"}:
        raise ValueError("invalid unittest result")
    counts, identities = result["counts"], result["identities"]
    if (not isinstance(counts, dict) or set(counts) != set(COUNTS)
            or any(type(value) is not int or value < 0 for value in counts.values())
            or not isinstance(identities, list)):
        raise ValueError("invalid unittest fields")
    lines = []
    seen = dict.fromkeys(OUTCOMES, 0)
    for identity in identities:
        if (not isinstance(identity, dict) or set(identity) != {"outcome", "method", "class"}
                or not isinstance(identity["outcome"], str) or identity["outcome"] not in OUTCOMES
                or any(not isinstance(identity[field], str) or not IDENTIFIER.fullmatch(identity[field])
                       for field in ("method", "class"))):
            raise ValueError("invalid unittest identity")
        outcome = identity["outcome"]
        seen[outcome] += 1
        lines.append(f'{outcome}: {identity["method"]} ({identity["class"]})')
    if any(seen[outcome] != counts[field] for outcome, field in OUTCOMES.items()):
        raise ValueError("inconsistent unittest counts")
    lines.append("unittest counts: " + " ".join(f"{key}={counts[key]}" for key in COUNTS))
    return "\n".join(lines)


def read_result(path: pathlib.Path) -> dict:
    """Refuse symlinks and result files readable by other users."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("unittest result must be private")
        return json.load(stream)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=pathlib.Path)
    args = parser.parse_args()
    try:
        public = summarize(read_result(args.result))
    except (OSError, ValueError):
        parser.exit(1, "unittest structured result unavailable or invalid\n")
    print(public)


if __name__ == "__main__":
    main()
