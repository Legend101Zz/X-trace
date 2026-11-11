"""Publish unittest failure identities and counts without captured fixture values."""

import argparse
import pathlib
import re


HEADER = re.compile(r"^(?:FAIL|ERROR): [A-Za-z_]\w* \([A-Za-z_][\w.]*\)(?= |$)", re.ASCII)
COUNTS = r"(?:failures|errors|skipped|expected failures|unexpected successes)=[0-9]+"
SUMMARY = re.compile(
    rf"(?:Ran [0-9]+ tests? in [0-9]+(?:\.[0-9]+)?s|"
    rf"(?:FAILED|OK) \({COUNTS}(?:, {COUNTS})*\)|OK)")


def summarize(text: str) -> str:
    """Keep headers without subtest parameters, and complete numeric summaries."""
    lines = []
    for line in text.splitlines():
        header = HEADER.match(line)
        if header:
            lines.append(header.group())
        elif SUMMARY.fullmatch(line):
            lines.append(line)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=pathlib.Path)
    args = parser.parse_args()
    print(summarize(args.log.read_text(encoding="utf-8", errors="replace")))


if __name__ == "__main__":
    main()
