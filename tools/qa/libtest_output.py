"""Private libtest frames. Callers must attest every public name and site to HEAD.

Cargo's target boundary and libtest's final summary frame the captured sections.
Individual status lines are not reliable: uncaptured worker/child writes can split
them. A thread name identifies a thread, not necessarily the owning test.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from tools.qa import rust_timing

RESULT = re.compile(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored")
SUMMARY_NAME = re.compile(r"^    (\S+)$")
SECTION = re.compile(r"^---- (\S+) (?:stdout|stderr) ----$")
PANIC = re.compile(r"^thread '([^']+)'(?: \([0-9]+\))? panicked at (\S{1,300}):([0-9]+):([0-9]+):$")


@dataclass
class Report:
    """One completed Cargo binary, with only the final libtest failure list."""

    header: str
    counts: tuple[int, int, int]
    names: list[str]
    body: list[str]
    boundaries: list[bool]


def _boundaries(lines: list[str]) -> list[bool]:
    """Quoted/compound fixture continuations cannot introduce harness facts."""
    quote = None
    depth = 0
    allowed = []
    for line in lines:
        allowed.append(not quote and not depth)
        if allowed[-1] and PANIC.fullmatch(line):
            continue
        escaped = False
        for char in line:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif quote:
                if char == quote:
                    quote = None
            elif char in {'"', '`'}:
                quote = char
            elif char in "{[":
                depth += 1
            elif char in "}]":
                depth = max(0, depth - 1)
    return allowed


def partition(text: str) -> tuple[list[Report], str]:
    """Remove complete Cargo/libtest frames; leave incomplete streams to the fallback.

    The final list is read backwards from the result, so the earlier `failures:`
    introducing captured output cannot be mistaken for the list of failed tests.
    Full framing is required before relaxing the fallback's payload ambiguity rule.
    """
    lines = rust_timing.ANSI.sub("", text).splitlines()
    allowed = _boundaries(lines)
    starts = [i for i, line in enumerate(lines) if allowed[i] and (
        rust_timing.RUNNING.fullmatch(line) or rust_timing.DOC_TESTS.fullmatch(line))]
    reports = []
    consumed = set()
    for start, end in zip(starts, [*starts[1:], len(lines)]):
        results = [i for i in range(start + 1, end) if allowed[i] and RESULT.match(lines[i])]
        if not results:
            continue
        result = results[-1]
        if not any(allowed[i] and re.fullmatch(r"running \d+ tests?", lines[i])
                   for i in range(start + 1, result)):
            continue
        counts = tuple(map(int, RESULT.match(lines[result]).groups()))
        cursor = result - 1
        names = []
        while cursor > start:
            if not lines[cursor].strip():
                cursor -= 1
                continue
            name = SUMMARY_NAME.fullmatch(lines[cursor]) if allowed[cursor] else None
            if not name:
                break
            names.append(name[1])
            cursor -= 1
        if counts[1] and not (cursor > start and allowed[cursor] and lines[cursor] == "failures:"):
            continue
        body_end = cursor if counts[1] else result
        reports.append(Report(lines[start], counts, list(dict.fromkeys(reversed(names))) if counts[1] else [],
                              lines[start + 1:body_end], allowed[start + 1:body_end]))
        consumed.update(range(start, result + 1))
    return reports, "\n".join(line for i, line in enumerate(lines) if i not in consumed)
