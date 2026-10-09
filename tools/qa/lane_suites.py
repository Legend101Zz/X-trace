#!/usr/bin/env python3
"""Select the lane CI suites for a push (stdlib only).

Always plans cumulatively: it diffs the merge-base with origin/main to HEAD, never only the pushed
range. A per-push range would let a later docs-only push (or a cancelled/failed earlier run) mask a changed
crate, so green on the lane would not mean HEAD is green. It prints a JSON suite plan:

  {"mode": ..., "changed": N, "suites": {"<suite>": {"status": "selected" | "skipped-by-filter" | "absent", ...}}}

Statuses at plan time are never "pass": a suite that did not run is never reported as passing.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

SUITES = ("meta", "rust", "java", "node", "web", "tui")
ZERO_SHA = "0" * 40
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CRATE_RE = re.compile(r"^crates/([A-Za-z0-9_-]+)/")

# Path prefixes (or exact files) that select a suite. "meta" is always selected: it is the cheap
# smoke suite (workflow lint plus the unit tests of these tools).
PREFIXES: dict[str, tuple[str, ...]] = {
    "rust": ("crates/", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/", "schema/",
             "rustfmt.toml", ".rustfmt.toml", "clippy.toml", ".clippy.toml", "deny.toml",
             # xtrace-cli tests drive the built adapters, the embedded viewer and the Playwright journeys.
             "adapters/", "web/app/"),
    "java": ("adapters/java/", "schema/"),
    "node": ("adapters/node/", "schema/"),
    "web": ("web/app/", "schema/xtp-client/"),
    "tui": ("crates/xtrace-tui/", "Cargo.toml", "Cargo.lock"),
}
TUI_DIR = "crates/xtrace-tui"
# A change to the lane's own definition or tooling can break any job, so it selects every present suite.
SELECT_ALL = (".github/workflows/lane.yml", "tools/qa/", "tools/release/ci_floor.py")


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)


def changed_files(repo: pathlib.Path, head: str, before: str | None, base_ref: str) -> tuple[str, list[str] | None]:
    """Return (mode, files); files is None when no diff basis could be established.

    `before` is accepted for command-line compatibility and ignored: the plan is cumulative.
    """
    mb = _git(repo, "merge-base", base_ref, head)
    if mb.returncode == 0 and mb.stdout.strip():
        out = _git(repo, "diff", "--name-only", "--no-renames", f"{mb.stdout.strip()}..{head}")
        if out.returncode == 0:
            return "merge-base", [line for line in out.stdout.splitlines() if line]
    return "unknown", None


def _matches(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p or (p.endswith("/") and path.startswith(p)) for p in prefixes)


def plan(files: list[str] | None, force: str, repo: pathlib.Path) -> dict:
    """Build the plan. files=None (unknown basis) selects everything: never silently skip."""
    forced = set(SUITES) if force == "all" else ({force} if force in SUITES else set())
    suites: dict[str, dict] = {}
    for name in SUITES:
        if name == "meta":
            suites[name] = {"status": "selected", "reason": "always"}
            continue
        if name == "tui" and not (repo / TUI_DIR).is_dir():
            suites[name] = {"status": "absent", "reason": "crates/xtrace-tui does not exist"}
            if name in forced and force != "all":
                suites[name]["forced"] = True  # an explicit request for an absent suite is not a pass
            continue
        if files is None:
            suites[name] = {"status": "selected", "reason": "no-diff-basis"}
        elif name in forced:
            suites[name] = {"status": "selected", "reason": "dispatch"}
        elif any(_matches(f, PREFIXES[name]) for f in files):
            suites[name] = {"status": "selected", "reason": "path-filter"}
        elif any(_matches(f, SELECT_ALL) for f in files):
            suites[name] = {"status": "selected", "reason": "lane-definition-changed"}
        else:
            suites[name] = {"status": "skipped-by-filter", "reason": "no matching path changed"}
    crates = sorted({m.group(1) for f in (files or []) if (m := CRATE_RE.match(f))})
    if "rust" in suites and suites["rust"]["status"] == "selected":
        # The workspace is small: any changed or shared crate selects the whole workspace.
        suites["rust"]["changedCrates"] = crates
    return suites


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--head", required=True)
    ap.add_argument("--before", default="")
    ap.add_argument("--base-ref", default="origin/main")
    ap.add_argument("--force", default="", help="suite name or 'all' (workflow_dispatch)")
    ap.add_argument("--github-output", default="")
    args = ap.parse_args()
    repo = pathlib.Path(args.repo).resolve()
    mode, files = changed_files(repo, args.head, args.before, args.base_ref)
    if args.force:
        mode = f"dispatch+{mode}"
    suites = plan(files, args.force, repo)
    doc = {"mode": mode, "changed": None if files is None else len(files), "suites": suites}
    print(json.dumps(doc, sort_keys=True, indent=1))
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as out:
            out.write("plan=" + json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
            for name, info in suites.items():
                out.write(f"{name}={'true' if info['status'] == 'selected' else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
