#!/usr/bin/env python3
"""Select campaign projects and emit a GitHub Actions matrix (stdlib only).

Sources, in priority order: an explicit comma-separated projects list (workflow_dispatch input), else the
branch name `ultra/campaign/<project>[-anything]` (`all` selects every project). Unknown selections fail.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

JAVA = ("petclinic", "jhipster", "fineract")
NODE = ("directus", "medusa", "vendure")
ALL = JAVA + NODE
PREFIX = "ultra/campaign/"


def select(projects: str, ref_name: str) -> list[str]:
    projects = projects.strip()
    if projects and projects != "all":
        names = [p.strip() for p in projects.split(",") if p.strip()]
    elif projects == "all":
        names = list(ALL)
    elif ref_name.startswith(PREFIX):
        token = re.split(r"-", ref_name[len(PREFIX):], maxsplit=1)[0]
        names = list(ALL) if token == "all" else [token]
    else:
        names = list(ALL)
    unknown = [n for n in names if n not in ALL]
    if unknown or not names:
        raise ValueError("unknown or empty project selection")
    return [n for n in ALL if n in names]


def matrix(repo: pathlib.Path, names: list[str]) -> dict:
    include = []
    for name in names:
        kind = "java" if name in JAVA else "node"
        camp = json.loads((repo / "campaigns" / kind / name / "campaign.json").read_text())
        up = camp["upstream"]
        entry = {"project": name, "kind": kind, "sha": up["sha"], "url": up["canonicalUrl"]}
        if kind == "java":
            entry["jdk"] = int(camp["runtime"]["jdk"])
            entry["buildCommand"] = camp["build"]["command"]
            entry["timeout"] = 180
        else:
            entry["timeout"] = 90
        include.append(entry)
    return {"include": include}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--projects", default="")
    ap.add_argument("--ref-name", default="")
    ap.add_argument("--github-output", default="")
    args = ap.parse_args()
    names = select(args.projects, args.ref_name)
    doc = matrix(pathlib.Path(args.repo), names)
    print(json.dumps(doc, indent=1))
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as out:
            out.write("matrix=" + json.dumps(doc, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
