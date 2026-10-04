#!/usr/bin/env python3
"""Reproducibility check: build the same commit twice from clean, differently-located checkouts and compare.

    python3 packaging/repro_check.py --out DIR [--platform P] [--tree SRC_DIR --commit SHA --source-date-epoch N]

Without --tree it exports HEAD with `git archive` into two fresh directories. With --tree (a checkout without .git,
e.g. inside the devbox) it copies that tree. Exit 0 only if the archives, SBOMs and license files are byte-identical.
Writes DIR/repro.json.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def sha(p: Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--platform")
    ap.add_argument("--tree", type=Path)
    ap.add_argument("--commit")
    ap.add_argument("--source-date-epoch", type=int)
    a = ap.parse_args(argv)
    out = a.out.resolve()
    if a.tree:
        if not a.commit or a.source_date_epoch is None:
            sys.exit("--tree needs --commit and --source-date-epoch")
        commit, epoch = a.commit, a.source_date_epoch
    else:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
        epoch = int(subprocess.check_output(["git", "log", "-1", "--format=%ct", commit], cwd=REPO, text=True))
    results = {}
    for name in ("build-a", "build-b"):
        base = out / name
        if base.exists():
            shutil.rmtree(base)
        src = base / ("src-" + name)  # differing absolute paths on purpose
        src.mkdir(parents=True)
        if a.tree:
            shutil.copytree(a.tree, src, dirs_exist_ok=True, ignore=shutil.ignore_patterns(
                ".git", "node_modules", "build", "dist", "target", ".gradle"), symlinks=True)
        else:
            tar = subprocess.Popen(["git", "archive", commit], cwd=REPO, stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "-C", str(src)], stdin=tar.stdout, check=True)
            if tar.wait():
                sys.exit("git archive failed")
        cmd = [sys.executable, str(src / "packaging" / "build.py"), "--source", str(src), "--commit", commit,
               "--source-date-epoch", str(epoch), "--out", str(base / "dist"), "--work", str(base / "work")]
        if a.platform:
            cmd += ["--platform", a.platform]
        subprocess.run(cmd, check=True)
        (plat,) = [d for d in (base / "dist").iterdir() if d.is_dir()]
        results[name] = {f.name: sha(f) for f in sorted(plat.iterdir()) if f.name != "build-info.json"}
        shutil.rmtree(base / "work", ignore_errors=True)
    a_, b_ = results["build-a"], results["build-b"]
    diff = sorted(k for k in set(a_) | set(b_) if a_.get(k) != b_.get(k))
    report = {"commit": commit, "sourceDateEpoch": epoch, "reproducible": not diff, "differing": diff,
              "buildA": a_, "buildB": b_}
    (out / "repro.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"reproducible": not diff, "differing": diff}))
    return 0 if not diff else 1


if __name__ == "__main__":
    raise SystemExit(main())
