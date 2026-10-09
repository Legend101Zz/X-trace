#!/usr/bin/env python3
"""Other-UID private-storage negative for the hosted macOS CI job (ADR 0006 section 2.3).

After a real xtrace store exists, a second local user on the hosted runner must be unable to traverse or read it.
The check fails (never skips) when the store is missing or empty, when any store entry is group or world
accessible, when the other user can list or read any probed target, or when the other user cannot run anything at
all (a positive control, so a broken sudo or user setup cannot masquerade as a permission denial). An ok-marker is
written only by a fully successful check; `verify-marker` is the final `if: always()` step that fails without it.

  create-user  : create the second local user (hosted GitHub Actions macOS runner only; uses sudo + dscl)
  check        : run the negative against a store root; writes the ok-marker on success
  verify-marker: fail unless the ok-marker exists with the exact expected content
  delete-user  : remove the second local user (best effort cleanup)

Public output is limited to the fixed lines below (counts, fixed words, exit codes). No paths, no names of store
entries, no raw command output ever leave this tool. Run from the repository root:
  python3 -B -m tools.qa.other_uid_negative <subcommand> ...
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import Callable, Sequence

USER_RE = re.compile(r"^[a-z][a-z0-9_]{2,30}$")
MARKER_RE = re.compile(r"^other-uid-negative ok targets=[1-9][0-9]{0,3} control=ok\n$")
MAX_TARGETS = 40
MAX_WALK = 5000
PROBE_TIMEOUT = 30
DENIED = ("permission denied", "operation not permitted")
FIRST_FREE_UID = 7700

# runner(argv) -> (returncode, stderr_text). Injected by the unit tests; the default one runs under a clean env.
Runner = Callable[[Sequence[str]], "tuple[int, str]"]


class CheckError(Exception):
    """A failed check. The message is a fixed phrase and never carries paths or raw output."""


def _emit(line: str) -> None:
    print(f"other-uid {line}")


def is_hosted_runner(env: "dict[str, str] | None" = None, platform: "str | None" = None) -> bool:
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    return (env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and platform == "darwin")


def pick_uid(existing: "Sequence[int]", start: int = FIRST_FREE_UID) -> int:
    taken = set(existing)
    uid = start
    while uid in taken:
        uid += 1
    return uid


def audit_store(root: pathlib.Path) -> "tuple[list[pathlib.Path], list[pathlib.Path], pathlib.Path]":
    """Walk the store (lstat only). Returns (directories, files, first sqlite database).

    Raises CheckError when the store is missing, empty, holds no database, contains a symlink, or any entry has a
    group or other permission bit set.
    """
    try:
        st = root.lstat()
    except OSError:
        raise CheckError("store-missing") from None
    if not stat.S_ISDIR(st.st_mode):
        raise CheckError("store-missing")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise CheckError("store-mode-open")
    dirs: list[pathlib.Path] = []
    files: list[pathlib.Path] = []
    db: "pathlib.Path | None" = None
    seen = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            names = sorted(os.listdir(current))
        except OSError:
            raise CheckError("store-unreadable") from None
        dirs.append(current)
        for name in names:
            seen += 1
            if seen > MAX_WALK:
                raise CheckError("store-too-large")
            path = current / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                raise CheckError("store-unreadable") from None
            if stat.S_ISLNK(mode):
                raise CheckError("store-symlink")
            if mode & 0o077:
                raise CheckError("store-mode-open")
            if stat.S_ISDIR(mode):
                stack.append(path)
            elif stat.S_ISREG(mode):
                files.append(path)
                if db is None and path.suffix in (".sqlite3", ".sqlite", ".db"):
                    db = path
    if not files:
        raise CheckError("store-empty")
    if db is None:
        raise CheckError("store-no-database")
    return dirs, files, db


def choose_targets(root: pathlib.Path, dirs: Sequence[pathlib.Path], files: Sequence[pathlib.Path],
                   db: pathlib.Path) -> "list[tuple[str, pathlib.Path]]":
    """Probe targets: the store root and its sub-directories (listing), the database and other files (reading)."""
    targets: "list[tuple[str, pathlib.Path]]" = [("list", root)]
    targets += [("list", d) for d in sorted(dirs) if d != root][: MAX_TARGETS // 2]
    targets.append(("read", db))
    others = [f for f in sorted(files) if f != db]
    targets += [("read", f) for f in others][: MAX_TARGETS // 2]
    return targets[:MAX_TARGETS]


def probe_argv(user: str, kind: str, path: "pathlib.Path | str") -> "list[str]":
    tool = ["/bin/ls", "--"] if kind == "list" else ["/bin/cat", "--"]
    return ["sudo", "-n", "-u", user, *tool, str(path)]


def default_runner(argv: Sequence[str]) -> "tuple[int, str]":
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
    try:
        proc = subprocess.run(list(argv), capture_output=True, cwd="/", env=env, timeout=PROBE_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""
    return proc.returncode, proc.stderr.decode("utf-8", errors="replace")


def _is_denied(rc: int, err: str) -> bool:
    return rc != 0 and any(token in err.lower() for token in DENIED)


def run_negative(root: pathlib.Path, user: str, runner: Runner = default_runner) -> int:
    """Run the whole negative. Returns the number of probed targets; raises CheckError on any failure."""
    if not USER_RE.fullmatch(user):
        raise CheckError("bad-user-name")
    dirs, files, db = audit_store(root)
    # Positive control: the other user can run commands and read world-readable system files. Without this a
    # broken sudo or a missing user would make every probe "fail" and look like a denial.
    for kind, control in (("list", "/usr/bin"), ("read", "/etc/hosts")):
        rc, _ = runner(probe_argv(user, kind, control))
        if rc != 0:
            raise CheckError("control-failed")
    targets = choose_targets(root, dirs, files, db)
    for kind, path in targets:
        rc, err = runner(probe_argv(user, kind, path))
        if rc == 0:
            raise CheckError("other-user-access-allowed")
        if not _is_denied(rc, err):
            raise CheckError("probe-not-a-permission-denial")
    return len(targets)


def write_marker(marker: pathlib.Path, targets: int) -> None:
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(f"other-uid-negative ok targets={targets} control=ok\n", encoding="ascii")


def marker_ok(marker: pathlib.Path) -> bool:
    try:
        return MARKER_RE.fullmatch(marker.read_text(encoding="ascii")) is not None
    except (OSError, UnicodeDecodeError):
        return False


def _sh(argv: Sequence[str]) -> "tuple[int, str]":
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=60, cwd="/")
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""
    return proc.returncode, proc.stdout


def cmd_create_user(args: argparse.Namespace) -> int:
    if not USER_RE.fullmatch(args.user):
        _emit("create-user FAIL bad-user-name")
        return 2
    if not is_hosted_runner():
        _emit("create-user FAIL not-a-hosted-macos-runner")  # never create users anywhere else
        return 2
    _, out = _sh(["dscl", ".", "-list", "/Users", "UniqueID"])
    uids = [int(p[-1]) for p in (line.split() for line in out.splitlines()) if p and p[-1].isdigit()]
    uid = pick_uid(uids)
    base = f"/Users/{args.user}"
    steps = [
        ["sudo", "-n", "dscl", ".", "-create", base],
        ["sudo", "-n", "dscl", ".", "-create", base, "UserShell", "/usr/bin/false"],
        ["sudo", "-n", "dscl", ".", "-create", base, "RealName", "xtrace other uid"],
        ["sudo", "-n", "dscl", ".", "-create", base, "UniqueID", str(uid)],
        ["sudo", "-n", "dscl", ".", "-create", base, "PrimaryGroupID", "20"],
        ["sudo", "-n", "dscl", ".", "-create", base, "NFSHomeDirectory", "/var/empty"],
    ]
    for step in steps:
        rc, _ = _sh(step)
        if rc != 0:
            _emit("create-user FAIL dscl")
            return 1
    rc, out = _sh(["id", "-u", args.user])
    if rc != 0 or out.strip() != str(uid) or uid == os.getuid():
        _emit("create-user FAIL not-created")
        return 1
    _emit("create-user ok")
    return 0


def cmd_delete_user(args: argparse.Namespace) -> int:
    if not USER_RE.fullmatch(args.user) or not is_hosted_runner():
        _emit("delete-user skipped-cleanup")  # cleanup only; the verdict comes from verify-marker
        return 0
    rc, _ = _sh(["sudo", "-n", "dscl", ".", "-delete", f"/Users/{args.user}"])
    _emit("delete-user ok" if rc == 0 else "delete-user failed")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    marker = pathlib.Path(args.marker)
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        _emit("check FAIL marker-unremovable")
        return 1
    try:
        n = run_negative(pathlib.Path(args.store_root), args.user, default_runner)
    except CheckError as err:
        _emit(f"check FAIL {err}")
        return 1
    write_marker(marker, n)
    _emit(f"check ok targets={n} control=ok")
    return 0


def cmd_verify_marker(args: argparse.Namespace) -> int:
    if marker_ok(pathlib.Path(args.marker)):
        _emit("verify-marker ok")
        return 0
    _emit("verify-marker FAIL the other-UID negative did not complete successfully (skipped or failed)")
    return 1


def main(argv: "Sequence[str] | None" = None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("create-user", cmd_create_user), ("delete-user", cmd_delete_user)):
        p = sub.add_parser(name)
        p.add_argument("--user", required=True)
        p.set_defaults(fn=fn)
    p = sub.add_parser("check")
    p.add_argument("--store-root", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--marker", required=True)
    p.set_defaults(fn=cmd_check)
    p = sub.add_parser("verify-marker")
    p.add_argument("--marker", required=True)
    p.set_defaults(fn=cmd_verify_marker)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
