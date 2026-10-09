#!/usr/bin/env python3
"""Other-UID private-storage substitute for the hosted macOS CI job (ADR 0006 section 2.3 and its 2026-10-10 addendum).

This is the "private-storage substitute" for the other-UID broker negative: it runs only while the tree holds no
broker code, and it does not replace the broker negative once broker code exists.

After a real xtrace store exists, a second local user on the hosted runner must be unable to traverse, read or
change it. The store directory (created by the product) is the barrier under test: the second user must be able to
list the store's parent and read a world-readable canary placed there (positive control), then fail to list the
store, read any probed entry, create a file in it, or rename or overwrite its database, and nothing may change.
The check fails (never skips) when the store is missing or empty, when any store entry is group or world
accessible or carries an ACL allow entry, when the layout is not the parent/store pair, when the other user can
list, read or write any probed target, when a denial is not an EACCES-style "Permission denied" (EPERM is
inconclusive), or when the other user cannot run anything at all. An ok-marker is written only by a fully
successful check; `verify-marker` is the final `if: always()` step that fails without it.

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
MARKER_RE = re.compile(r"^other-uid-negative ok targets=(?:[2-9]|[1-9][0-9]{1,3}) control=ok run=([0-9]{1,20})\n$")
ACL_ALLOW_RE = re.compile(r"^\s*[0-9]+:\s.*\ballow\b")
CANARY_NAME = "xtrace-canary.txt"
MAX_TARGETS = 40
MAX_WALK = 5000
PROBE_TIMEOUT = 30
FIRST_FREE_UID = 7700

# runner(argv) -> (returncode, stderr_text). Injected by the unit tests; the default one runs under a clean env.
Runner = Callable[[Sequence[str]], "tuple[int, str]"]
# acl_reader(path) -> ls -led output text for the runner's own view of an entry.
AclReader = Callable[[pathlib.Path], str]


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
                   db: pathlib.Path) -> "tuple[list[tuple[str, pathlib.Path]], int]":
    """Probe targets: the store root and its sub-directories (listing), the database and other files (reading).

    Returns (capped targets, total candidates before the cap)."""
    targets: "list[tuple[str, pathlib.Path]]" = [("list", root)]
    sub_dirs = [d for d in sorted(dirs) if d != root]
    others = [f for f in sorted(files) if f != db]
    total = 1 + len(sub_dirs) + 1 + len(others)
    targets += [("list", d) for d in sub_dirs][: MAX_TARGETS // 2]
    targets.append(("read", db))
    targets += [("read", f) for f in others][: MAX_TARGETS // 2]
    return targets[:MAX_TARGETS], total


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


def classify(rc: int, err: str) -> str:
    """allowed | denied (EACCES-shaped) | inconclusive (EPERM-shaped, TCC/SIP) | other."""
    if rc == 0:
        return "allowed"
    low = err.lower()
    if "operation not permitted" in low:
        return "inconclusive"
    if "permission denied" in low:
        return "denied"
    return "other"


def _require_denied(rc: int, err: str, allowed_phrase: str) -> None:
    verdict = classify(rc, err)
    if verdict == "allowed":
        raise CheckError(allowed_phrase)
    if verdict == "inconclusive":
        raise CheckError("probe-inconclusive")
    if verdict == "other":
        raise CheckError("probe-not-a-permission-denial")


def default_acl_reader(path: pathlib.Path) -> str:
    """The runner user's own view of an entry's ACL (`ls -led`)."""
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
    try:
        proc = subprocess.run(["/bin/ls", "-led", "--", str(path)], capture_output=True, cwd="/", env=env,
                              timeout=PROBE_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise CheckError("store-acl-unreadable") from None
    if proc.returncode != 0:
        raise CheckError("store-acl-unreadable")
    return proc.stdout.decode("utf-8", errors="replace")


def audit_acls(entries: Sequence[pathlib.Path], reader: AclReader) -> None:
    """Fail when any store entry carries an ACL allow entry (the owner needs none)."""
    for entry in entries:
        for line in reader(entry).splitlines()[1:]:
            if ACL_ALLOW_RE.match(line):
                raise CheckError("store-acl-allow")


def write_probes(root: pathlib.Path, db: pathlib.Path) -> "list[list[str]]":
    """Mutations the other user must be denied: create in the store, create beside the db, rename and overwrite db."""
    return [
        ["/usr/bin/touch", "--", str(root / ".xtrace-probe-new")],
        ["/usr/bin/touch", "--", str(db.parent / ".xtrace-probe-new")],
        ["/bin/mv", "-f", "--", str(db), str(db) + ".xtrace-probe-moved"],
        ["/bin/cp", "-f", "--", "/etc/hosts", str(db)],
    ]


def _snapshot(root: pathlib.Path, db: pathlib.Path) -> object:
    dirs, files, _ = audit_store(root)
    st = db.lstat()
    return (sorted(str(p) for p in dirs), sorted(str(p) for p in files), st.st_ino, st.st_size, st.st_mtime_ns)


def run_negative(root: pathlib.Path, user: str, runner: Runner = default_runner,
                 parent: "pathlib.Path | None" = None, acl_reader: "AclReader | None" = None,
                 log: "Callable[[str], None]" = _emit) -> int:
    """Run the whole negative. Returns the number of probes; raises CheckError on any failure.

    `parent` is the directory that holds the store. The other user must list it and read a world-readable canary in
    it (positive control), so the first denial on every probe is the product-created store directory itself.
    """
    if not USER_RE.fullmatch(user):
        raise CheckError("bad-user-name")
    if parent is None or root.parent != parent or root.name in ("", ".", ".."):
        raise CheckError("layout-unreachable")
    dirs, files, db = audit_store(root)
    audit_acls([*dirs, *files], acl_reader or default_acl_reader)
    # Positive control: the other user can run commands and read world-readable system files. Without this a
    # broken sudo or a missing user would make every probe "fail" and look like a denial.
    for kind, control in (("list", "/usr/bin"), ("read", "/etc/hosts")):
        rc, _ = runner(probe_argv(user, kind, control))
        if rc != 0:
            raise CheckError("control-failed")
    canary = parent / CANARY_NAME
    try:
        canary.unlink(missing_ok=True)
        fd = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write("xtrace canary\n")
        os.chmod(canary, 0o644)
    except OSError:
        raise CheckError("canary-unwritable") from None
    for kind, control in (("list", parent), ("read", canary)):
        rc, _ = runner(probe_argv(user, kind, control))
        if rc != 0:
            raise CheckError("parent-not-traversable")
    targets, total = choose_targets(root, dirs, files, db)
    if total > len(targets):
        log(f"check targets-capped total={total} kept={len(targets)}")
    before = _snapshot(root, db)
    for kind, path in targets:
        rc, err = runner(probe_argv(user, kind, path))
        _require_denied(rc, err, "other-user-access-allowed")
    writes = write_probes(root, db)
    for argv in writes:
        rc, err = runner(["sudo", "-n", "-u", user, *argv])
        _require_denied(rc, err, "other-user-write-allowed")
    try:
        after = _snapshot(root, db)
    except (CheckError, OSError):
        raise CheckError("store-modified") from None
    if after != before:
        raise CheckError("store-modified")
    return len(targets) + len(writes)


def write_marker(marker: pathlib.Path, targets: int, run_id: str) -> bool:
    """Write the ok-marker. Returns False (after one fixed line) when it cannot be written."""
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(f"other-uid-negative ok targets={targets} control=ok run={run_id}\n", encoding="ascii")
    except OSError:
        _emit("check FAIL marker-unwritable")
        return False
    return True


def marker_ok(marker: pathlib.Path, run_id: "str | None" = None) -> bool:
    try:
        match = MARKER_RE.fullmatch(marker.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError):
        return False
    return match is not None and (run_id is None or match.group(1) == run_id)


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
    if _sh(["dscl", ".", "-read", f"/Users/{args.user}", "UniqueID"])[0] == 0 or \
            _sh(["dscl", ".", "-read", f"/Groups/{args.user}", "PrimaryGroupID"])[0] == 0:
        _emit("create-user FAIL account-exists")  # never rewrite an existing account or group
        return 2
    _, out = _sh(["dscl", ".", "-list", "/Users", "UniqueID"])
    uids = [int(p[-1]) for p in (line.split() for line in out.splitlines()) if p and p[-1].isdigit()]
    uid = pick_uid(uids)
    _, gout = _sh(["dscl", ".", "-list", "/Groups", "PrimaryGroupID"])
    gids = [int(p[-1]) for p in (line.split() for line in gout.splitlines()) if p and p[-1].isdigit()]
    gid = pick_uid(gids, uid)  # a dedicated primary group the runner user is not a member of
    base = f"/Users/{args.user}"
    gbase = f"/Groups/{args.user}"
    steps = [
        ["sudo", "-n", "dscl", ".", "-create", gbase],
        ["sudo", "-n", "dscl", ".", "-create", gbase, "PrimaryGroupID", str(gid)],
        ["sudo", "-n", "dscl", ".", "-create", base],
        ["sudo", "-n", "dscl", ".", "-create", base, "UserShell", "/usr/bin/false"],
        ["sudo", "-n", "dscl", ".", "-create", base, "RealName", "xtrace other uid"],
        ["sudo", "-n", "dscl", ".", "-create", base, "UniqueID", str(uid)],
        ["sudo", "-n", "dscl", ".", "-create", base, "PrimaryGroupID", str(gid)],
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
    rc, gout = _sh(["id", "-g", args.user])
    if rc != 0 or gout.strip() != str(gid) or gid == os.getgid():
        _emit("create-user FAIL group")
        return 1
    _emit("create-user ok")
    return 0


def cmd_delete_user(args: argparse.Namespace) -> int:
    if not USER_RE.fullmatch(args.user) or not is_hosted_runner():
        _emit("delete-user skipped-cleanup")  # cleanup only; the verdict comes from verify-marker
        return 0
    rc, _ = _sh(["sudo", "-n", "dscl", ".", "-delete", f"/Users/{args.user}"])
    rg, _ = _sh(["sudo", "-n", "dscl", ".", "-delete", f"/Groups/{args.user}"])
    _emit("delete-user ok" if rc == 0 and rg == 0 else "delete-user failed")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    if not is_hosted_runner():
        _emit("check FAIL not-a-hosted-macos-runner")  # check runs sudo; never anywhere else
        return 2
    marker = pathlib.Path(args.marker)
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        _emit("check FAIL marker-unremovable")
        return 1
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[0-9]{1,20}", run_id):
        _emit("check FAIL run-id-missing")
        return 1
    try:
        n = run_negative(pathlib.Path(args.store_root), args.user, default_runner,
                         pathlib.Path(args.parent))
    except CheckError as err:
        _emit(f"check FAIL {err}")
        return 1
    if n < 2:
        _emit("check FAIL too-few-targets")
        return 1
    if not write_marker(marker, n, run_id):
        return 1
    _emit(f"check ok targets={n} control=ok")
    return 0


def cmd_verify_marker(args: argparse.Namespace) -> int:
    run_id = os.environ.get("GITHUB_RUN_ID") or None
    if marker_ok(pathlib.Path(args.marker), run_id):
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
    p.add_argument("--parent", required=True, help="directory holding the store; must be traversable by the user")
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
