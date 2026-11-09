#!/usr/bin/env bash
set -euo pipefail

apply=0
keep_days=7
while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply) apply=1; shift ;;
        --keep-days)
            if [[ $# -lt 2 || ! $2 =~ ^[0-9]+$ ]]; then
                printf 'clean.sh: --keep-days needs a nonnegative integer\n' >&2
                exit 2
            fi
            keep_days=$2
            shift 2
            ;;
        *) printf 'Usage: tools/dev/clean.sh [--apply] [--keep-days N]\n' >&2; exit 2 ;;
    esac
done

# Use the caller's repository, so worktree membership never comes from another checkout.
XTRACE_DEV_TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" python3 -B - "$apply" "$keep_days" <<'PY'
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time


def root(name):
    value = os.environ.get(name, "")
    if not value or not os.path.isabs(value):
        raise ValueError(f"{name} must be an absolute existing directory")
    path = Path(value)
    if path.resolve() in (Path("/"), Path.home().resolve()):
        raise ValueError(f"{name} refuses / or HOME")
    if ".." in path.parts:
        raise ValueError(f"{name} must not contain '..'")
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"symlink or non-directory refused: {item}")
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError(f"unsafe owner or writable ancestor: {item}")
    if path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError(f"{name} must be owner-only (0700)")
    return path


sys.path.insert(0, os.environ["XTRACE_DEV_TOOLS"])
from devid import worktree_id as _worktree_id  # noqa: E402


def worktree_id(path):
    return _worktree_id(Path(path).name)


DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def open_directory(path):
    """Anchor each ancestor without following links, including during renames."""
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def inspect_tree(parent_fd, name, path, device, remove=False):
    """All mutations are relative to pinned root descriptors, never absolute paths."""
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"symlinked entry refused: {path}")
    if info.st_dev != device:
        raise ValueError(f"mounted entry refused: {path}")
    if stat.S_ISDIR(info.st_mode):
        descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError(f"entry changed during cleanup: {path}")
            for child in os.listdir(descriptor):
                inspect_tree(descriptor, child, path / child, device, remove)
        finally:
            os.close(descriptor)
        if remove:
            os.rmdir(name, dir_fd=parent_fd)
    elif remove:
        os.unlink(name, dir_fd=parent_fd)
    return info


descriptors = []
try:
    cache = root("XTRACE_DEV_CACHE")
    scratch = root("XTRACE_DEV_SCRATCH")
    # Nested roots could turn an allowed child into a cache root deletion.
    if cache == scratch or cache in scratch.parents or scratch in cache.parents:
        raise ValueError("cache and scratch roots must be separate, non-nested directories")
    cache_fd = open_directory(cache)
    descriptors.append(cache_fd)
    scratch_fd = open_directory(scratch)
    descriptors.append(scratch_fd)
    target = cache / "target"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError(f"symlink or non-directory refused: {target}")
    listing = subprocess.check_output(["git", "worktree", "list", "--porcelain", "-z"])
    active = {
        worktree_id(os.fsdecode(line[len(b"worktree "):]))
        for line in listing.split(b"\0") if line.startswith(b"worktree ")
    }
    cutoff = time.time() - int(sys.argv[2]) * 86400
    candidates = []
    parents = [(scratch, scratch_fd)]
    if target.exists():
        target_fd = os.open("target", DIRECTORY_FLAGS, dir_fd=cache_fd)
        descriptors.append(target_fd)
        parents.insert(0, (target, target_fd))
    # Preflight every entry before the first deletion, including hidden entries.
    for parent, parent_fd in parents:
        device = os.fstat(parent_fd).st_dev
        if device != os.fstat(cache_fd if parent == target else scratch_fd).st_dev:
            raise ValueError(f"mounted entry refused: {parent}")
        for name in sorted(os.listdir(parent_fd)):
            entry = parent / name
            info = inspect_tree(parent_fd, name, entry, device)
            if stat.S_ISDIR(info.st_mode) and (name not in active or info.st_mtime < cutoff):
                candidates.append((parent_fd, name, entry, device))

    def sizes():
        subprocess.run(["du", "-sh", str(cache), str(scratch)], check=True)

    print("Before:", flush=True)
    sizes()
    for parent_fd, name, entry, device in candidates:
        # Names come only from listdir(parent_fd); no user path enters the delete walk.
        if name in (".", "..") or "/" in name:
            raise ValueError(f"entry escaped cleanup root: {entry}")
        inspect_tree(parent_fd, name, entry, device, remove=sys.argv[1] == "1")
        if sys.argv[1] == "1":
            print(f"Deleted: {entry}", flush=True)
        else:
            print(f"Would delete: {entry}", flush=True)
    print("After:", flush=True)
    sizes()
    print("Suggestion: npm cache verify")
    if shutil.which("sccache"):
        print("Suggestion: sccache --show-stats")
except (OSError, ValueError, subprocess.CalledProcessError) as error:
    sys.exit(f"clean.sh: {error}")
finally:
    for descriptor in descriptors:
        os.close(descriptor)
PY
