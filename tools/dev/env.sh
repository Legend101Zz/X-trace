#!/usr/bin/env bash
# Source this file (bash or zsh): `source tools/dev/env.sh [ID]`. It must not change the caller's
# shell options, so it does not use `set -e`; every step checks its own result instead.

# The directory of this file, found from bash or zsh while it is being sourced.
if [ -n "${BASH_SOURCE:-}" ]; then
    _xtrace_dev_tools=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
elif [ -n "${ZSH_VERSION:-}" ]; then
    eval '_xtrace_dev_tools=$(cd "$(dirname "${(%):-%x}")" && pwd)'
else
    _xtrace_dev_tools=$(pwd)/tools/dev
fi

_xtrace_dev_env() {
    local id name root
    if [[ $# -gt 1 ]]; then
        printf 'Usage: source tools/dev/env.sh [ID]\n' >&2
        return 2
    fi
    root=$(git rev-parse --show-toplevel) || return
    id=$(python3 -B "$_xtrace_dev_tools/devid.py" "${1:-${root##*/}}") || return
    python3 -B - "$id" <<'PY' || return
import os
from pathlib import Path
import stat
import subprocess
import sys


def ownership_enabled(path):
    # Darwin statvfs reports only readonly/nosuid; statfs retains noowners.
    if sys.platform != "darwin":
        return True
    import ctypes

    class StatFS(ctypes.Structure):
        _fields_ = [
            ("bsize", ctypes.c_uint32), ("iosize", ctypes.c_int32),
            ("counts", ctypes.c_uint64 * 5), ("fsid", ctypes.c_int32 * 2),
            ("owner", ctypes.c_uint32), ("type", ctypes.c_uint32),
            ("flags", ctypes.c_uint32), ("subtype", ctypes.c_uint32),
            ("fstypename", ctypes.c_char * 16), ("mntonname", ctypes.c_char * 1024),
            ("mntfromname", ctypes.c_char * 1024), ("reserved", ctypes.c_uint32 * 8),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    probe = getattr(libc, "statfs$INODE64", libc.statfs)
    probe.argtypes = [ctypes.c_char_p, ctypes.POINTER(StatFS)]
    probe.restype = ctypes.c_int
    facts = StatFS()
    if probe(os.fsencode(path), ctypes.byref(facts)) != 0:
        raise OSError(ctypes.get_errno(), "cannot inspect filesystem ownership")
    return not facts.flags & 0x200000  # MNT_IGNORE_OWNERSHIP


def private_directory(path):
    """Reject links and unsafe ancestors before tools can write private state."""
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            raise ValueError(f"unsafe directory or owner: {item}")
        if info.st_mode & 0o022:
            raise ValueError(f"group/other-writable ancestor: {item}")
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"directory must be owner-only (0700): {path}")
    if not ownership_enabled(path):
        raise ValueError(f"ownership must be enabled (noowners refused): {path}")


try:
    roots = {}
    for name in ("XTRACE_DEV_CACHE", "XTRACE_DEV_SCRATCH"):
        value = os.environ.get(name, "")
        if not value or not os.path.isabs(value):
            raise ValueError(f"{name} must be set to an absolute existing owner-only directory")
        if ".." in Path(value).parts:
            raise ValueError(f"{name} must not contain '..'")
        if name == "XTRACE_DEV_SCRATCH" and len(os.fsencode(value)) > 24:
            raise ValueError(f"{name} is too long (maximum 24 bytes)")
        roots[name] = Path(value)
        private_directory(roots[name])
    parent = roots["XTRACE_DEV_SCRATCH"] / sys.argv[1]
    for path in (parent, parent / "tmp", parent / "priv", parent / "rel"):
        if path.exists() or path.is_symlink():
            private_directory(path)
        subprocess.run(["mkdir", "-m", "700", "-p", str(path)], check=True)
        private_directory(path)
except (OSError, ValueError, subprocess.CalledProcessError) as error:
    sys.exit(f"env.sh: {error}")
PY
    export CARGO_HOME="$XTRACE_DEV_CACHE/cargo-home"
    export CARGO_TARGET_DIR="$XTRACE_DEV_CACHE/target/$id"
    export GRADLE_USER_HOME="$XTRACE_DEV_CACHE/gradle"
    export NPM_CONFIG_CACHE="$XTRACE_DEV_CACHE/npm"
    export PLAYWRIGHT_BROWSERS_PATH="$XTRACE_DEV_CACHE/pw"
    export SCCACHE_DIR="$XTRACE_DEV_CACHE/sccache"
    export SCCACHE_CACHE_SIZE=40G
    export TMPDIR="$XTRACE_DEV_SCRATCH/$id/tmp"
    export XTRACE_TEST_PRIVATE_SCRATCH="$XTRACE_DEV_SCRATCH/$id/priv"
    export XTRACE_TEST_SCRATCH_ROOT="$XTRACE_DEV_SCRATCH/$id/rel"
    export XTRACE_DEV_ID="$id"
    if command -v sccache >/dev/null 2>&1; then
        export RUSTC_WRAPPER=sccache
    elif [[ ${RUSTC_WRAPPER:-} == sccache ]]; then
        unset RUSTC_WRAPPER
    fi
    if [[ ${XTRACE_DEV_VERBOSE:-0} == 1 ]]; then
        for name in CARGO_HOME CARGO_TARGET_DIR GRADLE_USER_HOME NPM_CONFIG_CACHE \
            PLAYWRIGHT_BROWSERS_PATH SCCACHE_DIR SCCACHE_CACHE_SIZE TMPDIR \
            XTRACE_TEST_PRIVATE_SCRATCH XTRACE_TEST_SCRATCH_ROOT XTRACE_DEV_ID; do
            printf '%s=%s\n' "$name" "$(printenv "$name")"
        done
        if command -v sccache >/dev/null 2>&1; then
            printf 'RUSTC_WRAPPER=%s\n' "$RUSTC_WRAPPER"
        fi
    fi
}

_xtrace_dev_env "$@"
