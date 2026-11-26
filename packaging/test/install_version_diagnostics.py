"""Hosted installer regression: real execute refusal and bounded stderr on the single version check."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_package import resolve_root


VERSION_PROBE = """#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = "--version" ] || exit 120
printf 'version\\n' >> "$PROBE_CALLS" || exit 121
cat "$PROBE_STDERR" >&2 || exit 122
exit "$PROBE_STATUS"
"""


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def run_installer(package, prefix, status, category, env):
    result = subprocess.run(["sh", str(package / "install.sh"), "--prefix", str(prefix), "--data-home", str(prefix.parent / "data")],
                            cwd=package, env={**os.environ, **env, "LC_ALL": "C"},
                            capture_output=True, timeout=120, check=False)
    expected = (f"install.sh: version check: status={status} category={category}\n"
                "install.sh: error: installed binary failed to run\n").encode()
    require(result.returncode == 1 and result.stderr == expected, "installer exit or closed version diagnostic")


def qualify(archive, root):
    require(archive.is_file() and not archive.is_symlink(), "expected development package archive")
    package = resolve_root(archive, root)
    require(package.parent == root and package.name == "xtrace-0.0.1-linux-x86_64", "expected package root")
    real = package / "bin/xtrace"
    require(real.stat().st_mode & 0o100, "packaged CLI was executable before the fixture change")
    real.chmod(stat.S_IMODE(real.stat().st_mode) & ~0o111)
    # Genuine release bytes, checksums, installation and shell-generated refusal. Only the execute bits change.
    run_installer(package, root / "genuine prefix", 126, "exec_permission_reported", {})

    # Small disposable payloads use the exact same archived installer and single-shot path.
    # Their controlled stderr distinguishes what the bounded reader can and cannot classify.
    fixture = root / "classifier fixture"
    (fixture / "bin").mkdir(parents=True)
    metadata = fixture / "share/xtrace"
    metadata.mkdir(parents=True)
    for name in ("install.sh", "uninstall.sh"):
        shutil.copyfile(package / name, fixture / name)
    cli = fixture / "bin/xtrace"
    cli.write_text(VERSION_PROBE)
    cli.chmod(0o700)
    (metadata / "VERSION").write_text("0.0.1\n")
    (metadata / "PACKAGE-MANIFEST.json").write_text('{"packTrust": "unsigned"}\n')
    payload = sorted(p for p in fixture.rglob("*") if p.is_file())
    (metadata / "payload.sha256").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(fixture)}\n" for p in payload))
    cases = [
        ("format", 126, "cannot execute binary file: Exec format error", "exec_format_reported"),
        ("operation", 126, "Operation not permitted", "exec_operation_refused_reported"),
        ("missing", 127, "cannot execute: required file not found", "exec_file_missing_reported"),
        ("busy", 126, "Text file busy", "exec_file_busy_reported"),
        ("wrong-path", 126, "Permission denied", "other_diagnostic"),
        ("wrong-status", 35, "Permission denied", "other_diagnostic"),
        ("last-byte-inside", 126, "Permission denied", "exec_permission_reported"),
        ("last-byte-outside", 126, "Permission denied", "other_diagnostic"),
        ("after-prefix", 126, "Permission denied", "other_diagnostic"),
    ]
    for name, status, message, category in cases:
        prefix = root / ("target " + name)
        marker = f"fixture: {prefix}/bin/xtrace: {message}".encode()
        if name == "wrong-path":
            marker = b"fixture: /another-command: Permission denied"
        if name.startswith("last-byte-"):
            cut = 4096 if name == "last-byte-inside" else 4097
            require(len(marker) + 1 < cut, "fixture private path length")
            marker = b"." * (cut - len(marker) - 1) + b"\n" + marker
        elif name == "after-prefix":
            marker = b"." * 4096 + b"\n" + marker
        errors, calls = root / (name + ".stderr"), root / (name + ".calls")
        errors.write_bytes(marker + b"\n" + (b"x" * (1 << 20) if name.startswith("last-byte-") else b""))
        run_installer(fixture, prefix, status, category, {"PROBE_CALLS": str(calls), "PROBE_STDERR": str(errors),
                                                           "PROBE_STATUS": str(status)})
        require(calls.read_bytes() == b"version\n", "one unchanged invocation")
    print("Verified genuine installer refusal and nine bounded single-invocation cases")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("private_scratch", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(dir=args.private_scratch) as scratch:
        qualify(args.archive, Path(scratch))
