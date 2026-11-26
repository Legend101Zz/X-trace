"""Bind seed inputs to the exact pinned create tarball, without running the create tool."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_pin():
    campaign = json.loads((HERE.parent / "campaign.json").read_text())
    return campaign["starter"]["package"]["tarballSha256"]


def pinned_bytes(archive):
    # Read the same descriptor whose type was checked, and parse or retain only those bytes.
    try:
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("Vendure seed archive is unavailable") from exc
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Vendure seed archive must be a regular file")
        data = stream.read()
    if digest(data) != archive_pin():
        raise ValueError("Vendure seed archive does not match its pin")
    return data


def retain(archive, destination):
    data = pinned_bytes(archive)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def archive_inputs(archive):
    assets = {}
    with tarfile.open(fileobj=io.BytesIO(pinned_bytes(archive)), mode="r:gz") as package:
        for member in package.getmembers():
            if not member.name.startswith("package/assets/"):
                continue
            name = member.name.removeprefix("package/assets/").rstrip("/")
            if not name:
                continue
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts or str(relative) != name:
                raise ValueError("invalid Vendure asset path")
            if member.isdir():
                continue
            if not member.isfile() or name in assets:
                raise ValueError("linked or duplicate Vendure seed input")
            assets[name] = package.extractfile(member).read()
    if not {"initial-data.json", "products.csv"} <= assets.keys() or not any(name.startswith("images/") for name in assets):
        raise ValueError("Vendure seed inputs are missing")
    return assets


def prepare(archive, destination):
    assets = archive_inputs(archive)
    destination.mkdir(mode=0o700, exist_ok=False)
    for name, data in assets.items():
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o600)
    verify(archive, destination)


def verify(archive, destination):
    assets = archive_inputs(archive)
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("Vendure seed input directory is unavailable")
    found = {}
    for target in destination.rglob("*"):
        info = target.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Vendure seed inputs contain a link or special file")
        found[target.relative_to(destination).as_posix()] = digest(target.read_bytes())
    if found != {name: digest(data) for name, data in assets.items()}:
        raise ValueError("Vendure extracted seed inputs changed from the pinned archive")
    return {"archiveSha256": archive_pin(), "files": len(found),
            "treeSha256": digest(json.dumps(found, sort_keys=True, separators=(",", ":")).encode())}


if __name__ == "__main__":
    actions = {"retain": retain, "prepare": prepare, "verify": verify}
    if len(sys.argv) != 4 or sys.argv[1] not in actions:
        raise SystemExit("usage: seed_assets.py retain|prepare|verify ARCHIVE DESTINATION")
    action, archive, destination = sys.argv[1:]
    result = actions[action](Path(archive), Path(destination))
    if action == "verify":
        print(json.dumps(result, sort_keys=True))
