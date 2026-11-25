"""Retain only bounded package failure evidence from the exact baseline run."""
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

from tools.release.private_roots import AdmissionError, admit_directory, atomic_write_private, read_private_json


LIMIT = 128 * 1024
STREAMS = ("package.stdout", "package.stderr", "driver-exception.stderr")
ROOT = Path(os.environ["PROOF_ROOT"])


def read_tail(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return b"", None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("private stream rejected")
        stream.seek(max(0, info.st_size - LIMIT))
        return stream.read(LIMIT), info.st_size > LIMIT


def command_failure(data):
    for line in reversed(data.splitlines()):
        match = re.fullmatch(
            rb"subprocess\.CalledProcessError: Command '(\[.{1,4096}\])' returned non-zero exit status ([1-9][0-9]{0,2})\.", line)
        if not match:
            continue
        try:
            args = ast.literal_eval(match[1].decode("ascii"))
        except (SyntaxError, ValueError, RecursionError):
            continue
        code = int(match[2])
        if isinstance(args, list) and all(isinstance(arg, str) for arg in args) and 1 <= code <= 255:
            return args, code
    return [], None


def command_label(args):
    if args == ["cargo", "build", "--release", "--locked", "-p", "xtrace-cli"]:
        return "cargo-locked-release"
    if args[:2] == ["cargo", "metadata"]:
        return "cargo-locked-metadata"
    if args == ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]:
        # The same command is used in two component directories.
        return "npm-ci"
    if args in (["npm", "run", "check:embedded"], ["npm", "run", "build:protocol"], ["npm", "run", "build:core"]):
        return {"check:embedded": "web-embedded-parity", "build:protocol": "node-protocol",
                "build:core": "node-core"}[args[2]]
    if args[:5] == ["./gradlew", "--no-daemon", "--dependency-verification", "strict", "-I"] and args[6:] == [
            "clean", "javaPackDist"]:
        return "java-pack"
    return None


def encrypt(streams):
    cert = os.environ["RECIPIENT_CERT"].strip()
    match = re.fullmatch(r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)\n-----END CERTIFICATE-----", cert)
    if not match:
        raise ValueError("certificate shape rejected")
    der = base64.b64decode(match[1].replace("\n", ""), validate=True)
    if hashlib.sha256(der).hexdigest() != os.environ["RECIPIENT_DER_SHA256"]:
        raise ValueError("certificate digest mismatch")
    cert_path = ROOT / "private" / "package-recipient.pem"
    atomic_write_private(cert_path, (cert + "\n").encode("ascii"))

    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, (data, _) in streams.items():
            if not data:
                continue
            member = tarfile.TarInfo(name + ".tail")
            member.size = len(data)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(data))
    output = ROOT / "encrypted" / "package-diagnostics.cms"
    output.parent.mkdir(mode=0o700)
    with (ROOT / "logs" / "package-encryption.stderr").open("xb") as err:
        subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER",
                        "-out", str(output), str(cert_path)], input=payload.getvalue(), stdout=subprocess.DEVNULL,
                       stderr=err, check=True, timeout=60)
    info = output.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_nlink != 1 or not 0 < info.st_size <= 512 * 1024):
        raise ValueError("ciphertext rejected")
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write("ready=true\n")


def main():
    for directory in (ROOT, ROOT / "logs", ROOT / "private", ROOT / "safe"):
        admit_directory(directory)
    baseline = read_private_json(ROOT / "safe" / "report.json", maximum_bytes=65536, maximum_nodes=1024,
                                 maximum_commas=1024)
    if (baseline.get("kind") != "installed-spring-replay-118-baseline"
            or baseline.get("sourceSha") != os.environ["PRODUCT"]
            or baseline.get("sourceTree") != os.environ["PRODUCT_TREE"]
            or baseline.get("uiManifestSha256") != os.environ["EXPECTED_UI_MANIFEST_SHA256"]
            or baseline.get("releaseAcceptance") is not False):
        raise ValueError("proof identity rejected")
    if baseline.get("status") != "failed" or baseline.get("stage") != "package":
        return
    receipt = {"schemaVersion": 1, "kind": "installed-replay-package-diagnostic", "releaseAcceptance": False,
               "sourceSha": os.environ["PRODUCT"], "sourceTree": os.environ["PRODUCT_TREE"],
               "priorRedRun": 45692502625, "archiveVerified": False, "packageProcessExit": None,
               "observedChildFailure": None, "childExit": None, "retention": "unavailable", "streams": {}}
    out = ROOT / "safe" / "package-diagnostic.json"
    try:
        streams = {name: read_tail(ROOT / "logs" / name) for name in STREAMS}
        receipt["streams"] = {name: ({"tailBytes": len(data), "truncated": truncated}
                                     if truncated is not None else None)
                              for name, (data, truncated) in streams.items()}
        package_args, package_exit = command_failure(streams["driver-exception.stderr"][0])
        if package_args[:3] == ["python3", "-B", "packaging/build.py"]:
            receipt["packageProcessExit"] = package_exit
            child_args, child_exit = command_failure(streams["package.stderr"][0])
            label = command_label(child_args)
            if label:
                receipt.update(observedChildFailure=label, childExit=child_exit)
        if any(data for data, _ in streams.values()):
            encrypt(streams)
            receipt["retention"] = "encrypted"
    finally:
        atomic_write_private(out, (json.dumps(receipt, sort_keys=True) + "\n").encode())


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except (AdmissionError, OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Package diagnostic retention unavailable") from None
