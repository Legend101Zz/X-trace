#!/usr/bin/env python3
"""Retain only an identified pre-receipt failure's stderr as recipient-only ciphertext.

The recipient certificate is public, supplied by a proof-only wrapper. No key is
accepted, no plaintext fallback exists, and only a completed fixed ciphertext file
may be uploaded. The plaintext ZIP contains stderr plus fixed provenance, never
stdout, command lines, environment, recordings, application logs or storage.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lib"))
from private_diagnostic import LABELS, MAX_STDERR, root_admitted  # noqa: E402

PHASES = ("prerequisite", "package-verify", "candidate-install", "installed-verify", "checkout-upstream",
          "build-upstream", "baseline", "instrumented")
MAX_TOTAL_STDERR = 1 << 20
FINAL_NAME = "failure-stderr.cms"


def private_bytes(path, maximum):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("unsafe diagnostic entry")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("diagnostic entry is not an owner-only regular file")
        if info.st_size > maximum:
            raise OverflowError("diagnostic entry exceeds bound")
        value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise OverflowError("diagnostic entry exceeds bound")
        return value


def private_json(path):
    return json.loads(private_bytes(path, 64 << 10))


def private_write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def failed_driver(root):
    """The independent outer exit is usable even when root admission never succeeds."""
    try:
        driver = private_json(root.parent / "driver/status.json")
    except FileNotFoundError:
        return None
    code = driver.get("exitCode") if isinstance(driver, dict) else None
    if (not isinstance(driver, dict) or driver.get("schema") != "xtrace-jhipster-driver/1"
            or type(code) is not int or not -255 <= code <= 255 or code == 0):
        return None
    if not root_admitted(root):
        return "driver", code
    relevant = "baseline"
    try:
        phases = private_json(root / "phases.json")
        rows = phases.get("phases", []) if isinstance(phases, dict) else []
        baseline = [r for r in rows if isinstance(r, dict) and r.get("name") == "baseline"]
        if len(baseline) == 1 and baseline[0].get("status") == "passed" and baseline[0].get("exitCode") == 0:
            relevant = "instrumented"
    except (OSError, ValueError, OverflowError):
        pass
    return None if receipt_established(root, relevant) else ("driver", code)


def receipt_established(root, mode):
    try:
        doc = private_json(root / f"campaign/java/jhipster/{mode}-1/receipt.json")
        return (isinstance(doc, dict) and doc.get("project") == "jhipster"
                and doc.get("instrumented") is (mode == "instrumented") and doc.get("releaseAcceptance") is False)
    except (OSError, ValueError, OverflowError):
        return False


def failed_phase(root):
    """Select a concrete failed stage only while its relevant receipt is absent."""
    if not root_admitted(root):
        try:
            build = private_json(root.parent / "package-build/status.json")
        except FileNotFoundError:
            build = None
        code = build.get("exitCode") if isinstance(build, dict) else None
        if (isinstance(build, dict) and build.get("schema") == "xtrace-jhipster-build/1"
                and type(code) is int and -255 <= code <= 255 and code != 0):
            return "package-build", code
        return failed_driver(root)
    try:
        build = private_json(root / "build-status.json")
    except FileNotFoundError:
        build = None
    if isinstance(build, dict) and build.get("schema") == "xtrace-jhipster-build/1":
        code = build.get("exitCode")
        if type(code) is int and -255 <= code <= 255 and code != 0:
            if receipt_established(root, "baseline") or receipt_established(root, "instrumented"):
                return None
            return "package-build", code
    try:
        phases = private_json(root / "phases.json")
    except FileNotFoundError:
        return failed_driver(root)
    if not isinstance(phases, dict) or phases.get("schema") != "xtrace-jhipster-phases/1":
        raise ValueError("invalid failure manifest")
    rows = phases.get("phases")
    if not isinstance(rows, list):
        raise ValueError("invalid failure manifest")
    for name in PHASES:
        matches = [r for r in rows if isinstance(r, dict) and r.get("name") == name]
        if len(matches) != 1:
            raise ValueError("ambiguous failure phase")
        row = matches[0]
        code = row.get("exitCode")
        if row.get("status") == "failed" and type(code) is int and -255 <= code <= 255 and code != 0:
            if receipt_established(root, "instrumented" if name == "instrumented" else "baseline"):
                return None
            return name, code
    return failed_driver(root)


def stderr_bundle(root, phase, code):
    if phase == "driver":
        stderr = root.parent / "driver/stderr"
    elif phase == "package-build" and not root_admitted(root):
        stderr = root.parent / "package-build/stderr"
    else:
        stderr = root / f"console/{phase}.stderr"
    streams = {"phase.stderr": private_bytes(stderr, MAX_STDERR)}
    entries = [{"stream": "phase.stderr", "phase": phase, "exitCode": code, "kind": "phase-stderr"}]
    unavailable = 0
    if phase in ("baseline", "instrumented"):
        for label in LABELS:
            status = root / f"child-stderr/{phase}-{label}.json"
            try:
                doc = private_json(status)
            except FileNotFoundError:
                continue
            child_code = doc.get("exitCode") if isinstance(doc, dict) else None
            if (not isinstance(doc, dict) or doc.get("schema") != "xtrace-private-child-stderr/1"
                    or doc.get("phase") != phase or doc.get("child") != label
                    or not ((type(child_code) is int and -255 <= child_code <= 255 and child_code != 0)
                            or (child_code is None and doc.get("timedOut") is True))):
                raise ValueError("invalid child failure state")
            if doc.get("stderrState") == "oversized":
                raise OverflowError("child stderr exceeds bound")
            if doc.get("stderrState") != "captured":
                unavailable += 1
                continue
            name = f"child-{label}.stderr"
            streams[name] = private_bytes(root / f"child-stderr/{phase}-{label}.stderr", MAX_STDERR)
            entries.append({"stream": name, "child": label, "phase": phase, "exitCode": child_code,
                            "timedOut": doc.get("timedOut") is True, "kind": "captured-child-stderr"})
    if not any(streams.values()):
        raise FileNotFoundError("no observed stderr bytes")
    if sum(map(len, streams.values())) > MAX_TOTAL_STDERR:
        raise OverflowError("combined stderr exceeds bound")
    manifest = {"schema": "xtrace-jhipster-failure-stderr/1", "streams": entries,
                "unavailableCapturedChildStreams": unavailable,
                "deeperDiagnostics": "not-retained-by-existing-tools"}
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True) + "\n")
        for name, value in streams.items():
            archive.writestr(name, value)
    return data.getvalue(), len(streams)


def retain(root, output, recipient):
    status = {"schema": "xtrace-jhipster-diagnostic-retention/1", "status": "not-required", "phase": None,
              "exitCode": None, "retainedStderrStreams": 0, "deeperDiagnostics": "not-retained-by-existing-tools"}
    try:
        failure = failed_phase(root)
    except (OSError, ValueError, OverflowError, UnicodeError):
        status["status"] = "gap-invalid-failure-state"
        return status
    if failure is None:
        return status
    phase, code = failure
    status.update(phase=phase, exitCode=code)
    if (len(recipient.encode()) > 16 << 10 or not re.fullmatch(
            r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+\s+-----END CERTIFICATE-----\s*", recipient)):
        status["status"] = "gap-recipient-unavailable"
        return status
    try:
        plaintext, stream_count = stderr_bundle(root, phase, code)
    except OverflowError:
        status["status"] = "gap-stderr-oversized"
        return status
    except (OSError, ValueError, UnicodeError):
        status["status"] = "gap-stderr-unavailable"
        return status
    try:
        if not output.is_absolute() or any(p.is_symlink() for p in output.parents):
            raise ValueError("unsafe encrypted output parent")
        parent = output.parent.stat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077):
            raise ValueError("encrypted output parent must be private")
        # Driver admission failures can leave a refused root with unrelated state.
        # The workflow-owned sibling remains the only workspace for that case.
        work = (root if root_admitted(root) else root.parent) / "diagnostic-private"
        work.mkdir(mode=0o700)
        # Plaintext never enters the upload directory or a command argument.
        source, cert = work / "stderr.zip", work / "recipient.pem"
        private_write(source, plaintext)
        private_write(cert, recipient.encode())
        output.mkdir(mode=0o700)
        partial = output / "failure-stderr.partial"
        private_write(partial, b"")
        encrypted = subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER",
                                    "-in", str(source), "-out", str(partial), "-recip", str(cert)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if encrypted.returncode != 0:
            raise ValueError("recipient encryption failed")
        cipher = private_bytes(partial, MAX_TOTAL_STDERR + (64 << 10))
        if not cipher:
            raise ValueError("recipient encryption produced no ciphertext")
        partial.rename(output / FINAL_NAME)
        status.update(status="ciphertext-prepared", retainedStderrStreams=stream_count)
    except (OSError, ValueError, OverflowError, subprocess.SubprocessError):
        status["status"] = "gap-encryption-failed"
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--encrypted-out", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    status = retain(args.private_root, args.encrypted_out, os.environ.get("XTRACE_DIAGNOSTIC_CERT_PEM", ""))
    status_path = args.private_root.parent / "diagnostic-status.json"
    try:
        if any(p.is_symlink() for p in status_path.parents):
            raise ValueError("unsafe diagnostic status parent")
        private_write(status_path, (json.dumps(status, sort_keys=True) + "\n").encode())
    except (OSError, ValueError):
        pass
    ready = status["status"] == "ciphertext-prepared"
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write("ready=" + str(ready).lower() + "\n")
    print("JHipster pre-receipt diagnostic retention: " + status["status"])
    # The retention channel never changes the product/campaign verdict.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
