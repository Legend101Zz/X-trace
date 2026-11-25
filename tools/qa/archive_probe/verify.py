"""Independently check the actual public artifact of a synthetic publication probe."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import quote_from_bytes
from zipfile import ZipFile

SOURCE = "522b2a95607ba7cefb8cefbafe167e377274e7ee"
PACKAGE = b"synthetic package identity fixture\n"
ANALYZER = b"synthetic installed analyzer inventory fixture\n"
SUCCESS = {"summary.json", "publication.json", "package.sha256", "analyzer.sha256",
           "baseline-receipt.json", "instrumented-receipt.json", "privacy-canary-report.json",
           "campaign-receipt.NON-RELEASE.json"}
FALLBACK = {"summary.json", "publication.json"}
CASES = {"success": SUCCESS, "recorded-failure": SUCCESS, "missing-canaries": FALLBACK,
         "canary-hit": FALLBACK, "missing-evidence": FALLBACK}
ALLOWED = {f"{case}/{file}" for case, files in CASES.items() for file in files}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def markers(run_id):
    token = digest(f"archive-probe-v1/{run_id}".encode())[:32]
    return f"archive-probe-{token}", f"archive-hit-{token}"


def check(condition):
    if not condition:
        raise ValueError("public archive verification failed")


def entries(path):
    if path.is_dir():
        paths = list(path.rglob("*"))
        check(all(not item.is_symlink() and (item.is_file() or item.is_dir()) for item in paths))
        files = {str(item.relative_to(path)): item for item in paths if item.is_file()}
        check(set(files) == ALLOWED and all(item.stat().st_size < 32768 for item in files.values()))
        return {name: item.read_bytes() for name, item in files.items()}
    with ZipFile(path) as archive:
        members = archive.infolist()
        names = [m.filename for m in members if not m.is_dir()]
        check(len(names) == len(set(names)) and set(names) == ALLOWED)
        check(all(m.filename in ALLOWED or (m.is_dir() and m.filename.rstrip("/") in CASES) for m in members))
        check(all(m.file_size < 32768 and (m.external_attr >> 16) & 0o170000 != 0o120000 for m in members))
        return {name: archive.read(name) for name in names}


def references(value):
    if isinstance(value, dict):
        if "path" in value or "sha256" in value:
            check(set(value) == {"path", "sha256"})
            yield value
        else:
            for child in value.values():
                yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


def verify(files, run_id):
    check(set(files) == ALLOWED)
    for mark in markers(run_id):
        raw = mark.encode()
        forbidden = [raw, raw.hex().encode(), quote_from_bytes(raw, safe="").encode(),
                     base64.b64encode(raw), base64.urlsafe_b64encode(raw)]
        check(not any(needle in content for content in files.values() for needle in forbidden))
    counts = {}
    for case in CASES:
        read = lambda name: json.loads(files[f"{case}/{name}"])
        publication = read("publication.json")
        summary = read("summary.json")
        if case not in {"success", "recorded-failure"}:
            check(set(summary) == {"stepCounts"} and sum(summary["stepCounts"].values()) == 1)
            check(publication == {
                "receiptGeneration": "failed" if case == "missing-evidence" else "succeeded",
                "finalPrivacyScan": {"canary-hit": "failed", "missing-canaries": "missing-canaries",
                                     "missing-evidence": "unreached"}[case],
            })
            continue
        receipt = read("campaign-receipt.NON-RELEASE.json")
        check(publication == {"receiptGeneration": "succeeded", "finalPrivacyScan": "passed"})
        check(receipt["candidateSha"] == receipt["build"]["sourceSha"] == SOURCE)
        check(receipt["nonRelease"] is True and receipt["signing"] == "unsigned" and receipt["signatures"] == [])
        check(receipt["build"]["archiveSha256"] == digest(PACKAGE))
        check(receipt["build"]["installedAnalyzerInventorySha256"] == digest(ANALYZER))
        for name, raw in (("package.sha256", PACKAGE), ("analyzer.sha256", ANALYZER)):
            check(files[f"{case}/{name}"] == (digest(raw) + "\n").encode())
        check(set(summary) == {"schemaVersion", "project", "steps"})
        passed = case == "success"
        check(summary["steps"] == [{"step": "synthetic-workload", "status": "pass" if passed else "fail"}])
        check(receipt["result"] == ("passed" if passed else "failed"))
        check(receipt["checks"] == [{"name": "synthetic-workload", "note": "", "reached": True,
                                     "status": "passed" if passed else "fail"}])
        check(receipt["failedChecks"] == ([] if passed else ["synthetic-workload"]))
        required = SUCCESS - {"campaign-receipt.NON-RELEASE.json", "publication.json"}
        seen = []
        for ref in references(receipt):
            name = ref["path"]
            check(name in required)
            check(re.fullmatch("[0-9a-f]{64}", ref["sha256"]) is not None)
            check(ref["sha256"] == digest(files[f"{case}/{name}"]))
            seen.append(name)
        check(set(seen) == required and len(seen) == 9)
        counts[case] = len(seen)
    return counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("run_id")
    args = parser.parse_args()
    try:
        files = entries(args.path)
        seen = verify(files, args.run_id)
        for name in SUCCESS - {"campaign-receipt.NON-RELEASE.json", "publication.json"}:
            tampered = dict(files)
            key = f"success/{name}"
            tampered[key] += b"\n"
            try:
                verify(tampered, args.run_id)
            except ValueError:
                continue
            raise ValueError("modified reference was accepted")
    except (ValueError, KeyError, TypeError) as error:
        raise SystemExit("public archive failed its independent check") from None
    print(json.dumps({"sourceSha": SOURCE, "cases": len(CASES), "files": len(files),
                      "referencesChecked": sum(seen.values()), "tamperedReferencesRejected": 6,
                      "archiveSha256": digest(args.path.read_bytes()) if args.path.is_file() else None,
                      "releaseEvidence": False}, sort_keys=True))


if __name__ == "__main__":
    main()
