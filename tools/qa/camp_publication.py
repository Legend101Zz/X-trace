"""Stage only bounded campaign evidence and scan its final bytes before publication."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import tempfile

from tools.qa import camp_receipt, camp_summary, canary

IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{0,79}")
ARCHIVE_DIGEST = re.compile(r"[0-9a-f]{64}")
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
RECEIPT = "campaign-receipt.NON-RELEASE.json"


def read(path: pathlib.Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("expected an evidence object")
    return doc


def write(path: pathlib.Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def public_summary(summary: dict, project: str) -> dict:
    if not IDENTIFIER.fullmatch(project) or summary.get("project") != project:
        raise ValueError("invalid summary project")
    rows = summary["steps"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("missing campaign steps")
    names = set()
    steps = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid campaign step")
        name, status = row.get("step"), row.get("status")
        if (not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in names
                or status not in camp_summary.STATUSES):
            raise ValueError("invalid or duplicate campaign step")
        names.add(name)
        steps.append({"step": name, "status": status})
    return {"schemaVersion": 1, "project": project, "steps": steps}


def count_privacy(report: dict) -> dict:
    return {
        "clean": report.get("clean") is True,
        "scannedFiles": sum(max(0, s["files"]) for s in report["scanned"] if type(s["files"]) is int),
        "hitClasses": len(report["hits"]),
        "uncoveredClasses": len(report["uncovered"]),
    }


def public_scenarios(source: dict, allowed: set[str]) -> dict:
    """Produce bounded status facts from a raw receipt without any transcript or notes."""
    scenarios = []
    for row in source.get("scenarios", []):
        scenario = row.get("id")
        if not isinstance(scenario, str) or scenario not in allowed:
            continue
        fingerprint = row.get("semanticEffectFingerprint")
        verdict = row.get("recordingVerdict")
        scenarios.append({
            "id": scenario,
            "semanticEffectFingerprint": (
                fingerprint if isinstance(fingerprint, str) and ARCHIVE_DIGEST.fullmatch(fingerprint) else None
            ),
            "scenarioChecksPassed": row.get("scenarioChecksPassed", row.get("passed")) is True,
            "recordingVerdict": {"passed": isinstance(verdict, dict) and verdict.get("passed") is True},
        })
    return {"scenarios": scenarios}


def recorded_refs(value):
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            yield value
        else:
            for child in value.values():
                yield from recorded_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from recorded_refs(child)


def verify_references(root: pathlib.Path, receipt: dict) -> None:
    for entry in recorded_refs(receipt):
        rel = entry["path"]
        if not isinstance(rel, str) or rel not in {
            "summary.json", "baseline-receipt.json", "instrumented-receipt.json",
            "privacy-canary-report.json", "package.sha256",
        }:
            raise ValueError("unexpected evidence reference")
        if camp_receipt.ref(root, rel) != entry:
            raise ValueError("evidence bytes do not match the receipt")


def publish(args: argparse.Namespace) -> bool:
    private = pathlib.Path(args.private)
    public = pathlib.Path(args.public)
    if public.exists() or public.is_symlink():
        raise ValueError("publication directory already exists")
    if not SOURCE_SHA.fullmatch(args.candidate) or not args.run_id.isdecimal():
        raise ValueError("invalid source or run identity")
    summary_path = private / "summary.json"
    summary = {}
    generation = "failed"
    scan_outcome = "unreached"
    with tempfile.TemporaryDirectory(prefix="campaign-evidence-", dir=public.parent) as temp:
        stage = pathlib.Path(temp) / "output"
        stage.mkdir(mode=0o700)
        try:
            summary = public_summary(read(summary_path), args.project)
            write(stage / "summary.json", summary)
            campaign = read(pathlib.Path(args.campaign))
            if campaign.get("project") != args.project:
                raise ValueError("wrong campaign definition")
            # A tracked, bounded scenario identifier is the only public scenario label.
            scenarios = campaign.get("scenarios", [])
            if any(not IDENTIFIER.fullmatch(s["id"]) for s in scenarios):
                raise ValueError("invalid campaign scenario identity")
            sha = campaign.get("upstream", {}).get("sha")
            definition = {
                "upstream": {"sha": sha if isinstance(sha, str) and SOURCE_SHA.fullmatch(sha) else None},
                "scenarios": scenarios,
            }
            scenario_ids = {row["id"] for row in scenarios}
            baseline = instrumented = None
            if args.baseline and pathlib.Path(args.baseline).is_file():
                baseline = public_scenarios(read(pathlib.Path(args.baseline)), scenario_ids)
                write(stage / "baseline-receipt.json", baseline)
            if args.instrumented and pathlib.Path(args.instrumented).is_file():
                instrumented = public_scenarios(read(pathlib.Path(args.instrumented)), scenario_ids)
                write(stage / "instrumented-receipt.json", instrumented)
            first_scan = private / "privacy-canary-report.json"
            if first_scan.is_file():
                write(stage / "privacy-canary-report.json", count_privacy(read(first_scan)))
            package = private / "package.sha256"
            archive_digest = None
            if package.is_file():
                archive_digest = package.read_text(encoding="ascii").strip()
                if not ARCHIVE_DIGEST.fullmatch(archive_digest):
                    raise ValueError("invalid archive digest")
                (stage / "package.sha256").write_text(archive_digest + "\n", encoding="ascii")

            if args.project == "petclinic" and (
                baseline is None or instrumented is None or not first_scan.is_file() or archive_digest is None
            ):
                raise ValueError("required campaign evidence is missing")

            receipt = camp_receipt.build_receipt(
                stage, args.project, "CAMPAIGN-" + args.project.upper(), args.candidate, definition,
                summary, instrumented, baseline, archive_digest, args.run_id,
            )
            verify_references(stage, receipt)
            write(stage / RECEIPT, receipt)
            # This document is eligible for publication only if this exact tree passes its scan.
            write(stage / "publication.json", {"receiptGeneration": "succeeded", "finalPrivacyScan": "passed"})
            generation = "succeeded"
            if pathlib.Path(args.canaries).is_file():
                report = canary.run_scan(read(pathlib.Path(args.canaries)), {"upload-tree": [stage]}, {"upload-tree": 1})
                write(private / "privacy-canary-report-final.json", report)
                scan_outcome = "passed" if report["clean"] else "failed"
            else:
                scan_outcome = "missing-canaries"
        except (OSError, ValueError, TypeError, AttributeError, KeyError):
            # The raw paths and parse error may carry private values.
            print("campaign evidence staging or scanning failed")
            if generation == "succeeded":
                scan_outcome = "failed"

        if scan_outcome == "passed":
            stage.rename(public)
        else:
            public.mkdir(mode=0o700)
            # A fixed fallback contains no raw data, scenarios, checksums or notes.
            if summary:
                write(public / "summary.json", {
                    "stepCounts": {
                        status: sum(row["status"] == status for row in summary["steps"])
                        for status in camp_summary.STATUSES
                    },
                })
            write(public / "publication.json", {"receiptGeneration": generation, "finalPrivacyScan": scan_outcome})

    camp_summary.record(summary_path, args.project, "campaign-receipt-artifact",
                        "reported" if generation == "succeeded" else "fail")
    camp_summary.record(summary_path, args.project, "privacy-canary-final-scan",
                        "pass" if scan_outcome == "passed" else "fail")
    print("campaign evidence: " + ("published" if scan_outcome == "passed" else "fixed failure summary only"))
    return scan_outcome == "passed"


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("private", "public", "project", "candidate", "campaign", "run-id", "canaries"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--baseline", default="")
    parser.add_argument("--instrumented", default="")
    return 0 if publish(parser.parse_args()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
