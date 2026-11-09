#!/usr/bin/env python3
"""Scan the Spring MVC catalog, then export and judge all developer formats, including the bundle.

  camp_exports.py --xtrace BIN --project-dir DIR --analyzer BIN --out DIR --file SUMMARY --project P

Exit code 9 (the CLI's NotImplemented) for a format is not-implemented; any other non-zero exit, or an exit 0 that wrote
nothing, is a failure. The output directory is later scanned for privacy canaries (location class `exports`).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_summary as cs  # noqa: E402

FORMATS = ("openapi", "postman", "curl")
ALL_FORMATS = (*FORMATS, "bundle")


def judge(results: dict[str, tuple[int, int]]) -> tuple[str, str]:
    """results: format -> (exit code, bytes written). Returns (status, note)."""
    if not results:
        return "fail", "no formats attempted"
    if all(code == 9 for code, _ in results.values()):
        return "not-implemented", "xtrace export exited 9 for every format (not implemented in this build)"
    bad = [f for f, (code, size) in results.items() if code != 0 or size == 0]
    if bad:
        return "fail", "; ".join(f"{f}: exit {results[f][0]}, {results[f][1]} bytes" for f in bad)
    return "pass", "all formats exported and wrote output: " + ",".join(results)


def judge_scan(code: int, doc: dict) -> tuple[str, str]:
    data = doc.get("data", doc)
    if code != 0:
        return "fail", f"Spring MVC scan exited {code}; exports not attempted"
    if not isinstance(data, dict) or data.get("persisted") is not True or not data.get("catalogRevisionId") or not \
            isinstance(data.get("result"), dict) or not data["result"].get("operations"):
        return "fail", "scan produced no persisted catalog with operations; exports not attempted"
    return "pass", "Spring MVC analyzer persisted a catalog with operations"


def judge_bundle(dest: pathlib.Path, catalog: dict, counts: dict[str, int]) -> tuple[str, str]:
    """Check the actual bundle inventory and counts against the scan, exports and payloads.

    YAML inspection is specific to the product's canonical two-space emitter, not a general YAML parser.
    Privacy is judged separately by the workflow's required recursive bundle-files canary scan.
    """
    try:
        if not dest.is_dir() or dest.is_symlink():
            raise ValueError("bundle is not a directory")
        entries = list(dest.rglob("*"))
        if any(p.is_symlink() for p in entries):
            raise ValueError("bundle contains a symlink")
        files = {p.relative_to(dest).as_posix(): p for p in entries if p.is_file()}
        required = {"manifest.json", "README.md", "openapi.yaml", "collection.postman.json", "curl/all.sh"}
        if not required <= files.keys() or any(p.stat().st_size == 0 for p in files.values()):
            raise ValueError("bundle has missing or empty files")
        manifest = json.loads(files["manifest.json"].read_text())
        expected = len(catalog["result"]["operations"])
        if manifest["operation_count"] != expected or manifest["revision_id"] != catalog["catalogRevisionId"]:
            raise ValueError("bundle count or revision differs from the scanned catalog")
        payloads = manifest["files"]
        paths = [f["path"] for f in payloads]
        if len(paths) != len(set(paths)) or set(paths) != files.keys() - {"manifest.json", "README.md"}:
            raise ValueError("bundle manifest inventory differs from the files written")
        if any(f["bytes"] != files[f["path"]].stat().st_size or
               not re.fullmatch(r"[0-9a-f]{64}", f["blake3"]) for f in payloads):
            raise ValueError("bundle manifest has incorrect sizes or missing file hashes")
        rows = manifest["formats"]
        declared = {row["format"]: row["operation_count"] for row in rows}
        if len(rows) != len(FORMATS) or set(declared) != set(FORMATS) or declared != counts:
            raise ValueError("bundle format counts differ from the individual exports")
        if any(type(n) is not int or not 0 < n <= expected for n in declared.values()) or \
                declared["postman"] != expected or declared["curl"] != expected:
            raise ValueError("bundle format counts differ from the scanned catalog")
        collection = json.loads(files["collection.postman.json"].read_text())
        items = collection["item"]
        if not isinstance(items, list) or any(not isinstance(i.get("request"), dict) for i in items) or \
                len(items) != declared["postman"]:
            raise ValueError("bundle Postman request count differs from its manifest")
        yaml = files["openapi.yaml"].read_text()
        if 'openapi: "3.1.0"' not in yaml.splitlines() or \
                len(re.findall(r"^      operationId: .+$", yaml, re.MULTILINE)) != declared["openapi"]:
            raise ValueError("bundle OpenAPI operation count differs from its manifest")
        recipes = set(files) - required
        if len(recipes) != declared["curl"] or any(not p.startswith("curl/") or not p.endswith(".sh") or
                not files[p].read_text().startswith("#!/bin/sh\n") for p in recipes):
            raise ValueError("bundle cURL recipe count or contents differ from its manifest")
        if not isinstance(manifest["omissions"], list):
            raise ValueError("bundle does not declare omissions")
        return "pass", f"bundle: {len(files)} nonempty files; catalog revision and all format/payload counts agree ({expected} operations)"
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # Never echo catalog values or file contents into the public summary.
        return "fail", "bundle contents, inventory, catalog revision or operation counts could not be verified"


def run_exports(xtrace: str, project_dir: str, analyzer: str, out: pathlib.Path) -> list[tuple[str, str, str]]:
    """Scan before exporting. Never count pre-existing output as evidence from this invocation."""
    out.mkdir(parents=True, exist_ok=True)
    try:
        scan = subprocess.run([xtrace, "scan", "--project-dir", project_dir,
                               "--source", str(pathlib.Path(project_dir) / "src/main/java"),
                               "--framework", "spring-mvc", "--analyzer", analyzer, "--json"],
                              capture_output=True, text=True, timeout=320)
        try:
            doc = json.loads(scan.stdout)
        except ValueError:
            doc = {}
        status, note = judge_scan(scan.returncode, doc if isinstance(doc, dict) else {})
    except (OSError, subprocess.SubprocessError):
        status, note = "fail", "Spring MVC scan could not complete; exports not attempted"
    steps = [("export-catalog-scan", status, note)]
    if status != "pass":
        return steps + [(f"export-{fmt}", "fail", note) for fmt in ALL_FORMATS] + [("export-formats", "fail", note)]
    results = {}
    counts = {}
    bundle_ok = False
    for fmt in ALL_FORMATS:
        dest = out / f"export-{fmt}"
        if dest.exists():
            code, size = 127, 0
        else:
            try:
                r = subprocess.run([xtrace, "export", "--project-dir", project_dir, "--format", fmt, "--json", "--output", str(dest)],
                                   capture_output=True, text=True, timeout=120)
                code = r.returncode
                if fmt in FORMATS and code == 0:
                    try:
                        report = json.loads(r.stdout)
                        report = report.get("data", report)
                        if type(report.get("operation_count")) is int and report.get("written") is True:
                            counts[fmt] = report["operation_count"]
                    except (ValueError, AttributeError):
                        pass  # the bundle comparison fails if an individual count was not observed
            except (OSError, subprocess.SubprocessError):
                code = 127
            size = dest.stat().st_size if dest.is_file() else sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
        results[fmt] = (code, size)
        st, why = judge({fmt: (code, size)})
        if fmt == "bundle" and st == "pass":
            st, why = judge_bundle(dest, doc.get("data", doc), counts)
        if fmt == "bundle":
            bundle_ok = st == "pass"
        steps.append((f"export-{fmt}", st, why))
    status, note = judge(results)
    if status == "pass" and not bundle_ok:
        status, note = "fail", "bundle content verification failed"
    return steps + [("export-formats", status, note)]


def main() -> int:
    ap = argparse.ArgumentParser()
    for n in ("xtrace", "project-dir", "analyzer", "out", "file", "project"):
        ap.add_argument(f"--{n}", required=True)
    a = ap.parse_args()
    for name, status, note in run_exports(a.xtrace, a.project_dir, a.analyzer, pathlib.Path(a.out)):
        cs.record(pathlib.Path(a.file), a.project, name, status, note)
        print(f"campaign step {name}: {status} ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
