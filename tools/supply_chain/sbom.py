#!/usr/bin/env python3
"""Deterministic CycloneDX 1.5 JSON SBOM from Cargo.lock, Gradle lock + verification metadata, npm lockfiles.

usage: sbom.py --root REPO --out FILE [--version 0.0.1] [--commit SHA] [--source-date-epoch N]
               [--cargo-metadata FILE | --no-cargo-metadata]
Output is a pure function of the lockfiles + arguments (no wall clock, random UUID or host paths).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inputs  # noqa: E402

ALG = {"SHA-256": "SHA-256", "SHA-512": "SHA-512", "SHA-1": "SHA-1"}


def merge(comps):
    merged = {}
    for c in comps:
        k = c["purl"]
        if k in merged:
            m = merged[k]
            m.setdefault("also", []).append(c.get("lockfile"))
            order = {"required": 0, "optional": 1, "excluded": 2}
            if order[c["scope"]] < order[m["scope"]]:
                m["scope"] = c["scope"]
        else:
            merged[k] = dict(c)
    return [merged[k] for k in sorted(merged)]


def build(root: Path, version, commit, epoch, cargo_metadata, run_metadata):
    comps, info = inputs.read_all(root, cargo_metadata, run_metadata)
    comps = merge(comps)
    out = []
    for c in comps:
        e = {
            "type": "library",
            "bom-ref": c["purl"],
            "name": c["name"],
            "version": c["version"],
            "purl": c["purl"],
            "scope": c["scope"],
        }
        if c.get("group"):
            e["group"] = c["group"]
        if c["hashes"]:
            e["hashes"] = [{"alg": a, "content": h} for a, h in sorted(c["hashes"].items())]
        if c.get("license"):
            e["licenses"] = [{"expression": c["license"]}]
        props = [{"name": "xtrace:ecosystem", "value": c["ecosystem"]}]
        if c.get("lockfile"):
            props.append({"name": "xtrace:lockfile", "value": c["lockfile"]})
        if c.get("workspace"):
            props.append({"name": "xtrace:workspace-member", "value": "true"})
        if c.get("configs"):
            props.append({"name": "xtrace:gradle-configurations", "value": ",".join(c["configs"])})
        e["properties"] = props
        out.append(e)
    digest = hashlib.sha256()
    for e in out:
        digest.update(e["purl"].encode() + b"\0")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:xtrace:sbom:{version}:{commit}:{digest.hexdigest()}")
    app_ref = f"pkg:generic/xtrace@{version}"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
            "tools": {"components": [{"type": "application", "name": "xtrace-supply-chain-sbom", "version": "1"}]},
            "component": {
                "type": "application", "bom-ref": app_ref, "name": "xtrace", "version": version,
                "purl": app_ref,
                "properties": [{"name": "xtrace:source-commit", "value": commit}],
            },
            "properties": [
                {"name": "xtrace:cargo-metadata-enriched", "value": str(info["cargo"]["cargoMetadata"]).lower()},
                {"name": "xtrace:gradle-verification-components", "value": str(info["gradle"]["verificationComponents"])},
            ],
        },
        "components": out,
        "dependencies": [{"ref": app_ref, "dependsOn": [e["purl"] for e in out if e["scope"] == "required"]}],
    }
    return bom, info


def summarize(bom):
    counts = {}
    for c in bom["components"]:
        eco = next(p["value"] for p in c["properties"] if p["name"] == "xtrace:ecosystem")
        key = f"{eco}:{c['scope']}"
        counts[key] = counts.get(key, 0) + 1
    no_hash = sum(1 for c in bom["components"] if "hashes" not in c and c["scope"] != "excluded")
    return {"components": len(bom["components"]), "byEcosystemScope": dict(sorted(counts.items())),
            "shippedWithoutHash": no_hash}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--version", default="0.0.1")
    ap.add_argument("--commit", default="0" * 40)
    ap.add_argument("--source-date-epoch", type=int, default=0)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--cargo-metadata", type=Path)
    g.add_argument("--no-cargo-metadata", action="store_true")
    a = ap.parse_args(argv)
    bom, _ = build(a.root.resolve(), a.version, a.commit, a.source_date_epoch,
                   a.cargo_metadata, not a.no_cargo_metadata)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summarize(bom), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
