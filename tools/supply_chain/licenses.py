#!/usr/bin/env python3
"""License inventory + THIRD_PARTY_LICENSES for the release payload.

usage: licenses.py --root REPO --out-dir DIR [--cargo-metadata FILE | --no-cargo-metadata] [--strict]
Writes DIR/licenses.json (machine readable) and DIR/THIRD_PARTY_LICENSES (human readable).
Flags: `unknown` (no license evidence), `copyleft` (GPL/LGPL/AGPL/EPL/CDDL/MPL/CC-BY-SA/SSPL ...),
`review` (non-allowlisted license, or non-SPDX string). Only non-excluded (shipped/build) components are inventoried;
dev-only components are counted separately. --strict exits 1 when any flag is present.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inputs  # noqa: E402

PERMISSIVE = {
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Zlib", "CC0-1.0",
    "BSL-1.0", "Unicode-3.0", "Unicode-DFS-2016", "Unlicense", "BlueOak-1.0.0", "Python-2.0", "OpenSSL",
    "WTFPL", "CC-BY-4.0",
}
COPYLEFT_RE = re.compile(r"^(A?GPL|LGPL|EPL|CDDL|MPL|CC-BY-SA|CC-BY-NC|SSPL|EUPL|OSL|RPL|Sleepycat|BUSL)", re.I)
TOKEN = re.compile(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9.+\-]+")


def normalize(expr: str) -> str:
    e = expr.strip().replace("/", " OR ") if "/" in expr and " " not in expr.strip() else expr.strip()
    return re.sub(r"\s+", " ", e)


def classify_id(i: str) -> str:
    base = i.rstrip("+")
    if i in PERMISSIVE or base in PERMISSIVE:
        return "permissive"
    if COPYLEFT_RE.match(base):
        return "copyleft"
    return "review"


def evaluate(expr: str) -> str:
    """OR -> best disjunct, AND -> worst conjunct; WITH exceptions keep the base class (flagged review)."""
    toks = TOKEN.findall(expr)
    rank = {"permissive": 0, "review": 1, "copyleft": 2}
    pos = 0

    def parse_or():
        nonlocal pos
        vals = [parse_and()]
        while pos < len(toks) and toks[pos] == "OR":
            pos += 1
            vals.append(parse_and())
        return min(vals, key=rank.get)

    def parse_and():
        nonlocal pos
        vals = [parse_atom()]
        while pos < len(toks) and toks[pos] == "AND":
            pos += 1
            vals.append(parse_atom())
        return max(vals, key=rank.get)

    def parse_atom():
        nonlocal pos
        if pos >= len(toks):
            return "review"
        t = toks[pos]
        pos += 1
        if t == "(":
            v = parse_or()
            if pos < len(toks) and toks[pos] == ")":
                pos += 1
            return v
        v = classify_id(t)
        if pos < len(toks) and toks[pos] == "WITH":
            pos += 2
            v = "review" if v == "permissive" else v
        return v

    v = parse_or()
    return v if pos == len(toks) else "review"


def find_license_texts(manifest_dir):
    if not manifest_dir:
        return []
    d = Path(manifest_dir)
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.iterdir()):
        if p.is_file() and re.match(r"(LICENSE|LICENCE|COPYING|NOTICE|UNLICENSE)", p.name, re.I):
            try:
                out.append((p.name, p.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                pass
    return out


def build(root: Path, cargo_metadata, run_metadata, node_modules_dirs):
    comps, info = inputs.read_all(root, cargo_metadata, run_metadata)
    overrides = json.loads((Path(__file__).with_name("license_overrides.json")).read_text(encoding="utf-8"))
    seen = {}
    dev_only = 0
    for c in comps:
        if c["scope"] == "excluded":
            dev_only += 1
            continue
        key = c["purl"]
        if key in seen:
            continue
        lic, evidence = c.get("license"), "lockfile/registry metadata"
        ov = overrides.get(f"pkg:maven/{c.get('group')}/{c['name']}") if c["ecosystem"] == "maven" else None
        if ov and not lic:
            lic, evidence = ov["spdx"], "override: " + ov["evidence"]
        if c["ecosystem"] == "npm" and not lic:
            for nm in node_modules_dirs:
                pj = Path(nm) / c["name"] / "package.json"
                if pj.is_file():
                    lic = json.loads(pj.read_text(encoding="utf-8")).get("license")
                    evidence = "installed package.json"
                    break
        flags = []
        if not lic:
            flags.append("unknown")
            cls = "unknown"
        else:
            lic = normalize(lic)
            cls = evaluate(lic)
            if cls == "copyleft":
                flags.append("copyleft")
            elif cls == "review":
                flags.append("review")
        if c["ecosystem"] == "maven" and ov and ov.get("notes"):
            flags.append("review")
        texts = find_license_texts(c.get("manifest_dir"))
        seen[key] = {
            "purl": key, "name": c["name"], "version": c["version"], "ecosystem": c["ecosystem"],
            "scope": c["scope"], "license": lic, "classification": cls, "flags": sorted(set(flags)),
            "evidence": evidence, "workspace": bool(c.get("workspace")),
            "textFiles": [n for n, _ in texts], "_texts": texts,
        }
    return [seen[k] for k in sorted(seen)], dev_only, info


def render_notices(items):
    lines = ["THIRD-PARTY LICENSES FOR X-TRACE", "=" * 32, "",
             "Generated from lockfiles; see licenses.json for machine-readable data and flags.", ""]
    texts, order = {}, []
    for it in items:
        for _, t in it["_texts"]:
            h = hashlib.sha256(t.encode()).hexdigest()
            if h not in texts:
                texts[h] = t
                order.append(h)
    idx = {h: i + 1 for i, h in enumerate(order)}
    for it in items:
        refs = sorted({idx[hashlib.sha256(t.encode()).hexdigest()] for _, t in it["_texts"]})
        flag = f"  [FLAGS: {', '.join(it['flags'])}]" if it["flags"] else ""
        lines.append(f"{it['purl']}  license={it['license'] or 'UNKNOWN'}{flag}"
                     + (f"  text=[{', '.join(map(str, refs))}]" if refs else "  text=see SPDX id"))
    lines += ["", "-" * 72, "LICENSE TEXTS (deduplicated)", "-" * 72, ""]
    for h in order:
        lines += [f"[{idx[h]}]", texts[h].rstrip(), "", "-" * 40, ""]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--node-modules", type=Path, action="append", default=[],
                    help="installed node_modules dirs used to resolve missing npm license ids")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--cargo-metadata", type=Path)
    g.add_argument("--no-cargo-metadata", action="store_true")
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args(argv)
    root = a.root.resolve()
    nm = a.node_modules or [root / "adapters/node/node_modules", root / "web/app/node_modules"]
    items, dev_only, info = build(root, a.cargo_metadata, not a.no_cargo_metadata, nm)
    a.out_dir.mkdir(parents=True, exist_ok=True)
    (a.out_dir / "THIRD_PARTY_LICENSES").write_text(render_notices(items), encoding="utf-8")
    pub = [{k: v for k, v in it.items() if not k.startswith("_")} for it in items]
    flagged = [p for p in pub if p["flags"]]
    doc = {
        "schema": "xtrace-licenses/1",
        "counts": {"inventoried": len(pub), "devOnlyExcluded": dev_only, "flagged": len(flagged),
                   "unknown": sum("unknown" in p["flags"] for p in pub),
                   "copyleft": sum("copyleft" in p["flags"] for p in pub),
                   "review": sum("review" in p["flags"] for p in pub)},
        "cargoMetadataEnriched": info["cargo"]["cargoMetadata"],
        "components": pub,
    }
    (a.out_dir / "licenses.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(doc["counts"], sort_keys=True))
    for p in flagged:
        print(f"FLAG {','.join(p['flags'])}: {p['purl']} license={p['license']}", file=sys.stderr)
    return 1 if (a.strict and flagged) else 0


if __name__ == "__main__":
    raise SystemExit(main())
