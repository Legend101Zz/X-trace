#!/usr/bin/env python3
"""Re-create the deterministic archive from an (optionally re-signed) extracted payload and refresh SHA256SUMS.

    repack.py --dir xtrace-0.0.1-<platform>/ --out-dir OUT --src-dist DIST [--pack-trust T] [--notarization-id ID]
Recomputes payload.sha256 and PACKAGE-MANIFEST.json (new bin/xtrace hash, packTrust marker). Mtime = manifest epoch.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--src-dist", type=Path, required=True, help="dist/<platform> dir holding sbom/licenses/build-info")
    ap.add_argument("--pack-trust", default="unsigned")
    ap.add_argument("--notarization-id", default="")
    a = ap.parse_args(argv)
    root = a.dir.resolve()
    share = root / "share" / "xtrace"
    manifest = json.loads((share / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    rows = [f"{build.sha256_file(p)}  {p.relative_to(root).as_posix()}"
            for p in sorted(root.rglob("*")) if p.is_file()
            and p.relative_to(root).as_posix() not in ("share/xtrace/payload.sha256", "share/xtrace/PACKAGE-MANIFEST.json")]
    (share / "payload.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.relative_to(root).as_posix() != "share/xtrace/PACKAGE-MANIFEST.json":
            rel = p.relative_to(root).as_posix()
            files.append({"path": rel, "sha256": build.sha256_file(p), "size": p.stat().st_size,
                          "mode": "0755" if rel in build.EXECUTABLES else "0644"})
    manifest.update({"files": files, "packTrust": a.pack_trust})
    if a.notarization_id:
        manifest["notarizationSubmissionId"] = a.notarization_id
    (share / "PACKAGE-MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    a.out_dir.mkdir(parents=True, exist_ok=True)
    archive = a.out_dir / f"{root.name}.tar.gz"
    build.deterministic_tar_gz(root, root.name, archive, int(manifest["sourceDateEpoch"]))
    names = [archive.name]
    for n in ("sbom.cdx.json", "licenses.json", "THIRD_PARTY_LICENSES"):
        shutil.copyfile(a.src_dist / n, a.out_dir / n)
        names.append(n)
    info = json.loads((a.src_dist / "build-info.json").read_text(encoding="utf-8"))
    info.update({"archiveSha256": build.sha256_file(archive), "packTrust": a.pack_trust,
                 "note": "re-signed payload; see PACKAGE-MANIFEST.json"})
    (a.out_dir / "build-info.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    names.append("build-info.json")
    (a.out_dir / "SHA256SUMS").write_text(
        "".join(f"{build.sha256_file(a.out_dir / n)}  {n}\n" for n in sorted(names)), encoding="utf-8")
    print(json.dumps({"archive": str(archive), "sha256": info["archiveSha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
