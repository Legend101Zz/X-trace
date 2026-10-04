#!/usr/bin/env python3
"""Build the deterministic X-trace release payload archive.

    python3 packaging/build.py --out DIST [--platform macos-arm64|linux-x86_64|linux-aarch64-dev]
                               [--source DIR] [--commit SHA] [--source-date-epoch N] [--work DIR]

Produces DIST/<platform>/{xtrace-<ver>-<platform>.tar.gz, SHA256SUMS, sbom.cdx.json, licenses.json,
THIRD_PARTY_LICENSES, build-info.json}. Every artifact is UNSIGNED; see sign-*.sh for the signing interfaces.
Dev builds are feedback only. Release acceptance builds come from CI on the real platform runners.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import platform as pyplatform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "tools" / "supply_chain"))

PLATFORMS = {
    "macos-arm64": ("aarch64-apple-darwin", "Darwin", "arm64"),
    "linux-x86_64": ("x86_64-unknown-linux-gnu", "Linux", "x86_64"),
    "linux-aarch64-dev": ("aarch64-unknown-linux-gnu", "Linux", "aarch64"),
}
EXECUTABLES = {"bin/xtrace", "install.sh", "uninstall.sh"}


def run(cmd, cwd=None, env=None, capture=False):
    print("+", " ".join(map(str, cmd)), flush=True)
    r = subprocess.run(cmd, cwd=cwd, env=env, check=True, text=True,
                       stdout=subprocess.PIPE if capture else None)
    return r.stdout if capture else None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_platform() -> str:
    s, m = pyplatform.system(), pyplatform.machine().lower()
    if s == "Darwin" and m in ("arm64", "aarch64"):
        return "macos-arm64"
    if s == "Linux" and m in ("x86_64", "amd64"):
        return "linux-x86_64"
    if s == "Linux" and m in ("aarch64", "arm64"):
        return "linux-aarch64-dev"
    sys.exit(f"unsupported build host {s}/{m}; supported: {', '.join(PLATFORMS)}")


def tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        return "unavailable"


def rust_host() -> str:
    try:
        out = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return ""
    return next((l.split()[1] for l in out.splitlines() if l.startswith("host:")), "")


def build_env(src: Path, epoch: int, target_dir: Path) -> dict:
    env = dict(os.environ)
    cargo_home = env.get("CARGO_HOME") or str(Path.home() / ".cargo")
    rustflags = " ".join([
        f"--remap-path-prefix={src}=/xtrace-src",
        f"--remap-path-prefix={cargo_home}=/cargo",
        f"--remap-path-prefix={target_dir}=/xtrace-target",  # build-script OUT_DIR paths (include!) end up in panic locations
        "-C strip=symbols",
    ])
    cflags = (f"-ffile-prefix-map={src}=/xtrace-src -ffile-prefix-map={cargo_home}=/cargo "
              f"-ffile-prefix-map={target_dir}=/xtrace-target")
    env.update({
        "SOURCE_DATE_EPOCH": str(epoch), "TZ": "UTC", "LC_ALL": "C", "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(target_dir), "RUSTFLAGS": rustflags, "CFLAGS": cflags,
        "ZERO_AR_DATE": "1",
    })
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    return env


def copy_tree(src: Path, dst: Path, skip=lambda rel: False):
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src)
        if skip(rel):
            continue
        if p.is_symlink():
            sys.exit(f"refusing symlink in payload: {p}")
        if p.is_dir():
            (dst / rel).mkdir(parents=True, exist_ok=True)
        elif p.is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, dst / rel)


def sha_rows(root: Path, exclude=()):
    rows = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and rel not in exclude:
            rows.append(f"{sha256_file(p)}  {rel}")
    return rows


def node_pack(src: Path, env: dict, stage_pack: Path):
    node = src / "adapters" / "node"
    run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=node, env=env)
    run(["npm", "run", "build:protocol"], cwd=node, env=env)
    run(["npm", "run", "build:core"], cwd=node, env=env)
    dist = node / "packages" / "adapter-core" / "dist"
    if not (dist / "register.cjs").is_file() or not (dist / "register.mjs").is_file():
        sys.exit("node adapter dist is missing register.cjs/register.mjs")

    def skip(rel):
        parts = rel.parts
        return (parts[0] == "test" or rel.name.endswith((".d.ts", ".d.cts", ".d.mts", ".map", ".tsbuildinfo"))
                or rel.as_posix() == "manifest.sha256")

    copy_tree(dist, stage_pack / "dist", skip)
    # ADR 0004 unbundled layout: licenses/THIRD_PARTY.txt lists every bundled dependency.
    lic = ["Third-party packages bundled in the Node adapter pack", ""]
    for pj in sorted((stage_pack / "dist" / "node_modules").rglob("package.json")):
        if "node_modules" in pj.parent.relative_to(stage_pack / "dist" / "node_modules").parts:
            continue
        meta = json.loads(pj.read_text(encoding="utf-8"))
        if "name" in meta and "version" in meta:
            lic.append(f"{meta['name']}@{meta['version']}  {meta.get('license', 'UNKNOWN')}")
    (stage_pack / "licenses").mkdir(parents=True, exist_ok=True)
    (stage_pack / "licenses" / "THIRD_PARTY.txt").write_text("\n".join(lic) + "\n", encoding="utf-8")
    (stage_pack / "pack.manifest").write_text("\n".join(sha_rows(stage_pack, {"pack.manifest"})) + "\n",
                                              encoding="utf-8")


def deterministic_tar_gz(stage: Path, top: str, out: Path, epoch: int):
    entries = [(top + "/" + p.relative_to(stage).as_posix(), p) for p in stage.rglob("*")]
    entries.append((top, stage))
    entries.sort(key=lambda e: e[0].encode())
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, p in entries:
            rel = name[len(top) + 1:] if name != top else ""
            ti = tarfile.TarInfo(name + ("/" if p.is_dir() else ""))
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = epoch, 0, 0, "root", "root"
            if p.is_dir():
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                tf.addfile(ti)
            else:
                assert p.is_file() and not p.is_symlink(), p
                ti.type = tarfile.REGTYPE
                ti.mode = 0o755 if rel in EXECUTABLES else 0o644
                ti.size = p.stat().st_size
                with open(p, "rb") as f:
                    tf.addfile(ti, f)
    with open(out, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, compresslevel=9, mtime=0) as gz:
            gz.write(raw.getvalue())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--platform", choices=sorted(PLATFORMS), default=None)
    ap.add_argument("--source", type=Path, default=REPO, help="clean checkout to build (default: this repo)")
    ap.add_argument("--version", default="0.0.1")
    ap.add_argument("--commit", help="40-hex source commit (required when --source has no .git)")
    ap.add_argument("--source-date-epoch", type=int)
    ap.add_argument("--work", type=Path, help="scratch dir (default: temp dir, removed afterwards)")
    ap.add_argument("--allow-dirty", action="store_true", help="dev only; refuses to run otherwise on a dirty .git tree")
    ap.add_argument("--skip-web-verify", action="store_true")
    a = ap.parse_args(argv)

    src = a.source.resolve()
    plat = a.platform or detect_platform()
    triple, want_sys, want_arch = PLATFORMS[plat]
    host = rust_host()
    if host != triple:
        sys.exit(f"platform {plat} needs rust host {triple}, found {host or 'no rustc'}; build on the real runner")

    if (src / ".git").exists():
        commit = a.commit or run(["git", "rev-parse", "HEAD"], cwd=src, capture=True).strip()
        dirty = run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=src, capture=True).strip()
        if dirty and not a.allow_dirty:
            sys.exit("source tree is not clean (use a fresh checkout, or --allow-dirty for dev feedback):\n" + dirty)
        epoch = a.source_date_epoch if a.source_date_epoch is not None else int(
            run(["git", "log", "-1", "--format=%ct", commit], cwd=src, capture=True).strip())
    else:
        if not a.commit or a.source_date_epoch is None:
            sys.exit("--commit and --source-date-epoch are required when --source is not a git checkout")
        commit, epoch = a.commit, a.source_date_epoch
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        sys.exit("commit must be 40 lowercase hex")

    work_owned = a.work is None
    work = (a.work or Path(tempfile.mkdtemp(prefix="xtrace-pkg-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    target = work / "target"
    env = build_env(src, epoch, target)
    out = a.out.resolve() / plat
    out.mkdir(parents=True, exist_ok=True)
    top = f"xtrace-{a.version}-{plat}"
    stage = work / "stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()

    # 1. Rust binary
    run(["cargo", "build", "--release", "--locked", "-p", "xtrace-cli"], cwd=src, env=env)
    (stage / "bin").mkdir()
    shutil.copyfile(target / "release" / "xtrace", stage / "bin" / "xtrace")
    # 2. web assets exactly as the binary embeds them
    ui = src / "crates" / "xtrace-daemon" / "assets" / "ui"
    if not a.skip_web_verify:
        web = src / "web" / "app"
        run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=web, env=env)
        run(["npm", "run", "check:embedded"], cwd=web, env=env)
    copy_tree(ui, stage / "share" / "xtrace" / "web")
    # 3. Java pack (attach helper + agent), strict dependency verification, reproducible archives
    java = src / "adapters" / "java"
    run(["./gradlew", "--no-daemon", "--dependency-verification", "strict",
         "-I", str(HERE / "gradle" / "reproducible.init.gradle"), "clean", "javaPackDist"], cwd=java, env=env)
    pack = java / "build" / "java-pack-dist"
    copy_tree(pack, stage / "share" / "xtrace" / "packs" / "java")
    # 4. Node pack
    node_pack(src, env, stage / "share" / "xtrace" / "packs" / "node")
    # 5. schemas
    copy_tree(src / "schema" / "proto", stage / "share" / "xtrace" / "schema" / "proto")
    shutil.copyfile(src / "schema" / "xtp-client" / "openapi.yaml", _mk(stage / "share/xtrace/schema/xtp-client/openapi.yaml"))
    # 6. SBOM + licenses (from lockfiles; cargo metadata filtered to this platform)
    meta_file = work / "cargo-metadata.json"
    meta_file.write_text(run(["cargo", "metadata", "--format-version", "1", "--locked",
                              "--filter-platform", triple], cwd=src, env=env, capture=True), encoding="utf-8")
    import sbom, licenses
    bom, _ = sbom.build(src, a.version, commit, epoch, meta_file, False)
    sbom_text = json.dumps(bom, indent=2, sort_keys=True) + "\n"
    items, dev_only, info = licenses.build(
        src, meta_file, False, [src / "adapters/node/node_modules", src / "web/app/node_modules"])
    pub = [{k: v for k, v in it.items() if not k.startswith("_")} for it in items]
    lic_doc = {"schema": "xtrace-licenses/1", "cargoMetadataEnriched": True, "components": pub,
               "counts": {"inventoried": len(pub), "devOnlyExcluded": dev_only,
                          "flagged": sum(bool(p["flags"]) for p in pub),
                          "unknown": sum("unknown" in p["flags"] for p in pub),
                          "copyleft": sum("copyleft" in p["flags"] for p in pub),
                          "review": sum("review" in p["flags"] for p in pub)}}
    lic_text = json.dumps(lic_doc, indent=2, sort_keys=True) + "\n"
    notices = licenses.render_notices(items)
    share = stage / "share" / "xtrace"
    (share / "sbom.cdx.json").write_text(sbom_text, encoding="utf-8")
    (share / "licenses.json").write_text(lic_text, encoding="utf-8")
    (share / "THIRD_PARTY_LICENSES").write_text(notices, encoding="utf-8")
    # 7. install scripts + version stamp
    for name in ("install.sh", "uninstall.sh"):
        shutil.copyfile(HERE / name, stage / name)
    (share / "VERSION").write_text(a.version + "\n", encoding="utf-8")
    # 8. payload.sha256 (sha256sum -c rows, used by install.sh verify), then the package manifest
    rows = [f"{sha256_file(p)}  {p.relative_to(stage).as_posix()}"
            for p in sorted(stage.rglob("*")) if p.is_file()]
    (share / "payload.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")
    files = []
    for p in sorted(stage.rglob("*")):
        if p.is_file():
            rel = p.relative_to(stage).as_posix()
            files.append({"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size,
                          "mode": "0755" if rel in EXECUTABLES else "0644"})
    manifest = {"schema": "xtrace-package-manifest/1", "name": "xtrace", "version": a.version,
                "platform": plat, "rustTriple": triple, "sourceCommit": commit,
                "sourceDateEpoch": epoch, "packTrust": "unsigned", "files": files}
    (share / "PACKAGE-MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                                 encoding="utf-8")

    archive = out / f"{top}.tar.gz"
    deterministic_tar_gz(stage, top, archive, epoch)

    # 9. outputs beside the archive
    (out / "sbom.cdx.json").write_text(sbom_text, encoding="utf-8")
    (out / "licenses.json").write_text(lic_text, encoding="utf-8")
    (out / "THIRD_PARTY_LICENSES").write_text(notices, encoding="utf-8")
    lockfiles = ["Cargo.lock", "adapters/node/package-lock.json", "web/app/package-lock.json",
                 "adapters/java/gradle.lockfile", "adapters/java/gradle/verification-metadata.xml"]
    info_doc = {
        "schema": "xtrace-build-info/1", "platform": plat, "version": a.version, "sourceCommit": commit,
        "sourceDateEpoch": epoch, "packTrust": "unsigned", "archive": archive.name,
        "archiveSha256": sha256_file(archive),
        "materials": {l: sha256_file(src / l) for l in lockfiles},
        "toolchain": {"rustc": tool_version(["rustc", "--version"]), "cargo": tool_version(["cargo", "--version"]),
                      "node": tool_version(["node", "--version"]), "java": tool_version(["java", "-version"]),
                      "python": sys.version.split()[0]},
        "note": "builder-provided, unsigned, non-attested; not release evidence by itself",
    }
    (out / "build-info.json").write_text(json.dumps(info_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    names = [archive.name, "sbom.cdx.json", "licenses.json", "THIRD_PARTY_LICENSES", "build-info.json"]
    (out / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(out / n)}  {n}\n" for n in sorted(names)), encoding="utf-8")
    print(json.dumps({"archive": str(archive), "sha256": info_doc["archiveSha256"], "files": len(files)}))
    if work_owned:
        shutil.rmtree(work, ignore_errors=True)
    return 0


def _mk(p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


if __name__ == "__main__":
    raise SystemExit(main())
