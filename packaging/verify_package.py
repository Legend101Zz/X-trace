#!/usr/bin/env python3
"""Package content verifier for the X-trace archive produced by packaging/build.py.

    python3 packaging/verify_package.py PACKAGE [--version 0.0.1] [--repo REPO]
                                        [--run-binary] [--out report.json]

PACKAGE is an extracted package directory or the xtrace-<version>-<platform>.tar.gz archive.
Standard library only. Exits 0 when every check passes, 1 otherwise; the JSON report on stdout (and
--out) lists every check with its result, so a skipped check can never read as a pass.

Checks (names are stable; the tests in packaging/test/test_verify_package.py pin them):
  manifest_schema        PACKAGE-MANIFEST.json parses and has the xtrace-package-manifest/1 shape
  version_matches        manifest.version, share/xtrace/VERSION and the expected version agree
  pack_trust_non_release packTrust is "unsigned" or "dev": this tool never accepts a release claim
  required_components    CLI binary, web assets, Java pack, Node pack, schemas, migrations
                         evidence (embedded in the single binary), SBOM, licenses, installers
  manifest_hashes        every listed file exists with the listed size and sha256; no unlisted file
  payload_hashes         share/xtrace/payload.sha256 rows match the files
  binary_version         (--run-binary) `bin/xtrace --version` prints the package version and the
                         store schema version
  schema_version         (--repo) the reported schema version equals the migration catalog's latest
  tui_subcommand_registered (--run-binary) `bin/xtrace tui --help` exits 0 (the subcommand exists; says nothing
                         about a working TUI)
  tui_implemented        (--run-binary) `bin/xtrace tui` with stdin closed does not exit 9 / report
                         XTR-CLI-NOT-IMPLEMENTED; RED until the TUI is real

The daemon and TUI are part of the single `xtrace` binary; migrations are compiled into it. The
report says so in `notes` instead of pretending there are separate files.
"""
import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

MANIFEST_REL = "share/xtrace/PACKAGE-MANIFEST.json"
MANIFEST_SCHEMA = "xtrace-package-manifest/1"
ALLOWED_TRUST = ("unsigned", "dev")

# (component, predicate over the set of manifest paths)
def _any(prefix, suffix=""):
    return lambda paths: any(p.startswith(prefix) and p.endswith(suffix) for p in paths)


def _has(path):
    return lambda paths: path in paths


REQUIRED = [
    ("cli_binary_incl_daemon_and_tui", _has("bin/xtrace")),
    ("web_index", _has("share/xtrace/web/index.html")),
    ("web_app_bundle", _has("share/xtrace/web/app.js")),
    ("web_asset_hashes", _has("share/xtrace/web/assets.sha256")),
    ("java_pack_agent", _any("share/xtrace/packs/java/agent/")),
    ("java_pack_files", _any("share/xtrace/packs/java/")),
    ("node_pack_manifest", _has("share/xtrace/packs/node/pack.manifest")),
    ("node_pack_dist", _any("share/xtrace/packs/node/dist/", ".cjs")),
    ("schema_proto", _any("share/xtrace/schema/proto/", ".proto")),
    ("schema_openapi", _has("share/xtrace/schema/xtp-client/openapi.yaml")),
    ("sbom", _has("share/xtrace/sbom.cdx.json")),
    ("licenses", _has("share/xtrace/licenses.json")),
    ("third_party_notices", _has("share/xtrace/THIRD_PARTY_LICENSES")),
    ("version_stamp", _has("share/xtrace/VERSION")),
    ("payload_sums", _has("share/xtrace/payload.sha256")),
    ("installer", _has("install.sh")),
    ("uninstaller", _has("uninstall.sh")),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_root(package, scratch):
    """Return the package top directory, extracting an archive into `scratch` when needed."""
    package = Path(package)
    if package.is_dir():
        if (package / MANIFEST_REL).is_file():
            return package
        subs = [p for p in package.iterdir() if p.is_dir() and (p / MANIFEST_REL).is_file()]
        if len(subs) == 1:
            return subs[0]
        raise SystemExit(f"no {MANIFEST_REL} under {package}")
    if package.is_file() and package.name.endswith(".tar.gz"):
        with tarfile.open(package, "r:gz") as tf:
            for m in tf.getmembers():
                parts = Path(m.name).parts
                if m.name.startswith("/") or ".." in parts or m.issym() or m.islnk() or m.isdev():
                    raise SystemExit(f"unsafe archive member: {m.name}")
            tf.extractall(scratch)
        tops = [p for p in Path(scratch).iterdir() if p.is_dir()]
        if len(tops) != 1:
            raise SystemExit("archive must have exactly one top-level directory")
        return tops[0]
    raise SystemExit(f"{package} is neither a directory nor a .tar.gz")


class Report:
    def __init__(self):
        self.checks = []

    def add(self, name, ok, detail=""):
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return ok

    @property
    def ok(self):
        return all(c["ok"] for c in self.checks)


def read_manifest(root, rep):
    path = root / MANIFEST_REL
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        rep.add("manifest_schema", False, f"cannot read manifest: {e}")
        return None
    problems = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        problems.append(f"schema is {manifest.get('schema')!r}")
    for key in ("name", "version", "platform", "sourceCommit", "packTrust", "files"):
        if key not in manifest:
            problems.append(f"missing {key}")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        problems.append("files is empty")
    else:
        for f in files:
            if not (isinstance(f, dict) and isinstance(f.get("path"), str)
                    and isinstance(f.get("sha256"), str) and len(f["sha256"]) == 64
                    and isinstance(f.get("size"), int)):
                problems.append(f"malformed file row {f!r}")
                break
            p = Path(f["path"])
            if p.is_absolute() or ".." in p.parts:
                problems.append(f"unsafe path {f['path']!r}")
                break
    rep.add("manifest_schema", not problems, "; ".join(problems) or "ok")
    return manifest if not problems else None


def check_manifest(root, manifest, expected_version, rep):
    version_file = root / "share/xtrace/VERSION"
    stamp = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else None
    ok = manifest["version"] == expected_version and stamp == expected_version
    rep.add("version_matches", ok,
            f"manifest={manifest['version']!r} VERSION={stamp!r} expected={expected_version!r}")
    trust = manifest["packTrust"]
    rep.add("pack_trust_non_release", trust in ALLOWED_TRUST,
            f"packTrust={trust!r}; a release-trust claim is never accepted by this verifier")

    paths = {f["path"] for f in manifest["files"]}
    missing = [name for name, pred in REQUIRED if not pred(paths)]
    rep.add("required_components", not missing, "missing: " + ", ".join(missing) if missing else "all present")

    bad = []
    for f in manifest["files"]:
        p = root / f["path"]
        if not p.is_file() or p.is_symlink():
            bad.append(f"{f['path']}: missing or not a regular file")
        elif p.stat().st_size != f["size"] or sha256_file(p) != f["sha256"]:
            bad.append(f"{f['path']}: size or sha256 differs")
    on_disk = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    unlisted = sorted(on_disk - paths - {MANIFEST_REL})
    bad += [f"{u}: present but not listed" for u in unlisted]
    rep.add("manifest_hashes", not bad, "; ".join(bad[:10]) + (f" (+{len(bad) - 10} more)" if len(bad) > 10 else "") or "ok")

    sums = root / "share/xtrace/payload.sha256"
    bad = []
    if sums.is_file():
        for line in sums.read_text(encoding="utf-8").splitlines():
            m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if not m:
                bad.append(f"malformed row {line[:40]!r}")
                continue
            target = root / m.group(2)
            if not target.is_file() or sha256_file(target) != m.group(1):
                bad.append(f"{m.group(2)}: differs")
    else:
        bad.append("payload.sha256 missing")
    rep.add("payload_hashes", not bad, "; ".join(bad[:10]) or "ok")


def run_binary(root, expected_version, rep):
    exe = root / "bin/xtrace"
    try:
        out = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        rep.add("binary_version", False, f"cannot run bin/xtrace --version: {e}")
        return None
    text = out.stdout
    first = text.splitlines()[0].strip() if text.splitlines() else ""
    m = re.search(r"^schema-version:\s*(\d+)\s*$", text, re.M)
    ok = out.returncode == 0 and first == f"xtrace {expected_version}" and m is not None
    rep.add("binary_version", ok,
            f"first line {first!r}; schema-version {'reported' if m else 'NOT reported'}"
            + ("" if out.returncode == 0 else f"; exit {out.returncode}"))
    try:
        tui = subprocess.run([str(exe), "tui", "--help"], capture_output=True, text=True, timeout=30)
        rep.add("tui_subcommand_registered", tui.returncode == 0, f"`xtrace tui --help` exit {tui.returncode}")
    except (OSError, subprocess.TimeoutExpired) as e:
        rep.add("tui_subcommand_registered", False, f"cannot run bin/xtrace tui --help: {e}")
    try:
        tui = subprocess.run([str(exe), "tui"], capture_output=True, text=True, timeout=15,
                             stdin=subprocess.DEVNULL)
        stub = tui.returncode == 9 or "NOT-IMPLEMENTED" in (tui.stdout + tui.stderr)
        rep.add("tui_implemented", not stub,
                "tui not implemented in this build (exit 9 / XTR-CLI-NOT-IMPLEMENTED)" if stub
                else f"`xtrace tui` without a terminal exit {tui.returncode}")
    except subprocess.TimeoutExpired:
        rep.add("tui_implemented", False, "`xtrace tui` with stdin closed did not exit within 15 s")
    except OSError as e:
        rep.add("tui_implemented", False, f"cannot run bin/xtrace tui: {e}")
    return int(m.group(1)) if m else None


def latest_migration_version(repo):
    text = (Path(repo) / "crates/xtrace-store/src/connection.rs").read_text(encoding="utf-8")
    m = re.search(r"pub const CURRENT_SCHEMA_VERSION: u32 = (\d+);", text)
    return int(m.group(1)) if m else None


def verify(package, expected_version="0.0.1", repo=None, run=False):
    rep = Report()
    with tempfile.TemporaryDirectory(prefix="xtrace-verify-") as scratch:
        root = resolve_root(package, scratch)
        manifest = read_manifest(root, rep)
        reported = None
        if manifest is not None:
            check_manifest(root, manifest, expected_version, rep)
            if run:
                reported = run_binary(root, expected_version, rep)
        if repo:
            latest = latest_migration_version(repo)
            if not run:
                rep.add("schema_version", False, "--repo needs --run-binary to compare the reported schema version")
            else:
                rep.add("schema_version", latest is not None and reported == latest,
                        f"binary reports {reported}, migration catalog latest is {latest}")
        info = {
            "name": manifest and manifest.get("name"),
            "version": manifest and manifest.get("version"),
            "platform": manifest and manifest.get("platform"),
            "packTrust": manifest and manifest.get("packTrust"),
            "sourceCommit": manifest and manifest.get("sourceCommit"),
            "schemaVersionReported": reported,
            "fileCount": manifest and len(manifest["files"]),
        }
    return {
        "schema": "xtrace-package-verification/1",
        "ok": rep.ok,
        "release_evidence": False,
        "package": info,
        "checks": rep.checks,
        "notes": [
            "daemon and TUI are subcommands of the single bin/xtrace binary",
            "store migrations are compiled into bin/xtrace; the schema version it reports is the evidence",
            "packs are unsigned or test-key (dev) only; this report is never release evidence",
        ],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package")
    ap.add_argument("--version", default="0.0.1")
    ap.add_argument("--repo", help="source checkout, to compare the schema version with the migration catalog")
    ap.add_argument("--run-binary", action="store_true", help="execute bin/xtrace (needs a matching platform)")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    report = verify(a.package, a.version, a.repo, a.run_binary)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if a.out:
        a.out.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
