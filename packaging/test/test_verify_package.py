"""Tests for packaging/verify_package.py against synthetic package layouts.

The layouts are built in a temp dir to exercise the verifier's logic (missing components, hash
drift, version drift, trust claims). They are NOT a build of the product: the real archive is
verified in package.yml. Run: python3 -B -m unittest discover -s packaging/test -p 'test_*.py'
"""
import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import verify_package as vp  # noqa: E402

FILES = {
    "bin/xtrace": "#!/bin/sh\ncase \"$1\" in --version) printf 'xtrace 0.0.1\\nschema-version: 6\\nxtp-protocol: 1.1\\n';; tui) [ \"$2\" = --help ] && exit 0; echo real tui needs a terminal >&2; exit 2;; esac\n",
    "install.sh": "#!/bin/sh\n", "uninstall.sh": "#!/bin/sh\n",
    "share/xtrace/web/index.html": "<html></html>", "share/xtrace/web/app.js": "1",
    "share/xtrace/web/assets.sha256": "x",
    "share/xtrace/packs/java/agent/xtrace-agent.jar": "jar",
    "share/xtrace/packs/node/pack.manifest": "m",
    "share/xtrace/packs/node/dist/register.cjs": "c",
    "share/xtrace/schema/proto/xtp-agent/v1.proto": "p",
    "share/xtrace/schema/xtp-client/openapi.yaml": "o",
    "share/xtrace/sbom.cdx.json": "{}", "share/xtrace/licenses.json": "{}",
    "share/xtrace/THIRD_PARTY_LICENSES": "n", "share/xtrace/VERSION": "0.0.1\n",
}


def build(root, trust="unsigned", version="0.0.1", drop=(), extra=None):
    files = dict(FILES)
    files.update(extra or {})
    for d in drop:
        files.pop(d)
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        if rel == "bin/xtrace":
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
    rows = [f"{vp.sha256_file(root / r)}  {r}" for r in sorted(files)]
    (root / "share/xtrace/payload.sha256").write_text("\n".join(rows) + "\n")
    listed = sorted(list(files) + ["share/xtrace/payload.sha256"])
    manifest = {"schema": vp.MANIFEST_SCHEMA, "name": "xtrace", "version": version, "platform": "linux-x86_64",
                "sourceCommit": "0" * 40, "packTrust": trust,
                "files": [{"path": r, "sha256": vp.sha256_file(root / r), "size": (root / r).stat().st_size}
                          for r in listed]}
    (root / vp.MANIFEST_REL).write_text(json.dumps(manifest))


def verdict(report):
    return {c["check"]: c["ok"] for c in report["checks"]}


class VerifyPackage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vp-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "xtrace-0.0.1-linux-x86_64"
        self.root.mkdir()

    def test_manifest_lists_every_required_component(self):
        build(self.root)
        report = vp.verify(self.root)
        self.assertTrue(report["ok"], report)
        self.assertFalse(report["release_evidence"])
        for drop in ("share/xtrace/packs/node/pack.manifest", "share/xtrace/web/index.html",
                     "share/xtrace/schema/xtp-client/openapi.yaml", "bin/xtrace"):
            shutil.rmtree(self.root)
            self.root.mkdir()
            build(self.root, drop=[drop])
            v = verdict(vp.verify(self.root))
            self.assertFalse(v["required_components"], drop)

    def test_version_matches_package_name(self):
        build(self.root, version="0.1.0")
        (self.root / "share/xtrace/VERSION").write_text("0.1.0\n")
        build(self.root, version="0.1.0", extra={"share/xtrace/VERSION": "0.1.0\n"})
        self.assertFalse(verdict(vp.verify(self.root))["version_matches"])
        self.assertTrue(verdict(vp.verify(self.root, "0.1.0"))["version_matches"])

    def test_release_trust_claim_is_rejected(self):
        build(self.root, trust="signed")
        self.assertFalse(verdict(vp.verify(self.root))["pack_trust_non_release"])
        shutil.rmtree(self.root)
        self.root.mkdir()
        build(self.root, trust="dev")
        self.assertTrue(verdict(vp.verify(self.root))["pack_trust_non_release"])

    def test_modified_and_unlisted_files_are_detected(self):
        build(self.root)
        (self.root / "bin/xtrace").write_text("tampered")
        self.assertFalse(verdict(vp.verify(self.root))["manifest_hashes"])
        shutil.rmtree(self.root)
        self.root.mkdir()
        build(self.root)
        (self.root / "share/xtrace/extra.bin").write_text("x")
        report = vp.verify(self.root)
        self.assertFalse(verdict(report)["manifest_hashes"])
        self.assertIn("not listed", json.dumps(report))

    def test_payload_sums_drift_is_detected(self):
        build(self.root)
        p = self.root / "share/xtrace/payload.sha256"
        p.write_text(p.read_text().replace("0", "1", 1))
        # the manifest hash of payload.sha256 also drifts; both must fail
        v = verdict(vp.verify(self.root))
        self.assertFalse(v["manifest_hashes"])

    def test_payload_row_drift_is_caught_by_payload_hashes_even_when_the_manifest_agrees(self):
        build(self.root)
        p = self.root / "share/xtrace/payload.sha256"
        rows = p.read_text().splitlines()
        rows[0] = "0" * 64 + rows[0][64:]
        p.write_text("\n".join(rows) + "\n")
        mpath = self.root / vp.MANIFEST_REL
        manifest = json.loads(mpath.read_text())
        for entry in manifest["files"]:
            if entry["path"] == "share/xtrace/payload.sha256":
                entry["sha256"] = vp.sha256_file(p)
                entry["size"] = p.stat().st_size
        mpath.write_text(json.dumps(manifest))
        v = verdict(vp.verify(self.root))
        self.assertTrue(v["manifest_hashes"])
        self.assertFalse(v["payload_hashes"])

    def test_archive_with_a_fifo_member_is_rejected(self):
        build(self.root)
        archive = self.tmp / "xtrace-0.0.1-linux-x86_64.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(self.root, arcname=self.root.name)
            info = tarfile.TarInfo(self.root.name + "/pipe")
            info.type = tarfile.FIFOTYPE
            tf.addfile(info)
        with self.assertRaises(SystemExit):
            vp.verify(archive)

    def test_binary_without_xtp_protocol_line_fails(self):
        build(self.root, extra={"bin/xtrace": "#!/bin/sh\nprintf 'xtrace 0.0.1\\nschema-version: 6\\n'\n"})
        self.assertFalse(verdict(vp.verify(self.root, run=True))["binary_version"])

    def test_archive_input_and_unsafe_members(self):
        build(self.root)
        archive = self.tmp / "xtrace-0.0.1-linux-x86_64.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(self.root, arcname=self.root.name)
        self.assertTrue(vp.verify(archive)["ok"])
        evil = self.tmp / "evil.tar.gz"
        with tarfile.open(evil, "w:gz") as tf:
            info = tarfile.TarInfo("../escape")
            info.size = 0
            tf.addfile(info)
        with self.assertRaises(SystemExit):
            vp.verify(evil)

    def test_schema_version_reported_equals_migrations_latest(self):
        build(self.root)
        repo = self.tmp / "repo"
        (repo / "crates/xtrace-store/src").mkdir(parents=True)
        conn = repo / "crates/xtrace-store/src/connection.rs"
        conn.write_text("pub const CURRENT_SCHEMA_VERSION: u32 = 6;\n")
        report = vp.verify(self.root, repo=repo, run=True)
        v = verdict(report)
        self.assertTrue(v["binary_version"] and v["schema_version"] and v["tui_subcommand_registered"] and v["tui_implemented"], report)
        conn.write_text("pub const CURRENT_SCHEMA_VERSION: u32 = 7;\n")
        self.assertFalse(verdict(vp.verify(self.root, repo=repo, run=True))["schema_version"])

    def test_tui_stub_binary_fails_tui_implemented_but_registers_the_subcommand(self):
        stub = ("#!/bin/sh\ncase \"$1\" in --version) printf 'xtrace 0.0.1\\nschema-version: 6\\n';; "
                "tui) [ \"$2\" = --help ] && exit 0; echo XTR-CLI-NOT-IMPLEMENTED >&2; exit 9;; esac\n")
        build(self.root, extra={"bin/xtrace": stub})
        v = verdict(vp.verify(self.root, run=True))
        self.assertTrue(v["tui_subcommand_registered"])
        self.assertFalse(v["tui_implemented"])

    def test_binary_that_does_not_report_schema_version_fails(self):
        build(self.root, extra={"bin/xtrace": "#!/bin/sh\necho 'xtrace 0.0.1'\n"})
        self.assertFalse(verdict(vp.verify(self.root, run=True))["binary_version"])


if __name__ == "__main__":
    unittest.main()
