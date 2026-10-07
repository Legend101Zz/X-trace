"""Unit checks for the SBOM and license tooling. Run: python3 -B -m unittest discover -s tools/supply_chain"""
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent / "packaging"))
import inputs  # noqa: E402
import licenses  # noqa: E402
import sbom  # noqa: E402

ROOT = HERE.parent.parent


class LicenseEval(unittest.TestCase):
    def test_classes(self):
        ev = licenses.evaluate
        self.assertEqual(ev("MIT"), "permissive")
        self.assertEqual(ev("MIT OR Apache-2.0"), "permissive")
        self.assertEqual(ev("Apache-2.0 OR GPL-3.0-only"), "permissive")
        self.assertEqual(ev("MIT AND GPL-2.0-only"), "copyleft")
        self.assertEqual(ev("LGPL-2.1-or-later"), "copyleft")
        self.assertEqual(ev("MPL-2.0"), "copyleft")
        self.assertEqual(ev("Apache-2.0 WITH LLVM-exception"), "review")
        self.assertEqual(ev("OFL-1.1"), "review")
        self.assertEqual(ev("(MIT OR Apache-2.0) AND Unicode-3.0"), "permissive")

    def test_slash_form(self):
        self.assertEqual(licenses.normalize("MIT/Apache-2.0"), "MIT OR Apache-2.0")


class SbomShape(unittest.TestCase):
    def test_deterministic_and_complete(self):
        a, _ = sbom.build(ROOT, "0.0.1", "a" * 40, 1700000000, None, False)
        b, _ = sbom.build(ROOT, "0.0.1", "a" * 40, 1700000000, None, False)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(a["bomFormat"], "CycloneDX")
        self.assertEqual(a["specVersion"], "1.5")
        self.assertEqual(a["metadata"]["timestamp"], "2023-11-14T22:13:20Z")
        purls = [c["purl"] for c in a["components"]]
        self.assertEqual(len(purls), len(set(purls)))
        self.assertTrue(all(c["version"] and c["purl"].startswith("pkg:") for c in a["components"]))
        eco = {p["value"] for c in a["components"] for p in c["properties"] if p["name"] == "xtrace:ecosystem"}
        self.assertEqual(eco, {"cargo", "maven", "npm"})
        crates = [c for c in a["components"] if c["purl"].startswith("pkg:cargo/") and "hashes" in c]
        self.assertGreater(len(crates), 50)

    def test_changes_with_commit(self):
        a, _ = sbom.build(ROOT, "0.0.1", "a" * 40, 1, None, False)
        b, _ = sbom.build(ROOT, "0.0.1", "b" * 40, 1, None, False)
        self.assertNotEqual(a["serialNumber"], b["serialNumber"])


class TarDeterminism(unittest.TestCase):
    def test_same_bytes_regardless_of_creation_order_and_mtime(self):
        import build
        out = []
        for order in (("b", "a"), ("a", "b")):
            with tempfile.TemporaryDirectory() as d:
                d = Path(d)
                stage = d / "stage"
                (stage / "bin").mkdir(parents=True)
                for n in order:
                    (stage / n).write_text(n)
                (stage / "bin" / "xtrace").write_text("x")
                (stage / "install.sh").write_text("#!/bin/sh\n")
                arc = d / "o.tar.gz"
                build.deterministic_tar_gz(stage, "xtrace-0.0.1-test", arc, 1234)
                raw = arc.read_bytes()
                out.append(hashlib.sha256(raw).hexdigest())
                self.assertEqual(raw[4:8], b"\0\0\0\0")  # gzip header mtime 0
                with tarfile.open(arc) as tf:
                    names = tf.getnames()
                    self.assertEqual(names, sorted(names))
                    for m in tf.getmembers():
                        self.assertEqual((m.uid, m.gid, m.uname, m.gname, m.mtime), (0, 0, "root", "root", 1234))
                    self.assertEqual(tf.getmember("xtrace-0.0.1-test/bin/xtrace").mode, 0o755)
                    self.assertEqual(tf.getmember("xtrace-0.0.1-test/a").mode, 0o644)
        self.assertEqual(out[0], out[1])


if __name__ == "__main__":
    unittest.main()
