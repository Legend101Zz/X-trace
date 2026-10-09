"""Version-family consistency: every shipped component must carry the packaging default version.

No build is run; this only reads manifests and sources. Run:
python3 -B -m unittest discover -s packaging/test -p 'test_*.py'
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NODE = ROOT / "adapters" / "node"
JAVA = ROOT / "adapters" / "java"


def packaging_default():
    text = (ROOT / "packaging" / "build.py").read_text(encoding="utf-8")
    m = re.search(r'add_argument\(\s*"--version"\s*,\s*default\s*=\s*"([^"]+)"', text)
    assert m, "packaging/build.py --version default not found"
    return m.group(1)


DEFAULT = packaging_default()


class VersionConsistency(unittest.TestCase):
    def test_default_is_sane(self):
        self.assertRegex(DEFAULT, r"^\d+\.\d+\.\d+$")

    def test_rust_workspace_version(self):
        text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        m = re.search(r"\[workspace\.package\][^\[]*?\nversion\s*=\s*\"([^\"]+)\"", text)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), DEFAULT)

    def test_node_workspace_packages(self):
        manifests = sorted(NODE.glob("packages/*/package.json")) + [NODE / "examples/synthetic-client/package.json"]
        self.assertGreaterEqual(len(manifests), 4)
        for p in manifests:
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data.get("version"), DEFAULT, str(p.relative_to(ROOT)))
            for dep, ver in data.get("dependencies", {}).items():
                if dep.startswith("@xtrace/"):
                    self.assertEqual(ver, DEFAULT, f"{p.relative_to(ROOT)} dep {dep}")

    def test_node_lockfile_workspace_entries(self):
        lock = json.loads((NODE / "package-lock.json").read_text(encoding="utf-8"))
        seen = 0
        for key, entry in lock["packages"].items():
            if entry.get("name", "").startswith("@xtrace/") and "version" in entry or (
                key.startswith("packages/") and "version" in entry
            ):
                seen += 1
                self.assertEqual(entry["version"], DEFAULT, key)
            for dep, ver in entry.get("dependencies", {}).items():
                if dep.startswith("@xtrace/"):
                    self.assertEqual(ver, DEFAULT, f"{key} dep {dep}")
        self.assertGreaterEqual(seen, 4)

    def test_node_adapter_version_constants(self):
        files = [NODE / "packages/adapter-core/src/transport-worker.ts", NODE / "examples/synthetic-client/src/main.ts"]
        for f in files:
            found = re.findall(r'adapterVersion:\s*"([^"]+)"', f.read_text(encoding="utf-8"))
            self.assertTrue(found, f.name)
            for v in found:
                self.assertEqual(v, DEFAULT, f.name)

    def test_java_versions(self):
        kts = [JAVA / "build.gradle.kts"] + sorted(JAVA.glob("*/build.gradle.kts"))
        self.assertGreaterEqual(len(kts), 5)
        for p in kts:
            m = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8"), re.M)
            self.assertIsNotNone(m, str(p.relative_to(ROOT)))
            self.assertEqual(m.group(1), DEFAULT, str(p.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
