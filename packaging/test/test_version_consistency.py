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
DEP_TABLES = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


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
            for table in DEP_TABLES:
                for dep, ver in data.get(table, {}).items():
                    if dep.startswith("@xtrace/"):
                        self.assertEqual(ver, DEFAULT, f"{p.relative_to(ROOT)} {table} {dep}")

    def test_node_lockfile_workspace_entries(self):
        lock = json.loads((NODE / "package-lock.json").read_text(encoding="utf-8"))
        seen = 0
        for key, entry in lock["packages"].items():
            is_workspace = "node_modules/" not in key and key != "" and "version" in entry
            if is_workspace:
                seen += 1
                self.assertEqual(entry["version"], DEFAULT, key)
            for table in DEP_TABLES:
                for dep, ver in entry.get(table, {}).items():
                    if dep.startswith("@xtrace/"):
                        self.assertEqual(ver, DEFAULT, f"{key} {table} {dep}")
        self.assertGreaterEqual(seen, 4)

    def test_node_adapter_version_constants(self):
        sources = [
            f
            for root in (NODE / "packages", NODE / "examples")
            for ext in ("*.ts", "*.cts", "*.mts")
            for f in root.rglob(ext)
            if "node_modules" not in f.parts and "dist" not in f.parts and "test" not in f.parts
            and not f.name.endswith((".test.ts", ".d.ts"))
        ]
        total = 0
        for f in sources:
            for v in re.findall(r'adapterVersion\s*[:=]\s*"([^"]+)"', f.read_text(encoding="utf-8")):
                total += 1
                self.assertEqual(v, DEFAULT, str(f.relative_to(ROOT)))
        self.assertGreaterEqual(total, 2)

    def test_node_analyzer_version_constant(self):
        f = NODE / "packages/analyzer/src/analyzer.ts"
        m = re.search(r'^const VERSION\s*=\s*"([^"]+)"', f.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), DEFAULT)

    def test_java_versions(self):
        kts = [JAVA / "build.gradle.kts"] + sorted(JAVA.glob("*/build.gradle.kts"))
        self.assertGreaterEqual(len(kts), 5)
        for p in kts:
            m = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8"), re.M)
            self.assertIsNotNone(m, str(p.relative_to(ROOT)))
            self.assertEqual(m.group(1), DEFAULT, str(p.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
