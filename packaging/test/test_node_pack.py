"""Verify package staging writes the Node launcher inventory for the shipped files."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build as package_build  # noqa: E402


class NodePack(unittest.TestCase):
    def test_runtime_manifest_covers_exact_packaged_dist(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / "adapters/node/packages/adapter-core/dist"
            files = {
                "register.cjs": b"require('./runtime/context.cjs')",
                "register.mjs": b"import './runtime/context.cjs'",
                "runtime/context.cjs": b"module.exports = {}",
                "node_modules/example/package.json": b'{"name":"example","version":"1.0.0"}',
            }
            for name, contents in files.items():
                file = source / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(contents)
            (source / "register.d.cts").write_text("export {};")
            (source / "manifest.sha256").write_text("stale source build inventory\n")

            staged = root / "package"
            with patch.object(package_build, "run"):
                package_build.node_pack(root, {}, staged)

            packaged_dist = staged / "dist"
            runtime_inventory = packaged_dist / "manifest.sha256"
            expected = [
                f"{hashlib.sha256(contents).hexdigest()}  {name}"
                for name, contents in sorted(files.items())
            ]
            self.assertEqual(runtime_inventory.read_text().splitlines(), expected)
            self.assertEqual(
                {p.relative_to(packaged_dist).as_posix() for p in packaged_dist.rglob("*") if p.is_file()},
                {*files, "manifest.sha256"},
            )
            manifest_digest = hashlib.sha256(runtime_inventory.read_bytes()).hexdigest()
            self.assertIn(f"{manifest_digest}  dist/manifest.sha256", (staged / "pack.manifest").read_text().splitlines())
