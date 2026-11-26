"""Unit tests for packaging/repro_check.py --emit-dist safety."""
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import repro_check  # noqa: E402


class ReproCheckEmitDistTests(unittest.TestCase):
    def _run_with_payloads(self, payloads: list[bytes], *, preseed=None, extra_symlink: bool = False):
        calls = iter(payloads)

        def fake_run(cmd, check=True, **kwargs):
            out_idx = cmd.index("--out") + 1
            plat_idx = cmd.index("--platform") + 1
            dest = pathlib.Path(cmd[out_idx]) / cmd[plat_idx]
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "xtrace-0.0.1-linux-x86_64.tar.gz").write_bytes(next(calls))
            (dest / "SHA256SUMS").write_text("ok\n", encoding="utf-8")
            (dest / "build-info.json").write_text('{"build":"ok"}\n', encoding="utf-8")
            if extra_symlink:
                os.symlink("xtrace-0.0.1-linux-x86_64.tar.gz", dest / "latest.tar.gz")

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            (src / "packaging").mkdir(parents=True)
            (src / "packaging" / "build.py").write_text("# stub\n", encoding="utf-8")
            out = root / "repro"
            emit = root / "dist"
            if preseed is not None:
                preseed(emit)
            with mock.patch.object(repro_check.subprocess, "run", side_effect=fake_run):
                rc = repro_check.main([
                    "--out", str(out),
                    "--tree", str(src),
                    "--commit", "0" * 40,
                    "--source-date-epoch", "1700000000",
                    "--platform", "linux-x86_64",
                    "--emit-dist", str(emit),
                ])
            report = json.loads((out / "repro.json").read_text(encoding="utf-8"))
            plat_dir = emit / "linux-x86_64"
            exists = os.path.lexists(plat_dir)
            emitted = sorted(p.name for p in plat_dir.iterdir()) if exists and plat_dir.is_dir() else []
            payload = (plat_dir / "xtrace-0.0.1-linux-x86_64.tar.gz").read_bytes() if "xtrace-0.0.1-linux-x86_64.tar.gz" in emitted else None
            is_symlink = (plat_dir / "latest.tar.gz").is_symlink() if "latest.tar.gz" in emitted else False
            return rc, report, exists, emitted, payload, is_symlink

    def test_emits_verified_dist_and_replaces_dangling_symlink(self) -> None:
        def preseed(emit: pathlib.Path) -> None:
            emit.mkdir(parents=True)
            os.symlink("/nonexistent/stale-dist", emit / "linux-x86_64")

        rc, report, exists, emitted, payload, is_symlink = self._run_with_payloads(
            [b"identical", b"identical"], preseed=preseed, extra_symlink=True,
        )
        self.assertEqual(rc, 0)
        self.assertTrue(report["reproducible"])
        self.assertTrue(exists)
        self.assertEqual(emitted, ["SHA256SUMS", "build-info.json", "latest.tar.gz", "xtrace-0.0.1-linux-x86_64.tar.gz"])
        self.assertEqual(payload, b"identical")
        self.assertTrue(is_symlink)

    def test_removes_stale_dist_when_builds_differ(self) -> None:
        def preseed(emit: pathlib.Path) -> None:
            stale = emit / "linux-x86_64"
            stale.mkdir(parents=True)
            (stale / "stale.tar.gz").write_bytes(b"stale")

        rc, report, exists, emitted, payload, _ = self._run_with_payloads([b"build-a", b"build-b"], preseed=preseed)
        self.assertEqual(rc, 1)
        self.assertFalse(report["reproducible"])
        self.assertEqual(report["differing"], ["xtrace-0.0.1-linux-x86_64.tar.gz"])
        self.assertFalse(exists)
        self.assertEqual(emitted, [])
        self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main()
