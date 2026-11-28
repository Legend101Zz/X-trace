"""Unit tests for packaging/build.py deterministic build environment."""
from __future__ import annotations

import pathlib
import shlex
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import build  # noqa: E402


class BuildEnvTests(unittest.TestCase):
    def test_paths_with_spaces_use_encoded_rustflags_and_quoted_cflags(self) -> None:
        src = pathlib.Path("/Volumes/External SSD/X-trace Checkout")
        target = pathlib.Path("/tmp/work dir/target")
        env = build.build_env(src, 1700000000, target)

        self.assertNotIn("RUSTFLAGS", env)
        self.assertIn("CARGO_ENCODED_RUSTFLAGS", env)
        rust_args = env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        self.assertIn(f"--remap-path-prefix={src}=/xtrace-src", rust_args)
        self.assertIn(f"--remap-path-prefix={target}=/xtrace-target", rust_args)
        self.assertIn("-C", rust_args)
        self.assertIn("strip=symbols", rust_args)

        c_args = shlex.split(env["CFLAGS"])
        self.assertIn(f"-ffile-prefix-map={src}=/xtrace-src", c_args)
        self.assertIn(f"-ffile-prefix-map={target}=/xtrace-target", c_args)


if __name__ == "__main__":
    unittest.main()
