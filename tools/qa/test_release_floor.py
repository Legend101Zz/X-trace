import argparse
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.qa import lane_run, release_floor
from tools.qa.test_lane_run import CheckoutFixture
from tools.release import run_gates


class FloorConfigurationTests(unittest.TestCase):
    def test_only_rust_test_gates_get_feature_and_lane_diagnostics(self):
        original = run_gates.GATES
        configured = release_floor.instrumented_gates(original, pathlib.Path("private-root"), 7200)
        self.assertEqual(len(configured), 23)
        self.assertEqual([gate.name for gate in configured], [gate.name for gate in original])
        for before, after in zip(original, configured):
            with self.subTest(gate=before.name):
                if before.name not in release_floor.RUST_TEST_GATES:
                    self.assertIs(after, before)
                    continue
                self.assertIn("--ci-diagnostics", after.argv)
                self.assertIn("--private-log-dir", after.argv)
                self.assertEqual(after.argv[after.argv.index("--timeout") + 1], "7200")
                cargo = list(after.argv[after.argv.index("--") + 1:])
                feature = cargo.index("--features")
                self.assertEqual(cargo[feature + 1], release_floor.DIAGNOSTIC_FEATURE)
                self.assertLess(feature, cargo.index("--") if "--" in cargo else len(cargo))
                del cargo[feature:feature + 2]
                self.assertEqual(cargo, list(before.argv))
                self.assertEqual((after.cwd, after.env), (before.cwd, before.env))

    def test_receipt_validation_and_execution_share_the_same_gate_definition(self):
        original = run_gates.GATES
        root = pathlib.Path("private-root")
        with release_floor.configured_floor(root, 7200):
            executed = run_gates.GATES
            self.assertEqual(release_floor.ci_floor.run_gates.GATES, executed)
        self.assertIs(run_gates.GATES, original)
        with release_floor.configured_floor(root, 7200):
            self.assertEqual(run_gates.GATES, executed)
        self.assertIs(run_gates.GATES, original)

    def test_non_debug_test_task_is_rejected(self):
        for flags in (("--release",), ("--profile", "release"), ("--profile=release",)):
            gate = run_gates.Gate("rust-workspace", ("cargo", "test", *flags))
            with self.assertRaises(ValueError):
                release_floor.instrumented_gates((gate,), pathlib.Path("private-root"), 7200)

    def test_entry_points_forward_to_existing_runner_and_strict_sanitizer(self):
        original = run_gates.GATES
        executed = []

        def run():
            self.assertIn("--cache-root", sys.argv)
            self.assertEqual(sys.argv[sys.argv.index("--command-timeout") + 1], "7200")
            executed.extend(run_gates.GATES)
            return 5

        def sanitize():
            self.assertEqual(sys.argv[1], "sanitize-floor")
            self.assertNotIn("--command-timeout", sys.argv)
            self.assertEqual(sys.argv[sys.argv.index("--root") + 1], "private-root")
            self.assertEqual(list(run_gates.GATES), executed)
            return 6

        with mock.patch.object(sys, "argv", ["release_floor", "run", "--cache-root", "private-root",
                                            "--command-timeout", "7200", "--repo", "checkout"]), \
                mock.patch.object(run_gates, "main", side_effect=run):
            self.assertEqual(release_floor.main(), 5)
        self.assertIs(run_gates.GATES, original)
        with mock.patch.object(sys, "argv", ["release_floor", "sanitize-floor", "--root", "private-root",
                                            "--command-timeout", "7200", "--repo", "checkout"]), \
                mock.patch.object(release_floor.ci_floor, "main", side_effect=sanitize):
            self.assertEqual(release_floor.main(), 6)
        self.assertIs(run_gates.GATES, original)


class FloorEnvironmentTests(CheckoutFixture):
    def test_stripped_floor_environment_gets_directory_only_in_test_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            floor_env = run_gates.build_task_env(root, {"XTRACE_CI_DIAG_DIR": "ambient-value"},
                                                scratch=root / "tmp", home=root / "home")
            self.assertNotIn("XTRACE_CI_DIAG_DIR", floor_env)
            for command in (["cargo", "test"], ["cargo", "build", "--release"], ["cargo", "package"]):
                with self.subTest(command=command):
                    args = argparse.Namespace(suite="rust", variant="-", step="floor", out=str(root / "frag"),
                                              private_log_dir=temporary, ci_diagnostics=True, command=command,
                                              cwd="", timeout=7200, min_passed=0, max_ignored=-1, canaries="")
                    captured = {}

                    def run(cmd, *, log=None, stdout=None, env, observations=None, **kwargs):
                        captured.update(env)
                        output = log if log is not None else stdout
                        output.write(b"test fails ... FAILED\n")
                        if cmd[1] == "test":
                            directory = pathlib.Path(env["XTRACE_CI_DIAG_DIR"])
                            self.assertTrue(directory.is_relative_to(root / "frag"))
                            path = directory / "private-storage.jsonl"
                            path.write_text(json.dumps(self.diagnostic()) + "\n")
                            path.chmod(0o600)
                            return subprocess.CompletedProcess(cmd, 101), False, observations.finish(1, False)
                        self.assertNotIn("XTRACE_CI_DIAG_DIR", env)
                        return subprocess.CompletedProcess(cmd, 101)

                    public = io.StringIO()
                    with mock.patch.dict(os.environ, floor_env, clear=True), \
                            mock.patch.object(lane_run.rust_timing, "run", side_effect=run), \
                            mock.patch.object(lane_run.subprocess, "run", side_effect=run), \
                            contextlib.redirect_stdout(public):
                        rc = lane_run.cmd_run(args)
                    self.assertEqual(rc, 101)
                    self.assertEqual("XTRACE_CI_DIAG_DIR" in captured, command[1] == "test")
                    fragment = json.loads((root / "frag/rust__-__floor.json").read_text())
                    rows = fragment["failureDetails"].get("observedDiagnostics", [])
                    if command[1] == "test":
                        self.assertEqual(rows, [{"test": "fails", "relevance": "unknown",
                                                 "category": ["Admission", "Deadline"]}])
                        logged = [json.loads(line.removeprefix("lane observed-diagnostic "))
                                  for line in public.getvalue().splitlines() if line.startswith("lane observed-diagnostic ")]
                        self.assertEqual(logged, rows)
                    else:
                        self.assertEqual(rows, [])
                    self.assertNotIn("ambient-value", json.dumps(fragment))
                    self.assertNotIn("ambient-value", public.getvalue())


if __name__ == "__main__":
    unittest.main()
