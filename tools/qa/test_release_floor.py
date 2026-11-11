import argparse
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from tools.qa import lane_run, release_floor
from tools.qa.test_lane_run import CheckoutFixture
from tools.release import run_gates
from tools.release.test_release_tools import own_process_snapshot


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
        original_run = run_gates._run
        root = pathlib.Path("private-root")
        with release_floor.configured_floor(root, 7200):
            executed = run_gates.GATES
            self.assertEqual(release_floor.ci_floor.run_gates.GATES, executed)
        self.assertIs(run_gates.GATES, original)
        self.assertIs(run_gates._run, original_run)
        with release_floor.configured_floor(root, 7200):
            self.assertEqual(run_gates.GATES, executed)
        self.assertIs(run_gates.GATES, original)
        self.assertIs(run_gates._run, original_run)

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


class FloorSupervisorTests(unittest.TestCase):
    def private_temporary_directory(self):
        # _run admits every log ancestor; a 0700 leaf under /tmp still fails.
        # Do not depend on the private TMPDIR supplied only by PR CI's dev tests.
        # The owned checkout is the fallback when no scratch root is configured.
        return tempfile.TemporaryDirectory(
            dir=os.environ.get("XTRACE_TEST_SCRATCH_ROOT") or pathlib.Path(__file__).resolve().parents[2])

    def test_wrapper_timeout_preserves_its_completed_fragment(self):
        with self.private_temporary_directory() as temporary:
            root = pathlib.Path(temporary)
            shim = root / "bin"
            shim.mkdir(mode=0o700)
            cargo = shim / "cargo"
            cargo.write_text(f"#!{sys.executable}\nimport signal\nsignal.pause()\n")
            cargo.chmod(0o700)
            gate = run_gates.Gate("rust-workspace", ("cargo", "test", "--locked"))
            fragment_path = root / "frag/rust__-__rust-workspace.json"
            original_run = run_gates._run
            completed = {}

            def capture_completed(argv, **kwargs):
                result = original_run(argv, **kwargs)
                self.assertEqual(result[0], 124)
                self.assertEqual(kwargs["outcome_report"], {"timed_out": False})
                completed["fragment"] = fragment_path.read_bytes()
                return result

            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_run", side_effect=capture_completed), \
                    mock.patch.object(run_gates, "_process_snapshot", side_effect=own_process_snapshot()), \
                    mock.patch.object(lane_run, "recover_timeout", wraps=lane_run.recover_timeout) as recovery, \
                    release_floor.configured_floor(root, 0):
                # Expire the wrapper's timer immediately; the outer supervisor
                # keeps a bounded safety budget and observes the wrapper's return.
                code, _ = run_gates._run(list(run_gates.GATES[0].argv),
                                         cwd=pathlib.Path(__file__).resolve().parents[2],
                                         env={**os.environ, "PATH": str(shim) + os.pathsep + os.environ["PATH"]},
                                         timeout=10, log_path=root / "supervisor.log")
            self.assertEqual(code, 124)
            recovery.assert_not_called()
            self.assertEqual(fragment_path.read_bytes(), completed["fragment"])
            fragment = json.loads(completed["fragment"])
            self.assertEqual((fragment["status"], fragment["exitCode"], fragment["timedOut"]), ("fail", 124, True))
            self.assertNotIn("wallObservation", fragment["rustTiming"])

    def test_outer_timeout_publishes_completed_active_and_diagnostic_observations(self):
        """Exercise real _run termination, with lane_run's own deadline still pending."""
        metadata = lane_run._checkout_metadata()
        name = "admission::tests::an_expired_deadline_refuses_before_any_probe"
        waiting = "admission::tests::an_expired_deadline_inside_a_live_scope_refuses_before_any_probe"
        self.assertIn(name, metadata.rust_tests)
        self.assertIn(waiting, metadata.rust_tests)
        crate = "xtrace_domain"
        output = (f"    Finished `test` profile [unoptimized] target(s) in 0.01s\n"
                  f"     Running unittests src/lib.rs (target/debug/deps/{crate}-0123456789abcdef)\n"
                  f"test {name} ... FAILED\n"
                  "test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured\n"
                  f"   Doc-tests {crate}\n"
                  f"test {waiting} ...\n"
                  "captured-value-731\n")
        record = {"thread": name, "error": "Admission", "operation": "Deadline", "kind": None, "errno": None}
        with self.private_temporary_directory() as temporary:
            root = pathlib.Path(temporary)
            shim = root / "bin"
            shim.mkdir(mode=0o700)
            cargo = shim / "cargo"
            cargo.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, signal\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "directory = pathlib.Path(os.environ['XTRACE_CI_DIAG_DIR'])\n"
                f"records = [{record!r}, {{**{record!r}, 'error': 'captured-value-731'}}]\n"
                "with os.fdopen(os.open(directory / 'private-storage.jsonl', "
                "os.O_WRONLY | os.O_CREAT, 0o600), 'w') as stream:\n"
                "    stream.write(''.join(json.dumps(row) + '\\n' for row in records))\n"
                f"os.write(1, {output.encode()!r})\n"
                "signal.pause()\n")
            cargo.chmod(0o700)
            gate = run_gates.Gate("rust-workspace", ("cargo", "test", "--locked"))
            snapshot = own_process_snapshot()
            scans = 0
            expired = False
            ready_at_timeout = False
            started = time.monotonic()

            def scoped_snapshot(**kwargs):
                nonlocal scans
                scans += 1
                return snapshot(**kwargs)

            def monotonic():
                nonlocal expired, ready_at_timeout
                now = time.monotonic()
                # _run sets its deadline before the first post-spawn snapshot.
                # Advance only that supervisor clock after observable evidence;
                # the child wrapper keeps its real 7200-second timer.
                if scans >= 2 and not expired:
                    for path in root.glob("lane-recovery-*/timing.json"):
                        checkpoint = json.loads(path.read_text())
                        state = checkpoint["state"]
                        if len(state["events"]) == 3 and state["active"] is not None:
                            ready_at_timeout = True
                            expired = True
                    expired |= now - started >= 10  # bounded failure if initialization breaks
                return now + (7201 if expired else 0)

            public = io.StringIO()
            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_process_snapshot", side_effect=scoped_snapshot), \
                    mock.patch.object(run_gates, "time", SimpleNamespace(monotonic=monotonic, sleep=time.sleep)), \
                    release_floor.configured_floor(root, 7200), contextlib.redirect_stdout(public):
                argv = list(run_gates.GATES[0].argv)
                code, _ = run_gates._run(argv, cwd=pathlib.Path(__file__).resolve().parents[2],
                                         env={**os.environ, "PATH": str(shim) + os.pathsep + os.environ["PATH"]},
                                         timeout=7200, log_path=root / "supervisor.log")
            self.assertTrue(ready_at_timeout)
            self.assertEqual(code, 124)
            self.assertIn("owned process tree drained", (root / "supervisor.log").read_text())
            fragment = json.loads((root / "frag/rust__-__rust-workspace.json").read_text())
            self.assertEqual((fragment["status"], fragment["exitCode"], fragment["timedOut"]), ("fail", 124, True))
            self.assertEqual(fragment["passed"], 3)
            timing = fragment["rustTiming"]
            self.assertEqual(timing["wallObservation"], "cargo-start-to-supervisor-cleanup")
            self.assertEqual([row["event"] for row in timing["events"]], ["start", "completion", "start"])
            self.assertEqual(timing["events"][1]["observation"], "libtest-result")
            active = timing["runningAtTimeout"][0]
            self.assertEqual(active["binary"], {"crate": "xtrace-domain", "targetKind": "doctest",
                                                "targetName": crate})
            self.assertFalse(active["harnessResultObserved"])
            self.assertEqual(active["processExit"], "not-observed")
            self.assertEqual(fragment["failureDetails"]["timeout"]["runningTests"], [waiting.rsplit("::", 1)[-1]])
            self.assertEqual(fragment["failureDetails"]["observedDiagnostics"], [
                {"test": name, "relevance": "unknown", "category": ["Admission", "Deadline"]}])
            for text in (json.dumps(fragment), public.getvalue()):
                self.assertNotIn("captured-value-731", text)
                self.assertNotIn("target/debug", text)
                self.assertNotIn(str(root), text)
            self.assertEqual(list((root / "frag").glob("*.json")), [root / "frag/rust__-__rust-workspace.json"])


class FloorRecoveryValidationTests(CheckoutFixture):
    def test_startup_or_broken_checkpoint_timeout_still_validates_available_diagnostics(self):
        for checkpoint in (None, b'{"started":', b"[]", b"x" * (lane_run.MAX_TIMING_CHECKPOINT_BYTES + 1)):
            with self.subTest(checkpoint_bytes=None if checkpoint is None else len(checkpoint)):
                directory = lane_run.prepare_recovery(self.checkout)
                if checkpoint is not None:
                    (directory / "timing.json").write_bytes(checkpoint)
                (directory / "output.log").write_text("test fails ... FAILED\ncaptured-value-731\n")
                diagnostic = directory / "diagnostics/private-storage.jsonl"
                diagnostic.write_text(json.dumps(self.diagnostic()) + "\n"
                                      + json.dumps(self.diagnostic(operation="captured-value-731")) + "\n")
                diagnostic.chmod(0o600)
                args = argparse.Namespace(suite="rust", variant="-", step="rust-workspace",
                                          command=["--", "cargo", "test"], out=str(self.checkout / "frag"),
                                          min_passed=0, cwd="", canaries="")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(lane_run.recover_timeout(args, directory, self.metadata, 7200), 124)
                fragment = json.loads((self.checkout / "frag/rust__-__rust-workspace.json").read_text())
                self.assertTrue(fragment["timedOut"])
                self.assertEqual(fragment["rustTiming"]["events"], [])
                self.assertEqual(fragment["rustTiming"]["runningAtTimeout"], [])
                self.assertIsNone(fragment["rustTiming"]["compilationFinishedSeconds"])
                self.assertEqual(fragment["failureDetails"]["observedDiagnostics"], [
                    {"test": "fails", "relevance": "unknown", "category": ["Admission", "Deadline"]}])
                self.assertNotIn("captured-value-731", json.dumps(fragment))
                args.canaries = str(self.checkout / "missing-canaries")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(lane_run.recover_timeout(args, directory, self.metadata, 7200), 124)
                fragment = json.loads((self.checkout / "frag/rust__-__rust-workspace.json").read_text())
                self.assertIsNone(fragment["failureDetails"])
                self.assertEqual(fragment["failureDetailsUnavailable"], lane_run.WITHHELD)


if __name__ == "__main__":
    unittest.main()
