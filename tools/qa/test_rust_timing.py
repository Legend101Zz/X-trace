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

from tools.qa import lane_run, rust_timing


SOURCES = {
    "crates/example/Cargo.toml": '[package]\nname = "example-crate"\n',
    "crates/example/src/lib.rs": "pub fn example() {}\n",
    "crates/example/tests/journey.rs": "#[test]\nfn fails() {}\n",
}
LIB = "     Running unittests src/lib.rs (target/debug/deps/example_crate-0123456789abcdef)"
JOURNEY = "     Running tests/journey.rs (target/debug/deps/journey-fedcba9876543210)"
FINISHED = "    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.00s"
OK = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"
FAILED = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"


def observations(sources=None, private=lambda value: False):
    return rust_timing.Observations(rust_timing.checkout_targets(SOURCES if sources is None else sources), private)


class TimingTests(unittest.TestCase):
    def test_compile_execution_failure_and_doctests_are_distinct_observations(self):
        observed = observations()
        for wall, line in ((2, FINISHED), (3, LIB), (7, OK), (8, JOURNEY), (13, FAILED),
                           (14, "   Doc-tests example_crate"), (15, OK)):
            observed.line(line, wall)
        result = observed.finish(16, False)
        self.assertEqual(result["compilationFinishedSeconds"], 2)
        self.assertEqual(result["compilationObservation"], "cargo-finished")
        self.assertEqual(result["executionStartedSeconds"], 3)
        self.assertEqual(result["executionElapsedSeconds"], 13)
        self.assertEqual(result["runningAtTimeout"], [])
        self.assertEqual([row["event"] for row in result["events"]], ["start", "completion"] * 3)
        completions = result["events"][1::2]
        self.assertEqual([row["elapsedSeconds"] for row in completions], [4, 5, 1])
        self.assertEqual([row["binary"]["targetKind"] for row in completions], ["lib", "test", "doctest"])
        self.assertTrue(all(row["binary"]["crate"] == "example-crate" for row in completions))
        self.assertTrue(all(row["observation"] == "libtest-result" for row in completions))

    def test_timeout_names_the_active_binary_even_without_a_test_name(self):
        observed = observations()
        observed.line(FINISHED, 2)
        observed.line(LIB, 3)
        observed.line(OK, 4)
        observed.line(JOURNEY, 5)
        result = observed.finish(3000, True)
        self.assertEqual(result["runningAtTimeout"], [{
            "binary": {"crate": "example-crate", "targetKind": "test", "targetName": "journey"},
            "elapsedSeconds": 2995, "harnessResultObserved": False, "processExit": "not-observed"}])
        self.assertEqual([row["event"] for row in result["events"]], ["start", "completion", "start"])
        self.assertEqual(result["wallSeconds"], 3000)

    def test_compilation_timeout_does_not_invent_a_binary_or_execution_time(self):
        result = observations().finish(3000, True)
        self.assertEqual(result["events"], [])
        self.assertEqual(result["runningAtTimeout"], [])
        self.assertIsNone(result["compilationFinishedSeconds"])
        self.assertIsNone(result["executionStartedSeconds"])
        self.assertIsNone(result["executionElapsedSeconds"])
        self.assertEqual(result["executionObservation"], "not-observed")

    def test_timeout_keeps_identity_when_the_harness_printed_a_result_but_cargo_has_not_advanced(self):
        observed = observations()
        observed.line(JOURNEY, 1)
        observed.line(OK, 2)
        result = observed.finish(3000, True)
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["runningAtTimeout"][0]["binary"]["targetName"], "journey")
        self.assertTrue(result["runningAtTimeout"][0]["harnessResultObserved"])
        self.assertEqual(result["runningAtTimeout"][0]["processExit"], "not-observed")

    def test_missing_compilation_boundary_and_crashed_harness_are_explicit(self):
        observed = observations()
        observed.line(LIB, 2)
        observed.line(JOURNEY, 4)
        result = observed.finish(5, False)
        self.assertIsNone(result["compilationFinishedSeconds"])
        self.assertEqual(result["compilationObservation"], "not-observed")
        self.assertEqual([row.get("observation") for row in result["events"] if row["event"] == "completion"],
                         ["next-cargo-target-upper-bound", "cargo-exit-upper-bound"])

    def test_unverified_paths_names_collisions_and_canaries_are_withheld(self):
        duplicate = {**SOURCES, "crates/other/Cargo.toml": '[package]\nname = "other"\n',
                     "crates/other/tests/journey.rs": "#[test]\nfn example() {}\n"}
        cases = [(SOURCES, LIB.replace("example_crate-", "customer731-"), lambda value: False),
                 (SOURCES, LIB.replace("src/lib.rs", "captured/value.rs"), lambda value: False),
                 ({}, LIB, lambda value: False), (duplicate, JOURNEY, lambda value: False),
                 (SOURCES, JOURNEY, lambda value: value == "journey")]
        for sources, line, private in cases:
            with self.subTest(line=line):
                observed = observations(sources, private)
                observed.line(line, 1)
                result = observed.finish(3000, True)
                self.assertEqual(result["unverifiedBinaries"], 1)
                self.assertEqual(result["events"][0]["binary"], lane_run.UNVERIFIED)
                self.assertEqual(result["runningAtTimeout"][0]["binary"], lane_run.UNVERIFIED)
                public = json.dumps(result)
                for captured in ("customer731", "captured/value", "journey", "example_crate", "target/debug"):
                    self.assertNotIn(captured, public)

    def test_explicit_and_conventional_targets_include_cargo_kind_and_name(self):
        sources = {**SOURCES,
                   "crates/cli/Cargo.toml": '[package]\nname = "cli"\n[[bin]]\nname = "command"\npath = "src/main.rs"\n',
                   "crates/cli/src/main.rs": "fn main() {}\n",
                   "crates/example/tests/nested/main.rs": "fn main() {}\n"}
        targets = rust_timing.checkout_targets(sources)
        self.assertIn(rust_timing.Target("cli", "bin", "command", "src/main.rs"), targets)
        self.assertIn(rust_timing.Target("example-crate", "test", "nested", "tests/nested/main.rs"), targets)
        self.assertNotIn(rust_timing.Target("cli", "bin", "cli", "src/main.rs"), targets)
        observed = rust_timing.Observations(targets, lambda value: False)
        observed.line(" Running unittests src/main.rs (target/debug/deps/command-0123456789abcdef)", 1)
        self.assertEqual(observed.events[0]["binary"], {"crate": "cli", "targetKind": "bin", "targetName": "command"})

    def test_event_limit_keeps_the_active_timeout_target(self):
        observed = observations()
        with mock.patch.object(rust_timing, "MAX_EVENTS", 2):
            observed.line(LIB, 1)
            observed.line(OK, 2)
            observed.line(JOURNEY, 3)
        result = observed.finish(3000, True)
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["eventsOmitted"], 1)
        self.assertEqual(result["runningAtTimeout"][0]["binary"]["targetName"], "journey")

    def test_real_pipe_preserves_order_counts_exit_code_and_private_output(self):
        text = "\n".join((FINISHED, LIB, "captured-value-731", OK, JOURNEY, FAILED)) + "\n"
        command = [sys.executable, "-B", "-c", f"import os; os.write(1, {text.encode()!r}); raise SystemExit(101)"]
        with tempfile.TemporaryFile() as log:
            proc, timed_out, result = rust_timing.run(command, log=log, cwd=None, env=os.environ.copy(),
                                                    timeout=60, observations=observations())
            log.seek(0)
            raw = log.read().decode()
        self.assertEqual(proc.returncode, 101)
        self.assertFalse(timed_out)
        self.assertEqual(raw, text)
        self.assertEqual(lane_run.parse_output(raw)["passed"], 3)
        self.assertEqual(lane_run.parse_output(raw)["failed"], 1)
        self.assertEqual(len(result["events"]), 4)
        self.assertNotIn("captured-value-731", json.dumps(result))

    def test_one_deadline_covers_compilation_and_execution_without_waiting(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, (FINISHED + "\n" + JOURNEY + "\n").encode())
        os.close(write_fd)
        observed = observations()
        now = [0]
        original_line = observed.line

        def line(text, wall):
            original_line(text, wall)
            if text == JOURNEY:
                now[0] = 3000

        observed.line = line
        child = mock.MagicMock()
        child.__enter__.return_value = child
        child.poll.return_value = None
        child.wait.return_value = -9
        with os.fdopen(read_fd, "rb") as stream, tempfile.TemporaryFile() as log:
            child.stdout = stream
            with mock.patch.object(rust_timing.subprocess, "Popen", return_value=child), \
                    mock.patch.object(rust_timing.time, "monotonic", side_effect=lambda: now[0]):
                proc, timed_out, result = rust_timing.run(["cargo", "test"], log=log, cwd=None, env={},
                                                        timeout=3000, observations=observed)
        child.kill.assert_called_once_with()
        self.assertEqual(proc.returncode, 124)
        self.assertTrue(timed_out)
        self.assertEqual(result["runningAtTimeout"][0]["binary"]["targetName"], "journey")
        self.assertEqual(result["wallSeconds"], 3000)

    def test_head_metadata_rejects_staged_and_untracked_target_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name, source in SOURCES.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_COMMITTER_NAME": "Fixture",
                   "GIT_AUTHOR_EMAIL": "fixture@example.test", "GIT_COMMITTER_EMAIL": "fixture@example.test"}
            for command in (("init",), ("add", "."), ("commit", "-m", "Fixture")):
                subprocess.run(["git", "-C", temporary, *command], env=env, check=True, capture_output=True)
            manifest = root / "crates/example/Cargo.toml"
            manifest.write_text('[package]\nname = "captured731"\n')
            subprocess.run(["git", "-C", temporary, "add", "."], env=env, check=True, capture_output=True)
            (root / "crates/example/tests/captured731.rs").write_text("fn main() {}\n")
            with mock.patch.object(lane_run, "__file__", str(root / "tools/qa/lane_run.py")):
                metadata = lane_run._checkout_metadata()
            observed = rust_timing.Observations(metadata.rust_targets, lambda value: False)
            observed.line(JOURNEY, 1)
            observed.line(JOURNEY.replace("journey", "captured731"), 2)
            public = json.dumps(observed.finish(3000, True))
            self.assertIn("example-crate", public)
            self.assertNotIn("captured731", public)


class FragmentTimingTests(unittest.TestCase):
    def test_unverified_binary_is_withheld_from_both_fragment_and_job_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(suite="rust", variant="-", step="test", out=temporary,
                                      private_log_dir=temporary, command=["cargo", "test"], cwd="",
                                      timeout=3000, min_passed=0, max_ignored=0, canaries="")

            def run(command, *, log, observations, **kwargs):
                line = JOURNEY.replace("journey", "customer731")
                log.write((line + "\n").encode())
                observations.line(line, 1)
                return subprocess.CompletedProcess(command, 124), True, observations.finish(3000, True)

            public = io.StringIO()
            with mock.patch.object(lane_run, "_checkout_metadata", return_value=lane_run.CheckoutMetadata(SOURCES)), \
                    mock.patch.object(rust_timing, "run", side_effect=run), contextlib.redirect_stdout(public):
                self.assertEqual(lane_run.cmd_run(args), 124)
            fragment = json.loads((pathlib.Path(temporary) / "rust__-__test.json").read_text())
            self.assertEqual(fragment["rustTiming"]["unverifiedBinaries"], 1)
            self.assertEqual(fragment["rustTiming"]["runningAtTimeout"][0]["binary"], lane_run.UNVERIFIED)
            self.assertNotIn("customer731", json.dumps(fragment))
            self.assertNotIn("customer731", public.getvalue())
            self.assertNotIn("target/debug", public.getvalue())

    def test_fragment_and_job_log_share_rows_on_success_failure_and_timeout(self):
        for code, timed_out in ((0, False), (101, False), (124, True)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                args = argparse.Namespace(suite="rust", variant="-", step="test", out=str(root / "frag"),
                                          private_log_dir=temporary, command=["cargo", "test", "--locked", "--workspace",
                                          "--all-features", "--no-fail-fast"], cwd="", timeout=3000,
                                          min_passed=0 if timed_out else 1, max_ignored=0, canaries="")

                def run(command, *, log, observations, timeout, **kwargs):
                    self.assertEqual(command, args.command)
                    self.assertEqual(timeout, 3000)
                    for wall, line in ((2, FINISHED), (3, JOURNEY)):
                        log.write((line + "\n").encode())
                        observations.line(line, wall)
                    if not timed_out:
                        result = OK if code == 0 else FAILED
                        log.write((result + "\n").encode())
                        observations.line(result, 7)
                    return subprocess.CompletedProcess(command, code), timed_out, observations.finish(3000 if timed_out else 8, timed_out)

                public = io.StringIO()
                with mock.patch.object(lane_run, "_checkout_metadata", return_value=lane_run.CheckoutMetadata(SOURCES)), \
                        mock.patch.object(rust_timing, "run", side_effect=run), contextlib.redirect_stdout(public):
                    rc = lane_run.cmd_run(args)
                fragment = json.loads((root / "frag/rust__-__test.json").read_text())
                self.assertEqual(rc, code)
                self.assertEqual(fragment["status"], "pass" if code == 0 else "fail")
                timing = fragment["rustTiming"]
                logged = [json.loads(line.removeprefix("lane rust-binary ")) for line in public.getvalue().splitlines()
                          if line.startswith("lane rust-binary ")]
                self.assertEqual(logged, timing["events"])
                running = [json.loads(line.removeprefix("lane rust-timeout ")) for line in public.getvalue().splitlines()
                           if line.startswith("lane rust-timeout ")]
                self.assertEqual(running, timing["runningAtTimeout"])
                self.assertNotIn("target/debug", public.getvalue())


if __name__ == "__main__":
    unittest.main()
