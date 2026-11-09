import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.qa import lane_run  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_cargo_failures_are_allowlisted(self):
        text = "\n".join([
            "test a::b::ok ... ok",
            "test a::b::bad ... FAILED",
            "test weird name with /home/x/secret ... FAILED",
            "test result: FAILED. 3 passed; 2 failed; 1 ignored; 0 measured",
        ])
        r = lane_run.parse_output(text)
        self.assertEqual(r["failingTests"], ["a::b::bad"])
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (3, 2, 1))

    def test_unittest_counts(self):
        r = lane_run.parse_output("Ran 23 tests in 0.2s\n\nFAILED (failures=2, errors=1)")
        self.assertEqual((r["passed"], r["failed"]), (20, 3))
        r = lane_run.parse_output("Ran 5 tests in 0.2s\n\nOK")
        self.assertEqual((r["passed"], r["failed"]), (5, 0))

    def test_gradle_failure_name(self):
        r = lane_run.parse_output("com.example.FooTest > doesThing() FAILED")
        self.assertEqual(r["failingTests"], ["FooTest::doesThing"])

    def test_invalid_names_dropped_and_counted(self):
        r = lane_run.parse_output("test ../../etc/passwd ... FAILED")
        self.assertEqual(r["failingTests"], [])
        self.assertEqual(r["droppedInvalidNames"], 1)

    def test_truncation(self):
        text = "\n".join(f"test t::n{i} ... FAILED" for i in range(40))
        r = lane_run.parse_output(text)
        self.assertEqual(len(r["failingTests"]), 32)
        self.assertEqual(r["failingTruncated"], 8)


class FailureDetailsTests(unittest.TestCase):
    @staticmethod
    def cargo(name="journey::fails", message="assertion `left == right` failed\n  left: 1\n right: 2"):
        return (f"test {name} ... FAILED\n\nfailures:\n\n---- {name} stdout ----\n"
                f"thread '{name}' panicked at crates/example/tests/journey.rs:42:7:\n"
                f"{message}\nnote: run with RUST_BACKTRACE=1\n\nfailures:\n    {name}\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored\n")

    def test_cargo_captured_failure_has_name_location_and_first_assertion_lines(self):
        detail = lane_run.failure_details(self.cargo(), False)
        self.assertEqual(detail["failures"], [{
            "test": "journey::fails", "location": "crates/example/tests/journey.rs:42:7",
            "message": ["assertion `left == right` failed", "left: 1", "right: 2"], "truncated": False,
        }])

    def test_cargo_nocapture_panics_are_associated_with_their_own_tests(self):
        text = ("unrelated stdout\n"
                "thread 'first' panicked at crates/a.rs:1:2:\nfirst assertion\n"
                "test first ... FAILED\n"
                "thread 'second' panicked at crates/b.rs:3:4:\nsecond assertion\n"
                "test second ... FAILED\n")
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual([r["message"] for r in rows], [["first assertion"], ["second assertion"]])
        self.assertNotIn("unrelated", json.dumps(rows))

    def test_gradle_full_and_short_failure_formats(self):
        for exception in ("org.opentest4j.AssertionFailedError: expected: <200> but was: <500>",
                          "java.lang.AssertionError: expected status 200"):
            text = ("  com.example.HttpTest > finalStatus() FAILED\n"
                    f"    {exception}\n"
                    "        at org.junit.AssertionFailureBuilder.build(AssertionFailureBuilder.java:100)\n"
                    "        at com.example.HttpTest.finalStatus(HttpTest.java:81)\n"
                    "> Task :agent:test FAILED\n")
            with self.subTest(exception=exception):
                rows = lane_run.failure_details(text, False)["failures"]
                self.assertEqual(rows, [{"test": "HttpTest::finalStatus", "location": "HttpTest.java:81",
                                         "message": [exception], "truncated": False}])
        text = ("HttpTest > finalStatus() FAILED\n"
                "    org.opentest4j.AssertionFailedError at HttpTest.java:81\n")
        self.assertEqual(lane_run.failure_details(text, False)["failures"][0]["location"], "HttpTest.java:81")

    def test_backtrace_is_excluded_and_secondary_capture_does_not_erase_message(self):
        text = ("test fails ... FAILED\n---- fails stdout ----\n"
                "thread 'fails' panicked at crates/a.rs:1:2:\nfirst assertion\n"
                "stack backtrace:\n0: irrelevant stack\n"
                "---- fails stderr ----\nother output\n")
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assertEqual(row["message"], ["first assertion"])
        self.assertEqual(row["location"], "crates/a.rs:1:2")

    def test_captured_worker_panic_belongs_to_the_harness_test_section(self):
        text = ("test journey ... FAILED\n---- journey stdout ----\n"
                "thread 'worker' panicked at crates/a.rs:1:2:\nworker assertion\n")
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assertEqual(row["test"], "journey")
        self.assertEqual(row["message"], ["worker assertion"])

    def test_unsafe_panic_location_is_never_published_as_a_source_site(self):
        text = self.cargo().replace("crates/example/tests/journey.rs", "../escape.rs")
        self.assertEqual(lane_run.failure_details(text, False)["failures"][0]["location"], "not observed")

    def test_missing_failure_output_is_named_as_not_observed(self):
        row = lane_run.failure_details("test missing ... FAILED\n", False)["failures"][0]
        self.assertEqual(row["location"], "not observed")
        self.assertEqual(row["message"], ["not observed"])

    def test_per_test_line_and_serialized_byte_caps(self):
        messages = ("\n".join(f"assertion line {i}" for i in range(30)), "é" * 10000)
        for message in messages:
            with self.subTest(message_length=len(message)):
                row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
                self.assertLessEqual(len(row["message"]), lane_run.MAX_EXCERPT_LINES)
                self.assertLessEqual(len(lane_run._encoded(row)), lane_run.MAX_EXCERPT_BYTES)
                self.assertTrue(row["truncated"])
                self.assertTrue(row["message"][0])

    def test_job_cap_and_omitted_count(self):
        text = "".join(self.cargo(name=f"case{i}", message="x" * 3000) for i in range(32))
        detail = lane_run.failure_details(text, False)
        self.assertLessEqual(len(lane_run._encoded(detail)), lane_run.MAX_JOB_EXCERPT_BYTES)
        self.assertGreater(detail["omitted"], 0)
        self.assertEqual(len(detail["failures"]) + detail["omitted"], 32)
        self.assertIsNone(lane_run.failure_details(text, False, budget=0))

    def test_canary_anywhere_in_block_withholds_the_whole_excerpt(self):
        text = self.cargo(message="safe assertion\n" + "safe line\n" * 20 + "BODY_CANARY_123")
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assertEqual(row, {"test": "journey::fails", "excerpt": "withheld: privacy scan"})
        self.assertNotIn("safe assertion", json.dumps(row))

    def test_private_canaries_use_existing_scanner_encodings(self):
        values = {"assertion": "synthetic-value-31fe"}
        index = [*lane_run.CANARY_INDEX, *lane_run.canary.build_index(values)]
        for encoding, needle in lane_run.canary.needles(values["assertion"]):
            with self.subTest(encoding=encoding):
                detail = lane_run.failure_details(self.cargo(message=needle.decode()), False, index=index)
                self.assertEqual(detail["failures"][0]["excerpt"], lane_run.WITHHELD)
                self.assertNotIn(needle.decode(), json.dumps(detail))

    def test_paths_credentials_and_terminal_controls_withhold_excerpts(self):
        for value in ("/Users/example/data", "/home/runner/data", "/opt/local/data", "token=123",
                      "Authorization: value", "Cookie: value", "unexpected\x00value"):
            with self.subTest(value=value):
                row = lane_run.failure_details(self.cargo(message=value), False)["failures"][0]
                self.assertEqual(row["excerpt"], lane_run.WITHHELD)

    def test_syntactically_valid_canary_test_id_is_withheld(self):
        detail = lane_run.failure_details(self.cargo(name="BODY_CANARY"), False)
        self.assertEqual(detail["failures"], [{"excerpt": lane_run.WITHHELD}])

    def test_timeout_tracks_only_unfinished_observed_tests_and_safe_progress(self):
        text = ("running 4 tests\n"
                "test completed ...\ntest completed ... ok\n"
                "test waiting has been running for over 60 seconds\n"
                "test also_waiting ...\n"
                "test BODY_CANARY has been running for over 60 seconds\n"
                "unstructured output with private data\n"
                "Compiling secret token=123\n")
        detail = lane_run.failure_details(text, True)
        timeout = detail["timeout"]
        self.assertEqual(timeout["runningTests"], ["waiting", "also_waiting"])
        self.assertEqual(timeout["runningOmitted"], 1)
        self.assertEqual(timeout["progressWithheld"], 2)
        rendered = json.dumps(detail)
        for value in ("BODY_CANARY", "token=123", "unstructured output"):
            self.assertNotIn(value, rendered)
        self.assertNotIn("timeout", lane_run.failure_details(text, False))

    def test_timeout_progress_keeps_last_n_safe_harness_lines(self):
        lines = [f"test case{i} ... ok" for i in range(30)]
        timeout = lane_run.failure_details("\n".join(lines), True)["timeout"]
        self.assertEqual(timeout["progress"], lines[-lane_run.MAX_PROGRESS_LINES:])
        self.assertEqual(timeout["progressOmitted"], 30 - lane_run.MAX_PROGRESS_LINES)
        self.assertEqual(timeout["runningTests"], [])

    def test_timeout_job_cap_preserves_running_names_before_progress(self):
        text = "\n".join(["test waiting has been running for over 60 seconds",
                          *["Finished " + "x" * 1000 for _ in range(20)]])
        detail = lane_run.failure_details(text, True, budget=800)
        self.assertLessEqual(len(lane_run._encoded(detail)), 800)
        self.assertEqual(detail["timeout"]["runningTests"], ["waiting"])
        self.assertEqual(detail["timeout"]["progress"], [])
        self.assertEqual(detail["timeout"]["progressOmitted"], 21)

    def test_timeout_gradle_started_and_completed_and_unknown_tests(self):
        text = ("FooTest > done() STARTED\nFooTest > done() PASSED\n"
                "FooTest > waiting() STARTED\n")
        timeout = lane_run.failure_details(text, True)["timeout"]
        self.assertEqual(timeout["runningTests"], ["FooTest::waiting"])
        self.assertIn("not observed", timeout["basis"])
        self.assertEqual(lane_run.failure_details("", True)["timeout"]["runningTests"], [])

    def test_timeout_does_not_retain_running_tests_from_a_finished_binary(self):
        text = ("test old has been running for over 60 seconds\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored\n"
                "running 1 test\n")
        self.assertEqual(lane_run.failure_details(text, True)["timeout"]["runningTests"], [])

    def test_previous_step_fragments_consume_the_same_job_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = pathlib.Path(temporary)
            current = out / "next.json"
            detail = lane_run.failure_details(self.cargo(), False)
            (out / "previous.json").write_text(json.dumps({"failureDetails": detail}))
            current.write_text(json.dumps({"failureDetails": detail}))
            remaining = lane_run._remaining_excerpt_budget(out, current)
            self.assertEqual(remaining, lane_run.MAX_JOB_EXCERPT_BYTES - len(lane_run._encoded(detail)))
            (out / "broken.json").write_text("{")
            self.assertEqual(lane_run._remaining_excerpt_budget(out, current), 0)

    def test_private_canary_file_is_optional_but_requested_missing_file_fails_closed(self):
        self.assertEqual(lane_run._excerpt_index(""), lane_run.CANARY_INDEX)
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "values.json"
            self.assertIsNone(lane_run._excerpt_index(str(path)))
            for value in ({}, [], {"a": 1}, {"a": ""}):
                path.write_text(json.dumps(value))
                self.assertIsNone(lane_run._excerpt_index(str(path)))
            path.write_text(json.dumps({"a": "synthetic-value-31fe"}))
            self.assertGreater(len(lane_run._excerpt_index(str(path))), len(lane_run.CANARY_INDEX))


class MergeTests(unittest.TestCase):
    def merge(self, plan, frags, results=None):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "plan.json").write_text(json.dumps(plan))
            (d / "f").mkdir()
            for i, f in enumerate(frags):
                (d / "f" / f"{i}.json").write_text(json.dumps(f))
            args = type("A", (), {"plan": str(d / "plan.json"), "frag_dir": str(d / "f"),
                                  "out": str(d / "s.json"), "step_summary": "", "job_result": results})()
            rc = lane_run.cmd_merge(args)
            return rc, json.loads((d / "s.json").read_text())

    def frag(self, suite, status="pass", variant="-"):
        return {"suite": suite, "variant": variant, "step": "t", "status": status, "exitCode": 0,
                "passed": 1, "failed": 0, "ignored": 0, "failingTests": [], "failingTruncated": 0,
                "droppedInvalidNames": 0}

    def test_missing_result_is_not_pass(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}, "tui": {"status": "absent"}}}
        rc, s = self.merge(plan, [])
        self.assertEqual(rc, 1)
        self.assertEqual(s["suites"][0]["variants"][0]["status"], "no-result")
        self.assertEqual(s["suites"][1]["status"], "absent")

    def test_pass_and_skip(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}, "java": {"status": "skipped-by-filter"}}}
        rc, s = self.merge(plan, [self.frag("meta")])
        self.assertEqual(rc, 0)
        self.assertEqual([x["status"] for x in s["suites"]], ["pass", "skipped-by-filter"])

    def test_all_java_variants_required(self):
        plan = {"mode": "x", "suites": {"java": {"status": "selected"}}}
        rc, _ = self.merge(plan, [self.frag("java", variant="17"), self.frag("java", variant="21")])
        self.assertEqual(rc, 1)

    def test_failed_job_result_fails_suite(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}}}
        rc, _ = self.merge(plan, [self.frag("meta")], ["meta=failure"])
        self.assertEqual(rc, 1)

    def test_forced_absent_suite_fails(self):
        plan = {"mode": "x", "suites": {"tui": {"status": "absent", "forced": True}}}
        rc, s = self.merge(plan, [])
        self.assertEqual(rc, 1)
        self.assertEqual(s["suites"][0]["status"], "fail")

    def test_missing_plan_emits_failing_summary(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            args = type("A", (), {"plan": str(d / "none.json"), "frag_dir": str(d), "out": str(d / "s.json"),
                                  "step_summary": "", "job_result": None})()
            self.assertEqual(lane_run.cmd_merge(args), 1)
            doc = json.loads((d / "s.json").read_text())
            self.assertEqual((doc["overall"], doc["reason"]), ("fail", "plan-unavailable"))
            self.assertIn("headSha", doc)


class RunTests(unittest.TestCase):
    def run_step(self, cmd, min_passed=0, timeout=60, max_ignored=-1, canaries=""):
        with tempfile.TemporaryDirectory() as d:
            args = type("A", (), {"suite": "meta", "variant": "-", "step": "t", "out": d + "/o", "cwd": "",
                                  "timeout": timeout, "min_passed": min_passed, "max_ignored": max_ignored,
                                  "canaries": canaries, "command": ["--"] + cmd})()
            import os
            with mock.patch.dict(os.environ, {"LANE_PRIVATE_LOG_DIR": d}):
                rc = lane_run.cmd_run(args)
            frag = json.loads((pathlib.Path(d) / "o/meta__-__t.json").read_text())
            return rc, frag

    def test_zero_tests_fails_with_min_passed(self):
        rc, frag = self.run_step([sys.executable, "-c", "print('Ran 0 tests in 0.0s')"], 1)
        self.assertNotEqual(rc, 0)
        self.assertEqual(frag["status"], "fail")

    def test_ignored_tests_fail_a_no_skips_step(self):
        out = "test result: ok. 5 passed; 0 failed; 2 ignored; 0 measured"
        rc, frag = self.run_step([sys.executable, "-c", f"print({out!r})"], 1, max_ignored=0)
        self.assertNotEqual(rc, 0)
        self.assertEqual(frag["status"], "fail")
        rc, frag = self.run_step([sys.executable, "-c", f"print({out!r})"], 1, max_ignored=2)
        self.assertEqual((rc, frag["status"]), (0, "pass"))

    def test_panic_sites_keep_only_repo_relative_locations(self):
        text = "\n".join([
            "thread 'a' panicked at crates/x/src/lib.rs:12:5:",
            "thread 'b' panicked at /Users/me/secret/lib.rs:3:1:",
            "thread 'c' panicked at ../escape.rs:3:1:",
            "thread 'd' panicked at crates/x/src/lib.rs:12:9:",
            "boom token=abc"])
        sites, dropped = lane_run.panic_sites(text)
        self.assertEqual(sites, ["crates/x/src/lib.rs:12"])
        self.assertEqual(dropped, 2)

    def test_timeout_is_a_failed_step_not_a_traceback(self):
        rc, frag = self.run_step([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertEqual(rc, 124)
        self.assertEqual((frag["status"], frag["exitCode"]), ("fail", 124))

    def test_failed_command_writes_scanned_excerpt_only_to_fragment(self):
        import contextlib
        import io
        public = io.StringIO()
        with contextlib.redirect_stdout(public):
            rc, frag = self.run_step([sys.executable, "-c",
                                      f"print({FailureDetailsTests.cargo()!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assertFalse(frag["timedOut"])
        self.assertEqual(frag["failureDetails"]["failures"][0]["message"][0],
                         "assertion `left == right` failed")
        self.assertNotIn("left == right", public.getvalue())
        rc, frag = self.run_step([sys.executable, "-c",
                                  f"print({FailureDetailsTests.cargo(message='BODY_CANARY_123')!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assertEqual(frag["failureDetails"]["failures"][0]["excerpt"], lane_run.WITHHELD)
        self.assertNotIn("BODY_CANARY_123", json.dumps(frag))

    def test_timeout_fragment_uses_output_written_before_timeout(self):
        def timeout(cmd, *, stdout, **kwargs):
            stdout.write(b"test waiting has been running for over 60 seconds\n")
            stdout.flush()
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        with mock.patch.object(lane_run.subprocess, "run", side_effect=timeout):
            rc, frag = self.run_step(["unused-command"], timeout=3000)
        self.assertEqual(rc, 124)
        self.assertTrue(frag["timedOut"])
        self.assertEqual(frag["failureDetails"]["timeout"]["runningTests"], ["waiting"])

    def test_requested_unreadable_canary_file_withholds_all_failure_details(self):
        with tempfile.TemporaryDirectory() as temporary:
            rc, frag = self.run_step([sys.executable, "-c", "raise SystemExit(101)"],
                                      canaries=str(pathlib.Path(temporary) / "missing.json"))
        self.assertEqual(rc, 101)
        self.assertIsNone(frag["failureDetails"])
        self.assertEqual(frag["failureDetailsUnavailable"], lane_run.WITHHELD)

    def test_fragments_share_job_cap_across_failed_steps(self):
        import os
        text = "".join(FailureDetailsTests.cargo(name=f"case{i}", message="x" * 3000) for i in range(32))

        def failed(cmd, *, stdout, **kwargs):
            stdout.write(text.encode())
            return subprocess.CompletedProcess(cmd, 101)

        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.dict(os.environ, {"LANE_PRIVATE_LOG_DIR": temporary}), \
                mock.patch.object(lane_run.subprocess, "run", side_effect=failed):
            args = type("A", (), {"suite": "rust", "variant": "-", "step": "first", "out": temporary + "/o",
                                  "cwd": "", "timeout": 3000, "min_passed": 0, "command": ["unused-command"]})()
            for step in ("first", "second", "third"):
                args.step = step
                self.assertEqual(lane_run.cmd_run(args), 101)
            fragments = [json.loads(p.read_text()) for p in pathlib.Path(args.out).glob("*.json")]
            self.assertEqual(len(fragments), 3)
            self.assertLessEqual(sum(len(lane_run._encoded(f["failureDetails"])) for f in fragments
                                     if f["failureDetails"] is not None), lane_run.MAX_JOB_EXCERPT_BYTES)
            self.assertTrue(any(f.get("failureDetailsUnavailable") == "job excerpt cap" for f in fragments))

    def test_uncounted_step_reports_null(self):
        rc, frag = self.run_step([sys.executable, "-c", "print('hi')"])
        self.assertEqual(rc, 0)
        self.assertIsNone(frag["passed"])
        self.assertNotIn("failureDetails", frag)


class ErrorHintTests(unittest.TestCase):
    def test_allowlisted_codes_and_categories_only(self):
        text = "\n".join([
            'Err(Error { code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource, message: "at /Users/x" })',
            'code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource,',
            'code: ErrorCode("xtr-lower"), category: Bogus,',
            'code: ErrorCode("XTR-/home/me"), category: Internal,',
            'code: ErrorCode("OTHER-1"), category: Policy,',
        ])
        h = lane_run.error_hints(text)
        self.assertEqual(h["errorCodes"], ["XTR-STORE-OBJECT-IO"])
        self.assertEqual(h["errorCategories"], ["Resource", "Internal", "Policy"])
        self.assertEqual(h["droppedInvalid"], 4)

    def test_hints_are_bounded(self):
        text = "\n".join(f'ErrorCode("XTR-E{i}"), category: Internal,' for i in range(40))
        h = lane_run.error_hints(text)
        self.assertEqual(len(h["errorCodes"]), lane_run.MAX_ERROR_HINTS)
        self.assertEqual(h["truncated"], 40 - lane_run.MAX_ERROR_HINTS)

    def test_failing_step_prints_hints_and_never_the_message(self):
        with tempfile.TemporaryDirectory() as d:
            body = ('print("test a::b ... FAILED"); '
                    'print(\'Err(code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource, message: "/Users/me/secret")\'); '
                    'raise SystemExit(101)')
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", "t",
                 "--out", d, "--", sys.executable, "-c", body],
                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("lane error-code XTR-STORE-OBJECT-IO", proc.stdout)
            self.assertIn("lane error-category Resource", proc.stdout)
            self.assertNotIn("/Users", proc.stdout)
            self.assertNotIn("secret", proc.stdout)

    def test_passing_step_prints_no_hints(self):
        with tempfile.TemporaryDirectory() as d:
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", "t",
                 "--out", d, "--", sys.executable, "-c", 'print(\'ErrorCode("XTR-A"), category: Internal,\')'],
                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
            self.assertEqual(proc.returncode, 0)
            self.assertNotIn("error-code", proc.stdout)


class LintTests(unittest.TestCase):
    def test_repo_workflows_pass_lint(self):
        files = [str(p) for p in (ROOT / ".github/workflows").glob("*.yml")]
        r = subprocess.run([sys.executable, "-B", "-m", "tools.qa.workflow_lint", *files], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


class DiagnosticsTests(unittest.TestCase):
    def test_pairs_error_with_location_and_skips_noise(self):
        text = (
            "warning: unused variable: `x`\n  --> crates/a/src/lib.rs:1:1\n"
            "error: this `panic!` should not be used (clippy::panic)\n   --> crates/xtrace-export/tests/export_core.rs:158:21\n"
            "error[E0425]: cannot find value `y` in this scope\n --> crates/b/src/main.rs:9:5\n"
            "error: could not compile `x` (test) due to 2 previous errors\n"
        )
        diags, dropped = lane_run.diagnostics(text)
        self.assertEqual(dropped, 0)
        self.assertEqual(diags, ["error: this `panic!` should not be used (clippy::panic) @ crates/xtrace-export/tests/export_core.rs:158:21",
                                 "error[E0425]: cannot find value `y` in this scope @ crates/b/src/main.rs:9:5"])

    def test_host_paths_and_secrets_are_dropped_and_counted(self):
        text = ("error: boom\n --> /home/runner/work/x/src/lib.rs:1:1\n"
                "error: leaked token abc\n --> src/lib.rs:2:2\n"
                "error: fine\n --> ../escape/src/lib.rs:3:3\n")
        diags, dropped = lane_run.diagnostics(text)
        self.assertEqual(diags, [])
        self.assertEqual(dropped, 3)

    def test_bounded(self):
        text = "".join(f"error: e{i}\n --> src/f.rs:{i}:1\n" for i in range(1, 40))
        diags, dropped = lane_run.diagnostics(text)
        self.assertEqual(len(diags), lane_run.MAX_DIAG)
        self.assertEqual(dropped, 39 - lane_run.MAX_DIAG)


class CountTests(unittest.TestCase):
    def test_node_test_summary_counts(self):
        r = lane_run.parse_output("\u2139 tests 12\n\u2139 pass 11\n\u2139 fail 1\n\u2139 skipped 0")
        self.assertEqual((r["passed"], r["failed"]), (11, 1))

    def test_vitest_summary_counts(self):
        r = lane_run.parse_output("      Tests  2 failed | 40 passed (42)")
        self.assertEqual((r["passed"], r["failed"]), (40, 2))
        r = lane_run.parse_output("      Tests  40 passed (40)")
        self.assertEqual((r["passed"], r["failed"]), (40, 0))
        r = lane_run.parse_output("\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m162 passed\x1b[39m\x1b[22m | 2 skipped\x1b[90m (164)\x1b[39m")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (162, 0, 2))
        r = lane_run.parse_output("      Tests  1 failed | 70 passed | 3 skipped | 1 todo (75)")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (70, 1, 4))
        r = lane_run.parse_output("      Test Files  1 failed | 5 passed (6)")
        self.assertFalse(r["counted"])

    def test_unittest_skips_are_ignored_tests(self):
        r = lane_run.parse_output("Ran 10 tests in 0.1s\n\nOK (skipped=3)")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (7, 0, 3))
        r = lane_run.parse_output("Ran 10 tests in 0.1s\n\nFAILED (failures=1, skipped=2)")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (7, 1, 2))
        r = lane_run.parse_output("Ran 10 tests in 0.1s\n\nOK")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (10, 0, 0))

    def test_vitest_skip_fails_a_no_skips_step(self):
        with tempfile.TemporaryDirectory() as d:
            for skipped, want in ((0, "pass"), (1, "fail")):
                out = f"      Tests  70 passed | {skipped} skipped (71)" if skipped else "      Tests  70 passed (70)"
                proc = subprocess.run(
                    [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "web", "--step", "u",
                     "--min-passed", "70", "--max-ignored", "0", "--out", d, "--", sys.executable, "-c",
                     f"print({out!r})"],
                    cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
                frag = json.loads((pathlib.Path(d) / "web__-__u.json").read_text())
                self.assertEqual(frag["status"], want)
                self.assertEqual(proc.returncode == 0, want == "pass")

    def _junit(self, d, tests, failures=0, skipped=0):
        (pathlib.Path(d) / "m" / "build" / "test-results" / "test").mkdir(parents=True, exist_ok=True)
        (pathlib.Path(d) / "m" / "build" / "test-results" / "test" / "TEST-a.xml").write_text(
            f'<testsuite name="a" tests="{tests}" failures="{failures}" errors="0" skipped="{skipped}"/>')

    def test_junit_counts_and_missing_reports(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(lane_run.junit_counts(pathlib.Path(d), "*/build/test-results/test/*.xml"))
            self._junit(d, 10, failures=1, skipped=2)
            self.assertEqual(lane_run.junit_counts(pathlib.Path(d), "*/build/test-results/test/*.xml"),
                             {"passed": 7, "failed": 1, "ignored": 2})

    def test_zero_tests_below_minimum_is_a_failure(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "out"
            for tests, want in ((3, "fail"), (0, "fail"), (5, "pass")):
                self._junit(d, tests)
                rc = subprocess.run([sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "java",
                                     "--step", "t", "--cwd", d, "--junit-glob", "*/build/test-results/test/*.xml",
                                     "--min-passed", "5", "--out", str(out), "--", sys.executable, "-c", "pass"],
                                    cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d}).returncode
                frag = json.loads((out / "java__-__t.json").read_text())
                self.assertEqual(frag["status"], want)
                self.assertEqual(rc == 0, want == "pass")

    def test_countless_step_cannot_satisfy_a_minimum(self):
        with tempfile.TemporaryDirectory() as d:
            rc = subprocess.run([sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "node", "--step", "t",
                                 "--min-passed", "1", "--out", d, "--", sys.executable, "-c", "print('hi')"],
                                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d}).returncode
            self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
