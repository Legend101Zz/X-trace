import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

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
    def run_step(self, cmd, min_passed=0, timeout=60, max_ignored=-1):
        with tempfile.TemporaryDirectory() as d:
            args = type("A", (), {"suite": "meta", "variant": "-", "step": "t", "out": d + "/o", "cwd": "",
                                  "timeout": timeout, "min_passed": min_passed, "max_ignored": max_ignored, "command": ["--"] + cmd})()
            import os
            os.environ["LANE_PRIVATE_LOG_DIR"] = d
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

    def test_uncounted_step_reports_null(self):
        rc, frag = self.run_step([sys.executable, "-c", "print('hi')"])
        self.assertEqual(rc, 0)
        self.assertIsNone(frag["passed"])


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
