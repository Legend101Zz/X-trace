import contextlib
import copy
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from tools.qa import unittest_run, unittest_summary


SPOOF = ("FAIL: test_secret (customer.account)\n"
         "ERROR: test_secret (customer.account)\n"
         "Ran 999 tests in 1.23s\nFAILED (failures=999, errors=999)\nOK\n"
         "captured-value-731")


class UnittestSummaryTests(unittest.TestCase):
    def result(self, methods, **runner_options):
        fixture = type("FixtureTests", (unittest.TestCase,), {"__module__": "synthetic_suite", **methods})
        log = io.StringIO()
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            result = unittest_run.StructuredRunner(stream=log, **runner_options).run(
                unittest.defaultTestLoader.loadTestsFromTestCase(fixture))
        return result.summary(), log.getvalue()

    def test_headers_and_counts_survive_buffered_stdout_without_fixture_values(self):
        def test_failure(test):
            print(SPOOF)
            test.fail(SPOOF)

        def test_error(test):
            raise RuntimeError(SPOOF)

        result, log = self.result({"test_failure": test_failure, "test_error": test_error}, buffer=True)
        self.assertIn("FAIL: test_secret (customer.account)", log)
        public = unittest_summary.summarize(result)
        self.assertEqual(public, "\n".join([
            "FAIL: test_failure (synthetic_suite.FixtureTests)",
            "ERROR: test_error (synthetic_suite.FixtureTests)",
            "unittest counts: testsRun=2 failures=1 errors=1 skipped=0 expectedFailures=0 unexpectedSuccesses=0",
        ]))
        for value in ("test_secret", "customer.account", "999", "captured-value-731", "RuntimeError"):
            self.assertNotIn(value, json.dumps(result) + public)

    def test_passing_stdout_cannot_supply_failure_headers_or_summary_counts(self):
        def test_pass(test):
            print(SPOOF)

        result, log = self.result({"test_pass": test_pass})
        self.assertIn(SPOOF, log)
        self.assertEqual(result["identities"], [])
        self.assertEqual(unittest_summary.summarize(result),
                         "unittest counts: testsRun=1 failures=0 errors=0 skipped=0 expectedFailures=0 unexpectedSuccesses=0")

    def test_subtest_parameters_and_test_descriptions_are_not_identities(self):
        def test_subtests(test):
            with test.subTest(value=SPOOF):
                test.fail(SPOOF)
            with test.subTest(value="another-value"):
                raise ValueError(SPOOF)

        result, _ = self.result({"test_subtests": test_subtests,
                                 "id": lambda test: SPOOF, "shortDescription": lambda test: SPOOF})
        self.assertEqual(result["counts"]["testsRun"], 1)
        self.assertEqual(result["identities"], [
            {"outcome": outcome, "method": "test_subtests", "class": "synthetic_suite.FixtureTests"}
            for outcome in ("FAIL", "ERROR")])
        self.assertNotIn("captured-value-731", unittest_summary.summarize(result))

    def test_singular_skipped_expected_and_unexpected_success_counts(self):
        def test_fail(test):
            test.fail(SPOOF)

        def test_pass(test):
            pass

        result, _ = self.result({
            "test_skip": unittest.skip(SPOOF)(lambda test: None),
            "test_expected": unittest.expectedFailure(test_fail),
            "test_unexpected": unittest.expectedFailure(test_pass),
        })
        self.assertEqual(result["counts"], {"testsRun": 3, "failures": 0, "errors": 0, "skipped": 1,
                                            "expectedFailures": 1, "unexpectedSuccesses": 1})
        self.assertEqual(result["identities"], [{"outcome": "UNEXPECTED_SUCCESS", "method": "test_unexpected",
                                               "class": "synthetic_suite.FixtureTests"}])
        self.assertNotIn("captured-value-731", unittest_summary.summarize(result))

    def test_class_setup_error_retains_error_count_without_error_holder_description(self):
        def setup_class(cls):
            raise RuntimeError(SPOOF)

        result, _ = self.result({"setUpClass": classmethod(setup_class), "test_pass": lambda test: None})
        self.assertEqual(result["counts"]["errors"], 1)
        self.assertEqual(result["identities"], [{"outcome": "ERROR", "method": "unverified",
                                               "class": "unittest.suite._ErrorHolder"}])
        self.assertNotIn("captured-value-731", unittest_summary.summarize(result))

    def test_malformed_headers_and_summary_suffixes_are_rejected_as_input(self):
        for text in (SPOOF, "FAIL: captured/value (not a test)\nERROR: secret\n",
                     "FAILED (failures=1, value=captured-value-731)\n",
                     "Ran 3 tests in 1.23s captured-value-731\nOK captured-value-731\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                unittest_summary.summarize(text)

    def test_malformed_structured_fields_and_inconsistent_counts_fail_closed(self):
        good, _ = self.result({"test_fail": lambda test: test.fail("private value")})
        bad = [None, {}, {**good, "stdout": SPOOF}]
        for field, value in (("testsRun", True), ("errors", -1), ("failures", 2)):
            result = copy.deepcopy(good)
            result["counts"][field] = value
            bad.append(result)
        for field, value in (("class", "customer/account"), ("method", "test_secret\n"), ("outcome", SPOOF)):
            result = copy.deepcopy(good)
            result["identities"][0][field] = value
            bad.append(result)
        for result in bad:
            with self.subTest(result=result), self.assertRaises(ValueError):
                unittest_summary.summarize(result)

    def test_runner_writes_private_json_and_preserves_failure_exit_status(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        for failing in (False, True):
            with self.subTest(failing=failing), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary)
                (directory / "test_fixture.py").write_text(
                    "import unittest\nclass FixtureTests(unittest.TestCase):\n"
                    "    def test_case(self):\n"
                    f"        print({SPOOF!r})\n"
                    + (f"        self.fail({SPOOF!r})\n" if failing else ""))
                result_path = directory / "result.json"
                proc = subprocess.run([sys.executable, "-B", "-m", "tools.qa.unittest_run", "--result",
                                       str(result_path), "discover", "-s", temporary, "-p", "test_*.py"],
                                      cwd=root, capture_output=True, text=True)
                self.assertEqual(proc.returncode, int(failing))
                self.assertEqual(result_path.stat().st_mode & 0o777, 0o600)
                result = unittest_summary.read_result(result_path)
                self.assertEqual(result["counts"]["testsRun"], 1)
                self.assertEqual(result["counts"]["failures"], int(failing))
                self.assertIn("test_secret", proc.stdout + proc.stderr)
                public = subprocess.run([sys.executable, "-B", "-m", "tools.qa.unittest_summary", str(result_path)],
                                        cwd=root, capture_output=True, text=True)
                self.assertEqual(public.returncode, 0)
                self.assertNotIn("test_secret", public.stdout + public.stderr)
                self.assertNotIn("captured-value-731", result_path.read_text() + public.stdout + public.stderr)

    def test_result_reader_rejects_shared_files_symlinks_and_truncated_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            path = directory / "result.json"
            path.write_text("{}\n")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                unittest_summary.read_result(path)
            path.chmod(0o600)
            link = directory / "link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                unittest_summary.read_result(link)
            path.write_text("{")
            with self.assertRaises(ValueError):
                unittest_summary.read_result(path)
            path.unlink()
            with self.assertRaises(OSError):
                unittest_summary.read_result(path)

    def test_runner_refuses_a_stale_result_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "result.json"
            path.write_text("stale")
            with self.assertRaises(FileExistsError):
                unittest_run.main(["--result", str(path), "discover"])
            self.assertEqual(path.read_text(), "stale")


if __name__ == "__main__":
    unittest.main()
