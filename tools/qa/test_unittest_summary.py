import unittest

from tools.qa import unittest_summary


class UnittestSummaryTests(unittest.TestCase):
    def test_headers_and_summary_survive_buffered_stdout_without_fixture_values(self):
        text = ("..FE\n"
                "FAIL: test_timeout (test_release_floor.FloorSupervisorTests.test_timeout) "
                "(value='captured-value-731')\n"
                "Traceback (most recent call last):\nAssertionError: captured-value-731\n"
                "ERROR: test_wrapper (tools.qa.test_release_floor.FloorSupervisorTests.test_wrapper)\n"
                "Ran 315 tests in 12.345s\n\nFAILED (failures=1, errors=1)\n"
                + "buffered captured-value-731\n" * 50)
        self.assertEqual(unittest_summary.summarize(text), "\n".join([
            "FAIL: test_timeout (test_release_floor.FloorSupervisorTests.test_timeout)",
            "ERROR: test_wrapper (tools.qa.test_release_floor.FloorSupervisorTests.test_wrapper)",
            "Ran 315 tests in 12.345s", "FAILED (failures=1, errors=1)",
        ]))

    def test_malformed_headers_and_summary_suffixes_are_withheld(self):
        self.assertEqual(unittest_summary.summarize(
            "FAIL: captured/value (not a test)\nERROR: secret\n"
            "FAILED (failures=1, value=captured-value-731)\n"
            "Ran 3 tests in 1.23s captured-value-731\nOK captured-value-731\n"), "")

    def test_singular_and_skipped_summaries(self):
        text = "Ran 1 test in 0.001s\n\nOK (skipped=1)\n"
        self.assertEqual(unittest_summary.summarize(text), "Ran 1 test in 0.001s\nOK (skipped=1)")


if __name__ == "__main__":
    unittest.main()
