"""Keep per-leg evidence bounded even when teardown fails while a primary error propagates."""
import inspect
import unittest

from installed_journey import cleanup, failure_site
from pages import decimal


class ProgressTest(unittest.TestCase):
    def test_source_location_identifies_the_fixture_assertion_without_exception_data(self):
        lines, start = inspect.getsourcelines(decimal)
        assertions = [start + offset for offset, line in enumerate(lines) if 'require(' in line]
        for value, expected_line in zip(("private fixture input", str(2**64)), assertions, strict=True):
            try:
                decimal(value)
            except ValueError as error:
                site = failure_site(error)
            else:
                self.fail("invalid fixture evidence admitted")
            self.assertEqual(site, {"file": "pages.py", "line": expected_line})
            lines, start = inspect.getsourcelines(decimal)
            self.assertIn("require(", lines[site["line"] - start])
        try:
            raise RuntimeError("unrelated private exception")
        except RuntimeError as error:
            self.assertIsNone(failure_site(error))

    def test_cleanup_preserves_primary_failure_and_attributes_ordinary_teardown_failure(self):
        for cleanup_fails in (False, True):
            progress = {"phase": "fixture-readiness", "cleanupFailure": None}
            with self.assertRaisesRegex(ValueError, "^primary$"):
                try:
                    raise ValueError("primary")
                finally:
                    with cleanup(progress, "recording-shutdown"):
                        if cleanup_fails:
                            raise OSError("secondary")
            self.assertEqual(progress, {"phase": "fixture-readiness",
                                       "cleanupFailure": "recording-shutdown" if cleanup_fails else None})
        progress = {"phase": "http-workload", "cleanupFailure": None}
        with self.assertRaises(OSError), cleanup(progress, "recording-shutdown"):
            raise OSError("primary cleanup failure")
        self.assertEqual(progress, {"phase": "recording-shutdown", "cleanupFailure": None})
