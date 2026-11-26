"""Keep per-leg evidence bounded even when teardown fails while a primary error propagates."""
import inspect
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from installed_journey import cleanup, failure_site, observe_legs, stop_recording
from observation import OutcomeMismatch, judge
from pages import decimal


class ProgressTest(unittest.TestCase):
    def test_marker_publication_failure_releases_the_direct_child_and_remains_failure(self):
        marker, child = Mock(), Mock(stdout=None)
        marker.touch.side_effect = FileExistsError("marker already exists")
        child.poll.return_value = None
        with self.assertRaises(FileExistsError):
            stop_recording(child, marker)
        marker.touch.assert_called_once_with(exist_ok=False)
        child.terminate.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=30)
        child.kill.assert_not_called()

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

    def test_outcome_mismatch_exports_only_the_fixed_comparison(self):
        root = {"kind": "recording_event_kind:request_update", "symbol": "http.request GET",
                "interaction": {"driver": "servlet"}}
        response = {"kind": "recording_event_kind:response", "interaction": {"driver": "servlet"}}
        for kind, status, public_kind, public_status in (("unobserved", None, "unobserved", None),
                                                         ("responded", 401, "responded", 401),
                                                         ("private", "private", "unavailable", "unavailable")):
            detail = {"events": [root, response], "outcome": {"kind": kind, "httpStatus": status}}
            with self.assertRaises(OutcomeMismatch) as failure:
                judge({"private-recording": detail}, "3.1.10")
            self.assertEqual(failure.exception.evidence, {
                "requestClass": "filter-refusal", "expectedKind": "responded", "expectedStatus": 403,
                "observedKind": public_kind, "observedStatus": public_status})

    def test_failed_first_leg_preserves_its_failure_and_attempts_the_second(self):
        with tempfile.TemporaryDirectory() as directory:
            report = {"legs": {}, "legProgress": {}}
            failure = OutcomeMismatch("conversion", "responded", 404, "unobserved", None)
            second = {"recordings": 1}
            with patch("installed_journey.leg", side_effect=[failure, second]) as run:
                observe_legs(Path(directory), (("a", "3.1.11"), ("b", "3.1.10")), "cli", "agent", "java", report)
            self.assertEqual([call.args[2] for call in run.call_args_list], ["3.1.11", "3.1.10"])
            self.assertEqual(report["legs"], {"3.1.10": second})
            first = report["legProgress"]["3.1.11"]
            self.assertEqual(first["outcomeMismatch"], failure.evidence)
            self.assertIsNotNone(first["failureSite"])
            self.assertNotEqual(first["phase"], "complete")
            self.assertEqual(report["legProgress"]["3.1.10"]["phase"], "complete")
