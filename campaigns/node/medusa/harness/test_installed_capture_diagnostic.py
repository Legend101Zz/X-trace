"""Hosted cases for bounded ordinary capture diagnostics."""
import json
import unittest

from installed_capture_diagnostic import PREFIX, project_capture_diagnostic


class InstalledCaptureDiagnostic(unittest.TestCase):
    nonce = "a" * 48

    def snapshot(self, **overrides):
        return dict(nonce=self.nonce, exitCode=0, scope="transitive-only", express="express-not-found",
                    patchedLayers=0, counts={"startAttempts": 47, "startAccepted": 12,
                        "startCapacityRejected": 35, "startOtherRejected": 0, "finishPosted": 12,
                        "finishRejected": 0, "eventRejected": 2, "routeRejected": 0,
                        "startBeforeCreditNotification": 1, "eventBeforeCreditNotification": 3,
                        "routeBeforeCreditNotification": 0},
                    expressEvidence=dict(invoked=0, withContext=0, posted=0, anyLayerStaged=0),
                    startStaged=9, finishStaged=8, workerFailed=False, transportFailed=False,
                    closeRequested=False) | overrides

    def line(self, **overrides):
        return PREFIX + json.dumps(self.snapshot(**overrides)).encode() + b"\n"

    def test_opted_in_snapshot_reports_closed_scope_and_counts_without_private_source(self):
        result = project_capture_diagnostic(b"private example path\n" + self.line(), self.nonce)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["scope"], "transitive-only")
        self.assertEqual(result["startStaged"], 9)
        self.assertEqual(result["counts"]["startCapacityRejected"], 35)
        self.assertEqual(result["counts"]["startBeforeCreditNotification"], 1)
        private = json.dumps(result)
        self.assertNotIn(self.nonce, private)
        self.assertNotIn("private example path", private)
        self.assertIsNone(project_capture_diagnostic(self.line(), None))

    def test_layer_invocation_and_worker_staging_are_separate(self):
        counts = dict(invoked=40, withContext=12, posted=9, anyLayerStaged=7)
        data = self.line(express="installed", patchedLayers=1, expressEvidence=counts)
        self.assertEqual(project_capture_diagnostic(data, self.nonce)["expressEvidence"], counts)
        for bad in (counts | dict(posted=13), counts | dict(withContext=41),
                    counts | dict(anyLayerStaged=True), counts | dict(sourcePath="/private/example")):
            data = self.line(express="installed", patchedLayers=1, expressEvidence=bad)
            self.assertEqual(project_capture_diagnostic(data, self.nonce), {"status": "invalid"})
        self.assertEqual(project_capture_diagnostic(self.line(expressEvidence=counts), self.nonce),
                         {"status": "invalid"})

    def test_stale_ambiguous_or_unterminated_observation_is_invalid(self):
        self.assertEqual(project_capture_diagnostic(b"ordinary stderr\n", self.nonce), {"status": "missing"})
        for log in (self.line(nonce="b" * 48), self.line() * 2, self.line().rstrip(b"\n"),
                    self.line().replace(b'"exitCode": 0', b'"exitCode": 0, "exitCode": 0')):
            self.assertEqual(project_capture_diagnostic(log, self.nonce), {"status": "invalid"})

    def test_records_with_extra_values_or_impossible_counts_are_invalid(self):
        for overrides in ({"examplePath": "/private/example"}, {"scope": "/private/example"},
                          {"finishStaged": 13}, {"startStaged": 13}, {"workerFailed": 1},
                          {"counts": self.snapshot()["counts"] | {"startAttempts": 46}},
                          {"counts": self.snapshot()["counts"] | {"startBeforeCreditNotification": 13}},
                          {"counts": self.snapshot()["counts"] | {"eventBeforeCreditNotification": "private"}}):
            self.assertEqual(project_capture_diagnostic(self.line(**overrides), self.nonce), {"status": "invalid"})
