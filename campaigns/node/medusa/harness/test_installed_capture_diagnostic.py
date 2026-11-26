"""Hosted cases for bounded ordinary capture diagnostics."""
import json
import unittest

from installed_capture_diagnostic import DAEMON_PREFIX, PREFIX, project_capture_diagnostic, project_daemon_finish


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
                    routeFoldEvidence=dict(batches=2, events=3),
                    finishProgress=dict(received=12, dispatched=10, submitted=9, written=9, staged=8, active="route"),
                    startStaged=9, finishStaged=8, workerFailed=False, transportFailed=False,
                    closeRequested=False, beforeExitSeen=False) | overrides

    def line(self, **overrides):
        return PREFIX + json.dumps(self.snapshot(**overrides)).encode() + b"\n"

    def test_opted_in_snapshot_reports_closed_scope_and_counts_without_private_source(self):
        result = project_capture_diagnostic(b"private example path\n" + self.line(), self.nonce)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["scope"], "transitive-only")
        self.assertIs(result["beforeExitSeen"], False)
        self.assertIs(project_capture_diagnostic(self.line(beforeExitSeen=True), self.nonce)["beforeExitSeen"], True)
        self.assertEqual(result["startStaged"], 9)
        self.assertEqual(result["counts"]["startCapacityRejected"], 35)
        self.assertEqual(result["counts"]["startBeforeCreditNotification"], 1)
        self.assertEqual(result["routeFoldEvidence"], {"batches": 2, "events": 3})
        self.assertEqual(result["finishProgress"], self.snapshot()["finishProgress"])
        for active in ("route-start", "route-held-events"):
            progress = self.snapshot()["finishProgress"] | {"active": active}
            self.assertEqual(project_capture_diagnostic(self.line(finishProgress=progress), self.nonce)
                             ["finishProgress"], progress)
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
        progress = self.snapshot()["finishProgress"]
        for overrides in ({"beforeExitSeen": "false"}, {"finishProgress": None},
                          {"finishProgress": progress | {"staged": 9}},
                          {"finishProgress": progress | {"written": 10}},
                          {"finishProgress": progress | {"received": 13}},
                          {"finishProgress": progress | {"received": 4096}},
                          {"finishProgress": progress | {"received": True}},
                          {"finishProgress": progress | {"private": "example"}},
                          {"finishProgress": progress | {"active": "/private/example"}},
                          {"examplePath": "/private/example"}, {"scope": "/private/example"},
                          {"finishStaged": 13}, {"startStaged": 13}, {"workerFailed": 1},
                          {"routeFoldEvidence": {"batches": 0, "events": 1}},
                          {"routeFoldEvidence": {"batches": 1, "events": 64}},
                          {"routeFoldEvidence": {"batches": 1, "events": 2, "private": "example"}},
                          {"counts": self.snapshot()["counts"] | {"startAttempts": 46}},
                          {"counts": self.snapshot()["counts"] | {"startBeforeCreditNotification": 13}},
                          {"counts": self.snapshot()["counts"] | {"eventBeforeCreditNotification": "private"}}):
            self.assertEqual(project_capture_diagnostic(self.line(**overrides), self.nonce), {"status": "invalid"})

    def test_daemon_finish_reports_only_closed_authenticated_aggregate(self):
        data = dict(nonce=self.nonce, sessions=1, decoded=12, admitted=12, ackReady=11, ackQueued=11, ackFlushed=10)
        def line(values):
            return DAEMON_PREFIX + json.dumps(values).encode() + b"\n"
        good = line(data)
        self.assertEqual(project_daemon_finish(self.line() + good, self.nonce),
                         {"status": "observed", **{k: v for k, v in data.items() if k != "nonce"}})
        self.assertEqual(project_daemon_finish(self.line(), self.nonce), {"status": "missing"})
        self.assertIsNone(project_daemon_finish(good, None))
        for bad in (good * 2, good.rstrip(b"\n"), line(data | {"ackFlushed": 12}),
                    line(data | {"nonce": "b" * 48}), line(data | {"decoded": True}),
                    line(data | {"sessions": 0}), line(data | {"requestId": "/private/example"})):
            self.assertEqual(project_daemon_finish(bad, self.nonce), {"status": "invalid"})
