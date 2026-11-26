"""Hosted checks for the finite Medusa startup and cleanup projection."""
import subprocess
import unittest

from installed import LifecycleProcessExit, Proof, lifecycle_failure
from installed_evidence import EvidenceError


class InstalledLifecycle(unittest.TestCase):
    def test_operation_and_reason_are_projected_without_private_details(self):
        private = "private marker"
        error = subprocess.CalledProcessError(73, [private], output=private, stderr=private)
        self.assertEqual(lifecycle_failure("owned-health", error), {"reason": "accepted-socket-not-verified"})
        self.assertEqual(lifecycle_failure("migrate", error), {"reason": "process-exited", "exitCode": 73})
        self.assertEqual(lifecycle_failure("await-readiness-log", LifecycleProcessExit(0)),
                         {"reason": "process-exited", "exitCode": 0})
        self.assertEqual(lifecycle_failure("stop-process", subprocess.TimeoutExpired([private], 1, output=private)),
                         {"reason": "deadline"})
        self.assertEqual(lifecycle_failure("cleanup-port-vacant", EvidenceError(private)), {"reason": "condition-failed"})
        self.assertEqual(lifecycle_failure("owned-health", subprocess.CalledProcessError(1234, [private])),
                         {"reason": "process-exited"})

    def test_first_failed_operation_remains_failed_during_later_cleanup(self):
        proof = Proof.__new__(Proof)
        proof.summary = {"lifecycle": {"baseline": {}, "installed": {}}}
        proof.save = lambda: None
        failure = EvidenceError("private check")
        with self.assertRaises(EvidenceError) as raised:
            with proof.phase("baseline", "await-readiness-log"):
                self.assertEqual(proof.summary["lifecycle"]["baseline"], {"await-readiness-log": {"status": "running"}})
                raise failure
        self.assertIs(raised.exception, failure)
        with proof.phase("baseline", "check-owned-children-absent"):
            pass
        self.assertEqual(proof.summary["lifecycle"], {
            "baseline": {
                "await-readiness-log": {"status": "failed", "reason": "condition-failed"},
                "check-owned-children-absent": {"status": "passed"},
            },
            "installed": {},
        })
