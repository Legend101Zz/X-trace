"""Hosted checks for the finite Medusa startup and cleanup projection."""
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

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


    def test_unverified_cleanup_blocks_the_next_leg_or_readback(self):
        for failed_leg, expected_legs in (("baseline", ["baseline"]), ("installed", ["baseline", "installed"])):
            with self.subTest(leg=failed_leg), TemporaryDirectory() as root:
                proof = Proof.__new__(Proof)
                proof.summary = {"stages": {}}
                proof.project = Path(root) / "project"
                proof.cli = Path(root) / "cli"
                proof.install = Mock()
                proof.command = Mock()
                proof.save = Mock()
                proof.readback = Mock()

                def leg(name):
                    proof.summary["stages"][f"{name}:cleanup"] = "failed" if name == failed_leg else "passed"
                    return None, None

                proof.leg = Mock(side_effect=leg)
                with patch("installed.verify_children_gone"), self.assertRaises(EvidenceError):
                    proof.run()
                self.assertEqual([call.args[0] for call in proof.leg.call_args_list], expected_legs)
                proof.readback.assert_not_called()
