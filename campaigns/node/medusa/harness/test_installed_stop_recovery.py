"""Hosted-only tests of the Medusa supervisor's finite recovery reasons."""
import signal
import subprocess
import unittest
from unittest.mock import Mock, call, patch

from installed import Process, ProcessStopFailure


class InstalledStopRecovery(unittest.TestCase):
    def process(self, handles=()):
        process = Process.__new__(Process)
        process.child = Mock(pid=246, returncode=0)
        process.child.poll.return_value = None
        process.child.wait.return_value = 0
        process.observe_children = Mock()
        process.owned_children = dict(enumerate(handles))
        process.stopped = False
        process.cleaned = False
        process.stop_recovery_reasons = None
        return process

    def test_all_forced_paths_keep_order_and_do_not_pass_a_cleaned_group(self):
        process = self.process((30, 31))
        private = "private fixture argv"
        process.observe_children.side_effect = RuntimeError(private)
        process.child.wait.side_effect = [subprocess.TimeoutExpired([private], 25), 0]
        with (patch("installed.traceback.print_exc"),
              patch("installed.select.select", side_effect=[([], [], []), ([30], [], []),
                                                           ([], [], []), ([31], [], [])]) as ready,
              patch("installed.signal.pidfd_send_signal") as pidfd_send,
              patch("installed.reap_exited_group_children", return_value=1) as reap,
              patch("installed.os.close") as close,
              patch("installed.os.killpg", side_effect=[None, ProcessLookupError]) as killpg):
            with self.assertRaises(ProcessStopFailure) as failure:
                process.stop()
        self.assertEqual(failure.exception.reason, "forced-cleanup")
        self.assertTrue(process.cleaned)
        self.assertEqual(process.reaped_group_exits, 1)
        self.assertEqual(process.stop_recovery_reasons, [
            "descendant-inventory-failed", "launcher-wait-deadline", "descendant-exit-not-yet-observed",
        ])
        process.child.terminate.assert_called_once_with()
        self.assertEqual(process.child.wait.call_args_list, [call(timeout=25), call(timeout=5)])
        self.assertEqual(ready.call_args_list, [call([30], [], [], 0), call([30], [], [], 5),
                                               call([31], [], [], 0), call([31], [], [], 5)])
        self.assertEqual(pidfd_send.call_args_list, [call(30, signal.SIGKILL), call(31, signal.SIGKILL)])
        self.assertEqual(killpg.call_args_list, [call(246, signal.SIGKILL), call(246, 0)])
        self.assertEqual(close.call_args_list, [call(30), call(31)])
        reap.assert_called_once_with(246)

    def test_no_recovery_is_distinct_from_the_group_absence_verdict(self):
        process = self.process()
        self.assertIsNone(process.stop_recovery_reasons)
        with (patch("installed.reap_exited_group_children", return_value=0),
              patch("installed.os.killpg", side_effect=ProcessLookupError)):
            self.assertEqual(process.stop(), 0)
        self.assertEqual(process.stop_recovery_reasons, [])
        self.assertTrue(process.cleaned)
        process = self.process()
        process.observe_children.side_effect = RuntimeError("private fixture")
        with (patch("installed.traceback.print_exc"),
              patch("installed.reap_exited_group_children", return_value=0),
              patch("installed.os.killpg")):
            with self.assertRaises(ProcessStopFailure) as failure:
                process.stop()
        self.assertEqual(failure.exception.reason, "process-group-present")
        self.assertEqual(process.stop_recovery_reasons, ["descendant-inventory-failed"])
        self.assertFalse(process.cleaned)
