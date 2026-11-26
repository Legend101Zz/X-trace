"""Hosted-only tests of the Medusa supervisor's finite recovery reasons."""
import os
import subprocess
import unittest
from unittest.mock import Mock, call, patch

from installed import Process, ProcessStopFailure
from installed_process import verify_children_gone


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
              patch("installed.time.monotonic", side_effect=[0, 0, 25, 26, 26, 27]),
              patch("installed.select.select", side_effect=[([], [], []), ([30], [], []),
                                                           ([31], [], [])]) as ready,
              patch("installed.signal.pidfd_send_signal") as pidfd_send,
              patch("installed.reap_exited_group_children", return_value=1) as reap,
              patch("installed.os.close") as close,
              patch("installed.os.killpg", side_effect=ProcessLookupError) as killpg):
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
        self.assertEqual(ready.call_args_list, [call([30, 31], [], [], 0), call([30, 31], [], [], 4),
                                               call([31], [], [], 3)])
        process.child.kill.assert_called_once_with()
        pidfd_send.assert_not_called()
        killpg.assert_called_once_with(246, 0)
        self.assertEqual(close.call_args_list, [call(30), call(31)])
        reap.assert_called_once_with(246)

    def test_grace_only_probe_fails_on_deadline_without_forcing_the_child(self):
        process = self.process()
        process.child.wait.side_effect = subprocess.TimeoutExpired(["owned fixture"], 25)
        with patch("installed.time.monotonic", side_effect=[100, 100]):
            with self.assertRaises(subprocess.TimeoutExpired):
                process.stop(grace_only=True)
        process.child.terminate.assert_called_once_with()
        process.child.wait.assert_called_once_with(timeout=25)
        process.child.kill.assert_not_called()
        self.assertEqual(process.stop_recovery_reasons, ["launcher-wait-deadline"])
        self.assertFalse(process.cleaned)

    def test_descendants_share_the_original_grace_deadline_after_launcher_exit(self):
        process = self.process((30, 31))
        with (patch("installed.time.monotonic", side_effect=[100, 101, 110, 119]),
              patch("installed.select.select", side_effect=[([31], [], []), ([30], [], [])]) as ready,
              patch("installed.signal.pidfd_send_signal") as pidfd_send,
              patch("installed.reap_exited_group_children", return_value=2),
              patch("installed.os.close"),
              patch("installed.os.killpg", side_effect=ProcessLookupError)):
            self.assertEqual(process.stop(), 0)
        process.child.terminate.assert_called_once_with()
        process.child.wait.assert_called_once_with(timeout=24)
        self.assertEqual(ready.call_args_list, [call([30, 31], [], [], 15), call([30], [], [], 6)])
        pidfd_send.assert_not_called()
        process.child.kill.assert_not_called()
        self.assertEqual(process.stop_recovery_reasons, [])
        self.assertEqual(process.reaped_group_exits, 2)
        self.assertTrue(process.cleaned)

    def test_live_descendant_keeps_stop_red_without_recovery_signals(self):
        process = self.process((30,))
        with (patch("installed.time.monotonic", side_effect=[100, 101, 105, 125]),
              patch("installed.select.select", return_value=([], [], [])) as ready,
              patch("installed.signal.pidfd_send_signal") as pidfd_send,
              patch("installed.reap_exited_group_children") as reap,
              patch("installed.os.close") as close,
              patch("installed.os.killpg") as killpg):
            with self.assertRaises(ProcessStopFailure) as failure:
                process.stop()
        self.assertEqual(failure.exception.reason, "descendant-exit-unverified")
        self.assertEqual(process.stop_recovery_reasons, ["descendant-exit-not-yet-observed"])
        self.assertEqual(ready.call_args_list, [call([30], [], [], 20), call([30], [], [], 5)])
        process.child.terminate.assert_called_once_with()
        process.child.kill.assert_not_called()
        killpg.assert_not_called()
        pidfd_send.assert_not_called()
        reap.assert_not_called()
        close.assert_called_once_with(30)
        self.assertFalse(process.cleaned)

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


class InstalledChildAbsence(unittest.TestCase):
    def test_exited_children_are_reaped_without_signals(self):
        with (patch("installed_process.time.monotonic", side_effect=[0, 1, 2]),
              patch("installed_process.os.waitpid", side_effect=[(246, 0), ChildProcessError]) as wait,
              patch("installed_process.os.killpg") as killpg,
              patch("signal.pidfd_send_signal") as pidfd_send):
            verify_children_gone()
        self.assertEqual(wait.call_args_list, [call(-1, os.WNOHANG), call(-1, os.WNOHANG)])
        killpg.assert_not_called()
        pidfd_send.assert_not_called()

    def test_live_adopted_child_keeps_absence_unverified_without_signals(self):
        with (patch("installed_process.time.monotonic", side_effect=[0, 1, 10]),
              patch("installed_process.time.sleep") as sleep,
              patch("installed_process.os.waitpid", return_value=(0, 0)),
              patch("installed_process.os.killpg") as killpg,
              patch("signal.pidfd_send_signal") as pidfd_send):
            with self.assertRaisesRegex(TimeoutError, "owned process absence"):
                verify_children_gone()
        sleep.assert_called_once_with(0.05)
        killpg.assert_not_called()
        pidfd_send.assert_not_called()
