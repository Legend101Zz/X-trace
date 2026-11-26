"""Hosted-only tests for owned shutdown and a subreaper's wait boundary."""
from pathlib import Path
import subprocess
import sys
import unittest

from installed import ProcessStopFailure, lifecycle_failure


class InstalledStop(unittest.TestCase):
    def test_stop_reaps_exited_adopted_group_child_before_verifying_absence(self):
        # The subreaper belongs to this isolated helper process only.
        script = """
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from installed import Process
from installed_process import contain_children, verify_children_gone

leader = '''
import os
import signal
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
descendant = os.fork()
if descendant == 0:
    os._exit(0)
os.waitid(os.P_PID, descendant, os.WEXITED | os.WNOWAIT)
print("fixture-ready", flush=True)
while True:
    signal.pause()
'''
contain_children()
with tempfile.TemporaryDirectory() as directory:
    process = Process(Path(directory), [sys.executable, "-B", "-c", leader],
                      Path(directory), dict(os.environ), descendants=True)
    try:
        process.ready(lambda line: True if line == "fixture-ready" else None, 5)
        assert process.stop() == 0 and process.cleaned
        assert process.reaped_group_exits == 1
        verify_children_gone()
    finally:
        if process.child.poll() is None:
            process.child.kill()
            process.child.wait(timeout=5)
        verify_children_gone()
"""
        subprocess.run([sys.executable, "-B", "-c", script], check=True, timeout=20, cwd=Path(__file__).parent)

    def test_stop_cause_is_finite_and_limited_to_stop_phase(self):
        for reason in ProcessStopFailure.REASONS:
            failure = ProcessStopFailure(reason)
            self.assertEqual(lifecycle_failure("stop-process", failure), {"reason": reason})
            self.assertEqual(lifecycle_failure("cleanup-port-vacant", failure), {"reason": "condition-failed"})
        self.assertEqual(lifecycle_failure("stop-process", ProcessStopFailure("private marker")),
                         {"reason": "condition-failed"})
