"""Hosted cases for Medusa development readiness stream handling."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from installed import Process, medusa_ready_line


class InstalledReadiness(unittest.TestCase):
    def streams(self, directory, stdout, stderr):
        process = Process.__new__(Process)
        process.stdout = Path(directory) / "stdout"
        process.stderr = Path(directory) / "stderr"
        process.stdout.write_bytes(stdout)
        process.stderr.write_bytes(stderr)
        process.child = Mock()
        process.child.poll.return_value = None
        process.observe_children = Mock()
        return process

    def test_wait_reads_medusa_ora_success_from_stderr_and_preserves_stdout(self):
        for expected in ("stderr", "stdout"):
            with self.subTest(stream=expected), tempfile.TemporaryDirectory() as directory:
                marker = "✔ Server is ready on port: 9000 – 47ms\n".encode()
                # Split the real-format marker across two reads and leave the other stream partial.
                content = b"x" * 65525 + b"\n" + marker
                wrong_port = b"Server is ready on port: 90001\npartial"
                process = self.streams(directory, content if expected == "stdout" else wrong_port,
                                       content if expected == "stderr" else wrong_port)
                with patch("installed.time.monotonic", side_effect=[0, 0, 1]), patch("installed.time.sleep"):
                    self.assertEqual(process.ready(medusa_ready_line, 3, include_stderr=True), (True, expected))
                process.observe_children.assert_called_once_with()

    def test_default_stdout_wait_does_not_accept_stderr_or_join_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            process = self.streams(directory, b"unrelated\n", b"Server is ready on port: 9000\n")
            with patch("installed.time.monotonic", side_effect=[0, 0, 2]), patch("installed.time.sleep"):
                with self.assertRaises(TimeoutError):
                    process.ready(medusa_ready_line, 1)
            process.observe_children.assert_not_called()
            process.stdout.write_bytes(b"Server is ready on ")
            process.stderr.write_bytes(b"port: 9000\n")
            with patch("installed.time.monotonic", side_effect=[0, 0, 2]), patch("installed.time.sleep"):
                with self.assertRaises(TimeoutError):
                    process.ready(medusa_ready_line, 1, include_stderr=True)
            process.observe_children.assert_not_called()
