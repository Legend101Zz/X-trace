import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tui_transcript as t  # noqa: E402


class T(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(t.classify(9, False, b"")[0], "not-implemented")
        self.assertEqual(t.classify(0, False, b"\x1b[2J GET /owners 200")[0], "pass")
        self.assertEqual(t.classify(0, False, b"\x1b[2J hello")[0], "fail")
        self.assertEqual(t.classify(0, False, b"\x1b[2J")[0], "fail")
        self.assertEqual(t.classify(1, False, b"GET /owners")[0], "fail")
        self.assertEqual(t.classify(143, True, b"POST /owners/new")[0], "pass")
        self.assertEqual(t.classify(1, True, b"GET /owners")[0], "fail")
        self.assertEqual(t.classify(None, False, b"GET /owners")[0], "fail")

    def test_real_pty_with_fake_binary(self):
        with tempfile.TemporaryDirectory() as td:
            exe = pathlib.Path(td) / "fake"
            exe.write_text("#!/bin/sh\nprintf '\\033[2Jrecordings: GET /owners 200\\n'\nexit 0\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            code, stopped, buf = t.run(str(exe), td, 3.0, 24, 80)
            self.assertEqual(code, 0)
            self.assertFalse(stopped)
            self.assertEqual(t.classify(code, stopped, buf)[0], "pass")
            ni = pathlib.Path(td) / "ni"
            ni.write_text("#!/bin/sh\nexit 9\n")
            ni.chmod(ni.stat().st_mode | stat.S_IXUSR)
            code, stopped, buf = t.run(str(ni), td, 3.0, 24, 80)
            self.assertEqual(t.classify(code, stopped, buf)[0], "not-implemented")

    def test_enter_opens_the_recording_so_its_route_reaches_the_transcript(self):
        with tempfile.TemporaryDirectory() as td:
            exe = pathlib.Path(td) / "fake"
            # a list screen that names only ids; the route appears only after the key press
            exe.write_text("#!/bin/sh\nprintf 'X-trace recordings: > 01a12327-8de6-7000-8000-000000000000  complete  12 events\\n'\nread x\nprintf 'http.request GET /owners\\n'\nexit 0\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            code, stopped, buf = t.run(str(exe), td, 5.0, 24, 80)
            self.assertEqual(t.classify(code, stopped, buf)[0], "pass", buf)
            plain = pathlib.Path(td) / "plain"  # a list that names ids only and exits by itself: no route, so no pass
            plain.write_text("#!/bin/sh\nprintf 'X-trace recordings: > 01a12327-8de6-7000-8000-000000000000  complete  12 events\\n'\nexit 0\n")
            plain.chmod(plain.stat().st_mode | stat.S_IXUSR)
            code, stopped, buf = t.run(str(plain), td, 2.0, 24, 80, open_recording=False)
            self.assertEqual(t.classify(code, stopped, buf)[0], "fail")

    def test_list_requires_a_selected_recording_row(self):
        self.assertFalse(t.list_observed(b"X-trace recordings; Loading..."))
        self.assertFalse(t.list_observed(b"> 01a12327-8de6-7000-8000-000000000000 complete 12 events"))
        self.assertFalse(t.list_observed(b"recordings: > 01a12327-8de6"))
        self.assertTrue(t.list_observed(b"X-trace recordings: > 01a12327-8de6-7000-8000-000000000000 complete 12 events"))

    def test_input_follows_observed_row_and_discloses_detail_navigation(self):
        chunks = [b"X-trace recordings; Loading...", b"> 01a12327-8de6-7000-8000-000000000000 complete 12 events", b"http.request GET /owners"]
        reads, writes = [], []
        def read(*args):
            chunk = chunks.pop(0) if chunks else b""
            reads.append(chunk)
            return chunk
        def write(fd, data):
            writes.append((data, len(reads)))
            return len(data)
        observed = {}
        with mock.patch.object(t.pty, "fork", return_value=(42, 9)), \
             mock.patch.object(t.fcntl, "ioctl"), mock.patch.object(t.os, "close"), \
             mock.patch.object(t.select, "select", return_value=([9], [], [])), \
             mock.patch.object(t.os, "read", side_effect=read), mock.patch.object(t.os, "write", side_effect=write), \
             mock.patch.object(t.os, "waitpid", side_effect=[(0, 0), (0, 0), (42, 0)]):
            code, stopped, buf = t.run("xtrace", "project", 3, 24, 80, observations=observed)
        self.assertEqual(writes, [(t.OPEN_KEY, 2)])
        self.assertEqual((code, stopped), (0, False))
        self.assertTrue(observed["listObserved"])
        self.assertTrue(observed["inputSent"])
        self.assertTrue(observed["routeObservedAfterOpen"])
        self.assertIsInstance(observed["open_after"], float)
        self.assertIn("detail", observed["accommodation"])


if __name__ == "__main__":
    unittest.main()
