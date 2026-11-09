import pathlib
import stat
import sys
import tempfile
import unittest

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
            exe.write_text("#!/bin/sh\nprintf 'recordings: 01a12327-8de6-complete\\n'\nread x\nprintf 'http.request GET /owners\\n'\nsleep 0.3\nexit 0\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            code, stopped, buf = t.run(str(exe), td, 5.0, 24, 80, open_after=0.5)
            self.assertEqual(t.classify(code, stopped, buf)[0], "pass", buf)
            plain = pathlib.Path(td) / "plain"  # a list that names ids only and exits by itself: no route, so no pass
            plain.write_text("#!/bin/sh\nprintf 'recordings: 01a12327-8de6-complete\\n'\nexit 0\n")
            plain.chmod(plain.stat().st_mode | stat.S_IXUSR)
            code, stopped, buf = t.run(str(plain), td, 2.0, 24, 80, open_after=0)
            self.assertEqual(t.classify(code, stopped, buf)[0], "fail")


if __name__ == "__main__":
    unittest.main()
