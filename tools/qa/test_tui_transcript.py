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


if __name__ == "__main__":
    unittest.main()
