import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_exports as ce  # noqa: E402


class T(unittest.TestCase):
    def test_judge(self):
        self.assertEqual(ce.judge({f: (9, 0) for f in ce.FORMATS})[0], "not-implemented")
        self.assertEqual(ce.judge({f: (0, 10) for f in ce.FORMATS})[0], "pass")
        self.assertEqual(ce.judge({"openapi": (0, 0), "curl": (0, 5)})[0], "fail")  # exit 0 with no output is not a pass
        self.assertEqual(ce.judge({"openapi": (9, 0), "curl": (0, 5)})[0], "fail")  # mixed: not wholly unimplemented
        self.assertEqual(ce.judge({"openapi": (2, 0)})[0], "fail")

    def test_cli_with_fake_binary(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            exe = td / "fake"
            exe.write_text("#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = --output ] && out=$2; shift; done\necho data > \"$out\"\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            summ = td / "s.json"
            subprocess.run([sys.executable, "-B", str(pathlib.Path(ce.__file__)), "--xtrace", str(exe), "--project-dir", str(td),
                            "--out", str(td / "o"), "--file", str(summ), "--project", "p"], check=True, capture_output=True)
            step = json.loads(summ.read_text())["steps"][0]
            self.assertEqual((step["step"], step["status"]), ("export-formats", "pass"))


if __name__ == "__main__":
    unittest.main()
