import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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
            exe.write_text("#!/bin/sh\n"
                           "if [ \"$1\" = scan ]; then echo '{\"persisted\":true,\"catalogRevisionId\":\"rev\",\"result\":{\"operations\":[{}]}}'; exit 0; fi\n"
                           "while [ $# -gt 0 ]; do [ \"$1\" = --output ] && out=$2; [ \"$1\" = --format ] && fmt=$2; shift; done\n"
                           "[ \"$fmt\" = bundle ] && exit 9\necho data > \"$out\"\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            summ = td / "s.json"
            subprocess.run([sys.executable, "-B", str(pathlib.Path(ce.__file__)), "--xtrace", str(exe), "--project-dir", str(td),
                            "--analyzer", "real-analyzer", "--out", str(td / "o"), "--file", str(summ), "--project", "p"], check=True, capture_output=True)
            steps = {s["step"]: s for s in json.loads(summ.read_text())["steps"]}
            step = steps["export-formats"]
            self.assertEqual(steps["export-catalog-scan"]["status"], "pass")
            self.assertEqual(steps["export-bundle"]["status"], "not-implemented")
            self.assertEqual((step["step"], step["status"]), ("export-formats", "pass"))

    def test_scan_is_a_required_observed_prerequisite(self):
        for code, doc in ((2, {}), (0, {}), (0, {"persisted": True, "catalogRevisionId": "r", "result": {"operations": []}})):
            with tempfile.TemporaryDirectory() as td, mock.patch.object(ce.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], code, json.dumps(doc))
                steps = ce.run_exports("xtrace", "project", "analyzer", pathlib.Path(td))
                self.assertEqual(run.call_count, 1, "failed scan must not export from a stale catalog")
                self.assertEqual(run.call_args.args[0][1], "scan")
                self.assertIn("spring-mvc", run.call_args.args[0])
                self.assertIn("analyzer", run.call_args.args[0])
                self.assertEqual(dict((n, st) for n, st, _ in steps)["export-formats"], "fail")
        self.assertEqual(ce.judge({})[0], "fail")

    def test_scan_precedes_every_export_and_stale_files_fail(self):
        calls = []
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td)
            (out / "export-openapi").write_text("stale")
            def execute(args, **kwargs):
                calls.append(args[1])
                if args[1] == "scan":
                    return subprocess.CompletedProcess(args, 0, json.dumps({"persisted": True, "catalogRevisionId": "r", "result": {"operations": [{}]}}))
                fmt = args[args.index("--format") + 1]
                if fmt == "bundle":
                    return subprocess.CompletedProcess(args, 9, "")
                pathlib.Path(args[-1]).write_text("export")
                return subprocess.CompletedProcess(args, 0, "")
            with mock.patch.object(ce.subprocess, "run", side_effect=execute):
                steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", out)}
            self.assertEqual(calls, ["scan", "export", "export", "export"])
            self.assertEqual(steps["export-openapi"], "fail")
            self.assertEqual(steps["export-formats"], "fail")
            self.assertEqual(steps["export-bundle"], "not-implemented")


if __name__ == "__main__":
    unittest.main()
