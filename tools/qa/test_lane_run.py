import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.qa import lane_run  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_cargo_failures_are_allowlisted(self):
        text = "\n".join([
            "test a::b::ok ... ok",
            "test a::b::bad ... FAILED",
            "test weird name with /home/x/secret ... FAILED",
            "test result: FAILED. 3 passed; 2 failed; 1 ignored; 0 measured",
        ])
        r = lane_run.parse_output(text)
        self.assertEqual(r["failingTests"], ["a::b::bad"])
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (3, 2, 1))

    def test_gradle_failure_name(self):
        r = lane_run.parse_output("com.example.FooTest > doesThing() FAILED")
        self.assertEqual(r["failingTests"], ["FooTest::doesThing"])

    def test_invalid_names_dropped_and_counted(self):
        r = lane_run.parse_output("test ../../etc/passwd ... FAILED")
        self.assertEqual(r["failingTests"], [])
        self.assertEqual(r["droppedInvalidNames"], 1)

    def test_truncation(self):
        text = "\n".join(f"test t::n{i} ... FAILED" for i in range(40))
        r = lane_run.parse_output(text)
        self.assertEqual(len(r["failingTests"]), 32)
        self.assertEqual(r["failingTruncated"], 8)


class MergeTests(unittest.TestCase):
    def merge(self, plan, frags, results=None):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "plan.json").write_text(json.dumps(plan))
            (d / "f").mkdir()
            for i, f in enumerate(frags):
                (d / "f" / f"{i}.json").write_text(json.dumps(f))
            args = type("A", (), {"plan": str(d / "plan.json"), "frag_dir": str(d / "f"),
                                  "out": str(d / "s.json"), "step_summary": "", "job_result": results})()
            rc = lane_run.cmd_merge(args)
            return rc, json.loads((d / "s.json").read_text())

    def frag(self, suite, status="pass", variant="-"):
        return {"suite": suite, "variant": variant, "step": "t", "status": status, "exitCode": 0,
                "passed": 1, "failed": 0, "ignored": 0, "failingTests": [], "failingTruncated": 0,
                "droppedInvalidNames": 0}

    def test_missing_result_is_not_pass(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}, "tui": {"status": "absent"}}}
        rc, s = self.merge(plan, [])
        self.assertEqual(rc, 1)
        self.assertEqual(s["suites"][0]["variants"][0]["status"], "no-result")
        self.assertEqual(s["suites"][1]["status"], "absent")

    def test_pass_and_skip(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}, "java": {"status": "skipped-by-filter"}}}
        rc, s = self.merge(plan, [self.frag("meta")])
        self.assertEqual(rc, 0)
        self.assertEqual([x["status"] for x in s["suites"]], ["pass", "skipped-by-filter"])

    def test_all_java_variants_required(self):
        plan = {"mode": "x", "suites": {"java": {"status": "selected"}}}
        rc, _ = self.merge(plan, [self.frag("java", variant="17"), self.frag("java", variant="21")])
        self.assertEqual(rc, 1)

    def test_failed_job_result_fails_suite(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}}}
        rc, _ = self.merge(plan, [self.frag("meta")], ["meta=failure"])
        self.assertEqual(rc, 1)


class LintTests(unittest.TestCase):
    def test_repo_workflows_pass_lint(self):
        files = [str(p) for p in (ROOT / ".github/workflows").glob("*.yml")]
        r = subprocess.run([sys.executable, "-B", "-m", "tools.qa.workflow_lint", *files], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
