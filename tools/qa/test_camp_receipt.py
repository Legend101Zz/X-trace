import json
import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_receipt as cr  # noqa: E402

CAMP = {"upstream": {"sha": "a" * 40}, "tagException": {}, "scenarios": [{"id": "s1"}, {"id": "s2"}]}


class T(unittest.TestCase):
    def build(self, steps):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "summary.json").write_text("{}")
            return cr.build_receipt(root, "p", "CAMPAIGN-X", "b" * 40, CAMP, {"steps": steps}, None, None, None, "1")

    def test_any_failed_or_not_implemented_means_failed(self):
        r = self.build([{"step": "a", "status": "pass"}, {"step": "b", "status": "not-implemented"}])
        self.assertEqual(r["result"], "failed")
        self.assertEqual(r["failedChecks"], ["b"])
        self.assertFalse([c for c in r["checks"] if c["name"] == "b"][0]["reached"])

    def test_all_pass_is_passed_but_never_release(self):
        r = self.build([{"step": "a", "status": "pass"}, {"step": "o", "status": "reported"}])
        self.assertEqual(r["result"], "passed")
        self.assertTrue(r["nonRelease"])
        self.assertEqual(r["signatures"], [])
        self.assertEqual(len(r["checks"]), 1)
        self.assertEqual([x["name"] for x in r["reported"]], ["o"])  # visible, but never a passed check

    def test_result_stays_failed_while_gating_capability_rows_are_not_implemented(self):
        import camp_instr_steps as ci
        good = {"id": "a", "scenarioChecksPassed": True, "fingerprintEqualsBaseline": True, "recordingVerdict": {"passed": True}}
        inst = {"scenarios": [good], "api": {"ok": True, "recordings": 3}, "problemClasses": {}, "recordingsWithSource": 3,
                "notes": {"launcherExitCode": 0}}
        agg = {"baseline": {"p50Ms": 1, "p95Ms": 2, "n": 3}, "instrumented": {"p50Ms": 1, "p95Ms": 2, "n": 3}, "p50Ratio": 1, "p95Ratio": 1}
        steps = [{"step": n, "status": st, "note": note} for n, st, note in
                 ci.instrumented_steps(inst) + ci.overhead_steps({"aggregate": agg})
                 + ci.flow_steps({"steps": {n: {"status": "not-implemented", "note": "x"} for n in ci.FLOW_STEPS}})]
        r = self.build(steps)
        self.assertEqual(r["result"], "failed")
        for n in ("active-line-frames", "frame-values", "restart-reopen", "partial-recording-reopen", "record-stop-flow",
                  "overhead-repeats-ge-5"):
            self.assertIn(n, r["failedChecks"])
        missing = self.build([{"step": n, "status": st, "note": note} for n, st, note in ci.flow_steps(None)])
        self.assertEqual(missing["result"], "failed")  # a flows run that produced no document can never read as green

    def test_no_steps_is_not_passed(self):
        self.assertEqual(self.build([])["result"], "failed")

    def test_scenarios_follow_campaign(self):
        r = self.build([{"step": "a", "status": "pass"}])
        self.assertEqual([s["name"] for s in r["attestation"]["scenarios"]], ["s1", "s2"])
        json.dumps(r)


if __name__ == "__main__":
    unittest.main()
