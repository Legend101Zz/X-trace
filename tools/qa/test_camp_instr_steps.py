import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_instr_steps as s  # noqa: E402


def sc(i, checks=True, eq=True, rec=True):
    return {"id": i, "scenarioChecksPassed": checks, "fingerprintEqualsBaseline": eq, "recordingVerdict": {"passed": rec}}


def by(steps):
    return {n: (st, note) for n, st, note in steps}


class T(unittest.TestCase):
    def test_missing_receipt_fails(self):
        self.assertEqual(by(s.instrumented_steps(None))["instrumented-run"][0], "fail")

    def test_all_good(self):
        r = {"scenarios": [sc("a"), sc("b")], "api": {"ok": True, "recordings": 5}, "problemClasses": {}, "recordingsWithSource": 3,
             "notes": {"stopCommand": {"exitCode": 3}, "launcherExitCode": 0}}
        d = by(s.instrumented_steps(r))
        # everything the instrumented run exercised passes; the lifecycle and focused-capture flows are judged by `flows`
        self.assertEqual({n for n, v in d.items() if v[0] != "pass"}, set(), d)
        for n in s.FLOW_STEPS:
            self.assertNotIn(n, d, "flow steps come only from the flows document")
        self.assertNotIn("executed line)", d["source-identity"][1].replace("not an executed line)", ""))
        self.assertIn("not an executed line", d["source-identity"][1])

    def test_source_identity_respects_binding_problem_classes(self):
        for cls in ("source-binding-unacceptable", "source-binding-missing", "no-source-file-line"):
            r = {"scenarios": [sc("a")], "api": {"ok": True, "recordings": 5}, "problemClasses": {cls: 2}, "recordingsWithSource": 1,
                 "notes": {"launcherExitCode": 0}}
            self.assertEqual(by(s.instrumented_steps(r))["source-identity"][0], "fail", cls)

    def test_overhead_needs_five_repeats(self):
        agg = {"baseline": {"p50Ms": 1, "p95Ms": 2, "n": 14}, "instrumented": {"p50Ms": 2, "p95Ms": 3, "n": 14}, "p50Ratio": 2, "p95Ratio": 1.5}
        d = by(s.overhead_steps({"aggregate": agg}))
        self.assertEqual((d["overhead-measurement"][0], d["overhead-repeats-ge-5"][0]), ("reported", "not-implemented"))
        self.assertEqual(by(s.overhead_steps({"aggregate": agg, "repeats": 5}))["overhead-repeats-ge-5"][0], "pass")
        self.assertEqual(by(s.overhead_steps(None))["overhead-repeats-ge-5"][0], "fail")

    def test_each_failure_is_visible(self):
        r = {"scenarios": [sc("a", eq=False), sc("b", rec=False)], "api": {"ok": True, "recordings": 5},
             "problemClasses": {"no-source-file-line": 2}, "notes": {"stopCommand": {"exitCode": 9, "notImplemented": True}}}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["instrumented-fingerprints-equal-baseline"][0], "fail")
        self.assertEqual(d["recordings-per-scenario"][0], "fail")
        self.assertEqual(d["source-identity"][0], "fail")
        self.assertEqual(d["launcher-exit-after-sigterm"][0], "fail")

    def test_flow_steps_come_from_the_document_and_missing_is_a_failure(self):
        self.assertEqual({n: st for n, st, _ in s.flow_steps(None)}, {n: "fail" for n in s.FLOW_STEPS})
        doc = {"steps": {n: {"status": "pass", "note": "ok"} for n in s.FLOW_STEPS}}
        self.assertEqual({st for _, st, _ in s.flow_steps(doc)}, {"pass"})
        doc["steps"]["frame-values"] = {"status": "fail", "note": "no captured binding"}
        del doc["steps"]["restart-reopen"]
        doc["steps"]["partial-recording-reopen"] = {"status": "skipped", "note": ""}
        d = by(s.flow_steps(doc))
        self.assertEqual(d["frame-values"], ("fail", "no captured binding"))
        self.assertEqual(d["restart-reopen"][0], "fail")
        self.assertEqual(d["partial-recording-reopen"][0], "fail")

    def test_zero_recordings_never_pass_source_identity(self):
        r = {"scenarios": [sc("a", rec=False)], "api": {"ok": True, "recordings": 0}, "problemClasses": {"no-recording-for-route": 1},
             "recordingsWithSource": 0, "notes": {}}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["source-identity"][0], "fail")
        self.assertEqual(d["recordings-per-scenario"][0], "fail")
        self.assertEqual(d["api-json-artifact"][0], "fail")  # nothing was saved, so nothing to hand over

    def test_no_baseline_is_fail_not_pass(self):
        r = {"scenarios": [{"id": "a", "scenarioChecksPassed": True, "fingerprintEqualsBaseline": None}],
             "api": {"ok": False, "reason": "viewer down"}, "problemClasses": {}, "notes": {}}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["instrumented-fingerprints-equal-baseline"][0], "fail")
        self.assertEqual(d["recordings-per-scenario"][0], "fail")

    def test_browser_and_tui(self):
        j = {"widths": [{"width": 320}], "linear": "pass", "canvas": "not-implemented", "overflowAt": []}
        d = by(s.browser_steps(j))
        self.assertEqual((d["browser-journeys-linear"][0], d["browser-journeys-canvas"][0]), ("pass", "not-implemented"))
        j["overflowAt"] = [320]
        self.assertEqual(by(s.browser_steps(j))["browser-journeys-linear"][0], "fail")
        self.assertEqual(by(s.tui_steps({"verdict": "not-implemented", "reason": "x"}))["tui-pty-transcript"][0], "not-implemented")
        self.assertEqual(by(s.tui_steps({"verdict": "weird"}))["tui-pty-transcript"][0], "fail")
        self.assertEqual(by(s.tui_steps(None))["tui-pty-transcript"][0], "fail")


if __name__ == "__main__":
    unittest.main()
