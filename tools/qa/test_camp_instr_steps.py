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
        # everything the harness exercised passes; the record+stop flow is not exercised and stays not-implemented
        self.assertEqual({n for n, v in d.items() if v[0] != "pass"}, {"record-stop-flow"}, d)
        self.assertEqual(d["record-stop-flow"][0], "not-implemented")

    def test_each_failure_is_visible(self):
        r = {"scenarios": [sc("a", eq=False), sc("b", rec=False)], "api": {"ok": True, "recordings": 5},
             "problemClasses": {"no-source-file-line": 2}, "notes": {"stopCommand": {"exitCode": 9, "notImplemented": True}}}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["instrumented-fingerprints-equal-baseline"][0], "fail")
        self.assertEqual(d["recordings-per-scenario"][0], "fail")
        self.assertEqual(d["source-identity"][0], "fail")
        self.assertEqual(d["record-stop-flow"][0], "not-implemented")
        self.assertEqual(d["launcher-exit-after-sigterm"][0], "fail")

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
