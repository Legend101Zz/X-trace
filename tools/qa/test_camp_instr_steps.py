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

    def test_shared_burst_diagnostics_reach_summary_without_crediting_scenarios(self):
        r = {"scenarios": [sc("serial"), sc("burst-a", rec=False), sc("burst-b", rec=False)],
             "api": {"ok": True, "recordings": 3},
             "burstRouteGroups": [{"evidenceScope": "burst-route-group", "recordingsMatchingRoute": 2,
                                   "recordingsWithSource": 0, "problems": ["source-binding-missing"]}],
             "problemClasses": {"attribution-ambiguous": 2, "source-binding-missing": 1},
             "recordingsWithSource": 1}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["instrumented-run"][0], "pass")
        self.assertEqual(d["recordings-per-scenario"][0], "fail")
        self.assertIn("1/3 scenarios", d["recordings-per-scenario"][1])
        self.assertIn("burst route groups", d["recordings-per-scenario"][1])
        self.assertIn('"source-binding-missing": 1', d["recordings-per-scenario"][1])
        self.assertEqual(d["source-identity"][0], "fail")
        self.assertIn("source-binding-missing", d["source-identity"][1])

    def test_missing_burst_boundary_recordings_fail_source_identity_with_other_sources(self):
        for fully_dropped in (False, True):
            with self.subTest(fully_dropped=fully_dropped):
                observed = int(not fully_dropped)
                scenarios = [sc("serial"), sc("burst-a", rec=False)]
                problems = ["count-below-minimum(need 2, have 1)"]
                if fully_dropped:
                    problems = ["burst-route-count-mismatch(requests 1, recordings 0)", "no-recording-for-route",
                                "count-below-minimum(need 1, have 0)"]
                else:
                    scenarios.append(sc("burst-b", rec=False))
                problems.append("burst-boundary-recordings-missing(missing 1)")
                classes = {"attribution-ambiguous": len(scenarios) - 1, **{p.split("(")[0]: 1 for p in problems}}
                groups = [{"requests": 1, "recordingsMatchingRoute": observed,
                           "recordingsWithSource": observed, "problems": problems}]
                if fully_dropped:
                    classes["burst-drops"] = 1
                    groups.append({"requests": 1, "recordingsMatchingRoute": 1, "recordingsWithSource": 1, "problems": []})
                sourced = 1 + sum(g["recordingsWithSource"] for g in groups)
                r = {"scenarios": scenarios, "api": {"ok": True, "recordings": sourced},
                     "burstRouteGroups": groups, "problemClasses": classes, "recordingsWithSource": sourced}
                d = by(s.instrumented_steps(r))
                self.assertEqual(d["instrumented-run"][0], "pass")
                self.assertEqual(d["recordings-per-scenario"][0], "fail")
                self.assertIn(f"1/{len(scenarios)} scenarios", d["recordings-per-scenario"][1])
                self.assertIn('"burst-boundary-recordings-missing": 1', d["recordings-per-scenario"][1])
                self.assertEqual(d["source-identity"][0], "fail")
                self.assertIn(f"{sourced} recordings carry a matched .java file", d["source-identity"][1])
                self.assertIn("burst-boundary-recordings-missing", d["source-identity"][1])

    def test_failed_readback_still_reports_unavailable_burst_details(self):
        r = {"scenarios": [sc("burst", rec=False)], "api": {"ok": False, "reason": "recordings list HTTP 503"},
             "burstRouteGroups": [{"problems": ["burst-recording-detail-unavailable(missing 2)", "no-source-file-line"]}],
             "problemClasses": {"burst-recording-detail-unavailable": 1, "no-source-file-line": 1}}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["recordings-per-scenario"][0], "fail")
        self.assertIn("recordings list HTTP 503", d["recordings-per-scenario"][1])
        self.assertIn('"burst-recording-detail-unavailable": 1', d["recordings-per-scenario"][1])
        self.assertEqual(d["source-identity"][0], "fail")
        self.assertIn("burst-recording-detail-unavailable", d["source-identity"][1])
        self.assertEqual(d["api-json-artifact"][0], "fail")

    def test_api_level_read_gaps_fail_source_identity_with_sourced_recordings(self):
        r = {"scenarios": [sc("a")], "api": {"ok": True, "recordings": 2}, "recordingsWithSource": 1}
        self.assertEqual(by(s.instrumented_steps(r))["source-identity"][0], "pass")
        for gap, problem, artifact in (
            ({"listReadGap": "recordings list HTTP 503"}, "api-recordings-list-incomplete", "incomplete API listing"),
            ({"incompleteDetails": 1}, "recording-detail-incomplete", "1 incomplete recording details"),
        ):
            with self.subTest(gap=gap):
                d = by(s.instrumented_steps({**r, "api": {**r["api"], **gap}}))
                self.assertEqual(d["source-identity"][0], "fail")
                self.assertIn(problem, d["source-identity"][1])
                self.assertIn("1 recordings carry a matched .java file", d["source-identity"][1])
                self.assertIn(artifact, d["api-json-artifact"][1])
                self.assertEqual(d["api-json-artifact"][0], "fail")
                self.assertEqual(d["recordings-per-scenario"][0], "fail")

    def test_mixed_burst_source_coverage_needs_support_for_every_expectation(self):
        r = {"scenarios": [sc("a", rec=False), sc("b", rec=False)], "api": {"ok": True, "recordings": 2},
             "recordingsWithSource": 2, "problemClasses": {"burst-frame-expectations-differ": 1}}
        group = {"problems": ["burst-frame-expectations-differ"], "recordingsWithSource": 2}
        for coverage in (None, [True], [True, False], [True, True]):
            with self.subTest(coverage=coverage):
                entry = group if coverage is None else {**group, "frameExpectations": [
                    {"framesCovered": True, "sourceCovered": covered} for covered in coverage]}
                d = by(s.instrumented_steps({**r, "burstRouteGroups": [entry]}))
                self.assertEqual(d["recordings-per-scenario"][0], "fail")
                self.assertIn("0/2 scenarios", d["recordings-per-scenario"][1])
                self.assertEqual(d["source-identity"][0], "pass" if coverage == [True, True] else "fail")
                if coverage != [True, True]:
                    self.assertIn("burst-source-expectation-unresolved", d["source-identity"][1])

    def test_overhead_needs_five_repeats(self):
        agg = {"baseline": {"p50Ms": 1, "p95Ms": 2, "n": 14}, "instrumented": {"p50Ms": 2, "p95Ms": 3, "n": 14}, "p50Ratio": 2, "p95Ratio": 1.5}
        d = by(s.overhead_steps({"aggregate": agg}))
        self.assertEqual((d["overhead-measurement"][0], d["overhead-repeats-ge-5"][0]), ("fail", "fail"))
        self.assertEqual(by(s.overhead_steps({"aggregate": agg, "repeats": 5}))["overhead-repeats-ge-5"][0], "fail")
        from test_camp_overhead import paired_runs
        import camp_overhead
        valid = camp_overhead.compare_interleaved(paired_runs())
        self.assertEqual(by(s.overhead_steps(valid))["overhead-repeats-ge-5"][0], "pass")
        self.assertEqual(by(s.overhead_steps(valid))["overhead-measurement"][0], "reported")
        valid["runs"][1]["startedNs"] = valid["runs"][0]["startedNs"]
        self.assertEqual(by(s.overhead_steps(valid))["overhead-repeats-ge-5"][0], "fail")
        self.assertEqual(by(s.overhead_steps(None))["overhead-repeats-ge-5"][0], "fail")

    def test_accommodations_are_visible_and_never_product_passes(self):
        r = {"scenarios": [], "notes": {"accommodations": {"pace_seconds": 0.4, "drain_seconds": 0, "reason": "writer bound"}}}
        d = by(s.instrumented_steps(r))
        self.assertEqual(d["unpaced-load-not-exercised"][0], "reported")
        self.assertIn("pace_seconds", d["unpaced-load-not-exercised"][1])
        d = by(s.tui_steps({"verdict": "pass", "observations": {"accommodation": "route read from detail", "open_after": 0.1}}))
        self.assertEqual(d["tui-navigation-accommodation"][0], "reported")
        self.assertIn("detail", d["tui-navigation-accommodation"][1])
        self.assertIn("focused-canary-injection", s.FLOW_STEPS)
        for name in ("focused-redaction-control", "focused-value-control", "standard-no-values"):
            self.assertIn(name, s.FLOW_STEPS)

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

    def test_privacy_scope_is_visible_without_becoming_a_pass(self):
        doc = {"steps": {"privacy-scope": {"status": "reported", "note": "focused ordinary Strings are captured"}}}
        steps = by(s.flow_steps(doc))
        self.assertEqual(steps["privacy-scope"], ("reported", "focused ordinary Strings are captured"))
        self.assertEqual(steps["focused-redaction-control"][0], "fail")
        self.assertEqual(steps["standard-no-values"][0], "fail")

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
