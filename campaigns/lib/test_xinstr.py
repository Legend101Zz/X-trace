import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xinstr  # noqa: E402


def rec(method, path, status, symbols=("OwnerController.showOwner", "OwnerRepository.findById"), src=True, kind="responded",
        resp_symbol=None):
    evs = [{"kind": "recording_event_kind:request_update", "symbol": f"http.request {method} {path}", "interaction": {"method": method}, "source": None}]
    for sy in symbols:
        evs.append({"kind": "recording_event_kind:frame_enter", "symbol": sy, "interaction": {},
                    "source": {"path": "src/main/java/X.java", "startLine": 3, "status": "matched"} if src else None,
                    "sourceBinding": "verified"})
    evs.append({"kind": "recording_event_kind:response", "symbol": resp_symbol or f"http.response {status}", "interaction": {}, "source": None})
    return {"events": evs, "outcome": {"kind": kind, "httpStatus": status if kind == "responded" else None}}


class T(unittest.TestCase):
    def test_percentile(self):
        self.assertIsNone(xinstr.percentile([], 50))
        self.assertEqual(xinstr.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(xinstr.percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(xinstr.percentile([7], 95), 7)

    def test_readiness_wrapped_and_plain(self):
        t = "x\n" + '{"ok":true,"data":{"kind":"viewer_ready","origin":"http://127.0.0.1:5","url":"http://127.0.0.1:5/#' + "A" * 43 + '"}}'
        r = xinstr.parse_readiness(t)
        self.assertEqual(r["origin"], "http://127.0.0.1:5")
        self.assertEqual(xinstr.bootstrap_token(r["url"]), "A" * 43)
        self.assertIsNone(xinstr.parse_readiness("no json"))

    def test_route_regex(self):
        rx = xinstr.route_regex("/owners/{ownerId}/edit")
        self.assertTrue(rx.match("/owners/12/edit"))
        self.assertFalse(rx.match("/owners/12"))

    def test_analyze_pass_and_each_failure(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": ["controller", "repository"]}]}
        ok = xinstr.analyze({"a": rec("GET", "/owners/4", 200)}, exp)
        self.assertTrue(ok["s"]["passed"], ok)
        self.assertEqual(xinstr.analyze({}, exp)["s"]["expectations"][0]["problems"], ["no-recording-for-route"])
        bad = xinstr.analyze({"a": rec("GET", "/owners/4", 500)}, exp)["s"]["expectations"][0]["problems"]
        self.assertTrue(bad[0].startswith("http-outcome-mismatch"))
        nof = xinstr.analyze({"a": rec("GET", "/owners/4", 200, symbols=())}, exp)["s"]["expectations"][0]["problems"]
        self.assertIn("no-controller-frame", nof)
        self.assertIn("no-repository-frame", nof)
        un = xinstr.analyze({"a": rec("GET", "/owners/4", 200, kind="unobserved")}, exp)["s"]["expectations"][0]["problems"]
        self.assertEqual(un, ["outcome-unobserved"])
        nos = xinstr.analyze({"a": rec("GET", "/owners/4", 200, src=False)}, exp)["s"]["expectations"][0]["problems"]
        self.assertEqual(nos, ["no-source-file-line"])
        self.assertEqual(xinstr.problem_classes(xinstr.analyze({"a": rec("GET", "/owners/4", 500)}, exp)),
                         {"http-outcome-mismatch": 1})

    def test_method_must_match(self):
        exp = {"s": [{"method": "POST", "route": "/owners/new", "status": 302, "layers": []}]}
        self.assertEqual(xinstr.analyze({"a": rec("GET", "/owners/new", 302)}, exp)["s"]["expectations"][0]["problems"],
                         ["no-recording-for-route"])

    def test_min_count(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": [], "minCount": 3}]}
        two = {"a": rec("GET", "/owners/1", 200), "b": rec("GET", "/owners/2", 200)}
        self.assertFalse(xinstr.analyze(two, exp)["s"]["passed"])
        two["c"] = rec("GET", "/owners/3", 200)
        self.assertTrue(xinstr.analyze(two, exp)["s"]["passed"])

    def test_literal_recording_does_not_satisfy_template(self):
        exp = {"a": [{"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": []}],
               "b": [{"method": "GET", "route": "/owners/new", "status": 200, "layers": []}]}
        v = xinstr.analyze({"x": rec("GET", "/owners/new", 200)}, exp)
        self.assertEqual(v["a"]["expectations"][0]["problems"], ["no-recording-for-route"])
        self.assertTrue(v["b"]["passed"])

    def test_recorded_template_matches_by_equality(self):
        exp = {"a": [{"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": []},
                     {"method": "GET", "route": "/owners/{ownerId}/edit", "status": 200, "layers": []}]}
        v = xinstr.analyze({"x": rec("GET", "/owners/{ownerId}/edit", 200)}, exp)["a"]["expectations"]
        self.assertEqual(v[0]["problems"], ["no-recording-for-route"])
        self.assertEqual(v[1]["problems"], [])

    def test_count_below_minimum_message(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": [], "minCount": 5}]}
        p = xinstr.analyze({"a": rec("GET", "/owners/1", 200)}, exp)["s"]["expectations"][0]["problems"]
        self.assertEqual(p, ["count-below-minimum(need 5, have 1)"])
        self.assertEqual(xinstr.problem_classes(xinstr.analyze({"a": rec("GET", "/owners/1", 200)}, exp)), {"count-below-minimum": 1})

    def test_order_attribution_rejects_neighbour_recordings(self):
        """Adjacent scenarios (290 ms and 177 ms apart, as in the pushed run): the redirect recorded as 200 belongs to the
        neighbour's request, so the validation scenario must not be judged on it."""
        exp = {"validation": [{"method": "POST", "route": "/owners/new", "status": 200, "layers": []}],
               "roundtrip": [{"method": "POST", "route": "/owners/new", "status": 302, "layers": []}]}
        a, b = rec("POST", "/owners/new", 200), rec("POST", "/owners/new", 200)  # product bug: the 302 is recorded as 200
        a["_openedAt"], b["_openedAt"] = "2026-10-09T10:00:00.000Z", "2026-10-09T10:00:00.290Z"
        sent = [("validation", "POST", "/owners/new"), ("roundtrip", "POST", "/owners/new")]
        v = xinstr.analyze({"a": a, "b": b}, exp, sent)
        self.assertTrue(v["validation"]["passed"])
        self.assertEqual(v["validation"]["expectations"][0]["recordingsMatchingRoute"], 1)
        self.assertEqual(v["roundtrip"]["expectations"][0]["problems"], ["http-outcome-mismatch(expected 302, saw 200)"])
        self.assertEqual(v["validation"]["attribution"], "order")

    def test_extra_recordings_for_a_route_are_ambiguous_not_guessed(self):
        exp = {"validation": [{"method": "POST", "route": "/owners/new", "status": 200, "layers": []}]}
        a, b = rec("POST", "/owners/new", 200), rec("POST", "/owners/new", 200)
        a["_openedAt"], b["_openedAt"] = "2026-10-09T10:00:00Z", "2026-10-09T10:00:01Z"
        v = xinstr.analyze({"a": a, "b": b}, exp, [("validation", "POST", "/owners/new")])
        self.assertEqual(v["validation"]["expectations"][0]["problems"], ["attribution-ambiguous(recordings 2, requests 1)"])
        self.assertEqual(xinstr.problem_classes(v), {"attribution-ambiguous": 1})
        # too few recordings is equally unattributable; zero stays no-recording-for-route
        v = xinstr.analyze({"a": a}, exp, [("validation", "POST", "/owners/new"), (None, "POST", "/owners/new")])
        self.assertTrue(v["validation"]["expectations"][0]["problems"][0].startswith("attribution-ambiguous"))
        self.assertEqual(xinstr.analyze({}, exp, [("validation", "POST", "/owners/new")])["validation"]["expectations"][0]["problems"],
                         ["no-recording-for-route"])

    def test_non_scenario_canary_traffic_counts_as_a_request(self):
        exp = {"s": [{"method": "POST", "route": "/owners/new", "status": 200, "layers": []}]}
        a, b = rec("POST", "/owners/new", 200), rec("POST", "/owners/new", 302)
        a["_openedAt"], b["_openedAt"] = "2026-10-09T10:00:00Z", "2026-10-09T10:00:01Z"
        v = xinstr.analyze({"a": a, "b": b}, exp, [("s", "POST", "/owners/new"), (None, "POST", "/owners/new")])
        self.assertTrue(v["s"]["passed"])

    def test_unknown_recording_time_is_ambiguous(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]}
        v = xinstr.analyze({"u": rec("GET", "/owners/1", 200)}, exp, [("s", "GET", "/owners/1")])
        self.assertEqual(v["s"]["expectations"][0]["problems"], ["attribution-ambiguous(recording time unknown)"])

    def test_uuidv7_time(self):
        d = {"recordingId": "0199c1a2-b3c4-7abc-8def-0123456789ab"}
        self.assertEqual(xinstr.recording_time(d), int("0199c1a2b3c4", 16) / 1000.0)
        self.assertIsNone(xinstr.recording_time({"recordingId": "nope"}))

    def test_source_must_be_on_layer_frame_with_acceptable_binding(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": ["controller"]}]}
        r = rec("GET", "/owners/1", 200, symbols=("OwnerController.show",), src=False)
        r["events"].append({"kind": "recording_event_kind:frame_enter", "symbol": "Other.helper", "interaction": {},
                            "source": {"path": "src/X.java", "startLine": 3, "status": "matched"}})
        self.assertEqual(xinstr.analyze({"a": r}, exp)["s"]["expectations"][0]["problems"], ["no-source-file-line"])
        good = rec("GET", "/owners/1", 200, symbols=("OwnerController.show",))
        good["events"][1]["sourceBinding"] = "SOURCE_BINDING_ATTESTATION_MISSING"
        self.assertEqual(xinstr.analyze({"a": good}, exp)["s"]["expectations"][0]["problems"], ["source-binding-unacceptable"])
        good["events"][1]["sourceBinding"] = "verified"
        self.assertTrue(xinstr.analyze({"a": good}, exp)["s"]["passed"])
        del good["events"][1]["sourceBinding"]  # required by the contract: absent is a violation, not "unreported = fine"
        self.assertEqual(xinstr.analyze({"a": good}, exp)["s"]["expectations"][0]["problems"], ["source-binding-missing"])

    def _exc_rec(self, typ="java.lang.RuntimeException", kind="exception_propagated"):
        r = rec("GET", "/oups", None, symbols=("CrashController.triggerException",), kind=kind,
                resp_symbol="http.response unavailable")
        r["outcome"] = {"kind": kind, "httpStatus": None,
                        "exception": {"exceptionType": typ, "message": None} if kind == "exception_propagated" else None}
        return r

    def test_exception_propagated_is_an_observed_outcome(self):
        exp = {"s": [{"method": "GET", "route": "/oups", "status": 500, "exception": "RuntimeException",
                      "layers": ["controller"], "layerHints": {"controller": "CrashController"}}]}
        v = xinstr.analyze({"a": self._exc_rec()}, exp)["s"]["expectations"][0]
        self.assertEqual(v["problems"], [], v)
        self.assertEqual(v["recordingsWithStatus"], 1)

    def test_exception_propagated_needs_the_expected_exception_type(self):
        exp = {"s": [{"method": "GET", "route": "/oups", "status": 500, "exception": "RuntimeException", "layers": []}]}
        wrong = xinstr.analyze({"a": self._exc_rec("java.lang.IllegalStateException")}, exp)["s"]["expectations"][0]["problems"]
        self.assertTrue(wrong[0].startswith("http-outcome-mismatch"), wrong)
        none = {"s": [{"method": "GET", "route": "/oups", "status": 500, "layers": []}]}  # no exception expectation: no match
        self.assertTrue(xinstr.analyze({"a": self._exc_rec()}, none)["s"]["expectations"][0]["problems"][0]
                        .startswith("http-outcome-mismatch"))
        ok200 = {"s": [{"method": "GET", "route": "/oups", "status": 200, "exception": "RuntimeException", "layers": []}]}
        self.assertTrue(xinstr.analyze({"a": self._exc_rec()}, ok200)["s"]["expectations"][0]["problems"][0]
                        .startswith("http-outcome-mismatch"))  # an exception never satisfies a 2xx expectation

    def test_client_aborted_and_unobserved_are_not_observed(self):
        for kind in ("client_aborted", "unobserved"):
            exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]}
            self.assertEqual(xinstr.analyze({"a": rec("GET", "/owners/1", 200, kind=kind)}, exp)["s"]["expectations"][0]["problems"][-1:],
                             ["outcome-unobserved"] if kind else [])

    def test_legacy_exception_kind_is_not_a_product_kind(self):
        self.assertNotIn("exception", xinstr.OBSERVED_OUTCOME_KINDS)

    def test_burst_scenario_does_not_break_attribution_of_paced_scenarios(self):
        exp = {"a": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}],
               "b": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": [], "minCount": 5}]}
        # 2 paced requests of `a`, then 5 burst requests of `b`, then one non-scenario request; the product kept 2 + 3 + 1
        sent = [("a", "GET", "/owners/1"), ("a", "GET", "/owners/2")] + [("b", "GET", f"/owners/{i}") for i in range(5)] \
            + [(None, "GET", "/owners/9")]
        d = {f"{i:02d}": rec("GET", f"/owners/{i}", 200) for i in range(6)}
        for i, det in enumerate(d.values()):
            det["recordingId"] = f"01a12327-{0x100 + i:04x}-7000-8000-000000000000"
            det["_openedAt"] = f"2026-10-10T00:00:0{i}Z"
        v = xinstr.analyze(d, exp, sent, frozenset({"b"}))
        self.assertTrue(v["a"]["passed"], v["a"])
        self.assertEqual(v["a"]["expectations"][0]["recordingsMatchingRoute"], 2)
        self.assertEqual(v["b"]["expectations"][0]["recordingsMatchingRoute"], 3)  # 4 left minus the later non-scenario request
        self.assertEqual(v["b"]["expectations"][0]["problems"], ["count-below-minimum(need 5, have 3)"])

    def test_burst_with_fewer_recordings_than_paced_requests_is_ambiguous(self):
        exp = {"a": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]}
        sent = [("a", "GET", "/owners/1"), ("a", "GET", "/owners/2"), ("b", "GET", "/owners/3")]
        d = {"x": rec("GET", "/owners/1", 200)}
        d["x"]["_openedAt"] = "2026-10-10T00:00:00Z"
        v = xinstr.analyze(d, exp, sent, frozenset({"b"}))
        self.assertTrue(v["a"]["expectations"][0]["problems"][0].startswith("attribution-ambiguous"))

    def test_silent_viewer_hits_the_deadline(self):
        import os, stat, tempfile, time
        with tempfile.TemporaryDirectory() as d:
            exe = pathlib.Path(d) / "xtrace"
            exe.write_text("#!/bin/sh\nexec sleep 20\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            t0 = time.time()
            with self.assertRaises(RuntimeError):
                xinstr.start_viewer(str(exe), pathlib.Path(d), dict(os.environ), pathlib.Path(d) / "v.log", timeout=2.0)
            self.assertLess(time.time() - t0, 10)


if __name__ == "__main__":
    unittest.main()
