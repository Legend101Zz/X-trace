import pathlib
import sys
import unittest
from unittest import mock
import subprocess

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xinstr  # noqa: E402


BURST_CORRELATION_PROBLEM = f"attribution-ambiguous({xinstr.REQUEST_CORRELATION_GAP})"


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
    def test_live_list_failure_keeps_only_fixed_problem_metadata_and_never_retries(self):
        import json
        import tempfile
        for status, code in ((422, "XTR-PORT-CORRUPTION"), (500, "XTR-PORT-TRANSPORT"),
                             (500, "XTR-PORT-INTERNAL")):
            with self.subTest(status=status, code=code):
                problem = {"code": code, "requestId": "01900000-0000-7000-8000-000000000001",
                           "detail": "private source path", "message": "private captured value"}
                client = mock.Mock()
                client.get.return_value = (status, problem)
                with tempfile.TemporaryDirectory() as td, \
                     mock.patch.object(xinstr.time, "monotonic", return_value=1):
                    result = xinstr.wait_burst_boundary(client, pathlib.Path(td), [], {}, {}, 3)
                    self.assertFalse(result["verified"])
                    self.assertEqual(result["readError"], f"recordings list HTTP {status}")
                    self.assertEqual(result["readProblem"], {"httpStatus": status, "code": code,
                                                             "requestId": problem["requestId"]})
                    self.assertNotIn("private", json.dumps(result))
                client.get.assert_called_once()
                self.assertIsNone(client.deadline)

    def test_read_problem_rejects_unknown_codes_and_private_request_ids(self):
        for doc in (None, [], "private", {"code": "XTR-private", "requestId": "private"},
                    {"code": "XTR-PORT-PRIVATE", "requestId": "private"},
                    {"code": "XTR-PORT-TRANSPORT\nprivate", "requestId": "private"},
                    {"code": ["XTR-STORE-OBJECT-IO"], "requestId": 1}):
            self.assertEqual(xinstr.read_problem(500, doc), {"httpStatus": 500, "code": None, "requestId": None})

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

    def test_layers_use_the_declaring_class_not_the_package_or_method(self):
        symbols = ("org.springframework.samples.petclinic.owner.OwnerController.showOwner",
                   "org.springframework.samples.petclinic.owner.OwnerRepository.findById",
                   "org.springframework.data.repository.CrudRepository.save",
                   "org.example.Other.OwnerRepository", "org.example.RepositoryTools.helper",
                   "org.example.DataDao.find", "org.example.OwnerResource.show")
        detail = rec("GET", "/owners/1", 200, symbols=symbols)
        for layer, hint, expected in (
                ("controller", "OwnerController", symbols[:1]),
                ("repository", "OwnerRepository", symbols[1:2]),
                ("repository", ["OwnerRepository", "org.springframework.data.repository.CrudRepository"], symbols[1:3]),
                ("repository", "DataDao", symbols[5:6]),
                ("controller", "OwnerResource", symbols[6:7])):
            with self.subTest(layer=layer, hint=hint):
                self.assertEqual([ev["symbol"] for ev in xinstr.layer_frames(detail, layer, hint)], list(expected))
        # Neither a method named like a repository nor a package segment proves that layer.
        self.assertEqual(xinstr.layer_frames(rec("GET", "/", 200, symbols=(symbols[3],)), "repository"), [])
        self.assertEqual(xinstr.layer_frames(rec("GET", "/", 200, symbols=("org.Repository.Helper.work",)), "repository"), [])
        self.assertEqual(xinstr.layer_frames(detail, "repository", "UnrelatedRepository"), [])

    def test_exact_symbol_hint_requires_both_declaring_class_and_method(self):
        symbol = "org.springframework.data.jpa.repository.JpaRepository.saveAndFlush"
        hints = ["OwnerRepository", "org.springframework.data.repository.CrudRepository", symbol]
        expectation = {"pet": [{"method": "POST", "route": "/pets/new", "status": 302,
                                "layers": ["repository"], "layerHints": {"repository": hints}}]}
        for observed, accepted in ((symbol, True),
                                   ("org.springframework.data.jpa.repository.JpaRepository.findAll", False),
                                   ("org.example.JpaRepository.saveAndFlush", False),
                                   (symbol + "Extra", False),
                                   ("org.example.OwnerRepository.save", True),
                                   ("org.springframework.data.repository.CrudRepository.save", True)):
            with self.subTest(symbol=observed):
                detail = rec("POST", "/pets/new", 302, symbols=(observed,))
                frames = xinstr.layer_frames(detail, "repository", hints)
                self.assertEqual([ev["symbol"] for ev in frames], [observed] if accepted else [])
                self.assertEqual(bool(xinstr.layer_frames(detail, "repository", symbol)), observed == symbol)
                verdict = xinstr.analyze({"r": detail}, expectation)["pet"]
                self.assertEqual(verdict["passed"], accepted, verdict)
                if not accepted:
                    self.assertIn("no-repository-frame", verdict["expectations"][0]["problems"])
        # An exact hint still requires the declaring class to identify the layer.
        other = "org.example.Helper.saveAndFlush"
        self.assertEqual(xinstr.layer_frames(rec("POST", "/pets/new", 302, symbols=(other,)),
                                             "repository", other), [])

    def test_inherited_repository_frame_keeps_its_observed_symbol_and_missing_source(self):
        symbol = "org.springframework.data.repository.CrudRepository.save"
        detail = rec("POST", "/owners/new", 302, symbols=(symbol,), src=False)
        expectation = {"s": [{"method": "POST", "route": "/owners/new", "status": 302,
                              "layers": ["repository"], "layerHints": {"repository": ["OwnerRepository", symbol.rsplit(".", 1)[0]]}}]}
        verdict = xinstr.analyze({"r": detail}, expectation)["s"]
        self.assertEqual(verdict["expectations"][0]["layers"]["repository"]["recordingsWithFrame"], 1)
        self.assertEqual(verdict["expectations"][0]["problems"], ["no-source-file-line"])
        self.assertEqual(verdict["frameSymbols"], [symbol])

    def test_exact_outcome_multiset_rejects_missing_extra_duplicate_and_wrong_statuses(self):
        exp = {"s": [{"method": "POST", "route": "/owners/{id}/pets/new", "statuses": [302, 200], "layers": []}]}
        for statuses, passed in (([302, 200], True), ([200, 302], True), ([302], False), ([200], False),
                                 ([302, 302], False), ([200, 200], False), ([302, 200, 200], False),
                                 ([302, 500], False), ([302, None], False)):
            with self.subTest(statuses=statuses):
                details = {str(i): rec("POST", "/owners/1/pets/new", s) for i, s in enumerate(statuses)}
                verdict = xinstr.analyze(details, exp)["s"]
                self.assertEqual(verdict["passed"], passed, verdict)
                self.assertEqual(verdict["expectations"][0]["expectedStatuses"], [302, 200])
                if not passed:
                    self.assertTrue(verdict["expectations"][0]["problems"][0].startswith("http-outcome-multiset-mismatch"))

    def test_outcome_multiset_still_requires_observed_kinds_layers_and_source(self):
        exp = {"s": [{"method": "POST", "route": "/pets/new", "statuses": [302, 200], "layers": ["controller"]}]}
        for changes, problem in (({"kind": "unobserved"}, "outcome-unobserved"),
                                 ({"symbols": ()}, "no-controller-frame"), ({"src": False}, "no-source-file-line")):
            details = {str(i): rec("POST", "/pets/new", status, **changes) for i, status in enumerate((302, 200))}
            self.assertIn(problem, xinstr.analyze(details, exp)["s"]["expectations"][0]["problems"])

    def test_outcome_multisets_are_compared_after_serial_attribution(self):
        exp = {"pet": [{"method": "POST", "route": "/pets/new", "statuses": [302, 200], "layers": []}],
               "other": [{"method": "POST", "route": "/pets/new", "status": 500, "layers": []}]}
        details = {str(i): {**rec("POST", "/pets/new", status), "_openedAt": f"2026-10-10T00:00:0{i}Z",
                            "completion": "complete"} for i, status in enumerate((302, 200, 500))}
        sent = [(sid, "POST", "/pets/new") for sid in ("pet", "pet", "other")]
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        for serial in (None, boundary):
            verdict = xinstr.analyze(details, exp, sent, serial_boundary=serial)
            self.assertTrue(all(v["passed"] for v in verdict.values()), verdict)
            self.assertEqual(verdict["pet"]["recordingsAttributed"], 2)

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
        r["events"].append({"kind": "recording_event_kind:frame_throw", "symbol": "CrashController.triggerException",
                            "exception": {"exceptionType": typ}})
        return r

    def test_application_throw_type_is_distinct_from_the_boundary_wrapper(self):
        detail = self._exc_rec()
        detail["outcome"]["exception"]["exceptionType"] = "jakarta.servlet.ServletException"
        detail["events"].append({"kind": "recording_event_kind:frame_throw", "symbol": "FrameworkFilter.doFilter",
                                 "exception": {"exceptionType": "jakarta.servlet.ServletException"}})
        exp = {"outcome": "exception_propagated", "exception": "RuntimeException", "status": None,
               "layerHints": {"controller": "CrashController"}}
        self.assertTrue(xinstr.outcome_matches(detail, exp))
        for change in ({"exception": None}, {"exception": {"exceptionType": None}},
                       {"exception": {"exceptionType": "java.lang.IllegalStateException"}},
                       {"kind": "recording_event_kind:frame_exit"}, {"symbol": "FrameworkFilter.doFilter"}):
            with self.subTest(change=change):
                candidate = {**detail, "events": [*detail["events"][:-2], {**detail["events"][-2], **change}, detail["events"][-1]]}
                self.assertFalse(xinstr.outcome_matches(candidate, exp))
        # An outcome type alone cannot replace the typed application throw.
        detail = self._exc_rec()
        detail["events"].pop()
        self.assertFalse(xinstr.outcome_matches(detail, exp))
        detail = self._exc_rec()
        self.assertFalse(xinstr.outcome_matches(detail, {**exp, "exception": "ServletException"}))

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

    def test_explicit_propagated_outcome_requires_no_final_status_and_the_expected_type(self):
        exp = {"s": [{"method": "GET", "route": "/oups", "status": None,
                      "outcome": "exception_propagated", "exception": "RuntimeException", "layers": ["controller"]}]}
        verdict = xinstr.analyze({"r": self._exc_rec()}, exp)["s"]["expectations"][0]
        self.assertTrue(verdict["passed"], verdict)
        self.assertIsNone(verdict["expectedStatus"])
        self.assertEqual(verdict["expectedOutcome"], "exception_propagated")
        for detail in (self._exc_rec("java.lang.IllegalStateException"), self._exc_rec(kind="unobserved"),
                       rec("GET", "/oups", 500), self._exc_rec("jakarta.servlet.ServletException")):
            with self.subTest(detail=detail):
                self.assertFalse(xinstr.analyze({"r": detail}, exp)["s"]["passed"])
        # Even a matching exception cannot make an observed final status into a withheld one.
        detail = self._exc_rec()
        detail["outcome"]["httpStatus"] = 500
        self.assertFalse(xinstr.analyze({"r": detail}, exp)["s"]["passed"])

    def test_client_aborted_and_unobserved_are_not_observed(self):
        for kind in ("client_aborted", "unobserved"):
            exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]}
            self.assertEqual(xinstr.analyze({"a": rec("GET", "/owners/1", 200, kind=kind)}, exp)["s"]["expectations"][0]["problems"][-1:],
                             ["outcome-unobserved"] if kind else [])

    def test_legacy_exception_kind_is_not_a_product_kind(self):
        self.assertNotIn("exception", xinstr.OBSERVED_OUTCOME_KINDS)

    def test_burst_without_correlation_never_credits_serial_or_burst_requests(self):
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
        for sid in ("a", "b"):
            self.assertFalse(v[sid]["passed"])
            self.assertEqual(v[sid]["attribution"], "ambiguous")
            self.assertEqual(v[sid]["expectations"][0]["recordingsMatchingRoute"], 0)
            self.assertIn("attribution-ambiguous", v[sid]["expectations"][0]["problems"][0])
        # Losing a serial request while retaining a later burst recording must never turn serial green.
        one_serial = [("a", "GET", "/owners/1"), ("b", "GET", "/owners/2")]
        v = xinstr.analyze({"burst-only": d["02"]}, exp, one_serial, frozenset({"b"}))
        self.assertFalse(v["a"]["passed"])
        self.assertEqual(v["a"]["recordingsAttributed"], 0)

    def test_unrelated_burst_does_not_relax_strict_counts(self):
        exp = {"a": [{"method": "GET", "route": "/vets", "status": 200, "layers": []}]}
        d = {"x": rec("GET", "/vets", 200)}
        d["x"]["_openedAt"] = "2026-10-10T00:00:00Z"
        sent = [("a", "GET", "/vets"), ("a", "GET", "/vets"), ("b", "GET", "/owners/1")]
        v = xinstr.analyze(d, exp, sent, frozenset({"b"}))
        self.assertEqual(v["a"]["expectations"][0]["problems"], ["attribution-ambiguous(recordings 1, requests 2)"])
        self.assertFalse(v["b"]["passed"])
        self.assertEqual(v["b"]["attribution"], "ambiguous")
        self.assertEqual(v["b"]["recordingsAttributed"], 0)
        self.assertEqual(v["b"]["frameSymbols"], [])

    def test_template_only_burst_reports_the_missing_product_correlation(self):
        exp = {"burst": [{"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": []}]}
        # Unique concrete resources still become the same request template in the Spring MVC read API.
        sent = [("burst", "GET", "/owners/1"), ("burst", "GET", "/owners/2")]
        details = {str(i): rec("GET", "/owners/{ownerId}", 200) for i in range(2)}
        for i, detail in enumerate(details.values()):
            detail["recordingId"] = f"01a12327-{0x100 + i:04x}-7000-8000-000000000000"
            detail["_openedAt"] = f"2026-10-10T00:00:0{i}Z"
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}))["burst"]
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["attribution"], "ambiguous")
        self.assertEqual(verdict["recordingsAttributed"], 0)
        problem = verdict["expectations"][0]["problems"][0]
        self.assertIn("allowlisted non-secret request marker", problem)
        self.assertIn("recording id returned to the requester", problem)
        self.assertIn("without concrete path, query or headers", problem)

    def test_burst_with_fewer_recordings_than_paced_requests_is_ambiguous(self):
        exp = {"a": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]}
        sent = [("a", "GET", "/owners/1"), ("a", "GET", "/owners/2"), ("b", "GET", "/owners/3")]
        d = {"x": rec("GET", "/owners/1", 200)}
        d["x"]["_openedAt"] = "2026-10-10T00:00:00Z"
        v = xinstr.analyze(d, exp, sent, frozenset({"b"}))
        self.assertTrue(v["a"]["expectations"][0]["problems"][0].startswith("attribution-ambiguous"))

    def boundary_fixture(self):
        exp = {"burst": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}],
               "serial": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]}
        sent = [("burst", "GET", "/owners/1"), ("burst", "GET", "/owners/2")]
        details = {str(i): rec("GET", "/owners/{id}", 200) for i in range(2)}
        for d in details.values():
            d["completion"] = "complete"
        return exp, sent, details

    def test_boundary_records_exact_ids_counts_and_verification_time(self):
        exp, sent, details = self.boundary_fixture()
        exp["burst"][0]["layers"] = ["controller"]
        with mock.patch.object(xinstr.time, "time", return_value=123):
            boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(boundary["verified"])
        self.assertEqual(boundary["verifiedAt"], 123)
        self.assertEqual(boundary["recordingIds"], ["0", "1"])
        self.assertEqual(boundary["recordingCount"], 2)
        self.assertEqual(boundary["requests"], 2)
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)["burst"]
        self.assertFalse(verdict["passed"], verdict)
        self.assertEqual(verdict["attribution"], "ambiguous")
        self.assertEqual(verdict["recordingsAttributed"], 0)
        self.assertEqual(verdict["frameSymbols"], [])
        item = verdict["expectations"][0]
        self.assertFalse(item["passed"])
        self.assertEqual(item["attribution"], "ambiguous")
        self.assertEqual(item["recordingsMatchingRoute"], 0)
        self.assertEqual(item["recordingsWithStatus"], 0)
        self.assertEqual(item["layers"], {})
        self.assertEqual(item["recordingsWithSource"], 0)
        self.assertEqual(item["problems"], [BURST_CORRELATION_PROBLEM])
        groups = xinstr.burst_route_evidence(details, exp, frozenset({"burst"}), boundary, None, (set(), set()))
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group["evidenceScope"], "burst-route-group")
        self.assertEqual(group["recordingsMatchingRoute"], 2)
        self.assertEqual(group["recordingsWithStatus"], 2)
        self.assertEqual(group["layers"], {"controller": {"recordingsWithFrame": 2, "of": 2}})
        self.assertEqual(group["recordingsWithSource"], 2)
        self.assertEqual(group["problems"], [])
        details["0"]["outcome"]["httpStatus"] = 500
        groups = xinstr.burst_route_evidence(details, exp, frozenset({"burst"}), boundary, None, (set(), set()))
        self.assertEqual(groups[0]["problems"], ["http-outcome-count-mismatch(expected 2, observed 1)"])

    def test_duplicate_concrete_paths_cannot_be_correlated_within_or_across_bursts(self):
        path = "/owners/1"
        details = {}
        for i in range(2):
            rid = f"01a12327-{0x100 + i:04x}-7000-8000-000000000000"
            details[rid] = {**rec("GET", path, 200), "recordingId": rid, "completion": "complete",
                            "_openedAt": f"2026-10-10T00:00:0{i}Z"}
        for scenarios in (("burst", "burst"), ("burst", "other-burst")):
            with self.subTest(scenarios=scenarios):
                burst = frozenset(scenarios)
                exp = {sid: [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": []}]
                       for sid in burst}
                sent = [(sid, "GET", path) for sid in scenarios]
                serial = xinstr.burst_accounting({}, [], exp, {})
                boundary = xinstr.burst_accounting(details, sent, exp, {})
                self.assertTrue(serial["verified"])
                self.assertTrue(boundary["verified"])
                self.assertEqual(boundary["recordingIds"], sorted(details))
                self.assertEqual(boundary["routes"][0]["requests"], 2)
                self.assertEqual(boundary["routes"][0]["recordings"], 2)
                with mock.patch.object(xinstr, "recording_time") as recording_time:
                    verdicts = xinstr.analyze(details, exp, sent, burst, boundary, serial)
                    groups = xinstr.burst_route_evidence(details, exp, burst, boundary, serial, (set(), set()))
                recording_time.assert_not_called()
                self.assertEqual(len(groups), 1)
                self.assertEqual(groups[0]["recordingsMatchingRoute"], 2)
                for verdict in verdicts.values():
                    self.assertFalse(verdict["passed"])
                    self.assertEqual(verdict["attribution"], "ambiguous")
                    self.assertEqual(verdict["recordingsAttributed"], 0)
                    self.assertEqual(verdict["frameSymbols"], [])
                    item = verdict["expectations"][0]
                    self.assertEqual(item["recordingsMatchingRoute"], 0)
                    self.assertEqual(item["problems"], [BURST_CORRELATION_PROBLEM])

    def test_shared_burst_route_reports_evidence_and_problems_once(self):
        exp, _, _ = self.boundary_fixture()
        exp["burst"][0]["layers"] = ["controller", "repository"]
        exp["other-burst"] = exp["burst"]
        burst = frozenset({"burst", "other-burst"})
        sent = [(sid, "GET", "/owners/1?secret=private") for sid in sorted(burst)]
        serial_details = {"serial": {**rec("GET", "/owners/{id}", 200), "completion": "complete"}}
        serial = xinstr.burst_accounting(serial_details, [("serial", "GET", "/owners/2")], exp, {})
        for problem in (None, "http-outcome-count-mismatch", "no-controller-frame", "source-binding-missing",
                        "partial-recording"):
            with self.subTest(problem=problem):
                first = {**rec("GET", "/owners/{id}", 200), "completion": "complete"}
                second = {**rec("GET", "/owners/{id}", 500 if problem == "http-outcome-count-mismatch" else 200,
                                symbols=() if problem == "no-controller-frame"
                                else ("OwnerController.showOwner", "OwnerRepository.findById")),
                          "completion": "complete"}
                if problem == "source-binding-missing":
                    for event in second["events"]:
                        event.pop("sourceBinding", None)
                details = {**serial_details, "first": first, "second": second}
                if problem == "partial-recording":
                    first["completion"] = "partial"
                    first["sessionContext"] = {"runtimeSessionId": "s", "rejectedRequests": "1"}
                    del details["second"]
                boundary = xinstr.burst_accounting(details, sent, exp, serial_details)
                self.assertTrue(boundary["verified"])
                verdicts = xinstr.analyze(details, exp, sent, burst, boundary, serial)
                ids = (set(), set())
                groups = xinstr.burst_route_evidence(details, exp, burst, boundary, serial, ids)
                self.assertEqual(len(groups), 1)
                group = groups[0]
                self.assertEqual(group["evidenceScope"], "burst-route-group")
                self.assertEqual((group["method"], group["route"], group["requests"]), ("GET", "/owners/{id}", 2))
                self.assertNotIn("private", str(group))
                partial = problem == "partial-recording"
                bad_outcome = problem == "http-outcome-count-mismatch"
                missing_frame = problem == "no-controller-frame"
                missing_source = problem == "source-binding-missing"
                n = 1 if partial else 2
                self.assertEqual(group["recordingsMatchingRoute"], n)
                self.assertEqual(group["partialRecordings"], int(partial))
                self.assertEqual(boundary["capacityDrops"], int(partial))
                self.assertEqual(group["outcomes"], [{"httpStatus": 200, "kind": "responded",
                                                     "recordings": n - int(bad_outcome)}]
                                 + ([{"httpStatus": 500, "kind": "responded", "recordings": 1}] if bad_outcome else []))
                self.assertEqual(group["recordingsWithStatus"], n - int(bad_outcome))
                self.assertEqual(group["layers"], {
                    layer: {"recordingsWithFrame": n - int(missing_frame), "of": n}
                    for layer in ("controller", "repository")})
                self.assertEqual(group["recordingsWithSource"], n - int(missing_frame or missing_source))
                self.assertEqual(ids[0], {"first"} if partial or bad_outcome else {"first", "second"})
                self.assertEqual(ids[1], {"first"} if partial or missing_frame or missing_source else {"first", "second"})
                self.assertEqual(bool(group["problems"]), problem is not None)
                classes = xinstr.problem_classes({sid: verdicts[sid] for sid in burst}, groups)
                self.assertEqual(classes["attribution-ambiguous"], 2)
                if problem:
                    self.assertEqual(classes[problem], 1)
                if partial:
                    self.assertEqual(classes["burst-route-count-mismatch"], 1)
                self.assertEqual(classes.get("burst-boundary-recordings-missing", 0), int(partial))
                for sid in burst:
                    verdict = verdicts[sid]
                    self.assertFalse(verdict["passed"])
                    self.assertEqual(verdict["attribution"], "ambiguous")
                    self.assertEqual(verdict["recordingsAttributed"], 0)
                    self.assertEqual(verdict["frameSymbols"], [])
                    item = verdict["expectations"][0]
                    self.assertEqual(item["recordingsMatchingRoute"], 0)
                    self.assertEqual(item["recordingsWithSource"], 0)
                    self.assertEqual(item["problems"], [BURST_CORRELATION_PROBLEM])

    def test_shared_route_includes_expectations_from_a_burst_that_did_not_send_it(self):
        exp, sent, details = self.boundary_fixture()
        del exp["serial"]
        exp["other-burst"] = [dict(exp["burst"][0])]
        burst = frozenset({"burst", "other-burst"})
        sent = sent[:1]
        live = {"0": details["0"]}
        boundary = xinstr.burst_accounting(live, sent, exp, {})
        self.assertTrue(boundary["verified"])
        self.assertEqual(boundary["recordingIds"], ["0"])

        for exact in (False, True):
            with self.subTest(exact_outcomes=exact):
                if exact:
                    for sid, statuses in (("burst", [200]), ("other-burst", [200, 302])):
                        exp[sid][0].pop("status")
                        exp[sid][0]["statuses"] = statuses
                ids = (set(), set())
                groups = xinstr.burst_route_evidence(details, exp, burst, boundary, None, ids)
                self.assertEqual(len(groups), 1)
                group = groups[0]
                self.assertEqual((group["requests"], group["recordingsMatchingRoute"]), (1, 1))
                self.assertEqual((group["recordingsWithStatus"], group["recordingsWithSource"]), (1, 1))
                self.assertEqual(ids, ({"0"}, {"0"}))
                self.assertEqual(group["problems"],
                                 (["http-outcome-multiset-mismatch(expected [200, 200, 302], saw [200])"] if exact else [])
                                 + ["count-below-minimum(need 2, have 1)",
                                    f"burst-boundary-recordings-missing(missing {2 if exact else 1})"])
                verdicts = xinstr.analyze(details, exp, sent, burst, boundary)
                for sid in burst:
                    verdict = verdicts[sid]
                    self.assertFalse(verdict["passed"])
                    self.assertEqual(verdict["attribution"], "ambiguous")
                    self.assertEqual(verdict["recordingsAttributed"], 0)
                    self.assertEqual(verdict["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
                classes = xinstr.problem_classes({sid: verdicts[sid] for sid in burst}, groups)
                self.assertEqual(classes, {"attribution-ambiguous": 2, "count-below-minimum": 1,
                                           "burst-boundary-recordings-missing": 1,
                                           **({"http-outcome-multiset-mismatch": 1} if exact else {})})

    def test_shared_outcome_multiset_uses_only_live_boundary_ids(self):
        exp, _, details = self.boundary_fixture()
        first = exp["burst"][0]
        first.pop("status")
        first["statuses"] = [200]
        exp["other-burst"] = [{**first, "statuses": [302]}]
        details["1"]["outcome"]["httpStatus"] = 302
        burst = frozenset({"burst", "other-burst"})
        sent = [(sid, "GET", "/owners/1") for sid in sorted(burst)]
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(boundary["verified"])
        ids = (set(), set())
        groups = xinstr.burst_route_evidence(details, exp, burst, boundary, None, ids)
        self.assertEqual(groups[0]["problems"], [])
        self.assertEqual(ids, ({"0", "1"}, {"0", "1"}))

        final = {"0": details["0"], "late": details["1"]}
        ids = (set(), set())
        groups = xinstr.burst_route_evidence(final, exp, burst, boundary, None, ids)
        self.assertEqual(ids, ({"0"}, {"0"}))
        self.assertEqual(xinstr.problem_classes({}, groups), {
            "burst-route-count-mismatch": 1, "burst-recording-detail-unavailable": 1,
            "http-outcome-multiset-mismatch": 1, "count-below-minimum": 1, "no-source-file-line": 1,
        })

    def test_shared_route_covers_each_distinct_frame_and_source_expectation(self):
        from tools.qa.camp_instr_steps import instrumented_steps

        exp, _, details = self.boundary_fixture()
        first = {**exp["burst"][0], "layers": ["controller", "repository"]}
        exp = {"a": [{**first, "layerHints": {"controller": "OwnerController"}}],
               "b": [{**first, "layerHints": {"controller": ["OtherController.show"]}}]}
        burst = frozenset(exp)
        sent = [(sid, "GET", "/owners/1") for sid in sorted(burst)]
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(boundary["verified"])
        for other in ("absent", "unsourced", "sourced"):
            with self.subTest(other=other):
                final = {rid: {**d, "events": d["events"][:]} for rid, d in details.items()}
                if other != "absent":
                    event = {**final["0"]["events"][1], "symbol": "OtherController.show"}
                    if other == "unsourced":
                        event.pop("sourceBinding")
                    final["0"]["events"].insert(2, event)
                ids = (set(), set())
                group, = xinstr.burst_route_evidence(final, exp, burst, boundary, None, ids)
                self.assertEqual(group["layers"]["controller"], {"recordingsWithFrame": 2, "of": 2})
                self.assertEqual(group["recordingsWithSource"], 2)
                self.assertEqual(ids, ({"0", "1"}, {"0", "1"}))
                coverage = {tuple(c["layers"]["controller"]["hints"]): c for c in group["frameExpectations"]}
                self.assertEqual(set(coverage), {("OwnerController",), ("OtherController.show",)})
                self.assertTrue(coverage["OwnerController",]["sourceCovered"])
                other_coverage = coverage["OtherController.show",]
                self.assertEqual(other_coverage["layers"]["controller"], {
                    "hints": ["OtherController.show"], "recordingsWithFrame": int(other != "absent"),
                    "recordingsWithSource": int(other == "sourced"),
                })
                self.assertEqual(other_coverage["sourceCovered"], other == "sourced")
                self.assertEqual(other_coverage["framesCovered"], other != "absent")
                self.assertEqual(other_coverage["layers"]["repository"]["recordingsWithSource"], 2)
                self.assertEqual(group["problems"], (["no-controller-frame"] if other == "absent" else [])
                                 + ["burst-frame-expectations-differ"]
                                 + (["burst-source-expectation-unresolved"] if other != "sourced" else []))
                verdicts = xinstr.analyze(final, exp, sent, burst, boundary)
                for verdict in verdicts.values():
                    self.assertFalse(verdict["passed"])
                    self.assertEqual(verdict["recordingsAttributed"], 0)
                    self.assertEqual(verdict["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
                receipt = {"api": {"ok": True, "recordings": 2}, "burstRouteGroups": [group],
                           "problemClasses": xinstr.problem_classes(verdicts, [group]), "recordingsWithSource": len(ids[1]),
                           "scenarios": [{"id": sid, "scenarioChecksPassed": True, "recordingVerdict": verdict}
                                         for sid, verdict in verdicts.items()]}
                summary = {step: (status, note) for step, status, note in instrumented_steps(receipt)}
                self.assertEqual(summary["recordings-per-scenario"][0], "fail")
                self.assertEqual(summary["source-identity"][0], "pass" if other == "sourced" else "fail")
                if other != "sourced":
                    self.assertIn("burst-source-expectation-unresolved", summary["source-identity"][1])

    def test_partial_accounting_polls_state_and_expiry_reports_exact_numbers(self):
        exp, sent, details = self.boundary_fixture()
        client = mock.Mock()
        with mock.patch.object(xinstr.time, "monotonic", side_effect=[0, 1, 2]), \
             mock.patch.object(xinstr, "collect_api", side_effect=[
                 {"ok": True, "details": {"0": details["0"]}}, {"ok": True, "details": details}]) as collect:
            boundary = xinstr.wait_burst_boundary(client, pathlib.Path("unused"), sent, exp, {}, 3)
        self.assertTrue(boundary["verified"])
        self.assertEqual(collect.call_count, 2)
        self.assertIsNone(client.deadline)
        with mock.patch.object(xinstr.time, "monotonic", side_effect=[0, 3]), \
             mock.patch.object(xinstr, "collect_api", return_value={"ok": True, "details": {"0": details["0"]}}):
            boundary = xinstr.wait_burst_boundary(client, pathlib.Path("unused"), sent, exp, {}, 3)
        self.assertFalse(boundary["verified"])
        self.assertIsNone(boundary["verifiedAt"])
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertFalse(v["burst"]["passed"])
        self.assertEqual(v["burst"]["recordingsAttributed"], 0)
        self.assertEqual(v["burst"]["expectations"][0]["recordingsMatchingRoute"], 0)
        self.assertEqual(v["burst"]["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
        self.assertEqual((boundary["requests"], boundary["recordingCount"], boundary["capacityDrops"],
                          boundary["unaccounted"]), (2, 1, 0, 1))
        groups = xinstr.burst_route_evidence(details, exp, frozenset({"burst"}), boundary, None, (set(), set()))
        self.assertEqual(groups[0]["recordingsMatchingRoute"], 1)
        self.assertEqual(groups[0]["problems"], ["burst-route-count-mismatch(requests 2, recordings 1)",
                                                "burst-boundary-recordings-missing(missing 1)"])
        self.assertFalse(v["serial"]["passed"])

    def test_snapshot_finishing_after_budget_does_not_verify(self):
        exp, sent, details = self.boundary_fixture()
        with mock.patch.object(xinstr.time, "monotonic", side_effect=[0, 4, 4]), \
             mock.patch.object(xinstr, "collect_api", return_value={"ok": True, "details": details}):
            boundary = xinstr.wait_burst_boundary(mock.Mock(), pathlib.Path("unused"), sent, exp, {}, 3)
        self.assertFalse(boundary["verified"])
        self.assertIsNone(boundary["verifiedAt"])

    def test_late_recording_after_boundary_cannot_inflate_serial_counts(self):
        exp, sent, details = self.boundary_fixture()
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        sent.append(("serial", "GET", "/owners/3"))
        details["serial"] = rec("GET", "/owners/{id}", 200)
        details["serial"]["_openedAt"] = "2026-10-10T00:00:00Z"
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertTrue(v["serial"]["passed"], v)
        details["serial"]["completion"] = "partial"
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertIn("partial-recording", v["serial"]["expectations"][0]["problems"])
        details["serial"]["completion"] = "complete"
        details["late"] = rec("GET", "/owners/{id}", 200)
        details["late"]["_openedAt"] = "2026-10-10T00:00:01Z"
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertEqual(v["serial"]["expectations"][0]["problems"],
                         ["serial-count-mismatch(recordings 2, requests 1)"])
        self.assertFalse(v["burst"]["passed"])
        self.assertEqual(v["burst"]["recordingsAttributed"], 0)
        self.assertEqual(v["burst"]["expectations"][0]["recordingsMatchingRoute"], 0)
        groups = xinstr.burst_route_evidence(details, exp, frozenset({"burst"}), boundary, None, (set(), set()))
        self.assertEqual(groups[0]["recordingsMatchingRoute"], 2)
        del details["serial"]
        del details["late"]
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertEqual(v["serial"]["expectations"][0]["problems"],
                         ["serial-count-mismatch(recordings 0, requests 1)"])

    def test_capacity_drops_are_deduplicated_and_partials_still_fail(self):
        exp, sent, details = self.boundary_fixture()
        context = {"runtimeSessionId": "s", "rejectedRequests": "1"}
        details["0"]["sessionContext"] = context
        details["1"]["sessionContext"] = context
        self.assertEqual(xinstr.capacity_counts(details), {"s": 1})
        # One admitted forced drop and one refused request fully account for the burst, but fail it.
        details.pop("1")
        details["0"]["completion"] = "partial"
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(boundary["verified"])
        self.assertEqual(boundary["capacityDrops"], 1)
        self.assertEqual(boundary["partialRecordingIds"], ["0"])
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertFalse(v["burst"]["passed"])
        self.assertEqual(v["burst"]["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
        self.assertEqual(boundary["capacityDrops"], 1)
        groups = xinstr.burst_route_evidence(details, exp, frozenset({"burst"}), boundary, None, (set(), set()))
        self.assertEqual(groups[0]["partialRecordings"], 1)
        self.assertEqual(groups[0]["problems"],
                         ["burst-route-count-mismatch(requests 2, recordings 1)", "partial-recording",
                          "burst-boundary-recordings-missing(missing 1)"])
        before = {"old": {"sessionContext": context}}
        self.assertFalse(xinstr.burst_accounting(details, sent, exp, before)["verified"])

    def test_partial_recordings_and_capacity_drops_each_fail_burst_isolation(self):
        exp, sent, details = self.boundary_fixture()
        partial = {**details, "0": {**details["0"], "completion": "partial"}}
        refused = {"0": {**details["0"], "sessionContext": {"runtimeSessionId": "s", "rejectedRequests": "1"}}}
        for snapshot, capacity, partial_count in ((partial, 0, 1), (refused, 1, 0)):
            with self.subTest(capacity=capacity, partial=partial_count):
                serial = xinstr.burst_accounting({}, [], exp, {})
                boundary = xinstr.burst_accounting(snapshot, sent, exp, {})
                self.assertTrue(boundary["verified"])
                verdict = xinstr.analyze(snapshot, exp, sent, frozenset({"burst"}), boundary, serial)["burst"]
                self.assertFalse(verdict["passed"])
                self.assertEqual(verdict["recordingsAttributed"], 0)
                self.assertEqual(verdict["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
                self.assertEqual(boundary["capacityDrops"], capacity)
                self.assertEqual(len(boundary["partialRecordingIds"]), partial_count)
                groups = xinstr.burst_route_evidence(snapshot, exp, frozenset({"burst"}), boundary, serial, (set(), set()))
                self.assertEqual(groups[0]["partialRecordings"], partial_count)
                self.assertEqual(groups[0]["problems"],
                                 ["partial-recording"] if partial_count
                                 else ["burst-route-count-mismatch(requests 2, recordings 1)",
                                       "burst-boundary-recordings-missing(missing 1)"])

    def test_capacity_context_null_zero_maxima_and_independent_sessions(self):
        details = {str(i): {"sessionContext": context} for i, context in enumerate([
            None, {}, {"runtimeSessionId": "unreported", "rejectedRequests": None},
            {"runtimeSessionId": "zero", "rejectedRequests": "0"},
            {"runtimeSessionId": "s", "rejectedRequests": "12"},
            {"runtimeSessionId": "s", "rejectedRequests": "2"},
            {"runtimeSessionId": "t", "rejectedRequests": "3"},
            *({"runtimeSessionId": "invalid", "rejectedRequests": v} for v in (-1, 1, "-1", "1.0", "", "１２")),
        ])}
        self.assertEqual(xinstr.capacity_counts(details), {"zero": 0, "s": 12, "t": 3})

    def test_real_shaped_list_and_detail_capacity_accounting(self):
        import tempfile
        exp, sent, details = self.boundary_fixture()
        context = {"runtimeSessionId": "session-a", "rejectedRequests": "8"}
        detail = {**details["0"], "recordingId": "0", "sessionContext": context, "incompleteEvidence": []}
        client = mock.Mock()
        client.get.side_effect = [
            (200, {"recordings": [{"recordingId": "0", "completion": "complete", "sessionContext": context,
                                      "incompleteEvidence": []}], "nextAfter": None}),
            (200, {**detail, "nextCursor": None}),
        ]
        with tempfile.TemporaryDirectory() as td:
            api = xinstr.collect_api(client, pathlib.Path(td))
        self.assertTrue(api["ok"])
        before = {"old": {"sessionContext": {**context, "rejectedRequests": "7"}}}
        boundary = xinstr.burst_accounting(api["details"], sent, exp, before)
        self.assertTrue(boundary["verified"], boundary)
        self.assertEqual(boundary["capacityDrops"], 1)
        self.assertEqual(boundary["unaccounted"], 0)

    def test_detail_pagination_marks_early_exit_and_preserves_the_prefix(self):
        import json
        import tempfile
        exp, sent, live = self.boundary_fixture()
        boundary = xinstr.burst_accounting(live, sent, exp, {})
        self.assertTrue(boundary["verified"])
        listing = (200, {"recordings": [{"recordingId": rid} for rid in live], "nextAfter": None})
        first = {**live["0"], "events": live["0"]["events"][:-1], "nextCursor": "next", "incompleteEvidence": []}
        tail = {"events": live["0"]["events"][-1:], "nextCursor": None}
        cases = [
            ("complete", [tail], None),
            ("capture-partial", [tail], None),
            ("capture-gap", [{**tail, "incompleteEvidence": ["gap_event_sequence:5"]}], None),
            ("HTTP", [(503, {"detail": "private"})], "detail HTTP 503"),
            ("transport", [TimeoutError("private")], "detail transport failure"),
            ("malformed-page", [{"events": None, "nextCursor": None}], "detail malformed page"),
            ("empty-follow-up", [{"events": [], "nextCursor": None}], "detail malformed page"),
            ("missing", [{"events": tail["events"]}], "detail malformed continuation"),
            ("wrong-type", [{**tail, "nextCursor": []}], "detail malformed continuation"),
            ("empty", [{**tail, "nextCursor": ""}], "detail malformed continuation"),
            ("repeated", [{**tail, "nextCursor": "next"}], "detail malformed continuation"),
            ("bound", [{**tail, "nextCursor": f"next-{i}"} for i in range(39)], "detail pagination bound reached"),
        ]
        for case, pages, gap in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                client = mock.Mock(deadline=None)
                first_page = {**first, "completion": "partial"} if case == "capture-partial" else first
                client.get.side_effect = [listing, (200, first_page),
                                          *(p if isinstance(p, (tuple, Exception)) else (200, p) for p in pages),
                                          (200, {**live["1"], "nextCursor": None})]
                out = pathlib.Path(td)
                api = xinstr.collect_api(client, out)
                self.assertEqual(api["ok"], gap is None)
                self.assertEqual(api["reason"], gap or "")
                self.assertNotIn("listReadGap", api)
                detail = api["details"]["0"]
                self.assertEqual(detail, json.loads((out / "recording-0.json").read_text()))
                self.assertEqual(detail["events"][:len(first["events"])], first["events"])
                self.assertEqual(detail.get("_detailReadGap"), gap)
                self.assertEqual(xinstr.detail_read_incomplete(detail), gap is not None)
                self.assertNotIn("private", str(detail))
                self.assertIn("&cursor=next", client.get.call_args_list[2].args[0])
                self.assertEqual(client.get.call_count, 3 + len(pages))
                ids = (set(), set())
                group, = xinstr.burst_route_evidence(api["details"], exp, frozenset({"burst"}), boundary, None, ids)
                if gap:
                    self.assertEqual(ids, ({"1"}, {"1"}))
                    self.assertIn("burst-recording-detail-unavailable(missing 1)", group["problems"])
                else:
                    self.assertEqual(detail["events"], first["events"] + tail["events"])
                    self.assertIsNone(detail["nextCursor"])
                    self.assertEqual(ids, ({"0", "1"}, {"0", "1"}))
                    expected_problems = {"capture-gap": ["recording-evidence-incomplete"],
                                         "capture-partial": ["partial-recording"]}
                    self.assertEqual(group["problems"], expected_problems.get(case, []))
                if case == "capture-gap":
                    self.assertEqual(detail["incompleteEvidence"], ["gap_event_sequence:5"])

    def test_listing_early_exit_keeps_prefix_and_discloses_read_gap(self):
        import tempfile

        def page(i, after):
            return (200, {"recordings": [{"recordingId": str(i)}], "nextAfter": after})

        cases = [
            ([page(0, "next"), (503, {"detail": "private"})], 400, 1, "recordings list HTTP 503"),
            ([page(0, "next"), TimeoutError("private")], 400, 1, "recordings list transport failure"),
            ([page(0, [])], 400, 1, "recordings list malformed continuation"),
            ([page(0, "next"), page(0, None)], 400, 1, "recordings list repeated recording IDs"),
            ([page(0, "next")], 1, 1, "recordings list recording bound reached"),
            ([page(i, f"next-{i}") for i in range(20)], 400, 20, "recordings list pagination bound reached"),
            ([page(0, "next"), page(1, None)], 2, 2, None),
            ([(200, {"recordings": [], "nextAfter": None})], 400, 0, None),
        ]
        for pages, limit, count, gap in cases:
            with self.subTest(gap=gap), tempfile.TemporaryDirectory() as td:
                client = mock.Mock(deadline=None)
                client.get.side_effect = [*pages, *((200, {"events": [], "nextCursor": None}) for _ in range(count))]
                api = xinstr.collect_api(client, pathlib.Path(td), limit)
                self.assertEqual(api["ok"], gap is None)
                self.assertEqual(api["reason"], gap or "")
                self.assertEqual(api.get("listReadGap"), gap)
                self.assertEqual(set(api["details"]), {str(i) for i in range(count)})
                self.assertEqual(client.get.call_count, len(pages) + count)
                self.assertNotIn("private", str(api))

    def test_live_detail_timeout_keeps_prefix_and_leaves_remaining_ids_unread(self):
        import tempfile
        _, _, details = self.boundary_fixture()
        client = mock.Mock(deadline=3)
        client.get.side_effect = [
            (200, {"recordings": [{"recordingId": rid} for rid in details], "nextAfter": None}),
            (200, {**details["0"], "nextCursor": "next"}),
            TimeoutError("private"),
        ]
        with tempfile.TemporaryDirectory() as td:
            api = xinstr.collect_api(client, pathlib.Path(td))
        self.assertFalse(api["ok"])
        self.assertEqual(api["reason"], api["detailCollectionGap"])
        self.assertEqual(client.get.call_count, 3)
        self.assertEqual([r["recordingId"] for r in api["recordings"]], ["0", "1"])
        self.assertEqual(set(api["details"]), {"0"})
        self.assertEqual(api["details"]["0"]["events"], details["0"]["events"])
        self.assertEqual(api["details"]["0"]["_detailReadGap"], "detail transport failure")
        self.assertIn("timed out", api["detailCollectionGap"])

    def test_incomplete_reads_cannot_verify_a_live_boundary_even_with_all_ids(self):
        exp, sent, details = self.boundary_fixture()
        cases = [(details, "recordings list pagination bound reached"),
                 ({**details, "0": {**details["0"], "_detailReadGap": "detail HTTP 503"}}, "detail HTTP 503")]
        for observed, gap in cases:
            api = {"ok": False, "reason": gap, "details": observed}
            with self.subTest(gap=gap), mock.patch.object(xinstr.time, "monotonic", return_value=0), \
                 mock.patch.object(xinstr, "collect_api", return_value=api) as collect:
                boundary = xinstr.wait_burst_boundary(mock.Mock(), pathlib.Path("unused"), sent, exp, {}, 3)
                collect.assert_called_once()
            self.assertFalse(boundary["verified"])
            self.assertIsNone(boundary["verifiedAt"])
            self.assertEqual(boundary["readError"], gap)
            self.assertEqual(boundary["recordingIds"], ["0", "1"])

    def test_open_and_excess_route_recordings_do_not_verify_boundary(self):
        exp, sent, details = self.boundary_fixture()
        details["0"]["completion"] = "open"
        self.assertFalse(xinstr.burst_accounting(details, sent, exp, {})["verified"])
        details["0"]["completion"] = "complete"
        details["extra"] = dict(details["0"])
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertFalse(boundary["verified"])
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)["burst"]
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["recordingsAttributed"], 0)
        self.assertEqual(verdict["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
        self.assertEqual((boundary["requests"], boundary["recordingCount"], boundary["capacityDrops"],
                          boundary["unaccounted"]), (2, 3, 0, -1))
        groups = xinstr.burst_route_evidence(details, exp, frozenset({"burst"}), boundary, None, (set(), set()))
        self.assertEqual(groups[0]["problems"], ["burst-route-count-mismatch(requests 2, recordings 3)"])

    def test_serial_boundary_requires_one_complete_recording_per_request(self):
        exp, sent, details = self.boundary_fixture()
        details.pop("1")
        context = {"runtimeSessionId": "s", "rejectedRequests": "1"}
        cases = [{"0": {**details["0"], "sessionContext": context}},
                 {"0": {**details["0"], "completion": "partial"}, "1": details["0"]}]
        for snapshot in cases:
            with self.subTest(snapshot=snapshot), mock.patch.object(xinstr.time, "monotonic", return_value=0), \
                 mock.patch.object(xinstr, "collect_api", return_value={"ok": True, "details": snapshot}):
                result = xinstr.wait_burst_boundary(mock.Mock(), pathlib.Path("unused"), sent, exp, {}, 3, require_complete=True)
            self.assertFalse(result["verified"])
            self.assertIsNone(result["verifiedAt"])

    def test_serial_first_boundary_never_uses_later_burst_or_canary_to_fill_a_missing_serial(self):
        exp, _, details = self.boundary_fixture()
        serial_sent = [("serial", "GET", "/owners/1"), ("serial", "GET", "/owners/2")]
        for i, detail in enumerate(details.values()):
            detail["_openedAt"] = f"2026-10-10T00:00:0{i}Z"
        serial = xinstr.burst_accounting(details, serial_sent, exp, {})
        later = {"burst": {**rec("GET", "/owners/{id}", 200), "completion": "complete"}}
        burst_sent = [("burst", "GET", "/owners/3")]
        combined = {**details, **later}
        boundary = xinstr.burst_accounting(combined, burst_sent, exp, details)
        self.assertTrue(serial["verified"])
        self.assertTrue(boundary["verified"])
        sent = serial_sent + burst_sent + [(None, "GET", "/owners/4")]
        verdict = xinstr.analyze(combined, exp, sent, frozenset({"burst"}), boundary, serial)
        self.assertTrue(verdict["serial"]["passed"], verdict)
        self.assertEqual(verdict["serial"]["recordingsAttributed"], 2)
        self.assertFalse(verdict["burst"]["passed"], verdict)
        self.assertEqual(verdict["burst"]["attribution"], "ambiguous")
        self.assertEqual(verdict["burst"]["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
        # Late recordings are outside the serial snapshot, even with the same route and time.
        del combined["1"]
        combined["canary"] = {**later["burst"], "_openedAt": "2026-10-10T00:00:01Z"}
        verdict = xinstr.analyze(combined, exp, sent, frozenset({"burst"}), boundary, serial)
        self.assertEqual(verdict["serial"]["expectations"][0]["problems"],
                         ["serial-count-mismatch(recordings 1, requests 2)"])
        self.assertFalse(verdict["serial"]["passed"])
        self.assertEqual(verdict["serial"]["frameSymbols"], [])
        self.assertEqual(verdict["burst"]["recordingsAttributed"], 0)
        self.assertEqual(verdict["burst"]["frameSymbols"], [])
        self.assertEqual(verdict["burst"]["expectations"][0]["recordingsMatchingRoute"], 0)
        groups = xinstr.burst_route_evidence(combined, exp, frozenset({"burst"}), boundary, serial, (set(), set()))
        self.assertEqual(groups[0]["recordingsMatchingRoute"], 1)

    def test_frame_symbols_are_unique_names_from_attributed_entries_even_on_bad_outcomes(self):
        detail = rec("GET", "/vets", 500, symbols=("VetController.show", "VetRepository.findAll", "VetController.show"))
        detail["events"][1]["bindings"] = [{"value": {"preview": "private-value"}}]
        detail["events"].append({"kind": "recording_event_kind:line_cursor", "symbol": "cursor-only"})
        exp = {"s": [{"method": "GET", "route": "/vets", "status": 200}]}
        verdict = xinstr.analyze({"r": detail, "other": rec("GET", "/owners", 200)}, exp)["s"]
        self.assertFalse(verdict["passed"])
        self.assertEqual(verdict["frameSymbols"], ["VetController.show", "VetRepository.findAll"])
        self.assertNotIn("private-value", str(verdict))

    def test_serial_symbol_inventory_includes_requests_without_a_scenario_expectation(self):
        exp, _, details = self.boundary_fixture()
        exp["other"] = [{"method": "GET", "route": "/vets", "status": 200}]
        details["vets"] = {**rec("GET", "/vets", 200, symbols=("VetController.show",)), "completion": "complete"}
        for i, detail in enumerate(details.values()):
            detail["_openedAt"] = f"2026-10-10T00:00:0{i}Z"
        sent = [("serial", "GET", "/owners/1"), ("serial", "GET", "/owners/2"), ("serial", "GET", "/vets")]
        serial = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(serial["verified"])
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), serial_boundary=serial)
        self.assertTrue(verdict["serial"]["passed"])
        self.assertEqual(verdict["serial"]["frameSymbols"],
                         ["OwnerController.showOwner", "OwnerRepository.findById", "VetController.show"])
        self.assertEqual(verdict["other"]["frameSymbols"], [])
        details["1"]["_openedAt"] = details["0"]["_openedAt"]
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), serial_boundary=serial)
        self.assertEqual(verdict["serial"]["attribution"], "ambiguous")
        self.assertEqual(verdict["serial"]["frameSymbols"], ["VetController.show"])

    def test_orchestration_preserves_serial_order_and_stops_burst_when_unaccounted(self):
        import tempfile
        import xcamp
        from types import SimpleNamespace
        for verified, shared in ((True, False), (False, False), (True, True)):
            with self.subTest(verified=verified, shared=shared), tempfile.TemporaryDirectory() as td:
                events = []
                stack = mock.Mock(launcher_exit=0, base="http://127.0.0.1:1234")
                stack.logs.return_value = ""
                def run(sc, *args):
                    events.append(sc.id)
                    xcamp.SENT_LOG.append(("GET", "/owners/1"))
                    return {"id": sc.id, "passed": True, "semanticEffectFingerprint": "fp", "requests": [], "elapsedMs": 1}
                exp, _, details = self.boundary_fixture()
                details["0"]["_openedAt"] = "2026-10-10T00:00:00Z"
                burst_scenarios = [SimpleNamespace(id="burst", kind="concurrency")]
                if shared:
                    burst_scenarios.append(SimpleNamespace(id="other-burst", kind="concurrency"))
                    exp["other-burst"] = exp["burst"]
                    details["2"] = {**rec("GET", "/owners/{id}", 200, src=False), "completion": "complete"}
                serial_details = {"0": details["0"]} if verified else {}
                boundaries = []

                def wait(*args, **kwargs):
                    events.append("boundary")
                    if not boundaries:
                        self.assertEqual([r[0] for r in args[2]], ["serial"])
                        self.assertTrue(kwargs["require_complete"])
                        boundary = xinstr.burst_accounting(serial_details, args[2], exp, {})
                    else:
                        self.assertEqual([r[0] for r in args[2]], [sc.id for sc in burst_scenarios])
                        self.assertEqual(args[5], deadline[0], "both phases share the existing budget")
                        boundary = xinstr.burst_accounting(details, args[2], exp, serial_details)
                    boundaries.append(boundary)
                    deadline.append(args[5])
                    return boundary

                deadline = []
                initial = {"ok": True, "reason": "", "recordings": [], "details": {}}
                # A later read may find a serial recording even when the live boundary failed.
                final_details = details if verified else {"0": details["0"]}
                api = {**initial, "recordings": [{"recordingId": rid} for rid in final_details], "details": final_details}
                with mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
                     mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
                     mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A" * 43})), \
                     mock.patch.object(xinstr, "ViewerClient"), \
                     mock.patch.object(xinstr, "stop_process_group"), \
                     mock.patch.object(xinstr, "collect_api", side_effect=[initial, api]), \
                     mock.patch.object(xinstr, "wait_burst_boundary", side_effect=wait), \
                     mock.patch.object(xcamp, "run_scenario", side_effect=run):
                    receipt = xinstr.run_instrumented(
                        project="p", pin={}, make_stack=lambda _: stack,
                        scenarios=[SimpleNamespace(id="serial", kind="business"), *burst_scenarios],
                        out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations=exp, xtrace="xtrace",
                        project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                        canaries=None, baseline_receipt=None, extra_canary_paths=[], harness_files=[])
                self.assertEqual(events, ["serial", "boundary", *[sc.id for sc in burst_scenarios], "boundary"]
                                 if verified else ["serial", "boundary"])
                self.assertEqual(receipt["notes"]["serialBoundary"], boundaries[0])
                self.assertEqual(receipt["notes"]["serialBoundary"]["verified"], verified)
                burst = next(s for s in receipt["scenarios"] if s["id"] == "burst")
                self.assertFalse(burst["recordingVerdict"]["passed"])
                if verified:
                    self.assertEqual(receipt["notes"]["burstBoundary"], boundaries[1])
                    self.assertTrue(receipt["notes"]["burstBoundary"]["verified"])
                    self.assertEqual(receipt["result"], "recorded")
                    self.assertEqual(receipt["api"]["recordings"], 3 if shared else 2)
                    serial = next(s for s in receipt["scenarios"] if s["id"] == "serial")
                    self.assertTrue(serial["recordingVerdict"]["passed"])
                    self.assertTrue(burst["scenarioChecksPassed"])
                    self.assertEqual(burst["recordingVerdict"]["recordingsAttributed"], 0)
                    self.assertEqual(burst["recordingVerdict"]["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
                    if shared:
                        self.assertEqual(receipt["problemClasses"], {"attribution-ambiguous": 2, "no-source-file-line": 1})
                        self.assertEqual(len(receipt["burstRouteGroups"]), 1)
                        self.assertEqual(receipt["burstRouteGroups"][0]["problems"], ["no-source-file-line"])
                        self.assertEqual(receipt["recordingsWithStatus"], 3)
                        self.assertEqual(receipt["recordingsWithSource"], 2)
                    else:
                        self.assertEqual(receipt["problemClasses"], {"attribution-ambiguous": 1})
                        self.assertEqual(len(receipt["burstRouteGroups"]), 1)
                        self.assertEqual(receipt["burstRouteGroups"][0]["problems"], [])
                        self.assertEqual(receipt["recordingsWithStatus"], 2)
                        self.assertEqual(receipt["recordingsWithSource"], 2)
                self.assertTrue(all("frameSymbols" in sc for sc in receipt["scenarios"]))
                stack.down.assert_called_once()
                if not verified:
                    self.assertFalse(burst["scenarioChecksPassed"])
                    self.assertEqual(burst["notRunReason"], "serial boundary was not verified")
                    self.assertEqual(receipt["result"], "failed", "a later API read cannot repair a skipped workload")

    def test_fully_dropped_burst_route_reports_source_gap_with_sourced_serial_recording(self):
        import tempfile
        import xcamp
        from types import SimpleNamespace
        from tools.qa.camp_instr_steps import instrumented_steps

        exp, _, details = self.boundary_fixture()
        exp["burst"][0]["route"] = "/vets"
        details["0"]["_openedAt"] = "2026-10-10T00:00:00Z"
        serial_details = {"0": details["0"]}
        live = {"0": {**details["0"], "sessionContext": {"runtimeSessionId": "s", "rejectedRequests": "1"}}}
        final = {**live, "late": {**rec("GET", "/vets", 200), "completion": "complete"}}
        requests = {"serial": ("GET", "/owners/1"), "burst": ("GET", "/vets")}
        scenarios = [SimpleNamespace(id="serial", kind="business"), SimpleNamespace(id="burst", kind="concurrency")]
        stack = mock.Mock(launcher_exit=0, base="http://127.0.0.1:1234")
        stack.logs.return_value = ""

        def run(sc, *args):
            xcamp.SENT_LOG.append(requests[sc.id])
            return {"id": sc.id, "passed": True, "semanticEffectFingerprint": "fp", "requests": [], "elapsedMs": 1}

        def wait(client, out_dir, sent, expectations, before, deadline, *, require_complete=False):
            sid = "serial" if require_complete else "burst"
            self.assertEqual(sent, [(sid, *requests[sid])])
            return xinstr.burst_accounting(serial_details if require_complete else live, sent, expectations, before)

        initial = {"ok": True, "reason": "", "recordings": [], "details": {}}
        api = {**initial, "recordings": [{"recordingId": rid} for rid in final], "details": final}
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(xinstr.os.environ), \
             mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
             mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
             mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A" * 43})), \
             mock.patch.object(xinstr, "ViewerClient"), mock.patch.object(xinstr, "stop_process_group"), \
             mock.patch.object(xinstr, "collect_api", side_effect=[initial, api]), \
             mock.patch.object(xinstr, "wait_burst_boundary", side_effect=wait), \
             mock.patch.object(xcamp, "run_scenario", side_effect=run):
            receipt = xinstr.run_instrumented(
                project="p", pin={}, make_stack=lambda _: stack, scenarios=scenarios,
                out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations=exp, xtrace="xtrace",
                project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                canaries=None, baseline_receipt=None, extra_canary_paths=[], harness_files=[])

        boundary = receipt["notes"]["burstBoundary"]
        self.assertTrue(boundary["verified"])
        self.assertEqual((boundary["requests"], boundary["capacityDrops"], boundary["unaccounted"]), (1, 1, 0))
        self.assertEqual(boundary["recordingIds"], [])
        self.assertEqual(receipt["requestsSent"], 2)
        self.assertEqual(receipt["api"]["recordings"], 2)
        self.assertEqual((receipt["recordingsWithStatus"], receipt["recordingsWithSource"]), (1, 1))
        serial, burst = (sc["recordingVerdict"] for sc in receipt["scenarios"])
        self.assertTrue(serial["passed"])
        self.assertEqual(serial["expectations"][0]["recordingsWithSource"], 1)
        self.assertFalse(burst["passed"])
        self.assertEqual(burst["attribution"], "ambiguous")
        self.assertEqual(burst["recordingsAttributed"], 0)
        self.assertEqual(burst["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
        group, = receipt["burstRouteGroups"]
        self.assertEqual((group["route"], group["requests"], group["recordingsMatchingRoute"]), ("/vets", 1, 0))
        self.assertEqual((group["recordingsWithStatus"], group["recordingsWithSource"], group["outcomes"]), (0, 0, []))
        self.assertEqual(group["problems"], ["burst-route-count-mismatch(requests 1, recordings 0)",
                                             "no-recording-for-route", "count-below-minimum(need 1, have 0)",
                                             "burst-boundary-recordings-missing(missing 1)"])
        self.assertEqual(receipt["problemClasses"], {
            "attribution-ambiguous": 1, "burst-drops": 1,
            **{p.split("(")[0]: 1 for p in group["problems"]},
        })
        summary = {step: (status, note) for step, status, note in instrumented_steps(receipt)}
        self.assertEqual(summary["recordings-per-scenario"][0], "fail")
        self.assertIn("1/2 scenarios", summary["recordings-per-scenario"][1])
        self.assertEqual(summary["source-identity"][0], "fail")
        self.assertIn("burst-boundary-recordings-missing", summary["source-identity"][1])

    def test_burst_refuses_unread_historical_capacity_baseline(self):
        import json
        import tempfile
        import xcamp
        from types import SimpleNamespace

        exp, sent, live = self.boundary_fixture()
        exp = {"burst": exp["burst"]}
        context = {"runtimeSessionId": "session-a", "rejectedRequests": "1"}
        historical = {**rec("GET", "/vets", 200), "completion": "complete", "sessionContext": context}
        admitted = {**live["0"], "sessionContext": context}
        client = mock.Mock(deadline=None)
        client.get.side_effect = [
            (200, {"recordings": [{"recordingId": "old"}], "nextAfter": None}),
            (503, {"detail": "private"}),
            (200, {"recordings": [{"recordingId": "old"}, {"recordingId": "0"}], "nextAfter": None}),
            (200, {**historical, "nextCursor": None}),
            (200, {**admitted, "nextCursor": None}),
        ]
        stack = mock.Mock(launcher_exit=0, base="http://127.0.0.1:1234")
        stack.logs.return_value = ""

        def run(*args):
            xcamp.SENT_LOG.extend((method, path) for _, method, path in sent)
            return {"id": "burst", "passed": True, "semanticEffectFingerprint": "fp", "requests": [], "elapsedMs": 1}

        with tempfile.TemporaryDirectory() as td, mock.patch.dict(xinstr.os.environ), \
             mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
             mock.patch.object(xinstr, "list_recording_ids", return_value={"old"}), \
             mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A" * 43})), \
             mock.patch.object(xinstr, "ViewerClient", return_value=client), mock.patch.object(xinstr, "stop_process_group"), \
             mock.patch.object(xcamp, "run_scenario", side_effect=run) as run_scenario:
            root = pathlib.Path(td)
            with self.assertRaisesRegex(RuntimeError, "cannot snapshot recordings before scenarios: detail HTTP 503"):
                xinstr.run_instrumented(
                    project="p", pin={}, make_stack=lambda _: stack, scenarios=[SimpleNamespace(id="burst", kind="concurrency")],
                    out_dir=root / "out", norm_extra=[], expectations=exp, xtrace="xtrace", project_dir=root,
                    data_home=root / "data", adaptations=[], canaries=None, baseline_receipt=None, extra_canary_paths=[],
                    harness_files=[])
            run_scenario.assert_not_called()
            stack.down.assert_called_once()
            self.assertEqual(client.get.call_count, 2)
            saved = json.loads((root / "out/boundary-before/recording-old.json").read_text())
            self.assertEqual(saved["_detailReadGap"], "detail HTTP 503")
            self.assertNotIn("sessionContext", saved)

            later = xinstr.collect_api(client, root / "later")
            self.assertTrue(later["ok"])
            self.assertEqual(xinstr.capacity_counts(later["details"]), {"session-a": 1})
            boundary = xinstr.burst_accounting(later["details"], sent, exp, {"old": historical})
            self.assertFalse(boundary["verified"])
            self.assertEqual((boundary["capacityDrops"], boundary["unaccounted"]), (0, 1))

    def test_single_owner_burst_gaps_reach_the_receipt_and_summary(self):
        import json
        import tempfile
        import xcamp
        from types import SimpleNamespace
        from tools.qa.camp_instr_steps import instrumented_steps
        from tools.qa.camp_overhead import compare_interleaved
        from tools.qa.test_camp_overhead import paired_runs

        unavailable = (1, 1, {"burst-route-count-mismatch": 1, "burst-recording-detail-unavailable": 1,
                              "no-source-file-line": 1})
        detail_failures = {
            "http-error": "detail HTTP 404",
            "later-http-error": "detail HTTP 503",
            "later-transport": "detail transport failure",
            "later-malformed": "detail malformed page",
            "detail-bound": "detail pagination bound reached",
            "missing-detail": "recording detail read timed out before all listed IDs were read",
        }
        list_failures = {
            "incomplete-listing": ("recordings list HTTP 503", (503, {"detail": "private"})),
            "listing-transport": ("recordings list transport failure", ConnectionResetError("private")),
            "listing-malformed": ("recordings list malformed page", (200, {"recordings": None, "nextAfter": None})),
            "listing-bound": ("recordings list pagination bound reached", None),
        }
        cases = {
            "binding": (2, 1, {"source-binding-missing": 1}),
            "frame": (2, 2, {"no-controller-frame": 1}),
            "absent": unavailable,
            "complete-pagination": (2, 2, {}),
            **dict.fromkeys(detail_failures, unavailable),
            **dict.fromkeys(list_failures, (2, 2, {})),
        }
        for gap, (matched, sourced, classes) in cases.items():
            with self.subTest(gap=gap), tempfile.TemporaryDirectory() as td:
                exp, sent, live = self.boundary_fixture()
                exp = {"burst": exp["burst"]}
                exp["burst"][0]["layers"] = ["controller", "repository"]
                if gap == "binding":
                    for event in live["1"]["events"]:
                        event.pop("sourceBinding", None)
                elif gap == "frame":
                    live["1"]["events"] = [e for e in live["1"]["events"] if e["symbol"] != "OwnerController.showOwner"]
                boundary = xinstr.burst_accounting(live, sent, exp, {})
                self.assertTrue(boundary["verified"])
                self.assertEqual(boundary["routes"][0]["recordingIds"], ["0", "1"])
                final = dict(live)
                if gap == "absent":
                    final["late"] = final.pop("1")
                if gap in ("http-error", "missing-detail"):
                    final["late"] = live["1"]
                rows = [{"recordingId": rid} for rid in final]
                list_gap, list_failure = list_failures.get(gap, (None, None))
                pages = [(200, {"recordings": rows, "nextAfter": "next" if list_gap else None})]
                if gap == "listing-bound":
                    for i in range(19):
                        rid = f"extra-{i}"
                        pages.append((200, {"recordings": [{"recordingId": rid}], "nextAfter": rid}))
                        final[rid] = {"events": []}
                elif list_gap:
                    pages.append(list_failure)
                tail = {"events": live["1"]["events"][-1:], "nextCursor": None}
                later_pages = {
                    "complete-pagination": [(200, tail)],
                    "later-http-error": [(503, {"detail": "private"})],
                    "later-transport": [ConnectionResetError("private")],
                    "later-malformed": [(200, {"events": None, "nextCursor": None})],
                    "detail-bound": [(200, {**tail, "nextCursor": f"next-{i}"}) for i in range(39)],
                    "missing-detail": [TimeoutError("private")],
                }
                for rid, detail in final.items():
                    if rid == "1" and gap == "http-error":
                        pages.append((404, {"detail": "private"}))
                    elif rid == "1" and gap in later_pages:
                        pages.append((200, {**detail, "events": detail["events"][:-1], "nextCursor": "next"}))
                        pages.extend(later_pages[gap])
                    elif rid != "late" or gap != "missing-detail":
                        pages.append((200, {**detail, "nextCursor": None}))
                client = mock.Mock(deadline=1 if gap == "missing-detail" else None)
                client.get.side_effect = pages
                live_client = mock.Mock()
                live_client.get.side_effect = [
                    (200, {"recordings": [], "nextAfter": None}),
                    (200, {"recordings": [{"recordingId": rid} for rid in live], "nextAfter": None}),
                    *((200, {**detail, "nextCursor": None}) for detail in live.values()),
                ]
                scenario = SimpleNamespace(id="burst", kind="concurrency")
                stack = mock.Mock(launcher_exit=0, base="http://127.0.0.1:1234")
                stack.logs.return_value = ""
                runs = paired_runs()
                pin = runs[0]["receipt"]["pin"]
                baseline = runs[-2]["receipt"]
                baseline["scenarios"][0].update(id="burst", semanticEffectFingerprint="fp",
                                                requests=[{"elapsedMs": 1} for _ in sent])
                root = pathlib.Path(td)
                baseline_path = root / "baseline.json"
                baseline_path.write_text(json.dumps(baseline))

                def run(*args):
                    xcamp.SENT_LOG.extend((m, path) for _, m, path in sent)
                    return {"id": "burst", "passed": True, "semanticEffectFingerprint": "fp",
                            "requests": [{"label": "get", "response": {"status": 200}, "elapsedMs": 1} for _ in sent],
                            "elapsedMs": 1}

                with mock.patch.dict(xinstr.os.environ), \
                     mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
                     mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
                     mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A" * 43})), \
                     mock.patch.object(xinstr, "ViewerClient", side_effect=[live_client, client]), \
                     mock.patch.object(xinstr, "stop_process_group"), \
                     mock.patch.object(xinstr, "wait_burst_boundary", wraps=xinstr.wait_burst_boundary) as wait, \
                     mock.patch.object(xcamp, "run_scenario", side_effect=run):
                    receipt = xinstr.run_instrumented(
                        project="p", pin=pin, make_stack=lambda _: stack, scenarios=[scenario],
                        out_dir=root / "out", norm_extra=[], expectations=exp, xtrace="xtrace", project_dir=root,
                        data_home=root / "data", adaptations=[], canaries=None, baseline_receipt=baseline_path,
                        extra_canary_paths=[], harness_files=[])
                wait.assert_called_once()
                self.assertEqual(wait.call_args.args[2], sent)
                serial = receipt["notes"]["serialBoundary"]
                self.assertTrue(serial["verified"])
                self.assertEqual(serial["requests"], 0)
                self.assertEqual(serial["recordingIds"], [])
                self.assertEqual(serial["capacityDrops"], 0)
                self.assertEqual(serial["unaccounted"], 0)
                burst = receipt["notes"]["burstBoundary"]
                self.assertTrue(burst["verified"])
                self.assertEqual(burst["recordingIds"], boundary["recordingIds"])
                self.assertEqual(burst["capacityDrops"], 0)
                self.assertEqual(burst["unaccounted"], 0)
                reason = list_gap or detail_failures.get(gap, "")
                self.assertEqual(receipt["api"]["ok"], not reason)
                self.assertEqual(receipt["api"]["reason"], reason)
                self.assertEqual(receipt["result"], "failed" if reason else "recorded")
                self.assertEqual(client.get.call_count, len(pages))
                runs[-1]["receipt"] = json.loads((root / "out/receipt.json").read_text())
                overhead = compare_interleaved(runs)
                self.assertEqual(overhead["eligibleForClaim"], not reason, overhead["errors"])
                self.assertEqual(overhead["aggregate"]["p50Ratio"], None if reason else 2)
                self.assertEqual(receipt["problemClasses"], {"attribution-ambiguous": 1, **classes})
                self.assertEqual(receipt["recordingsWithStatus"], matched)
                self.assertEqual(receipt["recordingsWithSource"], sourced)
                self.assertEqual(len(receipt["burstRouteGroups"]), 1)
                group = receipt["burstRouteGroups"][0]
                self.assertEqual(group["evidenceScope"], "burst-route-group")
                self.assertEqual(group["requests"], 2)
                self.assertEqual(group["recordingsMatchingRoute"], matched)
                self.assertEqual(group["recordingsWithStatus"], matched)
                self.assertEqual(group["recordingsWithSource"], sourced)
                self.assertEqual(group["layers"]["controller"],
                                 {"recordingsWithFrame": matched - int(gap == "frame"), "of": matched})
                self.assertEqual(group["outcomes"], [{"httpStatus": 200, "kind": "responded", "recordings": matched}])
                if matched == 1:
                    self.assertIn("burst-recording-detail-unavailable(missing 1)", group["problems"])
                    self.assertEqual(receipt["api"]["recordings"], len(final))
                self.assertEqual(receipt["api"]["incompleteDetails"], int(gap in detail_failures) + int(gap == "missing-detail"))
                self.assertEqual(receipt["api"]["listReadGap"], list_gap)
                if gap == "missing-detail":
                    self.assertFalse((root / "out/api/recording-late.json").exists())
                if gap in detail_failures:
                    saved = json.loads((root / "out/api/recording-1.json").read_text())
                    self.assertEqual(saved["_detailReadGap"], "detail transport failure" if gap == "missing-detail" else reason)
                    self.assertNotIn("private", json.dumps(saved))
                    if gap != "http-error":
                        self.assertEqual(saved["events"][:len(live["1"]["events"]) - 1], live["1"]["events"][:-1])
                verdict = receipt["scenarios"][0]["recordingVerdict"]
                self.assertFalse(verdict["passed"])
                self.assertEqual(verdict["attribution"], "ambiguous")
                self.assertEqual(verdict["recordingsAttributed"], 0)
                self.assertEqual(verdict["frameSymbols"], [])
                self.assertEqual(verdict["expectations"][0]["recordingsMatchingRoute"], 0)
                self.assertEqual(verdict["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
                summary = {step: (status, note) for step, status, note in instrumented_steps(receipt)}
                self.assertEqual(summary["recordings-per-scenario"][0], "fail")
                self.assertIn("0/1 scenarios", summary["recordings-per-scenario"][1])
                for problem in classes:
                    self.assertIn(f'"{problem}": 1', summary["recordings-per-scenario"][1])
                self.assertEqual(summary["source-identity"][0], "pass" if gap == "complete-pagination" else "fail")
                self.assertEqual(summary["api-json-artifact"][0], "fail" if reason else "pass")
                if list_gap:
                    self.assertIn("api-recordings-list-incomplete", summary["source-identity"][1])
                for problem in classes.keys() - {"burst-route-count-mismatch"}:
                    self.assertIn(problem, summary["source-identity"][1])

    def test_failed_workload_or_burst_boundary_cannot_be_reported_recorded(self):
        import tempfile
        import xcamp
        from types import SimpleNamespace
        for workload_ok, boundary_ok in ((False, True), (True, False)):
            with self.subTest(workload=workload_ok, boundary=boundary_ok), tempfile.TemporaryDirectory() as td:
                stack = mock.Mock(launcher_exit=0, base="http://127.0.0.1:1234")
                stack.logs.return_value = ""
                scenario = SimpleNamespace(id="burst", kind="concurrency")
                res = {"id": "burst", "passed": workload_ok, "semanticEffectFingerprint": "fp",
                       "requests": [], "elapsedMs": 1}
                api = {"ok": True, "reason": "", "recordings": [], "details": {}}
                boundary = xinstr.burst_accounting({}, [], {}, {})
                boundary["verified"] = boundary_ok
                with mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
                     mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
                     mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A" * 43})), \
                     mock.patch.object(xinstr, "ViewerClient"), mock.patch.object(xinstr, "stop_process_group"), \
                     mock.patch.object(xinstr, "collect_api", return_value=api), \
                     mock.patch.object(xinstr, "wait_burst_boundary", return_value=boundary), \
                     mock.patch.object(xinstr, "analyze", return_value={}), \
                     mock.patch.object(xcamp, "run_scenario", return_value=res):
                    receipt = xinstr.run_instrumented(
                        project="p", pin={}, make_stack=lambda _: stack, scenarios=[scenario],
                        out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations={}, xtrace="xtrace",
                        project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                        canaries=None, baseline_receipt=None, extra_canary_paths=[], harness_files=[])
                self.assertTrue(receipt["api"]["ok"])
                self.assertEqual(receipt["result"], "failed")
                self.assertEqual(receipt["problemClasses"], {} if boundary_ok else {"burst-boundary-not-verified": 1})
                stack.down.assert_called_once()

    def test_recording_snapshot_requires_valid_paginated_cli_evidence(self):
        with mock.patch.object(xinstr.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, '{"recordings":[{"recording_id":"old"}],"next_after":"next"}'),
            subprocess.CompletedProcess([], 0, '{"recordings":[{"recording_id":"older"}],"next_after":null}')
        ]) as run:
            self.assertEqual(xinstr.list_recording_ids("xtrace", pathlib.Path("project"), {}), {"old", "older"})
            self.assertIn("--after", run.call_args.args[0])
        with mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{}')):
            with self.assertRaises(RuntimeError):
                xinstr.list_recording_ids("xtrace", pathlib.Path("project"), {})

    def test_receipt_discloses_pacing_and_counts_only_new_recordings(self):
        import os
        import tempfile
        import xcamp
        from types import SimpleNamespace
        from tools.qa import canary
        canaries = canary.make_canaries()
        stack = mock.Mock(launcher_exit=0)
        stack.logs.return_value = ""
        scenario = SimpleNamespace(id="s", kind="business")
        result = {"id": "s", "passed": True, "semanticEffectFingerprint": "fp", "requests": [], "elapsedMs": 1}
        api = {"ok": True, "reason": "", "recordings": [{"recordingId": "old"}, {"recordingId": "new"}],
               "details": {"old": {}, "new": {}}}
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {}), \
             mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
             mock.patch.object(xinstr, "list_recording_ids", return_value={"old"}), \
             mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": "http://127.0.0.1:1234", "url": "http://x/#" + "A" * 43})), \
             mock.patch.object(xinstr, "ViewerClient"), mock.patch.object(xinstr, "stop_process_group"), \
             mock.patch.object(xinstr, "collect_api", return_value=api), \
             mock.patch.object(xcamp, "run_scenario", return_value=result), \
             mock.patch.object(xinstr, "analyze", return_value={"s": {"frameSymbols": ["OwnerController.show"], "expectations": []}}) as analyze:
            receipt = xinstr.run_instrumented(project="petclinic", pin={}, make_stack=lambda tag: stack,
                scenarios=[scenario], out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations={}, xtrace="xtrace",
                project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                canaries=canaries, baseline_receipt=None, extra_canary_paths=[], harness_files=[])
            self.assertEqual(os.environ["XTRACE_CANARY_ENV"], canaries["env-var"])
        self.assertEqual(receipt["api"]["recordings"], 1)
        self.assertEqual(receipt["scenarios"][0]["frameSymbols"], ["OwnerController.show"])
        self.assertEqual(set(analyze.call_args.args[0]), {"new"})
        self.assertEqual(receipt["notes"]["accommodations"]["pace_seconds"], 0.4)
        self.assertEqual(receipt["notes"]["accommodations"]["drain_seconds"], 0)
        self.assertIn("8 unwritten", receipt["notes"]["accommodations"]["reason"])
        self.assertEqual(receipt["notes"]["accommodations"]["correlationGap"], xinstr.REQUEST_CORRELATION_GAP)
        self.assertEqual(receipt["notes"]["canaryLocations"], {
            "authorization-header": "Authorization header", "cookie-header": "Cookie header",
            "query-token": "unread query parameter xt_token; also lastName during the standard flows probe",
            "json-body-password": "request body field password",
            "env-var": "application environment variable XTRACE_CANARY_ENV",
            "focused-business-secret": "focused owner search business parameter lastName (content redaction control)"})
        self.assertEqual(set(receipt["notes"]["canaryLocations"]), set(canaries))
        for value in canaries.values():
            self.assertNotIn(value, str(receipt))
        self.assertIsNone(xcamp.REQUEST_HOOK)
        self.assertIsNone(xcamp.SENT_LOG)
        self.assertEqual(xcamp.REQUEST_PACE_S, 0)

    def test_canary_pacing_never_adds_a_final_drain_sleep(self):
        import xcamp
        events = []
        canaries = {k: "canary" for k in ("json-body-password", "authorization-header", "cookie-header")}
        with mock.patch.object(xinstr.time, "sleep", side_effect=lambda seconds: events.append(("pace", seconds))), \
             mock.patch.object(xcamp, "http_request", side_effect=lambda *a, **kw: events.append(("request", a[2])) or {"status": 200}):
            sent = xinstr.send_canary_requests("http://127.0.0.1:1234", canaries, [("POST", "/owners/new")], pace=0.4)
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(events, [("pace", 0.4), ("request", "/owners/new")])

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
