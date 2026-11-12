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
        self.assertEqual(item["evidenceScope"], "burst-route-group")
        self.assertEqual(item["recordingsMatchingRoute"], 2)
        self.assertEqual(item["recordingsWithStatus"], 2)
        self.assertEqual(item["layers"], {"controller": {"recordingsWithFrame": 2, "of": 2}})
        self.assertEqual(item["recordingsWithSource"], 2)
        self.assertEqual(item["problems"], [BURST_CORRELATION_PROBLEM])
        details["0"]["outcome"]["httpStatus"] = 500
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertEqual(verdict["burst"]["expectations"][0]["problems"],
                         ["http-outcome-count-mismatch(expected 2, observed 1)", BURST_CORRELATION_PROBLEM])

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
                recording_time.assert_not_called()
                for verdict in verdicts.values():
                    self.assertFalse(verdict["passed"])
                    self.assertEqual(verdict["attribution"], "ambiguous")
                    self.assertEqual(verdict["recordingsAttributed"], 0)
                    self.assertEqual(verdict["frameSymbols"], [])
                    item = verdict["expectations"][0]
                    self.assertEqual(item["recordingsMatchingRoute"], 2 if len(burst) == 1 else 0)
                    self.assertEqual(item["problems"], [BURST_CORRELATION_PROBLEM])

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
        self.assertEqual(v["burst"]["expectations"][0]["recordingsMatchingRoute"], 1)
        self.assertEqual(v["burst"]["expectations"][0]["problems"],
                         ["burst-unaccounted(requests 2, recordings 1, capacity drops 0, unaccounted 1)",
                          BURST_CORRELATION_PROBLEM])
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
        self.assertEqual(v["burst"]["expectations"][0]["recordingsMatchingRoute"], 2)
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
        self.assertEqual(v["burst"]["expectations"][0]["problems"],
                         ["burst-drops(capacity 1, partial 1)", BURST_CORRELATION_PROBLEM])
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
                self.assertEqual(verdict["expectations"][0]["problems"],
                                 [f"burst-drops(capacity {capacity}, partial {partial_count})", BURST_CORRELATION_PROBLEM])

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
        self.assertEqual(verdict["expectations"][0]["problems"],
                         ["burst-unaccounted(requests 2, recordings 3, capacity drops 0, unaccounted -1)",
                          BURST_CORRELATION_PROBLEM])

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
        self.assertEqual(verdict["burst"]["expectations"][0]["recordingsMatchingRoute"], 1)

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
        for verified in (True, False):
            with self.subTest(verified=verified), tempfile.TemporaryDirectory() as td:
                events = []
                stack = mock.Mock(launcher_exit=0, base="http://127.0.0.1:1234")
                stack.logs.return_value = ""
                def run(sc, *args):
                    events.append(sc.id)
                    xcamp.SENT_LOG.append(("GET", "/owners/1"))
                    return {"id": sc.id, "passed": True, "semanticEffectFingerprint": "fp", "requests": [], "elapsedMs": 1}
                exp, _, details = self.boundary_fixture()
                details["0"]["_openedAt"] = "2026-10-10T00:00:00Z"
                serial_details = {"0": details["0"]} if verified else {}
                boundaries = []

                def wait(*args, **kwargs):
                    events.append("boundary")
                    if not boundaries:
                        self.assertEqual([r[0] for r in args[2]], ["serial"])
                        self.assertTrue(kwargs["require_complete"])
                        boundary = xinstr.burst_accounting(serial_details, args[2], exp, {})
                    else:
                        self.assertEqual([r[0] for r in args[2]], ["burst"])
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
                        scenarios=[SimpleNamespace(id="serial", kind="business"), SimpleNamespace(id="burst", kind="concurrency")],
                        out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations=exp, xtrace="xtrace",
                        project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                        canaries=None, baseline_receipt=None, extra_canary_paths=[], harness_files=[])
                self.assertEqual(events, ["serial", "boundary", "burst", "boundary"] if verified else ["serial", "boundary"])
                self.assertEqual(receipt["notes"]["serialBoundary"], boundaries[0])
                self.assertEqual(receipt["notes"]["serialBoundary"]["verified"], verified)
                burst = next(s for s in receipt["scenarios"] if s["id"] == "burst")
                self.assertFalse(burst["recordingVerdict"]["passed"])
                if verified:
                    self.assertEqual(receipt["notes"]["burstBoundary"], boundaries[1])
                    self.assertTrue(receipt["notes"]["burstBoundary"]["verified"])
                    self.assertEqual(receipt["result"], "recorded")
                    self.assertEqual(receipt["api"]["recordings"], 2)
                    serial = next(s for s in receipt["scenarios"] if s["id"] == "serial")
                    self.assertTrue(serial["recordingVerdict"]["passed"])
                    self.assertTrue(burst["scenarioChecksPassed"])
                    self.assertEqual(burst["recordingVerdict"]["recordingsAttributed"], 0)
                    self.assertEqual(burst["recordingVerdict"]["expectations"][0]["problems"], [BURST_CORRELATION_PROBLEM])
                    self.assertEqual(receipt["problemClasses"], {"attribution-ambiguous": 1})
                self.assertTrue(all("frameSymbols" in sc for sc in receipt["scenarios"]))
                stack.down.assert_called_once()
                if not verified:
                    self.assertFalse(burst["scenarioChecksPassed"])
                    self.assertEqual(burst["notRunReason"], "serial boundary was not verified")
                    self.assertEqual(receipt["result"], "failed", "a later API read cannot repair a skipped workload")

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
                boundary = {"verified": boundary_ok, "recordingIds": [], "snapshotIds": []}
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
