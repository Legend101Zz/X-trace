import pathlib
import sys
import unittest
from unittest import mock
import subprocess

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
        with mock.patch.object(xinstr.time, "time", return_value=123):
            boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(boundary["verified"])
        self.assertEqual(boundary["verifiedAt"], 123)
        self.assertEqual(boundary["recordingIds"], ["0", "1"])
        self.assertEqual(boundary["recordingCount"], 2)
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertTrue(verdict["burst"]["passed"], verdict)
        details["0"]["outcome"]["httpStatus"] = 500
        verdict = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertEqual(verdict["burst"]["expectations"][0]["problems"],
                         ["http-outcome-count-mismatch(expected 2, observed 1)"])

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
        self.assertEqual(v["burst"]["expectations"][0]["problems"],
                         ["burst-unaccounted(requests 2, recordings 1, capacity drops 0, unaccounted 1)"])
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
        self.assertEqual(v["burst"]["recordingsAttributed"], 2)
        del details["serial"]
        del details["late"]
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertEqual(v["serial"]["expectations"][0]["problems"],
                         ["serial-count-mismatch(recordings 0, requests 1)"])

    def test_capacity_drops_are_deduplicated_and_partials_still_fail(self):
        exp, sent, details = self.boundary_fixture()
        evidence = "1 requests were not recorded: agent capacity (session s, cumulative as last reported)"
        details["0"]["incompleteEvidence"] = [evidence]
        details["1"]["incompleteEvidence"] = [evidence]
        self.assertEqual(xinstr.capacity_counts(details), {"s": 1})
        # One admitted forced drop and one refused request fully account for the burst, but fail it.
        details.pop("1")
        details["0"]["completion"] = "partial"
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        self.assertTrue(boundary["verified"])
        self.assertEqual(boundary["capacityDrops"], 1)
        self.assertEqual(boundary["partialRecordingIds"], ["0"])
        v = xinstr.analyze(details, exp, sent, frozenset({"burst"}), boundary)
        self.assertEqual(v["burst"]["expectations"][0]["problems"], ["burst-drops(capacity 1, partial 1)"])
        before = {"old": {"incompleteEvidence": [evidence]}}
        self.assertFalse(xinstr.burst_accounting(details, sent, exp, before)["verified"])

    def test_open_and_excess_route_recordings_do_not_verify_boundary(self):
        exp, sent, details = self.boundary_fixture()
        details["0"]["completion"] = "open"
        self.assertFalse(xinstr.burst_accounting(details, sent, exp, {})["verified"])
        details["0"]["completion"] = "complete"
        details["extra"] = dict(details["0"])
        self.assertFalse(xinstr.burst_accounting(details, sent, exp, {})["verified"])

    def test_orchestration_waits_before_serial_and_stops_when_unaccounted(self):
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
                exp, sent, details = self.boundary_fixture()
                boundary = xinstr.burst_accounting(details, sent, exp, {})
                boundary["verified"] = verified
                def wait(*args):
                    events.append("boundary")
                    return boundary
                api = {"ok": True, "reason": "", "recordings": [], "details": {}}
                with mock.patch.object(xinstr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "")), \
                     mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
                     mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A" * 43})), \
                     mock.patch.object(xinstr, "ViewerClient"), \
                     mock.patch.object(xinstr, "stop_process_group"), \
                     mock.patch.object(xinstr, "collect_api", return_value=api), \
                     mock.patch.object(xinstr, "wait_burst_boundary", side_effect=wait), \
                     mock.patch.object(xcamp, "run_scenario", side_effect=run):
                    receipt = xinstr.run_instrumented(
                        project="p", pin={}, make_stack=lambda _: stack,
                        scenarios=[SimpleNamespace(id="serial", kind="business"), SimpleNamespace(id="burst", kind="concurrency")],
                        out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations=exp, xtrace="xtrace",
                        project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                        canaries=None, baseline_receipt=None, extra_canary_paths=[], harness_files=[])
                self.assertEqual(events, ["burst", "boundary", "serial"] if verified else ["burst", "boundary"])
                self.assertEqual(receipt["notes"]["burstBoundary"], boundary)
                stack.down.assert_called_once()
                if not verified:
                    serial = next(s for s in receipt["scenarios"] if s["id"] == "serial")
                    self.assertFalse(serial["scenarioChecksPassed"])
                    self.assertEqual(serial["notRunReason"], "burst boundary was not verified")

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
             mock.patch.object(xinstr, "analyze", return_value={}) as analyze:
            receipt = xinstr.run_instrumented(project="petclinic", pin={}, make_stack=lambda tag: stack,
                scenarios=[scenario], out_dir=pathlib.Path(td) / "out", norm_extra=[], expectations={}, xtrace="xtrace",
                project_dir=pathlib.Path(td), data_home=pathlib.Path(td) / "data", adaptations=[],
                canaries=None, baseline_receipt=None, extra_canary_paths=[], harness_files=[])
        self.assertEqual(receipt["api"]["recordings"], 1)
        self.assertEqual(set(analyze.call_args.args[0]), {"new"})
        self.assertEqual(receipt["notes"]["accommodations"]["pace_seconds"], 0.4)
        self.assertEqual(receipt["notes"]["accommodations"]["drain_seconds"], 0)
        self.assertIn("8 unwritten", receipt["notes"]["accommodations"]["reason"])
        self.assertEqual(receipt["notes"]["accommodations"]["correlationGap"], xinstr.REQUEST_CORRELATION_GAP)
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
