import json
import hashlib
from contextlib import nullcontext
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xflows  # noqa: E402


def rec(method="GET", route="/vets", completion="complete", events=4, evidence=()):
    evs = [{"kind": "recording_event_kind:request_update", "symbol": f"http.request {method} {route}"}]
    evs += [{"kind": "recording_event_kind:frame_enter", "symbol": "X.y"}] * (events - 1)
    return {"events": evs, "completion": completion, "incompleteEvidence": list(evidence)}


def line_rec(start=10, end=30, lines=(12, 15), fid="f1", with_source=True):
    symbol = "A.run#m1:" + hashlib.sha256(b"demo.A\0run\0()V").hexdigest()
    evs = [{"kind": "recording_event_kind:frame_enter", "frameId": fid, "symbol": symbol,
            "source": {"path": "A.java", "startLine": start, "endLine": end, "status": "matched"} if with_source else None}]
    evs += [{"kind": "recording_event_kind:line_cursor", "frameId": f"{fid}-cursor-{i}", "parentFrameId": fid,
             "line": n, "symbol": symbol,
             "source": {"path": "A.java", "startLine": n, "endLine": n, "status": "matched"}}
            for i, n in enumerate(lines)]
    return {"events": evs}


def privacy_details(marker="XTplain.0123456789abcdef"):
    details = {label: {**rec(method, route), "outcome": {"kind": "responded", "httpStatus": 200}}
               for label, (method, route) in xflows.FOCUSED_REQUESTS.items()}
    details["owner"]["events"].extend(line_rec()["events"])
    details["secret"]["events"].append({"bindings": [{"name": "lastName", "value": {
        "state": "redacted", "ruleId": "content.secret_pattern", "shapeHint": "string"}}]})
    details["plain"]["events"].append({"bindings": [{"name": "lastName", "value": {
        "state": "captured", "preview": marker, "shape": "string", "contentHash": "b3:" + "0" * 64}}]})
    return details


def viewer_pages(details, gap=None):
    pages = [(200, {"recordings": [{"recordingId": rid} for rid in details],
                    "nextAfter": "next" if gap == "listing" else None})]
    if gap == "listing":
        pages.append((503, {"detail": "private"}))
    for index, (rid, detail) in enumerate(details.items()):
        interrupted = index == 0 and gap == "detail"
        pages.append((200, {**detail, "recordingId": rid, "nextCursor": "next" if interrupted else None}))
        if interrupted:
            pages.append(ConnectionResetError("private"))
    return pages


class Judges(unittest.TestCase):
    wanted = [("GET", "/vets"), ("GET", "/owners/{ownerId}")]

    def rs(self, **kw):
        base = dict(record_rc=0, record_doc={"data": {"bootstrap_path": "/x", "pid": 5}}, served={"/vets": 200}, stop_rc=0,
                    daemon_gone=True, new_details={"a": rec("GET", "/vets"), "b": rec("GET", "/owners/{ownerId}")}, wanted=self.wanted)
        base.update(kw)
        return xflows.judge_record_stop(**base)

    def test_record_stop_pass_and_each_failure(self):
        self.assertEqual(self.rs()[0], "pass")
        self.assertEqual(self.rs(record_rc=9)[0], "not-implemented")
        self.assertEqual(self.rs(record_rc=2)[0], "fail")
        self.assertEqual(self.rs(record_doc={})[0], "fail")
        self.assertEqual(self.rs(served={"/vets": 500})[0], "fail")
        self.assertEqual(self.rs(stop_rc=3)[0], "fail")
        self.assertEqual(self.rs(daemon_gone=False)[0], "fail")
        st, note = self.rs(new_details={"a": rec("GET", "/vets")})
        self.assertEqual(st, "fail")
        self.assertIn("/owners/{ownerId}", note)
        st, note = self.rs(new_details={"a": rec("GET", "/vets"), "b": rec("GET", "/owners/{ownerId}", completion="partial")})
        self.assertEqual((st, "not complete" in note or "not complete" in note), ("fail", True))

    def test_restart_reopen(self):
        before = {"id1": ("complete", 4)}
        ok = dict(restart_rc=0, restart_doc={}, started_alive=True, before=before, after_details={"id1": rec(events=4)}, stop_rc=0)
        self.assertEqual(xflows.judge_restart_reopen(**ok)[0], "pass")
        self.assertEqual(xflows.judge_restart_reopen(**{**ok, "after_details": {}})[0], "fail")
        self.assertEqual(xflows.judge_restart_reopen(**{**ok, "after_details": {"id1": rec(events=5)}})[0], "fail")
        self.assertEqual(xflows.judge_restart_reopen(**{**ok, "after_details": {"id1": rec(completion="partial")}})[0], "fail")
        self.assertEqual(xflows.judge_restart_reopen(**{**ok, "before": {}})[0], "fail")
        self.assertEqual(xflows.judge_restart_reopen(**{**ok, "started_alive": False})[0], "fail")
        self.assertEqual(xflows.judge_restart_reopen(**{**ok, "restart_rc": 9})[0], "not-implemented")

    def test_partial(self):
        stalled = ("POST", "/owners/new")
        ctl = [rec("GET", "/vets")]
        part = rec("POST", "/owners/new", completion="partial", events=2, evidence=["gap_event_sequence"])
        ok = dict(record_rc=0, stop_rc=0, stop_doc={}, control_details=ctl, new_details={"p": part}, stalled=stalled, stalled_id="p")
        self.assertEqual(xflows.judge_partial(**ok)[0], "pass")
        self.assertEqual(xflows.judge_partial(**{**ok, "stop_rc": 10})[0], "pass")
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {}})[0], "fail")
        liar = rec("POST", "/owners/new", completion="complete")
        self.assertIn("complete", xflows.judge_partial(**{**ok, "new_details": {"p": part, "l": liar}})[1])
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {"p": rec("POST", "/owners/new", "partial")}})[0], "fail")
        self.assertEqual(xflows.judge_partial(**{**ok, "control_details": []})[0], "fail")
        self.assertEqual(xflows.judge_partial(**{**ok, "stop_rc": 4})[0], "fail")
        self.assertEqual(xflows.judge_partial(**{**ok, "stalled_id": None})[0], "fail")
        unrelated = rec("GET", "/vets", "partial", evidence=["interrupted"])
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {"p": unrelated}})[0], "fail")
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {"another": part}})[0], "fail")
        empty = {**part, "events": []}
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {"p": empty}})[0], "fail")
        self.assertIn("not invoked", xflows.judge_partial(**{**ok, "stop_rc": None})[1])
        self.assertEqual(xflows.judge_partial(**{**ok, "stop_rc": -1})[0], "fail")
        # Other partials are extra evidence and cannot stand in for the observed request.
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {"p": part, "other": unrelated}})[0], "pass")

    def test_active_line(self):
        self.assertEqual(xflows.judge_active_line([line_rec()])[0], "pass")
        st, note = xflows.judge_active_line([line_rec(lines=(10, 10))])
        self.assertEqual(st, "fail")
        self.assertIn("method start", note)
        self.assertEqual(xflows.judge_active_line([line_rec(lines=(99,))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(lines=(0,))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(lines=(True,))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(end=None, lines=(9, 12))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(with_source=False, lines=(3, 4))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(with_source=False, lines=(3,))])[0], "fail")
        gap = {"events": [{"kind": "recording_event_kind:gap", "symbol": "gap.not-transformed"}]}
        st, note = xflows.judge_active_line([gap])
        self.assertEqual(st, "fail")
        self.assertIn("gap.not-transformed", note)
        self.assertEqual(xflows.judge_active_line([])[0], "fail")

    def test_line_extent_comes_only_from_parent_method_in_the_same_recording(self):
        detail = line_rec()
        lines = xflows._line_events([detail])
        self.assertEqual([(ev["line"], src["startLine"], src["endLine"]) for ev, src in lines], [(12, 10, 30), (15, 10, 30)])
        for ev in detail["events"][1:]:
            ev["parentFrameId"] = "missing"
        status, note = xflows.judge_active_line([detail, line_rec(fid="other")])
        self.assertEqual(status, "fail")
        self.assertIn("parentFrameId", note)
        # A different recording with a coincident frame id cannot supply the missing parent.
        self.assertEqual(xflows.judge_active_line([{"events": detail["events"][1:]}, line_rec(fid="missing")])[0], "fail")

    def test_cursor_range_cannot_hide_a_line_outside_its_parent_method(self):
        detail = line_rec(lines=(12, 99))
        self.assertEqual(xflows.judge_active_line([detail])[0], "fail")
        detail["events"][0]["kind"] = "recording_event_kind:frame_exit"
        self.assertEqual(xflows.judge_active_line([detail])[0], "fail")

    def test_accessor_cursor_cannot_borrow_its_callers_overlapping_extent(self):
        detail = line_rec()
        getter = "A.getName#m1:" + hashlib.sha256(b"demo.A\0getName\0()Ljava/lang/String;").hexdigest()
        for event in detail["events"][1:]:
            event["symbol"] = getter
        # The getter was observed, but its id is not the recorded cursor parent.
        detail["events"].append({**detail["events"][0], "frameId": "getter", "symbol": getter})
        self.assertEqual(xflows.line_parent_gaps([detail]), {"parent-method-symbol-mismatch": 2})
        status, note = xflows.judge_active_line([detail])
        self.assertEqual(status, "fail")
        self.assertIn("parent-method-symbol-mismatch", note)
        self.assertNotIn("A.getName", note)
        self.assertNotIn("A.run", note)
        for event in detail["events"][1:3]:
            event["parentFrameId"] = "getter"
        self.assertEqual(xflows.line_parent_gaps([detail]), {})
        self.assertEqual(xflows.judge_active_line([detail])[0], "pass")

    def test_overload_cursor_cannot_borrow_a_same_named_callers_overlapping_lines(self):
        detail = line_rec()
        # Both overloads declare the same lines. The callee's entry was dropped, and its cursor
        # borrows the accepted caller's parent id. Names and extents alone would accept this.
        callee = "A.run#m1:" + hashlib.sha256(b"demo.A\0run\0(I)V").hexdigest()
        for event in detail["events"][1:]:
            event["symbol"] = callee
        status, note = xflows.judge_active_line([detail])
        self.assertEqual(status, "fail")
        self.assertEqual(xflows.line_parent_gaps([detail]), {"parent-method-symbol-mismatch": 2})
        self.assertIn("parent-method-symbol-mismatch", note)
        self.assertNotIn(callee, note)
        detail["events"].append({**detail["events"][0], "frameId": "overload", "symbol": callee})
        for event in detail["events"][1:3]:
            event["parentFrameId"] = "overload"
        self.assertEqual(xflows.judge_active_line([detail])[0], "pass")

    def test_cursor_parent_requires_an_observed_overload_distinguishing_identity(self):
        for symbol in (None, "A.run", "A.run#m1:" + "0" * 63, "A.run#m1:" + "g" * 64):
            with self.subTest(symbol=symbol):
                detail = line_rec()
                for event in detail["events"]:
                    event["symbol"] = symbol
                self.assertEqual(xflows.line_parent_gaps([detail]), {"parent-method-identity-unavailable": 2})
                self.assertEqual(xflows.judge_active_line([detail])[0], "fail")

    def test_request_parent_is_not_a_method_extent_even_with_matching_source(self):
        detail = line_rec()
        detail["events"][0]["kind"] = "recording_event_kind:request_update"
        self.assertEqual(xflows.line_parent_gaps([detail]), {"parent-is-not-method-entry": 2})
        status, note = xflows.judge_active_line([detail])
        self.assertEqual(status, "fail")
        self.assertIn("2 line events", note)
        self.assertIn("parent-is-not-method-entry", note)

    def test_line_parent_diagnostics_distinguish_missing_non_method_and_unavailable_extent(self):
        details = [line_rec(fid=str(i)) for i in range(3)]
        details[0]["events"].pop(0)
        details[1]["events"][0]["kind"] = "recording_event_kind:request_update"
        details[2]["events"][0]["source"] = None
        expected = {"parent-not-observed": 2, "parent-is-not-method-entry": 2, "parent-method-extent-unavailable": 2}
        self.assertEqual(xflows.line_parent_gaps(details), expected)
        status, note = xflows.judge_active_line(details)
        self.assertEqual(status, "fail")
        self.assertIn("6 line events", note)
        for reason in expected:
            self.assertIn(reason, note)

    def test_parent_method_can_be_on_an_earlier_api_page(self):
        detail = line_rec()
        client = Mock()
        client.get.side_effect = [
            (200, {"recordings": [{"recordingId": "r"}], "nextAfter": None}),
            (200, {"events": detail["events"][:1], "nextCursor": "page-two"}),
            (200, {"events": detail["events"][1:], "nextCursor": None}),
        ]
        with tempfile.TemporaryDirectory() as td:
            api = xflows.xinstr.collect_api(client, pathlib.Path(td))
        self.assertTrue(api["ok"])
        self.assertIn("cursor=page-two", client.get.call_args.args[0])
        self.assertEqual(xflows.judge_active_line(list(api["details"].values()))[0], "pass")

    def test_distinct_method_starts_are_not_evidence_of_an_executed_line_within_a_method(self):
        self.assertEqual(xflows.judge_active_line([line_rec(start=10, lines=(10,)),
                                                  line_rec(start=20, lines=(20,))])[0], "fail")

    def test_frame_values(self):
        cap = {"events": [{"kind": "k", "bindings": [{"name": "ownerId", "role": "argument", "nameOrigin": "x",
                                                      "value": {"state": "captured", "shape": "int", "preview": "4", "contentHash": "b3:" + "0" * 64}}]}]}
        self.assertEqual(xflows.judge_frame_values([cap])[0], "pass")
        red = {"events": [{"kind": "k", "bindings": [{"name": "p", "value": {"state": "redacted", "ruleId": "r", "shapeHint": None}}]}]}
        st, note = xflows.judge_frame_values([red])
        self.assertEqual(st, "fail")
        self.assertIn("redacted", note)
        self.assertEqual(xflows.judge_frame_values([{"events": [{"kind": "k", "bindings": []}]}])[0], "fail")
        self.assertEqual(xflows.judge_frame_values([])[0], "fail")

    def test_helpers(self):
        self.assertEqual(xflows.find_key({"a": [{"b": {"pid": 7}}]}, "pid"), 7)
        self.assertIsNone(xflows.find_key({"a": 1}, "pid"))
        self.assertEqual(xflows.parse_doc('{"x": 1}\n'), {"x": 1})
        self.assertIsNone(xflows.parse_doc("noise\n{\"x\": 1}\n"))
        self.assertIsNone(xflows.parse_doc("none"))

    def test_parse_doc_keeps_the_whole_pretty_document(self):
        for value in ("src/main/java", 7, True, None, {"pid": 71}):
            doc = {"data": {"pid": 71, "bootstrap_path": "/bootstrap.json", "items": [value]}}
            text = json.dumps(doc, indent=2)
            self.assertEqual(xflows.parse_doc(text), doc)
            for rc in (0, 2):
                result = subprocess.CompletedProcess([], rc, stdout=text if rc == 0 else "", stderr=text if rc else "")
                with mock.patch.object(xflows.subprocess, "run", return_value=result):
                    self.assertEqual(xflows.cli("xtrace", ["record"], {}), (rc, doc))
        self.assertIsNone(xflows.parse_doc('{"first": 1}\n{"second": 2}\n'))
        self.assertIsNone(xflows.parse_doc('{"items": [\n  "inner"\n'))

    def test_focused_canaries_preserve_metadata_locations_and_add_business_controls(self):
        import xcamp
        import urllib.parse
        canaries = {k: "canary-" + k for k in ("authorization-header", "cookie-header", "query-token", "json-body-password", "focused-business-secret")}
        observe = Mock()
        marker = "XTplain.0123456789abcdef"
        with mock.patch.object(xcamp, "http_request", return_value={"status": 200}) as request:
            served = xflows.focused_requests("http://127.0.0.1:1234", canaries, observe, marker)
        self.assertEqual(list(served.values()), [200] * 6)
        self.assertEqual([call.args[:3] for call in observe.call_args_list],
                         [(label, method, route) for label, (method, route) in xflows.FOCUSED_REQUESTS.items()])
        paths = [call.args[2] for call in request.call_args_list]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(paths[1]).query)["lastName"], ["Davis"])
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(paths[4]).query)["lastName"], [canaries["focused-business-secret"]])
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(paths[5]).query)["lastName"], [marker])
        for call in request.call_args_list:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(call.args[2]).query)
            self.assertEqual(query["xt_token"], [canaries["query-token"]])
            self.assertNotIn("password", query)
            self.assertNotIn(canaries["query-token"], query.get("lastName", []))
            self.assertEqual(call.kwargs["headers"]["Authorization"], canaries["authorization-header"])
            self.assertEqual(call.kwargs["headers"]["Cookie"], canaries["cookie-header"])
        post = request.call_args_list[3]
        self.assertEqual(post.args[1], "POST")
        self.assertEqual(urllib.parse.urlsplit(post.args[2]).path, "/owners/new")
        self.assertEqual(post.kwargs["headers"]["Content-Type"], "application/x-www-form-urlencoded")
        form = urllib.parse.parse_qs(post.kwargs["body"].decode(), keep_blank_values=True)
        self.assertEqual(form["password"], [canaries["json-body-password"]])
        self.assertEqual(form["firstName"], [""])
        self.assertEqual(form["lastName"], ["Invalid"])
        self.assertTrue(all(call.kwargs["body"] is None for i, call in enumerate(request.call_args_list) if i != 3))
        self.assertNotIn("canary-", str(served), "flow receipt must not itself save the injected values")

    def test_canary_recordings_require_every_request_including_successful_post(self):
        details = privacy_details()
        served = dict.fromkeys(xflows.FOCUSED_REQUESTS, 200)
        attributed = {label: label for label in served}
        judge = lambda ds, ids=attributed, responses=served: xflows.judge_canary_recordings(responses, ids, ds, xflows.FOCUSED_REQUESTS)[0]
        self.assertEqual(judge(details), "pass")
        for label in served:
            with self.subTest(missing=label):
                self.assertEqual(judge({k: d for k, d in details.items() if k != label}), "fail")
                self.assertEqual(judge(details, {k: rid for k, rid in attributed.items() if k != label}), "fail")
        self.assertEqual(judge({**details, "form": {**details["form"], "completion": "partial"}}), "fail")
        self.assertEqual(judge(details, {**attributed, "secret": "search"}), "fail")
        self.assertEqual(judge(details, responses={**served, "form": None}), "fail")
        self.assertEqual(judge({**details, "form": {**details["form"], "outcome": {"httpStatus": 500}}}), "fail")

    def test_redaction_needs_the_business_binding_rule_and_no_raw_secret(self):
        detail = privacy_details()["secret"]
        canaries = {"focused-business-secret": "Bearer XTCANARY.bound.0123456789abcdef"}
        self.assertEqual(xflows.judge_redaction(detail, canaries)[0], "pass")
        self.assertEqual(xflows.judge_redaction(rec(), canaries)[0], "fail")
        for field, value in (("state", "unavailable"), ("ruleId", "name.secret")):
            candidate = json.loads(json.dumps(detail))
            candidate["events"][-1]["bindings"][0]["value"][field] = value
            self.assertEqual(xflows.judge_redaction(candidate, canaries)[0], "fail")
        candidate = json.loads(json.dumps(detail))
        candidate["events"][-1]["bindings"][0]["name"] = "password"
        self.assertEqual(xflows.judge_redaction(candidate, canaries)[0], "fail")
        detail["leak"] = canaries["focused-business-secret"]
        self.assertEqual(xflows.judge_redaction(detail, canaries)[0], "fail")

    def test_plain_control_is_captured_only_in_its_binding_and_standard_has_no_bindings(self):
        marker = "XTplain.0123456789abcdef"
        details = privacy_details(marker)
        self.assertEqual(xflows.judge_value_control(details, "plain", marker)[0], "pass")
        self.assertEqual(xflows.judge_value_control(details, "search", marker)[0], "fail")
        missing = {k: d for k, d in details.items() if k != "plain"}
        self.assertEqual(xflows.judge_value_control(missing, "plain", marker)[0], "fail")
        details["owner"]["leak"] = marker
        self.assertEqual(xflows.judge_value_control(details, "plain", marker)[0], "fail")
        canaries = {"query-token": "XTCANARYqt0123456789abcdef"}
        standard = {"standard": rec("GET", "/owners")}
        self.assertEqual(xflows.judge_standard_values(standard, canaries)[0], "pass")
        self.assertEqual(xflows.judge_standard_values({}, canaries)[0], "fail")
        standard["standard"]["leak"] = canaries["query-token"]
        self.assertEqual(xflows.judge_standard_values(standard, canaries)[0], "fail")
        for state in ("captured", "redacted", "unavailable"):
            self.assertEqual(xflows.judge_standard_values({"s": {"events": [{"bindings": [{"value": {"state": state}}]}]}}, {})[0], "fail")

    def test_canary_wait_requires_new_unambiguous_complete_recording_and_obeys_deadline(self):
        detail = privacy_details()["form"]
        client = Mock()
        snapshots = [{"ok": True, "details": {"old": detail}},
                     {"ok": True, "details": {"old": detail, "new": {**detail, "completion": "open"}}},
                     {"ok": True, "details": {"old": detail, "new": detail}}]
        with patch.object(xflows.xinstr, "collect_api", side_effect=snapshots), patch.object(xflows.time, "monotonic", return_value=0):
            rid, details = xflows.wait_canary_recording(client, pathlib.Path("unused"), {"old": detail}, "POST", "/owners/new", 30)
        self.assertEqual(rid, "new")
        self.assertEqual(details["new"], detail)
        self.assertIsNone(client.deadline)
        for snapshot in ({"ok": True, "details": {"a": detail, "b": detail}},
                         {"ok": True, "details": {"a": {**detail, "completion": "partial"}}}, {"ok": False}):
            with self.subTest(snapshot=snapshot), patch.object(xflows.xinstr, "collect_api", return_value=snapshot), \
                 patch.object(xflows.time, "monotonic", return_value=0), self.assertRaises(RuntimeError):
                xflows.wait_canary_recording(client, pathlib.Path("unused"), {}, "POST", "/owners/new", 30)
        with patch.object(xflows.xinstr, "collect_api", return_value={"ok": True, "details": {}}), \
             patch.object(xflows.time, "monotonic", side_effect=[0, 31]), self.assertRaises(RuntimeError):
            xflows.wait_canary_recording(client, pathlib.Path("unused"), {}, "POST", "/owners/new", 30)
        self.assertIsNone(client.deadline)

    def test_open_partial_prefix_is_polled_until_terminal_proof_without_sleeping(self):
        detail = privacy_details()["owner"]
        snapshots = [{"ok": True, "details": {"new": {**detail, "status": status, "completion": "partial"}}}
                     for status in ("recording", "finalizing")]
        snapshots.append({"ok": True, "details": {"new": {**detail, "status": "complete"}}})
        client = Mock()
        with patch.object(xflows.xinstr, "collect_api", side_effect=snapshots) as collect, \
                patch.object(xflows.time, "monotonic", return_value=0), patch.object(xflows.time, "sleep") as sleep:
            rid, details = xflows.wait_canary_recording(client, pathlib.Path("unused"), {}, "GET", "/owners/{ownerId}", 30)
        self.assertEqual(rid, "new")
        self.assertEqual(details["new"]["status"], "complete")
        self.assertEqual(collect.call_count, 3)
        sleep.assert_not_called()
        self.assertIsNone(client.deadline)
        for status, completion in (("partial", "partial"), ("invalid", "invalid")):
            with self.subTest(status=status), patch.object(xflows.time, "monotonic", return_value=0), \
                    patch.object(xflows.xinstr, "collect_api", return_value={
                        "ok": True, "details": {"new": {**detail, "status": status, "completion": completion}}}) as collect:
                with self.assertRaisesRegex(xflows.CanaryEvidenceError, "not complete"):
                    xflows.wait_canary_recording(client, pathlib.Path("unused"), {}, "GET", "/owners/{ownerId}", 30)
                self.assertEqual(collect.call_count, 1)

    def test_open_recording_does_not_extend_the_request_budget(self):
        detail = {**privacy_details()["owner"], "status": "recording", "completion": "partial"}
        with patch.object(xflows.time, "monotonic", side_effect=[0, 30]), \
                patch.object(xflows.xinstr, "collect_api", return_value={"ok": True, "details": {"new": detail}}):
            with self.assertRaisesRegex(xflows.CanaryEvidenceError, "within its request budget"):
                xflows.wait_canary_recording(Mock(), pathlib.Path("unused"), {}, "GET", "/owners/{ownerId}", 30)

    def test_terminal_canary_failure_names_observed_loss_without_echoing_private_fields(self):
        detail = {**privacy_details()["owner"], "status": "partial", "completion": "partial"}
        detail["events"] = [*detail["events"], {
            "kind": "recording_event_kind:gap", "symbol": "private.symbol",
            "gap": {"reason": "class_not_transformed", "count": "12", "message": "private value"}}]
        client = Mock()
        with patch.object(xflows.time, "monotonic", return_value=0), \
                patch.object(xflows.xinstr, "collect_api", return_value={"ok": True, "details": {"new": detail}}) as collect:
            with self.assertRaises(xflows.CanaryEvidenceError) as caught:
                xflows.wait_canary_recording(client, pathlib.Path("unused"), {}, "GET", "/owners/{ownerId}", 30)
        self.assertEqual(str(caught.exception),
                         "canary request recording is not complete (status=partial; observed gaps: class_not_transformed=12)")
        self.assertEqual(collect.call_count, 1)
        self.assertIsNone(client.deadline)

    def test_canary_loss_note_masks_unknown_text_and_rejects_unbounded_counts(self):
        detail = {"status": "private status", "events": [
            {"kind": "gap", "gap": {"reason": "private reason", "count": "1"}},
            {"kind": "gap", "gap": {"reason": "queue_full", "count": "9" * 21}},
            {"kind": "gap", "gap": {"reason": "queue_full", "count": "private count"}},
            {"kind": "gap", "gap": {"reason": ["private"], "count": "1"}}]}
        note = xflows.canary_incomplete_note(detail)
        self.assertEqual(note,
                         "canary request recording is not complete (status=unrecognized; observed gaps: unrecognized=2)")
        self.assertNotIn("private", note)

    def test_focused_without_canaries_fails_before_launching(self):
        import os
        flow = xflows.Flows.__new__(xflows.Flows)
        flow.results = {}
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(flow, "_stack") as stack:
            flow.focused()
        stack.assert_not_called()
        for name in ("active-line-frames", "frame-values", "focused-canary-injection"):
            self.assertEqual(flow.results[name]["status"], "fail")

    def test_control_pacing_has_no_final_drain_sleep(self):
        events = []
        with mock.patch.object(xflows.time, "sleep", side_effect=lambda gap: events.append(("pace", gap))), \
             mock.patch.object(xflows, "_get", side_effect=lambda base, path: events.append(("request", path)) or 200):
            served = xflows._paced_gets("http://127.0.0.1:1234", ["/vets", "/owners"])
        self.assertEqual(served, {"/vets": 200, "/owners": 200})
        self.assertEqual(events, [("pace", 0.6), ("request", "/vets"), ("pace", 0.6), ("request", "/owners")])


class Drivers(unittest.TestCase):
    def flow(self):
        flow = object.__new__(xflows.Flows)
        flow.xtrace, flow.project_dir = "xtrace", pathlib.Path("/project")
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        flow.agent, flow.out_dir = "agent.jar", pathlib.Path(scratch.name)
        flow.app_package, flow.source_root = "com.example.app", "src/main/java"
        flow.env, flow.results = {}, {}
        flow._stack = Mock(return_value=Mock(base="http://127.0.0.1:8000", host_port=8000))
        flow._stack.return_value.hold_owner_writes = Mock(side_effect=nullcontext)
        flow._stop_daemon_quietly = Mock()
        return flow

    def result(self, doc, rc=0):
        text = json.dumps(doc, indent=2) + "\n"
        return subprocess.CompletedProcess([], rc, stdout=text if rc == 0 else "", stderr=text if rc else "")

    def armed(self):
        # These final bare string array elements triggered the line-oriented parser bug.
        return {"kind": "recording", "pid": 71, "bootstrap_path": "/bootstrap.json",
                "application_packages": ["com.example.app"], "source_roots": ["src/main/java"]}

    def api(self, details):
        return {"ok": True, "reason": "", "details": details}

    def test_focused_uses_stack_port_reads_artifacts_and_does_not_hide_canary_leaks(self):
        import os
        from tools.qa import canary
        flow = self.flow()
        canaries = canary.make_canaries()
        details = privacy_details()
        with tempfile.TemporaryDirectory() as td:
            flow.out_dir = pathlib.Path(td) / "flows"
            path = pathlib.Path(td) / "canaries.json"
            path.write_text(json.dumps(canaries))
            def read_api(*args):
                dest = args[-1]
                dest.mkdir(parents=True, exist_ok=True)
                # Simulate an observed leak in a focused binding: it must remain a scan failure.
                (dest / "recording-new.json").write_text(json.dumps({"preview": canaries["query-token"]}))
                return self.api(details)
            def requests(base, injected, observe, marker):
                self.assertEqual(marker, "XTplain.0123456789abcdef")
                for label, (method, route) in xflows.FOCUSED_REQUESTS.items():
                    observe(label, method, route, 30)
                return dict.fromkeys(xflows.FOCUSED_REQUESTS, 200)
            with patch.dict(os.environ, {"XCAMP_CANARY_FILE": str(path)}), \
                 patch.object(xflows, "list_ids", return_value={"old"}), \
                 patch.object(xflows.secrets, "token_hex", return_value="0123456789abcdef"), \
                 patch.object(xflows.xinstr, "start_viewer", return_value=(Mock(), {"origin": "http://127.0.0.1:9000", "url": "unused"})), \
                 patch.object(xflows.xinstr, "ViewerClient"), patch.object(xflows.xinstr, "stop_process_group"), \
                 patch.object(xflows.xinstr, "collect_api", return_value=self.api({})), \
                 patch.object(xflows, "wait_canary_recording", side_effect=[(label, details) for label in xflows.FOCUSED_REQUESTS]) as wait, \
                 patch.object(xflows, "focused_requests", side_effect=requests) as send, \
                 patch.object(xflows, "read_api", side_effect=read_api) as read:
                flow.focused()
                self.assertEqual(os.environ["XTRACE_CANARY_ENV"], canaries["env-var"])
            self.assertEqual(send.call_args.args[:2], (flow._stack.return_value.base, canaries))
            self.assertEqual(wait.call_count, 6)
            self.assertIn("--capture-depth focused", flow._stack.call_args.args[0])
            self.assertEqual(read.call_args.args[-1], flow.out_dir / "api-focused")
            self.assertEqual(flow.results["focused-canary-injection"]["status"], "pass")
            self.assertIn("6 canary requests", flow.results["focused-canary-injection"]["note"])
            for step in ("active-line-frames", "frame-values", "focused-redaction-control", "focused-value-control"):
                self.assertEqual(flow.results[step]["status"], "pass", flow.results[step])
            self.assertEqual(set(xflows.xinstr.CANARY_LOCATIONS), set(canaries))
            self.assertEqual(flow._stack.return_value.up.call_count, 1)
            flow._stack.return_value.down.assert_called_once()
            report = canary.run_scan(canaries, {"focused-artifacts": [flow.out_dir / "api-focused"]}, {"focused-artifacts": 1})
            self.assertFalse(report["clean"])
            self.assertEqual(report["uncovered"], [])
            self.assertEqual({hit["locationClass"] for hit in report["hits"]}, {"focused-artifacts"})
            self.assertNotIn(canaries["query-token"], json.dumps(report))

    def test_failed_focused_request_still_reads_artifacts_and_fails_both_judges(self):
        import os
        flow = self.flow()
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "canaries.json"
            path.write_text('{"env-var": "synthetic"}')
            with patch.dict(os.environ, {"XCAMP_CANARY_FILE": str(path)}), \
                 patch.object(xflows, "list_ids", return_value=set()), \
                 patch.object(xflows.xinstr, "start_viewer", return_value=(Mock(), {"origin": "http://127.0.0.1:9000", "url": "unused"})), \
                 patch.object(xflows.xinstr, "ViewerClient"), patch.object(xflows.xinstr, "stop_process_group"), \
                 patch.object(xflows.xinstr, "collect_api", return_value=self.api({})), \
                 patch.object(xflows, "focused_requests", return_value={"focused-request-0": None}), \
                 patch.object(xflows, "read_api", return_value=self.api({})) as read:
                flow.focused()
            self.assertEqual(read.call_count, 1)
            for step in ("focused-canary-injection", "active-line-frames", "frame-values"):
                self.assertEqual(flow.results[step]["status"], "fail")

    def test_http_200_post_without_recording_fails_focused_flow_and_controls(self):
        import os
        flow = self.flow()
        details = privacy_details()
        details.pop("form")
        served = dict.fromkeys(xflows.FOCUSED_REQUESTS, 200)
        with patch.dict(os.environ, {"XCAMP_CANARY_FILE": "unused"}), \
             patch.object(xflows.pathlib.Path, "read_text", return_value='{"env-var":"synthetic"}'), \
             patch.object(flow, "_privacy_capture", return_value=(served, {label: label for label in details}, details, "")):
            flow.focused()
        for step in ("focused-canary-injection", "focused-redaction-control", "focused-value-control", "active-line-frames", "frame-values"):
            self.assertEqual(flow.results[step]["status"], "fail", step)

    def test_standard_probe_sends_canary_as_business_parameter_and_requires_capture(self):
        import os
        import urllib.parse
        import xcamp
        from tools.qa import canary
        flow = self.flow()
        canaries = canary.make_canaries()
        details = {"standard": {**rec("GET", "/owners"), "outcome": {"kind": "responded", "httpStatus": 200}}}
        with tempfile.TemporaryDirectory() as td:
            flow.out_dir = pathlib.Path(td) / "flow"
            path = pathlib.Path(td) / "canaries.json"
            path.write_text(json.dumps(canaries))
            with patch.dict(os.environ, {"XCAMP_CANARY_FILE": str(path)}), \
                 patch.object(xflows, "list_ids", return_value=set()), \
                 patch.object(xflows.xinstr, "start_viewer", return_value=(Mock(), {"origin": "http://127.0.0.1:9000", "url": "unused"})), \
                 patch.object(xflows.xinstr, "ViewerClient"), patch.object(xflows.xinstr, "stop_process_group"), \
                 patch.object(xflows.xinstr, "collect_api", return_value=self.api({})), \
                 patch.object(xcamp, "http_request", return_value={"status": 200}) as request, \
                 patch.object(xflows, "wait_canary_recording", return_value=("standard", details)) as wait, \
                 patch.object(xflows, "read_api", return_value=self.api(details)) as read:
                flow.standard()
            self.assertIn("--capture-depth standard", flow._stack.call_args.args[0])
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.call_args.args[2]).query)
            self.assertEqual(query["lastName"], [canaries["query-token"]])
            self.assertEqual(query["xt_token"], [canaries["query-token"]])
            self.assertEqual(request.call_args.args[:2], (flow._stack.return_value.base, "GET"))
            self.assertEqual(wait.call_args.args[3:5], ("GET", "/owners"))
            self.assertEqual(read.call_args.args[-1], flow.out_dir / "api-standard")
            self.assertEqual(flow.results["standard-no-values"]["status"], "pass")
            self.assertNotIn(canaries["query-token"], json.dumps(flow.results))

        for attributed, new in (({}, details), ({"standard": "standard"}, {})):
            with patch.object(flow, "_canaries", return_value=canaries), \
                 patch.object(flow, "_privacy_capture", return_value=({"standard": 200}, attributed, new, "")):
                flow.standard()
            self.assertEqual(flow.results["standard-no-values"]["status"], "fail")

    def test_privacy_requires_complete_live_and_final_api_reads(self):
        import xcamp
        from tools.qa import canary

        canaries = canary.make_canaries()
        focused_steps = ("active-line-frames", "frame-values", *xflows.PRIVACY_STEPS[:3])
        details_by_mode = {
            "focused": privacy_details(),
            "standard": {"standard": {**rec("GET", "/owners"), "outcome": {"kind": "responded", "httpStatus": 200}}},
        }
        for mode, details in details_by_mode.items():
            for phase, gap in ((None, None), ("live", "listing"), ("live", "detail"),
                               ("final", "listing"), ("final", "detail")):
                with self.subTest(mode=mode, phase=phase, gap=gap):
                    flow = self.flow()
                    observed = {}
                    live_pages = viewer_pages({})
                    for rid, detail in details.items():
                        observed[rid] = detail
                        live_pages.extend(viewer_pages(observed, gap if phase == "live" else None))
                        if phase == "live":
                            break
                    live_client, final_client = Mock(deadline=None), Mock(deadline=None)
                    live_client.get.side_effect = live_pages
                    final_pages = viewer_pages(details, gap if phase == "final" else None)
                    final_client.get.side_effect = final_pages
                    ready = {"origin": flow._stack.return_value.base, "url": "http://x/#" + "A" * 43}
                    with patch.dict(xflows.os.environ), patch.object(flow, "_canaries", return_value=canaries), \
                         patch.object(xflows, "list_ids", return_value=set()), \
                         patch.object(xflows.secrets, "token_hex", return_value="0123456789abcdef"), \
                         patch.object(xflows.xinstr, "start_viewer", return_value=(Mock(), ready)), \
                         patch.object(xflows.xinstr, "ViewerClient", side_effect=[live_client, final_client]), \
                         patch.object(xflows.xinstr, "stop_process_group"), \
                         patch.object(xcamp, "http_request", return_value={"status": 200}) as request:
                        getattr(flow, mode)()
                    self.assertEqual(live_client.get.call_count, len(live_pages))
                    self.assertEqual(final_client.get.call_count, len(final_pages))
                    self.assertEqual(request.call_count, 1 if phase == "live" else len(details))
                    self.assertIsNone(live_client.deadline)
                    steps = focused_steps if mode == "focused" else ("standard-no-values",)
                    for step in steps:
                        self.assertEqual(flow.results[step]["status"], "fail" if gap else "pass", flow.results)
                        if phase:
                            expected = ("canary recording read failed" if phase == "live"
                                        else "privacy capture read API unavailable")
                            self.assertEqual(flow.results[step]["note"], expected)
                    first_id = next(iter(details))
                    artifact_dir = flow.out_dir / f"api-{mode}"
                    if phase == "live":
                        artifact_dir /= first_id
                    saved = json.loads((artifact_dir / f"recording-{first_id}.json").read_text())
                    self.assertEqual(saved["events"], details[first_id]["events"])
                    if gap == "detail":
                        self.assertEqual(saved["_detailReadGap"], "detail transport failure")

    def test_record_and_restart_parse_one_whole_pretty_document(self):
        flow = self.flow()
        for command, doc in (("record", self.armed()),
                             ("restart", {"stopped": {"pid": 70}, "started": self.armed()})):
            with self.subTest(command=command), patch.object(xflows.subprocess, "run", return_value=self.result(doc)) as run:
                rc, parsed, bootstrap = flow._record(command)
                self.assertEqual((rc, parsed, bootstrap), (0, doc, "/bootstrap.json"))
                self.assertEqual(run.call_args.args[0][1], command)
                self.assertIn("--source-root", run.call_args.args[0])
        error = {"kind": "error", "exit_code": 9}
        with patch.object(xflows.subprocess, "run", return_value=self.result(error, 9)):
            self.assertEqual(flow._record(), (9, error, ""))
        # A timeout is an exception; a negative return code is preserved as a signal result.
        with patch.object(xflows.subprocess, "run", side_effect=subprocess.TimeoutExpired("xtrace", 120)):
            with self.assertRaises(subprocess.TimeoutExpired):
                flow._record()
        with patch.object(xflows.subprocess, "run", return_value=subprocess.CompletedProcess([], -1, stdout="", stderr="")):
            self.assertEqual(flow._record()[0], -1)

    def test_record_stop_launches_with_bootstrap_and_checks_the_reported_pid(self):
        flow = self.flow()
        details = {"a": rec("GET", "/owners"), "b": rec("GET", "/vets"), "c": rec("GET", "/owners/{ownerId}")}
        with patch.object(xflows.subprocess, "run", side_effect=[self.result(self.armed()), self.result({"kind": "stopped"})]), \
                patch.object(flow, "_recorded_gets", return_value={"/vets": 200}) as requests, \
                patch.object(xflows, "wait_gone", return_value=True) as gone, \
                patch.object(xflows, "read_api", side_effect=[self.api({}), self.api(details)]):
            reopened = flow.record_stop()
        self.assertEqual(flow.results["record-stop-flow"]["status"], "pass")
        self.assertEqual(set(reopened), set(details))
        flow._stack.assert_called_once_with("", ["-javaagent:agent.jar=/bootstrap.json"])
        gone.assert_called_once_with(71)
        self.assertEqual(requests.call_args.args[1], ["/owners?lastName=Davis", "/vets", "/owners/1"])

    def test_record_stop_observes_each_completed_capture_before_stopping_and_still_judges_readback(self):
        import xcamp
        for persisted in (True, False):
            flow = self.flow()
            order = []
            routes = [("GET", "/owners"), ("GET", "/vets"), ("GET", "/owners/{ownerId}")]
            details = {str(i): rec(*route) for i, route in enumerate(routes)}
            def record(command="record", **kwargs):
                order.append(command)
                return 0, self.armed(), "/bootstrap.json"
            def observe(client, dest, before, method, route, deadline):
                order.append(route)
                self.assertEqual(deadline, 30)
                return "observed", details
            flow._record = Mock(side_effect=record)
            with self.subTest(persisted=persisted), \
                    patch.object(xflows.xinstr, "start_viewer", return_value=(Mock(), {"origin": "o", "url": "u"})), \
                    patch.object(xflows.xinstr, "ViewerClient"), patch.object(xflows.xinstr, "bootstrap_token"), \
                    patch.object(xflows.xinstr, "collect_api", return_value=self.api({})), \
                    patch.object(xflows.xinstr, "stop_process_group"), \
                    patch.object(xcamp, "http_request", return_value={"status": 200}) as http, \
                    patch.object(xflows, "wait_canary_recording", side_effect=observe), \
                    patch.object(xflows.time, "monotonic", return_value=0), patch.object(xflows.time, "sleep") as sleep, \
                    patch.object(xflows, "wait_gone", return_value=True), \
                    patch.object(xflows, "read_api", side_effect=[self.api({}), self.api(details if persisted else {})]):
                flow.record_stop()
            self.assertEqual(order, ["record", "/owners", "/vets", "/owners/{ownerId}", "stop"])
            self.assertEqual(http.call_count, 3)
            sleep.assert_not_called()
            self.assertEqual(flow.results["record-stop-flow"]["status"], "pass" if persisted else "fail")

    def test_restart_reopen_checks_started_pid_inside_pretty_document(self):
        flow = self.flow()
        details = {"a": rec()}
        with patch.object(xflows, "read_api", return_value=self.api(details)), \
                patch.object(xflows.subprocess, "run", side_effect=[
                    self.result({"stopped": {"pid": 70}, "started": self.armed()}), self.result({"kind": "stopped"})]), \
                patch.object(xflows, "pid_alive", return_value=True) as alive:
            flow.restart_reopen()
        alive.assert_called_once_with(71)
        self.assertEqual(flow.results["restart-reopen"]["status"], "pass")

    def test_partial_waits_for_request_evidence_and_reopens_that_id(self):
        for reopened_id in ("held", "unrelated"):
            with self.subTest(reopened_id=reopened_id):
                flow = self.flow()
                flow._record = Mock(side_effect=[(0, self.armed(), "/bootstrap.json"), (0, {}, "")])
                proc = flow._stack.return_value._proc
                proc.pid = 71
                proc.poll.return_value = None
                order = []
                listing = iter(["control", "held"])

                def show(args, **kwargs):
                    if args[2] == "list":
                        rid = next(listing)
                        return self.result({"recordings": [{"recording_id": rid, "status": "recording"}], "next_after": None})
                    rid = args[3]
                    order.append(rid)
                    detail = rec("POST", "/owners/new") if rid == "held" else rec()
                    detail["status"] = "recording"
                    return self.result(detail)

                part = rec("POST", "/owners/new", "partial", evidence=["interrupted"])
                details = {"control": rec(), reopened_id: part}
                with patch.object(xflows, "_paced_gets"), patch.object(xflows.socket, "create_connection") as connect, \
                        patch.object(xflows.subprocess, "run", side_effect=show), \
                        patch.object(xflows.time, "monotonic", side_effect=[0, 0, 0, 0.05]), \
                        patch.object(xflows.time, "sleep") as sleep, \
                        patch.object(xflows.os, "kill", side_effect=lambda *args: order.append("kill")), \
                        patch.object(xflows, "read_api", side_effect=[self.api({}), self.api(details)]):
                    flow.partial()
                self.assertEqual(order, ["control", "held", "kill"])
                flow._stack.return_value.hold_owner_writes.assert_called_once_with()
                payload = connect.return_value.sendall.call_args.args[0]
                headers, body = payload.split(b"\r\n\r\n", 1)
                self.assertIn(f"Content-Length: {len(body)}".encode(), headers)
                self.assertIn(b"telephone=0123456789", body)
                sleep.assert_called_once_with(0.05)
                self.assertEqual(flow.results["partial-recording-reopen"]["status"], "pass" if reopened_id == "held" else "fail")
                proc.wait.assert_called_once_with(timeout=30)
                self.assertEqual(flow._record.call_args_list[-1].args, ("stop",))

    def test_partial_requires_a_live_process_after_observing_the_request(self):
        flow = self.flow()
        flow._record = Mock(side_effect=[(0, self.armed(), "/bootstrap.json"), (0, {}, "")])
        flow._stack.return_value._proc.poll.return_value = 0
        listing = {"recordings": [{"recording_id": "held", "status": "recording"}]}
        detail = {**rec("POST", "/owners/new"), "status": "recording"}
        with patch.object(xflows, "_paced_gets"), patch.object(xflows.socket, "create_connection"), \
                patch.object(xflows, "read_api", return_value=self.api({})), \
                patch.object(xflows.subprocess, "run", side_effect=[self.result(listing), self.result(detail)]), \
                patch.object(xflows.time, "monotonic", side_effect=[0, 0]), patch.object(xflows.os, "kill") as kill:
            with self.assertRaisesRegex(RuntimeError, "no live application process"):
                flow.partial()
        kill.assert_not_called()
        flow._stack.return_value.down.assert_called_once()
        self.assertEqual(flow._record.call_args_list[-1].args, ("stop",))

    def test_partial_fails_when_the_request_never_enters_capture(self):
        flow = self.flow()
        flow._record = Mock(side_effect=[(0, self.armed(), "/bootstrap.json"), (0, {}, "")])
        flow._stack.return_value._proc.poll.return_value = 0
        with patch.object(xflows, "_paced_gets"), patch.object(xflows.socket, "create_connection"), \
                patch.object(xflows.time, "monotonic", side_effect=[0, 3]), \
                patch.object(xflows.time, "sleep") as sleep, patch.object(xflows.os, "kill") as kill, \
                patch.object(xflows, "read_api", return_value=self.api({})) as api:
            flow.partial()
        self.assertEqual(flow.results["partial-recording-reopen"]["status"], "fail")
        self.assertIn("no observed open recording", flow.results["partial-recording-reopen"]["note"])
        sleep.assert_not_called()
        kill.assert_not_called()
        self.assertEqual(api.call_count, 2)
        self.assertEqual([call.args[-1] for call in api.call_args_list],
                         [flow.out_dir / "api-before-partial", flow.out_dir / "api-partial"])

    def test_failed_snapshot_does_not_arm_capture(self):
        for command, step in (("record_stop", "record-stop-flow"), ("partial", "partial-recording-reopen")):
            flow = self.flow()
            flow._record = Mock()
            with self.subTest(command=command), patch.object(xflows, "read_api", return_value={"ok": False, "reason": "unavailable"}):
                getattr(flow, command)()
            self.assertEqual(flow.results[step]["status"], "fail")
            flow._record.assert_not_called()

    def test_restart_does_not_prove_reopening_from_api_prefixes(self):
        details = {"old": rec()}
        for before_gap, after_gap in ((None, None), ("listing", None), (None, "detail")):
            with self.subTest(before_gap=before_gap, after_gap=after_gap):
                flow = self.flow()
                flow._record = Mock(side_effect=[(0, {"started": {"pid": 71}}, ""), (0, {}, "")])
                before, after = Mock(deadline=None), Mock(deadline=None)
                before.get.side_effect = viewer_pages(details, before_gap)
                after.get.side_effect = viewer_pages(details, after_gap)
                ready = {"origin": flow._stack.return_value.base, "url": "http://x/#" + "A" * 43}
                with patch.object(xflows, "pid_alive", return_value=True), \
                     patch.object(xflows.xinstr, "start_viewer", return_value=(Mock(), ready)), \
                     patch.object(xflows.xinstr, "ViewerClient", side_effect=[before, after]), \
                     patch.object(xflows.xinstr, "stop_process_group"):
                    flow.restart_reopen()
                step = flow.results["restart-reopen"]
                self.assertEqual(step["status"], "fail" if before_gap or after_gap else "pass", step)
                if before_gap or after_gap:
                    self.assertIn("recordings list HTTP 503" if before_gap else "detail transport failure", step["note"])
                self.assertEqual(flow._record.call_args_list[-1].args, ("stop",))

    def test_partial_without_bootstrap_reports_stop_not_invoked(self):
        flow = self.flow()
        flow._record = Mock(return_value=(0, {}, ""))
        with patch.object(xflows, "read_api", return_value=self.api({})):
            flow.partial()
        self.assertIn("stop was not invoked", flow.results["partial-recording-reopen"]["note"])
        flow._record.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
