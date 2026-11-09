import pathlib
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xflows  # noqa: E402


def rec(method="GET", route="/vets", completion="complete", events=4, evidence=()):
    evs = [{"kind": "recording_event_kind:request_update", "symbol": f"http.request {method} {route}"}]
    evs += [{"kind": "recording_event_kind:frame_enter", "symbol": "X.y"}] * (events - 1)
    return {"events": evs, "completion": completion, "incompleteEvidence": list(evidence)}


def line_rec(start=10, end=30, lines=(12, 15), fid="f1", with_source=True):
    evs = [{"kind": "recording_event_kind:frame_enter", "frameId": fid,
            "source": {"path": "A.java", "startLine": start, "endLine": end, "status": "matched"} if with_source else None}]
    evs += [{"kind": "recording_event_kind:line_cursor", "frameId": fid, "line": n, "source": None} for n in lines]
    return {"events": evs}


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
        ok = dict(record_rc=0, stop_rc=0, stop_doc={}, control_details=ctl, new_details={"p": part}, stalled=stalled)
        self.assertEqual(xflows.judge_partial(**ok)[0], "pass")
        self.assertEqual(xflows.judge_partial(**{**ok, "stop_rc": 10})[0], "pass")
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {}})[0], "fail")
        liar = rec("POST", "/owners/new", completion="complete")
        self.assertIn("complete", xflows.judge_partial(**{**ok, "new_details": {"p": part, "l": liar}})[1])
        self.assertEqual(xflows.judge_partial(**{**ok, "new_details": {"p": rec("POST", "/owners/new", "partial")}})[0], "fail")
        self.assertEqual(xflows.judge_partial(**{**ok, "control_details": []})[0], "fail")
        self.assertEqual(xflows.judge_partial(**{**ok, "stop_rc": 4})[0], "fail")

    def test_active_line(self):
        self.assertEqual(xflows.judge_active_line([line_rec()])[0], "pass")
        st, note = xflows.judge_active_line([line_rec(lines=(10, 10))])
        self.assertEqual(st, "fail")
        self.assertIn("method start", note)
        self.assertEqual(xflows.judge_active_line([line_rec(lines=(99,))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(lines=(0,))])[0], "fail")
        self.assertEqual(xflows.judge_active_line([line_rec(with_source=False, lines=(3, 4))])[0], "pass")
        self.assertEqual(xflows.judge_active_line([line_rec(with_source=False, lines=(3,))])[0], "fail")
        gap = {"events": [{"kind": "recording_event_kind:gap", "symbol": "gap.not-transformed"}]}
        st, note = xflows.judge_active_line([gap])
        self.assertEqual(st, "fail")
        self.assertIn("gap.not-transformed", note)
        self.assertEqual(xflows.judge_active_line([])[0], "fail")

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
        self.assertEqual(xflows.parse_doc("noise\n{\"x\": 1}\n"), {"x": 1})
        self.assertIsNone(xflows.parse_doc("none"))

    def test_focused_requests_inject_canaries_into_an_argument_and_password(self):
        import xcamp
        canaries = {k: "canary-" + k for k in ("authorization-header", "cookie-header", "query-token", "json-body-password")}
        with mock.patch.object(xcamp, "http_request", return_value={"status": 200}) as request:
            served = xflows.focused_requests("http://127.0.0.1:1234", canaries)
        self.assertEqual(list(served.values()), [200, 200, 200])
        paths = [call.args[2] for call in request.call_args_list]
        self.assertIn("lastName=canary-query-token", paths[1])
        for call in request.call_args_list:
            self.assertIn("password=canary-json-body-password", call.args[2])
            self.assertIn("xt_token=canary-query-token", call.args[2])
            self.assertEqual(call.kwargs["headers"]["Authorization"], canaries["authorization-header"])
            self.assertEqual(call.kwargs["headers"]["Cookie"], canaries["cookie-header"])
        self.assertNotIn("canary-", str(served), "flow receipt must not itself save the injected values")

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


if __name__ == "__main__":
    unittest.main()
