import json
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

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


class Drivers(unittest.TestCase):
    def flow(self):
        flow = object.__new__(xflows.Flows)
        flow.xtrace, flow.project_dir = "xtrace", pathlib.Path("/project")
        flow.agent, flow.out_dir = "agent.jar", pathlib.Path("/flow-artifacts")
        flow.app_package, flow.source_root = "com.example.app", "src/main/java"
        flow.env, flow.results = {}, {}
        flow._stack = Mock(return_value=Mock(base="http://127.0.0.1:8000", host_port=8000))
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
                patch.object(xflows, "_paced_gets", return_value={"/vets": 200}), \
                patch.object(xflows, "wait_gone", return_value=True) as gone, \
                patch.object(xflows, "read_api", side_effect=[self.api({}), self.api(details)]):
            reopened = flow.record_stop()
        self.assertEqual(flow.results["record-stop-flow"]["status"], "pass")
        self.assertEqual(set(reopened), set(details))
        flow._stack.assert_called_once_with("", ["-javaagent:agent.jar=/bootstrap.json"])
        gone.assert_called_once_with(71)

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
                with patch.object(xflows, "_paced_gets"), patch.object(xflows.socket, "create_connection"), \
                        patch.object(xflows.subprocess, "run", side_effect=show), \
                        patch.object(xflows.time, "monotonic", side_effect=[0, 0, 0, 0.05]), \
                        patch.object(xflows.time, "sleep") as sleep, \
                        patch.object(xflows.os, "kill", side_effect=lambda *args: order.append("kill")), \
                        patch.object(xflows, "read_api", side_effect=[self.api({}), self.api(details)]):
                    flow.partial()
                self.assertEqual(order, ["control", "held", "kill"])
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
        api.assert_called_once()

    def test_failed_snapshot_does_not_arm_capture(self):
        for command, step in (("record_stop", "record-stop-flow"), ("partial", "partial-recording-reopen")):
            flow = self.flow()
            flow._record = Mock()
            with self.subTest(command=command), patch.object(xflows, "read_api", return_value={"ok": False, "reason": "unavailable"}):
                getattr(flow, command)()
            self.assertEqual(flow.results[step]["status"], "fail")
            flow._record.assert_not_called()

    def test_partial_without_bootstrap_reports_stop_not_invoked(self):
        flow = self.flow()
        flow._record = Mock(return_value=(0, {}, ""))
        with patch.object(xflows, "read_api", return_value=self.api({})):
            flow.partial()
        self.assertIn("stop was not invoked", flow.results["partial-recording-reopen"]["note"])
        flow._record.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
