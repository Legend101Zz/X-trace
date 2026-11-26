"""Finite phase evidence regressions; no additional application calls or clock budget."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import fineract_phase_evidence as phase
from test_fineract_first_partial_pair import PROJECT, RECORDING, OTHER, PRIVATE


def document(rid=RECORDING, project=PROJECT):
    return {"schemaVersion": 3, "recordingId": rid, "projectId": project, "projection": "full",
            "completion": "partial", "outcome": None, "capacity": None, "durationNs": None,
            "events": [{"symbol": PRIVATE}]}


def observed(*docs):
    return {d["recordingId"]: d for d in docs}, [{"recordingId": d["recordingId"]} for d in docs], {}


def stop(*ids, project=PROJECT, kind="stop_not_running", code=None):
    doc = {"kind": kind, "project_id": project, "pid": None if kind == "stop_not_running" else 123,
           "runtime_session_id": None if kind == "stop_not_running" else OTHER,
           "was_running": kind == "stopped", "recovered_recordings": [
               {"recording_id": rid, "persisted_events": "7", "completion": "partial"} for rid in ids]}
    return subprocess.CompletedProcess([], (3 if ids and kind == "stop_not_running" else 0) if code is None else code,
                                       json.dumps(doc))


class FineractPhaseEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.addCleanup(os.umask, os.umask(0o077))
        # Match existing hosted fixtures' scratch ancestor exception only.
        patch = mock.patch.object(phase.installed_java, "private_dir", side_effect=lambda p: Path(p).absolute())
        patch.start()
        self.addCleanup(patch.stop)

    def live(self, docs, ordinal=1, poll=2):
        parent = self.root / f"phase-{ordinal}-api"
        parent.mkdir(mode=0o700)
        phase.save_live(parent / "fineract-phase.json", observed(*docs), poll)

    def test_terminal_presence_and_duration_are_separate_and_finite(self):
        doc = document()
        self.assertEqual(phase.metadata(doc, api=True), dict(terminalMetadata="absent", duration="null", completion="partial"))
        doc.update(outcome={"kind": "unobserved"}, capacity={"capacityDroppedEvents": "0"}, durationNs="0")
        self.assertEqual(phase.metadata(doc, api=True), dict(terminalMetadata="present", duration="present", completion="partial"))
        for bad in (True, 1, "-1", str(2**64), PRIVATE):
            self.assertEqual(phase.metadata({"duration_ns": bad}, api=False)["duration"], "malformed")
        self.assertEqual(phase.metadata({}, api=False), dict(terminalMetadata="unknown", duration="missing", completion="unknown"))

    def test_same_recording_live_and_actual_recovery_are_correlated_privately(self):
        self.live([document()])
        phase.save_stop(self.root / "fineract-stop.json", stop(RECORDING))
        result = phase.correlate(self.root, PROJECT, RECORDING)
        self.assertTrue(phase.valid(result))
        self.assertEqual((result["liveState"], result["livePhase"], result["livePoll"]), ("observed", 1, 2))
        self.assertEqual((result["stopState"], result["selectedRecovery"], result["recoveredCount"]), ("observed", "listed", 1))
        for private in (PROJECT, RECORDING, OTHER, PRIVATE):
            self.assertNotIn(private, json.dumps(result))

    def test_unrelated_record_never_inherits_group_observations(self):
        self.live([document(OTHER)])
        phase.save_stop(self.root / "fineract-stop.json", stop(OTHER))
        result = phase.correlate(self.root, PROJECT, RECORDING)
        self.assertEqual(result["liveState"], "not-observed")
        self.assertIsNone(result["live"])
        self.assertEqual(result["selectedRecovery"], "not-listed")
        self.assertEqual(result["recoveredCount"], 1)

    def test_wrong_project_and_invalid_selected_identity_never_correlate(self):
        self.live([document(project=OTHER)])
        phase.save_stop(self.root / "fineract-stop.json", stop(RECORDING, project=OTHER))
        result = phase.correlate(self.root, PROJECT, RECORDING)
        self.assertEqual((result["liveState"], result["stopState"]), ("rejected", "rejected"))
        self.assertEqual(phase.correlate(self.root, None, None)["selectedRecovery"], "unknown")

    def test_missing_or_no_complete_live_poll_remains_unknown(self):
        result = phase.correlate(self.root, PROJECT, RECORDING)
        self.assertEqual((result["liveState"], result["stopState"], result["selectedRecovery"]), ("unavailable", "unavailable", "unknown"))
        parent = self.root / "phase-1-api"
        parent.mkdir(mode=0o700)
        phase.save_live(parent / "fineract-phase.json", None, None)
        self.assertEqual(phase.correlate(self.root, PROJECT, RECORDING)["liveState"], "unavailable")

    def test_live_projection_drops_values_and_rejects_noncomplete_or_unbound_reads(self):
        parent = self.root / "phase-1-api"
        parent.mkdir(mode=0o700)
        path = parent / "fineract-phase.json"
        phase.save_live(path, observed(document()), 2)
        self.assertNotIn(PRIVATE, path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for extra in ({"_detailReadGap": "private"}, {"projectId": "bad"}, {"projection": "focused"},
                      {"recordingId": None}):
            doc = {**document(), **extra}
            with self.assertRaises(ValueError):
                phase.save_live(parent / "bad.json", observed(doc), 2)
        with self.assertRaises(ValueError):
            phase.save_live(parent / "bad.json", None, 1)

    def test_stop_document_requires_real_shape_identity_and_exit_consistency(self):
        self.assertEqual(phase.stop_projection(stop(RECORDING))["recordings"],
                         [{"recording": RECORDING, "completion": "partial"}])
        self.assertEqual(phase.stop_projection(stop(kind="stopped"))["recordings"], [])
        for result in (stop(RECORDING, code=0), stop(RECORDING, RECORDING), stop(project="bad"),
                       subprocess.CompletedProcess([], 1, PRIVATE)):
            with self.assertRaises(ValueError):
                phase.stop_projection(result)
        doc = json.loads(stop(RECORDING).stdout)
        for key, value in (("unknown", PRIVATE), ("pid", True), ("was_running", True)):
            candidate = {**doc, key: value}
            with self.assertRaises(ValueError):
                phase.stop_projection(subprocess.CompletedProcess([], 3, json.dumps(candidate)))

    def test_unsafe_private_files_and_unknown_fields_fail_closed(self):
        self.live([document()])
        path = self.root / "phase-1-api/fineract-phase.json"
        path.chmod(0o644)
        self.assertEqual(phase.correlate(self.root, PROJECT, RECORDING)["liveState"], "rejected")
        path.chmod(0o600)
        data = json.loads(path.read_text())
        data["private"] = PRIVATE
        path.write_text(json.dumps(data))
        self.assertEqual(phase.correlate(self.root, PROJECT, RECORDING)["liveState"], "rejected")

    def test_public_phase_schema_rejects_unknown_values_bool_counts_and_extra_fields(self):
        result = phase.correlate(self.root, PROJECT, RECORDING)
        self.assertTrue(phase.valid(result))
        for key, value in (("unknown", PRIVATE), ("livePoll", True), ("recoveredCount", False),
                           ("selectedRecovery", "not-listed"), ("liveState", PRIVATE)):
            self.assertFalse(phase.valid({**result, key: value}))
        observed_result = {**result, "liveState": "observed", "livePhase": 1, "livePoll": 2,
                           "live": phase.metadata(document(), api=True), "stopState": "observed",
                           "recoveredCount": 0, "selectedRecovery": "listed"}
        self.assertFalse(phase.valid(observed_result))

    def test_boundary_diagnostic_save_does_not_add_reads_or_change_verdict(self):
        import xinstr
        doc = document()
        doc["events"] = []
        client = mock.Mock(deadline=None)
        boundary = dict(verified=True, verifiedAt=1, capacityDrops=0, partialRecordingIds=[])
        api = dict(ok=True, details={RECORDING: doc}, recordings=[{"recordingId": RECORDING}])
        parent = self.root / "phase-1-api"
        parent.mkdir(mode=0o700)
        retained = []
        with mock.patch.object(xinstr, "collect_api", return_value=api) as read, \
                mock.patch.object(xinstr, "burst_accounting", return_value=boundary.copy()), \
                mock.patch.object(xinstr.boundary_diagnostics, "snapshot", return_value={}), \
                mock.patch.object(xinstr.time, "monotonic", side_effect=[1, 1]), \
                mock.patch.object(phase, "save_live", side_effect=OSError) as save:
            result = xinstr.wait_burst_boundary(client, parent, [], {}, {}, 2, diagnose=True, phase_observation=retained)
        self.assertTrue(result["verified"])
        self.assertEqual(read.call_count, 1)
        save.assert_not_called()
        self.assertEqual(len(retained), 1)
        self.assertIs(retained[0][0][0], api["details"])
        self.assertEqual(retained[0][1], 1)
        self.assertEqual(result["diagnostic"]["lastCompletePoll"], 1)
        self.assertIsNone(client.deadline)

    def test_installed_collector_requires_closed_phase_projection_without_changing_commands(self):
        import test_fineract_first_partial_pair as fixture
        from campaigns.java.fineract.harness import receipt_diagnostics
        case = fixture.FineractFirstPartialPair()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.save_api((200, fixture.detail(True, markers=["persisted_status:partial"])))
        parent = case.capture / "phase-1-api"
        parent.mkdir(mode=0o700)
        phase.save_live(parent / "fineract-phase.json", observed(document()), 2)
        phase.save_stop(case.capture / "fineract-stop.json", stop(RECORDING))
        raw = case.cli(fixture.detail(False, markers=["persisted_status:partial"]))
        self.assertEqual(raw["schema"], "xtrace-fineract-cli-sinks/4")
        public = receipt_diagnostics.cli_diagnostics(raw)["firstIncomplete"]
        self.assertEqual(public["phaseEvidence"]["selectedRecovery"], "listed")
        self.assertEqual(public["phaseEvidence"]["selectedRecoveryResult"], "partial")
        self.assertEqual(public["phaseEvidence"]["live"]["terminalMetadata"], "absent")
        self.assertEqual(public["cli"]["duration"], "missing")
        self.assertEqual(public["terminalMeaning"], "persisted-terminal-metadata-not-adapter-finish")
        self.assertNotIn(RECORDING, json.dumps(public))
        for bad in ("extra", "missing-phase", "missing-duration", "unavailable-identity"):
            candidate = copy.deepcopy(raw)
            if bad == "extra":
                candidate["firstIncomplete"]["phaseEvidence"]["private"] = PRIVATE
            elif bad == "missing-phase":
                del candidate["firstIncomplete"]["phaseEvidence"]
            elif bad == "missing-duration":
                del candidate["firstIncomplete"]["cli"]["duration"]
            else:
                candidate["firstIncomplete"].update(cli=None, cliRead="rejected", api=None, apiRead="unavailable")
            self.assertIsNone(receipt_diagnostics.cli_diagnostics(candidate))

    def test_missing_wire_identity_cannot_be_replaced_by_collector_default(self):
        import xinstr
        import test_fineract_first_partial_pair as fixture
        doc = fixture.detail(True)
        del doc["recordingId"]
        client = mock.Mock(deadline=None)
        client.get.side_effect = [(200, fixture.listing(True)), (200, doc)]
        result = xinstr.collect_api(client, self.root / "api", fineract_phase=True)
        self.assertEqual(client.get.call_count, 2)
        captured = result["details"][RECORDING]
        self.assertNotIn("recordingId", captured)
        with self.assertRaises(ValueError):
            phase.save_live(self.root / "bad.json", (result["details"], result["recordings"], {}), 1)

    def test_not_running_retains_actual_stale_record_identity_and_rejects_mixed_shapes(self):
        # Both Identity::Mismatch with released lock and Identity::NotRunning serialize
        # this same retained-identity shape; the absent-record branch has null/null.
        original = json.loads(stop(RECORDING).stdout)
        for shape in (dict(pid=None, runtime_session_id=None), dict(pid=123, runtime_session_id=OTHER)):
            doc = {**original, **shape}
            projection = phase.stop_projection(subprocess.CompletedProcess([], 3, json.dumps(doc)))
            self.assertEqual(projection["recordings"], [{"recording": RECORDING, "completion": "partial"}])
        for shape in (dict(pid=None, runtime_session_id=OTHER), dict(pid=123, runtime_session_id=None),
                      dict(pid=True, runtime_session_id=OTHER), dict(pid=2**32, runtime_session_id=OTHER),
                      dict(pid=123, runtime_session_id=PRIVATE)):
            with self.assertRaises(ValueError):
                phase.stop_projection(subprocess.CompletedProcess([], 3, json.dumps({**original, **shape})))

    def test_failed_recovery_keeps_real_exit_precedence_and_failed_result(self):
        for kind, code in (("stop_not_running", 3), ("stopped", 10)):
            doc = json.loads(stop(RECORDING, kind=kind).stdout)
            doc["recovered_recordings"][0]["completion"] = "failed"
            result = phase.stop_projection(subprocess.CompletedProcess([], code, json.dumps(doc)))
            self.assertEqual(result["recordings"][0]["completion"], "failed")
            for wrong in ({0, 3, 10} - {code}):
                with self.assertRaises(ValueError):
                    phase.stop_projection(subprocess.CompletedProcess([], wrong, json.dumps(doc)))

    def test_only_first_serial_boundary_receives_the_one_snapshot_holder(self):
        import xinstr
        import xcamp
        from types import SimpleNamespace
        scenarios = [SimpleNamespace(id="a", kind="business"), SimpleNamespace(id="b", kind="concurrency"),
                     SimpleNamespace(id="c", kind="business")]
        retained = []
        seen = []
        def run(sc, *args):
            return dict(id=sc.id, requests=[], passed=True, semanticEffectFingerprint="fp", elapsedMs=1)
        def boundary(*args, **kwargs):
            seen.append(kwargs["phase_observation"])
            return dict(verified=True, snapshotIds=[], capacityCounts={})
        with mock.patch.object(xcamp, "run_scenario", side_effect=run), \
                mock.patch.object(xinstr, "wait_burst_boundary", side_effect=boundary):
            phases = xinstr.capture_ordered_phases(mock.Mock(base="local"), scenarios, [],
                       {sc.id: [] for sc in scenarios}, frozenset(), self.root, mock.Mock(), {}, 60,
                       phase_observation=retained)
        self.assertEqual(len(phases), 3)
        self.assertIs(seen[0], retained)
        self.assertIsNone(seen[1])
        self.assertIsNone(seen[2])

    def test_diagnostic_projection_and_writes_follow_stop_api_judgment_and_receipt_measurements(self):
        import xinstr
        from types import SimpleNamespace
        events = []
        capture = self.root / "capture"
        initial = dict(ok=True, reason="", recordings=[], details={})
        stack = SimpleNamespace(env={}, up=mock.Mock(), down=mock.Mock(side_effect=lambda: events.append("app-stop")),
                                logs=mock.Mock(return_value=""), launcher_exit=0, base="http://127.0.0.1:1")
        def child(args, **kwargs):
            events.append(args[1])
            return stop(RECORDING) if args[1] == "stop" else subprocess.CompletedProcess(args, 0, "")
        def collect(*args, **kwargs):
            events.append("initial-api" if len([x for x in events if x == "initial-api"]) == 0 else "final-api")
            return initial
        def ordered(*args, **kwargs):
            events.extend(["serial-judged", "burst-judged", "cleanup-judged"])
            (capture / "phase-1-api").mkdir(mode=0o700)
            kwargs["phase_observation"].append((observed(document()), 2))
            return [xinstr.OrderedPhase("serial", [], dict(verified=False, diagnostic={}))]
        def judge(*args):
            events.append("recordings-judged")
            return {"s": dict(passed=False, expectations=[], problems=[], frameSymbols=[])}, [], set(), set(), []
        def probes(*args):
            events.append("existing-probes")
            return []
        def save(path, retained, result):
            self.assertEqual(path, capture)
            self.assertEqual(len(retained), 1)
            receipt = json.loads((capture / "receipt.json").read_text())
            self.assertEqual(receipt["result"], "failed")
            self.assertIn("durationSeconds", receipt)
            self.assertIn("final-api", events)
            self.assertEqual(events[-1], "recordings-judged")
            events.append("diagnostics")
            original_save(path, retained, result)
        original_save = phase.save_deferred
        with mock.patch.object(xinstr.private_diagnostic, "run_captured", side_effect=child), \
                mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
                mock.patch.object(xinstr, "start_viewer", return_value=(object(), {"origin": stack.base, "url": "http://x/#" + "A"*43})), \
                mock.patch.object(xinstr, "ViewerClient"), \
                mock.patch.object(xinstr, "stop_process_group", side_effect=lambda _: events.append("viewer-stop")), \
                mock.patch.object(xinstr, "collect_api", side_effect=collect) as reads, \
                mock.patch.object(xinstr, "capture_ordered_phases", side_effect=ordered), \
                mock.patch.object(phase, "save_deferred", side_effect=save):
            receipt = xinstr.run_instrumented(project="fineract", pin={}, make_stack=lambda _: stack,
                scenarios=[SimpleNamespace(id="s", kind="business")], out_dir=capture, norm_extra=[],
                expectations={"s": [{"method": "GET", "route": "/"}]}, xtrace="installed", project_dir=self.root,
                data_home=self.root / "data", adaptations=[], canaries={"env-var": PRIVATE}, baseline_receipt=None,
                extra_canary_paths=[], harness_files=[], ordered_campaign=xinstr.OrderedCampaign(frozenset(), probes, judge, fineract_phase=True))
        self.assertEqual(events, ["init", "initial-api", "serial-judged", "burst-judged", "cleanup-judged",
                                 "existing-probes", "viewer-stop", "app-stop", "stop", "final-api", "viewer-stop",
                                 "recordings-judged", "diagnostics"])
        self.assertEqual(reads.call_count, 2)
        self.assertEqual(phase.correlate(capture, PROJECT, RECORDING)["selectedRecoveryResult"], "partial")
        self.assertEqual(json.loads((capture / "receipt.json").read_text()), receipt)
