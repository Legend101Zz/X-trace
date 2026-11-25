"""Fail-closed Fineract receipt projection and positive evidence of inspection reachability."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import xinstr
from campaigns.java.fineract.harness import receipt_diagnostics as diagnostics, recording_evidence as evidence


def receipt(**fields):
    return dict(schemaVersion=1, kind="instrumented_campaign_non_release", project="fineract",
                instrumented=True, releaseAcceptance=False, **fields)


def failed_first_phase(first, private, *, version=2):
    skipped = dict(status="prior-unverified", failure=None, snapshot=None, snapshotPoll=None, polls=0)
    if version == 2:
        skipped.update(lastComplete=None, lastCompletePoll=None)
    phases = [first, dict(skipped, ordinal=2, kind="burst"), dict(skipped, ordinal=3, kind="serial")]
    return receipt(notes=dict(boundaryDiagnostics=dict(schemaVersion=version, initial=dict(status="verified", failure=None),
                                                       phases=phases),
                              orderedBoundaries=[dict(kind=row["kind"], verified=False, private=private) for row in phases]),
                   boundariesVerified=False)


class FineractDiagnostics(unittest.TestCase):
    def test_first_failed_poll_is_bound_to_its_observation_and_later_phases_are_unreached(self):
        private = "excluded-id-and-error"
        client = mock.Mock()
        failed = {"ok": False, "reason": private, "readFailure": {"stage": "detail", "reason": "deadline"},
                  "details": {private: {"_detailReadGap": private}}, "recordings": [{"recordingId": private}]}
        with mock.patch.object(xinstr.time, "monotonic", return_value=1), mock.patch.object(xinstr, "collect_api", return_value=failed):
            boundary = xinstr.wait_burst_boundary(client, Path("unused"), [], {}, {}, 2, diagnose=True)
        first = dict(boundary["diagnostic"], ordinal=1, kind="serial")
        doc = failed_first_phase(first, private)
        public = diagnostics.boundary_manifest(doc)
        self.assertEqual(public["firstUnverifiedPhase"], 1)
        self.assertIsNone(public["phases"][0]["lastComplete"])
        self.assertIsNone(public["phases"][0]["lastCompletePoll"])
        self.assertEqual((first["polls"], first["snapshotPoll"], first["snapshot"]["unreadRecordings"]), (1, 1, 1))
        self.assertEqual(public["phases"][0]["failure"], {"stage": "detail", "reason": "deadline"})
        self.assertNotIn(private, json.dumps(public))
        doc["notes"]["orderedBoundaries"][1]["verified"] = True
        self.assertIsNone(diagnostics.boundary_manifest(doc))
        doc["notes"]["orderedBoundaries"][1]["verified"] = False
        first["failure"]["reason"] = private
        self.assertIsNone(diagnostics.boundary_manifest(doc))

    def test_partial_detail_poll_preserves_the_separate_fineract_complete_on_time_poll(self):
        private = "private-fineract-id"
        complete = {"ok": True, "details": {private: {"events": [], "completion": "complete"}},
                    "recordings": [{"recordingId": private}]}
        partial = {"ok": False, "reason": private, "readFailure": {"stage": "detail", "reason": "deadline"},
                   "details": {private: {"_detailReadGap": private}},
                   "recordings": [{"recordingId": private}, {"recordingId": "private-next"}]}
        with mock.patch.object(xinstr.time, "monotonic", return_value=1), \
                mock.patch.object(xinstr, "collect_api", side_effect=[complete, partial]):
            boundary = xinstr.wait_burst_boundary(mock.Mock(), Path("unused"), [], {}, {}, 2, diagnose=True)
        self.assertFalse(boundary["verified"])
        doc = failed_first_phase(dict(boundary["diagnostic"], ordinal=1, kind="serial"), private)
        output = diagnostics.boundary_manifest(doc)
        first = output["phases"][0]
        self.assertEqual((first["polls"], first["snapshotPoll"], first["lastCompletePoll"]), (2, 2, 1))
        self.assertEqual((first["snapshot"]["listedNewRecordings"], first["snapshot"]["unreadRecordings"]), (2, 1))
        self.assertEqual((first["lastComplete"]["listedNewRecordings"], first["lastComplete"]["unreadRecordings"],
                          first["lastComplete"]["unassignedRecordings"]), (1, 0, 1))
        self.assertNotIn(private, json.dumps(output))
        doc["notes"]["boundaryDiagnostics"]["phases"][0]["lastCompletePoll"] = 2
        self.assertIsNone(diagnostics.boundary_manifest(doc))

    def test_saved_v1_fineract_poll_is_read_without_supplying_unobserved_v2_fields(self):
        first = dict(ordinal=1, kind="serial", status="read", failure=dict(stage="detail", reason="deadline"),
                     polls=2, snapshotPoll=2, snapshot=dict(listedNewRecordings=2, newRecordings=1,
                         namedMatched=0, optionalNamed=0, missingNamed=1, capacityRejected=0, unexpectedRoots=0,
                         unclassifiedRecordings=0, unreadRecordings=1, routeLess=[]))
        doc = failed_first_phase(first, "private-historical-marker", version=1)
        public = diagnostics.boundary_manifest(doc)
        self.assertEqual(public["phases"][0], first)
        self.assertNotIn("lastComplete", public["phases"][0])
        self.assertNotIn("private-historical-marker", json.dumps(public))
        first["lastComplete"] = None
        self.assertIsNone(diagnostics.boundary_manifest(doc))

    def test_serial_unread_absent_and_checked_seams_remain_distinct(self):
        sid = "client-create-read-roundtrip"
        rules = evidence.EXPECT[sid]
        sent = [dict(label=r["label"], request=dict(method=r["method"], path=r["route"].replace("{clientId}", "1")),
                     response=dict(status=200)) for r in rules]
        phase = SimpleNamespace(kind="serial", results=[dict(id=sid, requests=sent)], boundary=dict(verified=False))
        # Whole verdict remains failed when no recording can be allocated.
        with mock.patch.object(evidence, "judge_probes", return_value=[]):
            verdicts, *_ = evidence.judge({}, {sid: rules}, [phase], [])
        checks = diagnostics.scenario_observations(sid, dict(recordingVerdict=verdicts[sid]))
        self.assertEqual(checks["required-sql-operation-unobserved"],
                         dict(expectedRequests=2, candidateDetails=0, checked=0, failed=0))
        allocation = {(sid, r["label"]): str(i) for i, r in enumerate(rules)}
        with mock.patch.object(evidence, "allocations", return_value=allocation), \
                mock.patch.object(evidence, "judge_probes", return_value=[]):
            verdicts, *_ = evidence.judge({"0": {"_detailReadGap": "private marker"}, "1": {"events": []}},
                                          {sid: rules}, [phase], [])
        row = dict(id=sid, recordingVerdict=verdicts[sid])
        checks = diagnostics.scenario_observations(sid, row)
        self.assertEqual(checks["required-sql-operation-unobserved"],
                         dict(expectedRequests=2, candidateDetails=2, checked=1, failed=1))
        self.assertEqual(checks["command-pipeline-unobserved"],
                         dict(expectedRequests=1, candidateDetails=1, checked=0, failed=0))
        self.assertNotIn("private marker", json.dumps(checks))
        row["recordingVerdict"]["expectations"][1]["failedObservations"]["invented"] = 0
        self.assertIsNone(diagnostics.scenario_observations(sid, row))

    def test_malformed_or_legacy_projections_do_not_credit_checks(self):
        self.assertIsNone(diagnostics.observations(receipt(scenarios=[])))
        self.assertIsNone(diagnostics.cli_diagnostics({"schema": "xtrace-fineract-cli-sinks/1"}))
        self.assertIsNone(diagnostics.boundary_manifest(receipt(notes={"orderedBoundaries": []})))
        self.assertIsNone(diagnostics.cli_diagnostics(dict(schema="xtrace-fineract-cli-sinks/2", complete=True,
                        completedDetails=1, recordings=1, detailCommands=1, listCommands=1, commandExits=[0])))

    def test_burst_group_checked_jdbc_and_missing_sql_operation_stay_separate_from_individual_attribution(self):
        sid = "concurrent-isolation"
        rules = evidence.EXPECT[sid]
        route = {"method": rules[0]["method"], "route": rules[0]["route"], "recordingIds": ["private-id"]}
        detail = {"completion": "complete", "outcome": {"kind": "responded", "httpStatus": 200}, "events": [
            {"kind": "recording_event_kind:request_update", "symbol": f"http.request POST {evidence.CLIENTS}"},
            {"kind": "recording_event_kind:database_start", "interaction": {
                "kind": "interaction_kind:database", "driver": "pgjdbc", "method": "execute", "table": "m_client"}}]}
        phase = SimpleNamespace(kind="burst", results=[dict(id=sid, requests=[])],
                                boundary=dict(verified=False, routes=[route]))
        with mock.patch.object(evidence, "judge_probes", return_value=[]):
            verdicts, *_ = evidence.judge({"private-id": detail}, {sid: rules}, [phase], [])
        rows = [dict(id=name, recordingVerdict=verdicts.get(name, {})) for name in evidence.EXPECT]
        result = diagnostics.observations(receipt(scenarios=rows))
        group = next(s for s in result if s["id"] == sid)
        self.assertEqual(group["scope"], "route-group")
        self.assertEqual(group["checks"]["pgjdbc-boundary-unobserved"]["checked"], 1)
        self.assertEqual(group["checks"]["pgjdbc-boundary-unobserved"]["failed"], 0)
        self.assertEqual(group["checks"]["required-sql-operation-unobserved"]["failed"], 1)
        self.assertFalse(verdicts[sid]["passed"])
        self.assertNotIn("private-id", json.dumps(result))
