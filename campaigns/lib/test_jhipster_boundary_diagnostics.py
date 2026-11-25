"""Synthetic regressions for diagnostics. None qualify a live campaign boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import boundary_diagnostics as diag
import xinstr

PUBLIC_PATH = Path(__file__).resolve().parents[1] / "java/jhipster/harness/public_result.py"
SPEC = importlib.util.spec_from_file_location("jhipster_boundaries_public", PUBLIC_PATH)
public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public)

PRIVATE = "private-id-cursor-body-message"
EXPECTED = {"serial": [{"method": "GET", "route": "/known"}]}
SENT = [("serial", "GET", "/known")]


def root(symbol, *, completion="complete", status=403, outcome="responded"):
    return {"completion": completion, "outcome": (
                {"kind": outcome, "httpStatus": status} if outcome is not None else None),
            "events": [{"kind": "recording_event_kind:request_update", "symbol": symbol,
                        "interaction": {"kind": "interaction_kind:framework", "driver": "servlet", "method": "GET"}}]}


def phase(status, *, ordinal=1, polls=0, failure=None, snapshot=None, snapshot_poll=None):
    return {"ordinal": ordinal, "kind": ("serial", "burst", "serial")[ordinal - 1],
            "status": status, "polls": polls, "failure": failure,
            "snapshot": snapshot, "snapshotPoll": snapshot_poll,
            "lastComplete": None, "lastCompletePoll": None}


def manifest(initial, phases, failure=None):
    return {"schemaVersion": 2, "initial": {"status": initial, "failure": failure}, "phases": phases}


class JHipsterBoundaryDiagnostics(unittest.TestCase):
    def test_route_less_inventory_separates_outcome_completion_capacity_and_ambiguity(self):
        route_less = root("http.request GET")
        route_less["events"][0]["private"] = PRIVATE
        named = root("http.request GET /other")
        named["sessionContext"] = {"runtimeSessionId": PRIVATE, "rejectedRequests": "3"}
        ambiguous = root("http.request GET")
        ambiguous["events"].append(dict(ambiguous["events"][0], symbol="http.request GET /known"))
        unrelated = root("http.request GET")
        unrelated["events"].append({"kind": "recording_event_kind:frame_enter", "symbol": PRIVATE})
        bad_status = root("http.request GET", status=True)
        details = {PRIVATE: route_less, "other": named, "ambiguous": ambiguous, "unrelated": unrelated,
                   "bad-status": bad_status, "provisional": root("http.request GET", status=None, outcome="unobserved"),
                   "partial": root("http.request GET", completion="partial", status=None, outcome=None),
                   "unread": {"_detailReadGap": PRIVATE}, "before": root("http.request GET")}
        before = {"before": {}}
        boundary = xinstr.burst_accounting(details, SENT, EXPECTED, before, {PRIVATE: 1})
        output = diag.snapshot(details, [{"recordingId": rid} for rid in details] + [{"recordingId": "only-listed"}],
                               before, boundary)
        self.assertFalse(boundary["verified"])
        self.assertEqual((output["listedNewRecordings"], output["newRecordings"], output["missingNamed"],
                          output["capacityRejected"], output["unexpectedRoots"], output["unclassifiedRecordings"],
                          output["unreadRecordings"], output["namedMatched"], output["optionalNamed"]),
                         (9, 8, 1, 2, 1, 3, 1, 0, 0))
        self.assertEqual(output["routeLess"], [
            {"completion": "complete", "method": "GET", "outcome": "responded", "httpStatus": 403, "recordings": 1},
            {"completion": "complete", "method": "GET", "outcome": "unobserved", "httpStatus": None, "recordings": 1},
            {"completion": "partial", "method": "GET", "outcome": "unavailable", "httpStatus": None, "recordings": 1},
        ])
        self.assertNotIn(PRIVATE, json.dumps(output))
        self.assertIsNotNone(diag.projection(manifest("verified", [
            phase("deadline", polls=1, snapshot=output, snapshot_poll=1),
            phase("prior-unverified", ordinal=2),
        ])))

    def test_named_and_filter_roots_do_not_change_boundary_acceptance(self):
        known = root("http.request GET /known", status=200)
        refused = root("http.request GET", status=403)
        details = {"known": known, "filter": refused}
        optional = (("GET", "/denied", 403),)
        boundary = xinstr.burst_accounting(details, SENT, EXPECTED, {}, optional_roots=optional)
        self.assertFalse(boundary["verified"])
        self.assertEqual(boundary["optionalRootIds"], [])
        self.assertEqual(diag.snapshot(details, None, {}, boundary)["namedMatched"], 1)
        self.assertTrue(xinstr.burst_accounting({"known": known}, SENT, EXPECTED, {}, optional_roots=optional)["verified"])

    def test_initial_read_and_deadline_skip_are_not_success(self):
        initial_error = manifest("read", [phase("initial-unverified"), phase("prior-unverified", ordinal=2)],
                                 {"stage": "list", "reason": "cursor"})
        self.assertEqual(diag.projection(initial_error)["firstUnverifiedPhase"], 1)
        with mock.patch.object(xinstr.time, "monotonic", return_value=12), \
                mock.patch.object(xinstr, "collect_api") as collect:
            boundary = xinstr.wait_burst_boundary(mock.Mock(), Path("unused"), SENT, EXPECTED, {}, 10, diagnose=True)
        collect.assert_not_called()
        self.assertFalse(boundary["verified"])
        self.assertEqual(boundary["diagnostic"]["status"], "deadline")
        self.assertIsNone(boundary["diagnostic"]["snapshot"])

    def test_first_failed_live_read_keeps_stage_and_the_poll_of_the_last_snapshot(self):
        client = mock.Mock()
        good = {"ok": True, "details": {"root": root("http.request GET")}}
        fail = {"ok": False, "details": {}, "reason": PRIVATE,
                "readFailure": {"stage": "detail", "reason": "deadline"}}
        with mock.patch.object(xinstr.time, "monotonic", return_value=1), \
                mock.patch.object(xinstr, "collect_api", side_effect=[good, fail]):
            boundary = xinstr.wait_burst_boundary(client, Path("unused"), SENT, EXPECTED, {}, 10, diagnose=True)
        diagnostic = boundary["diagnostic"]
        self.assertFalse(boundary["verified"])
        self.assertEqual((diagnostic["status"], diagnostic["polls"], diagnostic["snapshotPoll"]), ("read", 2, 1))
        self.assertEqual(diagnostic["failure"], fail["readFailure"])
        self.assertEqual(diagnostic["snapshot"]["missingNamed"], 1)
        self.assertEqual(diagnostic["lastCompletePoll"], 1)
        self.assertEqual(diagnostic["lastComplete"], diagnostic["snapshot"])
        self.assertNotIn(PRIVATE, json.dumps(diagnostic))
        self.assertIsNone(client.deadline)

    def test_list_only_partial_poll_never_reuses_previous_detail_counters(self):
        previous = root("http.request GET /known")
        previous["sessionContext"] = {"runtimeSessionId": PRIVATE, "rejectedRequests": "3"}
        good = {"ok": True, "details": {"known": previous}}
        fail = {"ok": False, "details": {}, "recordings": [{"recordingId": "newly-listed"}],
                "reason": PRIVATE, "readFailure": {"stage": "list", "reason": "deadline"}}
        with mock.patch.object(xinstr.time, "monotonic", return_value=1), \
                mock.patch.object(xinstr, "collect_api", side_effect=[good, fail]):
            boundary = xinstr.wait_burst_boundary(mock.Mock(), Path("unused"), SENT, EXPECTED, {}, 10,
                                                 diagnose=True)
        diagnostic = boundary["diagnostic"]
        self.assertFalse(boundary["verified"])
        self.assertEqual((diagnostic["polls"], diagnostic["snapshotPoll"]), (2, 2))
        self.assertEqual(diagnostic["snapshot"], {
            "listedNewRecordings": 1, "newRecordings": 0, "namedMatched": 0, "optionalNamed": 0,
            "missingNamed": 1, "capacityRejected": 0, "unexpectedRoots": 0,
            "unclassifiedRecordings": 0, "unreadRecordings": 0, "routeLess": [],
            "unassignedRecordings": 0, "assignedPartialRecordings": 0, "overmatchedRequests": 0,
            "unmatchedSentRequests": 0, "unaccountedRequests": 1, "excessAccountedRequests": 0})
        self.assertEqual(diagnostic["lastCompletePoll"], 1)
        self.assertEqual(diagnostic["lastComplete"]["namedMatched"], 1)
        self.assertEqual(diagnostic["lastComplete"]["capacityRejected"], 3)
        self.assertEqual(diagnostic["lastComplete"]["excessAccountedRequests"], 3)
        self.assertNotIn(PRIVATE, json.dumps(diagnostic))
        self.assertIsNotNone(diag.projection(manifest("verified", [dict(diagnostic, ordinal=1, kind="serial")])))

    def test_strict_serial_still_rejects_partial_exact_named_recording(self):
        known = root("http.request GET /known", completion="partial", status=200)
        good = {"ok": True, "details": {"known": known}}
        with mock.patch.object(xinstr.time, "monotonic", return_value=1), \
                mock.patch.object(xinstr, "collect_api", return_value=good):
            boundary = xinstr.wait_burst_boundary(
                mock.Mock(), Path("unused"), SENT, EXPECTED, {}, 10, require_complete=True, diagnose=True)
        self.assertFalse(boundary["verified"])
        self.assertEqual(boundary["diagnostic"]["status"], "strict-serial")
        self.assertEqual(boundary["diagnostic"]["lastComplete"]["assignedPartialRecordings"], 1)

    def test_late_complete_read_only_updates_the_attempt_snapshot(self):
        prior = {"ok": True, "details": {"unknown": root("http.request GET")}}
        late = {"ok": True, "details": {"named": root("http.request GET /known")}}
        with mock.patch.object(xinstr.time, "monotonic", side_effect=[1, 2, 3, 11, 12]), \
                mock.patch.object(xinstr, "collect_api", side_effect=[prior, late]):
            boundary = xinstr.wait_burst_boundary(mock.Mock(), Path("unused"), SENT, EXPECTED, {}, 10,
                                                 diagnose=True)
        diagnostic = boundary["diagnostic"]
        self.assertFalse(boundary["verified"])
        self.assertEqual(diagnostic["status"], "deadline")
        self.assertEqual(diagnostic["snapshot"]["namedMatched"], 1)
        self.assertEqual(diagnostic["lastComplete"]["unassignedRecordings"], 1)
        self.assertEqual((diagnostic["snapshotPoll"], diagnostic["lastCompletePoll"]), (2, 1))
        phase_row = dict(diagnostic, ordinal=1, kind="serial")
        self.assertIsNotNone(diag.projection(manifest("verified", [phase_row])))
        phase_row["lastCompletePoll"] = 3
        self.assertIsNone(diag.projection(manifest("verified", [phase_row])))

    def test_api_read_classifies_detail_cursor_and_keeps_private_text_out(self):
        client = mock.Mock()
        client.get.side_effect = [
            (200, {"recordings": [{"recordingId": "rec"}], "nextAfter": None}),
            (200, {"recordingId": "rec", "events": [{}], "nextCursor": PRIVATE + " invalid"}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            result = xinstr.collect_api(client, Path(tmp))
        self.assertFalse(result["ok"])
        self.assertEqual(result["readFailure"], {"stage": "detail", "reason": "cursor"})
        self.assertNotIn(PRIVATE, json.dumps(result["readFailure"]))

    def test_manifest_rejects_invalid_private_and_inconsistent_evidence(self):
        data = manifest("verified", [phase("deadline"), phase("prior-unverified", ordinal=2)])
        for path, value in (
            (("initial", "status"), PRIVATE), (("phase", "ordinal"), True),
            (("phase", "kind"), PRIVATE), (("phase", "polls"), -1),
            (("phase", "snapshotPoll"), 2), (("phase", "context"), PRIVATE),
            (("phase", "status"), "verified"),
        ):
            with self.subTest(path=path):
                changed = copy.deepcopy(data)
                node = changed["initial"] if path[0] == "initial" else changed["phases"][0]
                node[path[1]] = value
                self.assertIsNone(diag.projection(changed))

    def test_saved_v1_boundary_projects_original_evidence_with_no_new_fields(self):
        snapshot = {
            "listedNewRecordings": 23, "newRecordings": 13, "namedMatched": 12, "optionalNamed": 0,
            "missingNamed": 8, "capacityRejected": 0, "unexpectedRoots": 0,
            "unclassifiedRecordings": 0, "unreadRecordings": 1, "routeLess": [],
        }
        old_phase = {"ordinal": 1, "kind": "serial", "status": "read", "polls": 138,
                     "failure": {"stage": "detail", "reason": "deadline"}, "snapshot": snapshot, "snapshotPoll": 138}
        skipped = {"ordinal": 2, "kind": "burst", "status": "prior-unverified", "polls": 0,
                   "failure": None, "snapshot": None, "snapshotPoll": None}
        data = {"schemaVersion": 1, "initial": {"status": "verified", "failure": None},
                "phases": [old_phase, skipped, dict(skipped, ordinal=3, kind="serial")]}
        receipt = {"project": "jhipster", "instrumented": True, "releaseAcceptance": False,
                   "boundariesVerified": False, "notes": {"boundaryDiagnostics": data,
                       "orderedBoundaries": [{"kind": item["kind"], "verified": False} for item in data["phases"]]}}
        self.assertEqual(public.boundary_manifest(receipt), dict(data, firstUnverifiedPhase=1))
        for target, key, value in ((old_phase, "lastComplete", None), (old_phase, "private", PRIVATE),
                                   (snapshot, "unassignedRecordings", 1), (snapshot, "private", PRIVATE)):
            with self.subTest(key=key):
                target[key] = value
                self.assertIsNone(public.boundary_manifest(receipt))
                del target[key]

    def test_projection_never_reports_rejected_phase_as_verified(self):
        data = manifest("verified", [phase("deadline")])
        receipt = {"project": "jhipster", "instrumented": True, "releaseAcceptance": False,
                   "boundariesVerified": False,
                   "notes": {"boundaryDiagnostics": data,
                             "orderedBoundaries": [{"kind": "serial", "verified": False, "readError": PRIVATE}]}}
        self.assertEqual(public.boundary_manifest(receipt)["firstUnverifiedPhase"], 1)
        receipt["notes"]["orderedBoundaries"][0]["verified"] = True
        self.assertIsNone(public.boundary_manifest(receipt))
