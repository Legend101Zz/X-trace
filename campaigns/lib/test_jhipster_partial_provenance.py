"""Projection must preserve uncertainty and never expose arbitrary recording fields."""
import json
import unittest
from campaigns.java.jhipster.harness.partial_provenance import project


class PartialProvenanceTest(unittest.TestCase):
    def test_absent_and_partial_are_not_zero_filled(self):
        value = project({"events": []}, whole=False)
        self.assertEqual(value["scope"], "partial-window")
        self.assertEqual(value["terminal"], "unavailable")
        self.assertEqual(value["capacityDrops"], "unavailable")
        self.assertIsNone(value["positiveDropBuckets"])
        self.assertEqual(value["sessionRejectedRequests"], "unavailable")

    def test_whitelisted_counts_and_redaction(self):
        doc = {"events": [{"kind": "gap", "gap": {"reason": "queue_full", "symbol": "secret"}},
                          {"kind": "private-kind", "gap": {"reason": "private-reason"}}],
               "outcome": {"kind": "responded", "message": "secret"},
               "capacity": {"capacityDroppedEvents": "3"},
               "dropCountsByPriority": {"12": "0", "4": "7"},
               "sessionContext": {"rejectedRequests": "4", "runtimeSessionId": "private-id"}}
        value = project(doc, whole=True)
        self.assertEqual(value["eventKinds"]["gap"], 1)
        self.assertEqual(value["gapReasons"]["queue_full"], 1)
        self.assertEqual(value["positiveDropBuckets"], 1)
        self.assertEqual(value["capacityDrops"], "positive")
        self.assertEqual(value["sessionRejectedRequests"], "positive")
        self.assertNotIn("private", json.dumps(value))
        self.assertNotIn("secret", json.dumps(value))

    def test_empty_priority_map_needs_observed_terminal_evidence_for_zero(self):
        from campaigns.java.jhipster.harness.partial_provenance import valid
        for key in ("dropCountsByPriority", "drop_counts_by_priority"):
            with self.subTest(key=key):
                doc = {"events": [], "outcome": None, "capacity": None, key: {}}
                missing = project(doc, whole=True)
                self.assertIsNone(missing["positiveDropBuckets"])
                self.assertTrue(valid(missing))
                self.assertFalse(valid({**missing, "positiveDropBuckets": 0}))
                observed = project({**doc, "outcome": {"kind": "unobserved"}}, whole=True)
                self.assertEqual(observed["positiveDropBuckets"], 0)
                self.assertTrue(valid(observed))

    def test_invalid_counter_is_unavailable(self):
        value = project({"events": [], "dropCountsByPriority": {"1": "-1"},
                         "sessionContext": {"rejectedRequests": "invalid"}}, whole=True)
        self.assertIsNone(value["positiveDropBuckets"])
        self.assertEqual(value["sessionRejectedRequests"], "unavailable")

    def test_capacity_observation_and_drop_bucket_must_agree_on_availability(self):
        from campaigns.java.jhipster.harness.partial_provenance import valid
        unavailable = project({"events": []}, whole=True)
        observed = project({"events": [], "capacity": {"capacityDroppedEvents": "1"}}, whole=True)
        self.assertTrue(valid(unavailable))
        self.assertTrue(valid(observed))
        for contradictory in ({**unavailable, "capacityDrops": "zero"},
                              {**unavailable, "capacityDrops": "positive"},
                              {**observed, "capacityDrops": "unavailable"}):
            self.assertFalse(valid(contradictory))

    def test_public_validator_rejects_extra_values_and_fake_counts(self):
        from campaigns.java.jhipster.harness.partial_provenance import valid
        value = project({"events": [{"kind": "request", "gap": None}]}, whole=True)
        self.assertTrue(valid(value))
        self.assertFalse(valid({**value, "raw": "secret"}))
        self.assertFalse(valid({**value, "eventKinds": {**value["eventKinds"], "other": 1001}}))
        self.assertFalse(valid({**value, "sessionScope": "this-recording"}))


class PairedPageProvenanceTest(unittest.TestCase):
    def setUp(self):
        from pathlib import Path
        import tempfile
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name).resolve()
        self.api = self.root / "campaign/java/jhipster/instrumented-1/api"
        self.rid = "private-recording"
        self.cursor = "private-next"
        self.first = self.page(None, self.cursor, "2", "request_update")
        self.last = self.page(self.cursor, None, "7", "response")

    def page(self, cursor, next_cursor, sequence, kind):
        return {"recordingId": self.rid, "cursor": cursor, "nextCursor": next_cursor, "limit": 1,
                "events": [{"sequence": sequence, "kind": "recording_event_kind:" + kind, "gap": None}],
                "incompleteEvidence": ["persisted_status:partial"], "status": "partial", "completion": "partial"}

    def fetch(self, last):
        from unittest import mock
        import xinstr
        client = mock.Mock()
        client.get.side_effect = [(200, {"recordings": [{"recordingId": self.rid}], "nextAfter": None}),
                                  (200, self.first), (200, last)]
        result = xinstr.collect_api(client, self.api, verified_detail_limit=1)
        self.assertEqual([call.args[0] for call in client.get.call_args_list], [
            "/api/v1/recordings?limit=200", f"/api/v1/recordings/{self.rid}?limit=1",
            f"/api/v1/recordings/{self.rid}?limit=1&cursor={self.cursor}"])
        return result

    def test_real_collectors_pair_partial_cli_window_with_verified_complete_api_pagination(self):
        import subprocess
        from unittest import mock
        from campaigns.java.jhipster.harness import collect_sinks as sinks
        from campaigns.java.jhipster.harness import public_result
        self.assertTrue(self.fetch(self.last)["ok"])
        cli = {"recording_id": self.rid, "limit": 1, "cursor": None, "next_cursor": self.cursor,
               "events": self.first["events"], "status": "partial", "completion": "partial",
               "incomplete_evidence": ["persisted_status:partial"]}
        def output(argv, **options):
            document = {"recordings": [{"recording_id": self.rid}], "next_after": None} if argv[2] == "list" else cli
            options["stdout"].write(json.dumps(document).encode())
            return subprocess.CompletedProcess(argv, 0)
        with mock.patch.object(sinks.subprocess, "run", side_effect=output) as run:
            self.assertFalse(sinks.collect(self.root, detail_limit=1))
        self.assertEqual(run.call_count, 2)
        receipt = public_result.cli_diagnostics(json.loads((self.root / "sinks/cli-status.json").read_bytes()))
        self.assertEqual(receipt["firstFailure"]["reason"], "incomplete-evidence")
        pair = receipt["firstIncomplete"]
        self.assertFalse(pair["sameReadScope"])
        self.assertEqual(pair["provenance"]["cli"]["scope"], "partial-window")
        self.assertEqual(pair["provenance"]["api"]["scope"], "whole-recording")
        self.assertEqual(pair["provenance"]["api"]["eventKinds"]["request_update"], 1)
        self.assertEqual(pair["provenance"]["api"]["eventKinds"]["response"], 1)
        self.assertEqual(pair["provenance"]["cli"]["eventKinds"]["response"], 0)
        self.assertNotIn("private-", json.dumps(receipt))

    def test_single_cli_page_requires_validated_binding_to_share_whole_api_scope(self):
        import subprocess
        import tempfile
        from unittest import mock
        from pathlib import Path
        from campaigns.java.jhipster.harness import collect_sinks as sinks, public_result
        self.assertTrue(self.fetch(self.last)["ok"])
        events = self.first["events"] + self.last["events"]
        api_bytes = (self.api / f"recording-{self.rid}.json").read_bytes()
        page = {"recording_id": self.rid, "limit": 2, "cursor": None, "next_cursor": None,
                "events": events, "incomplete_evidence": ["persisted_status:partial"]}
        for change in ({}, {"cursor": "wrong"}, {"limit": 1}, {"events": events[::-1]}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                api = root / self.api.relative_to(self.root)
                api.mkdir(parents=True)
                (api / f"recording-{self.rid}.json").write_bytes(api_bytes)
                def output(argv, **options):
                    doc = ({"recordings": [{"recording_id": self.rid}], "next_after": None}
                           if argv[2] == "list" else {**page, **change})
                    options["stdout"].write(json.dumps(doc).encode())
                    return subprocess.CompletedProcess(argv, 0)
                with mock.patch.object(sinks.subprocess, "run", side_effect=output):
                    self.assertFalse(sinks.collect(root, detail_limit=2))
                status = json.loads((root / "sinks/cli-status.json").read_bytes())
                pair = public_result.cli_diagnostics(status)["firstIncomplete"]
                self.assertEqual(pair["sameReadScope"], not change)
                self.assertEqual(pair["cliReadScope"], "one-page" if change else "whole-recording")
                self.assertEqual(pair["provenance"]["cli"]["scope"], "partial-window" if change else "whole-recording")
                self.assertEqual(pair["provenance"]["api"]["scope"], "whole-recording")
                legacy = dict(status["firstIncomplete"])
                del legacy["provenance"]
                self.assertFalse(public_result.first_incomplete_projection(legacy)["sameReadScope"])

    def test_unbound_or_unfinished_second_page_cannot_supply_whole_provenance(self):
        from campaigns.java.jhipster.harness import collect_sinks as sinks
        for key, value in (("recordingId", "different"), ("recordingId", None), ("cursor", "wrong"),
                           ("nextCursor", self.cursor), ("nextCursor", None), ("limit", True),
                           ("events", self.first["events"])):
            with self.subTest(key=key, value=value):
                last = dict(self.last)
                if value is None:
                    del last[key]
                else:
                    last[key] = value
                self.fetch(last)
                self.assertIsNone(sinks.paired_api_detail(self.api, self.rid)[2])

    def test_legacy_aggregate_retains_marker_evidence_without_page_provenance(self):
        from campaigns.java.jhipster.harness import collect_sinks as sinks
        self.api.mkdir(parents=True)
        path = self.api / f"recording-{self.rid}.json"
        path.write_text(json.dumps(self.last))
        state, marker, doc = sinks.paired_api_detail(self.api, self.rid)
        self.assertEqual(state, "complete-read")
        self.assertEqual(marker["markers"]["persisted-partial"], 1)
        self.assertIsNone(doc)
