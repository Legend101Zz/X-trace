"""Hosted source fixtures for finite Fineract first-incomplete provenance."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import fineract_detail_evidence as paired
import installed_java
import installed_sinks
import xinstr
from campaigns.java.fineract.harness import privacy, receipt_diagnostics


PROJECT = "01a00000-0000-7000-8000-000000000001"
RECORDING = "01a00000-0000-7000-8000-000000000002"
OTHER = "01a00000-0000-7000-8000-000000000003"
PRIVATE = "excluded-private-value"


def detail(api, sequences=(1, 2), *, cursor=None, next_cursor=None, markers=None):
    fields = {"schema_version": 3, "project_id": PROJECT, "recording_id": RECORDING,
              "first_sequence": str(sequences[0]) if sequences else None,
              "last_sequence": str(sequences[-1]) if sequences else None, "anchor_frame_id": None,
              "next_cursor": next_cursor, "incomplete_evidence": [] if markers is None else markers,
              "session_context": {"rejectedRequests": "0"}, "drop_counts_by_priority": {}}
    return {**{paired.field(key, api): value for key, value in fields.items()}, "projection": "full",
            "cursor": cursor, "limit": 1000, "completion": "partial", "outcome": None, "capacity": None,
            "events": [{"sequence": str(number), "kind": "recording_event_kind:gap", "gap": {"reason": "queue_full"},
                        "source": PRIVATE, "value": PRIVATE, "symbol": PRIVATE} for number in sequences]}


def listing(api, count="2", first="1", last="2"):
    fields = {"recording_id": RECORDING, "event_count": count, "first_sequence": first, "last_sequence": last}
    return {paired.field("schema_version", api): 3, paired.field("project_id", api): PROJECT,
            "limit": 200 if api else 100, "after": None, paired.field("next_after", api): None,
            "recordings": [{paired.field(key, api): value for key, value in fields.items()}]}


class FineractFirstPartialPair(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "run"
        self.root.mkdir(mode=0o700)
        self.capture = self.root / "campaign/java/fineract/instrumented-1/capture"
        self.api = self.capture / "api"
        self.addCleanup(os.umask, os.umask(0o077))
        # Same scratch-ancestor exception as the existing hosted privacy fixtures.
        # File mode, link counts, file reads and namespace replacements remain real.
        parent = mock.patch.object(installed_java, "private_dir", side_effect=lambda path: Path(path).absolute())
        parent.start()
        self.addCleanup(parent.stop)

    def save_api(self, *replies, page=None):
        client = mock.Mock(deadline=None)
        client.get.side_effect = [(200, listing(True) if page is None else page), *replies]
        result = xinstr.collect_api(client, self.api, fineract_pair=True)
        self.assertEqual(client.get.call_count, len(replies) + 1)
        return result

    def cli(self, *pages, page=None, complete=False):
        replies = iter([listing(False) if page is None else page, *pages])

        def run(args, **kwargs):
            kwargs["stdout"].write(json.dumps(next(replies)).encode())
            return subprocess.CompletedProcess(args, 0)

        with mock.patch.object(subprocess, "run", side_effect=run) as commands:
            success = installed_sinks.collect(self.root, "fineract", self.capture)
            self.assertIs(success, complete)
        self.assertEqual(commands.call_count, len(pages) + 1)
        raw = json.loads((self.root / "sinks/cli-status.json").read_text())
        if complete:
            self.assertIsNone(raw["firstFailure"])
            self.assertEqual(raw["completedDetails"], 1)
            return raw
        self.assertEqual(raw["firstFailure"], {"stage": "detail", "reason": "incomplete-evidence", "exitCode": None})
        self.assertEqual(raw["completedDetails"], 0)
        return raw

    def pair(self, doc):
        return receipt_diagnostics.cli_diagnostics(doc)["firstIncomplete"]

    def test_same_recording_complete_reads_keep_capture_loss_and_scopes_separate(self):
        observed = self.save_api((200, detail(True, markers=["persisted_status:partial", "gap_event_sequence:1", PRIVATE])))
        self.assertTrue(observed["ok"])
        later = detail(False, markers=["persisted_status:partial", "verification_budget_exceeded"])
        later.update(outcome={"kind": "unobserved", "httpStatus": 418}, capacity={"capacityDroppedEvents": "3"},
                     drop_counts_by_priority={"2": "0", "1": "7"})
        pair = self.pair(self.cli(later))
        self.assertEqual(pair["comparisonScope"], "both-whole")
        self.assertEqual(pair["observationPhases"], "earlier-saved-api-later-cli")
        self.assertEqual(pair["identityScope"], "same-recording-not-client-attribution")
        self.assertEqual(pair["sharedKnownMarkerCategories"], 1)
        self.assertEqual((pair["api"]["terminal"], pair["cli"]["terminal"]), ("unavailable", "observed"))
        self.assertEqual(pair["api"]["dropBuckets"], {"state": "unavailable", "positive": None})
        self.assertEqual(pair["cli"]["dropBuckets"], {"state": "observed", "positive": 1})
        self.assertEqual(pair["api"]["sessionRejectedRequests"], "zero")
        self.assertEqual(pair["api"]["markers"]["counts"]["other"], 1)
        self.assertEqual(pair["api"]["gapReasons"]["queue_full"], 2)
        for private in (PRIVATE, RECORDING, PROJECT, "418", "gap_event_sequence:"):
            self.assertNotIn(private, json.dumps(pair))

    def test_later_cli_page_is_not_whole_and_different_windows_do_not_compare(self):
        continuation = paired.cursor_for(PROJECT, RECORDING, 1)
        first = detail(True, (1,), next_cursor=continuation, markers=["persisted_status:partial"])
        second = detail(True, (2,), cursor=continuation, markers=["persisted_status:invalid"])
        self.assertTrue(self.save_api((200, first), (200, second))["ok"])
        raw = self.cli(detail(False, (1,), next_cursor=continuation),
                       detail(False, (2,), cursor=continuation, markers=["persisted_status:partial"]))
        projection = self.pair(raw)
        self.assertEqual((projection["apiRead"], projection["cliRead"]), ("whole-recording", "one-page"))
        self.assertIsNone(projection["sharedKnownMarkerCategories"])
        self.assertEqual(projection["api"]["markers"]["counts"]["persisted-invalid"], 1)
        self.assertEqual(sum(projection["cli"]["eventKinds"].values()), 1)

    def test_api_transport_gap_distinguishes_no_read_from_a_bound_prefix(self):
        result = self.save_api(TimeoutError())
        self.assertFalse(result["ok"])
        self.assertEqual(paired.read_api(self.api, RECORDING, PROJECT, 1 << 20), ("unavailable", None))
        self.assertEqual(paired.read_api(self.api, OTHER, PROJECT, 1 << 20), ("missing", None))
        next_cursor = paired.cursor_for(PROJECT, RECORDING, 1)
        result = self.save_api((200, detail(True, (1,), next_cursor=next_cursor)), TimeoutError())
        self.assertFalse(result["ok"])
        api_state, window = paired.read_api(self.api, RECORDING, PROJECT, 1 << 20)
        self.assertEqual(api_state, "partial-window")
        self.assertEqual(window["markers"]["state"], "observed")
        self.assertEqual(sum(window["markers"]["counts"].values()), 0)
        self.assertEqual(window["eventScope"], "partial-window")

    def test_bad_page_binding_and_wrong_project_leave_no_comparison(self):
        next_cursor = paired.cursor_for(PROJECT, RECORDING, 1)
        first = detail(True, (1,), next_cursor=next_cursor)
        second = detail(True, (2,), cursor=next_cursor)
        for invalid in (dict(second, cursor=paired.cursor_for(PROJECT, OTHER, 1)),
                        dict(second, projectId=OTHER), dict(second, firstSequence="0"),
                        detail(True, (1,), cursor=next_cursor), dict(second, projection="structure")):
            with self.subTest(invalid=invalid):
                self.save_api((200, first), (200, invalid))
                self.assertEqual(paired.read_api(self.api, RECORDING, PROJECT, 1 << 20), ("rejected", None))
        self.save_api((200, detail(True)))
        self.assertEqual(paired.read_api(self.api, RECORDING, OTHER, 1 << 20), ("rejected", None))
        raw = self.cli(dict(detail(False, markers=["persisted_status:partial"]), project_id=PRIVATE))
        proof = self.pair(raw)
        self.assertEqual((proof["cliRead"], proof["apiRead"]), ("rejected", "unavailable"))
        self.assertIsNone(proof["cli"])
        self.assertIsNone(proof["api"])

    def test_missing_and_malformed_markers_do_not_become_zero(self):
        missing = detail(True)
        missing.pop("incompleteEvidence")
        self.save_api((200, missing))
        self.assertEqual(paired.read_api(self.api, RECORDING, PROJECT, 1 << 20)[1]["markers"],
                         {"state": "missing", "counts": None, "truncated": None})
        self.save_api((200, detail(True, markers=[PRIVATE] * 33)))
        markers = paired.read_api(self.api, RECORDING, PROJECT, 1 << 20)[1]["markers"]
        self.assertEqual((sum(markers["counts"].values()), markers["counts"]["other"], markers["truncated"]), (32, 32, True))
        self.save_api((200, detail(True, markers=[PRIVATE, 1])))
        raw = self.cli(detail(False, markers=PRIVATE))
        pair = self.pair(raw)
        self.assertEqual(pair["api"]["markers"], pair["cli"]["markers"])
        self.assertEqual(pair["api"]["markers"], {"state": "malformed", "counts": None, "truncated": None})
        self.assertIsNone(pair["sharedKnownMarkerCategories"])

    def test_public_gate_rejects_unclosed_or_ambiguous_pair(self):
        self.save_api((200, detail(True)))
        raw = self.cli(detail(False, markers=["persisted_status:partial"]))
        self.assertEqual(self.pair(raw)["sharedKnownMarkerCategories"], 0)
        raw["firstIncomplete"]["api"]["recordingId"] = RECORDING
        self.assertIsNone(receipt_diagnostics.cli_diagnostics(raw))
        del raw["firstIncomplete"]
        self.assertIsNone(receipt_diagnostics.cli_diagnostics(raw))
        raw["schema"] = "xtrace-fineract-cli-sinks/2"
        self.assertNotIn("firstIncomplete", receipt_diagnostics.cli_diagnostics(raw))

    def test_list_count_range_identity_and_missing_fields_prevent_whole_api_claim(self):
        absent = listing(True)
        absent["recordings"][0].pop("eventCount")
        for page in (listing(True, "3", "1", "2"), listing(True, "2", "2", "3"), absent,
                     dict(listing(True), projectId=OTHER), dict(listing(True), after=OTHER)):
            with self.subTest(page=page):
                self.assertTrue(self.save_api((200, detail(True)), page=page)["ok"])
                state, capture = paired.read_api(self.api, RECORDING, PROJECT, 1 << 20)
                self.assertEqual(state, "terminal-window")
                self.assertEqual(capture["eventScope"], state)
        self.assertTrue(self.save_api((200, detail(True, ())), page=listing(True, "0", None, None))["ok"])
        state, empty = paired.read_api(self.api, RECORDING, PROJECT, 1 << 20)
        self.assertEqual(state, "whole-recording")
        self.assertEqual(sum(empty["eventKinds"].values()), 0)

    def test_earlier_complete_api_does_not_fill_later_cli_list_disagreement(self):
        self.assertTrue(self.save_api((200, detail(True)))["ok"])
        pair = self.pair(self.cli(detail(False, markers=["persisted_status:partial"]), page=listing(False, "3", "1", "3")))
        self.assertEqual((pair["apiRead"], pair["cliRead"]), ("whole-recording", "one-page"))
        self.assertEqual(pair["comparisonScope"], "different-or-bounded-windows")
        self.assertIsNone(pair["sharedKnownMarkerCategories"])

    def test_wire_counters_preserve_null_missing_malformed_and_decimal_evidence(self):
        empty = {"state": "observed", "counts": dict.fromkeys(paired.MARKER_CLASSES, 0), "truncated": False}
        for api in (False, True):
            source = detail(api)
            key = paired.field("session_context", api)
            for context, state in (({}, "missing"), (None, "malformed"), ({"rejectedRequests": None}, "unavailable"),
                                   ({"rejectedRequests": 0}, "malformed"), ({"rejectedRequests": "01"}, "malformed"),
                                   ({"rejectedRequests": "0"}, "zero"), ({"rejectedRequests": "1"}, "positive")):
                with self.subTest(api=api, context=context):
                    result = paired.capture({**source, key: context}, empty, "one-page", api=api)
                    self.assertEqual(result["sessionRejectedRequests"], state)
            for capacity, count, terminal in ((None, "unavailable", "unavailable"), ({}, "missing", "unavailable"),
                                             ({"capacityDroppedEvents": None}, "malformed", "unavailable"),
                                             ({"capacityDroppedEvents": 0}, "malformed", "unavailable"),
                                             ({"capacityDroppedEvents": "0"}, "zero", "observed"),
                                             ({"capacityDroppedEvents": "2"}, "positive", "observed")):
                result = paired.capture({**source, "capacity": capacity}, empty, "one-page", api=api)
                self.assertEqual((result["capacityDrops"], result["terminal"]), (count, terminal))
            for invalid in (None, 0, True, "00"):
                result = paired.capture({**source, paired.field("drop_counts_by_priority", api): {"2": invalid}},
                                        empty, "one-page", api=api)
                self.assertEqual(result["dropBuckets"], {"state": "malformed", "positive": None})

    def test_private_scanner_admits_complete_v3_collection_and_saved_archive(self):
        self.save_api((200, detail(True)))
        raw = self.cli(detail(False), complete=True)
        self.assertTrue(raw["artifactComplete"])
        self.assertEqual(self.scan_collection(), ("passed", "passed"))

    def scan_collection(self):
        driver = self.root.parent / "driver"
        if not driver.exists():
            driver.mkdir(mode=0o700)
            privacy.mark_admitted(self.root)
        collection = privacy.PrivacyEvidence(self.root).scan({})["collection"]
        return collection["cli"], collection["savedArtifact"]

    def test_private_scanner_distinguishes_partial_v3_and_rejects_impossible_comparators(self):
        self.save_api((200, detail(True)))
        raw = self.cli(detail(False, markers=["persisted_status:partial"]))
        self.assertTrue(raw["artifactComplete"])
        self.assertEqual(self.scan_collection(), ("failed", "passed"))
        for mutation in ("empty", "unrelated-marker", "unexpected-field", "impossible-drop-state"):
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(raw)
                cli = candidate["firstIncomplete"]["cli"]
                if mutation == "empty":
                    cli["markers"]["counts"]["persisted-partial"] = 0
                elif mutation == "unrelated-marker":
                    cli["markers"]["counts"].update({"persisted-partial": 0, "persisted-invalid": 1})
                elif mutation == "unexpected-field":
                    candidate["unexpected"] = PRIVATE
                else:
                    cli["terminal"], cli["capacityDrops"] = "observed", "zero"
                self.assertIsNone(receipt_diagnostics.cli_diagnostics(candidate))
                (self.root / "sinks/cli-status.json").write_text(json.dumps(candidate))
                self.assertEqual(self.scan_collection(), ("failed", "failed"))
