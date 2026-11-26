"""One preselected ordinary office-list GET across an on-time live poll and saved final detail."""
import json
import unittest

import fineract_phase_evidence as phase
import test_fineract_first_partial_pair as fixture
import test_fineract_phase_evidence as live_fixture
from campaigns.java.fineract.harness import receipt_diagnostics as diagnostics
from campaigns.java.fineract.harness.recording_evidence import OFFICES


class FineractOfficeReadPartial(unittest.TestCase):
    def setUp(self):
        self.files = fixture.FineractFirstPartialPair()
        self.files.setUp()
        self.addCleanup(self.files.doCleanups)
        self.capture = self.files.capture
        self.phase_dir = self.capture / "phase-1-api"
        self.phase_dir.mkdir(mode=0o700, parents=True)
        self.manifest = {"phases": [{"lastCompletePoll": 7,
                                     "lastComplete": {"namedMatched": 2, "assignedPartialRecordings": 2}}]}

    def poll(self):
        doc = live_fixture.document()
        doc["events"] = [{"kind": "recording_event_kind:request_update", "symbol": "http.request GET " + OFFICES}]
        doc.update(outcome={"kind": "responded"}, capacity={"capacityDroppedEvents": "0"}, durationNs="50")
        details, listing, _ = live_fixture.observed(doc, live_fixture.document(fixture.OTHER))
        row = dict(method="GET", route=OFFICES, requests=1, recordings=1, missing=0, recordingIds=[fixture.RECORDING])
        accounting = dict(routes=[row], recordingIds=[fixture.RECORDING, fixture.OTHER], optionalRootIds=[],
                          partialRecordingIds=[fixture.RECORDING, fixture.OTHER])
        return details, listing, accounting

    def save(self, observation=None):
        phase.save_deferred(self.capture, [(self.poll() if observation is None else observation, 7)],
                            live_fixture.stop(fixture.OTHER))

    def read(self):
        return diagnostics.office_read_partial(self.capture, self.manifest)

    def test_live_named_read_joins_only_its_saved_response_gap_and_actual_stop(self):
        self.save()
        doc = fixture.detail(True, sequences=(1, 2, 3), markers=["persisted_status:partial", "gap_event_sequence:3"])
        doc.update(outcome={"kind": "responded"}, capacity={"capacityDroppedEvents": "0"}, durationNs="50")
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        doc["events"][1].update(kind="recording_event_kind:response", gap=None)
        doc["events"][2]["gap"]["reason"] = "class_not_transformed"
        self.files.save_api((200, doc), page=fixture.listing(True, count="3", last="3"))
        result = self.read()
        self.assertEqual(result["selection"], "observed")
        self.assertEqual(result["phaseEvidence"]["live"], dict(terminalMetadata="present", duration="present", completion="partial"))
        self.assertEqual(result["phaseEvidence"]["livePoll"], 7)
        self.assertEqual(result["phaseEvidence"]["selectedRecovery"], "not-listed")
        self.assertEqual(result["phaseEvidence"]["recoveredCount"], 1)
        self.assertEqual(result["afterStopCommandApiRead"], "whole-recording")
        final = result["afterStopCommandApi"]
        self.assertEqual(final["completion"], "partial")
        self.assertEqual(final["eventKinds"]["response"], 1)
        self.assertEqual(final["gapReasons"]["class_not_transformed"], 1)
        for private in (fixture.PRIVATE, fixture.PROJECT, fixture.RECORDING, fixture.OTHER, OFFICES):
            self.assertNotIn(private, json.dumps(result))

    def test_unique_partial_root_required_without_selecting_a_replacement(self):
        for ambiguity in ("route", "count", "optional", "multiple-roots", "complete", "other-id", "not-assigned"):
            with self.subTest(ambiguity=ambiguity):
                details, listing, boundary = self.poll()
                doc = details[fixture.RECORDING]
                row = boundary["routes"][0]
                if ambiguity == "route":
                    row["route"] += "/{officeId}"
                elif ambiguity == "count":
                    row.update(recordings=2, missing=-1, recordingIds=[fixture.OTHER, fixture.RECORDING])
                elif ambiguity == "optional":
                    boundary["optionalRootIds"] = [fixture.RECORDING]
                elif ambiguity == "multiple-roots":
                    doc["events"] *= 2
                elif ambiguity == "complete":
                    doc["completion"] = "complete"
                elif ambiguity == "other-id":
                    row["recordingIds"] = [fixture.OTHER]
                else:
                    boundary["partialRecordingIds"] = [fixture.OTHER]
                phase.save_office_read(self.capture, (details, listing, boundary), 7)
                self.assertEqual(self.read(), {"selection": "not-observed"})

    def test_missing_post_stop_detail_and_mismatched_final_project_are_explicit(self):
        self.save()
        self.assertEqual(self.read()["afterStopCommandApiRead"], "missing")
        detail = fixture.detail(True)
        detail["projectId"] = fixture.OTHER
        page = fixture.listing(True)
        page["projectId"] = fixture.OTHER
        self.files.save_api((200, detail), page=page)
        result = self.read()
        self.assertEqual(result["afterStopCommandApiRead"], "rejected")
        self.assertIsNone(result["afterStopCommandApi"])
        self.assertEqual(result["phaseEvidence"]["live"]["completion"], "partial")

    def test_rejects_different_poll_and_private_selector_fields(self):
        self.save()
        self.manifest["phases"][0]["lastCompletePoll"] = 8
        self.assertEqual(self.read(), {"selection": "rejected"})
        self.manifest["phases"][0]["lastCompletePoll"] = 7
        path = self.phase_dir / "office-list-partial.json"
        value = json.loads(path.read_text())
        value["private"] = fixture.PRIVATE
        path.write_text(json.dumps(value))
        self.assertEqual(self.read(), {"selection": "rejected"})

    def test_final_api_window_without_matching_list_range_keeps_its_original_scope(self):
        self.save()
        doc = fixture.detail(True)
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        self.files.save_api((200, doc), page=fixture.listing(True, count="3", last="3"))
        result = self.read()
        self.assertEqual(result["afterStopCommandApiRead"], "terminal-window")
        self.assertEqual(result["afterStopCommandApi"]["eventScope"], "terminal-window")

    def test_final_detail_without_exact_expected_root_is_rejected(self):
        self.save()
        doc = fixture.detail(True)
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET /other", gap=None)
        self.files.save_api((200, doc))
        result = self.read()
        self.assertEqual(result["afterStopCommandApiRead"], "rejected")
        self.assertIsNone(result["afterStopCommandApi"])

    def retained(self, *pages):
        from unittest import mock
        import xinstr

        listing = fixture.listing(True, count=str(sum(len(page["events"]) for page in pages)),
                                  last=pages[-1]["lastSequence"])
        client = mock.Mock(deadline=None)
        client.get.side_effect = [(200, listing), *((200, page) for page in pages)]
        snapshot = xinstr.collect_api(client, self.phase_dir, fineract_phase=True)
        self.assertTrue(snapshot["ok"])
        self.assertEqual(client.get.call_count, len(pages) + 1)
        _, _, boundary = self.poll()
        boundary.update(recordingIds=[fixture.RECORDING], partialRecordingIds=[fixture.RECORDING])
        self.manifest["phases"][0]["lastComplete"].update(namedMatched=1, assignedPartialRecordings=1)
        return snapshot["details"], snapshot["recordings"], boundary

    def test_bound_live_page_counts_stay_separate_from_changed_saved_terminal(self):
        doc = fixture.detail(True, sequences=(1, 2, 3), markers=[
            "persisted_status:partial", "gap_event_sequence:3", "gap_event_sequence:3", fixture.PRIVATE])
        doc.update(outcome={"kind": "responded"}, capacity={"capacityDroppedEvents": "0"},
                   dropCountsByPriority={"1": "4", "2": "0"}, durationNs="50")
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        doc["events"][1].update(kind="recording_event_kind:response", gap=None)
        self.save(self.retained(doc))
        final = fixture.detail(True, markers=["persisted_status:partial"])
        final.update(outcome={"kind": "unobserved"}, dropCountsByPriority={"1": "0"})
        final["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        final["events"][1]["gap"]["reason"] = "class_not_transformed"
        self.files.save_api((200, final))
        result = self.read()
        self.assertEqual(result["liveApi"]["read"], "retained-first-page")
        live = result["liveApi"]["capture"]
        self.assertEqual(live["eventScope"], "retained-first-page")
        self.assertEqual(live["eventKinds"]["response"], 1)
        self.assertEqual(live["eventKinds"]["gap"], 1)
        self.assertEqual(live["gapReasons"]["queue_full"], 1)
        self.assertEqual(live["dropBuckets"], {"state": "observed", "positive": 1})
        self.assertEqual(result["liveApi"]["markerScope"], "retained-single-page-strings")
        self.assertEqual(live["markers"]["counts"]["gap-event"], 1)
        self.assertEqual(live["markers"]["counts"]["other"], 1)
        self.assertEqual(live["sessionRejectedRequests"], "missing")
        after = result["afterStopCommandApi"]
        self.assertEqual(after["eventKinds"]["response"], 0)
        self.assertEqual(after["dropBuckets"]["positive"], 0)
        self.assertEqual(after["gapReasons"]["class_not_transformed"], 1)
        self.assertNotIn(fixture.PRIVATE, json.dumps(result))

    def test_missing_live_page_header_preserves_selection_and_unavailable_window(self):
        self.save()
        result = self.read()
        self.assertEqual(result["selection"], "observed")
        self.assertEqual(result["phaseEvidence"]["live"]["completion"], "partial")
        self.assertEqual(result["liveApi"], {"read": "unavailable", "capture": None})

    def test_inconsistent_live_range_is_rejected_without_affecting_recovery_join(self):
        doc = fixture.detail(True)
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        doc["lastSequence"] = "7"
        self.save(self.retained(doc))
        result = self.read()
        self.assertEqual(result["liveApi"], {"read": "rejected", "capture": None})
        self.assertEqual(result["phaseEvidence"]["selectedRecovery"], "not-listed")

    def test_multi_page_live_event_counts_end_at_first_wire_range_and_withhold_merged_markers(self):
        cursor = fixture.paired.cursor_for(fixture.PROJECT, fixture.RECORDING, 2)
        first = fixture.detail(True, next_cursor=cursor, markers=["persisted_status:partial"])
        first["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        second = fixture.detail(True, sequences=(3,), cursor=cursor, markers=["verification_budget_exceeded"])
        second["events"][0].update(kind="recording_event_kind:response", gap=None)
        self.save(self.retained(first, second))
        result = self.read()
        self.assertEqual(result["liveApi"]["read"], "retained-first-page")
        live = result["liveApi"]["capture"]
        self.assertEqual(result["liveApi"]["markerScope"], "withheld-across-pages")
        self.assertEqual(sum(live["eventKinds"].values()), 2)
        self.assertEqual(live["eventKinds"]["response"], 0)
        self.assertEqual(live["markers"], {"state": "missing", "counts": None, "truncated": None})

    def test_live_window_admission_rejects_raw_fields_and_impossible_window_scope(self):
        doc = fixture.detail(True)
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        self.save(self.retained(doc))
        path = self.phase_dir / "office-list-partial.json"
        selected = json.loads(path.read_text())
        self.assertEqual(self.read()["liveApi"]["read"], "retained-first-page")
        for key, value in (("extra", fixture.PRIVATE), ("eventScope", "whole-recording"), ("duration", "present")):
            with self.subTest(key=key):
                changed = json.loads(json.dumps(selected))
                changed["window"]["capture"][key] = value
                path.write_text(json.dumps(changed))
                self.assertEqual(self.read(), {"selection": "rejected"})

    def test_header_endpoint_found_only_in_continuation_cannot_qualify_the_first_wire_page(self):
        cursor = fixture.paired.cursor_for(fixture.PROJECT, fixture.RECORDING, 3)
        first = fixture.detail(True, next_cursor=cursor, markers=["persisted_status:partial"])
        first["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        first["lastSequence"] = "3"
        second = fixture.detail(True, sequences=(3,), cursor=cursor, markers=["verification_budget_exceeded"])
        second["events"][0].update(kind="recording_event_kind:response", gap=None)
        self.save(self.retained(first, second))
        result = self.read()
        self.assertEqual(result["selection"], "observed")
        self.assertEqual(result["liveApi"], {"read": "rejected", "capture": None})
        self.assertEqual(result["phaseEvidence"]["livePoll"], 7)
        self.assertEqual(result["phaseEvidence"]["selectedRecovery"], "not-listed")

    def test_first_wire_metadata_and_marker_occurrences_exclude_continuation_payload(self):
        cursor = fixture.paired.cursor_for(fixture.PROJECT, fixture.RECORDING, 2)
        first = fixture.detail(True, next_cursor=cursor, markers=["persisted_status:partial", "persisted_status:partial"])
        first.update(durationNs="50", outcome={"kind": "responded"}, dropCountsByPriority={"1": "2", "2": "1"})
        first["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        second = fixture.detail(True, sequences=(3,), cursor=cursor, markers=["verification_budget_exceeded", fixture.PRIVATE])
        second["events"][0].update(kind="recording_event_kind:response", gap=None)
        second.update(outcome={"kind": "unobserved"}, dropCountsByPriority={}, durationNs=None)
        self.save(self.retained(first, second))
        window = self.read()["liveApi"]
        self.assertEqual(window["read"], "retained-first-page")
        self.assertEqual(window["capture"]["eventKinds"]["response"], 0)
        self.assertEqual(window["capture"]["dropBuckets"], {"state": "observed", "positive": 2})
        self.assertEqual(window["capture"]["outcome"], "responded")
        counts = window["firstPageMarkers"]["counts"]
        self.assertEqual(counts["persisted-partial"], 2)
        self.assertEqual(counts["verification-budget"], 0)
        self.assertEqual(counts["other"], 0)
        self.assertNotIn(fixture.PRIVATE, json.dumps(window))

    def test_flattened_detail_with_all_wire_looking_fields_cannot_stand_in_for_missing_first_reply(self):
        doc = fixture.detail(True)
        doc["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        details, listing, boundary = self.retained(doc)
        wire = details.first_pages[fixture.RECORDING]
        self.assertIs(wire, doc)
        flattened = dict(details)
        self.assertEqual(json.dumps(details, sort_keys=True), json.dumps(flattened, sort_keys=True))
        self.save((flattened, listing, boundary))
        result = self.read()
        self.assertEqual(result["selection"], "observed")
        self.assertEqual(result["liveApi"], {"read": "unavailable", "capture": None})
        self.assertEqual(result["phaseEvidence"]["selectedRecovery"], "not-listed")

    def test_unbound_first_response_cursor_and_raw_marker_fields_are_rejected(self):
        wrong = fixture.paired.cursor_for(fixture.OTHER, fixture.RECORDING, 2)
        first = fixture.detail(True, next_cursor=wrong)
        first["events"][0].update(kind="recording_event_kind:request_update", symbol="http.request GET " + OFFICES, gap=None)
        second = fixture.detail(True, sequences=(3,), cursor=wrong)
        self.save(self.retained(first, second))
        self.assertEqual(self.read()["liveApi"], {"read": "rejected", "capture": None})
        path = self.phase_dir / "office-list-partial.json"
        selected = json.loads(path.read_text())
        selected["window"]["firstPageMarkers"] = fixture.PRIVATE
        path.write_text(json.dumps(selected))
        self.assertEqual(self.read(), {"selection": "rejected"})
