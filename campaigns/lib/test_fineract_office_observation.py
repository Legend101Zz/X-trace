"""Bounded one-office read evidence. These cases never create an application or open a network connection."""
import copy
import json
import unittest
from unittest.mock import Mock

import fineract_office_observation as observer
import test_fineract_first_partial_pair as fixture
import test_fineract_phase_evidence as stop_fixture
import xinstr
from installed_sinks import MAX_OUTPUT


class OfficeObservation(unittest.TestCase):
    def setUp(self):
        self.files = fixture.FineractFirstPartialPair()
        self.files.setUp()
        self.addCleanup(self.files.doCleanups)
        self.list = fixture.listing(True)
        self.before_page = dict(self.list, recordings=[])
        self.before = observer.inventory(fixture.PROJECT, [self.before_page])

    def sample(self, *replies, listing=None):
        rows = self.list if listing is None else listing
        client = Mock(deadline=None)
        client.get.side_effect = [(200, rows), *((200, page) for page in replies)]
        doc = xinstr.collect_api(client, self.files.capture / "live", fineract_phase=True, fineract_pair=True)
        self.assertTrue(doc["ok"])
        return observer.inventory(fixture.PROJECT, [rows]), doc

    def page(self, completion="partial", rid=fixture.RECORDING, root=observer.ROOT):
        page = fixture.detail(True, markers=["persisted_status:partial"] if completion == "partial" else [])
        page.update(recordingId=rid, completion=completion)
        page.update(outcome={"kind": "responded", "httpStatus": 200}, durationNs="100")
        page["events"][0].update(kind=observer.PREFIX + "request_update", symbol=root, gap=None)
        return page

    def test_single_partial_whole_and_first_wire_have_distinct_scopes(self):
        page = self.page()
        rid, public = observer.observe(self.before, *self.sample(page))
        self.assertEqual(rid, fixture.RECORDING)
        self.assertEqual(public["wholeEvents"], 2)
        self.assertEqual(public["gaps"], 1)
        self.assertEqual(public["gapReasons"]["queue_full"], 1)
        self.assertEqual(public["responses"], 0)
        self.assertIs(public["http200"], True)
        self.assertEqual(public["firstWirePage"]["capture"]["eventScope"], "retained-first-page")
        for value in (fixture.RECORDING, fixture.PROJECT, fixture.PRIVATE, observer.ROOT):
            self.assertNotIn(value, json.dumps(public))

    def test_complete_ordinary_read_is_an_observation(self):
        page = self.page("complete")
        page["events"][1].update(kind=observer.PREFIX + "response", gap=None)
        rid, public = observer.observe(self.before, *self.sample(page))
        self.assertEqual(rid, fixture.RECORDING)
        self.assertEqual(public["firstWirePage"]["capture"]["completion"], "complete")
        self.assertEqual(public["responses"], 1)
        self.assertEqual(public["gaps"], 0)

    def test_open_recording_remains_open(self):
        page = self.page("unavailable")
        page.update(outcome=None, capacity=None, durationNs=None)
        rid, result = observer.observe(self.before, *self.sample(page))
        self.assertEqual(rid, fixture.RECORDING)
        self.assertEqual(result["terminalMetadata"], "absent")
        self.assertIsNone(result["http200"])

    def test_preexisting_and_absent_ids_cannot_supply_the_new_read(self):
        current, doc = self.sample(self.page())
        self.assertEqual(observer.observe(current, current, doc), (None, {"selection": "not-observed"}))
        self.assertEqual(observer.observe(current, self.before, doc), (None, {"selection": "unbound"}))

    def test_two_matching_ids_and_an_unresolved_root_are_ambiguous(self):
        second = self.page(rid=fixture.OTHER)
        listing = dict(self.list, recordings=self.list["recordings"]+
                       [dict(self.list["recordings"][0], recordingId=fixture.OTHER)])
        current, doc = self.sample(self.page(), second, listing=listing)
        self.assertEqual(observer.observe(self.before, current, doc), (None, {"selection": "ambiguous"}))
        doc["details"][fixture.OTHER]["events"][0]["symbol"] = None
        self.assertEqual(observer.observe(self.before, current, doc), (None, {"selection": "ambiguous"}))

        for suffix in ("{resource}", "*", "**", ":resource"):
            with self.subTest(suffix=suffix):
                root = "http.request GET /fineract-provider/api/v1/" + suffix
                current, doc = self.sample(self.page(), self.page(rid=fixture.OTHER, root=root), listing=listing)
                self.assertEqual(observer.observe(self.before, current, doc), (None, {"selection": "ambiguous"}))

    def test_whole_census_includes_response_beyond_first_wire_page(self):
        page = self.page()
        cursor = fixture.paired.cursor_for(fixture.PROJECT, fixture.RECORDING, 2)
        page["nextCursor"] = cursor
        end = fixture.detail(True, sequences=(3,), cursor=cursor)
        end["events"][0].update(kind=observer.PREFIX + "response", gap=None)
        current, doc = self.sample(page, end, listing=fixture.listing(True, count="3", last="3"))
        _, summary = observer.observe(self.before, current, doc)
        self.assertEqual(summary["responses"], 1)
        self.assertEqual(summary["wholeEvents"], 3)
        self.assertEqual(summary["firstWirePage"]["capture"]["eventKinds"]["response"], 0)
        self.assertEqual(summary["firstWirePage"]["markerScope"], "withheld-across-pages")

    def test_mismatched_or_missing_first_page_and_list_range_are_rejected(self):
        current, doc = self.sample(self.page())
        pages = doc["details"].first_pages
        original = pages.pop(fixture.RECORDING)
        self.assertEqual(observer.observe(self.before, current, doc), (None, {"selection": "unbound"}))
        pages[fixture.RECORDING] = copy.deepcopy(original)
        pages[fixture.RECORDING]["events"][0]["sequence"] = "9"
        self.assertEqual(observer.observe(self.before, current, doc), (None, {"selection": "unbound"}))
        pages[fixture.RECORDING] = original
        wrong = observer.inventory(fixture.PROJECT, [fixture.listing(True, count="3", last="3")])
        self.assertEqual(observer.observe(self.before, wrong, doc), (None, {"selection": "unbound"}))

    def test_empty_wrong_project_truncated_and_extra_list_pages_rejected(self):
        for pages in ([], [dict(self.before_page, projectId=fixture.OTHER)],
                      [dict(self.list, nextAfter=fixture.RECORDING)], [self.list, self.list]):
            with self.subTest(pages=len(pages)), self.assertRaises(ValueError):
                observer.inventory(fixture.PROJECT, pages)

    def test_final_recovery_join_requires_project_and_identity_without_replacement(self):
        page = self.page()
        self.files.save_api((200, page))
        final = observer.after_stop(self.files.capture, fixture.PROJECT, fixture.RECORDING,
                                    stop_fixture.stop(fixture.OTHER), MAX_OUTPUT)
        self.assertEqual(final["recovery"], "not-listed")
        self.assertEqual(final["finalApiRead"], "whole-recording")
        final = observer.after_stop(self.files.capture, fixture.PROJECT, fixture.RECORDING,
                                    stop_fixture.stop(fixture.RECORDING, project=fixture.OTHER), MAX_OUTPUT)
        self.assertEqual(final["recovery"], "rejected")
        self.assertEqual(final["finalApiRead"], "whole-recording")

    def test_recovered_match_survives_missing_saved_final_read(self):
        final = observer.after_stop(self.files.capture, fixture.PROJECT, fixture.RECORDING,
                                    stop_fixture.stop(fixture.RECORDING), MAX_OUTPUT)
        self.assertEqual(final["recovery"], "listed")
        self.assertEqual(final["result"], "partial")
        self.assertEqual(final["finalApiRead"], "missing")
        self.assertIsNone(final["finalApi"])

    def scenario(self):
        import os
        import runpy
        import sys
        from pathlib import Path
        from unittest.mock import patch

        harness = Path(__file__).resolve().parents[1] / "java/fineract/harness"
        with patch.dict(os.environ, XTRACE_CAMPAIGN_ROOT=str(self.files.root)), \
             patch.object(sys, "path", [str(harness), *sys.path]):
            return runpy.run_path(str(harness / "run.py"))

    def test_reduced_workload_uses_only_the_original_authenticated_office_get(self):
        from unittest.mock import call

        scenario = self.scenario()
        context = Mock()
        context.http.return_value = {"status": 200, "text": '[{"id":1}]'}
        scenario["read_seeded_office_list"](context)
        self.assertEqual(context.http.call_args_list, [call("GET", observer.phase.OFFICE_LIST_ROUTE, headers=scenario["H"])])
        context.check.assert_called_once_with("authenticated office list contains seeded head office", True)
        context.reset_mock()
        context.http.return_value = {"status": 200, "text": '[{"id":2}]'}
        scenario["read_seeded_office_list"](context)
        context.check.assert_called_once_with("authenticated office list contains seeded head office", False)

    def test_original_seed_scenario_keeps_its_three_reads_and_assertions(self):
        from unittest.mock import call

        scenario = self.scenario()
        context = Mock()
        context.http.side_effect = [{"status": 200, "text": text} for text in ('[{"id":1}]', '{"id":1}', '[]')]
        context.db = {"seed-office": [["1", "head office"]]}
        scenario["s_seed_read"](context)
        base, headers = scenario["BASE"], scenario["H"]
        self.assertEqual(context.http.call_args_list, [call("GET", base + "/offices", headers=headers),
                         call("GET", base + "/offices/1", headers=headers),
                         call("GET", base + "/clients?limit=5", headers=headers, label="client list (empty tenant)")])
        self.assertEqual(context.check.call_args_list, [call("authenticated office list contains seeded head office", True),
                         call("office 1 readable", True), call("empty client list 200", True),
                         call("db has head office row", True)])
        context.sql.assert_called_once_with("seed-office", "select id::text,name from m_office order by id")
