"""Failure/readiness regressions; only the hosted real driver proves capture."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "java/jhipster/harness/focused_fixture.py"
SPEC = importlib.util.spec_from_file_location("jhipster_focused_fixture", PATH)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FocusedFixture(unittest.TestCase):
    def test_owned_bound_port_signal_is_saved_privately_without_readiness_http(self):
        process = mock.Mock(stdout=io.BytesIO(b"Tomcat started on port 12345 (http)\n"))
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(fixture.xcamp, "http_request") as http:
            log = Path(tmp) / "owned.stdout"
            port = fixture.wait_port(process, log, fixture.time.monotonic() + 1)
            self.assertEqual(port, 12345)
            self.assertEqual(log.read_bytes(), b"Tomcat started on port 12345 (http)\n")
        http.assert_not_called()

    def test_early_process_end_or_missing_startup_signal_is_not_ready(self):
        for content, code in ((b"private log without a bound port\n", None),
                              (b"Tomcat started on port 12345 (http)\n", 1)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                process = mock.Mock(stdout=io.BytesIO(content))
                process.poll.return_value = code
                with self.assertRaises(ValueError):
                    fixture.wait_port(process, Path(tmp) / "owned.stdout", fixture.time.monotonic() + 1)

    def test_api_read_failure_is_terminal_and_clears_live_deadline(self):
        client = mock.Mock()
        fail = {"ok": False, "details": {}, "reason": "private response and path"}
        with mock.patch.object(fixture.xinstr, "collect_api", return_value=fail) as collect:
            with self.assertRaises(ValueError):
                fixture.read_until(client, Path("unused"), lambda api: True, fixture.time.monotonic() + 1)
        self.assertEqual(collect.call_count, 1)
        self.assertIsNone(client.deadline)

    def test_native_page_comparison_rejects_cli_identity_cursor_and_event_disagreement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "post-stop-api"
            private.mkdir()
            logs = root / "sinks/cli"
            logs.mkdir(parents=True)
            events = [{"sequence": "2", "kind": "recording_event_kind:request_update", "symbol": "http.request POST /orders", "gap": None},
                      {"sequence": "7", "kind": "recording_event_kind:response", "gap": None}]
            rid = "private-recording"
            detail = {"recordingId": rid, "events": events, "nextCursor": None, "_verifiedDetailPages": 2,
                      "_allDetailMarkerListsEmpty": True}
            (private / f"recording-{rid}.json").write_text(json.dumps(detail))
            listed = {"recordingId": rid, "eventCount": "2", "firstSequence": "2", "lastSequence": "7"}
            api = {"recordings": [listed], "details": {rid: detail}}
            first = {"recording_id": rid, "limit": 1, "cursor": None, "next_cursor": "private-next",
                     "events": events[:1], "incomplete_evidence": []}
            second = {**first, "cursor": "private-next", "next_cursor": None, "events": events[1:]}
            (logs / "detail-000-00.stdout").write_text(json.dumps(first))
            path = logs / "detail-000-01.stdout"
            path.write_text(json.dumps(second))
            self.assertEqual(fixture.compare_mapped_pages(root, api, [rid], 1),
                             {"apiPages": 2, "cliPages": 2, "comparedEvents": 2})
            # In both readers the same interior event can disappear while the
            # remaining request and response still agree, including their endpoints.
            for inventory in ({**listed, "eventCount": "3"}, {**listed, "firstSequence": "1"},
                              {**listed, "lastSequence": "8"}, {**listed, "recordingId": "other"}):
                with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                    fixture.compare_mapped_pages(root, {**api, "recordings": [inventory]}, [rid], 1)
            for change in ({"recording_id": "other"}, {"cursor": "other"}, {"next_cursor": "unfinished"},
                           {"events": events[:1]}, {"events": [{**events[1], "kind": "unknown"}]},
                           {"incomplete_evidence": ["persisted_status:partial"]}):
                with self.subTest(change=change):
                    path.write_text(json.dumps({**second, **change}))
                    with self.assertRaises(ValueError):
                        fixture.compare_mapped_pages(root, api, [rid], 1)

    def test_native_comparison_needs_explicit_empty_api_markers_on_every_page(self):
        rid = "private-recording"
        listing = {"recordingId": rid, "eventCount": "2", "firstSequence": "2", "lastSequence": "7"}
        events = [{"sequence": "2", "kind": "recording_event_kind:request_update",
                   "symbol": "http.request POST /orders", "gap": None},
                  {"sequence": "7", "kind": "recording_event_kind:response", "gap": None}]
        def page(i):
            return {"recordingId": rid, "limit": 1, "cursor": None if i == 0 else "next",
                    "nextCursor": "next" if i == 0 else None, "events": [events[i]],
                    "incompleteEvidence": [], "_allDetailMarkerListsEmpty": True}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            logs = root / "sinks/cli"
            logs.mkdir(parents=True)
            for i in range(2):
                doc = page(i)
                row = {"recording_id": rid, "limit": 1, "cursor": doc["cursor"],
                       "next_cursor": doc["nextCursor"], "events": doc["events"], "incomplete_evidence": []}
                (logs / f"detail-000-{i:02d}.stdout").write_text(json.dumps(row))
            for field in ({"incompleteEvidence": []}, {"incompleteEvidence": ["verification_budget_exceeded"]},
                          {}, {"incompleteEvidence": None}, {"incompleteEvidence": "unknown"}):
                with self.subTest(field=field):
                    final = page(1)
                    del final["incompleteEvidence"]
                    final.update(field)
                    client = mock.Mock()
                    client.get.side_effect = [(200, {"recordings": [listing], "nextAfter": None}),
                                              (200, page(0)), (200, final)]
                    api = fixture.xinstr.collect_api(client, root / "post-stop-api", verified_detail_limit=1)
                    self.assertTrue(api["ok"])
                    if field.get("incompleteEvidence") == []:
                        self.assertEqual(fixture.compare_mapped_pages(root, api, [rid], 1)["comparedEvents"], 2)
                    else:
                        with self.assertRaises(ValueError):
                            fixture.compare_mapped_pages(root, api, [rid], 1)

    def test_admission_failure_publishes_only_fixed_unreached_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / "public"
            private = "private-root-token"
            with mock.patch.object(fixture.installed, "prepare_root", side_effect=ValueError(private)), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                code = fixture.main(["--private-root", str(root / private), "--archive", str(root / private),
                                     "--source-sha", private, "--package-sha256", private,
                                     "--java", str(root / private), "--fixture", str(root / private),
                                     "--public-out", str(public)])
            raw = (public / "summary.json").read_text()
            summary = json.loads(raw)
            self.assertEqual(code, 1)
            self.assertEqual(summary["status"], "failed")
            self.assertEqual(set(summary["checks"].values()), {"unreached"})
            self.assertIsNone(summary["inventory"])
            self.assertIsNone(summary["cli"])
            self.assertNotIn(private, raw + output.getvalue())
            self.assertNotIn(str(root), raw + output.getvalue())


if __name__ == "__main__":
    unittest.main()
