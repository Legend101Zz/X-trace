"""Hosted-only regression coverage for the development proof's evidence boundaries."""
from collections import Counter
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from installed import local_transport, owned_id, starter_bytes
from installed_evidence import EvidenceError, capture, detail, keys, pages, workload


def rows(documents):
    replies = iter(documents)
    return lambda _cursor: next(replies)


def event(symbol, event_id, parent=None):
    return {"kind": "recording_event_kind:frame_enter", "symbol": symbol,
            "eventId": event_id, "parentEventId": parent}


def recording(status=200, completion="complete"):
    return {"completion": completion, "outcome": {"kind": "responded", "httpStatus": status},
            "events": [event("node:http.Server.request", "root"), event("express.handler:private-marker", "handler", "root")]}


class InstalledMedusaEvidence(unittest.TestCase):
    def test_local_transport_accepts_only_finite_consistent_counts(self):
        report = {"attempted": 46, "ownedResponses": 45, "refusedRedirects": 1, "otherFailures": 0}
        self.assertEqual(local_transport(report), report)
        for change in ({"raw": "private marker"}, {"attempted": 45}, {"otherFailures": True}):
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                local_transport(dict(report, **change))

    def test_supervisor_reaps_an_adopted_child_in_its_own_session(self):
        # Isolate the subreaper from the unittest worker and its other tests.
        source = """
import os
import subprocess
import sys
from installed_process import contain_children, verify_children_gone
contain_children()
read_end, write_end = os.pipe()
launcher = (
    "import subprocess,sys; fd=int(sys.argv[1]); "
    "subprocess.Popen([sys.executable, '-B', '-c', "
    "'import os,sys; os.read(int(sys.argv[1]), 1)', sys.argv[1]], "
    "pass_fds=(fd,), start_new_session=True)"
)
try:
    subprocess.run([sys.executable, "-B", "-c", launcher, str(read_end)],
                   pass_fds=(read_end,), check=True, timeout=5)
    try:
        verify_children_gone()
    except TimeoutError:
        pass
    else:
        raise AssertionError("adopted live child did not make cleanup fail")
finally:
    os.close(write_end)
    os.close(read_end)
    verify_children_gone()
"""
        subprocess.run([sys.executable, "-B", "-c", source], check=True, timeout=20, cwd=Path(__file__).parent)

    def test_late_private_cid_file_recovers_the_exact_docker_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cid = root / "postgres.cid"
            self.assertIsNone(owned_id(cid))
            cid.write_text("a" * 64 + "\n")
            self.assertEqual(owned_id(cid), "a" * 64)
            alias = root / "symlink.cid"
            alias.symlink_to(cid)
            self.assertIsNone(owned_id(alias))
            cid.write_text("not-an-owned-identity")
            self.assertIsNone(owned_id(cid))

    def test_prepared_inventory_binds_provider_bytes_and_rejects_external_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            prepared.mkdir()
            manifest = prepared / "locked.js"
            manifest.write_text("first")
            link = prepared / "linked.js"
            link.symlink_to("locked.js")
            expected = starter_bytes(prepared)
            manifest.write_text("other")
            self.assertNotEqual(starter_bytes(prepared), expected)
            link.unlink()
            link.symlink_to(root / "outside")
            with self.assertRaises(EvidenceError):
                starter_bytes(prepared)

    def test_readback_rejects_empty_advancing_page_and_repeated_cursor(self):
        for docs in ([{"items": [], "next": "a"}, {"items": [], "next": None}],
                     [{"items": [{}], "next": "a"}, {"items": [{}], "next": "a"}]):
            with self.subTest(docs=docs), self.assertRaises(EvidenceError):
                list(pages(rows(docs), "items", "next", limit=20, max_rows=40))

    def test_inventory_rejects_same_uuid_in_two_pages(self):
        rid = "018f0000-0000-7000-8000-000000000001"
        docs = [{"items": [{"id": rid}], "next": "a"}, {"items": [{"id": rid}], "next": None}]
        with self.assertRaises(EvidenceError):
            keys(pages(rows(docs), "items", "next", limit=20, max_rows=40), "items", "id")

    def test_paged_detail_refuses_a_different_terminal_outcome(self):
        rid = "018f0000-0000-7000-8000-000000000001"
        docs = [{"recordingId": rid, "completion": "complete", "outcome": {"httpStatus": value}, "events": []}
                for value in (200, 400)]
        with self.assertRaises(EvidenceError):
            detail(docs, rid, api=True)

    def test_readiness_never_masks_missing_or_wrong_outcome(self):
        details = {"ready": recording(), "work": recording(401)}
        self.assertTrue(capture(details, "ready", Counter({401: 1}))["passed"])
        self.assertFalse(capture(details, "ready", Counter({200: 1, 401: 1}))["passed"])
        details["work"]["outcome"] = None
        self.assertFalse(capture(details, "ready", Counter({401: 1}))["passed"])

    def test_bad_root_parent_partial_and_handler_absence_remain_red(self):
        for problem in ("orphan", "partial", "handler", "duplicate"):
            details = {"ready": recording(), "work": recording()}
            row = details["work"]
            if problem == "orphan":
                row["events"][1]["parentEventId"] = "missing"
            elif problem == "partial":
                row["completion"] = "partial"
            elif problem == "handler":
                row["events"].pop()
            else:
                row["events"].append(event("node:http.Server.request", "other-root"))
            with self.subTest(problem=problem):
                self.assertFalse(capture(details, "ready", Counter({200: 1}))["passed"])

    def test_private_fields_never_enter_workload_or_capture_projection(self):
        expected = ["concurrent-writes-and-reads"] + [f"scenario-{i}" for i in range(10)]
        report = {"project": "medusa", "scenarioCount": 11, "scenarios": [
            {"id": name, "result": "passed", "semanticEffectFingerprint": "a" * 64,
             "requests": [{"status": 200, "unused": "private-marker"}]} for name in expected]}
        work, http = workload(report, copy.deepcopy(report), expected)
        self.assertEqual(work["matched"], 11)
        trace = capture({"ready": recording(), **{str(i): recording() for i in range(11)}}, "ready", http)
        projected = json.dumps({"workload": work, "capture": trace})
        for marker in ("private-marker", "a" * 64, "node:http"):
            self.assertNotIn(marker, projected)
        changed = copy.deepcopy(report)
        changed["scenarios"][0]["requests"][0]["status"] = 0
        rejected, _ = workload(report, changed, expected)
        self.assertEqual(rejected["matched"], 10)
        self.assertEqual(rejected["transportFailures"], 1)
