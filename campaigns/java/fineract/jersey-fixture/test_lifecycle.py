"""Finite lifecycle projections never infer terminal evidence or discard a real gap."""
from copy import deepcopy
import unittest

from unittest.mock import patch

from lifecycle import after_stop, finite, APPLY, SERVICE, require_on_time, require_prefix_links, require_preserved_prefix, resource_enter_observed
from test_pages import NEW, PROJECT, details


class LifecycleTest(unittest.TestCase):
    def detail(self):
        return {"status": "recording", "completion": "unavailable", "outcome": None, "capacity": None,
                "durationNs": None, "dropCountsByPriority": {}, "incompleteEvidence": [], "events": []}

    def test_open_prefix_remains_unavailable(self):
        report = finite(self.detail())
        self.assertEqual(report["completion"], "unavailable")
        self.assertEqual(report["outcome"], "unavailable")
        self.assertFalse(report["durationPresent"])
        self.assertFalse(report["capacityPresent"])
        self.assertEqual(report["responses"], 0)

    def test_responded_partial_retains_gap_and_drop(self):
        detail = self.detail()
        detail.update(status="partial", completion="partial", outcome={"kind": "responded", "httpStatus": 200},
                      durationNs="12", dropCountsByPriority={"ordinary": "1"},
                      events=[{"kind": "recording_event_kind:response"}, {"kind": "recording_event_kind:gap"}])
        report = finite(detail)
        self.assertEqual((report["completion"], report["responses"], report["gaps"], report["positiveDropBuckets"]),
                         ("partial", 1, 1, 1))

    def test_nonfinite_or_malformed_projection_fails(self):
        for field, value in (("status", "private"), ("outcome", {"kind": "private"}),
                             ("durationNs", "-1"), ("dropCountsByPriority", {"private": "invalid"})):
            detail = self.detail()
            detail[field] = value
            with self.assertRaises(ValueError):
                finite(detail)

    def test_owned_stop_requires_same_identity_terminal_and_events(self):
        before = self.detail()
        before.update(status="complete", completion="complete", durationNs="1",
                      outcome={"kind": "responded", "httpStatus": 200}, events=[{"kind": "recording_event_kind:response"}])
        progress = {"lifecycle": {}}
        after_stop(("selected", before), {"selected": deepcopy(before)}, progress)
        self.assertEqual(progress["lifecycle"]["afterStop"]["completion"], "complete")
        with self.assertRaises(ValueError):
            after_stop(("selected", before), {"different": deepcopy(before)}, progress)
        for field, value in (("durationNs", "2"), ("events", []), ("completion", "partial")):
            after = deepcopy(before)
            after[field] = value
            with self.assertRaises(ValueError):
                after_stop(("selected", before), {"selected": after}, progress)

    def test_prefix_keeps_recorded_facts_when_navigation_gains_a_target(self):
        before = {"sequence": "1", "symbol": "Items.lifecycle", "navigation": {"next": None},
                  "depth": None, "frameId": None, "parentFrameId": None, "asyncParentFrameId": None}
        frame_id = "00000000-0000-7000-8000-000000000001"
        later = {**before, "navigation": {"next": "target"}, "frameId": frame_id, "depth": 1}
        require_preserved_prefix([before], [later, {"sequence": "2"}])
        for changed in ([], [{**later, "sequence": "2"}], [{**later, "symbol": None}]):
            with self.assertRaises(ValueError):
                require_preserved_prefix([before], changed)

    def test_open_discovery_validates_pages_without_assuming_a_final_count(self):
        docs = details(True)
        for index, page in enumerate(docs):
            page.update(completion="unavailable", outcome=None, incompleteEvidence=[f"durable_tail_pending:1..{2 + index}"])
            for event in page["events"]:
                event.update(kind="recording_event_kind:frame_enter", symbol="other")
        docs[-1]["events"][-1]["symbol"] = "Items.lifecycle"
        def read(rid, cursor):
            self.assertEqual(rid, NEW)
            return docs[0 if cursor is None else 1]
        self.assertTrue(resource_enter_observed(read, PROJECT, NEW))
        docs[-1]["events"][-1]["symbol"] = "other"
        self.assertFalse(resource_enter_observed(read, PROJECT, NEW))
        docs[0]["nextCursor"] = "invalid"
        with self.assertRaises(ValueError):
            resource_enter_observed(read, PROJECT, NEW)

    def test_observation_finishing_after_deadline_fails(self):
        with patch("lifecycle.time.monotonic", return_value=15.01), self.assertRaises(ValueError):
            require_on_time(15.0)

    def test_known_frame_metadata_cannot_change_or_disappear(self):
        first_id = "00000000-0000-7000-8000-000000000001"
        before = {"depth": 2, "frameId": first_id, "parentFrameId": None, "asyncParentFrameId": None, "navigation": {}}
        for key, value in (("depth", True), ("depth", 3), ("frameId", None),
                           ("frameId", "00000000-0000-7000-8000-000000000002"), ("parentFrameId", "invalid")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                require_preserved_prefix([before], [{**before, key: value}])

    def test_parent_links_require_recorded_distinct_event_ids(self):
        frames = {SERVICE: {"eventId": "service"}, APPLY: {"eventId": "apply", "parentEventId": "service"},
                  "Items.lifecycle": {"eventId": "resource", "parentEventId": "apply"}}
        require_prefix_links(frames)
        for value in (None, "", "apply"):
            changed = deepcopy(frames)
            changed[SERVICE]["eventId"] = changed[APPLY]["parentEventId"] = value
            with self.assertRaises(ValueError):
                require_prefix_links(changed)
