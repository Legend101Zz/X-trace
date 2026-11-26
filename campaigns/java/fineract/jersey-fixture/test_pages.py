"""Malformed read pages must fail before they can qualify a real installed observation."""
import copy
import unittest

from pages import bound_cursor, detail_pages, list_pages, name

PROJECT = "00000000-0000-4000-8000-000000000001"
NEW = "00000000-0000-4000-8000-000000000003"
OLD = "00000000-0000-4000-8000-000000000002"
MISSING = object()


def shape(api, **fields):
    return {name(k, api): v for k, v in fields.items()}


def listing(api):
    def page(after, rid, nxt):
        row = shape(api, recording_id=rid, opened_at="2026-11-26T08:10:15.000000Z",
                    event_count="3", first_sequence="1", last_sequence="3")
        return shape(api, schema_version=3, project_id=PROJECT, limit=1, after=after, recordings=[row], next_after=nxt)
    return [page(None, NEW, NEW), page(NEW, OLD, None)]


def details(api):
    token = bound_cursor(PROJECT, NEW, 2)
    def page(sequences, cursor, nxt):
        return shape(api, schema_version=3, project_id=PROJECT, recording_id=NEW, limit=2, cursor=cursor,
                     next_cursor=nxt, first_sequence=sequences[0], last_sequence=sequences[-1],
                     events=[{"sequence": seq} for seq in sequences], completion="complete",
                     outcome={"kind": "responded", "httpStatus": 200}, incomplete_evidence=[])
    return [page(["1", "2"], None, token), page(["3"], token, None)]


def reader(docs):
    pages = iter(docs)
    return lambda cursor: next(pages)


def alter(doc, key, value):
    if value is MISSING:
        del doc[key]
    else:
        doc[key] = value


class PagesTest(unittest.TestCase):
    def test_both_shapes_follow_actual_next_values_and_complete_in_order(self):
        for api in (False, True):
            with self.subTest(api=api):
                listed = listing(api)
                fetched = []
                def fetch_list(after):
                    fetched.append(after)
                    return listed[len(fetched) - 1]
                ids, count = list_pages(fetch_list, api, PROJECT)
                self.assertEqual((list(ids), count, fetched), ([NEW, OLD], 2, [None, NEW]))
                pages = details(api)
                cursors = []
                def fetch_detail(cursor):
                    cursors.append(cursor)
                    return pages[len(cursors) - 1]
                detail, count = detail_pages(fetch_detail, api, PROJECT, NEW, 3, ("1", "3"))
                self.assertEqual(cursors, [None, pages[0][name("next_cursor", api)]])
                self.assertEqual(([e["sequence"] for e in detail["events"]], count), (["1", "2", "3"], 2))

    def assert_invalid(self, parse, docs):
        with self.assertRaises((ValueError, KeyError), msg="malformed page admitted"):
            parse(reader(docs))

    def test_list_identity_cursor_limit_and_continuation(self):
        for api in (False, True):
            base = listing(api)
            for page, key, value in (
                    (0, "after", MISSING), (1, "after", None), (1, "after", OLD),
                    (1, "project_id", OLD), (1, "project_id", MISSING), (1, "limit", True),
                    (0, "schema_version", MISSING), (1, "next_after", MISSING), (1, "next_after", ""),
                    (1, "next_after", 0), (1, "next_after", False), (0, "next_after", OLD),
                    (0, "recordings", []), (1, "recordings", []), (0, "recordings", base[0]["recordings"] * 2)):
                with self.subTest(api=api, page=page, key=key, value=value):
                    docs = copy.deepcopy(base)
                    alter(docs[page], name(key, api), value)
                    self.assert_invalid(lambda fetch: list_pages(fetch, api, PROJECT), docs)

    def test_list_rejects_duplicates_time_order_and_noncanonical_identifiers(self):
        for api in (False, True):
            for key, value in (("recording_id", NEW), ("recording_id", "bad"), ("recording_id", MISSING),
                               ("opened_at", "2026-11-26T08:10:16.000000Z"), ("event_count", "01"),
                               ("event_count", 3), ("opened_at", "invalid")):
                docs = listing(api)
                with self.subTest(api=api, key=key, value=value):
                    alter(docs[1]["recordings"][0], name(key, api), value)
                    self.assert_invalid(lambda fetch: list_pages(fetch, api, PROJECT), docs)
            docs = listing(api)
            docs[0]["recordings"][0][name("recording_id", api)] = OLD
            docs[0][name("next_after", api)] = docs[1]["after"] = OLD
            docs[1]["recordings"][0][name("recording_id", api)] = NEW
            self.assert_invalid(lambda fetch: list_pages(fetch, api, PROJECT), docs)

    def test_detail_project_recording_cursor_and_evidence_bound_on_every_page(self):
        for api in (False, True):
            for key, value in (("project_id", OLD), ("recording_id", OLD), ("recording_id", MISSING),
                               ("limit", True), ("limit", 1), ("cursor", None), ("cursor", MISSING),
                               ("next_cursor", MISSING), ("next_cursor", ""), ("next_cursor", 0),
                               ("outcome", None), ("incomplete_evidence", ["unknown"]), ("completion", MISSING),
                               ("first_sequence", MISSING), ("first_sequence", "2"), ("last_sequence", "4")):
                with self.subTest(api=api, key=key, value=value):
                    docs = details(api)
                    alter(docs[1], name(key, api), value)
                    self.assert_invalid(lambda fetch: detail_pages(fetch, api, PROJECT, NEW, 3, ("1", "3")), docs)

    def test_detail_order_canonical_sequence_and_total(self):
        for api in (False, True):
            for bad in ("1", "2", "03", "-1", "18446744073709551616", 3):
                with self.subTest(api=api, bad=bad):
                    docs = details(api)
                    docs[1]["events"][0]["sequence"] = bad
                    docs[1][name("first_sequence", api)] = docs[1][name("last_sequence", api)] = bad
                    self.assert_invalid(lambda fetch: detail_pages(fetch, api, PROJECT, NEW, 3, ("1", "3")), docs)
            self.assert_invalid(lambda fetch: detail_pages(fetch, api, PROJECT, NEW, 4, ("1", "3")), details(api))

    def test_detail_endpoints_must_match_the_independent_listing_even_at_equal_count(self):
        for api in (False, True):
            for endpoints in (("0", "3"), ("1", "4")):
                with self.subTest(api=api, endpoints=endpoints):
                    docs = listing(api)
                    row = docs[0]["recordings"][0]
                    row[name("first_sequence", api)], row[name("last_sequence", api)] = endpoints
                    listed, _ = list_pages(reader(docs), api, PROJECT)
                    _, count, first, last = listed[NEW]
                    self.assertEqual(count, 3)
                    self.assert_invalid(lambda fetch: detail_pages(fetch, api, PROJECT, NEW, count,
                                                                   (first, last)), details(api))
            listed = listing(api)[0]
            listed[name("next_after", api)] = None
            listed["recordings"][0].update(shape(api, event_count="0", first_sequence=None, last_sequence=None))
            rows, _ = list_pages(reader([listed]), api, PROJECT)
            _, count, first, last = rows[NEW]
            empty = details(api)[0]
            empty.update(shape(api, events=[], first_sequence=None, last_sequence=None, next_cursor=None))
            result, pages = detail_pages(reader([empty]), api, PROJECT, NEW, count, (first, last))
            self.assertEqual((result["events"], pages), ([], 1))
            listed["recordings"][0][name("last_sequence", api)] = "0"
            self.assert_invalid(lambda fetch: list_pages(fetch, api, PROJECT), [listed])

    def test_negative_filter_recording_requires_complete_capture(self):
        from observation import judge
        detail = {"events": [{"kind": "recording_event_kind:request_update", "symbol": "http.request GET",
                              "interaction": {"driver": "servlet"}},
                             {"kind": "recording_event_kind:response", "interaction": {"driver": "servlet"}}],
                  "completion": "complete", "incompleteEvidence": [],
                  "outcome": {"kind": "responded", "httpStatus": 403}}
        self.assertEqual(judge({NEW: detail}, "3.1.10"), 1)
        for change in ({"completion": "partial"}, {"incompleteEvidence": ["gap_event_sequence:3"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                judge({NEW: {**detail, **change}}, "3.1.10")

    def test_detail_next_cursor_must_bind_project_id_recording_id_and_last_sequence(self):
        for api in (False, True):
            for token in ("v1.invalid", bound_cursor(OLD, NEW, 2), bound_cursor(PROJECT, OLD, 2),
                          bound_cursor(PROJECT, NEW, 1)):
                with self.subTest(api=api, token=token):
                    docs = details(api)
                    docs[0][name("next_cursor", api)] = docs[1]["cursor"] = token
                    self.assert_invalid(lambda fetch: detail_pages(fetch, api, PROJECT, NEW, 3, ("1", "3")), docs)
            docs = details(api)
            docs[1][name("next_cursor", api)] = docs[1]["cursor"]
            self.assert_invalid(lambda fetch: detail_pages(fetch, api, PROJECT, NEW, 3, ("1", "3")), docs)
