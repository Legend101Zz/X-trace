import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.qa import lane_run  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_cargo_failures_are_allowlisted(self):
        text = "\n".join([
            "test a::b::ok ... ok",
            "test a::b::bad ... FAILED",
            "test weird name with /home/x/secret ... FAILED",
            "test result: FAILED. 3 passed; 2 failed; 1 ignored; 0 measured",
        ])
        r = lane_run.parse_output(text)
        self.assertEqual(r["failingTests"], ["a::b::bad"])
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (3, 2, 1))

    def test_unittest_counts(self):
        r = lane_run.parse_output("Ran 23 tests in 0.2s\n\nFAILED (failures=2, errors=1)")
        self.assertEqual((r["passed"], r["failed"]), (20, 3))
        r = lane_run.parse_output("Ran 5 tests in 0.2s\n\nOK")
        self.assertEqual((r["passed"], r["failed"]), (5, 0))

    def test_gradle_failure_name(self):
        r = lane_run.parse_output("com.example.FooTest > doesThing() FAILED")
        self.assertEqual(r["failingTests"], ["FooTest::doesThing"])

    def test_invalid_names_dropped_and_counted(self):
        r = lane_run.parse_output("test ../../etc/passwd ... FAILED")
        self.assertEqual(r["failingTests"], [])
        self.assertEqual(r["droppedInvalidNames"], 1)

    def test_truncation(self):
        text = "\n".join(f"test t::n{i} ... FAILED" for i in range(40))
        r = lane_run.parse_output(text)
        self.assertEqual(len(r["failingTests"]), 32)
        self.assertEqual(r["failingTruncated"], 8)


class CheckoutFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.checkout = pathlib.Path(temporary.name)
        # first/second are declared in a.rs/b.rs below. Keep this fixture's
        # positive attribution cases unique; duplicate binaries have regressions.
        names = ["fails", "journey", "completed", "waiting", "also_waiting",
                 "done", "bad", "skip", "old", *[f"case{i}" for i in range(40)]]
        self.sources = {
            "crates/example/tests/journey.rs": "\n" * 40 + "\n".join(
                f"#[test]\nfn {name}() {{}}" for name in names),
            "crates/a.rs": "#[test]\nfn first() {}\n",
            "crates/b.rs": "#[test]\nfn second() {}\n",
            "adapters/java/tests/HttpTest.java": "class HttpTest {\n@Test\nvoid finalStatus() {}\n}\n" + "\n" * 90,
            "adapters/java/tests/FooTest.java": "class FooTest {\n" + "\n".join(
                f"@Test\nvoid {name}() {{}}" for name in ("check", "done", "waiting", "skip")) + "\n}\n",
            "web/app/src/example.test.ts": 'test("checkout JS test", () => {});\n',
            "tools/qa/test_example.py": "class ExampleTests:\n    def test_example(self): pass\n",
            "crates/xtrace-private-storage/src/admission.rs": (
                'pub enum PrivateStorageError {\n#[error("private storage is unavailable: {0}")]\n'
                'Admission(AdmissionFailure), Unavailable, InvalidName, AlreadyExists, Operation,\n}\n'),
            "crates/xtrace-private-storage/src/diagnostic.rs": (
                "pub enum AdmissionOperation { Deadline, WaitAclProbe, NamedMetadata, OwnershipAndMode, AclState, }\n"
                "pub(crate) enum AdmissionSite { Snapshot, ProbeState, RecheckAcl, }\n"
                "pub(crate) enum ListingRefusal { NotChecked, InheritedAllow, Header, }\n"
                "pub(crate) enum AdmissionObject { File, Directory, Other, }\n"
                "mod ci { mod tests { #[test]\n"
                "fn contextual_record_contains_only_fixed_categories_and_a_difference_mask() {} } }\n"),
            "crates/xtrace-private-storage/src/caller.rs": (
                "pub enum AdmissionCaller { Append, JournalPublish, Read, }\n"),
        }
        for name, source in self.sources.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.metadata = lane_run.CheckoutMetadata(self.sources)
        patcher = mock.patch.object(lane_run, "_checkout_metadata", return_value=self.metadata)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def diagnostic(thread="fails", **fields):
        return {"thread": thread, "error": "Admission", "operation": "Deadline",
                "kind": None, "errno": None, **fields}

    def records(self, *records, metadata=None, index=None):
        directory = self.checkout / "ci-diag"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "private-storage.jsonl"
        path.write_text("".join(json.dumps(record) + "\n" for record in records))
        path.chmod(0o600)
        return lane_run._ci_diagnostics(directory, metadata or self.metadata,
                                        lane_run.CANARY_INDEX if index is None else index)

    def assert_facts_only(self, row):
        fields = {"test", "location", "kind", "withheldLines", "category", "panicSites"}
        if row["test"] == lane_run.UNVERIFIED:
            fields.add("testUnverifiedReason")
            self.assertIn(row["testUnverifiedReason"], {reason.value for reason in lane_run.UnverifiedReason})
        self.assertEqual(set(row), fields)
        self.assertIn(row["kind"], {"assertion", "panic", "timeout", "exit", "unknown"})
        self.assertLessEqual(len(row["category"]), lane_run.MAX_CATEGORIES)
        self.assertEqual(len(row["category"]), len(set(row["category"])))
        for category in row["category"]:
            if type(category) is int:
                self.assertTrue(1 <= category <= 200)
            else:
                self.assertIn(category, self.metadata.diagnostic_variants | lane_run.IO_ERROR_KINDS)
        self.assertLessEqual(len(row["panicSites"]), lane_run.MAX_PANIC_SITES)
        for site in row["panicSites"]:
            self.assertEqual(site, self.metadata.location(site, lane_run.CANARY_INDEX))
        self.assertIsInstance(row["withheldLines"], int)
        self.assertGreaterEqual(row["withheldLines"], 0)
        self.assertLessEqual(len(lane_run._encoded(row)), lane_run.MAX_EXCERPT_BYTES)


class FailureDetailsTests(CheckoutFixture):
    @staticmethod
    def cargo(name="journey::fails", message="assertion `left == right` failed\n  left: 1\n right: 2",
              site="crates/example/tests/journey.rs:42:7", thread_id=None, footer=True):
        tid = f" ({thread_id})" if thread_id is not None else ""
        text = (f"test {name} ... FAILED\n\nfailures:\n\n---- {name} stdout ----\n"
                f"thread '{name}'{tid} panicked at {site}:\n{message}\n")
        if footer:
            text += (f"note: run with RUST_BACKTRACE=1\n\nfailures:\n    {name}\n"
                     "test result: FAILED. 0 passed; 1 failed; 0 ignored\n")
        return text

    def test_cargo_captured_failure_has_only_verified_facts_and_line_counts(self):
        detail = lane_run.failure_details(self.cargo(), False)
        row = detail["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["location"], row["kind"]),
                         ("fails", lane_run.UNVERIFIED, "exit"))
        self.assertEqual(row["withheldLines"], 8)
        self.assertEqual(len(detail["failures"]), 2)
        self.assertEqual(detail["failures"][1]["test"], lane_run.UNVERIFIED)
        self.assertEqual(detail["failures"][1]["panicSites"], [])
        self.assertNotIn("left == right", json.dumps(detail))

    def test_cargo_nocapture_multiple_panics_withhold_sites_and_owners(self):
        text = ("unrelated stdout\n"
                "thread 'first' panicked at crates/a.rs:1:2:\nfirst assertion\n"
                "test first ... FAILED\n"
                "thread 'second' panicked at crates/b.rs:2:4:\nsecond assertion\n"
                "test second ... FAILED\n")
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["test"], rows[0]["location"], rows[0]["panicSites"], rows[0]["category"]),
                         (lane_run.UNVERIFIED, lane_run.UNVERIFIED, [], []))
        self.assertEqual(rows[0]["testUnverifiedReason"], "ambiguous-panic-block")
        self.assert_facts_only(rows[0])
        for value in ("first assertion", "second assertion", "first", "second", "crates/a.rs", "crates/b.rs"):
            self.assertNotIn(value, json.dumps(rows))

    def test_private_storage_renderings_in_panic_text_never_supply_categories(self):
        cases = [
            ('admit private scratch: Admission(AdmissionFailure { operation: WaitAclProbe, '
             'kind: Some(PermissionDenied), raw_os_error: Some(13) })',
             ["Admission", "WaitAclProbe", "PermissionDenied", 13]),
            ('write: Bootstrap("private storage is unavailable: operation=Deadline '
             'kind=Some(TimedOut) raw_os_error=Some(60)")', ["Deadline", "TimedOut", 60]),
            ('parent: Admission(AdmissionFailure { operation: OwnershipAndMode, '
             'kind: None, raw_os_error: None })', ["Admission", "OwnershipAndMode"]),
            ('AdmissionFailure { operation: NamedMetadata, kind: None, raw_os_error: None }',
             ["NamedMetadata"]),
        ]
        for message, _ in cases:
            with self.subTest(message=message):
                row = lane_run.failure_details(self.cargo(message=message, footer=False), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertEqual(row["category"], [])
                self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])

    def test_categories_withhold_paths_values_unknown_identifiers_and_other_numbers(self):
        message = ('Admission(AdmissionFailure { operation: NamedMetadata, kind: Some(PermissionDenied), '
                   'raw_os_error: Some(13) })\n'
                   'path=/private/Deadline/Unavailable customer-731 balance: 42 UnknownDiagnostic 999999\n'
                   'raw_os_error: Some(999999) raw_os_error: Some(-13) raw_os_error: Some(0)\n'
                   'raw_os_error: Some(201) raw_os_error: Some(013) raw_os_error: Some(13.5)')
        row = lane_run.failure_details(self.cargo(message=message, footer=False), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["category"], [])
        for value in ("/private", "Deadline", "Unavailable", "customer-731", "balance", "42",
                      "UnknownDiagnostic", "999999", "201", "013", "13.5"):
            self.assertNotIn(value, json.dumps(row["category"]))

    def test_errno_boundaries_and_category_count_are_bounded_and_deduplicated(self):
        records = self.records(*(self.diagnostic(errno=errno) for errno in (1, 200, 1)),
                               *(self.diagnostic(kind=kind) for kind in sorted(lane_run.IO_ERROR_KINDS)))
        detail = lane_run.failure_details(self.cargo(name="fails"), False, diagnostic_records=records)
        self.assert_facts_only(detail["failures"][0])
        self.assertEqual(detail["failures"][0]["category"], [])
        row = detail["observedDiagnostics"][0]
        self.assertEqual((row["test"], row["relevance"]), ("fails", "unknown"))
        self.assertEqual(row["category"][:4], ["Admission", "Deadline", 1, 200])
        self.assertEqual(len(row["category"]), lane_run.MAX_CATEGORIES)

    def test_duplicate_test_names_across_binaries_cannot_attribute_observations(self):
        text = ("running 1 test\ntest first ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored\n"
                "running 1 test\ntest first ... FAILED\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored\n")
        detail = lane_run.failure_details(text, False, diagnostic_records=self.records(self.diagnostic("first")))
        self.assertEqual(detail["observedDiagnostics"], [{
            "test": lane_run.UNVERIFIED, "relevance": "unknown",
            "thread": "first",
            "testUnverifiedReason": "diagnostic-thread-ambiguous", "category": ["Admission", "Deadline"]}])
        self.assertEqual(detail["failures"][0]["category"], [])

    def test_colliding_values_paths_and_errno_prose_are_not_diagnostics(self):
        messages = [
            "Deadline Admission OwnershipAndMode PermissionDenied 13 42",
            "captured value: Deadline",
            "/private/éDeadline /private/éPermissionDenied /private/Deadline",
            "captured raw_os_error=42 raw_os_error: Some(13) raw_os_error=Some(60)",
            "operation=Deadline", "kind=Some(TimedOut)",
            "operation=Deadline kind=Some(TimedOut)",
            "operation=Admission kind=None raw_os_error=None",
            "operation=UnknownOperation kind=None raw_os_error=None",
            "operation=Deadline kind=Some(UnknownKind) raw_os_error=Some(13)",
        ]
        for errno in ("0", "201", "999999", "013", "-13", "13.5", "42"):
            # A bare number is never the Debug rendering of Option<i32>.
            value = errno if errno == "42" else f"Some({errno})"
            messages.extend([
                f"operation=Deadline kind=None raw_os_error={value}",
                "Admission(AdmissionFailure { operation: Deadline, kind: None, "
                f"raw_os_error: {value} }})",
            ])
        for prefix, suffix in (("é", ""), ("/private/é", ""), ("", "é"), ("", "/file")):
            messages.extend([
                prefix + "operation=Deadline kind=None raw_os_error=None" + suffix,
                prefix + "AdmissionFailure { operation: Deadline, kind: None, raw_os_error: None }" + suffix,
            ])
        for message in messages:
            with self.subTest(message=message):
                row = lane_run.failure_details(self.cargo(message=message, footer=False), False)["failures"][0]
                self.assertEqual(row["category"], [])
                self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])
                self.assert_facts_only(row)

    def test_complete_rendering_in_surrounding_prose_is_withheld(self):
        message = ("Deadline PermissionDenied 42 raw_os_error=Some(99) before: "
                   "Admission(AdmissionFailure { operation: OwnershipAndMode, kind: None, raw_os_error: None })"
                   " after TimedOut 13 raw_os_error: Some(60)")
        row = lane_run.failure_details(self.cargo(message=message, footer=False), False)["failures"][0]
        self.assertEqual(row["category"], [])
        self.assert_facts_only(row)

    def test_footer_shaped_message_lines_do_not_prove_a_single_line_message(self):
        for continuation in ("note: run with a captured value", "test first ... FAILED", "failures:"):
            text = ("test first ... FAILED\n---- first stdout ----\n"
                    "thread 'first' panicked at crates/a.rs:1:2:\n"
                    f"captured prose\n{continuation}\n")
            rows = lane_run.failure_details(text, False)["failures"]
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row["panicSites"], [])
                self.assertEqual(row["location"], lane_run.UNVERIFIED)
            self.assertEqual(rows[-1]["test"], lane_run.UNVERIFIED)
            self.assertEqual(rows[-1]["testUnverifiedReason"], "ambiguous-panic-block")

    def test_parallel_uncaptured_headers_withhold_test_attribution(self):
        for tid in ("", " (987654321)"):
            text = (f"thread 'first'{tid} panicked at crates/a.rs:1:2:\n"
                    f"thread 'second'{tid} panicked at crates/b.rs:2:4:\n"
                    "operation=Deadline kind=None raw_os_error=Some(13)\n"
                    "operation=NamedMetadata kind=Some(PermissionDenied) raw_os_error=Some(42)\n"
                    "test first ... FAILED\ntest second ... FAILED\n")
            with self.subTest(tid=tid):
                rows = lane_run.failure_details(text, False)["failures"]
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0]["test"], rows[0]["location"], rows[0]["panicSites"], rows[0]["category"]),
                                 (lane_run.UNVERIFIED, lane_run.UNVERIFIED, [], []))
                self.assertEqual(rows[0]["testUnverifiedReason"], "ambiguous-panic-block")
                for row in rows:
                    self.assert_facts_only(row)
                self.assertNotIn("987654321", json.dumps(rows))

    def test_multiline_panic_header_cannot_attest_another_site_or_test(self):
        text = ("test first ... FAILED\n---- first stdout ----\n"
                "thread 'first' (987654321) panicked at crates/a.rs:1:2:\n"
                "captured multiline prose\n"
                "thread 'second' (123456789) panicked at crates/b.rs:2:4:\n"
                "operation=Deadline kind=Some(TimedOut) raw_os_error=Some(60)\n")
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["test"], rows[0]["location"], rows[0]["panicSites"], rows[0]["category"]),
                         ("first", lane_run.UNVERIFIED, [], []))
        self.assertEqual((rows[1]["test"], rows[1]["testUnverifiedReason"], rows[1]["category"]),
                         (lane_run.UNVERIFIED, "ambiguous-panic-block", []))
        self.assertEqual(rows[1]["panicSites"], [])
        for row in rows:
            self.assert_facts_only(row)
        for value in ("second", "987654321", "123456789", "captured multiline prose"):
            self.assertNotIn(value, json.dumps(rows))

    def test_unattributed_row_key_cannot_collide_with_a_captured_test_name(self):
        metadata = lane_run.CheckoutMetadata({
            **self.sources, "web/app/src/internal.test.ts": 'test("<panic-block-0>", () => {});\n',
        })
        text = ("test <panic-block-0> ... FAILED\n"
                "thread 'first' panicked at crates/a.rs:1:2:\n"
                "thread 'second' panicked at crates/b.rs:2:4:\n"
                "operation=Deadline kind=None raw_os_error=None\n")
        rows = lane_run.failure_details(text, False, metadata=metadata)["failures"]
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["test"], rows[0]["panicSites"], rows[0]["category"]),
                         ("<panic-block-0>", [], []))
        self.assertEqual((rows[1]["test"], rows[1]["testUnverifiedReason"], rows[1]["category"]),
                         (lane_run.UNVERIFIED, "ambiguous-panic-block", []))
        self.assertEqual(rows[1]["panicSites"], [])

    def test_header_after_captured_prose_or_for_another_test_is_unattributed(self):
        for prefix, thread in (("captured prose\n", "first"), ("", "second")):
            text = ("test first ... FAILED\n---- first stdout ----\n" + prefix
                    + f"thread '{thread}' panicked at crates/b.rs:2:4:\n"
                    + "operation=Deadline kind=None raw_os_error=None\n")
            with self.subTest(prefix=prefix, thread=thread):
                rows = lane_run.failure_details(text, False)["failures"]
                self.assertEqual((rows[0]["location"], rows[0]["panicSites"], rows[0]["category"]),
                                 (lane_run.UNVERIFIED, [], []))
                self.assertEqual((rows[1]["test"], rows[1]["testUnverifiedReason"], rows[1]["panicSites"]),
                                 (lane_run.UNVERIFIED, "ambiguous-panic-block", []))
                self.assertEqual(rows[1]["category"], [])

    def test_thread_id_must_be_parenthesized_ascii_digits(self):
        for tid in (" (１２３)", " (-123)", " (123x)", " 123"):
            text = ("test first ... FAILED\n---- first stdout ----\n"
                    f"thread 'first'{tid} panicked at crates/a.rs:1:2:\n"
                    "operation=Deadline kind=None raw_os_error=None\n")
            with self.subTest(tid=tid):
                row = lane_run.failure_details(text, False)["failures"][0]
                self.assertEqual((row["location"], row["panicSites"], row["category"]),
                                 (lane_run.UNVERIFIED, [], []))

    def test_categories_and_multiple_sites_stay_with_their_tests(self):
        text = ("test first ... FAILED\ntest second ... FAILED\n"
                "---- first stdout ----\n"
                "thread 'first' panicked at crates/a.rs:1:2:\n"
                "captured prose\n---- second stdout ----\n"
                "thread 'second' panicked at crates/b.rs:2:4:\n"
                "operation=Deadline kind=None raw_os_error=None\n")
        records = self.records(self.diagnostic("first", kind="TimedOut"),
                               self.diagnostic("second", operation="NamedMetadata", errno=13))
        detail = lane_run.failure_details(text, False, diagnostic_records=records)
        rows = detail["failures"]
        self.assertEqual(detail["observedDiagnostics"], [
            {"test": "first", "relevance": "unknown", "category": ["Admission", "Deadline", "TimedOut"]},
            {"test": "second", "relevance": "unknown", "category": ["Admission", "NamedMetadata", 13]},
        ])
        self.assertEqual([(r["test"], r["panicSites"], r["category"]) for r in rows], [
            ("first", [], []),
            ("second", [], []),
            (lane_run.UNVERIFIED, [], []),
        ])
        self.assertEqual(rows[2]["testUnverifiedReason"], "ambiguous-panic-block")
        for row in rows:
            self.assert_facts_only(row)

    def test_timeout_keeps_panic_facts_before_a_failed_harness_observation(self):
        text = ("test waiting ...\n"
                "thread 'waiting' panicked at crates/a.rs:1:2:\n"
                "operation=Deadline kind=Some(TimedOut) raw_os_error=None\n")
        detail = lane_run.failure_details(text, True)
        self.assertEqual(detail["timeout"]["runningTests"], ["waiting"])
        row = detail["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["panicSites"], row["category"]),
                         ("waiting", ["crates/a.rs:1"], []))
        ambiguous = lane_run.failure_details(text + "test waiting ... ok\n", True)["failures"]
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(ambiguous[0]["test"], lane_run.UNVERIFIED)
        self.assertEqual(ambiguous[0]["panicSites"], [])

    def test_panic_sites_are_bounded_and_backtraces_cannot_add_categories(self):
        text = "test fails ... FAILED\n---- fails stdout ----\n" + "".join(
            "---- fails stderr ----\n"
            f"thread 'fails' panicked at crates/example/tests/journey.rs:{i + 1}:2:\n"
            "operation=Deadline kind=None raw_os_error=None\n"
            for i in range(lane_run.MAX_PANIC_SITES + 3))
        text += "stack backtrace:\noperation=NamedMetadata kind=Some(PermissionDenied) raw_os_error=Some(13)\n"
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assert_facts_only(row)
            self.assertEqual(row["category"], [])
            self.assertEqual(row["panicSites"], [])
            self.assertEqual(row["location"], lane_run.UNVERIFIED)

    def test_gradle_full_and_short_failure_formats(self):
        for exception in ("org.opentest4j.AssertionFailedError: expected: <200> but was: <500>",
                          "java.lang.AssertionError: expected status 200"):
            text = ("  com.example.HttpTest > finalStatus() FAILED\n"
                    f"    {exception}\n"
                    "        at org.junit.AssertionFailureBuilder.build(AssertionFailureBuilder.java:100)\n"
                    "        at com.example.HttpTest.finalStatus(HttpTest.java:81)\n"
                    "> Task :agent:test FAILED\n")
            with self.subTest(exception=exception):
                row = lane_run.failure_details(text, False)["failures"][0]
                self.assert_facts_only(row)
                self.assertEqual((row["test"], row["location"], row["kind"]),
                                 ("HttpTest::finalStatus", "adapters/java/tests/HttpTest.java:81", "assertion"))
                self.assertNotIn(exception, json.dumps(row))
        text = ("HttpTest > finalStatus() FAILED\n"
                "    org.opentest4j.AssertionFailedError at HttpTest.java:81\n")
        self.assertEqual(lane_run.failure_details(text, False)["failures"][0]["location"],
                         "adapters/java/tests/HttpTest.java:81")

    def test_backtrace_and_secondary_capture_withhold_unproven_location(self):
        text = ("test fails ... FAILED\n---- fails stdout ----\n"
                "thread 'fails' panicked at crates/a.rs:1:2:\nfirst assertion\n"
                "stack backtrace:\n0: irrelevant stack\n"
                "---- fails stderr ----\nother output\n")
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["location"], lane_run.UNVERIFIED)
        for value in ("first assertion", "irrelevant", "other output"):
            self.assertNotIn(value, json.dumps(row))

    def test_captured_worker_panic_has_no_verified_test_owner(self):
        text = ("test journey ... FAILED\n---- journey stdout ----\n"
                "thread 'worker' panicked at crates/a.rs:1:2:\nworker assertion\n")
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["test"], rows[0]["location"], rows[0]["panicSites"], rows[0]["category"]),
                         ("journey", lane_run.UNVERIFIED, [], []))
        self.assertEqual((rows[1]["test"], rows[1]["location"], rows[1]["kind"]),
                         (lane_run.UNVERIFIED, lane_run.UNVERIFIED, "panic"))
        self.assertEqual(rows[1]["testUnverifiedReason"], "name-not-declared-in-head")
        for row in rows:
            self.assert_facts_only(row)
        self.assertNotIn("worker", json.dumps(rows))

    def test_unsafe_panic_location_is_never_published_as_a_source_site(self):
        for path in ("../escape.rs", "/absolute/file.rs", "crates/missing.rs",
                     "crates/example/tests/../journey.rs", "crates/example/tests/journey.rs/extra"):
            with self.subTest(path=path):
                row = lane_run.failure_details(self.cargo(site=f"{path}:1:2", message="single-line failure", footer=False), False)["failures"][0]
                self.assertEqual(row["location"], lane_run.UNVERIFIED)
                self.assertNotIn(path, json.dumps(row))
        for line in (0, 100000):
            row = lane_run.failure_details(self.cargo(site=f"crates/a.rs:{line}:2", message="single-line failure", footer=False), False)["failures"][0]
            self.assertEqual(row["location"], lane_run.UNVERIFIED)

    def test_missing_failure_output_is_unverified(self):
        row = lane_run.failure_details("test missing ... FAILED\n", False)["failures"][0]
        self.assertEqual(row, {"test": lane_run.UNVERIFIED, "location": lane_run.UNVERIFIED,
                               "kind": "exit", "withheldLines": 0, "category": [], "panicSites": [],
                               "testUnverifiedReason": "name-not-declared-in-head"})
        self.assertNotIn("missing", json.dumps(row))

    def test_per_test_line_and_serialized_byte_caps(self):
        for message in ("\n".join(f"assertion line {i}" for i in range(30)), "é " * 10000):
            with self.subTest(message_length=len(message)):
                row = lane_run.failure_details(self.cargo(message=message, footer=False), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertGreater(row["withheldLines"], 0)
                self.assertNotIn(message, json.dumps(row))

    def test_byte_cap_preserves_the_continuation_withholding_count(self):
        row = lane_run.failure_details(self.cargo(message="é " * 10000 + "\nright", footer=False), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["withheldLines"], 3)
        self.assertNotIn("right", json.dumps(row))

    def test_job_cap_and_omitted_count(self):
        text = "".join(f"test case{i} ... FAILED\n" for i in range(32))
        # Rows no longer grow with prose; exercise the same cap with a smaller
        # caller-supplied budget rather than depending on retained message bytes.
        detail = lane_run.failure_details(text, False, budget=2048)
        self.assertLessEqual(len(lane_run._encoded(detail)), 2048)
        self.assertGreater(detail["omitted"], 0)
        self.assertEqual(len(detail["failures"]) + detail["omitted"], 32)
        self.assertIsNone(lane_run.failure_details(text, False, budget=0))

    def test_canary_anywhere_in_block_is_absent_from_failure_facts(self):
        text = self.cargo(message="safe assertion\n" + "safe line\n" * 20 + "BODY_CANARY_123", footer=False)
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["location"]), ("fails", lane_run.UNVERIFIED))
        for value in ("safe assertion", "safe line", "BODY_CANARY_123"):
            self.assertNotIn(value, json.dumps(row))

    def test_unmarked_values_are_absent_but_test_and_source_site_survive(self):
        for value in ("left: ghp_abc123", "right: account balance", "expected: customer-record",
                      "actual customer-record", "result=customer-record"):
            with self.subTest(value=value):
                self.assertFalse(lane_run._private(value, lane_run.CANARY_INDEX))
                row = lane_run.failure_details(self.cargo(message=value, footer=False), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertEqual((row["test"], row["location"]), ("fails", "crates/example/tests/journey.rs:42"))
                self.assertNotIn(value, json.dumps(row))

    def test_literals_paths_urls_long_tokens_and_numbers_are_absent(self):
        cases = ['message "business value" and \'other value\' and `expression`',
                 'message "escaped \\\" quote"', 'message "unterminated',
                 "read relative/data.txt and data.txt:42", r"read C:\work\data.txt",
                 "visit https://example.test/data", "value abcdefghijklmnopq",
                 "value 1234567 and 123456", "value 12345678901234567", "left: 200", 'actual: "short"']
        for message in cases:
            with self.subTest(message=message):
                row = lane_run.failure_details(self.cargo(message=message, footer=False), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertNotIn(message, json.dumps(row))
        for removed in ("MESSAGE_WORDS", "MESSAGE_LITERAL", "_message_structure", "_value_placeholder"):
            self.assertFalse(hasattr(lane_run, removed))

    def test_short_unlabelled_values_and_json_are_absent_end_to_end(self):
        for message, private in (("account balance 123456", ["account", "balance", "123456"]),
                                 ("received ghp_abc123", ["received", "ghp_abc123"]),
                                 ("customer Ada owes 7", ["customer", "Ada", "owes", "7"]),
                                 ("balance -12.5", ["balance", "-12.5"]),
                                 ("balance 2e3", ["balance", "2e3"]),
                                 ('{"balance": 42}', ["balance", "42"])):
            with self.subTest(message=message):
                detail = lane_run.failure_details(self.cargo(message=message,
                                                            site="crates/example/tests/journey.rs:88:6", footer=False), False)
                self.assert_facts_only(detail["failures"][0])
                for value in private:
                    self.assertNotIn(value, json.dumps(detail))

    def test_multiline_debug_and_quoted_values_are_withheld_end_to_end(self):
        cases = [("left:\nAccount {\n balance: 42,\n}", ["Account", "balance", "42"]),
                 ("left: Account {\n balance: 42,\n}", ["Account", "balance", "42"]),
                 ('left: "Ada\nshort ghp_abc123\n123456\n"', ["Ada", "short", "ghp_abc123", "123456"]),
                 ('"Ada\nshort ghp_abc123\n123456\n"', ["Ada", "short", "ghp_abc123", "123456"])]
        for message, private in cases:
            with self.subTest(message=message):
                detail = lane_run.failure_details(self.cargo(message=message,
                                                            site="crates/example/tests/journey.rs:88:6", footer=False), False)
                self.assert_facts_only(detail["failures"][0])
                self.assertGreater(detail["failures"][0]["withheldLines"], 1)
                for value in private:
                    self.assertNotIn(value, json.dumps(detail))

    def test_assertion_operators_and_operands_are_absent_end_to_end(self):
        for operator in ("==", "!="):
            for left, right in (("left", "right"), ("Ada", "Bob"), ("expected", "actual"), ("42", "7")):
                with self.subTest(operator=operator, left=left):
                    message = f"assertion `{left} {operator} {right}` failed"
                    row = lane_run.failure_details(self.cargo(message=message,
                                                             site="crates/example/tests/journey.rs:88:6", footer=False), False)["failures"][0]
                    self.assert_facts_only(row)
                    self.assertEqual(row["kind"], "assertion")
                    self.assertNotIn(message, json.dumps(row))
                    self.assertNotIn(operator, json.dumps(row))
                    self.assertNotIn(left, json.dumps(row))
                    self.assertNotIn(right, json.dumps(row))

    def test_fixed_deadline_diagnostic_and_request_values_are_absent_end_to_end(self):
        message = "3 POST /orders recordings were not persisted before deadline"
        detail = lane_run.failure_details(self.cargo(message=message,
                                                    site="crates/example/tests/journey.rs:88:6", footer=False), False)
        self.assert_facts_only(detail["failures"][0])
        for value in ("3", "POST", "/orders", "recordings", "not persisted", "deadline"):
            self.assertNotIn(value, json.dumps(detail))

    def test_even_pure_diagnostic_continuations_are_withheld(self):
        message = "timed out\nassertion `left != right` failed\nshort 42\nright: 7"
        row = lane_run.failure_details(self.cargo(message=message,
                                                 site="crates/example/tests/journey.rs:88:6", footer=False), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["withheldLines"], 5)
        for value in ("timed out", "left != right", "short", "right"):
            self.assertNotIn(value, json.dumps(row))

    def test_libtest_assertion_frames_are_never_published(self):
        message = ('assertion `left == right` failed\n  left: Account { balance: 42 }\n'
                   ' right: "Ada"\nexpected: 7\n}\n')
        row = lane_run.failure_details(self.cargo(message=message,
                                                 site="crates/example/tests/journey.rs:88:6", footer=False), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["kind"], "exit")
        self.assertEqual(row["location"], lane_run.UNVERIFIED)
        for value in ("Account", "balance", "42", "Ada", "expected", "7", "left", "right"):
            self.assertNotIn(value, json.dumps(row))

    def test_gradle_continuations_cannot_use_the_libtest_frame_exception(self):
        text = ('FooTest > check() FAILED\njava.lang.AssertionError: timed out\n'
                ' right: not persisted\nright\n')
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["withheldLines"], 3)
        for value in ("right", "not persisted", "timed out"):
            self.assertNotIn(value, json.dumps(row))

    def test_verified_names_are_still_scanned_for_private_canaries(self):
        index = [*lane_run.CANARY_INDEX, *lane_run.canary.build_index({"name": "fails"})]
        row = lane_run.failure_details(self.cargo(message='assertion "value"', footer=False), False, index=index)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["test"], lane_run.UNVERIFIED)
        self.assertNotIn("fails", json.dumps(row))

    def test_private_canaries_use_existing_scanner_encodings(self):
        values = {"assertion": "synthetic-value-31fe"}
        index = [*lane_run.CANARY_INDEX, *lane_run.canary.build_index(values)]
        for encoding, needle in lane_run.canary.needles(values["assertion"]):
            with self.subTest(encoding=encoding):
                detail = lane_run.failure_details(self.cargo(message=needle.decode(), footer=False), False, index=index)
                self.assert_facts_only(detail["failures"][0])
                self.assertNotIn(needle.decode(), json.dumps(detail))

    def test_paths_credentials_and_terminal_controls_are_absent(self):
        for value in ("/Users/example/data", "/home/runner/data", "/opt/local/data", "token=123",
                      "Authorization: value", "Cookie: value", "unexpected\x00value"):
            with self.subTest(value=value):
                row = lane_run.failure_details(self.cargo(message=value, footer=False), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertNotIn(value, json.dumps(row))

    def test_syntactically_valid_canary_test_id_is_withheld(self):
        detail = lane_run.failure_details(self.cargo(name="BODY_CANARY"), False)
        row = detail["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["test"], lane_run.UNVERIFIED)
        self.assertNotIn("BODY_CANARY", json.dumps(detail))

    def test_timeout_tracks_only_unfinished_observed_tests_and_safe_progress(self):
        text = ("running 4 tests\n"
                "test completed ...\ntest completed ... ok\n"
                "test waiting has been running for over 60 seconds\n"
                "test also_waiting ...\n"
                "test BODY_CANARY has been running for over 60 seconds\n"
                "unstructured output with private data\n"
                "Compiling secret token=123\n")
        detail = lane_run.failure_details(text, True)
        timeout = detail["timeout"]
        self.assertEqual(timeout["runningTests"], ["waiting", "also_waiting"])
        self.assertEqual(timeout["runningOmitted"], 1)
        self.assertEqual(timeout["progressWithheld"], 1)
        self.assertEqual(timeout["progress"], [
            {"test": "completed", "state": "running"}, {"test": "completed", "state": "ok"},
            {"test": "waiting", "state": "running"}, {"test": "also_waiting", "state": "running"}])
        for value in ("BODY_CANARY", "token=123", "unstructured output", "Compiling"):
            self.assertNotIn(value, json.dumps(detail))
        self.assertNotIn("timeout", lane_run.failure_details(text, False))

    def test_timeout_progress_keeps_last_n_safe_harness_lines(self):
        lines = [f"test case{i} ... ok" for i in range(30)]
        timeout = lane_run.failure_details("\n".join(lines), True)["timeout"]
        self.assertEqual(timeout["progress"], [{"test": f"case{i}", "state": "ok"}
                                              for i in range(30 - lane_run.MAX_PROGRESS_LINES, 30)])
        self.assertEqual(timeout["progressOmitted"], 30 - lane_run.MAX_PROGRESS_LINES)
        self.assertEqual(timeout["runningTests"], [])

    def test_timeout_job_cap_preserves_running_names_before_progress(self):
        text = "\n".join(["test waiting has been running for over 60 seconds",
                          *[f"test case{i} ... ok" for i in range(20)]])
        baseline = lane_run.failure_details("test waiting ...", True)
        baseline["timeout"]["progress"] = []
        baseline["timeout"]["progressOmitted"] = 21
        budget = len(lane_run._encoded(baseline))
        detail = lane_run.failure_details(text, True, budget=budget)
        self.assertLessEqual(len(lane_run._encoded(detail)), budget)
        self.assertEqual(detail["timeout"]["runningTests"], ["waiting"])
        self.assertEqual(detail["timeout"]["progress"], [])
        self.assertEqual(detail["timeout"]["progressOmitted"], 21)

    def test_timeout_progress_rebuilds_only_validated_fields(self):
        lines = ["test suite::done ... ok", "test suite::bad ... FAILED", "test suite::skip ... ignored",
                 "com.example.FooTest > check() STARTED", "FooTest > check(balance 42) PASSED",
                 "FooTest > check(ghp_abc123)[balance 42] FAILED",
                 "Compiling crate_name v1.2.3", "Compiling crate-name v1.2.3-rc.1+build.2 (balance 42)",
                 "Finished", "Finished balance 42"]
        detail = lane_run.failure_details("\n".join(lines), True)
        self.assertEqual(detail["timeout"]["progress"], [
            {"test": "done", "state": "ok"}, {"test": "bad", "state": "failed"},
            {"test": "FooTest::check", "state": "running"}, {"test": "FooTest::check", "state": "ok"},
            {"test": "FooTest::check", "state": "failed"}])
        for value in ("balance", "ghp_abc123", "Compiling", "Finished", "params"):
            self.assertNotIn(value, json.dumps(detail))

    def test_timeout_progress_drops_invalid_or_unapproved_harness_lines(self):
        lines = ["test invalid-name ... ok", "test café ... FAILED", "test unknown ...",
                 "test unknown has been running for over 60 seconds", "running 2 tests",
                 "test result: ok. balance 42", "> Task :balance42 PASSED",
                 "FööTest > check() STARTED", "FooTest > chéck() PASSED", "FooTest > skip() SKIPPED",
                 "Compiling balance 42", "Compiling crate_name v01.2.3", "Compiling crate_name v1.2",
                 "Compiling crate_name v1.2.3-01", "Compiling crate_name v1.2.3balance42",
                 "Finishedbalance42", "balance 42"]
        detail = lane_run.failure_details("\n".join(lines), True)
        self.assertEqual(detail["timeout"]["progress"], [])
        for value in ("balance", "42", "invalid-name", "café", "unknown", "chéck"):
            self.assertNotIn(value, json.dumps(detail))

    def test_timeout_gradle_started_and_completed_and_unknown_tests(self):
        text = ("FooTest > done() STARTED\nFooTest > done() PASSED\n"
                "FooTest > waiting() STARTED\n")
        timeout = lane_run.failure_details(text, True)["timeout"]
        self.assertEqual(timeout["runningTests"], ["FooTest::waiting"])
        self.assertIn("not observed", timeout["basis"])
        self.assertEqual(lane_run.failure_details("", True)["timeout"]["runningTests"], [])

    def test_timeout_does_not_retain_running_tests_from_a_finished_binary(self):
        text = ("test old has been running for over 60 seconds\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored\n"
                "running 1 test\n")
        self.assertEqual(lane_run.failure_details(text, True)["timeout"]["runningTests"], [])

    def test_previous_step_fragments_consume_the_same_job_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = pathlib.Path(temporary)
            current = out / "next.json"
            detail = lane_run.failure_details(self.cargo(), False)
            (out / "previous.json").write_text(json.dumps({"failureDetails": detail}))
            current.write_text(json.dumps({"failureDetails": detail}))
            remaining = lane_run._remaining_excerpt_budget(out, current)
            self.assertEqual(remaining, lane_run.MAX_JOB_EXCERPT_BYTES - len(lane_run._encoded(detail)))
            (out / "broken.json").write_text("{")
            self.assertEqual(lane_run._remaining_excerpt_budget(out, current), 0)

    def test_private_canary_file_is_optional_but_requested_missing_file_fails_closed(self):
        self.assertEqual(lane_run._excerpt_index(""), lane_run.CANARY_INDEX)
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "values.json"
            self.assertIsNone(lane_run._excerpt_index(str(path)))
            for value in ({}, [], {"a": 1}, {"a": ""}):
                path.write_text(json.dumps(value))
                self.assertIsNone(lane_run._excerpt_index(str(path)))
            path.write_text(json.dumps({"a": "synthetic-value-31fe"}))
            self.assertGreater(len(lane_run._excerpt_index(str(path))), len(lane_run.CANARY_INDEX))

    def test_trusted_metadata_recognizes_each_source_language(self):
        for candidate in ("fails", "HttpTest::finalStatus", "checkout JS test", "ExampleTests::test_example"):
            with self.subTest(candidate=candidate):
                self.assertEqual(self.metadata.test(candidate, lane_run.CANARY_INDEX), candidate)
        detail = lane_run.failure_details("not ok 1 - checkout JS test\n", False)
        self.assertEqual(detail["failures"][0]["test"], "checkout JS test")

    def test_attested_identifiers_skip_keywords_and_shapes_while_free_text_does_not(self):
        for name in ("private_key", "credential", "passwd", "api_key", "password",
                     "/opt/local/fixture", "https://fixture.example/path", "fixture@example.test"):
            with self.subTest(name=name):
                metadata = lane_run.CheckoutMetadata({
                    "web/app/src/example.test.ts": f"test({json.dumps(name)}, () => {{}});\n",
                })
                self.assertIn(name, metadata.tests)
                self.assertEqual(metadata.test(name, lane_run.CANARY_INDEX), name)
                self.assertTrue(lane_run._private(name, lane_run.CANARY_INDEX))
                self.assertEqual(self.metadata.test(name, lane_run.CANARY_INDEX), lane_run.UNVERIFIED)
        path = "crates/private_key/tests/credential.rs"
        metadata = lane_run.CheckoutMetadata({path: "#[test]\nfn private_key() {}\n"})
        self.assertEqual(metadata.location(f"{path}:2", lane_run.CANARY_INDEX), f"{path}:2")
        self.assertEqual(metadata.test("private_key", lane_run.CANARY_INDEX), "private_key")
        self.assertEqual(lane_run._rust_failure_name("private_key", metadata, lane_run.CANARY_INDEX), "private_key")
        self.assertTrue(lane_run._private("captured private_key fixture", lane_run.CANARY_INDEX))

    def test_attested_private_thread_keeps_structured_diagnostics_and_canary_guard(self):
        name = "private_root_admission"
        metadata = lane_run.CheckoutMetadata({**self.sources,
                                             "crates/example/tests/private.rs": f"#[test]\nfn {name}() {{}}\n"})
        self.assertEqual(self.records(self.diagnostic(thread=name), metadata=metadata),
                         [lane_run.AdmissionDiagnostic(name, ["Admission", "Deadline"])])
        index = [*lane_run.CANARY_INDEX, *lane_run.canary.build_index({"thread": "root_admission"})]
        self.assertEqual(self.records(self.diagnostic(thread=name), metadata=metadata, index=index),
                         [lane_run.AdmissionDiagnostic(lane_run.UNVERIFIED, ["Admission", "Deadline"])])
        detail = lane_run.failure_details(f"test {name} ... FAILED\n", False, metadata=metadata,
                                          diagnostic_records=self.records(self.diagnostic(thread=name),
                                                                          metadata=metadata))
        self.assertEqual(detail["failures"][0]["test"], name)
        self.assertEqual(detail["failures"][0]["category"], [])
        self.assertEqual(detail["observedDiagnostics"], [
            {"test": name, "relevance": "unknown", "category": ["Admission", "Deadline"]}])

    def test_comments_literals_and_helpers_cannot_attest_names(self):
        name = "crates/example/tests/declarations.rs"
        source = ('/* outer /* inner */ #[test]\nfn comment_value() {} */\n'
                  'const VALUE: &str = r###"#[test]\nfn literal_value() {}"###;\n'
                  'fn helper_value() {}\n#[test]\nfn actual_test() {}\n')
        (self.checkout / name).write_text(source)
        metadata = lane_run.CheckoutMetadata({name: source})
        self.assertEqual(metadata.tests, {"actual_test"})
        for candidate in ("comment_value", "literal_value", "helper_value", "ghp_abc123"):
            self.assertEqual(metadata.test(candidate, lane_run.CANARY_INDEX), lane_run.UNVERIFIED)

    def test_rust_lifetimes_do_not_hide_declared_tests(self):
        source = ("fn before(_: &mut Formatter<'_>) {}\n"
                  "#[test]\nfn between_lifetimes() {}\n"
                  "fn after(_: &mut Formatter<'_>) {}\n"
                  "const C: char = 'x';\n"
                  'const TEXT: &str = "#[test] fn literal_value() {}";\n')
        metadata = lane_run.CheckoutMetadata({"crates/example/src/lib.rs": source})
        self.assertEqual(metadata.tests, {"between_lifetimes"})
        self.assertEqual(metadata.test("tests::between_lifetimes", lane_run.CANARY_INDEX), "between_lifetimes")

    def test_rust_visibility_preserves_test_attribute_and_module_context(self):
        for visibility in ("", "pub ", "pub(crate) ", "pub(super) ", "pub(self) ",
                           "pub(in crate::outer) "):
            for asynchronous in ("", "async "):
                with self.subTest(visibility=visibility, asynchronous=asynchronous):
                    declaration = f"{visibility}{asynchronous}fn"
                    source = (f"mod outer {{ #[test] #[allow(dead_code)] {declaration} actual() {{}}\n"
                              f"{declaration} helper() {{}}\n"
                              f'const TEXT: &str = "#[test] {declaration} literal() {{}}";\n'
                              f"/* #[test] {declaration} comment() {{}} */ }}\n")
                    metadata = lane_run.CheckoutMetadata({"crates/example/src/lib.rs": source})
                    self.assertEqual(metadata.tests, {"actual"})
                    self.assertEqual(metadata.rust_tests, {"outer::actual"})

    def test_categories_require_declarations_in_the_private_storage_diagnostic_enums(self):
        source = ('/* outer /* inner */ enum AdmissionOperation { CommentValue } */\n'
                  'const TEXT: &str = r###"enum PrivateStorageError { LiteralValue }"###;\n'
                  'enum OtherEnum { OtherValue }\n'
                  'enum AdmissionOperation { ActualStep, }\n'
                  'enum PrivateStorageError {\n#[error("AttributeValue")]\n'
                  'Admission(AdmissionFailure), OtherError { detail: FieldType },\n}\n')
        metadata = lane_run.CheckoutMetadata({
            "crates/xtrace-private-storage/src/diagnostic.rs": source,
            "crates/example/src/error.rs": "enum AdmissionOperation { WrongCrateValue }",
            "crates/xtrace-private-storage/tests/example.rs": "enum AdmissionOperation { TestValue }",
            "crates/example/tests/journey.rs": self.sources["crates/example/tests/journey.rs"],
        })
        self.assertEqual(metadata.diagnostic_variants, {"ActualStep", "Admission", "OtherError"})
        self.assertEqual(metadata.admission_operations, {"ActualStep"})
        row = lane_run.failure_details(self.cargo(message=(
            "Admission(AdmissionFailure { operation: ActualStep, kind: None, raw_os_error: None }) "
            "ActualStep Admission AdmissionFailure OtherError FieldType CommentValue LiteralValue "
            "OtherValue AttributeValue WrongCrateValue TestValue"), footer=False), False, metadata=metadata)["failures"][0]
        self.assertEqual(row["category"], [])
        self.assertEqual(row["test"], "fails")
        records = self.records(self.diagnostic(operation="ActualStep"), metadata=metadata)
        self.assertEqual(records, [lane_run.AdmissionDiagnostic("fails", ["Admission", "ActualStep"])])
        structured = lane_run.failure_details(self.cargo(name="fails"), False, metadata=metadata,
                                              diagnostic_records=records)
        self.assertEqual(structured["failures"][0]["category"], [])
        self.assertEqual(structured["observedDiagnostics"], [
            {"test": "fails", "relevance": "unknown", "category": ["Admission", "ActualStep"]}])
        for operation in ("OtherError", "FieldType", "CommentValue", "LiteralValue", "OtherValue",
                          "AttributeValue", "WrongCrateValue", "TestValue"):
            with self.subTest(operation=operation):
                self.assertEqual(self.records(self.diagnostic(operation=operation), metadata=metadata), [])

    def test_unverified_name_reason_distinguishes_privacy_from_missing_declaration(self):
        index = lane_run.canary.build_index({"name": "fails", "category": "Deadline"})
        row = lane_run.failure_details(self.cargo(message="operation=Deadline", footer=False), False,
                                       index=index)["failures"][0]
        self.assertEqual(row["test"], lane_run.UNVERIFIED)
        self.assertEqual(row["testUnverifiedReason"], "privacy-scan")
        self.assertEqual(row["category"], [])

    def test_java_locations_require_a_unique_tracked_file_and_valid_line(self):
        for site in ("HttpTest.java:0", "HttpTest.java:10000", "ghp_abc123.java:7"):
            self.assertEqual(self.metadata.location(site, lane_run.CANARY_INDEX, java=True), lane_run.UNVERIFIED)
        duplicate = "adapters/java/tests/other/HttpTest.java"
        (self.checkout / duplicate).parent.mkdir()
        (self.checkout / duplicate).write_text(self.sources["adapters/java/tests/HttpTest.java"])
        metadata = lane_run.CheckoutMetadata({**self.sources, duplicate: self.sources["adapters/java/tests/HttpTest.java"]})
        self.assertEqual(metadata.location("HttpTest.java:3", lane_run.CANARY_INDEX, java=True), lane_run.UNVERIFIED)

    def test_java_continuations_cannot_supply_even_a_tracked_location(self):
        for continuation in ("Error at HttpTest.java:7", "        at example.HttpTest.finalStatus(HttpTest.java:7)"):
            text = ('HttpTest > finalStatus() FAILED\njava.lang.AssertionError: "Ada\n'
                    f'{continuation}\n"\n')
            row = lane_run.failure_details(text, False)["failures"][0]
            self.assert_facts_only(row)
            self.assertEqual(row["location"], lane_run.UNVERIFIED)
            self.assertNotIn("Ada", json.dumps(row))
            self.assertNotIn("HttpTest.java", json.dumps(row))

    def test_cargo_quoted_stdout_cannot_supply_a_panic_location(self):
        text = ('test fails ... FAILED\n---- fails stdout ----\n"Ada\n'
                "thread 'fails' panicked at crates/a.rs:1:2:\n"
                '"\n')
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["location"], lane_run.UNVERIFIED)
        self.assertNotIn("crates/a.rs", json.dumps(row))

    def test_an_unframed_passing_status_cannot_establish_panic_ownership(self):
        text = ("thread 'waiting' panicked at crates/a.rs:1:2:\nexpected panic\n"
                "test waiting ... ok\n")
        ambiguous = lane_run.failure_details(text, False)["failures"]
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(ambiguous[0]["test"], lane_run.UNVERIFIED)
        self.assertEqual(ambiguous[0]["panicSites"], [])
        # A second panic cannot prove that the first stream ended, even if its
        # terminal status looks like a successful should_panic observation.
        rows = lane_run.failure_details(text + self.cargo(), False)["failures"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["testUnverifiedReason"], "ambiguous-panic-block")
        self.assertEqual(rows[0]["test"], lane_run.UNVERIFIED)
        self.assertEqual(rows[0]["panicSites"], [])

    def test_structured_records_validate_every_field_and_exact_thread_name(self):
        good = self.diagnostic(kind="PermissionDenied", errno=13)
        self.assertEqual(self.records(good), [
            lane_run.AdmissionDiagnostic("fails", ["Admission", "Deadline", "PermissionDenied", 13])])
        for field, values in {
            "error": ["/private/path", "Unknown", [], 42],
            "operation": ["/private/Deadline", "Unknown", [], None],
            "kind": ["/private/PermissionDenied", "Unknown", [], 13],
            "errno": [0, -1, 201, 10**100, True, "13", 13.5, []],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.records({**good, field: value}), [])
        self.assertEqual(self.records({**good, "message": "captured-value"}), [])
        self.assertEqual(self.records({key: value for key, value in good.items() if key != "kind"}), [])
        for thread in (None, "/private/fails", "customer42::fails", "unverified", [], 42):
            with self.subTest(thread=thread):
                records = self.records({**good, "thread": thread})
                self.assertEqual(records, [lane_run.AdmissionDiagnostic(
                    lane_run.UNVERIFIED, ["Admission", "Deadline", "PermissionDenied", 13])])
                detail = lane_run.failure_details("", False, diagnostic_records=records)
                self.assertEqual(detail["failures"], [])
                self.assertEqual(detail["observedDiagnostics"], [{
                    "test": lane_run.UNVERIFIED, "relevance": "unknown",
                    "testUnverifiedReason": "diagnostic-thread-unverified",
                    "category": ["Admission", "Deadline", "PermissionDenied", 13]}])
        index = lane_run.canary.build_index({"category": "Deadline"})
        self.assertEqual(self.records(good, index=index), [])

    def test_context_fields_use_their_own_head_enum_and_mask_bounds(self):
        good = self.diagnostic(operation="AclState", site="Snapshot", changes=0, listing="NotChecked")
        self.assertEqual(self.metadata.admission_sites, {"Snapshot", "ProbeState", "RecheckAcl"})
        self.assertEqual(self.metadata.listing_refusals, {"NotChecked", "InheritedAllow", "Header"})
        for site in sorted(self.metadata.admission_sites):
            for listing in sorted(self.metadata.listing_refusals):
                for changes in (0, 1, 3, 16, 31):
                    with self.subTest(site=site, listing=listing, changes=changes):
                        self.assertEqual(self.records({**good, "site": site, "listing": listing,
                                                       "changes": changes}),
                                         [lane_run.AdmissionDiagnostic(
                                             "fails", ["Admission", "AclState", site, changes, listing])])
        for field in ("site", "changes", "listing"):
            self.assertEqual(self.records({key: value for key, value in good.items() if key != field}), [])
        index = lane_run.canary.build_index({"category": "Snapshot"})
        self.assertEqual(self.records(good, index=index), [])
        metadata = lane_run.CheckoutMetadata({**self.sources,
            "crates/xtrace-private-storage/src/diagnostic.rs":
                "pub enum AdmissionOperation { AclState, }\n"
                "const TEXT: &str = \"enum AdmissionSite { Snapshot, }\";\n"
                "// enum ListingRefusal { NotChecked, }\n"})
        self.assertEqual(self.records(good, metadata=metadata), [])

    def test_structured_thread_names_include_only_head_verified_modules(self):
        metadata = lane_run.CheckoutMetadata({
            **self.sources,
            "crates/example/src/probe.rs": "mod tests { #[test] fn scoped() {} }",
        })
        self.assertIn("probe::tests::scoped", metadata.rust_tests)
        self.assertEqual(self.records(self.diagnostic("probe::tests::scoped"), metadata=metadata),
                         [lane_run.AdmissionDiagnostic("probe::tests::scoped", ["Admission", "Deadline"])])
        for thread in ("scoped", "tests::scoped", "customer42::scoped"):
            self.assertEqual(self.records(self.diagnostic(thread), metadata=metadata)[0].thread, lane_run.UNVERIFIED)

    def test_new_context_fields_publish_each_value_with_its_json_type(self):
        good = self.diagnostic(operation="AclState", site="Snapshot", changes=0, listing="NotChecked")
        for field, values in {
            "object": ["File", "Directory", "Other"],
            "component_depth": [-(2**63), -2, -1, 0, 1, 2**63 - 1],
            "nlink_changed": [False, True],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    records = self.records({**good, field: value})
                    self.assertEqual(records, [lane_run.AdmissionDiagnostic(
                        "fails", ["Admission", "AclState", "Snapshot", 0, "NotChecked"], {field: value})])
                    detail = lane_run.failure_details(self.cargo(name="fails"), False, diagnostic_records=records)
                    row, = detail["observedDiagnostics"]
                    self.assertEqual(row, {"test": "fails", "relevance": "unknown",
                                          "category": records[0].categories, field: value})
                    self.assertIs(type(json.loads(json.dumps(row))[field]), type(value))
                    self.assertEqual(detail["failures"][0]["category"], [])

    def test_caller_fields_publish_without_metadata_context_and_independently(self):
        for caller in sorted(self.metadata.admission_callers):
            for fields in ({"store_phase": caller}, {"store_site": caller},
                           {"store_phase": caller, "store_site": "JournalPublish"}):
                with self.subTest(fields=fields):
                    records = self.records(self.diagnostic(**fields))
                    self.assertEqual(records, [lane_run.AdmissionDiagnostic("fails", ["Admission", "Deadline"], fields)])
                    detail = lane_run.failure_details(self.cargo(name="fails"), False, diagnostic_records=records)
                    self.assertEqual(detail["observedDiagnostics"], [
                        {"test": "fails", "relevance": "unknown", "category": ["Admission", "Deadline"], **fields}])

    def test_new_fields_reject_wrong_types_bounds_and_vocabularies(self):
        good = self.diagnostic(operation="AclState", site="Snapshot", changes=3, listing="NotChecked",
                               object="Directory", component_depth=-2, nlink_changed=True,
                               store_phase="Append", store_site="JournalPublish")
        self.assertEqual(len(self.records(good)), 1)
        for field, values in {
            "object": [None, [], {}, 1, True, "Unknown", "Append", "Snapshot", "file"],
            "component_depth": [None, [], {}, True, False, "-2", -2.0, -(2**63) - 1, 2**63, 10**100],
            "nlink_changed": [None, [], {}, 0, 1, "true", 0.0, 1.0],
            "store_phase": [None, [], {}, True, 1, "Unknown", "Directory", "Snapshot", "append"],
            "store_site": [None, [], {}, False, 0, "Unknown", "File", "NotChecked", "journalpublish"],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.records({**good, field: value}), [])
        self.assertEqual(self.records({**good, "unknown": "captured-value"}), [])
        for key in ("site", "changes", "listing"):
            self.assertEqual(self.records({k: v for k, v in good.items() if k != key}), [])
        for field in ("object", "component_depth", "nlink_changed"):
            self.assertEqual(self.records(self.diagnostic(**{field: good[field]})), [])
        for value in ("Directory", "-2", "True", "Append", "JournalPublish"):
            with self.subTest(private=value):
                index = lane_run.canary.build_index({"category": value})
                self.assertEqual(self.records(good, index=index), [])

    def test_new_vocabulary_requires_the_declaring_head_file(self):
        metadata = lane_run.CheckoutMetadata({**self.sources,
            "crates/xtrace-private-storage/src/diagnostic.rs": (
                self.sources["crates/xtrace-private-storage/src/diagnostic.rs"]
                + "enum AdmissionCaller { WrongFileCaller, }\n"),
            "crates/xtrace-private-storage/src/caller.rs": (
                self.sources["crates/xtrace-private-storage/src/caller.rs"]
                + 'const TEXT: &str = "enum AdmissionCaller { LiteralCaller }";\n'
                + "// enum AdmissionCaller { CommentCaller }\n"
                + "enum AdmissionObject { WrongFileObject, }\n"),
            "crates/other/src/caller.rs": "enum AdmissionCaller { WrongCrateCaller, }\n",
            "crates/xtrace-private-storage/src/nested/caller.rs": "enum AdmissionCaller { NestedCaller, }\n",
            "crates/xtrace-private-storage/tests/caller.rs": "enum AdmissionCaller { TestCaller, }\n",
        })
        self.assertEqual(metadata.admission_objects, {"File", "Directory", "Other"})
        self.assertEqual(metadata.admission_callers, {"Append", "JournalPublish", "Read"})
        for caller in ("WrongFileCaller", "LiteralCaller", "CommentCaller", "WrongCrateCaller",
                       "NestedCaller", "TestCaller"):
            for field in ("store_phase", "store_site"):
                self.assertEqual(self.records(self.diagnostic(**{field: caller}), metadata=metadata), [])

    def test_differing_attribution_fields_are_not_overwritten_or_combined(self):
        records = self.records(self.diagnostic(store_phase="Append", store_site="JournalPublish"),
                               self.diagnostic(store_phase="Read", store_site="JournalPublish"),
                               self.diagnostic(store_phase="Append", store_site="JournalPublish"))
        detail = lane_run.failure_details(self.cargo(name="fails"), False, diagnostic_records=records)
        self.assertEqual(detail["observedDiagnostics"], [
            {"test": "fails", "relevance": "unknown", "category": ["Admission", "Deadline"],
             "store_phase": phase, "store_site": "JournalPublish"} for phase in ("Append", "Read")])

    def test_synthetic_thread_never_falls_back_to_an_unrelated_failure(self):
        synthetic = "diagnostic::ci::tests::contextual_record_contains_only_fixed_categories_and_a_difference_mask"
        records = self.records(self.diagnostic(synthetic, operation="AclState", site="Snapshot", changes=3,
                                              listing="InheritedAllow", object="Directory", component_depth=-2,
                                              nlink_changed=True))
        for status in (None, "ok", "FAILED"):
            with self.subTest(status=status):
                text = "test fails ... FAILED\n"
                if status is not None:
                    text += f"test {synthetic} ... {status}\n"
                detail = lane_run.failure_details(text, False, diagnostic_records=records)
                expected = {"test": synthetic if status == "FAILED" else lane_run.UNVERIFIED,
                            "relevance": "unknown", "category": ["Admission", "AclState", "Snapshot", 3,
                                                                    "InheritedAllow"],
                            "object": "Directory", "component_depth": -2, "nlink_changed": True}
                if status != "FAILED":
                    expected.update(thread=synthetic, testUnverifiedReason="diagnostic-thread-not-failing")
                self.assertEqual(detail["observedDiagnostics"], [expected])
                unrelated, = [row for row in detail["failures"] if row["test"] == "fails"]
                self.assertEqual(unrelated["category"], [])

    def test_record_reader_bounds_and_private_file_admission(self):
        import os
        records = self.records(*[self.diagnostic() for _ in range(lane_run.MAX_CI_RECORDS + 5)])
        self.assertEqual(len(records), lane_run.MAX_CI_RECORDS)
        directory = self.checkout / "ci-diag"
        path = directory / "private-storage.jsonl"
        self.assertEqual(lane_run._ci_diagnostics(None, self.metadata, lane_run.CANARY_INDEX), [])
        for raw in (b"{" + b"x" * lane_run.MAX_CI_RECORD_BYTES + b"\n", b"{bad json}\n",
                    json.dumps(self.diagnostic()).encode(), b"[1,2,3]\n", b"\xff\n"):
            path.write_bytes(raw)
            self.assertEqual(lane_run._ci_diagnostics(directory, self.metadata, lane_run.CANARY_INDEX), [])
        path.write_text(json.dumps(self.diagnostic()) + "\n")
        path.chmod(0o644)
        self.assertEqual(lane_run._ci_diagnostics(directory, self.metadata, lane_run.CANARY_INDEX), [])
        path.chmod(0o600)
        directory.chmod(0o755)
        self.assertEqual(lane_run._ci_diagnostics(directory, self.metadata, lane_run.CANARY_INDEX), [])
        directory.chmod(0o700)
        path.unlink()
        os.symlink(self.checkout / "crates/a.rs", path)
        self.assertEqual(lane_run._ci_diagnostics(directory, self.metadata, lane_run.CANARY_INDEX), [])


class CheckoutLookupTests(unittest.TestCase):
    def test_real_include_and_path_modules_keep_their_declared_contexts(self):
        metadata = lane_run._checkout_metadata()
        cases = [
            ("recording_store::tests::published_reads::first_journal_creation_cannot_overtake_a_published_read",
             "crates/xtrace-store/src/recording_published_read_tests.rs",
             "recording_published_read_tests::published_reads::first_journal_creation_cannot_overtake_a_published_read"),
            ("open_recording_durability::acknowledged_unfinished_batch_survives_a_running_daemon_restart",
             "crates/xtrace-cli/tests/lifecycle/open_recording_durability.rs",
             "lifecycle::open_recording_durability::acknowledged_unfinished_batch_survives_a_running_daemon_restart"),
        ]
        for name, path, wrong_name in cases:
            with self.subTest(name=name):
                self.assertIn(name, metadata.rust_tests)
                self.assertNotIn(wrong_name, metadata.rust_tests)
                self.assertEqual(lane_run._rust_failure_name(name, metadata, lane_run.CANARY_INDEX), name)
                self.assertEqual(lane_run._rust_failure_name(wrong_name, metadata, lane_run.CANARY_INDEX),
                                 lane_run.UNVERIFIED)
                body = ["failures:", f"---- {name} stdout ----",
                        f"thread 'worker' panicked at {path}:1:1:", "fixture message"]
                report = lane_run.libtest_output.Report(
                    "     Running tests/journey.rs (target/debug/deps/journey-0123456789abcdef)",
                    (0, 1, 0), [name], body, [True] * len(body))
                row, = lane_run._libtest_failures(report, metadata, lane_run.CANARY_INDEX)
                self.assertEqual((row["test"], row["panicSites"]), (name, [f"{path}:1"]))
                self.assertNotIn("testUnverifiedReason", row)

    def test_nested_includes_and_path_modules_resolve_only_literal_head_files(self):
        sources = {
            "crates/example/Cargo.toml": '[package]\nname = "example"\n',
            "crates/example/src/lib.rs": ('mod outer { include!("included.rs"); }\n'
                                          '#[path = "mapped.rs"] mod actual;\n'
                                          '// include!("comment.rs");\n'
                                          'const TEXT: &str = "include!(\\"comment.rs\\");";\n'),
            "crates/example/src/included.rs": ('include!("nested.rs");\n'
                                               '#[test] fn included() {}\n'),
            "crates/example/src/nested.rs": 'mod inner { #[test] fn nested() {} }\n',
            "crates/example/src/mapped.rs": '#[test] fn mapped() {}\n',
        }
        metadata = lane_run.CheckoutMetadata(sources)
        self.assertEqual(metadata.rust_tests, {"outer::included", "outer::inner::nested", "actual::mapped"})
        for name in ("included::included", "nested::inner::nested", "mapped::mapped", "comment::included"):
            self.assertEqual(lane_run._rust_failure_name(name, metadata, lane_run.CANARY_INDEX), lane_run.UNVERIFIED)
        missing = lane_run.CheckoutMetadata({name: source for name, source in sources.items()
                                            if not name.endswith("mapped.rs")})
        self.assertNotIn("actual::mapped", missing.rust_tests)

    def test_one_included_source_in_two_binary_roots_keeps_diagnostics_ambiguous(self):
        metadata = lane_run.CheckoutMetadata({
            "crates/example/Cargo.toml": '[package]\nname = "example"\n',
            "crates/example/tests/first.rs": 'include!("shared/body.rs");\n',
            "crates/example/tests/second.rs": 'include!("shared/body.rs");\n',
            "crates/example/tests/shared/body.rs": '#[test] fn shared() {}\n',
        })
        self.assertEqual(metadata.rust_tests, {"shared"})
        self.assertEqual({owner.path for owner in metadata.rust_test_owners["shared"]},
                         {"tests/first.rs", "tests/second.rs"})
        detail = lane_run.failure_details("test shared ... FAILED\n", False, metadata=metadata,
                                          diagnostic_records=[lane_run.AdmissionDiagnostic("shared", ["Admission"])])
        self.assertEqual(detail["observedDiagnostics"], [{
            "test": lane_run.UNVERIFIED, "thread": "shared", "relevance": "unknown", "category": ["Admission"],
            "testUnverifiedReason": "diagnostic-thread-ambiguous"}])

    def test_one_source_declared_as_two_cargo_targets_keeps_both_owners(self):
        metadata = lane_run.CheckoutMetadata({
            "crates/example/Cargo.toml": ('[package]\nname = "example"\nautotests = false\n'
                                         '[lib]\npath = "shared.rs"\n'
                                         '[[test]]\nname = "integration"\npath = "shared.rs"\n'),
            "crates/example/shared.rs": '#[test] fn shared() {}\n',
        })
        self.assertEqual(metadata.rust_tests, {"shared"})
        self.assertEqual({owner.kind for owner in metadata.rust_test_owners["shared"]}, {"lib", "test"})
        detail = lane_run.failure_details("test shared ... FAILED\n", False, metadata=metadata,
                                          diagnostic_records=[lane_run.AdmissionDiagnostic("shared", ["Admission"])])
        self.assertEqual(detail["observedDiagnostics"][0]["testUnverifiedReason"], "diagnostic-thread-ambiguous")

    def test_real_checkout_failing_test_name_and_location_survive_the_command_path(self):
        name = "honesty_strings_cover_every_stable_code"
        path = "crates/xtrace-domain/tests/honesty_strings.rs"
        lines = (ROOT / path).read_text().splitlines()
        line = next(i for i, text in enumerate(lines, 1) if text.startswith(f"fn {name}("))
        text = FailureDetailsTests.cargo(name=name, site=f"{path}:{line}:1", message="not persisted", footer=False)
        with tempfile.TemporaryDirectory() as temporary:
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", "t",
                 "--out", temporary, "--", sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"],
                cwd=ROOT, capture_output=True, text=True,
                env={**__import__("os").environ, "LANE_PRIVATE_LOG_DIR": temporary})
            frag = json.loads((pathlib.Path(temporary) / "rust__-__t.json").read_text())
        self.assertEqual(proc.returncode, 101)
        row = frag["failureDetails"]["failures"][0]
        self.assertEqual((row["test"], row["location"], row["kind"]), (name, f"{path}:{line}", "panic"))
        self.assertEqual(set(row), {"test", "location", "kind", "withheldLines", "category", "panicSites"})
        self.assertEqual(row["category"], [])
        self.assertEqual(row["panicSites"], [f"{path}:{line}"])
        self.assertEqual(frag["failingTests"], [name])
        self.assertNotIn("not persisted", json.dumps(frag))

    def test_unavailable_tracked_file_metadata_fails_closed(self):
        with mock.patch.object(lane_run.subprocess, "Popen", side_effect=OSError):
            detail = lane_run.failure_details(FailureDetailsTests.cargo(), False)
        row = detail["failures"][0]
        self.assertEqual((row["test"], row["location"]), (lane_run.UNVERIFIED, lane_run.UNVERIFIED))
        self.assertEqual(row["testUnverifiedReason"], "metadata-unavailable")
        self.assertNotIn("journey", json.dumps(detail))


class CommittedCheckoutTests(unittest.TestCase):
    def setUp(self):
        import os
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.checkout = pathlib.Path(temporary.name)
        directory = self.checkout / "crates/tests"
        directory.mkdir(parents=True)
        self.path = directory / "example.rs"
        self.path.write_text("#[test]\nfn committed_test() {}\n")
        (directory / "alias.rs").symlink_to("example.rs")
        (directory / "outside.rs").symlink_to("../outside.rs")
        self.diagnostic = self.checkout / "crates/xtrace-private-storage/src/diagnostic.rs"
        self.diagnostic.parent.mkdir(parents=True)
        self.diagnostic.write_text("pub enum AdmissionOperation { Deadline, }\n"
                                   "pub(crate) enum AdmissionSite { Snapshot, }\n"
                                   "pub(crate) enum ListingRefusal { NotChecked, }\n"
                                   "pub(crate) enum AdmissionObject { Directory, }\n")
        self.caller = self.diagnostic.parent / "caller.rs"
        self.caller.write_text("pub enum AdmissionCaller { Append, JournalPublish, }\n")
        (self.diagnostic.parent / "alias.rs").symlink_to("diagnostic.rs")
        env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_COMMITTER_NAME": "Fixture",
               "GIT_AUTHOR_EMAIL": "fixture@example.test", "GIT_COMMITTER_EMAIL": "fixture@example.test"}
        for command in (["init"], ["add", "."], ["commit", "-m", "Fixture"]):
            subprocess.run(["git", "-C", str(self.checkout), *command], env=env,
                           check=True, capture_output=True)
        patcher = mock.patch.object(lane_run, "__file__", str(self.checkout / "tools/qa/lane_run.py"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_committed_blobs_ignore_staged_changes_deleted_files_and_symlinks(self):
        self.path.write_text("#[test]\nfn captured_value() {}\n" + "\n" * 10)
        subprocess.run(["git", "-C", str(self.checkout), "add", "crates/tests/example.rs"],
                       check=True, capture_output=True)
        self.path.unlink()
        (self.checkout / "crates/tests/untracked.rs").write_text("#[test]\nfn untracked_value() {}\n")
        (self.checkout / "crates/outside.rs").write_text("#[test]\nfn outside_value() {}\n")
        metadata = lane_run._checkout_metadata()
        self.assertEqual(metadata.tests, {"committed_test"})
        self.assertEqual(metadata.location("crates/tests/example.rs:2", lane_run.CANARY_INDEX),
                         "crates/tests/example.rs:2")
        for name in ("captured_value", "untracked_value", "outside_value", "alias"):
            self.assertEqual(metadata.test(name, lane_run.CANARY_INDEX), lane_run.UNVERIFIED)
        for site in ("crates/tests/example.rs:3", "crates/tests/alias.rs:1",
                     "crates/tests/outside.rs:1", "crates/tests/untracked.rs:1"):
            self.assertEqual(metadata.location(site, lane_run.CANARY_INDEX), lane_run.UNVERIFIED)

    def test_diagnostic_vocabulary_comes_only_from_head_blobs(self):
        self.diagnostic.write_text("pub enum AdmissionOperation { StagedValue, }\n"
                                   "pub(crate) enum AdmissionSite { StagedSite, }\n"
                                   "pub(crate) enum ListingRefusal { StagedListing, }\n"
                                   "pub(crate) enum AdmissionObject { StagedObject, }\n")
        subprocess.run(["git", "-C", str(self.checkout), "add", "crates/xtrace-private-storage/src/diagnostic.rs"],
                       check=True, capture_output=True)
        self.diagnostic.unlink()
        self.caller.write_text("pub enum AdmissionCaller { StagedCaller, }\n")
        subprocess.run(["git", "-C", str(self.checkout), "add", "crates/xtrace-private-storage/src/caller.rs"],
                       check=True, capture_output=True)
        self.caller.write_text("pub enum AdmissionCaller { WorkingCaller, }\n")
        (self.diagnostic.parent / "untracked.rs").write_text(
            "enum AdmissionOperation { UntrackedValue }\n"
            "enum AdmissionSite { UntrackedSite }\n"
            "enum ListingRefusal { UntrackedListing }\n"
            "enum AdmissionObject { UntrackedObject }\n"
            "enum AdmissionCaller { UntrackedCaller }\n")
        metadata = lane_run._checkout_metadata()
        self.assertEqual(metadata.diagnostic_variants, {"Deadline"})
        self.assertEqual(metadata.admission_sites, {"Snapshot"})
        self.assertEqual(metadata.listing_refusals, {"NotChecked"})
        self.assertEqual(metadata.admission_objects, {"Directory"})
        self.assertEqual(metadata.admission_callers, {"Append", "JournalPublish"})
        row = lane_run.failure_details(FailureDetailsTests.cargo(
            name="committed_test", site="crates/tests/example.rs:2:1",
            message=("operation=Deadline kind=None raw_os_error=None "
                     "operation=StagedValue kind=None raw_os_error=None "
                     "operation=UntrackedValue kind=None raw_os_error=None"), footer=False), False, metadata=metadata)["failures"][0]
        self.assertEqual(row["category"], [])
        self.assertNotIn("StagedValue", json.dumps(row))
        self.assertNotIn("UntrackedValue", json.dumps(row))

    def test_wrapped_command_cannot_attest_captured_values_by_rewriting_tracked_tests(self):
        import os
        captured = "customer42"
        self.assertFalse(lane_run._private(captured, lane_run.CANARY_INDEX))
        original_run = subprocess.run
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out):
                text = (f"test {captured} has been running for over 60 seconds\n" if timed_out else
                        FailureDetailsTests.cargo(name=captured, site="crates/tests/example.rs:3:1"))
                source = f"#[test]\nfn {captured}() {{}}\n// captured extra line\n"
                body = (f"from pathlib import Path; Path({str(self.path)!r}).write_text({source!r}); "
                        f"print({text!r}); raise SystemExit(101)")
                args = type("A", (), {"suite": "rust", "variant": "-", "step": "t",
                                      "out": str(self.checkout / "out"), "cwd": "", "timeout": 60,
                                      "min_passed": 0, "command": [sys.executable, "-c", body]})()

                def command(cmd, **kwargs):
                    result = original_run(cmd, **kwargs)
                    if timed_out:
                        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
                    return result

                with mock.patch.dict(os.environ, {"LANE_PRIVATE_LOG_DIR": str(self.checkout)}), \
                        mock.patch.object(lane_run.subprocess, "run", side_effect=command):
                    rc = lane_run.cmd_run(args)
                self.assertEqual(rc, 124 if timed_out else 101)
                self.assertIn(captured, self.path.read_text())
                frag = json.loads((self.checkout / "out/rust__-__t.json").read_text())
                self.assertNotIn(captured, json.dumps(frag))
                detail = frag["failureDetails"]
                if timed_out:
                    self.assertEqual(detail["timeout"]["progress"], [])
                    self.assertEqual(detail["timeout"]["runningTests"], [])
                    self.assertEqual(detail["timeout"]["runningOmitted"], 1)
                else:
                    self.assertEqual(frag["failingTests"], [lane_run.UNVERIFIED])
                    self.assertEqual((detail["failures"][0]["test"], detail["failures"][0]["location"]),
                                     (lane_run.UNVERIFIED, lane_run.UNVERIFIED))


class MergeTests(unittest.TestCase):
    def merge(self, plan, frags, results=None):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "plan.json").write_text(json.dumps(plan))
            (d / "f").mkdir()
            for i, f in enumerate(frags):
                (d / "f" / f"{i}.json").write_text(json.dumps(f))
            args = type("A", (), {"plan": str(d / "plan.json"), "frag_dir": str(d / "f"),
                                  "out": str(d / "s.json"), "step_summary": "", "job_result": results})()
            rc = lane_run.cmd_merge(args)
            return rc, json.loads((d / "s.json").read_text())

    def frag(self, suite, status="pass", variant="-"):
        return {"suite": suite, "variant": variant, "step": "t", "status": status, "exitCode": 0,
                "passed": 1, "failed": 0, "ignored": 0, "failingTests": [], "failingTruncated": 0,
                "droppedInvalidNames": 0}

    def test_missing_result_is_not_pass(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}, "tui": {"status": "absent"}}}
        rc, s = self.merge(plan, [])
        self.assertEqual(rc, 1)
        self.assertEqual(s["suites"][0]["variants"][0]["status"], "no-result")
        self.assertEqual(s["suites"][1]["status"], "absent")

    def test_pass_and_skip(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}, "java": {"status": "skipped-by-filter"}}}
        rc, s = self.merge(plan, [self.frag("meta")])
        self.assertEqual(rc, 0)
        self.assertEqual([x["status"] for x in s["suites"]], ["pass", "skipped-by-filter"])

    def test_all_java_variants_required(self):
        plan = {"mode": "x", "suites": {"java": {"status": "selected"}}}
        rc, _ = self.merge(plan, [self.frag("java", variant="17"), self.frag("java", variant="21")])
        self.assertEqual(rc, 1)

    def test_failed_job_result_fails_suite(self):
        plan = {"mode": "x", "suites": {"meta": {"status": "selected"}}}
        rc, _ = self.merge(plan, [self.frag("meta")], ["meta=failure"])
        self.assertEqual(rc, 1)

    def test_forced_absent_suite_fails(self):
        plan = {"mode": "x", "suites": {"tui": {"status": "absent", "forced": True}}}
        rc, s = self.merge(plan, [])
        self.assertEqual(rc, 1)
        self.assertEqual(s["suites"][0]["status"], "fail")

    def test_missing_plan_emits_failing_summary(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            args = type("A", (), {"plan": str(d / "none.json"), "frag_dir": str(d), "out": str(d / "s.json"),
                                  "step_summary": "", "job_result": None})()
            self.assertEqual(lane_run.cmd_merge(args), 1)
            doc = json.loads((d / "s.json").read_text())
            self.assertEqual((doc["overall"], doc["reason"]), ("fail", "plan-unavailable"))
            self.assertIn("headSha", doc)


class SpringPremainDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = lane_run._checkout_metadata(ROOT)

    def run_floor_step(self, record, *, code=101, mode=0o600, metadata=None, private_canary=None):
        import contextlib
        import io
        import os
        from tools.qa import release_floor
        from tools.release import run_gates

        gate = next(gate for gate in run_gates.GATES if gate.name == "rust-workspace")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            wrapped, = release_floor.instrumented_gates((gate,), root, 7200)
            args = lane_run.parser().parse_args(wrapped.argv[4:])
            if private_canary is not None:
                canaries = root / "canaries.json"
                canaries.write_text(json.dumps({"fixture": private_canary}))
                args.canaries = str(canaries)
            recovery = lane_run.prepare_recovery(root)
            public = io.StringIO()

            def cargo(command, *, log, env, **kwargs):
                directory = pathlib.Path(env["XTRACE_CI_DIAG_DIR"])
                self.assertEqual(directory, recovery / "diagnostics")
                if record is not None:
                    path = directory / "spring-premain-order-wait.txt"
                    path.write_bytes(record)
                    path.chmod(mode)
                # Even a valid-looking record in child output has no diagnostic provenance.
                log.write(b"v2 error-request 2 1 present present present\ncaptured-value-731\n")
                return subprocess.CompletedProcess(command, code), False, None

            with contextlib.redirect_stdout(public), \
                    mock.patch.dict(os.environ, {"XTRACE_LANE_RECOVERY_DIR": str(recovery)}), \
                    mock.patch.object(lane_run, "_checkout_metadata", return_value=metadata or self.metadata), \
                    mock.patch.object(lane_run.rust_timing, "run", side_effect=cargo):
                rc = lane_run.cmd_run(args)
            fragment = (root / "frag" / "rust__-__rust-workspace.json").read_text()
            self.assertEqual(rc, code)
            self.assertNotIn("captured-value-731", fragment + public.getvalue())
            self.assertNotIn("v2 error-request 2 1", fragment + public.getvalue())
            return json.loads(fragment), fragment + public.getvalue()

    def test_failed_workspace_publishes_bounded_observations(self):
        for phase, state, expected, complete, matching, incomplete, drain, other in (
            ("successful-request", "no-complete-segment-rows", 1, 0, 0, "unavailable", "unavailable", "unavailable"),
            ("error-request", "no-matching-marker", 2, 16, 0, "not-observed", "not-observed", "not-observed"),
            ("attestation-mismatch", "insufficient-matching-rows", 3, 3, 2, "present", "present", "not-observed"),
            ("classfile-mutation", "insufficient-matching-rows", 4, 6, 3, "present", "unavailable", "present"),
        ):
            with self.subTest(phase=phase):
                record = f"v2 {phase} {complete} {matching} {incomplete} {drain} {other}\n"
                fragment, public = self.run_floor_step(record.encode())
                self.assertNotIn(record.strip(), public)
                self.assertEqual((fragment["status"], fragment["exitCode"], fragment["timedOut"]),
                                 ("fail", 101, False))
                self.assertEqual(fragment["springPremainOrderWait"], {
                    "status": "observed", "phase": phase, "state": state, "expectedRows": expected,
                    "completeRows": complete, "completeRowsLimit": 16, "matchingRows": matching,
                    "captureMarkers": {"incomplete": incomplete, "drainExpired": drain, "otherIncomplete": other},
                })

    def test_failed_workspace_withholds_unavailable_or_malformed_diagnostics(self):
        valid = b"v2 successful-request 0 0 present not-observed present\n"
        for record, mode, metadata in (
            (None, 0o600, None),
            (valid, 0o644, None),
            (valid, 0o600, lane_run.CheckoutMetadata({})),
            (b"v1 successful-request 0 0\n", 0o600, None),
            (valid.replace(b"successful-request", b"captured-value"), 0o600, None),
            (valid.replace(b" 0 0 ", b" 99999 0 "), 0o600, None),
            (valid.replace(b" 0 0 ", b" 17 0 "), 0o600, None),
            (valid.replace(b" 0 0 ", b" 00 0 "), 0o600, None),
            (b"v2 error-request 0 1 present present present\n", 0o600, None),
            (b"v2 error-request 2 2 present present present\n", 0o600, None),
            (valid.replace(b"not-observed", b"captured-value"), 0o600, None),
            (valid.replace(b"not-observed present", b"not-observed unavailable"), 0o600, None),
            (valid.replace(b"not-observed ", b""), 0o600, None),
            (valid.rstrip(), 0o600, None),
            (valid * 3, 0o600, None),
            (valid + b"/fixture/customer.txt\nb3:0123456789abcdef\n", 0o600, None),
        ):
            with self.subTest(record=record, mode=mode, head=metadata is None):
                fragment, public = self.run_floor_step(record, mode=mode, metadata=metadata)
                self.assertEqual(fragment["springPremainOrderWait"], {"status": "unavailable"})
                for value in ("captured-value", "99999", "/fixture/customer.txt", "b3:0123456789abcdef"):
                    self.assertNotIn(value, public)

    def test_canary_scan_still_checks_rebuilt_marker_observations(self):
        fragment, public = self.run_floor_step(
            b"v2 successful-request 0 0 present not-observed present\n", private_canary="not-observed")
        self.assertEqual(fragment["springPremainOrderWait"], {"status": "unavailable"})
        self.assertNotIn("not-observed", public)

    def test_successful_workspace_publishes_no_wait_failure(self):
        fragment, _ = self.run_floor_step(None, code=0)
        self.assertEqual((fragment["status"], fragment["exitCode"]), ("pass", 0))
        self.assertNotIn("springPremainOrderWait", fragment)


class RunTests(CheckoutFixture):
    def run_step(self, cmd, min_passed=0, timeout=60, max_ignored=-1, canaries=""):
        with tempfile.TemporaryDirectory() as d:
            args = type("A", (), {"suite": "meta", "variant": "-", "step": "t", "out": d + "/o", "cwd": "",
                                  "timeout": timeout, "min_passed": min_passed, "max_ignored": max_ignored,
                                  "canaries": canaries, "command": ["--"] + cmd})()
            import os
            with mock.patch.dict(os.environ, {"LANE_PRIVATE_LOG_DIR": d}):
                rc = lane_run.cmd_run(args)
            frag = json.loads((pathlib.Path(d) / "o/meta__-__t.json").read_text())
            return rc, frag

    def test_python_unittest_exception_and_non_rust_compiler_collisions_stay_private(self):
        import contextlib
        import io
        payload = "error[E0425]: customer data\n --> crates/a.rs:1:1"
        structured = DiagnosticsTests.compiler_record("E0425", "crates/a.rs", 1)
        commands = [
            [sys.executable, "-c", f"print({payload!r}); raise SystemExit(1)"],
            [sys.executable, "-c", f"print({structured!r}); raise SystemExit(1)"],
            [sys.executable, "-c", "import unittest\n"
             "class Probe(unittest.TestCase):\n"
             f" def test_value(self): raise AssertionError({'captured' + chr(10) + payload!r})\n"
             "unittest.main()\n"],
        ]
        for command in commands:
            with self.subTest(command=command):
                public = io.StringIO()
                with contextlib.redirect_stdout(public):
                    rc, frag = self.run_step(command)
                self.assertNotEqual(rc, 0)
                for value in ("E0425", "crates/a.rs", "customer data", "lane diagnostic "):
                    self.assertNotIn(value, public.getvalue())
                    self.assertNotIn(value, json.dumps(frag))

    def test_passing_negative_test_records_are_observations_without_failure_attribution(self):
        import contextlib
        import io
        import os
        text = "test first ... ok\ntest second ... FAILED\n"
        record = self.diagnostic("first", operation="NamedMetadata", kind="PermissionDenied", errno=13)
        body = ("import os, pathlib\n"
                "path = pathlib.Path(os.environ['XTRACE_CI_DIAG_DIR']) / 'private-storage.jsonl'\n"
                f"path.write_text({json.dumps(record) + chr(10)!r})\n"
                "path.chmod(0o600)\n"
                f"print({text!r})\nraise SystemExit(101)\n")
        public = io.StringIO()
        with contextlib.redirect_stdout(public), mock.patch.dict(os.environ, {"XTRACE_CI_DIAG_DIR": "enabled"}):
            rc, frag = self.run_step([sys.executable, "-c", body])
        self.assertEqual(rc, 101)
        detail = frag["failureDetails"]
        self.assertEqual([row["test"] for row in detail["failures"]], ["second"])
        self.assertEqual(detail["failures"][0]["category"], [])
        self.assertEqual(detail["observedDiagnostics"], [{
            "test": lane_run.UNVERIFIED, "relevance": "unknown",
            "thread": "first",
            "testUnverifiedReason": "diagnostic-thread-not-failing",
            "category": ["Admission", "NamedMetadata", "PermissionDenied", 13]}])
        logged = [json.loads(line.removeprefix("lane failure ")) for line in public.getvalue().splitlines()
                  if line.startswith("lane failure ")]
        self.assertEqual(logged, detail["failures"])
        observations = [json.loads(line.removeprefix("lane observed-diagnostic "))
                        for line in public.getvalue().splitlines() if line.startswith("lane observed-diagnostic ")]
        self.assertEqual(observations, detail["observedDiagnostics"])
        self.assertEqual(observations[0]["thread"], "first")
        # Only the explicit source-thread fact may expose the passing test's name.
        self.assertEqual(json.dumps(frag).count('"thread": "first"'), 1)
        self.assertEqual(public.getvalue().count('"thread": "first"'), 1)
        self.assertNotIn("first", json.dumps(frag).replace('"thread": "first"', ""))
        self.assertNotIn("first", public.getvalue().replace('"thread": "first"', ""))

    def test_acl_context_validation_in_fragment_and_job_log(self):
        import contextlib
        import io
        import os
        good = self.diagnostic(operation="AclState", site="ProbeState", changes=31, listing="InheritedAllow")
        cases = [(good, ["Admission", "AclState", "ProbeState", 31, "InheritedAllow"])]
        for field, values in {
            "site": ["Unknown", "InheritedAllow", "AclState", [], None, 13],
            "listing": ["Unknown", "ProbeState", "AclState", [], None, 13],
            "changes": [-1, 32, 10**100, True, False, "3", 3.5, [], None],
        }.items():
            cases.extend(({**good, field: value}, None) for value in values)
        cases.append(({**good, "message": "captured-value"}, None))
        cases.extend(({key: value for key, value in good.items() if key != field}, None)
                     for field in ("site", "changes", "listing"))
        for record, categories in cases:
            with self.subTest(record=record):
                def command(cmd, *, stdout, env, **kwargs):
                    path = pathlib.Path(env["XTRACE_CI_DIAG_DIR"]) / "private-storage.jsonl"
                    path.write_text(json.dumps(record) + "\n")
                    path.chmod(0o600)
                    stdout.write(b"test fails ... FAILED\n")
                    return subprocess.CompletedProcess(cmd, 101)

                public = io.StringIO()
                with contextlib.redirect_stdout(public), \
                        mock.patch.dict(os.environ, {"XTRACE_CI_DIAG_DIR": "enabled"}), \
                        mock.patch.object(lane_run.subprocess, "run", side_effect=command):
                    rc, frag = self.run_step(["unused-command"])
                self.assertEqual(rc, 101)
                observations = frag["failureDetails"].get("observedDiagnostics", [])
                expected = ([{"test": "fails", "relevance": "unknown", "category": categories}]
                            if categories is not None else [])
                self.assertEqual(observations, expected)
                logged = [json.loads(line.removeprefix("lane observed-diagnostic "))
                          for line in public.getvalue().splitlines()
                          if line.startswith("lane observed-diagnostic ")]
                self.assertEqual(logged, expected)
                self.assertEqual(frag["failureDetails"]["failures"][0]["category"], [])
                self.assertNotIn("captured-value", public.getvalue())
                self.assertNotIn("captured-value", json.dumps(frag))

    def test_new_fields_and_synthetic_threads_in_fragment_and_job_log(self):
        import contextlib
        import io
        import os
        synthetic = "diagnostic::ci::tests::contextual_record_contains_only_fixed_categories_and_a_difference_mask"
        self.assertIn(synthetic, self.metadata.rust_tests)
        fields = {"object": "Directory", "component_depth": -2, "nlink_changed": True,
                  "store_phase": "Append", "store_site": "JournalPublish"}
        context = {"operation": "AclState", "site": "Snapshot", "changes": 3, "listing": "InheritedAllow"}
        records = [self.diagnostic(**context, **fields),
                   self.diagnostic(synthetic, **context, **fields),
                   self.diagnostic("first", **context, **fields),
                   self.diagnostic(store_site="JournalPublish")]

        def command(cmd, *, stdout, env, **kwargs):
            path = pathlib.Path(env["XTRACE_CI_DIAG_DIR"]) / "private-storage.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records))
            path.chmod(0o600)
            stdout.write(f"test {synthetic} ... ok\ntest first ... ok\ntest fails ... FAILED\n".encode())
            return subprocess.CompletedProcess(cmd, 101)

        expected = [{"test": "fails", "relevance": "unknown",
                     "category": ["Admission", "AclState", "Snapshot", 3, "InheritedAllow"], **fields}]
        expected.extend({"test": lane_run.UNVERIFIED, "relevance": "unknown", "thread": thread,
                         "testUnverifiedReason": "diagnostic-thread-not-failing",
                         "category": ["Admission", "AclState", "Snapshot", 3, "InheritedAllow"], **fields}
                        for thread in (synthetic, "first"))
        expected.append({"test": "fails", "relevance": "unknown", "category": ["Admission", "Deadline"],
                         "store_site": "JournalPublish"})
        public = io.StringIO()
        with contextlib.redirect_stdout(public), \
                mock.patch.dict(os.environ, {"XTRACE_CI_DIAG_DIR": "enabled"}), \
                mock.patch.object(lane_run.subprocess, "run", side_effect=command):
            rc, frag = self.run_step(["unused-command"])
        self.assertEqual(rc, 101)
        detail = frag["failureDetails"]
        self.assertEqual(detail["observedDiagnostics"], expected)
        logged = [json.loads(line.removeprefix("lane observed-diagnostic "))
                  for line in public.getvalue().splitlines() if line.startswith("lane observed-diagnostic ")]
        self.assertEqual(logged, expected)
        self.assertEqual([row["test"] for row in detail["failures"]], ["fails"])
        self.assertEqual(detail["failures"][0]["category"], [])
        self.assertIs(type(logged[0]["nlink_changed"]), bool)

    def test_cargo_compile_reads_json_stdout_and_withholds_stderr(self):
        import contextlib
        import io
        command = ["cargo", "check", "--locked", "--message-format=json"]
        def compile_command(cmd, *, stdout, stderr, **kwargs):
            self.assertEqual(cmd, command)
            self.assertNotEqual(stderr, subprocess.STDOUT)
            stdout.write((DiagnosticsTests.compiler_record("E0425", "crates/a.rs", 1) + "\n").encode())
            stderr.write((DiagnosticsTests.compiler_record("E0001", "crates/b.rs", 2) + "\n").encode())
            return subprocess.CompletedProcess(cmd, 101)
        public = io.StringIO()
        with contextlib.redirect_stdout(public), mock.patch.object(lane_run.subprocess, "run", side_effect=compile_command):
            rc, frag = self.run_step(command)
        self.assertEqual(rc, 101)
        self.assertEqual(frag["status"], "fail")
        self.assertIn("lane diagnostic E0425 @ crates/a.rs:1", public.getvalue())
        self.assertNotIn("E0001", public.getvalue())
        self.assertNotIn("crates/b.rs", public.getvalue())

    def test_zero_tests_fails_with_min_passed(self):
        rc, frag = self.run_step([sys.executable, "-c", "print('Ran 0 tests in 0.0s')"], 1)
        self.assertNotEqual(rc, 0)
        self.assertEqual(frag["status"], "fail")

    def test_ignored_tests_fail_a_no_skips_step(self):
        out = "test result: ok. 5 passed; 0 failed; 2 ignored; 0 measured"
        rc, frag = self.run_step([sys.executable, "-c", f"print({out!r})"], 1, max_ignored=0)
        self.assertNotEqual(rc, 0)
        self.assertEqual(frag["status"], "fail")
        rc, frag = self.run_step([sys.executable, "-c", f"print({out!r})"], 1, max_ignored=2)
        self.assertEqual((rc, frag["status"]), (0, "pass"))

    def test_panic_sites_keep_only_repo_relative_locations(self):
        for site in ("/Users/me/secret/lib.rs:3:1", "../escape.rs:3:1", "crates/missing.rs:12:5"):
            rows = lane_run.failure_details(FailureDetailsTests.cargo(site=site, message="single-line failure", footer=False), False)["failures"]
            self.assertEqual(rows[0]["location"], lane_run.UNVERIFIED)
            self.assertEqual(rows[0]["panicSites"], [])
            self.assertNotIn(site, json.dumps(rows))

    def test_timeout_is_a_failed_step_not_a_traceback(self):
        rc, frag = self.run_step([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertEqual(rc, 124)
        self.assertEqual((frag["status"], frag["exitCode"]), ("fail", 124))

    def test_failed_command_writes_only_verified_facts_to_fragment(self):
        import contextlib
        import io
        public = io.StringIO()
        with contextlib.redirect_stdout(public):
            rc, frag = self.run_step([sys.executable, "-c",
                                      f"print({FailureDetailsTests.cargo()!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assertFalse(frag["timedOut"])
        row = frag["failureDetails"]["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["location"], row["kind"]),
                         ("fails", lane_run.UNVERIFIED, "exit"))
        self.assertEqual(len(frag["failureDetails"]["failures"]), 2)
        self.assertEqual(frag["failureDetails"]["failures"][1]["panicSites"], [])
        self.assertNotIn("left == right", public.getvalue())
        self.assertNotIn("left == right", json.dumps(frag))
        rc, frag = self.run_step([sys.executable, "-c",
                                  f"print({FailureDetailsTests.cargo(message='BODY_CANARY_123', footer=False)!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assert_facts_only(frag["failureDetails"]["failures"][0])
        self.assertNotIn("BODY_CANARY_123", json.dumps(frag))

    def test_failure_fragment_never_serializes_short_or_multiline_values(self):
        cases = [
            ("received ghp_abc123", ["received", "ghp_abc123"]),
            ('{"balance": 42}', ["balance", "42"]),
            ("account balance 123456", ["account", "balance", "123456"]),
            ("left: Account {\n balance: 42,\n}", ["Account", "balance", "42"]),
            ('left: "Ada\nshort ghp_abc123\n"', ["Ada", "short", "ghp_abc123"]),
        ]
        for message, private in cases:
            with self.subTest(message=message):
                text = FailureDetailsTests.cargo(message=message, site="crates/example/tests/journey.rs:88:6", footer=False)
                rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                self.assertEqual(rc, 101)
                row = frag["failureDetails"]["failures"][0]
                self.assertEqual(row["test"], "fails")
                self.assertEqual(row["location"], lane_run.UNVERIFIED if "\n" in message else "crates/example/tests/journey.rs:88")
                self.assert_facts_only(row)
                for value in private:
                    self.assertNotIn(value, json.dumps(frag))

    def test_failure_fragment_withholds_allowlisted_words_in_multiline_values(self):
        cases = [
            ('left: "secret\nnot persisted\n"', ["secret", "not persisted"]),
            ('left: "Ada\nright\n"', ["Ada", "right"]),
            ('left: "Ada\nnot persisted\n"', ["Ada", "not persisted"]),
            ("left: Account {\nnot persisted\nright\n}", ["Account", "not persisted", "right"]),
        ]
        for message, private in cases:
            with self.subTest(message=message):
                text = FailureDetailsTests.cargo(message=message, site="crates/example/tests/journey.rs:88:6", footer=False)
                rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                self.assertEqual(rc, 101)
                row = frag["failureDetails"]["failures"][0]
                self.assert_facts_only(row)
                self.assertEqual((row["test"], row["location"]), ("fails", lane_run.UNVERIFIED))
                self.assertGreater(row["withheldLines"], 1)
                for value in private:
                    self.assertNotIn(value, json.dumps(frag))

    def timed_out_step(self, text):
        def timeout(cmd, *, stdout, **kwargs):
            stdout.write(text.encode())
            stdout.flush()
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        with mock.patch.object(lane_run.subprocess, "run", side_effect=timeout):
            rc, frag = self.run_step(["unused-command"], timeout=3000)
        self.assertEqual(rc, 124)
        self.assertTrue(frag["timedOut"])
        self.assertEqual(frag["status"], "fail")
        return frag

    def test_timeout_publishes_categories_and_sites_in_fragment_and_job_log(self):
        import contextlib
        import io
        import os
        text = "test waiting ...\n" + FailureDetailsTests.cargo(name="fails", message="captured-value-731", footer=False)
        record = self.diagnostic(operation="WaitAclProbe", kind="PermissionDenied", errno=13)

        def timeout(cmd, *, stdout, env, **kwargs):
            directory = pathlib.Path(env["XTRACE_CI_DIAG_DIR"])
            self.assertTrue(directory.is_dir())
            path = directory / "private-storage.jsonl"
            path.write_text(json.dumps(record) + "\n")
            path.chmod(0o600)
            stdout.write(text.encode())
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        public = io.StringIO()
        with contextlib.redirect_stdout(public), \
                mock.patch.dict(os.environ, {"XTRACE_CI_DIAG_DIR": str(self.checkout)}), \
                mock.patch.object(lane_run.subprocess, "run", side_effect=timeout):
            rc, frag = self.run_step(["unused-command"], timeout=3000)
        self.assertEqual(rc, 124)
        row = frag["failureDetails"]["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["category"], [])
        observations = frag["failureDetails"]["observedDiagnostics"]
        self.assertEqual(observations, [{"test": "fails", "relevance": "unknown",
                                        "category": ["Admission", "WaitAclProbe", "PermissionDenied", 13]}])
        observed_log = [json.loads(line.removeprefix("lane observed-diagnostic "))
                        for line in public.getvalue().splitlines() if line.startswith("lane observed-diagnostic ")]
        self.assertEqual(observed_log, observations)
        self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])
        self.assertEqual(frag["failureDetails"]["timeout"]["runningTests"], ["waiting"])
        logged = [json.loads(line.removeprefix("lane failure ")) for line in public.getvalue().splitlines()
                  if line.startswith("lane failure ")]
        self.assertEqual(logged, [row])
        for value in ("captured-value-731", "AdmissionFailure", "raw_os_error"):
            self.assertNotIn(value, json.dumps(frag))
            self.assertNotIn(value, public.getvalue())

    def test_complete_rendering_collisions_and_compiler_payloads_stay_private(self):
        import contextlib
        import io
        messages = [
            "operation=Deadline kind=None raw_os_error=Some(42)",
            'assertion `left == right` failed\n  left: "operation=Deadline kind=None raw_os_error=Some(42)"\n right: "ok"',
            "error: customer Ada owes 42\n --> crates/a.rs:1:1",
            "error: CANARY\n --> crates/a.rs:1:1",
            "error[E0425]: customer Ada owes 42\n --> crates/a.rs:1:1",
            "---- second stdout ----\nthread 'second' panicked at crates/b.rs:2:4:\noperation=Deadline kind=None raw_os_error=None",
            "thread 'second' panicked at crates/b.rs:2:4:\noperation=Deadline kind=None raw_os_error=None",
        ]
        for message in messages:
            with self.subTest(message=message):
                text = FailureDetailsTests.cargo(name="first", message=message, site="crates/a.rs:1:2", footer=False)
                public = io.StringIO()
                with contextlib.redirect_stdout(public):
                    rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                self.assertEqual(rc, 101)
                rows = frag["failureDetails"]["failures"]
                for row in rows:
                    self.assertEqual(row["category"], [])
                if "\n" in message:
                    for row in rows:
                        self.assertEqual(row["panicSites"], [])
                        self.assertEqual(row["location"], lane_run.UNVERIFIED)
                    self.assertEqual(rows[-1]["test"], lane_run.UNVERIFIED)
                    self.assertEqual(rows[-1]["testUnverifiedReason"], "ambiguous-panic-block")
                logged = [json.loads(line.removeprefix("lane failure ")) for line in public.getvalue().splitlines()
                          if line.startswith("lane failure ")]
                self.assertEqual(logged, rows)
                for value in ("Deadline", "42", "Ada", "CANARY", "E0425", "second", "crates/b.rs", "lane diagnostic "):
                    self.assertNotIn(value, json.dumps(frag))
                    self.assertNotIn(value, public.getvalue())

    def test_section_shaped_multiline_payload_cannot_assign_the_second_test(self):
        import contextlib
        import io
        text = ("test first ... FAILED\ntest second ... FAILED\n"
                "---- first stdout ----\n"
                "thread 'first' panicked at crates/a.rs:1:2:\n"
                "captured prose\n---- second stdout ----\n"
                "thread 'second' panicked at crates/b.rs:2:4:\n"
                "operation=Deadline kind=None raw_os_error=None\n")
        public = io.StringIO()
        with contextlib.redirect_stdout(public):
            rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        rows = frag["failureDetails"]["failures"]
        self.assertEqual([row["test"] for row in rows], ["first", "second", lane_run.UNVERIFIED])
        for row in rows:
            self.assertEqual((row["location"], row["panicSites"], row["category"]),
                             (lane_run.UNVERIFIED, [], []))
        logged = [json.loads(line.removeprefix("lane failure ")) for line in public.getvalue().splitlines()
                  if line.startswith("lane failure ")]
        self.assertEqual(logged, rows)
        self.assertEqual(rows[-1]["testUnverifiedReason"], "ambiguous-panic-block")
        for value in ("crates/a.rs", "crates/b.rs", "Deadline", "captured prose"):
            self.assertNotIn(value, json.dumps(frag))
            self.assertNotIn(value, public.getvalue())

    def test_interleaving_with_terminal_status_never_attributes_a_message(self):
        import contextlib
        import io
        text = ("thread 'first' panicked at crates/a.rs:1:2:\n"
                "test first ... FAILED\n"
                "thread 'second' panicked at crates/b.rs:2:4:\n"
                "operation=Deadline kind=None raw_os_error=None\n")
        public = io.StringIO()
        with contextlib.redirect_stdout(public):
            rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        rows = frag["failureDetails"]["failures"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["test"], rows[0]["location"], rows[0]["panicSites"], rows[0]["category"]),
                         (lane_run.UNVERIFIED, lane_run.UNVERIFIED, [], []))
        self.assertEqual(rows[0]["testUnverifiedReason"], "ambiguous-panic-block")
        self.assertEqual(frag["failingTests"], [])
        for value in ("first", "second", "Deadline", "crates/a.rs", "crates/b.rs"):
            self.assertNotIn(value, json.dumps(frag))
            self.assertNotIn(value, public.getvalue())

    def test_current_headers_have_fragment_and_job_log_parity_in_all_output_modes(self):
        import contextlib
        import io
        message = ("parent: Admission(AdmissionFailure { operation: OwnershipAndMode, "
                   "kind: None, raw_os_error: None })")
        header = "thread 'fails' (987654321) panicked at crates/example/tests/journey.rs:42:7:\n"
        cases = [
            ("captured", FailureDetailsTests.cargo(name="fails", message=message, thread_id=987654321, footer=False), False),
            ("nocapture", header + message + "\ntest fails ... FAILED\n", False),
            ("timeout", "test fails ...\n" + header + message + "\n", True),
            ("captured-timeout", "---- fails stdout ----\n" + header + message + "\n", True),
        ]
        for mode, text, timed_out in cases:
            with self.subTest(mode=mode):
                public = io.StringIO()
                with contextlib.redirect_stdout(public):
                    if timed_out:
                        frag = self.timed_out_step(text)
                    else:
                        rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                        self.assertEqual(rc, 101)
                self.assertEqual(frag["timedOut"], timed_out)
                self.assertEqual(len(frag["failureDetails"]["failures"]), 1)
                row = frag["failureDetails"]["failures"][0]
                self.assert_facts_only(row)
                if mode == "nocapture":
                    self.assertEqual((row["test"], row["location"], row["panicSites"]),
                                     (lane_run.UNVERIFIED, lane_run.UNVERIFIED, []))
                    self.assertEqual(row["testUnverifiedReason"], "ambiguous-panic-block")
                else:
                    self.assertEqual((row["test"], row["location"], row["kind"]),
                                     ("fails", "crates/example/tests/journey.rs:42", "panic"))
                    self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])
                self.assertEqual(row["category"], [])
                logged = [json.loads(line.removeprefix("lane failure "))
                          for line in public.getvalue().splitlines() if line.startswith("lane failure ")]
                self.assertEqual(logged, [row])
                for value in ("987654321", "parent:", "AdmissionFailure", "raw_os_error"):
                    self.assertNotIn(value, json.dumps(frag))
                    self.assertNotIn(value, public.getvalue())

    def test_timeout_fragment_never_serializes_progress_values(self):
        cases = [
            ("Finished ghp_abc123\n", ["ghp_abc123"], [], []),
            ("Finished balance 42\n", ["balance", "42"], [], []),
            ("Compiling balance 42\n", ["balance", "42"], [], []),
            ("Compiling example v1.2.3 balance 42\n", ["balance", "42"], [], []),
            ("FooTest > check(ghp_abc123) STARTED\n", ["ghp_abc123"],
             [{"test": "FooTest::check", "state": "running"}], ["FooTest::check"]),
            ("FooTest > check(balance 42) STARTED\n", ["balance", "42"],
             [{"test": "FooTest::check", "state": "running"}], ["FooTest::check"]),
            ("balance 42\n", ["balance", "42"], [], []),
        ]
        for text, private, progress, running in cases:
            with self.subTest(text=text):
                frag = self.timed_out_step(text)
                self.assertEqual(frag["failureDetails"]["timeout"]["progress"], progress)
                self.assertEqual(frag["failureDetails"]["timeout"]["runningTests"], running)
                for value in private:
                    self.assertNotIn(value, json.dumps(frag))

    def test_timeout_fragment_uses_output_written_before_timeout(self):
        frag = self.timed_out_step("test waiting has been running for over 60 seconds\n")
        self.assertEqual(frag["failureDetails"]["timeout"]["runningTests"], ["waiting"])
        self.assertEqual(frag["failureDetails"]["timeout"]["progress"], [{"test": "waiting", "state": "running"}])

    def test_review_panic_allowlisted_words_publish_no_prose(self):
        text = FailureDetailsTests.cargo(message="not persisted", footer=False)
        rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assertNotIn("not persisted", json.dumps(frag))
        row = frag["failureDetails"]["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["location"], row["kind"]),
                         ("fails", "crates/example/tests/journey.rs:42", "panic"))

    def test_review_cargo_build_metadata_never_reaches_timeout_progress(self):
        frag = self.timed_out_step("Compiling example v1.2.3+customer42\n")
        self.assertEqual(frag["failureDetails"]["timeout"]["progress"], [])
        for value in ("Compiling", "example", "v1.2.3", "customer42"):
            self.assertNotIn(value, json.dumps(frag))

    def test_review_location_shaped_panic_continuation_is_not_a_location(self):
        message = 'left: "Ada\nError at ghp_abc123.java:7\n"'
        text = FailureDetailsTests.cargo(message=message, footer=False)
        rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assertEqual(frag["failureDetails"]["failures"][0]["location"], lane_run.UNVERIFIED)
        for value in ("Ada", "Error at", "ghp_abc123.java:7", "ghp_abc123"):
            self.assertNotIn(value, json.dumps(frag))

    def test_review_timeout_does_not_rescan_quoted_panic_progress(self):
        message = 'left: "Ada\nCompiling ghp_abc123 v1.2.3\n"'
        frag = self.timed_out_step(FailureDetailsTests.cargo(message=message, footer=False))
        self.assertEqual(frag["failureDetails"]["timeout"]["progress"], [{"test": "fails", "state": "failed"}])
        for value in ("Ada", "Compiling", "ghp_abc123", "v1.2.3"):
            self.assertNotIn(value, json.dumps(frag))

    def test_verified_names_inside_quoted_values_are_not_harness_progress(self):
        message = ('left: "Ada\ntest waiting ...\n'
                   'FooTest > check(ghp_abc123) STARTED\n'
                   '---- waiting stdout ----\n'
                   "thread 'waiting' panicked at crates/b.rs:1:2:\n"
                   'Error at HttpTest.java:7\n"')
        frag = self.timed_out_step(FailureDetailsTests.cargo(message=message, footer=False))
        detail = frag["failureDetails"]
        self.assertEqual(len(detail["failures"]), 2)
        self.assertEqual(detail["failures"][0]["location"], lane_run.UNVERIFIED)
        self.assertEqual(detail["timeout"]["progress"], [{"test": "fails", "state": "failed"}])
        self.assertEqual(detail["timeout"]["runningTests"], [])
        for value in ("Ada", "ghp_abc123", "HttpTest.java", "crates/b.rs", "waiting"):
            self.assertNotIn(value, json.dumps(frag))

    def test_unverified_names_never_leave_the_fragment(self):
        for name in ("ghp_abc123", "customer42::fails"):
            with self.subTest(name=name):
                text = FailureDetailsTests.cargo(name=name)
                rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                self.assertEqual(rc, 101)
                self.assertNotIn(name, json.dumps(frag))
                self.assertEqual(frag["failureDetails"]["failures"][0]["test"],
                                 "fails" if name.endswith("::fails") else lane_run.UNVERIFIED)
        frag = self.timed_out_step("test ghp_abc123 ...\n")
        self.assertEqual(frag["failureDetails"]["timeout"]["progress"], [])
        self.assertEqual(frag["failureDetails"]["timeout"]["runningTests"], [])
        self.assertNotIn("ghp_abc123", json.dumps(frag))

    def test_requested_unreadable_canary_file_withholds_all_failure_details(self):
        with tempfile.TemporaryDirectory() as temporary:
            rc, frag = self.run_step([sys.executable, "-c", "raise SystemExit(101)"],
                                      canaries=str(pathlib.Path(temporary) / "missing.json"))
        self.assertEqual(rc, 101)
        self.assertIsNone(frag["failureDetails"])
        self.assertEqual(frag["failureDetailsUnavailable"], lane_run.WITHHELD)

    def test_fragments_share_job_cap_across_failed_steps(self):
        import os
        text = "".join(f"test case{i} ... FAILED\n" for i in range(32))

        def failed(cmd, *, stdout, **kwargs):
            stdout.write(text.encode())
            return subprocess.CompletedProcess(cmd, 101)

        # Fact-only rows are small; use a budget that eight fragments can exhaust.
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.dict(os.environ, {"LANE_PRIVATE_LOG_DIR": temporary}), \
                mock.patch.object(lane_run.subprocess, "run", side_effect=failed), \
                mock.patch.object(lane_run, "MAX_JOB_EXCERPT_BYTES", 4096):
            args = type("A", (), {"suite": "rust", "variant": "-", "step": "first", "out": temporary + "/o",
                                  "cwd": "", "timeout": 3000, "min_passed": 0, "command": ["unused-command"]})()
            for step in ("first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth"):
                args.step = step
                self.assertEqual(lane_run.cmd_run(args), 101)
            fragments = [json.loads(p.read_text()) for p in pathlib.Path(args.out).glob("*.json")]
            self.assertEqual(len(fragments), 8)
            self.assertLessEqual(sum(len(lane_run._encoded(f["failureDetails"])) for f in fragments
                                     if f["failureDetails"] is not None), lane_run.MAX_JOB_EXCERPT_BYTES)
            self.assertTrue(any(f.get("failureDetailsUnavailable") == "job excerpt cap" for f in fragments))

    def test_uncounted_step_reports_null(self):
        rc, frag = self.run_step([sys.executable, "-c", "print('hi')"])
        self.assertEqual(rc, 0)
        self.assertIsNone(frag["passed"])
        self.assertNotIn("failureDetails", frag)


class ErrorHintTests(CheckoutFixture):
    def test_allowlisted_codes_and_categories_only(self):
        text = "\n".join([
            'Err(Error { code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource, message: "at /Users/x" })',
            'code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource,',
            'code: ErrorCode("xtr-lower"), category: Bogus,',
            'code: ErrorCode("XTR-/home/me"), category: Internal,',
            'code: ErrorCode("OTHER-1"), category: Policy,',
        ])
        rows = lane_run.failure_details(FailureDetailsTests.cargo(message=text, footer=False), False)["failures"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["category"], [])
            self.assertEqual(row["panicSites"], [])
        self.assertNotIn("XTR-STORE-OBJECT-IO", json.dumps(rows))

    def test_hints_are_bounded(self):
        text = "\n".join(f'ErrorCode("XTR-E{i}"), category: Internal,' for i in range(40))
        rows = lane_run.failure_details(FailureDetailsTests.cargo(message=text, footer=False), False)["failures"]
        for row in rows:
            self.assertEqual(row["category"], [])
            self.assertEqual(row["panicSites"], [])
        self.assertNotIn("Internal", json.dumps(rows))
        self.assertNotIn("XTR-E", json.dumps(rows))

    def test_failing_step_withholds_all_free_text_hints(self):
        with tempfile.TemporaryDirectory() as d:
            body = ('print("test a::b ... FAILED"); '
                    'print(\'Err(code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource, message: "/Users/me/secret")\'); '
                    'raise SystemExit(101)')
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", "t",
                 "--out", d, "--", sys.executable, "-c", body],
                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("lane error-code", proc.stdout)
            self.assertNotIn("lane error-category", proc.stdout)
            self.assertNotIn("/Users", proc.stdout)
            self.assertNotIn("secret", proc.stdout)

    def test_passing_step_prints_no_hints(self):
        with tempfile.TemporaryDirectory() as d:
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", "t",
                 "--out", d, "--", sys.executable, "-c", 'print(\'ErrorCode("XTR-A"), category: Internal,\')'],
                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
            self.assertEqual(proc.returncode, 0)
            self.assertNotIn("error-code", proc.stdout)


class LintTests(unittest.TestCase):
    def test_repo_workflows_pass_lint(self):
        files = [str(p) for p in (ROOT / ".github/workflows").glob("*.yml")]
        r = subprocess.run([sys.executable, "-B", "-m", "tools.qa.workflow_lint", *files], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


class DiagnosticsTests(CheckoutFixture):
    command = ["cargo", "check", "--message-format=json"]

    @staticmethod
    def compiler_record(code, path, line, *, level="error"):
        return json.dumps({"reason": "compiler-message", "message": {
            "level": level, "code": {"code": code}, "message": "captured value",
            "rendered": "private compiler prose", "spans": [
                {"is_primary": True, "file_name": path, "line_start": line,
                 "text": [{"text": "captured source value"}]}]}})

    def test_pairs_error_with_location_and_skips_noise(self):
        text = "\n".join([
            "warning: unused variable: `x`",
            "error[E0001]: captured value\n --> crates/a.rs:1:1",
            self.compiler_record("E0002", "crates/a.rs", 1, level="warning"),
            self.compiler_record("clippy::panic", "crates/a.rs", 1),
            self.compiler_record("E0425", "crates/b.rs", 2),
            json.dumps({"reason": "build-script-executed", "message": "captured value"}),
        ])
        diags, dropped = lane_run.diagnostics(text, command=self.command)
        self.assertEqual(dropped, 0)
        self.assertEqual(diags, ["E0425 @ crates/b.rs:2"])
        for value in ("captured", "value", "clippy", "private", "E0001", "E0002"):
            self.assertNotIn(value, json.dumps(diags))

    def test_host_paths_and_secrets_are_dropped_and_counted(self):
        text = "\n".join(self.compiler_record(code, path, line) for code, path, line in [
            ("E0001", "/home/runner/work/x/src/lib.rs", 1),
            ("E0002", "crates/a.rs", 99), ("E0003", "../escape/src/lib.rs", 3)])
        diags, dropped = lane_run.diagnostics(text, command=self.command)
        self.assertEqual(diags, [])
        self.assertEqual(dropped, 3)
        index = lane_run.canary.build_index({"site": "crates/a.rs", "code": "E0004"})
        self.assertEqual(lane_run.diagnostics(self.compiler_record("E0004", "crates/a.rs", 1),
                                             command=self.command, index=index), ([], 1))

    def test_bounded(self):
        text = "\n".join(self.compiler_record("E0425", "crates/example/tests/journey.rs", i)
                         for i in range(1, 40))
        diags, dropped = lane_run.diagnostics(text, command=self.command)
        self.assertEqual(len(diags), lane_run.MAX_DIAG)
        self.assertEqual(dropped, 39 - lane_run.MAX_DIAG)

    def test_test_and_mixed_commands_never_attest_even_structured_compiler_values(self):
        text = self.compiler_record("E0425", "crates/a.rs", 1)
        for command in ([], ["cargo", "test", "--message-format=json"],
                        ["cargo", "check"], ["npm", "test"], ["python3", "-m", "unittest"],
                        ["cargo", "check", "--message-format=json", "--message-format=human"],
                        ["bash", "-c", "cargo check --message-format=json"]):
            with self.subTest(command=command):
                self.assertEqual(lane_run.diagnostics(text, command=command), ([], 0))

    def test_malformed_records_do_not_supply_compiler_fields(self):
        for record in (None, [], {"reason": "compiler-message", "message": []},
                       {"reason": "compiler-message", "message": {"level": "error", "code": []}}):
            self.assertEqual(lane_run.diagnostics(json.dumps(record), command=self.command), ([], 0))


class CountTests(unittest.TestCase):
    def test_node_test_summary_counts(self):
        r = lane_run.parse_output("\u2139 tests 12\n\u2139 pass 11\n\u2139 fail 1\n\u2139 skipped 0")
        self.assertEqual((r["passed"], r["failed"]), (11, 1))

    def test_vitest_summary_counts(self):
        r = lane_run.parse_output("      Tests  2 failed | 40 passed (42)")
        self.assertEqual((r["passed"], r["failed"]), (40, 2))
        r = lane_run.parse_output("      Tests  40 passed (40)")
        self.assertEqual((r["passed"], r["failed"]), (40, 0))
        r = lane_run.parse_output("\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m162 passed\x1b[39m\x1b[22m | 2 skipped\x1b[90m (164)\x1b[39m")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (162, 0, 2))
        r = lane_run.parse_output("      Tests  1 failed | 70 passed | 3 skipped | 1 todo (75)")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (70, 1, 4))
        r = lane_run.parse_output("      Test Files  1 failed | 5 passed (6)")
        self.assertFalse(r["counted"])

    def test_unittest_skips_are_ignored_tests(self):
        r = lane_run.parse_output("Ran 10 tests in 0.1s\n\nOK (skipped=3)")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (7, 0, 3))
        r = lane_run.parse_output("Ran 10 tests in 0.1s\n\nFAILED (failures=1, skipped=2)")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (7, 1, 2))
        r = lane_run.parse_output("Ran 10 tests in 0.1s\n\nOK")
        self.assertEqual((r["passed"], r["failed"], r["ignored"]), (10, 0, 0))

    def test_vitest_skip_fails_a_no_skips_step(self):
        with tempfile.TemporaryDirectory() as d:
            for skipped, want in ((0, "pass"), (1, "fail")):
                out = f"      Tests  70 passed | {skipped} skipped (71)" if skipped else "      Tests  70 passed (70)"
                proc = subprocess.run(
                    [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "web", "--step", "u",
                     "--min-passed", "70", "--max-ignored", "0", "--out", d, "--", sys.executable, "-c",
                     f"print({out!r})"],
                    cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
                frag = json.loads((pathlib.Path(d) / "web__-__u.json").read_text())
                self.assertEqual(frag["status"], want)
                self.assertEqual(proc.returncode == 0, want == "pass")

    def _junit(self, d, tests, failures=0, skipped=0):
        (pathlib.Path(d) / "m" / "build" / "test-results" / "test").mkdir(parents=True, exist_ok=True)
        (pathlib.Path(d) / "m" / "build" / "test-results" / "test" / "TEST-a.xml").write_text(
            f'<testsuite name="a" tests="{tests}" failures="{failures}" errors="0" skipped="{skipped}"/>')

    def test_junit_counts_and_missing_reports(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(lane_run.junit_counts(pathlib.Path(d), "*/build/test-results/test/*.xml"))
            self._junit(d, 10, failures=1, skipped=2)
            self.assertEqual(lane_run.junit_counts(pathlib.Path(d), "*/build/test-results/test/*.xml"),
                             {"passed": 7, "failed": 1, "ignored": 2})

    def test_zero_tests_below_minimum_is_a_failure(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "out"
            for tests, want in ((3, "fail"), (0, "fail"), (5, "pass")):
                self._junit(d, tests)
                rc = subprocess.run([sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "java",
                                     "--step", "t", "--cwd", d, "--junit-glob", "*/build/test-results/test/*.xml",
                                     "--min-passed", "5", "--out", str(out), "--", sys.executable, "-c", "pass"],
                                    cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d}).returncode
                frag = json.loads((out / "java__-__t.json").read_text())
                self.assertEqual(frag["status"], want)
                self.assertEqual(rc == 0, want == "pass")

    def test_countless_step_cannot_satisfy_a_minimum(self):
        with tempfile.TemporaryDirectory() as d:
            rc = subprocess.run([sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "node", "--step", "t",
                                 "--min-passed", "1", "--out", d, "--", sys.executable, "-c", "print('hi')"],
                                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d}).returncode
            self.assertNotEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
