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
        names = ["fails", "first", "second", "journey", "completed", "waiting", "also_waiting",
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
                "pub enum AdmissionOperation { Deadline, WaitAclProbe, NamedMetadata, OwnershipAndMode, }\n"),
        }
        for name, source in self.sources.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        self.metadata = lane_run.CheckoutMetadata(self.sources)
        patcher = mock.patch.object(lane_run, "_checkout_metadata", return_value=self.metadata)
        patcher.start()
        self.addCleanup(patcher.stop)

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
              site="crates/example/tests/journey.rs:42:7", thread_id=None):
        tid = f" ({thread_id})" if thread_id is not None else ""
        return (f"test {name} ... FAILED\n\nfailures:\n\n---- {name} stdout ----\n"
                f"thread '{name}'{tid} panicked at {site}:\n"
                f"{message}\nnote: run with RUST_BACKTRACE=1\n\nfailures:\n    {name}\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored\n")

    def test_cargo_captured_failure_has_only_verified_facts_and_line_counts(self):
        detail = lane_run.failure_details(self.cargo(), False)
        row = detail["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["location"], row["kind"]),
                         ("fails", "crates/example/tests/journey.rs:42", "assertion"))
        self.assertEqual(row["withheldLines"], 4)
        self.assertNotIn("left == right", json.dumps(detail))

    def test_cargo_nocapture_panics_are_associated_with_their_own_tests(self):
        text = ("unrelated stdout\n"
                "thread 'first' panicked at crates/a.rs:1:2:\nfirst assertion\n"
                "test first ... FAILED\n"
                "thread 'second' panicked at crates/b.rs:2:4:\nsecond assertion\n"
                "test second ... FAILED\n")
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual([(r["test"], r["location"], r["kind"]) for r in rows],
                         [("first", "crates/a.rs:1", "panic"), ("second", "crates/b.rs:2", "panic")])
        for row in rows:
            self.assert_facts_only(row)
        for value in ("unrelated", "first assertion", "second assertion"):
            self.assertNotIn(value, json.dumps(rows))

    def test_private_storage_categories_from_realistic_debug_and_display_panics(self):
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
        for message, expected in cases:
            with self.subTest(message=message):
                row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertEqual(row["category"], expected)
                self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])

    def test_categories_withhold_paths_values_unknown_identifiers_and_other_numbers(self):
        message = ('Admission(AdmissionFailure { operation: NamedMetadata, kind: Some(PermissionDenied), '
                   'raw_os_error: Some(13) })\n'
                   'path=/private/Deadline/Unavailable customer-731 balance: 42 UnknownDiagnostic 999999\n'
                   'raw_os_error: Some(999999) raw_os_error: Some(-13) raw_os_error: Some(0)\n'
                   'raw_os_error: Some(201) raw_os_error: Some(013) raw_os_error: Some(13.5)')
        row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["category"], ["Admission", "NamedMetadata", "PermissionDenied", 13])
        for value in ("/private", "Deadline", "Unavailable", "customer-731", "balance", "42",
                      "UnknownDiagnostic", "999999", "201", "013", "13.5"):
            self.assertNotIn(value, json.dumps(row["category"]))

    def test_errno_boundaries_and_category_count_are_bounded_and_deduplicated(self):
        message = " ".join(f"operation=Deadline kind=None raw_os_error=Some({errno})"
                           for errno in (1, 200, 1))
        message += " " + " ".join(f"operation=Deadline kind=Some({kind}) raw_os_error=None"
                                  for kind in sorted(lane_run.IO_ERROR_KINDS))
        row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["category"][:3], ["Deadline", 1, 200])
        self.assertEqual(len(row["category"]), lane_run.MAX_CATEGORIES)

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
                row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
                self.assertEqual(row["category"], [])
                self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])
                self.assert_facts_only(row)

    def test_only_complete_rendering_fields_survive_surrounding_prose(self):
        message = ("Deadline PermissionDenied 42 raw_os_error=Some(99) before: "
                   "Admission(AdmissionFailure { operation: OwnershipAndMode, kind: None, raw_os_error: None })"
                   " after TimedOut 13 raw_os_error: Some(60)")
        row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
        self.assertEqual(row["category"], ["Admission", "OwnershipAndMode"])
        self.assert_facts_only(row)

    def test_parallel_uncaptured_headers_withhold_test_attribution(self):
        for tid in ("", " (987654321)"):
            text = (f"thread 'first'{tid} panicked at crates/a.rs:1:2:\n"
                    f"thread 'second'{tid} panicked at crates/b.rs:2:4:\n"
                    "operation=Deadline kind=None raw_os_error=Some(13)\n"
                    "operation=NamedMetadata kind=Some(PermissionDenied) raw_os_error=Some(42)\n"
                    "test first ... FAILED\ntest second ... FAILED\n")
            with self.subTest(tid=tid):
                rows = lane_run.failure_details(text, False)["failures"]
                self.assertEqual([row["test"] for row in rows], ["first", "second", lane_run.UNVERIFIED])
                for row in rows[:2]:
                    self.assertEqual((row["location"], row["panicSites"], row["category"]),
                                     (lane_run.UNVERIFIED, [], []))
                self.assertEqual(rows[2]["testUnverifiedReason"], "ambiguous-panic-block")
                self.assertEqual(rows[2]["panicSites"], ["crates/a.rs:1", "crates/b.rs:2"])
                self.assertEqual(rows[2]["category"], [])
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
        self.assertEqual(rows[1]["panicSites"], ["crates/a.rs:1", "crates/b.rs:2"])
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
        self.assertEqual(rows[1]["panicSites"], ["crates/a.rs:1", "crates/b.rs:2"])

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
                                 (lane_run.UNVERIFIED, "ambiguous-panic-block", ["crates/b.rs:2"]))
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
                "operation=Deadline kind=None raw_os_error=None\n"
                "---- first stderr ----\n"
                "thread 'first' panicked at crates/a.rs:2:3:\n"
                "operation=Deadline kind=Some(TimedOut) raw_os_error=None\n"
                "---- second stdout ----\n"
                "thread 'second' panicked at crates/b.rs:2:4:\n"
                "operation=NamedMetadata kind=None raw_os_error=Some(13)\n")
        rows = lane_run.failure_details(text, False)["failures"]
        self.assertEqual([(r["test"], r["panicSites"], r["category"]) for r in rows], [
            ("first", ["crates/a.rs:1", "crates/a.rs:2"], ["Deadline", "TimedOut"]),
            ("second", ["crates/b.rs:2"], ["NamedMetadata", 13]),
        ])
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
                         ("waiting", ["crates/a.rs:1"], ["Deadline", "TimedOut"]))
        self.assertEqual(lane_run.failure_details(text + "test waiting ... ok\n", True)["failures"], [])

    def test_panic_sites_are_bounded_and_backtraces_cannot_add_categories(self):
        text = "test fails ... FAILED\n---- fails stdout ----\n" + "".join(
            "---- fails stderr ----\n"
            f"thread 'fails' panicked at crates/example/tests/journey.rs:{i + 1}:2:\n"
            "operation=Deadline kind=None raw_os_error=None\n"
            for i in range(lane_run.MAX_PANIC_SITES + 3))
        text += "stack backtrace:\noperation=NamedMetadata kind=Some(PermissionDenied) raw_os_error=Some(13)\n"
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["category"], ["Deadline"])
        self.assertEqual(row["panicSites"], [f"crates/example/tests/journey.rs:{i + 1}"
                                             for i in range(lane_run.MAX_PANIC_SITES)])

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

    def test_backtrace_and_secondary_capture_cannot_erase_verified_location(self):
        text = ("test fails ... FAILED\n---- fails stdout ----\n"
                "thread 'fails' panicked at crates/a.rs:1:2:\nfirst assertion\n"
                "stack backtrace:\n0: irrelevant stack\n"
                "---- fails stderr ----\nother output\n")
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["location"], "crates/a.rs:1")
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
                         (lane_run.UNVERIFIED, "crates/a.rs:1", "panic"))
        self.assertEqual(rows[1]["testUnverifiedReason"], "name-not-declared-in-head")
        for row in rows:
            self.assert_facts_only(row)
        self.assertNotIn("worker", json.dumps(rows))

    def test_unsafe_panic_location_is_never_published_as_a_source_site(self):
        for path in ("../escape.rs", "/absolute/file.rs", "crates/missing.rs",
                     "crates/example/tests/../journey.rs", "crates/example/tests/journey.rs/extra"):
            with self.subTest(path=path):
                row = lane_run.failure_details(self.cargo(site=f"{path}:1:2"), False)["failures"][0]
                self.assertEqual(row["location"], lane_run.UNVERIFIED)
                self.assertNotIn(path, json.dumps(row))
        for line in (0, 100000):
            row = lane_run.failure_details(self.cargo(site=f"crates/a.rs:{line}:2"), False)["failures"][0]
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
                row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
                self.assert_facts_only(row)
                self.assertGreater(row["withheldLines"], 0)
                self.assertNotIn(message, json.dumps(row))

    def test_byte_cap_preserves_the_continuation_withholding_count(self):
        row = lane_run.failure_details(self.cargo(message="é " * 10000 + "\nright"), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["withheldLines"], 3)
        self.assertNotIn("right", json.dumps(row))

    def test_job_cap_and_omitted_count(self):
        text = "".join(self.cargo(name=f"case{i}", message="x " * 3000) for i in range(32))
        # Rows no longer grow with prose; exercise the same cap with a smaller
        # caller-supplied budget rather than depending on retained message bytes.
        detail = lane_run.failure_details(text, False, budget=2048)
        self.assertLessEqual(len(lane_run._encoded(detail)), 2048)
        self.assertGreater(detail["omitted"], 0)
        self.assertEqual(len(detail["failures"]) + detail["omitted"], 32)
        self.assertIsNone(lane_run.failure_details(text, False, budget=0))

    def test_canary_anywhere_in_block_is_absent_from_failure_facts(self):
        text = self.cargo(message="safe assertion\n" + "safe line\n" * 20 + "BODY_CANARY_123")
        row = lane_run.failure_details(text, False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual((row["test"], row["location"]), ("fails", "crates/example/tests/journey.rs:42"))
        for value in ("safe assertion", "safe line", "BODY_CANARY_123"):
            self.assertNotIn(value, json.dumps(row))

    def test_unmarked_values_are_absent_but_test_and_source_site_survive(self):
        for value in ("left: ghp_abc123", "right: account balance", "expected: customer-record",
                      "actual customer-record", "result=customer-record"):
            with self.subTest(value=value):
                self.assertFalse(lane_run._private(value, lane_run.CANARY_INDEX))
                row = lane_run.failure_details(self.cargo(message=value), False)["failures"][0]
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
                row = lane_run.failure_details(self.cargo(message=message), False)["failures"][0]
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
                                                            site="crates/example/tests/journey.rs:88:6"), False)
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
                                                            site="crates/example/tests/journey.rs:88:6"), False)
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
                                                             site="crates/example/tests/journey.rs:88:6"), False)["failures"][0]
                    self.assert_facts_only(row)
                    self.assertEqual(row["kind"], "assertion")
                    self.assertNotIn(message, json.dumps(row))
                    self.assertNotIn(operator, json.dumps(row))
                    self.assertNotIn(left, json.dumps(row))
                    self.assertNotIn(right, json.dumps(row))

    def test_fixed_deadline_diagnostic_and_request_values_are_absent_end_to_end(self):
        message = "3 POST /orders recordings were not persisted before deadline"
        detail = lane_run.failure_details(self.cargo(message=message,
                                                    site="crates/example/tests/journey.rs:88:6"), False)
        self.assert_facts_only(detail["failures"][0])
        for value in ("3", "POST", "/orders", "recordings", "not persisted", "deadline"):
            self.assertNotIn(value, json.dumps(detail))

    def test_even_pure_diagnostic_continuations_are_withheld(self):
        message = "timed out\nassertion `left != right` failed\nshort 42\nright: 7"
        row = lane_run.failure_details(self.cargo(message=message,
                                                 site="crates/example/tests/journey.rs:88:6"), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["withheldLines"], 5)
        for value in ("timed out", "left != right", "short", "right"):
            self.assertNotIn(value, json.dumps(row))

    def test_libtest_assertion_frames_are_never_published(self):
        message = ('assertion `left == right` failed\n  left: Account { balance: 42 }\n'
                   ' right: "Ada"\nexpected: 7\n}\n')
        row = lane_run.failure_details(self.cargo(message=message,
                                                 site="crates/example/tests/journey.rs:88:6"), False)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["kind"], "assertion")
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
        row = lane_run.failure_details(self.cargo(message='assertion "value"'), False, index=index)["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["test"], lane_run.UNVERIFIED)
        self.assertNotIn("fails", json.dumps(row))

    def test_private_canaries_use_existing_scanner_encodings(self):
        values = {"assertion": "synthetic-value-31fe"}
        index = [*lane_run.CANARY_INDEX, *lane_run.canary.build_index(values)]
        for encoding, needle in lane_run.canary.needles(values["assertion"]):
            with self.subTest(encoding=encoding):
                detail = lane_run.failure_details(self.cargo(message=needle.decode()), False, index=index)
                self.assert_facts_only(detail["failures"][0])
                self.assertNotIn(needle.decode(), json.dumps(detail))

    def test_paths_credentials_and_terminal_controls_are_absent(self):
        for value in ("/Users/example/data", "/home/runner/data", "/opt/local/data", "token=123",
                      "Authorization: value", "Cookie: value", "unexpected\x00value"):
            with self.subTest(value=value):
                row = lane_run.failure_details(self.cargo(message=value), False)["failures"][0]
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
            "OtherValue AttributeValue WrongCrateValue TestValue")), False, metadata=metadata)["failures"][0]
        self.assertEqual(row["category"], ["Admission", "ActualStep"])
        self.assertEqual(row["test"], "fails")
        for operation in ("OtherError", "FieldType", "CommentValue", "LiteralValue", "OtherValue",
                          "AttributeValue", "WrongCrateValue", "TestValue"):
            with self.subTest(operation=operation):
                self.assertEqual(lane_run._panic_categories(
                    f"operation={operation} kind=None raw_os_error=None", metadata, lane_run.CANARY_INDEX), [])

    def test_unverified_name_reason_distinguishes_privacy_from_missing_declaration(self):
        index = lane_run.canary.build_index({"name": "fails", "category": "Deadline"})
        row = lane_run.failure_details(self.cargo(message="operation=Deadline"), False,
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

    def test_a_panic_in_a_passing_test_is_not_a_failure(self):
        text = ("thread 'waiting' panicked at crates/a.rs:1:2:\nexpected panic\n"
                "test waiting ... ok\n" + self.cargo())
        detail = lane_run.failure_details(text, False)
        self.assertEqual(len(detail["failures"]), 1)
        self.assertEqual(detail["failures"][0]["test"], "fails")
        self.assertNotIn("waiting", json.dumps(detail))


class CheckoutLookupTests(unittest.TestCase):
    def test_real_checkout_failing_test_name_and_location_survive_the_command_path(self):
        name = "honesty_strings_cover_every_stable_code"
        path = "crates/xtrace-domain/tests/honesty_strings.rs"
        lines = (ROOT / path).read_text().splitlines()
        line = next(i for i, text in enumerate(lines, 1) if text.startswith(f"fn {name}("))
        text = FailureDetailsTests.cargo(name=name, site=f"{path}:{line}:1", message="not persisted")
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
        self.diagnostic.write_text("pub enum AdmissionOperation { Deadline, }\n")
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
        self.diagnostic.write_text("pub enum AdmissionOperation { StagedValue, }\n")
        subprocess.run(["git", "-C", str(self.checkout), "add", "crates/xtrace-private-storage/src/diagnostic.rs"],
                       check=True, capture_output=True)
        self.diagnostic.unlink()
        (self.diagnostic.parent / "untracked.rs").write_text("enum AdmissionOperation { UntrackedValue }")
        metadata = lane_run._checkout_metadata()
        self.assertEqual(metadata.diagnostic_variants, {"Deadline"})
        row = lane_run.failure_details(FailureDetailsTests.cargo(
            name="committed_test", site="crates/tests/example.rs:2:1",
            message=("operation=Deadline kind=None raw_os_error=None "
                     "operation=StagedValue kind=None raw_os_error=None "
                     "operation=UntrackedValue kind=None raw_os_error=None")), False, metadata=metadata)["failures"][0]
        self.assertEqual(row["category"], ["Deadline"])
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
        text = "\n".join([
            "thread 'a' panicked at crates/x/src/lib.rs:12:5:",
            "thread 'b' panicked at /Users/me/secret/lib.rs:3:1:",
            "thread 'c' panicked at ../escape.rs:3:1:",
            "thread 'd' panicked at crates/x/src/lib.rs:12:9:",
            "boom token=abc"])
        sites, dropped = lane_run.panic_sites(text)
        self.assertEqual(sites, ["crates/x/src/lib.rs:12"])
        self.assertEqual(dropped, 2)

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
                         ("fails", "crates/example/tests/journey.rs:42", "assertion"))
        self.assertNotIn("left == right", public.getvalue())
        self.assertNotIn("left == right", json.dumps(frag))
        rc, frag = self.run_step([sys.executable, "-c",
                                  f"print({FailureDetailsTests.cargo(message='BODY_CANARY_123')!r}); raise SystemExit(101)"])
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
                text = FailureDetailsTests.cargo(message=message, site="crates/example/tests/journey.rs:88:6")
                rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                self.assertEqual(rc, 101)
                row = frag["failureDetails"]["failures"][0]
                self.assertEqual(row["test"], "fails")
                self.assertEqual(row["location"], "crates/example/tests/journey.rs:88")
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
                text = FailureDetailsTests.cargo(message=message, site="crates/example/tests/journey.rs:88:6")
                rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
                self.assertEqual(rc, 101)
                row = frag["failureDetails"]["failures"][0]
                self.assert_facts_only(row)
                self.assertEqual((row["test"], row["location"]), ("fails", "crates/example/tests/journey.rs:88"))
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
        text = FailureDetailsTests.cargo(message=(
            "admit scratch: Admission(AdmissionFailure { operation: WaitAclProbe, "
            "kind: Some(PermissionDenied), raw_os_error: Some(13) })\n"
            "captured-value-731 /private/example/path 999999"), thread_id=987654321) + "test waiting ...\n"
        public = io.StringIO()
        with contextlib.redirect_stdout(public):
            frag = self.timed_out_step(text)
        row = frag["failureDetails"]["failures"][0]
        self.assert_facts_only(row)
        self.assertEqual(row["category"], ["Admission", "WaitAclProbe", "PermissionDenied", 13])
        self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])
        self.assertEqual(frag["failureDetails"]["timeout"]["runningTests"], ["waiting"])
        logged = [json.loads(line.removeprefix("lane failure ")) for line in public.getvalue().splitlines()
                  if line.startswith("lane failure ")]
        self.assertEqual(logged, [row])
        for value in ("captured-value-731", "/private/example/path", "999999", "AdmissionFailure", "987654321"):
            self.assertNotIn(value, json.dumps(frag))
            self.assertNotIn(value, public.getvalue())

    def test_current_headers_have_fragment_and_job_log_parity_in_all_output_modes(self):
        import contextlib
        import io
        message = ("parent: Admission(AdmissionFailure { operation: OwnershipAndMode, "
                   "kind: None, raw_os_error: None })")
        header = "thread 'fails' (987654321) panicked at crates/example/tests/journey.rs:42:7:\n"
        cases = [
            ("captured", FailureDetailsTests.cargo(name="fails", message=message, thread_id=987654321), False),
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
                self.assertEqual((row["test"], row["location"], row["kind"]),
                                 ("fails", "crates/example/tests/journey.rs:42", "panic"))
                self.assertEqual(row["panicSites"], ["crates/example/tests/journey.rs:42"])
                self.assertEqual(row["category"], ["Admission", "OwnershipAndMode"])
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
        text = FailureDetailsTests.cargo(message="not persisted")
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
        text = FailureDetailsTests.cargo(message=message)
        rc, frag = self.run_step([sys.executable, "-c", f"print({text!r}); raise SystemExit(101)"])
        self.assertEqual(rc, 101)
        self.assertEqual(frag["failureDetails"]["failures"][0]["location"], "crates/example/tests/journey.rs:42")
        for value in ("Ada", "Error at", "ghp_abc123.java:7", "ghp_abc123"):
            self.assertNotIn(value, json.dumps(frag))

    def test_review_timeout_does_not_rescan_quoted_panic_progress(self):
        message = 'left: "Ada\nCompiling ghp_abc123 v1.2.3\n"'
        frag = self.timed_out_step(FailureDetailsTests.cargo(message=message))
        self.assertEqual(frag["failureDetails"]["timeout"]["progress"], [{"test": "fails", "state": "failed"}])
        for value in ("Ada", "Compiling", "ghp_abc123", "v1.2.3"):
            self.assertNotIn(value, json.dumps(frag))

    def test_verified_names_inside_quoted_values_are_not_harness_progress(self):
        message = ('left: "Ada\ntest waiting ...\n'
                   'FooTest > check(ghp_abc123) STARTED\n'
                   '---- waiting stdout ----\n'
                   "thread 'waiting' panicked at crates/b.rs:1:2:\n"
                   'Error at HttpTest.java:7\n"')
        frag = self.timed_out_step(FailureDetailsTests.cargo(message=message))
        detail = frag["failureDetails"]
        self.assertEqual(len(detail["failures"]), 1)
        self.assertEqual(detail["failures"][0]["location"], "crates/example/tests/journey.rs:42")
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
        text = "".join(FailureDetailsTests.cargo(name=f"case{i}", message="x " * 3000) for i in range(32))

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


class ErrorHintTests(unittest.TestCase):
    def test_allowlisted_codes_and_categories_only(self):
        text = "\n".join([
            'Err(Error { code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource, message: "at /Users/x" })',
            'code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource,',
            'code: ErrorCode("xtr-lower"), category: Bogus,',
            'code: ErrorCode("XTR-/home/me"), category: Internal,',
            'code: ErrorCode("OTHER-1"), category: Policy,',
        ])
        h = lane_run.error_hints(text)
        self.assertEqual(h["errorCodes"], ["XTR-STORE-OBJECT-IO"])
        self.assertEqual(h["errorCategories"], ["Resource", "Internal", "Policy"])
        self.assertEqual(h["droppedInvalid"], 4)

    def test_hints_are_bounded(self):
        text = "\n".join(f'ErrorCode("XTR-E{i}"), category: Internal,' for i in range(40))
        h = lane_run.error_hints(text)
        self.assertEqual(len(h["errorCodes"]), lane_run.MAX_ERROR_HINTS)
        self.assertEqual(h["truncated"], 40 - lane_run.MAX_ERROR_HINTS)

    def test_failing_step_prints_hints_and_never_the_message(self):
        with tempfile.TemporaryDirectory() as d:
            body = ('print("test a::b ... FAILED"); '
                    'print(\'Err(code: ErrorCode("XTR-STORE-OBJECT-IO"), category: Resource, message: "/Users/me/secret")\'); '
                    'raise SystemExit(101)')
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", "t",
                 "--out", d, "--", sys.executable, "-c", body],
                cwd=ROOT, capture_output=True, text=True, env={**__import__("os").environ, "RUNNER_TEMP": d})
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("lane error-code XTR-STORE-OBJECT-IO", proc.stdout)
            self.assertIn("lane error-category Resource", proc.stdout)
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


class DiagnosticsTests(unittest.TestCase):
    def test_pairs_error_with_location_and_skips_noise(self):
        text = (
            "warning: unused variable: `x`\n  --> crates/a/src/lib.rs:1:1\n"
            "error: this `panic!` should not be used (clippy::panic)\n   --> crates/xtrace-export/tests/export_core.rs:158:21\n"
            "error[E0425]: cannot find value `y` in this scope\n --> crates/b/src/main.rs:9:5\n"
            "error: could not compile `x` (test) due to 2 previous errors\n"
        )
        diags, dropped = lane_run.diagnostics(text)
        self.assertEqual(dropped, 0)
        self.assertEqual(diags, ["error: this `panic!` should not be used (clippy::panic) @ crates/xtrace-export/tests/export_core.rs:158:21",
                                 "error[E0425]: cannot find value `y` in this scope @ crates/b/src/main.rs:9:5"])

    def test_host_paths_and_secrets_are_dropped_and_counted(self):
        text = ("error: boom\n --> /home/runner/work/x/src/lib.rs:1:1\n"
                "error: leaked token abc\n --> src/lib.rs:2:2\n"
                "error: fine\n --> ../escape/src/lib.rs:3:3\n")
        diags, dropped = lane_run.diagnostics(text)
        self.assertEqual(diags, [])
        self.assertEqual(dropped, 3)

    def test_bounded(self):
        text = "".join(f"error: e{i}\n --> src/f.rs:{i}:1\n" for i in range(1, 40))
        diags, dropped = lane_run.diagnostics(text)
        self.assertEqual(len(diags), lane_run.MAX_DIAG)
        self.assertEqual(dropped, 39 - lane_run.MAX_DIAG)


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
