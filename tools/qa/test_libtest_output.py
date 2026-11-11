"""Realistic Cargo/libtest transcripts; all fixture message prose stays private."""
import argparse
import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from tools.qa import lane_run, libtest_output


SOURCES = {
    "crates/example/Cargo.toml": '[package]\nname = "example-crate"\n',
    "crates/example/tests/journey.rs": "\n".join(
        f"#[test]\nfn case{i}() {{}}" for i in range(40)) + "\n",
    "crates/example/tests/other.rs": "#[test]\nfn case0() {}\n",
}
BINARY = {"crate": "example-crate", "targetKind": "test", "targetName": "journey"}
HEADER = "     Running tests/journey.rs (target/debug/deps/journey-0123456789abcdef)"
SITE = "crates/example/tests/journey.rs:2"


def transcript(names, body="", *, header=HEADER, failed=None, passed=0):
    failed = len(names) if failed is None else failed
    return (f"{header}\n\nrunning {passed + failed} tests\n{body}\nfailures:\n\n"
            + "".join(f"    {name}\n" for name in names)
            + f"\ntest result: FAILED. {passed} passed; {failed} failed; 0 ignored; "
              "0 measured; 0 filtered out; finished in 0.01s\n")


class LibtestOutputTests(unittest.TestCase):
    def setUp(self):
        self.metadata = lane_run.CheckoutMetadata(SOURCES)

    def details(self, text, **kwargs):
        return lane_run.failure_details(text, False, metadata=self.metadata, **kwargs)

    def finalize(self, text):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            log = root / "private.log"
            log.write_text(text)
            args = argparse.Namespace(suite="rust", variant="-", step="focused", out=str(root / "out"),
                                      cwd=None, min_passed=0, canaries="")
            public = io.StringIO()
            with contextlib.redirect_stdout(public):
                code = lane_run.finalize_run(
                    args, cmd=["cargo", "test"], log_path=log, metadata=self.metadata,
                    diagnostic_directory=root / "diagnostics", code=101, timed_out=False, timing=None)
            self.assertEqual(code, 101)
            fragment = json.loads((root / "out/rust__-__focused.json").read_text())
        return fragment, public.getvalue()

    def test_eight_parallel_failures_survive_split_status_lines_and_child_output(self):
        names = [f"case{i}" for i in range(8)]
        body = "test case0 ... FAILED\n" + "".join(
            f"test case{i} ... child fixture value\nFAILED\n" for i in range(1, 8))
        body += "\nfailures:\n\n" + "".join(
            f"---- case{i} stdout ----\nworker fixture value\n"
            f"thread '<unnamed>' ({100 + i}) panicked at {SITE}:7:\n"
            "assertion `left == right` failed\n  left: 12345\n right: 67890\n"
            "stack backtrace:\n   0: fixture frame\n" for i in range(8))
        text = transcript(names, body, passed=1197)
        parsed = lane_run.parse_output(text)
        self.assertEqual((parsed["passed"], parsed["failed"]), (1197, 8))
        self.assertEqual(parsed["failingTests"], names)
        fragment, public = self.finalize(text)
        self.assertEqual(fragment["failingTests"], names)
        self.assertEqual(fragment["failingNamesMissing"], 0)
        self.assertEqual(fragment["failingTruncated"], 0)
        self.assertEqual(fragment["droppedInvalidNames"], 0)
        rows = fragment["failureDetails"]["failures"]
        self.assertEqual(len(rows), fragment["failed"])
        self.assertEqual([row["test"] for row in rows], names)
        for row in rows:
            self.assertEqual((row["binary"], row["kind"], row["location"], row["panicSites"]),
                             (BINARY, "panic", SITE, [SITE]))
            self.assertEqual(row["category"], [])
            self.assertGreater(row["withheldLines"], 1)
        logged = [json.loads(line.removeprefix("lane failure ")) for line in public.splitlines()
                  if line.startswith("lane failure ")]
        self.assertEqual(logged, rows)
        for value in ("fixture value", "12345", "67890", "<unnamed>", "stack backtrace", "fixture frame"):
            self.assertNotIn(value, json.dumps(fragment) + public)

    def test_nocapture_single_failure_owns_worker_and_child_main_panics(self):
        for thread in ("<unnamed>", "main", "worker"):
            with self.subTest(thread=thread):
                text = transcript(["case0"], "test case0 ... child output\n"
                                  f"thread '{thread}' (123) panicked at {SITE}:7:\n"
                                  "child assertion prose\nFAILED\n", passed=3)
                row, = self.details(text)["failures"]
                self.assertEqual((row["test"], row["binary"], row["panicSites"]),
                                 ("case0", BINARY, [SITE]))
                self.assertNotIn("child assertion prose", json.dumps(row))

    def test_nocapture_multiple_failures_do_not_use_thread_names_as_owners(self):
        text = transcript(["case0", "case1"], f"thread 'case0' panicked at {SITE}:7:\nfixture value\n")
        rows = self.details(text)["failures"]
        self.assertEqual([row["test"] for row in rows], ["case0", "case1", lane_run.UNVERIFIED])
        self.assertEqual(rows[-1]["testUnverifiedReason"], "ambiguous-panic-block")
        self.assertEqual(rows[-1]["panicSites"], [])

    def test_captured_child_panic_uses_section_even_with_multiple_failures(self):
        text = transcript(["case0", "case1"], "failures:\n\n---- case1 stdout ----\n"
                          f"child output\nthread 'main' panicked at {SITE}:7:\nprivate message\n")
        first, second = self.details(text)["failures"]
        self.assertEqual((first["kind"], first["panicSites"]), ("exit", []))
        self.assertEqual((second["test"], second["kind"], second["panicSites"]), ("case1", "panic", [SITE]))

    def test_authoritative_list_replaces_status_and_section_candidates(self):
        text = transcript(["case1"], "test case0 ... FAILED\nfailures:\n\n---- case0 stdout ----\n"
                          f"thread '<unnamed>' panicked at {SITE}:7:\nfixture value\n")
        self.assertEqual(lane_run.parse_output(text)["failingTests"], ["case1"])
        rows = self.details(text)["failures"]
        self.assertEqual(rows[0]["test"], "case1")
        self.assertEqual(rows[0]["panicSites"], [])
        self.assertEqual(rows[1]["test"], lane_run.UNVERIFIED)

    def test_same_name_in_two_binaries_is_two_failures(self):
        body = f"thread 'main' panicked at {SITE}:7:\nfixture value\n"
        other = HEADER.replace("journey", "other")
        text = transcript(["case0"], body) + transcript(["case0"], body, header=other)
        fragment, _ = self.finalize(text)
        self.assertEqual(fragment["failed"], 2)
        self.assertEqual(fragment["failingTests"], ["case0", "case0"])
        self.assertEqual(fragment["failingNamesMissing"], 0)
        self.assertEqual([row["binary"]["targetName"] for row in fragment["failureDetails"]["failures"]],
                         ["journey", "other"])

    def test_unverified_names_sites_and_binary_values_are_withheld_and_gap_is_explicit(self):
        body = "---- case0 stdout ----\nthread 'main' panicked at untracked.rs:1:7:\nfixture value\n"
        fragment, public = self.finalize(transcript(
            ["case0", "captured_value", "CANARY", "../../private"], body,
            header=HEADER.replace("journey-", "captured_binary-"), failed=5))
        self.assertEqual(fragment["failingTests"], ["case0", lane_run.UNVERIFIED, lane_run.UNVERIFIED])
        self.assertEqual(fragment["droppedInvalidNames"], 1)
        self.assertEqual(fragment["failingNamesMissing"], 4)
        self.assertIn("lane failing-test-gap missing=4 excess=0", public)
        for row in fragment["failureDetails"]["failures"]:
            self.assertEqual(row["binary"], lane_run.UNVERIFIED)
            self.assertEqual(row["panicSites"], [])
        for value in ("captured_value", "CANARY", "../../private", "captured_binary", "untracked.rs"):
            self.assertNotIn(value, json.dumps(fragment) + public)

    def test_missing_or_capped_names_report_count_gap(self):
        for count, names, missing, truncated in (
            (8, ["case0"], 7, 0), (40, [f"case{i}" for i in range(40)], 8, 8), (1, [], 1, 0)):
            with self.subTest(count=count):
                fragment, _ = self.finalize(transcript(names, failed=count))
                self.assertEqual(fragment["failingNamesMissing"], missing)
                self.assertEqual(fragment["failingTruncated"], truncated)
                self.assertEqual(fragment["failed"], count)

    def test_module_prefixes_must_match_head_exactly(self):
        fragment, _ = self.finalize(transcript(["captured_prefix::case0"]))
        self.assertEqual(fragment["failingTests"], [lane_run.UNVERIFIED])
        self.assertEqual(fragment["failingNamesMissing"], 1)

    def test_framed_sites_require_head_file_and_line_and_privacy_scan(self):
        for path, line in (("untracked.rs", 1), ("../journey.rs", 1),
                           ("crates/example/tests/journey.rs", 0),
                           ("crates/example/tests/journey.rs", 999999),
                           ("crates/CANARY.rs", 1)):
            with self.subTest(path=path, line=line):
                body = ("---- case0 stdout ----\n"
                        f"thread '<unnamed>' panicked at {path}:{line}:7:\nfixture value\n")
                row, = self.details(transcript(["case0"], body))["failures"]
                self.assertEqual(row["test"], "case0")
                self.assertEqual(row["kind"], "panic")
                self.assertEqual(row["location"], lane_run.UNVERIFIED)
                self.assertEqual(row["panicSites"], [])

    def test_custom_canary_scan_can_only_remove_head_attested_fields(self):
        index = lane_run.canary.build_index({"name": "case0", "site": "journey.rs"})
        text = transcript(["case0"], f"---- case0 stdout ----\nthread 'main' panicked at {SITE}:7:\nprose\n")
        row, = self.details(text, index=index)["failures"]
        self.assertEqual(row["test"], lane_run.UNVERIFIED)
        self.assertEqual(row["testUnverifiedReason"], "privacy-scan")
        self.assertEqual(row["location"], lane_run.UNVERIFIED)
        self.assertEqual(row["panicSites"], [])

    def test_quoted_multiline_fixture_cannot_introduce_panic_site_or_owner(self):
        body = ('---- case0 stdout ----\nfixture: "continuation\n'
                f"---- case1 stdout ----\nthread 'main' panicked at {SITE}:7:\n"
                'fixture continuation"\n')
        rows = self.details(transcript(["case0", "case1"], body))["failures"]
        self.assertEqual([row["test"] for row in rows], ["case0", "case1"])
        self.assertTrue(all(row["panicSites"] == [] for row in rows))

    def test_unterminated_fixture_does_not_unlock_fallback_parser(self):
        text = transcript(["case0"], '---- case0 stdout ----\nfixture: "unterminated\n')
        reports, _ = libtest_output.partition(text)
        self.assertEqual(reports, [])

    def test_sites_remain_bounded_and_backtrace_text_is_not_a_site(self):
        body = "---- case0 stdout ----\n" + "".join(
            f"thread '<unnamed>' panicked at crates/example/tests/journey.rs:{i + 1}:7:\nfixture value\n"
            for i in range(lane_run.MAX_PANIC_SITES + 3))
        body += "stack backtrace:\ncrates/example/tests/other.rs:1\n"
        row, = self.details(transcript(["case0"], body))["failures"]
        self.assertEqual(len(row["panicSites"]), lane_run.MAX_PANIC_SITES)
        self.assertNotIn("crates/example/tests/other.rs:1", row["panicSites"])
        self.assertEqual(row["category"], [])

    def test_summary_failure_names_keep_structured_diagnostic_provenance(self):
        text = transcript(["case0"], "test case0 ... child output\nFAILED\n")
        detail = self.details(text, diagnostic_records=[
            lane_run.AdmissionDiagnostic("case0", ["Admission", "Deadline"])])
        self.assertEqual(detail["observedDiagnostics"], [
            {"test": "case0", "relevance": "unknown", "category": ["Admission", "Deadline"]}])

    def test_successful_binary_with_should_panic_output_has_no_failure_row(self):
        text = (f"{HEADER}\nrunning 1 test\nthread 'case0' panicked at {SITE}:7:\n"
                "expected panic prose\ntest case0 - should panic ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n")
        self.assertEqual(self.details(text)["failures"], [])
        self.assertEqual(lane_run.parse_output(text)["passed"], 1)
        self.assertEqual(lane_run.parse_output(text)["failingTests"], [])

    def test_failure_rows_still_obey_job_excerpt_budget(self):
        text = transcript([f"case{i}" for i in range(8)])
        detail = self.details(text, budget=600)
        self.assertIsNotNone(detail)
        self.assertLessEqual(len(lane_run._encoded(detail)), 600)
        self.assertEqual(len(detail["failures"]) + detail["omitted"], 8)
