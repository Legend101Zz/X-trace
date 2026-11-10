import json
import pathlib
import re
import tempfile
import unittest

from tools.qa import store_profiles


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = "expected_admissions=131072 counted_journal_syncs=true\n"
ACTIVE = "elapsed_ns=900 completed=256 active=journal_append"
STATE = "state=progress completed=256 elapsed_ns=800\n"
PHASE = "phase=journal_append spans=3 total_ns=500 max_ns=300 acl_probes=2\n"


class StoreProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = pathlib.Path(temporary.name)

    def write(self, suffix, text, name="singletons"):
        path = self.directory / f"store-{name}-{suffix}.txt"
        path.write_text(text)
        return path

    def test_all_profiles_retain_last_observed_numeric_measurements(self):
        for name in store_profiles.PROFILES:
            self.write("active", ACTIVE.ljust(159) + "\n", name)
            self.write("progress", HEADER + STATE + PHASE + PHASE.replace("spans=3", "spans=4"), name)
        profiles = store_profiles.collect(self.directory)
        self.assertEqual(set(profiles), set(store_profiles.PROFILES))
        for profile in profiles.values():
            self.assertEqual(profile, {
                "workload": {"expected_admissions": 131072, "counted_journal_syncs": 1},
                "active": {"elapsed_ns": 900, "completed": 256, "active": "journal_append"},
                "lastReport": {"state": "progress", "completed": 256, "elapsed_ns": 800},
                "phases": {"journal_append": {"spans": 4, "total_ns": 500, "max_ns": 300, "acl_probes": 2}},
            })

    def test_unknown_vocabulary_prose_and_non_unsigned_numbers_are_not_accepted(self):
        invalid = [
            PHASE.replace("journal_append", "private_payload"),
            PHASE.replace("journal_append", "not_a_phase"),
            PHASE.rstrip("\n") + " token=private_payload\n",
            "private_payload\n" + PHASE.replace("phase=", "message=phase="),
            STATE.replace("progress", "private_payload"),
            HEADER.replace("true", "private_payload"),
            *(PHASE.replace("spans=3", f"spans={number}")
              for number in ("-1", "+1", "1.2", "1e3", "１２", "9" * 40, "private_payload")),
        ]
        for text in invalid:
            with self.subTest(text=text):
                self.write("progress", text)
                self.assertEqual(store_profiles.collect(self.directory), {})
        for text in (ACTIVE.replace("journal_append", "private_payload"),
                     ACTIVE + " token=private_payload", ACTIVE.replace("900", "-900")):
            with self.subTest(active=text):
                self.write("active", text + "\n")
                self.assertEqual(store_profiles.collect(self.directory), {})

    def test_partial_timeout_records_are_absent_but_completed_records_survive(self):
        self.write("active", ACTIVE)
        self.write("progress", HEADER + STATE + PHASE.rstrip("\n"))
        profile = store_profiles.collect(self.directory)["singletons"]
        self.assertEqual(set(profile), {"workload", "lastReport"})
        self.assertEqual(profile["lastReport"]["completed"], 256)

    def test_regular_fixed_filenames_only(self):
        secret = self.directory / "private.log"
        secret.write_text(HEADER + STATE + PHASE)
        self.write("progress", HEADER, "unknown")
        (self.directory / "store-singletons-progress.txt").symlink_to(secret)
        (self.directory / "store-sparse-progress.txt").mkdir()
        self.assertEqual(store_profiles.collect(self.directory), {})
        self.assertEqual(store_profiles.collect(self.directory / "absent"), {})

    def test_large_history_retains_recent_progress_with_bounded_reads_and_output(self):
        self.write("progress", HEADER + PHASE * 2000 + STATE + PHASE.replace("spans=3", "spans=7"))
        profile = store_profiles.collect(self.directory)["singletons"]
        self.assertEqual(profile["workload"]["expected_admissions"], 131072)
        self.assertEqual(profile["lastReport"]["completed"], 256)
        self.assertEqual(profile["phases"]["journal_append"]["spans"], 7)
        path = self.directory / "store-singletons-progress.txt"
        self.assertLessEqual(len(store_profiles._read(path, tail=True)), store_profiles.TAIL_BYTES)
        # Even the largest accepted numbers and every allowed phase stay bounded.
        largest = "9" * 39
        for name in store_profiles.PROFILES:
            text = "".join(f"phase={phase} spans={largest} total_ns={largest} "
                           f"max_ns={largest} acl_probes={largest}\n"
                           for phase in sorted(store_profiles.PHASES))
            self.write("progress", HEADER + STATE + text, name)
            self.write("active", ACTIVE.ljust(159) + "\n", name)
        profiles = store_profiles.collect(self.directory)
        for profile in profiles.values():
            self.assertEqual(set(profile["phases"]), store_profiles.PHASES)
        self.assertLess(len(json.dumps(profiles).encode()), 64 * 1024)

    def test_vocabulary_covers_instrumented_store_phase_literals(self):
        observed = {"fixture"}
        for path in (ROOT / "crates/xtrace-store/src").glob("*.rs"):
            source = path.read_text()
            observed.update(re.findall(r'(?:Phase::enter|phase\.switch)\("([a-z_]+)"\)', source))
            observed.update(re.findall(r'(?:FileSync|SyncKind)::\w+ => "([a-z_]+)"', source))
        self.assertEqual(observed, store_profiles.PHASES)
