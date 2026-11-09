import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]


class OverheadHarness(unittest.TestCase):
    def load(self, root):
        spec = importlib.util.spec_from_file_location("petclinic_campaign", ROOT / "campaigns/java/petclinic/harness/run.py")
        module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"XTRACE_CAMPAIGN_ROOT": str(root)}):
            spec.loader.exec_module(module)
        return module

    def test_scenario_order_matches_the_pinned_baseline_and_burst_runs_last(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self.load(td)
            pinned = json.loads((ROOT / "campaigns/java/petclinic/baseline-summary.json").read_text())
            self.assertEqual([sc.id for sc in harness.SCENARIOS], [sc["id"] for sc in pinned["scenarios"]])
            self.assertEqual(harness.SCENARIOS[-1].kind, "concurrency")
            self.assertTrue(all(sc.kind != "concurrency" for sc in harness.SCENARIOS[:-1]))

    def test_pet_and_visit_expectations_pin_both_submission_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self.load(td)
        self.assertEqual([(e["route"], e["statuses"]) for e in harness.EXPECT["pet-and-visit-flow"]],
                         [("/owners/{ownerId}/pets/new", [302, 200]),
                          ("/owners/{ownerId}/pets/{petId}/visits/new", [200, 302])])
        self.assertEqual(harness.OWN["repository"], ["OwnerRepository", "org.springframework.data.repository.CrudRepository"])

    def test_error_expectations_name_propagation_without_claiming_a_final_500(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self.load(td)
        for sid, typ in (("missing-owner-error", "IllegalArgumentException"), ("controller-crash-path", "RuntimeException")):
            with self.subTest(scenario=sid):
                expectation = harness.EXPECT[sid][0]
                self.assertIsNone(expectation["status"])
                self.assertEqual(expectation["outcome"], "exception_propagated")
                self.assertEqual(expectation["exception"], typ)

    def test_exactly_five_interleaved_pairs_record_real_intervals_and_pair_paths(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self.load(td)
            out = pathlib.Path(td) / "overhead"
            calls = []
            def baseline(dest):
                calls.append(("baseline", dest))
                return {"result": "passed_baseline_only"}
            def instrumented(dest, baseline_receipt):
                calls.append(("instrumented", dest))
                self.assertEqual(baseline_receipt, calls[-2][1] / "receipt.json")
                return 0
            with mock.patch.dict(os.environ, {"XCAMP_OVERHEAD_DIR": str(out)}), \
                 mock.patch.object(harness, "baseline", side_effect=baseline), \
                 mock.patch.object(harness, "instrumented", side_effect=instrumented), \
                 mock.patch.object(harness.time, "time_ns", side_effect=range(1, 21)):
                self.assertEqual(harness.overhead(), 0)
            self.assertEqual([mode for mode, _ in calls], ["baseline", "instrumented"] * 5)
            rows = json.loads((out / "runs.json").read_text())["runs"]
            self.assertEqual(len(rows), 10)
            self.assertEqual(len({row["receiptPath"] for row in rows}), 10)
            for index, row in enumerate(rows):
                self.assertEqual(row["repeat"], index // 2)
                self.assertGreater(row["finishedNs"], row["startedNs"])
                if index:
                    self.assertGreaterEqual(row["startedNs"], rows[index - 1]["finishedNs"])

    def test_failed_repeat_stops_without_retry_or_counting_later_runs(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self.load(td)
            out = pathlib.Path(td) / "overhead"
            with mock.patch.dict(os.environ, {"XCAMP_OVERHEAD_DIR": str(out)}), \
                 mock.patch.object(harness, "baseline", return_value={"result": "failed"}) as baseline, \
                 mock.patch.object(harness, "instrumented") as instrumented:
                self.assertEqual(harness.overhead(), 1)
            baseline.assert_called_once()
            instrumented.assert_not_called()
            self.assertEqual(len(json.loads((out / "runs.json").read_text())["runs"]), 1)

    def test_baseline_cannot_inherit_the_previous_instrumented_launcher(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self.load(td)
            with mock.patch.dict(os.environ, {"XCAMP_LAUNCH_PREFIX": "xtrace run --"}), \
                 mock.patch.object(harness.xcamp, "sha256_file", return_value="jar"), \
                 mock.patch.object(harness.xcamp, "git_pin_check", return_value={}), \
                 mock.patch.object(harness.xcamp, "run_baseline", return_value={"result": "passed_baseline_only"}):
                harness.baseline(pathlib.Path(td) / "baseline")
                self.assertNotIn("XCAMP_LAUNCH_PREFIX", os.environ)


if __name__ == "__main__":
    unittest.main()
