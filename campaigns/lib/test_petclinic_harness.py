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
