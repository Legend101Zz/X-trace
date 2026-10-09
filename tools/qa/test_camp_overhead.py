import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_overhead as co  # noqa: E402


def receipt(vals_by_scenario):
    return {"scenarios": [{"id": k, "requests": [{"elapsedMs": v} for v in vs]} for k, vs in vals_by_scenario.items()]}


class T(unittest.TestCase):
    def test_percentile(self):
        self.assertEqual(co.percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(co.percentile(list(range(1, 21)), 95), 19)
        self.assertIsNone(co.percentile([], 50))

    def test_compare_ratio_and_concurrency_excluded(self):
        b = receipt({"a": [10, 10, 10, 10], "concurrent-isolation": [1000]})
        i = receipt({"a": [20, 20, 20, 40], "concurrent-isolation": [5000]})
        d = co.compare(b, i)
        self.assertEqual(d["aggregate"]["baseline"]["n"], 4)
        self.assertEqual(d["aggregate"]["p50Ratio"], 2.0)
        self.assertFalse(d["gated"])
        self.assertEqual({r["scenario"] for r in d["scenarios"]}, {"a", "concurrent-isolation"})

    def test_missing_side(self):
        d = co.compare(receipt({"a": [1]}), receipt({}))
        self.assertIsNone(d["scenarios"][0]["instrumented"]["p50Ms"])
        self.assertIsNone(d["scenarios"][0]["p50Ratio"])


if __name__ == "__main__":
    unittest.main()
