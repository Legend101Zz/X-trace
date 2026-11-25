import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_overhead as co  # noqa: E402


def receipt(vals_by_scenario):
    return {"scenarios": [{"id": k, "requests": [{"elapsedMs": v} for v in vs]} for k, vs in vals_by_scenario.items()]}


def paired_runs(count=5):
    runs = []
    for index in range(count * 2):
        instrumented = bool(index % 2)
        doc = receipt({"a": [20 if instrumented else 10]})
        doc.update({"instrumented": instrumented, "result": "recorded" if instrumented else "passed_baseline_only",
                    "pin": {"jarSha256": "a", "git": {"head": "b"}}, "api": {"ok": True, "recordings": 1},
                    "notes": {"launcherExitCode": 0}})
        doc["scenarios"][0].update({"passed": True, "scenarioChecksPassed": True, "fingerprintEqualsBaseline": True,
                                    "semanticEffectFingerprint": "same"})
        runs.append({"mode": "instrumented" if instrumented else "baseline", "repeat": index // 2,
                     "startedNs": index * 10 + 1, "finishedNs": index * 10 + 9,
                     "receiptPath": f"run-{index}/receipt.json", "receipt": doc, "exitCode": 0})
    return runs


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

    def test_five_observed_interleaved_pairs_qualify(self):
        d = co.compare_interleaved(paired_runs())
        self.assertTrue(d["eligibleForClaim"], d["errors"])
        self.assertEqual(d["repeats"], 5)
        self.assertEqual(d["aggregate"]["baseline"]["n"], 5)
        self.assertEqual(d["aggregate"]["p50Ratio"], 2)
        self.assertEqual(len(d["runs"][0]["canonicalReceiptSha256"]), 64)
        self.assertEqual(d["runs"][0]["scenarios"]["a"]["n"], 1)
        short = co.compare_interleaved(paired_runs(4))
        self.assertFalse(short["eligibleForClaim"])
        self.assertIsNone(short["aggregate"]["p50Ratio"])

    def test_bad_repeat_evidence_never_qualifies(self):
        import copy
        mutations = [lambda rs: rs[1].update(mode="baseline"),
                     lambda rs: rs[1].update(receiptPath=rs[0]["receiptPath"]),
                     lambda rs: rs[1].update(startedNs=rs[0]["startedNs"]),
                     lambda rs: rs[3].update(exitCode=1),
                     lambda rs: rs[1]["receipt"]["scenarios"][0].update(fingerprintEqualsBaseline=False),
                     lambda rs: rs[1]["receipt"]["scenarios"][0].update(semanticEffectFingerprint="different"),
                     lambda rs: rs[1]["receipt"]["api"].update(recordings=0),
                     lambda rs: rs[1]["receipt"]["api"].update(listReadGap="recordings list HTTP 503"),
                     lambda rs: rs[1]["receipt"]["api"].update(incompleteDetails=1),
                     lambda rs: rs[1]["receipt"]["notes"].update(launcherExitCode=1),
                     lambda rs: rs[1]["receipt"]["scenarios"][0].update(requests=[])]
        for mutate in mutations:
            runs = copy.deepcopy(paired_runs())
            mutate(runs)
            doc = co.compare_interleaved(runs)
            self.assertFalse(doc["eligibleForClaim"], doc)
            self.assertIsNone(doc["aggregate"]["p50Ratio"])
        self.assertFalse(co.compare_interleaved([])["eligibleForClaim"])
        self.assertFalse(co.compare_interleaved(paired_runs()[:-1])["eligibleForClaim"])


if __name__ == "__main__":
    unittest.main()
