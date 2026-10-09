import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_baseline_record as b  # noqa: E402


def rec(fp, result="passed_baseline_only", jar="j"):
    return {"project": "p", "result": result, "pin": {"sha": "s", "jarSha256": jar, "postgresImageDigest": "d"},
            "scenarios": [{"id": "a", "kind": "k", "requests": [1], "checks": [1], "semanticEffectFingerprint": fp}]}


class T(unittest.TestCase):
    def test_stable_pair(self):
        d = b.build([rec("x"), rec("x")], [], "linux/arm64", "n", "t", {})
        self.assertEqual(d["scenarios"][0]["semanticEffectFingerprint"], "x")
        self.assertEqual(d["provenance"]["platform"], "linux/arm64")

    def test_refuses_unstable_single_failed_or_mixed_jar(self):
        with self.assertRaises(ValueError):
            b.build([rec("x"), rec("y")], [], "p", "n", "t", {})
        with self.assertRaises(ValueError):
            b.build([rec("x")], [], "p", "n", "t", {})
        with self.assertRaises(ValueError):
            b.build([rec("x"), rec("x", result="failed")], [], "p", "n", "t", {})
        with self.assertRaises(ValueError):
            b.build([rec("x"), rec("x", jar="k")], [], "p", "n", "t", {})


if __name__ == "__main__":
    unittest.main()
