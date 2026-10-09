import json
import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_select as cs  # noqa: E402
import camp_summary as cu  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]


class SelectTests(unittest.TestCase):
    def test_branch_selects_one_project(self):
        self.assertEqual(cs.select("", "ultra/campaign/petclinic-w0"), ["petclinic"])
        self.assertEqual(cs.select("", "ultra/campaign/petclinic"), ["petclinic"])

    def test_branch_all(self):
        self.assertEqual(cs.select("", "ultra/campaign/all-rc1"), list(cs.ALL))

    def test_dispatch_list_and_default(self):
        self.assertEqual(cs.select("directus, petclinic", "main"), ["petclinic", "directus"])
        self.assertEqual(cs.select("all", "main"), list(cs.ALL))
        self.assertEqual(cs.select("", "main"), list(cs.ALL))

    def test_unknown_rejected(self):
        with self.assertRaises(ValueError):
            cs.select("", "ultra/campaign/nope-1")

    def test_matrix_reads_pins(self):
        m = cs.matrix(ROOT, ["petclinic", "directus"])["include"]
        self.assertEqual(m[0]["jdk"], 17)
        self.assertEqual(len(m[0]["sha"]), 40)
        self.assertEqual(m[1]["kind"], "node")


class GateTests(unittest.TestCase):
    def test_not_implemented_fails_gate(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "s.json"
            cu.record(f, "p", "baseline", "pass")
            self.assertEqual(cu.gate(f), 0)
            cu.record(f, "p", "overhead", "not-implemented", "no product feature")
            self.assertEqual(cu.gate(f), 1)

    def test_empty_fails(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(cu.gate(pathlib.Path(d) / "none.json"), 1)

    def test_reported_does_not_gate(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "s.json"
            cu.record(f, "p", "baseline", "pass")
            cu.record(f, "p", "compare", "reported", "differs")
            self.assertEqual(cu.gate(f), 0)


if __name__ == "__main__":
    unittest.main()
