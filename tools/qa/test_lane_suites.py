import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import lane_suites as ls  # noqa: E402


def status(files, force="", repo=None):
    repo = repo or pathlib.Path(tempfile.gettempdir())
    return {k: v["status"] for k, v in ls.plan(files, force, repo).items()}


class PlanTests(unittest.TestCase):
    def test_workflow_only_change_selects_meta_only(self):
        s = status([".github/workflows/lane.yml"])
        self.assertEqual(s["meta"], "selected")
        for name in ("rust", "java", "node", "web"):
            self.assertEqual(s[name], "skipped-by-filter")

    def test_crate_change_selects_rust_and_lists_crate(self):
        p = ls.plan(["crates/xtrace-domain/src/lib.rs"], "", pathlib.Path(tempfile.gettempdir()))
        self.assertEqual(p["rust"]["status"], "selected")
        self.assertEqual(p["rust"]["changedCrates"], ["xtrace-domain"])
        self.assertEqual(p["java"]["status"], "skipped-by-filter")

    def test_unknown_basis_selects_everything_present(self):
        s = status(None)
        self.assertEqual(s["rust"], "selected")
        self.assertEqual(s["web"], "selected")

    def test_tui_absent_never_pass(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(status(["crates/xtrace-tui/x.rs"], repo=pathlib.Path(d))["tui"], "absent")
            (pathlib.Path(d) / "crates/xtrace-tui").mkdir(parents=True)
            self.assertEqual(status(["crates/xtrace-tui/x.rs"], repo=pathlib.Path(d))["tui"], "selected")

    def test_dispatch_force(self):
        self.assertEqual(status([], "java")["java"], "selected")
        self.assertEqual(status([], "java")["node"], "skipped-by-filter")
        self.assertEqual(status([], "all")["node"], "selected")

    def test_adapter_paths(self):
        self.assertEqual(status(["adapters/node/package.json"])["node"], "selected")
        self.assertEqual(status(["adapters/node/package.json"])["java"], "skipped-by-filter")
        self.assertEqual(status(["web/app/src/a.ts"])["web"], "selected")


if __name__ == "__main__":
    unittest.main()
