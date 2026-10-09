import pathlib
import subprocess
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
    def test_other_workflow_change_selects_meta_only(self):
        s = status([".github/workflows/campaigns.yml", "docs/a.md"])
        self.assertEqual(s["meta"], "selected")
        for name in ("rust", "java", "node", "web"):
            self.assertEqual(s[name], "skipped-by-filter")

    def test_lane_definition_selects_every_present_suite(self):
        for path in (".github/workflows/lane.yml", "tools/qa/lane_run.py", "tools/release/ci_floor.py"):
            s = status([path])
            for name in ("meta", "rust", "java", "node", "web"):
                self.assertEqual(s[name], "selected", (path, name))

    def test_rust_config_and_adapters_select_rust(self):
        for path in ("rustfmt.toml", "clippy.toml", "deny.toml", "adapters/java/x/build.gradle.kts",
                     "adapters/node/src/a.ts", "web/app/src/a.ts"):
            self.assertEqual(status([path])["rust"], "selected", path)

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


def run(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                   check=True, capture_output=True)


class CumulativeTests(unittest.TestCase):
    def test_docs_push_after_crate_push_still_selects_rust(self):
        # Push A touches a crate, push B only docs: the plan for B must still select rust.
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            run("init", "-q", "-b", "main", cwd=repo)
            (repo / "README.md").write_text("x")
            run("add", ".", cwd=repo)
            run("commit", "-q", "-m", "base", cwd=repo)
            run("update-ref", "refs/remotes/origin/main", "HEAD", cwd=repo)
            run("checkout", "-q", "-b", "ultra/x", cwd=repo)
            (repo / "crates/xtrace-domain").mkdir(parents=True)
            (repo / "crates/xtrace-domain/lib.rs").write_text("a")
            run("add", ".", cwd=repo)
            run("commit", "-q", "-m", "A", cwd=repo)
            a = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
            (repo / "docs.md").write_text("b")
            run("add", ".", cwd=repo)
            run("commit", "-q", "-m", "B", cwd=repo)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
            mode, files = ls.changed_files(repo, head, a, "origin/main")
            self.assertEqual(mode, "merge-base")
            self.assertIn("crates/xtrace-domain/lib.rs", files)
            self.assertEqual(ls.plan(files, "", repo)["rust"]["status"], "selected")


if __name__ == "__main__":
    unittest.main()
