"""Exercise local release Node selection without running package or test suites."""

import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/dev/macos-release-check.sh"


class MacosReleaseNodeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name).resolve()
        source = SCRIPT.read_text()
        # Load the real shell functions, without macOS admission or heavy suites.
        self.functions = source[source.index("run_suite() {"):source.index("# Compilation")]
        self.environment = dict(os.environ, CALLS=str(self.root / "calls"))
        for version in (22, 24):
            self.environment[f"XTRACE_NODE_{version}_BIN"] = str(self.root / f"missing-{version}")

    def executable(self, directory, name, body):
        path = directory / name
        path.write_text("#!/bin/bash\nset -eu\n" + body + "\n")
        path.chmod(0o700)

    def runtime(self, major, *, actual=None, npm=True):
        directory = self.root / f"node {major}"
        directory.mkdir()
        self.executable(directory, "node", f"printf '%s\\n' {shlex.quote(actual or f'v{major}.1.2')}")
        if npm:
            self.executable(directory, "npm", 'printf "npm %s %s\\n" "$(node --version)" "$*" >> "$CALLS"')
        self.executable(directory, "npx", 'printf "npx %s %s\\n" "$(node --version)" "$*" >> "$CALLS"')
        self.environment[f"XTRACE_NODE_{major}_BIN"] = str(directory)
        return directory

    def run_versions(self, fail_variant=""):
        harness = f'''set -uo pipefail
run_root={shlex.quote(str(self.root))}
summary="$run_root/summary"
: > "$summary"
result=0
{self.functions}
lane() {{
    printf 'lane %s %s\\n' "$(node --version)" "$*" >> "$CALLS"
    if [[ "$*" == *"--suite node --variant {fail_variant} --step install"* ]]; then return 7; fi
}}
run_node_versions
cat "$summary"
exit "$result"
'''
        completed = subprocess.run(["/bin/bash"], input=harness, cwd=ROOT,
                                   env=self.environment, capture_output=True, text=True)
        calls = self.root / "calls"
        return completed, calls.read_text() if calls.exists() else ""

    def test_both_versions_run_both_suites_with_versioned_fragments(self):
        self.runtime(22)
        self.runtime(24)
        completed, calls = self.run_versions()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for version in (22, 24):
            for suite in ("node", "web"):
                self.assertIn(f"{suite}-{version} version=v{version}.1.2\n", completed.stdout)
                self.assertIn(f"{suite}-{version} exit=0\n", completed.stdout)
                self.assertIn(f"lane v{version}.1.2 --suite {suite} --variant {version} --step install", calls)
            self.assertIn(f"npm v{version}.1.2 run build --prefix adapters/node", calls)
            self.assertIn(f"npx v{version}.1.2 --no-install playwright install chromium", calls)
        self.assertNotIn("NOT-COVERED", completed.stdout)

    def test_only_node22_names_separate_node24_and_web_coverage_gaps(self):
        self.runtime(22)
        completed, calls = self.run_versions()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("node-22 exit=0\n", completed.stdout)
        self.assertIn("web-22 exit=0\n", completed.stdout)
        self.assertIn("node-24-unavailable NOT-COVERED exit=2\n", completed.stdout)
        self.assertIn("web-node-24-unavailable NOT-COVERED exit=2\n", completed.stdout)
        self.assertNotIn("--variant 24", calls)

    def test_wrong_major_and_missing_npm_cannot_claim_coverage(self):
        self.runtime(22, actual="v24.1.2")
        self.runtime(24, npm=False)
        completed, calls = self.run_versions()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        for version in (22, 24):
            self.assertIn(f"node-{version}-unavailable NOT-COVERED exit=2\n", completed.stdout)
            self.assertIn(f"web-node-{version}-unavailable NOT-COVERED exit=2\n", completed.stdout)
        self.assertEqual(calls, "")

    def test_path_discovery_selects_matching_runtime_beyond_first_node(self):
        directories = [self.runtime(22), self.runtime(24)]
        for version in (22, 24):
            del self.environment[f"XTRACE_NODE_{version}_BIN"]
        self.environment["PATH"] = ":".join(map(str, directories)) + ":/usr/bin:/bin"
        completed, calls = self.run_versions()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("node-22 version=v22.1.2\n", completed.stdout)
        self.assertIn("web-24 version=v24.1.2\n", completed.stdout)
        self.assertIn("lane v24.1.2 --suite web --variant 24", calls)

    def test_suite_failure_keeps_later_suites_and_versions_running(self):
        self.runtime(22)
        self.runtime(24)
        completed, calls = self.run_versions(fail_variant="22")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("node-22 exit=7\n", completed.stdout)
        self.assertIn("web-22 exit=0\n", completed.stdout)
        self.assertIn("node-24 exit=0\n", completed.stdout)
        self.assertIn("web-24 exit=0\n", completed.stdout)
        self.assertNotIn("--suite node --variant 22 --step test", calls)
        self.assertIn("--suite node --variant 24 --step test", calls)

    def test_failure_takes_precedence_over_missing_version_gap(self):
        self.runtime(22)
        completed, _ = self.run_versions(fail_variant="22")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("node-22 exit=7\n", completed.stdout)
        self.assertIn("node-24-unavailable NOT-COVERED exit=2\n", completed.stdout)

    def test_release_entrypoint_uses_version_loop(self):
        source = SCRIPT.read_text()
        self.assertIn("\nrun_node_versions\n", source[source.index("GRADLE\n"):])
        self.assertNotIn("\nrun_suite node node_suite\n", source)
        self.assertNotIn("\nrun_suite web web_suite\n", source)
