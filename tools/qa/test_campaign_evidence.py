import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]


class WorkflowEvidence(unittest.TestCase):
    def test_failed_self_checks_publish_filtered_unittest_diagnostics(self):
        text = (ROOT / ".github/workflows/campaigns.yml").read_text()
        step = text[text.index("      - name: Private canaries and scanner self-check"):
                    text.index("      - name: Instrumented scenarios through the packaged xtrace run")]
        self.assertIn("umask 077", step)
        for suite, start in (("ut-qa", "tools/qa"), ("ut-camp", "campaigns/lib")):
            result = f'"$RUNNER_TEMP/priv/{suite}.json"'
            self.assertIn(f"python3 -B -m tools.qa.unittest_run --result {result} "
                          f"discover -s {start} -p 'test_*.py'", step)
            self.assertIn(f'> "$RUNNER_TEMP/priv/{suite}.log" 2>&1', step)
            self.assertIn(f'|| {{ python3 -B -m tools.qa.unittest_summary {result}; exit 1; }}', step)
            self.assertIn(f'python3 -B -m tools.qa.unittest_summary {result}\n', step)
            self.assertNotIn(f'unittest_summary "$RUNNER_TEMP/priv/{suite}.log"', step)
        self.assertNotIn("tail", step)

    def test_exports_use_real_analyzer_and_required_privacy_coverage(self):
        text = (ROOT / ".github/workflows/campaigns.yml").read_text()
        self.assertIn(":static-analyzer:installDist", text)
        self.assertIn('--analyzer "$XCAMP_ANALYZER"', text)
        self.assertIn("analyzer is not shipped", text)
        self.assertIn("--require exports:3", text)
        self.assertIn('--loc "exports=$RUNNER_TEMP/xt/exports"', text)
        self.assertIn("--require bundle-files:6", text)
        self.assertIn('--loc "bundle-files=$RUNNER_TEMP/xt/exports/export-bundle"', text)
        self.assertNotIn("xtrace export exits 9", text)
        self.assertNotIn("while it exits 9", text)

    def test_focused_artifacts_and_repeated_runs_are_scanned_independently(self):
        text = (ROOT / ".github/workflows/campaigns.yml").read_text()
        self.assertIn("--require focused-artifacts:1", text)
        self.assertIn('--loc "focused-artifacts=${FLOWS_DIR:-/nonexistent}/api-focused"', text)
        self.assertIn("--require standard-artifacts:1", text)
        self.assertIn('--loc "standard-artifacts=${FLOWS_DIR:-/nonexistent}/api-standard"', text)
        self.assertIn("--require overhead-artifacts:1", text)
        self.assertIn('--loc "overhead-artifacts=$CAMP_ROOT/java/petclinic/overhead"', text)
        flows = text[text.index("      - name: Product flows,"):text.index("      - name: Privacy canary scan")]
        self.assertIn('export XCAMP_CANARY_FILE="$RUNNER_TEMP/priv/canaries.json"', flows)
        self.assertIn('camp_overhead.py --manifest "$CAMP_ROOT/java/petclinic/overhead/runs.json"', text)


if __name__ == "__main__":
    unittest.main()
