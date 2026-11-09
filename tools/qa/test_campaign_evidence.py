import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]


class WorkflowEvidence(unittest.TestCase):
    def test_exports_use_real_analyzer_and_required_privacy_coverage(self):
        text = (ROOT / ".github/workflows/campaigns.yml").read_text()
        self.assertIn(":static-analyzer:installDist", text)
        self.assertIn('--analyzer "$XCAMP_ANALYZER"', text)
        self.assertIn("analyzer is not shipped", text)
        self.assertIn("--require exports:3", text)
        self.assertIn('--loc "exports=$RUNNER_TEMP/xt/exports"', text)
        self.assertNotIn("xtrace export exits 9", text)
        self.assertNotIn("while it exits 9", text)

    def test_focused_artifacts_and_repeated_runs_are_scanned_independently(self):
        text = (ROOT / ".github/workflows/campaigns.yml").read_text()
        self.assertIn("--require focused-artifacts:1", text)
        self.assertIn('--loc "focused-artifacts=${FLOWS_DIR:-/nonexistent}/api-focused"', text)
        self.assertIn("--require overhead-artifacts:1", text)
        self.assertIn('--loc "overhead-artifacts=$CAMP_ROOT/java/petclinic/overhead"', text)
        flows = text[text.index("      - name: Product flows,"):text.index("      - name: Privacy canary scan")]
        self.assertIn('export XCAMP_CANARY_FILE="$RUNNER_TEMP/priv/canaries.json"', flows)
        self.assertIn('camp_overhead.py --manifest "$CAMP_ROOT/java/petclinic/overhead/runs.json"', text)


if __name__ == "__main__":
    unittest.main()
