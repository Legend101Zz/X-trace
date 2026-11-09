import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

from tools.qa import workflow_lint


ROOT = pathlib.Path(__file__).resolve().parents[2]


class WorkflowLintTests(unittest.TestCase):
    workflow = """permissions:
  contents: read
jobs:
  test:
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
"""

    def lint_text(self, text, strict_timeouts=False):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "workflow.yml"
            path.write_text(text, encoding="utf-8")
            return workflow_lint.lint(path, strict_timeouts)

    def test_valid_workflow_and_ci_extensions_are_accepted(self):
        self.assertEqual(self.lint_text(self.workflow, strict_timeouts=True), [])
        self.assertEqual(workflow_lint.lint(ROOT / ".github/workflows/ci.yml", False), [])

    def test_security_rules_still_reject_unsafe_workflows(self):
        cases = (
            (self.workflow.replace("contents: read", "contents: write"), "top-level permissions"),
            (self.workflow.replace("    timeout-minutes:", "    permissions: {contents: write}\n    timeout-minutes:"), "elevates permissions"),
            (self.workflow.replace("11d5960a326750d5838078e36cf38b85af677262", "v4"), "unpinned action"),
            (self.workflow.replace("persist-credentials: false", "persist-credentials: true"), "checkout lacks persist-credentials false"),
            (self.workflow + "# GITHUB_TOKEN\n", "references github.token or GITHUB_TOKEN"),
            (self.workflow + "# secrets.example\n", "references secrets"),
        )
        for text, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                self.assertTrue(any(diagnostic in problem for problem in self.lint_text(text)))

    def test_strict_timeout_rule_is_preserved(self):
        text = self.workflow.replace("    timeout-minutes: 5\n", "")
        self.assertEqual(self.lint_text(text), [])
        self.assertEqual(self.lint_text(text, True), ["workflow.yml: job test has no timeout-minutes"])

    def test_invalid_yaml_is_rejected(self):
        self.assertEqual(self.lint_text("jobs: [\n"), ["workflow.yml: does not parse"])


class CiPullRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = workflow_lint.load(ROOT / ".github/workflows/ci.yml")

    def test_concurrency_cancels_only_pull_requests(self):
        self.assertEqual(self.workflow["concurrency"], {
            "group": "${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}",
            "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
        })

    def test_every_source_job_checks_out_the_same_exact_head(self):
        jobs = self.workflow["jobs"]
        self.assertEqual(set(jobs) - {"ci-ok"}, {
            "release-tool-tests", "release-floor-linux-x86_64", "java-client", "node-client", "gates",
        })
        expected = "${{ github.event.pull_request.head.sha || github.sha }}"
        self.assertEqual(self.workflow["env"]["XTRACE_CI_SOURCE_SHA"], expected)
        for job_id, job in jobs.items():
            if job_id == "ci-ok":
                continue
            with self.subTest(job=job_id):
                checkouts = [step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@")]
                self.assertEqual(len(checkouts), 1)
                self.assertEqual(checkouts[0]["with"]["ref"], expected)
                if job_id.startswith("release-"):
                    self.assertEqual(checkouts[0]["with"]["fetch-depth"], 0)
                for step in job["steps"]:
                    run = step.get("run", "")
                    self.assertNotIn("$GITHUB_SHA", run)
                    for line in run.splitlines():
                        if "--expected-head" in line or "--source-sha" in line:
                            self.assertIn('"$XTRACE_CI_SOURCE_SHA"', line)

    def test_aggregator_covers_every_job_and_rejects_each_non_success(self):
        jobs = self.workflow["jobs"]
        aggregator = jobs["ci-ok"]
        needed = aggregator["needs"]
        self.assertEqual(set(needed), set(jobs) - {"ci-ok"})
        self.assertEqual(aggregator["if"], "always()")
        self.assertEqual(len(aggregator["steps"]), 1)
        step = aggregator["steps"][0]
        self.assertNotIn("uses", step)
        self.assertEqual(step["env"], {"NEEDS_JSON": "${{ toJSON(needs) }}"})
        results = {job: {"result": "success"} for job in needed}

        def run_check():
            return subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                env={**os.environ, "NEEDS_JSON": json.dumps(results)},
                capture_output=True, text=True, check=False,
            ).returncode

        self.assertEqual(run_check(), 0)
        for job in needed:
            for result in ("failure", "skipped", "cancelled", ""):
                with self.subTest(job=job, result=result):
                    results[job]["result"] = result
                    self.assertNotEqual(run_check(), 0)
            results[job]["result"] = "success"


class MacosWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / ".github/workflows/macos.yml"
        cls.workflow = workflow_lint.load(cls.path)

    def test_only_manual_and_wave_or_release_candidate_pushes_trigger(self):
        # Ruby's YAML 1.1 parser represents the unquoted `on` key as JSON's "true".
        triggers = self.workflow.get("on", self.workflow.get("true"))
        self.assertEqual(triggers, {
            "workflow_dispatch": None,
            "push": {"branches": ["wave/**", "ultra/rc-*"]},
        })
        self.assertEqual(self.workflow["concurrency"], {
            "group": "${{ github.workflow }}-${{ github.ref }}",
            "cancel-in-progress": False,
        })
        self.assertEqual(workflow_lint.lint(self.path, True), [])

    def test_source_jobs_use_the_exact_head(self):
        jobs = self.workflow["jobs"]
        self.assertEqual(set(jobs), {"release-tool-tests", "macos-arm64", "macos-ok"})
        expected = "${{ github.event.pull_request.head.sha || github.sha }}"
        self.assertEqual(self.workflow["env"]["XTRACE_CI_SOURCE_SHA"], expected)
        for job_id in ("release-tool-tests", "macos-arm64"):
            with self.subTest(job=job_id):
                steps = jobs[job_id]["steps"]
                checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
                self.assertEqual(len(checkouts), 1)
                self.assertEqual(checkouts[0]["with"], {
                    "ref": expected, "fetch-depth": 0, "persist-credentials": False,
                })
                for step in steps:
                    run = step.get("run", "")
                    self.assertNotIn("$GITHUB_SHA", run)
                    for line in run.splitlines():
                        if "--expected-head" in line or "--source-sha" in line:
                            self.assertIn('"$XTRACE_CI_SOURCE_SHA"', line)

    def test_original_matrix_timeout_and_test_floors_are_preserved(self):
        job = self.workflow["jobs"]["macos-arm64"]
        self.assertEqual(job["needs"], "release-tool-tests")
        self.assertEqual(job["runs-on"], "macos-15")
        self.assertEqual(job["timeout-minutes"], 180)
        self.assertEqual(job["strategy"], {
            "fail-fast": False,
            "matrix": {"include": [
                {"tuple": "jdk17-node22", "java-version": 17, "node-version": 22},
                {"tuple": "jdk21-node24", "java-version": 21, "node-version": 24},
            ]},
        })
        floors = {}
        for step in job["steps"]:
            run = step.get("run", "")
            if "--min-passed" in run:
                suite = re.search(r"--suite (\w+)", run).group(1)
                floors[suite] = int(re.search(r"--min-passed (\d+)", run).group(1))
                self.assertIn("--max-ignored 0", run)
                self.assertEqual(step["if"], "${{ !cancelled() }}")
        self.assertEqual(floors, {"node": 85, "web": 75, "java": 190, "rust": 1030})

    def test_uploads_only_fragment_json_and_linux_floor_keeps_its_separate_sanitizer(self):
        steps = self.workflow["jobs"]["macos-arm64"]["steps"]
        uploads = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(uploads[0]["if"], "always()")
        self.assertEqual(uploads[0]["with"]["path"], "${{ env.XTRACE_CI_PRIVATE_ROOT }}/frag/*.json")
        linux = workflow_lint.load(ROOT / ".github/workflows/ci.yml")
        steps = linux["jobs"]["release-floor-linux-x86_64"]["steps"]
        self.assertTrue(any("tools.release.ci_floor sanitize-floor" in s.get("run", "") for s in steps))
        self.assertFalse(any("tools.qa.lane_run" in s.get("run", "") for s in steps))
        uploads = [s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual([s["with"]["path"] for s in uploads],
                         ["${{ env.XTRACE_CI_PRIVATE_ROOT }}/release-floor-summary.json"])

    def test_aggregator_covers_every_job_and_rejects_each_non_success(self):
        jobs = self.workflow["jobs"]
        aggregator = jobs["macos-ok"]
        needed = aggregator["needs"]
        self.assertEqual(set(needed), set(jobs) - {"macos-ok"})
        self.assertEqual(aggregator["if"], "always()")
        self.assertEqual(aggregator["timeout-minutes"], 5)
        self.assertEqual(len(aggregator["steps"]), 1)
        step = aggregator["steps"][0]
        self.assertNotIn("uses", step)
        self.assertEqual(step["env"], {"NEEDS_JSON": "${{ toJSON(needs) }}"})
        results = {job: {"result": "success"} for job in needed}

        def run_check():
            return subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                env={**os.environ, "NEEDS_JSON": json.dumps(results)},
                capture_output=True, text=True, check=False,
            ).returncode

        self.assertEqual(run_check(), 0)
        for job in needed:
            for result in ("failure", "skipped", "cancelled", ""):
                with self.subTest(job=job, result=result):
                    results[job]["result"] = result
                    self.assertNotEqual(run_check(), 0)
            results[job]["result"] = "success"
