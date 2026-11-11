import fnmatch
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.qa import lane_run, workflow_lint


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

    def test_bounded_apt_installs_and_job_timeouts_are_preserved_in_both_workflows(self):
        installs = 0
        for filename in ("ci.yml", "macos.yml"):
            workflow = workflow_lint.load(ROOT / ".github/workflows" / filename)
            for job_id, job in workflow["jobs"].items():
                with self.subTest(workflow=filename, job=job_id):
                    self.assertGreater(job["timeout-minutes"], 0)
                    for step in job["steps"]:
                        run = step.get("run", "")
                        if "apt-get" not in run:
                            continue
                        installs += 1
                        self.assertEqual(step["timeout-minutes"], 10)
                        self.assertEqual(run.count("sudo -n env DEBIAN_FRONTEND=noninteractive apt-get"), 2)
                        for option in ("Acquire::Retries=3", "Acquire::http::Timeout=30",
                                       "Acquire::https::Timeout=30", "DPkg::Lock::Timeout=60"):
                            self.assertEqual(run.count(f"-o {option}"), 2)
                        self.assertIn("-o APT::Update::Error-Mode=any update", run)
                        self.assertIn("install --yes", run)
                        self.assertIn("lsof", run)
        self.assertEqual(installs, 3)

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

    def test_private_storage_ci_feature_and_channels_stay_out_of_packaging(self):
        manifest = (ROOT / "crates/xtrace-private-storage/Cargo.toml").read_text()
        self.assertRegex(manifest, r"(?m)^ci-diagnostics = \[\]$")
        default = re.search(r"(?m)^default\s*=\s*\[([^]]*)\]", manifest)
        self.assertNotIn("ci-diagnostics", default[1] if default else "")
        package = (ROOT / "packaging/build.py").read_text()
        self.assertIn('["cargo", "build", "--release", "--locked", "-p", "xtrace-cli"]', package)
        self.assertNotIn("ci-diagnostics", package)
        self.assertNotIn("--all-features", package)
        jobs = self.workflow["jobs"]
        gates = jobs["gates"]["steps"]
        tests = next(step for step in gates if step.get("name") == "Unit and integration tests")
        self.assertIn('export XTRACE_CI_DIAG_DIR="${RUNNER_TEMP:?}/xt/frag/ci-diag"', tests["run"])
        self.assertIn("cargo test --locked --workspace --all-features --no-fail-fast", tests["run"])
        scratch = next(step for step in gates if step.get("name") == "Admit private test scratch before cargo tests")
        self.assertIn('"$root/frag/ci-diag"', scratch["run"])
        floor = jobs["release-floor-linux-x86_64"]["steps"]
        run = next(step for step in floor if step.get("name") == "Run all 23 pinned release gates")
        self.assertEqual(run["env"]["XTRACE_CI_DIAG_DIR"], "${{ env.XTRACE_CI_PRIVATE_ROOT }}/frag/ci-diag")
        admission = next(step for step in floor if step.get("name") == "Admit private logs, leases, caches, and test scratch before writes")
        self.assertIn('mkdir -m 700 "$XTRACE_CI_PRIVATE_ROOT/frag" "$XTRACE_CI_PRIVATE_ROOT/frag/ci-diag"', admission["run"])

    def test_release_guard_is_compiled_for_explicit_and_all_features_on_both_platforms(self):
        source = (ROOT / "crates/xtrace-private-storage/src/diagnostic.rs").read_text()
        guard = "ci-diagnostics requires debug_assertions; release/package builds must exclude it"
        self.assertIn('#[cfg(all(feature = "ci-diagnostics", not(debug_assertions)))]\n'
                      f'compile_error!("{guard}");', source)
        self.assertIn('#[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]\nmod ci', source)
        for filename, job_id in (("ci.yml", "gates"), ("macos.yml", "macos-arm64")):
            workflow = workflow_lint.load(ROOT / ".github/workflows" / filename)
            steps = workflow["jobs"][job_id]["steps"]
            step = next(s for s in steps if s.get("name") == "Reject release CI diagnostic channel")
            run = step["run"]
            with self.subTest(workflow=filename):
                self.assertNotIn("continue-on-error", step)
                self.assertIn("set -euo pipefail", run)
                self.assertIn("umask 077", run)
                self.assertNotIn("runner.temp", (ROOT / ".github/workflows" / filename).read_text())
                self.assertEqual(run.count("exit 1"), 4)
                self.assertEqual(run.count(f"grep -F '{guard}'"), 2)
                override_guard = "ci-diagnostics is forbidden in release profiles even with debug assertions"
                self.assertEqual(run.count(f"grep -F '{override_guard}'"), 2)
                for features in ("--features ci-diagnostics", "--all-features"):
                    self.assertIn("if cargo check --release --locked -p xtrace-private-storage "
                                  + features + ' >"$log" 2>&1; then', run)
                    self.assertIn("if CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo check "
                                  "--release --locked -p xtrace-private-storage "
                                  + features + ' >"$log" 2>&1; then', run)
            for job in workflow["jobs"].values():
                self.assertNotIn("XTRACE_CI_DIAG_DIR", job.get("env", {}))
                for candidate in job["steps"]:
                    command = candidate.get("run", "")
                    if candidate.get("name") == step["name"]:
                        continue
                    if "--release" in command or "packaging/build.py" in command:
                        self.assertNotIn("ci-diagnostics", command)
                        self.assertNotIn("--all-features", command)


    def test_release_packaging_checks_reject_diagnostics_with_debug_assertions(self):
        # ci.yml's gates job runs this module. Execute both existing packaging
        # checks with the override that used to bypass the source-level guard.
        for filename, job_id in (("ci.yml", "gates"), ("macos.yml", "macos-arm64")):
            workflow = workflow_lint.load(ROOT / ".github/workflows" / filename)
            step = next(s for s in workflow["jobs"][job_id]["steps"]
                        if s.get("name") == "Reject release CI diagnostic channel")
            with self.subTest(workflow=filename), tempfile.TemporaryDirectory() as temporary:
                result = subprocess.run(
                    ["bash", "-e", "-c", step["run"]], cwd=ROOT,
                    env={**os.environ, "RUNNER_TEMP": temporary,
                         "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS": "true"},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                log = (pathlib.Path(temporary) / "ci-diagnostics-release.log").read_text()
                self.assertIn(
                    "ci-diagnostics is forbidden in release profiles even with debug assertions", log,
                )


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

    def test_rust_diagnostics_use_private_fragment_storage_and_test_only_feature(self):
        steps = self.workflow["jobs"]["macos-arm64"]["steps"]
        rust = next(step for step in steps if step.get("name") == "cargo test (locked workspace, no ignored tests)")
        self.assertEqual(rust["env"]["XTRACE_CI_DIAG_DIR"], "${{ env.XTRACE_CI_PRIVATE_ROOT }}/frag")
        self.assertIn("cargo test --locked --workspace --all-features --no-fail-fast", rust["run"])
        for step in steps:
            if "packaging/build.py" in step.get("run", ""):
                self.assertNotIn("XTRACE_CI_DIAG_DIR", step.get("env", {}))
                self.assertNotIn("ci-diagnostics", step["run"])
        upload = next(step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertEqual(upload["with"]["path"], "${{ env.XTRACE_CI_PRIVATE_ROOT }}/frag/*.json")

    def test_store_measurements_reach_the_uploaded_rust_fragment_on_success_and_timeout(self):
        steps = self.workflow["jobs"]["macos-arm64"]["steps"]
        rust = [s for s in steps if "--suite rust" in s.get("run", "")
                and "--step test" in s["run"]]
        self.assertEqual(len(rust), 1)
        upload = next(s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertGreater(steps.index(upload), steps.index(rust[0]))
        self.assertEqual(upload["if"], "always()")
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out), tempfile.TemporaryDirectory() as temporary:
                directory = pathlib.Path(temporary) / "frag"
                command = shlex.split(rust[0]["run"].replace("$XTRACE_CI_PRIVATE_ROOT", temporary)
                                      .replace("${{ matrix.tuple }}", "jdk17-node22"))
                self.assertEqual(command[:4], ["python3", "-B", "-m", "tools.qa.lane_run"])

                def run(cmd, *, stdout, **kwargs):
                    self.assertEqual(kwargs["timeout"], 3000)
                    state = "progress" if timed_out else "returned"
                    (directory / "store-sparse-active.txt").write_text(
                        "elapsed_ns=900 completed=256 active=journal_append".ljust(159) + "\n")
                    (directory / "store-sparse-progress.txt").write_text(
                        "expected_admissions=4096 counted_journal_syncs=false\n"
                        f"state={state} completed=256 elapsed_ns=800\n"
                        "phase=journal_append spans=3 total_ns=500 max_ns=300 acl_probes=2\n"
                        "phase=private_payload spans=3 total_ns=500 max_ns=300 acl_probes=2\n")
                    stdout.write(b"private log token=private_payload\n"
                                 b"test result: ok. 1030 passed; 0 failed; 0 ignored\n")
                    stdout.flush()
                    if timed_out:
                        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
                    return subprocess.CompletedProcess(cmd, 0)

                with mock.patch.object(sys, "argv", ["lane_run", *command[4:]]), \
                        mock.patch.dict(os.environ, {"LANE_PRIVATE_LOG_DIR": temporary}), \
                        mock.patch.object(lane_run, "_checkout_metadata", return_value=lane_run.CheckoutMetadata({})), \
                        mock.patch.object(lane_run.subprocess, "run", side_effect=run):
                    self.assertEqual(lane_run.main(), 124 if timed_out else 0)
                fragment = directory / "rust__jdk17-node22__test.json"
                pattern = upload["with"]["path"].replace("${{ env.XTRACE_CI_PRIVATE_ROOT }}", temporary)
                self.assertTrue(fnmatch.fnmatch(str(fragment), pattern))
                self.assertFalse(fnmatch.fnmatch(str(directory / "store-sparse-progress.txt"), pattern))
                text = fragment.read_text()
                self.assertNotIn("private_payload", text)
                self.assertNotIn("private log", text)
                document = json.loads(text)
                self.assertEqual(document["status"], "fail" if timed_out else "pass")
                if timed_out:
                    self.assertTrue(document["timedOut"])
                self.assertEqual(document["storeProfiles"], {"sparse": {
                    "workload": {"expected_admissions": 4096, "counted_journal_syncs": 0},
                    "active": {"elapsed_ns": 900, "completed": 256, "active": "journal_append"},
                    "lastReport": {"state": "progress" if timed_out else "returned",
                                   "completed": 256, "elapsed_ns": 800},
                    "phases": {"journal_append": {"spans": 3, "total_ns": 500, "max_ns": 300, "acl_probes": 2}},
                }})

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
