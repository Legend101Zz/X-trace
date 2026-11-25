"""Hosted driver sequencing and private diagnostics; subprocesses are never launched here."""
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_jhipster_evidence import campaign_harness

HARNESS = Path(__file__).resolve().parents[1] / "java/jhipster/harness"
SPEC = importlib.util.spec_from_file_location("jhipster_installed", HARNESS / "installed.py")
installed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installed)


class JHipsterInstalled(unittest.TestCase):
    def runner(self, root):
        (root / "console").mkdir()
        return installed.InstalledCampaign(root, root / "input", "a" * 64, "b" * 40, Path("/jdk/bin/java"))

    def test_phase_preserves_exact_exit_and_private_stderr_before_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = self.runner(root)
            with mock.patch.object(runner, "command", side_effect=lambda argv: (print("private cause", file=installed.sys.stderr), 37)[1]):
                self.assertEqual(runner.phase("baseline", lambda: runner.command(["unused"])), 37)
            rows = {row["name"]: row for row in json.loads((root / "phases.json").read_text())["phases"]}
            self.assertEqual(rows["baseline"], {"name": "baseline", "status": "failed", "exitCode": 37})
            self.assertEqual(rows["instrumented"]["status"], "unreached")
            self.assertIsNone(rows["instrumented"]["exitCode"])
            self.assertIn("private cause", (root / "console/baseline.stderr").read_text())
            self.assertFalse((root / "campaign/java/jhipster/baseline-1/receipt.json").exists())

    def test_failed_archive_verifier_never_runs_the_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(Path(tmp))
            with mock.patch.object(runner, "prerequisites", return_value=0), \
                    mock.patch.object(runner, "verify_archive", return_value=19), \
                    mock.patch.object(runner, "install") as install:
                self.assertEqual(runner.run(), 19)
            install.assert_not_called()

    def test_successful_verifier_still_requires_exact_package_source_and_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = self.runner(root)
            report = root / "package-verification.json"
            for package in ({"sourceCommit": "c" * 40, "platform": "linux-x86_64"},
                            {"sourceCommit": "b" * 40, "platform": "macos-arm64"}):
                report.write_text(json.dumps({"ok": True, "package": package}))
                with mock.patch.object(installed, "digest", return_value="a" * 64), \
                        mock.patch.object(runner, "command", return_value=0) as command:
                    with self.assertRaisesRegex(ValueError, "exact build identity"):
                        runner.verify_archive()
                    self.assertIn("--run-binary", command.call_args.args[0])
                    self.assertIn("--repo", command.call_args.args[0])

    def test_changed_archive_is_rejected_before_installer_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(Path(tmp))
            with mock.patch.object(installed, "digest", return_value="c" * 64), \
                    mock.patch.object(runner, "command") as command:
                with self.assertRaisesRegex(ValueError, "archive changed"):
                    runner.install()
                command.assert_not_called()

    def test_baseline_failure_never_claims_instrumented_or_sink_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(Path(tmp))
            observed = []
            def phase(name, operation):
                observed.append(name)
                return 41 if name == "baseline" else 0
            with mock.patch.object(runner, "phase", side_effect=phase):
                self.assertEqual(runner.run(), 41)
            self.assertEqual(observed, list(installed.PHASES[:7]))

    def test_product_gap_still_collects_sinks_and_keeps_original_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(Path(tmp))
            observed = []
            def phase(name, operation):
                observed.append(name)
                return 1 if name == "instrumented" else 0
            with mock.patch.object(runner, "phase", side_effect=phase):
                self.assertEqual(runner.run(), 1)
            self.assertEqual(observed, list(installed.PHASES))

    def test_clean_workload_cannot_hide_failed_sink_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = self.runner(Path(tmp))
            with mock.patch.object(runner, "phase", side_effect=lambda name, operation: 23 if name == "collect-sinks" else 0):
                self.assertEqual(runner.run(), 23)

    def test_runner_removes_inherited_instrumentation_and_body_dump(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "JAVA_TOOL_OPTIONS": "private", "XCAMP_LAUNCH_PREFIX": "private", "XCAMP_DUMP_BODIES": "private"}):
            runner = self.runner(Path(tmp))
            for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "XCAMP_LAUNCH_PREFIX", "XCAMP_DUMP_BODIES"):
                self.assertNotIn(key, runner.env)
            self.assertEqual(runner.env["XCAMP_JAVA"], "/jdk/bin/java")

    def test_prepared_root_rejects_existing_product_state_and_failed_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            parent.chmod(0o700)
            root = parent / "run"
            root.mkdir(mode=0o700)
            (root / "console").mkdir(mode=0o700)
            seed = root / "build-status.json"
            seed.write_text(json.dumps({"schema": "xtrace-jhipster-build/1", "exitCode": 7}))
            seed.chmod(0o600)
            for name in ("package-build.stdout", "package-build.stderr"):
                path = root / "console" / name
                path.touch(mode=0o600)
            # CI temporary-directory ancestors can differ across runners; this test
            # isolates the preexisting-state invariant from ancestor admission.
            with mock.patch.object(installed, "private_parent"):
                with self.assertRaisesRegex(ValueError, "did not complete"):
                    installed.prepare_root(root)
                seed.write_text(json.dumps({"schema": "xtrace-jhipster-build/1", "exitCode": 0}))
                installed.prepare_root(root)
                self.assertTrue((root / "home").is_dir())
                with self.assertRaisesRegex(ValueError, "already contains run state"):
                    installed.prepare_root(root)

    def test_admission_signal_is_created_only_after_prepare_root_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "run"
            root.mkdir(mode=0o700)
            driver = parent / "driver"
            driver.mkdir(mode=0o700)
            order = []
            mark = installed.mark_root_admitted
            def prepared(path):
                self.assertFalse((driver / "admission.json").exists())
                order.append("prepared")
            def admitted(path):
                order.append("admitted")
                mark(path)
            args = ["--private-root", str(root), "--archive", str(parent / "unused"),
                    "--package-sha256", "a" * 64, "--source-sha", "b" * 40, "--java", "/jdk/bin/java"]
            with mock.patch.object(installed, "prepare_root", side_effect=prepared), \
                    mock.patch.object(installed, "mark_root_admitted", side_effect=admitted), \
                    mock.patch.object(installed, "InstalledCampaign") as campaign, mock.patch.object(installed.os, "umask"):
                campaign.return_value.run.return_value = 0
                self.assertEqual(installed.main(args), 0)
            self.assertEqual(order, ["prepared", "admitted"])
            self.assertTrue((driver / "admission.json").is_file())

    def test_traceback_requires_opt_in_and_an_owner_only_regular_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = campaign_harness(Path(tmp))
            public = io.StringIO()
            with mock.patch.dict(os.environ, {"XCAMP_PRIVATE_PREPARATION_TRACEBACK": "1"}), redirect_stderr(public):
                try:
                    raise ValueError("sensitive setup detail")
                except ValueError:
                    harness.private_preparation_traceback()
            self.assertEqual(public.getvalue(), "")
            sink = Path(tmp) / "diagnosis"
            with sink.open("w") as stream:
                sink.chmod(0o600)
                with mock.patch.dict(os.environ, {"XCAMP_PRIVATE_PREPARATION_TRACEBACK": "1"}), redirect_stderr(stream):
                    try:
                        raise ValueError("sensitive setup detail")
                    except ValueError:
                        harness.private_preparation_traceback()
            self.assertIn("ValueError: sensitive setup detail", sink.read_text())
            with sink.open("w") as stream:
                sink.chmod(0o644)
                with mock.patch.dict(os.environ, {"XCAMP_PRIVATE_PREPARATION_TRACEBACK": "1"}), redirect_stderr(stream):
                    try:
                        raise ValueError("sensitive setup detail")
                    except ValueError:
                        harness.private_preparation_traceback()
            self.assertEqual(sink.read_text(), "")


if __name__ == "__main__":
    unittest.main()
