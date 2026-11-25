"""Hosted regression coverage for admitted inventories and fixed safe projections."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import zipfile

import installed_java
import installed_sinks
import xinstr
from private_sinks import AdmittedSinks
from tools.qa import canary

SPEC = importlib.util.spec_from_file_location("fineract_privacy", Path(__file__).resolve().parents[1] / "java/fineract/harness/privacy.py")
privacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(privacy)


class ProductSourceIdentity(unittest.TestCase):
    def test_same_sha_rejects_modified_deleted_staged_and_untracked_source(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            def git(*args):
                return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
            git("init", "-q")
            source = repo / "runner.py"
            source.write_text("original\n")
            git("add", "runner.py")
            git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgSign=false", "commit", "-qm", "fixture")
            sha = git("rev-parse", "HEAD")
            installed_java.clean_checkout(repo, sha)
            for mutation in ("modified", "deleted", "staged", "untracked"):
                with self.subTest(mutation=mutation):
                    if mutation == "deleted":
                        source.unlink()
                    elif mutation == "untracked":
                        (repo / "untracked.py").write_text("private\n")
                    else:
                        source.write_text("changed\n")
                        if mutation == "staged":
                            git("add", "runner.py")
                    with self.assertRaises(ValueError):
                        installed_java.clean_checkout(repo, sha)
                    if mutation == "untracked":
                        (repo / "untracked.py").unlink()
                    else:
                        git("restore", "--source=HEAD", "--staged", "--worktree", "runner.py")
            with self.assertRaises(ValueError):
                installed_java.clean_checkout(repo, "f" * 40)


class FineractPrivacy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name).resolve()
        self.root = self.parent / "run"
        self.root.mkdir(mode=0o700)
        (self.parent / "driver").mkdir(mode=0o700)
        self.previous_umask = os.umask(0o077)
        # Only system temporary ancestors are outside this test's scope. Entry
        # ownership/modes, symlinks, content hashes and inode admission remain real.
        self.private_parent = mock.patch.object(installed_java, "private_dir", side_effect=lambda p: Path(p).absolute())
        self.private_parent.start()
        privacy.mark_admitted(self.root)
        self.values = canary.make_canaries()
        self.file("canaries.json", json.dumps(self.values))

    def tearDown(self):
        self.private_parent.stop()
        os.umask(self.previous_umask)
        self.temp.cleanup()

    def file(self, relative, content="observed"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(content)
        return path

    def complete_sinks(self):
        base = "campaign/java/fineract"
        capture = base + "/instrumented-1/capture"
        for path in ("console/instrumented.stdout", base + "/baseline-1/application.log", "data/store.db",
                     capture + "/application.log", capture + "/viewer.log", capture + "/boundary-viewer.log", "tmp/launcher.log",
                     "sinks/cli/list.stdout", base + "/src/.xtrace/config.toml", "package-verification.json",
                     "package-runtime-verification.json", "installed X-trace/install-receipt.json"):
            self.file(path)
        (self.root / "home").mkdir(mode=0o700)
        for folder in ("api", "boundary-before", "phase-1-api", "phase-2-api", "phase-3-api"):
            self.file(capture + "/" + folder + "/page.json", '{"events":[]}')
        (self.root / "child-stderr").mkdir(mode=0o700)
        self.file("sinks/cli-status.json", json.dumps(dict(schema="xtrace-fineract-cli-sinks/1", complete=True,
                                                         artifactComplete=True, recordings=1, commandExits=[0, 0])))
        with zipfile.ZipFile(self.root / "sinks/recordings.zip", "x") as archive:
            archive.writestr("api.json", '{"events":[]}')
        probes = [dict(label="authorization", status=401, surfaces=["authorization-header"], passed=True),
                  dict(label="cookie-query-body", status=401,
                       surfaces=["cookie-header", "query-token", "json-body-password"], passed=True),
                  dict(label="authenticated-read", status=200, surfaces=["cookie-header", "query-token"], passed=True),
                  dict(label="authenticated-validation", status=400, surfaces=["json-body-password"], passed=True),
                  dict(label="environment", surfaces=["env-var"], passed=True)]
        for probe in probes:
            probe.update(problems=[])
            if probe["label"] != "environment":
                probe.update(recordings=1)
        receipt = dict(schemaVersion=1, kind="instrumented_campaign_non_release", project="fineract", releaseAcceptance=False, instrumented=True,
                       api=dict(ok=True, incompleteDetails=0, recordings=1, listReadGap=None), notes=dict(canaryProbes=probes),
                       scenarios=[], problemClasses={})
        self.file(capture + "/receipt.json", json.dumps(receipt))
        (self.parent / "driver/stdout").write_text("fixed driver status\n")
        (self.parent / "driver/stderr").touch(mode=0o600)
        (self.parent / "driver/status.json").write_text(json.dumps(dict(schema="xtrace-fineract-driver/1", exitCode=0)))
        phases = dict(schema="xtrace-fineract-installed-phases/1", sourceIdentityVerified=True, phases=[dict(name=name, status="passed", exitCode=0) for name in privacy.PHASES])
        self.file("phases.json", json.dumps(phases))
        evidence = privacy.PrivacyEvidence(self.root)
        for phase in privacy.PHASES:
            evidence.snapshot(phase, phases)
        return evidence, phases, receipt

    def test_failed_installed_verifier_preserves_its_actual_private_stderr(self):
        original = self.root / "original"
        prefix = self.root / "prefix"
        current = prefix / "versions/0.0.1"
        for name in ("bin/xtrace", "install.sh", "share/xtrace/packs/java/agent/xtrace-java-agent.jar",
                     "share/xtrace/analyzers/java/bin/xtrace-java-static"):
            path = original / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"verified payload")
            path.chmod(0o755)
        shutil.copytree(original, current)
        (prefix / "current").symlink_to("versions/0.0.1", target_is_directory=True)
        (prefix / "bin").mkdir()
        (prefix / "bin/xtrace").symlink_to("../current/bin/xtrace")
        archive = self.file("archive.tar.gz", "archive")
        captures = self.root / "child-stderr"
        captures.mkdir(mode=0o700)
        package = mock.Mock()
        package.verify.return_value = dict(ok=True, package=dict(sourceCommit="b" * 40, platform="linux-x86_64"))
        package.resolve_root.return_value = original
        with mock.patch.object(installed_java, "verifier", return_value=package), \
                mock.patch.dict(os.environ, XCAMP_PRIVATE_CHILD_STDERR_DIR=str(captures), XCAMP_DIAGNOSTIC_PHASE="instrumented"), \
                mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 19, b"", b"private verifier cause")):
            with self.assertRaises(ValueError):
                installed_java.installed_package(prefix, archive, installed_java.xcamp.sha256_file(archive), "b" * 40,
                                                self.root / "extract")
        self.assertEqual((captures / "instrumented-installed-payload-verify.stderr").read_bytes(), b"private verifier cause")
        self.assertEqual(json.loads((captures / "instrumented-installed-payload-verify.json").read_text())["exitCode"], 19)

    def test_fineract_ordered_init_and_stop_preserve_failed_child_stderr(self):
        for failure in ("init", "stop"):
            with self.subTest(failure=failure):
                captures = self.root / failure
                captures.mkdir(mode=0o700)
                stack = SimpleNamespace(env={}, up=mock.Mock(side_effect=RuntimeError("startup refused")),
                                        down=mock.Mock(), logs=mock.Mock(return_value="private application output"), launcher_exit=19)
                def child(args, **kwargs):
                    return subprocess.CompletedProcess(args, 19 if args[1] == failure else 0, b"", b"private " + failure.encode())
                judge = lambda details, expectations, phases, probes: ({"s": dict(passed=False, expectations=[],
                         problems=["scenario-unreached"], frameSymbols=[])}, [], set(), set(), [])
                ordered = xinstr.OrderedCampaign(frozenset(), lambda base, values: [], judge)
                with mock.patch.dict(os.environ, XCAMP_PRIVATE_CHILD_STDERR_DIR=str(captures), XCAMP_DIAGNOSTIC_PHASE="instrumented"), \
                        mock.patch.object(subprocess, "run", side_effect=child), \
                        mock.patch.object(xinstr, "list_recording_ids", return_value=set()), \
                        mock.patch.object(xinstr, "start_viewer", side_effect=RuntimeError("viewer unavailable")):
                    kwargs = dict(project="fineract", pin={}, make_stack=lambda tag: stack,
                                  scenarios=[SimpleNamespace(id="s", kind="business")], out_dir=self.root / (failure + "-capture"),
                                  norm_extra=[], expectations={"s": [{"method": "GET", "route": "/"}]}, xtrace="installed",
                                  project_dir=self.root, data_home=self.root / "data", adaptations=[], canaries=self.values,
                                  baseline_receipt=None, extra_canary_paths=[], harness_files=[], ordered_campaign=ordered)
                    if failure == "init":
                        with self.assertRaises(RuntimeError):
                            xinstr.run_instrumented(**kwargs)
                    else:
                        receipt = xinstr.run_instrumented(**kwargs)
                        self.assertEqual(receipt["notes"]["stopCommand"]["exitCode"], 19)
                        self.assertFalse(receipt["workloadsPassed"])
                self.assertEqual((captures / f"instrumented-{failure}.stderr").read_bytes(), b"private " + failure.encode())

    def test_cli_collection_retains_failed_stream_and_does_not_credit_partial_list(self):
        capture = self.root / "campaign/java/fineract/instrumented-1/capture"
        self.file(str(capture.relative_to(self.root)) + "/api/page.json", '{"recordings":[]}')
        def fail(args, **kwargs):
            kwargs["stderr"].write(b"private CLI refusal")
            return subprocess.CompletedProcess(args, 23)
        with mock.patch.object(subprocess, "run", side_effect=fail):
            self.assertFalse(installed_sinks.collect(self.root, "fineract", capture))
        status = json.loads((self.root / "sinks/cli-status.json").read_text())
        self.assertFalse(status["complete"])
        self.assertEqual(status["commandExits"], [23])
        self.assertEqual((self.root / "sinks/cli/list-00.stderr").read_bytes(), b"private CLI refusal")

    def test_complete_actual_sink_corpus_can_pass_scan_without_accepting_missing_workloads(self):
        evidence, phases, _ = self.complete_sinks()
        report = evidence.scan(phases, final=True)
        self.assertTrue(report["clean"])
        self.assertFalse(report["scopeComplete"])
        self.assertIn("valid-authorization-recording-not-exercised", report["scopeGaps"])
        self.assertEqual(report["sinks"]["child-stderr"]["status"], "not-produced")
        self.assertFalse(privacy.finalize(self.root, self.parent / "public"))
        summary = json.loads((self.parent / "public/summary.json").read_text())
        self.assertEqual(summary["privacy"]["status"], "passed")
        self.assertEqual(summary["instrumented"][0]["workload"], "not-observed")
        self.assertFalse(summary["releaseAcceptance"])

    def test_failed_or_unattributed_denied_probe_never_clears_privacy_gate(self):
        evidence, phases, receipt = self.complete_sinks()
        probe = receipt["notes"]["canaryProbes"][0]
        for changes in (dict(passed=False, problems=["probe-recording-attribution-unavailable"]),
                        dict(passed=True, problems=[], recordings=0),
                        dict(passed=True, problems=[], recordings=True)):
            with self.subTest(changes=changes):
                probe.update(changes)
                self.file("campaign/java/fineract/instrumented-1/capture/receipt.json", json.dumps(receipt))
                report = evidence.scan(phases, final=True)
                self.assertFalse(report["clean"])
                row = next(row for row in report["canaryInjection"] if row["kind"] == "authorization-header")
                self.assertEqual(row["recordingAttribution"], "failed")

    def test_denied_delivery_cannot_replace_missing_positive_probe_or_duplicate_receipt(self):
        evidence, phases, receipt = self.complete_sinks()
        probes = receipt["notes"]["canaryProbes"]
        probes[:] = [p for p in probes if p["label"] != "authenticated-read"]
        self.file("campaign/java/fineract/instrumented-1/capture/receipt.json", json.dumps(receipt))
        report = evidence.scan(phases, final=True)
        self.assertFalse(report["clean"])
        row = next(row for row in report["canaryInjection"] if row["kind"] == "query-token")
        self.assertEqual(row["recordableSurface"], "failed")
        probes.append(dict(probes[0]))
        self.file("campaign/java/fineract/instrumented-1/capture/receipt.json", json.dumps(receipt))
        row = next(row for row in evidence.scan(phases, final=True)["canaryInjection"] if row["kind"] == "authorization-header")
        self.assertEqual(row["delivery"], "not-observed")

    def test_actual_receipts_pointer_metadata_and_new_outputs_are_scanned(self):
        evidence, phases, _ = self.complete_sinks()
        targets = (("capture-output", "campaign/java/fineract/instrumented-1/capture/receipt.json"),
                   ("project-pointer", "campaign/java/fineract/src/.xtrace/config.toml"),
                   ("baseline-output", "campaign/java/fineract/baseline-1/receipt.json"),
                   ("campaign-metadata", "phases.json"), ("package-verification", "package-verification.json"),
                   ("install-receipt", "installed X-trace/install-receipt.json"),
                   ("home-output", "home/diagnostic.txt"), ("other-generated-output", "sinks/cli-status.json"),
                   ("other-generated-output", "new-output.json"),
                   ("other-generated-output", "campaign/java/fineract/instrumented-1/failure.json"),
                   ("privacy-reports", "privacy/diagnostic.json"))
        for name, relative in targets:
            with self.subTest(sink=name, relative=relative):
                path = self.root / relative
                original = path.read_bytes() if path.exists() else None
                self.file(relative, self.values["query-token"])
                report = evidence.scan(phases, final=True)
                self.assertFalse(report["clean"])
                self.assertEqual(report["sinks"][name]["status"], "failed")
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
        driver = self.parent / "driver/status.json"
        driver.write_text(self.values["query-token"])
        self.assertEqual(evidence.scan(phases, final=True)["sinks"]["outer-driver-output"]["status"], "failed")

    def test_unreached_phase_cannot_hide_produced_receipt_and_canary_controls_are_excluded(self):
        evidence, phases, _ = self.complete_sinks()
        for row in phases["phases"]:
            if row["name"] == "instrumented":
                row.update(status="unreached", exitCode=None)
        self.file("campaign/java/fineract/instrumented-1/capture/failure.json", self.values["json-body-password"])
        report = evidence.scan(phases, final=True)
        self.assertEqual(report["sinks"]["capture-output"]["status"], "failed")
        self.assertFalse(report["clean"])
        # The generated control deliberately contains every canary, but the
        # unexpected-output inventory must not accidentally include that input.
        self.assertEqual(report["sinks"]["other-generated-output"]["status"], "passed")

    def test_missing_failure_capture_and_inventory_bound_are_not_passes(self):
        evidence, phases, _ = self.complete_sinks()
        self.file("child-stderr/instrumented-init.json", json.dumps(dict(schema="xtrace-private-child-stderr/1",
                  phase="instrumented", child="init", exitCode=19, timedOut=False, stderrState="captured")))
        report = evidence.scan(phases, final=True)
        self.assertFalse(report["clean"])
        self.assertEqual(report["sinks"]["child-stderr"]["status"], "scan-error")
        target = self.file("bounded.txt", "content")
        with mock.patch("private_sinks.MAX_FILE_BYTES", 1):
            self.assertEqual(AdmittedSinks(self.root).scan([target], self.values)[0]["status"], "unsafe-or-bound")

    def test_missing_empty_and_unreached_are_never_clean(self):
        sink = AdmittedSinks(self.root)
        self.assertEqual(sink.scan([self.root / "absent"], self.values)[0]["status"], "missing")
        (self.root / "empty").mkdir(mode=0o700)
        self.assertEqual(sink.scan([self.root / "empty"], self.values)[0]["status"], "empty")
        evidence = privacy.PrivacyEvidence(self.root)
        report = evidence.scan(None)
        self.assertFalse(report["clean"])
        self.assertEqual(report["sinks"]["api-json"]["status"], "unreached")

    def test_symlink_replacement_and_escape_are_refused(self):
        sink = AdmittedSinks(self.root)
        target = self.file("private.log")
        (self.root / "link").symlink_to(target)
        self.assertEqual(sink.scan([self.root / "link"], self.values)[0]["status"], "unsafe-or-bound")
        self.assertEqual(sink.scan([self.root / "../driver"], self.values)[0]["status"], "unsafe-or-bound")
        self.root.rename(self.parent / "old-run")
        self.root.mkdir(mode=0o700)
        self.assertFalse(privacy.admitted(self.root))
        with self.assertRaises(ValueError):
            sink.check_root()

    def test_canary_in_parent_name_and_private_compressed_artifact_is_detected(self):
        sink = AdmittedSinks(self.root)
        value = self.values["query-token"]
        named = self.file(value + "/output.json", "clean content")
        self.assertEqual(sink.scan([named], self.values)[0]["status"], "failed")
        archive = self.root / "artifact.zip"
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("private.json", self.values["json-body-password"])
        self.assertEqual(sink.scan([archive], self.values)[0]["status"], "failed")

    def test_mutation_during_scan_does_not_pass(self):
        path = self.file("output.json", "initial")
        original = canary.run_scan
        def mutate(*args, **kw):
            report = original(*args, **kw)
            path.write_text("changed")
            return report
        with mock.patch.object(canary, "run_scan", side_effect=mutate):
            status, _ = AdmittedSinks(self.root).scan([path], self.values)
        self.assertEqual(status["status"], "changed")

    def test_absent_canary_surface_and_absent_api_field_remain_gaps(self):
        evidence, phases, receipt = self.complete_sinks()
        receipt["notes"]["canaryProbes"][1]["surfaces"].remove("json-body-password")
        del receipt["api"]["listReadGap"]
        self.file("campaign/java/fineract/instrumented-1/capture/receipt.json", json.dumps(receipt))
        report = evidence.scan(phases, final=True)
        self.assertFalse(report["clean"])
        self.assertEqual(report["collection"]["api"], "failed")
        self.assertEqual(next(row for row in report["canaryInjection"] if row["kind"] == "json-body-password")["delivery"], "not-observed")

    def test_public_projection_ignores_free_form_paths_and_preserves_prior_red(self):
        evidence, phases, receipt = self.complete_sinks()
        private_text = "private-credential-and-path"
        receipt["problemClasses"] = {private_text: 1, "individual-isolation-unobserved": 1}
        receipt["notes"][private_text] = private_text
        self.file("campaign/java/fineract/instrumented-1/capture/receipt.json", json.dumps(receipt))
        previous = privacy.read(self.root / "privacy/phase-baseline.json")
        previous["sinks"]["console-output"]["status"] = "failed"
        (self.root / "privacy/phase-baseline.json").unlink()
        privacy.write(self.root / "privacy/phase-baseline.json", previous)
        self.assertFalse(privacy.finalize(self.root, self.parent / "public"))
        raw = (self.parent / "public/summary.json").read_text()
        self.assertNotIn(private_text, raw)
        self.assertNotIn(str(self.root), raw)
        summary = json.loads(raw)
        self.assertEqual(summary["seamGapCounts"]["isolation"], 1)
        self.assertEqual(summary["privacy"]["status"], "failed")

    def test_final_public_bytes_are_scanned_and_withheld_on_hit(self):
        self.complete_sinks()
        original = canary.scan_bytes
        def final_hit(data, index, hits, loc_class, depth=0):
            if loc_class == "final-public-output":
                hits[(loc_class, "query-token", "raw")] = 1
            else:
                original(data, index, hits, loc_class, depth)
        with mock.patch.object(canary, "scan_bytes", side_effect=final_hit):
            self.assertFalse(privacy.finalize(self.root, self.parent / "public"))
        self.assertEqual((self.parent / "public/summary.json").read_bytes(), b"{}\n")


if __name__ == "__main__":
    unittest.main()
