"""Narrow pre-receipt retention: actual stderr, fail-closed bounds, no plaintext upload."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

import private_diagnostic
import xinstr
from test_jhipster_installed import installed

HARNESS = Path(__file__).resolve().parents[1] / "java/jhipster/harness"
SPEC = importlib.util.spec_from_file_location("jhipster_encrypt_diagnostic", HARNESS / "encrypt_diagnostic.py")
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)
CERT = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"


class JHipsterDiagnostic(unittest.TestCase):
    def failed(self, root, *, phase="instrumented", code=1):
        (root.parent / "driver").mkdir(mode=0o700, exist_ok=True)
        private_diagnostic.mark_root_admitted(root)
        (root / "console").mkdir()
        rows = [{"name": name, "status": "passed" if name != phase else "failed",
                 "exitCode": 0 if name != phase else code} for name in diagnostic.PHASES]
        diagnostic.private_write(root / "phases.json", json.dumps({
            "schema": "xtrace-jhipster-phases/1", "phases": rows}).encode())
        diagnostic.private_write(root / f"console/{phase}.stderr", b"phase failure\n")

    def test_no_failure_or_existing_receipt_never_encrypts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            with mock.patch.object(diagnostic.subprocess, "run") as command:
                self.assertEqual(diagnostic.retain(root, root / "out", CERT)["status"], "not-required")
                self.failed(root)
                receipt = root / "campaign/java/jhipster/instrumented-1/receipt.json"
                receipt.parent.mkdir(parents=True)
                diagnostic.private_write(receipt, json.dumps({"project": "jhipster", "instrumented": True,
                                                            "releaseAcceptance": False}).encode())
                self.assertEqual(diagnostic.retain(root, root / "out", CERT)["status"], "not-required")
                command.assert_not_called()

    def test_missing_or_private_key_recipient_has_explicit_gap_and_no_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            self.failed(root)
            for cert in ("", "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"):
                with mock.patch.object(diagnostic.subprocess, "run") as command:
                    status = diagnostic.retain(root, root / "out", cert)
                    self.assertEqual(status["status"], "gap-recipient-unavailable")
                    self.assertEqual(status["retainedStderrStreams"], 0)
                    command.assert_not_called()
                    self.assertFalse((root / "out").exists())

    def test_exact_top_and_child_stderr_are_only_bundle_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            self.failed(root)
            child_dir = root / "child-stderr"
            child_dir.mkdir(mode=0o700)
            env = {"XCAMP_PRIVATE_CHILD_STDERR_DIR": str(child_dir), "XCAMP_DIAGNOSTIC_PHASE": "instrumented"}
            private_diagnostic.capture_failed_stderr(env, "init", b"actual init stderr\x00\xff", 23)
            diagnostic.private_write(root / "console/instrumented.stdout", b"forbidden stdout")
            payload, count = diagnostic.stderr_bundle(root, "instrumented", 1)
            self.assertEqual(count, 2)
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                self.assertEqual(set(archive.namelist()), {"manifest.json", "phase.stderr", "child-init.stderr"})
                self.assertEqual(archive.read("phase.stderr"), b"phase failure\n")
                self.assertEqual(archive.read("child-init.stderr"), b"actual init stderr\x00\xff")
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual([row["exitCode"] for row in manifest["streams"]], [1, 23])
            self.assertNotIn(b"forbidden stdout", payload)

    def test_package_build_failure_is_retained_without_phase_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            build = root.parent / "package-build"
            build.mkdir(mode=0o700)
            diagnostic.private_write(build / "status.json", json.dumps({
                "schema": "xtrace-jhipster-build/1", "exitCode": 101}).encode())
            diagnostic.private_write(build / "stderr", b"build failure")
            self.assertEqual(diagnostic.failed_phase(root), ("package-build", 101))

    def test_refused_root_keeps_outer_driver_failure_in_private_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, driver = parent / "run", parent / "driver"
            root.mkdir(mode=0o700)
            driver.mkdir(mode=0o700)
            unrelated = root / "unrelated-input"
            diagnostic.private_write(unrelated, b"must remain untouched")
            stderr = driver / "stderr"
            diagnostic.private_write(stderr, b"")
            with stderr.open("w") as stream, mock.patch.dict(os.environ, {"XTRACE_PRIVATE_DRIVER_DIAGNOSTIC": "1"}), \
                    mock.patch.object(installed, "private_parent"), mock.patch.object(installed.os, "umask"), \
                    mock.patch.object(installed.sys, "stderr", stream):
                code = installed.main(["--private-root", str(root), "--archive", str(parent / "unused"),
                                       "--package-sha256", "a" * 64, "--source-sha", "b" * 40,
                                       "--java", "/jdk/bin/java"])
            self.assertEqual(code, 2)
            self.assertIn(b"already contains run state", stderr.read_bytes())
            self.assertFalse((driver / "admission.json").exists())
            diagnostic.private_write(driver / "status.json", json.dumps({
                "schema": "xtrace-jhipster-driver/1", "exitCode": code}).encode())
            self.assertEqual(diagnostic.failed_phase(root), ("driver", 2))
            self.assertFalse((root / "phases.json").exists())
            payload, streams = diagnostic.stderr_bundle(root, "driver", 2)
            self.assertEqual(streams, 1)
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                self.assertEqual(archive.read("phase.stderr"), stderr.read_bytes())
            status = diagnostic.retain(root, parent / "encrypted", "")
            self.assertEqual((status["status"], status["phase"], status["exitCode"]),
                             ("gap-recipient-unavailable", "driver", 2))
            self.assertEqual(set(root.iterdir()), {unrelated})

    def test_refused_stale_symlink_and_malformed_roots_are_never_inspected(self):
        for kind in ("stale", "symlink", "file"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root, driver = parent / "run", parent / "driver"
                driver.mkdir(mode=0o700)
                diagnostic.private_write(driver / "status.json", json.dumps({
                    "schema": "xtrace-jhipster-driver/1", "exitCode": 2}).encode())
                if kind == "file":
                    diagnostic.private_write(root, b"malformed root entry")
                else:
                    target = root if kind == "stale" else parent / "unrelated"
                    target.mkdir(mode=0o700)
                    diagnostic.private_write(target / "phases.json", b"malformed stale phase data")
                    receipt = target / "campaign/java/jhipster/instrumented-1/receipt.json"
                    receipt.parent.mkdir(parents=True)
                    diagnostic.private_write(receipt, b"stale receipt must not suppress this failure")
                    if kind == "symlink":
                        root.symlink_to(target, target_is_directory=True)
                original = diagnostic.private_json
                def read(path):
                    if path == root or root in path.parents:
                        raise AssertionError("refused root content inspected")
                    return original(path)
                with mock.patch.object(diagnostic, "private_json", side_effect=read):
                    self.assertEqual(diagnostic.failed_phase(root), ("driver", 2))

    def test_admitted_driver_failure_survives_earlier_passed_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, driver = parent / "run", parent / "driver"
            root.mkdir(mode=0o700)
            driver.mkdir(mode=0o700)
            private_diagnostic.mark_root_admitted(root)
            diagnostic.private_write(driver / "status.json", json.dumps({
                "schema": "xtrace-jhipster-driver/1", "exitCode": 2}).encode())
            rows = [{"name": name, "status": "unreached", "exitCode": None} for name in diagnostic.PHASES]
            diagnostic.private_write(root / "phases.json", json.dumps({
                "schema": "xtrace-jhipster-phases/1", "phases": rows}).encode())
            self.assertEqual(diagnostic.failed_driver(root), ("driver", 2))
            rows[0].update(status="passed", exitCode=0)
            (root / "phases.json").write_text(json.dumps({"schema": "xtrace-jhipster-phases/1", "phases": rows}))
            self.assertEqual(diagnostic.failed_driver(root), ("driver", 2))
            self.assertEqual(diagnostic.failed_phase(root), ("driver", 2))
            baseline = root / "campaign/java/jhipster/baseline-1/receipt.json"
            baseline.parent.mkdir(parents=True)
            diagnostic.private_write(baseline, json.dumps({"project": "jhipster", "instrumented": False,
                                                         "releaseAcceptance": False}).encode())
            next(row for row in rows if row["name"] == "baseline").update(status="passed", exitCode=0)
            (root / "phases.json").write_text(json.dumps({"schema": "xtrace-jhipster-phases/1", "phases": rows}))
            self.assertEqual(diagnostic.failed_driver(root), ("driver", 2))
            receipt = root / "campaign/java/jhipster/instrumented-1/receipt.json"
            receipt.parent.mkdir(parents=True)
            diagnostic.private_write(receipt, json.dumps({"project": "jhipster", "instrumented": True,
                                                        "releaseAcceptance": False}).encode())
            self.assertIsNone(diagnostic.failed_driver(root))

    def test_initial_manifest_failure_leaves_no_partial_observed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            runner = installed.InstalledCampaign(root, root / "unused", "a" * 64, "b" * 40, Path("/jdk/bin/java"))
            with mock.patch.object(Path, "replace", side_effect=OSError("manifest commit failed")):
                with self.assertRaisesRegex(OSError, "manifest commit failed"):
                    runner.save()
            self.assertFalse((root / "phases.json").exists())
            self.assertTrue((root / "phases.pending.json").exists())

    def test_unavailable_oversized_and_linked_stderr_never_encrypted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            self.failed(root)
            path = root / "console/instrumented.stderr"
            path.unlink()
            with mock.patch.object(diagnostic.subprocess, "run") as command:
                self.assertEqual(diagnostic.retain(root, root / "out", CERT)["status"], "gap-stderr-unavailable")
                diagnostic.private_write(path, b"x" * (diagnostic.MAX_STDERR + 1))
                self.assertEqual(diagnostic.retain(root, root / "out", CERT)["status"], "gap-stderr-oversized")
                path.unlink()
                path.symlink_to(root / "phases.json")
                self.assertEqual(diagnostic.retain(root, root / "out", CERT)["status"], "gap-stderr-unavailable")
                command.assert_not_called()

    def test_only_completed_ciphertext_is_eligible_for_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            self.failed(root)
            def encrypt(args, **kwargs):
                self.assertEqual(args[:8], ["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-outform", "DER", "-in"])
                self.assertEqual(kwargs["timeout"], 30)
                self.assertIs(kwargs["stderr"], subprocess.PIPE)
                output = Path(args[args.index("-out") + 1])
                output.write_bytes(b"completed ciphertext")
                return subprocess.CompletedProcess(args, 0, b"", b"")
            with mock.patch.object(diagnostic.subprocess, "run", side_effect=encrypt):
                status = diagnostic.retain(root, root / "encrypted", CERT)
            self.assertEqual(status["status"], "ciphertext-prepared")
            self.assertEqual({p.name for p in (root / "encrypted").iterdir()}, {"failure-stderr.cms"})
            self.assertEqual((root / "encrypted/failure-stderr.cms").read_bytes(), b"completed ciphertext")

    def test_failed_encryptor_leaves_no_final_ciphertext_and_does_not_emit_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            self.failed(root)
            with mock.patch.object(diagnostic.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 5, b"private crypto stdout", b"private crypto stderr")):
                status = diagnostic.retain(root, root / "encrypted", CERT)
            self.assertEqual(status["status"], "gap-encryption-failed")
            self.assertNotIn("private", json.dumps(status))
            self.assertFalse((root / "encrypted/failure-stderr.cms").exists())

    def test_ordered_jhipster_init_captures_actual_child_stderr_before_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            children = root / "child-stderr"
            children.mkdir(mode=0o700)
            env = {"XCAMP_PRIVATE_CHILD_STDERR_DIR": str(children), "XCAMP_DIAGNOSTIC_PHASE": "instrumented"}
            hooks = xinstr.OrderedCampaign(frozenset(), lambda *_: [], lambda *_: ({}, [], set(), set(), []))
            with mock.patch.dict(os.environ, env), mock.patch.object(xinstr.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 29, b"init stdout must not survive", b"exact product init stderr")) as command:
                with self.assertRaisesRegex(RuntimeError, "init failed with exit 29"):
                    xinstr.run_instrumented(project="jhipster", pin={}, make_stack=mock.Mock(),
                        scenarios=[SimpleNamespace(id="original", kind="business")], out_dir=root / "instrumented-1",
                        norm_extra=[], expectations={"original": [{}]}, xtrace="installed-xtrace", project_dir=root,
                        data_home=root / "data", adaptations=[], canaries={"proof": "private"}, baseline_receipt=None,
                        extra_canary_paths=[], harness_files=[], ordered_campaign=hooks)
            self.assertFalse(command.call_args.kwargs["text"])
            self.assertEqual((children / "instrumented-init.stderr").read_bytes(), b"exact product init stderr")
            self.assertEqual(json.loads((children / "instrumented-init.json").read_text())["exitCode"], 29)
            self.assertFalse((root / "instrumented-1/receipt.json").exists())
            self.assertEqual({p.suffix for p in children.iterdir()}, {".stderr", ".json"})

    def test_child_capture_is_opt_in_and_preserves_timeout_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            private_diagnostic.capture_failed_stderr({}, "init", b"private", 9)
            self.assertEqual(list(root.iterdir()), [])
            env = {"XCAMP_PRIVATE_CHILD_STDERR_DIR": str(root), "XCAMP_DIAGNOSTIC_PHASE": "instrumented"}
            with mock.patch.object(private_diagnostic.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                    ["private command"], 120, output=b"private stdout", stderr=b"captured before timeout")):
                with self.assertRaises(subprocess.TimeoutExpired):
                    private_diagnostic.run_captured(["unused"], env=env, timeout=120, label="init")
            doc = json.loads((root / "instrumented-init.json").read_text())
            self.assertTrue(doc["timedOut"])
            self.assertIsNone(doc["exitCode"])
            self.assertEqual((root / "instrumented-init.stderr").read_bytes(), b"captured before timeout")


if __name__ == "__main__":
    unittest.main()
