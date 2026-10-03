from __future__ import annotations

import hashlib
import json
import os
import pathlib
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from unittest import mock

from tools.release import check_ledger, run_gates

REAL_VERSIONS = run_gates._versions


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def process_running(pid: int) -> bool:
    record = run_gates._process_snapshot().get(pid)
    return record is not None and record[2] not in {"Z", "X"}


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name) / "evidence"
        self.root.mkdir()
        self.ledger = pathlib.Path(self.temp.name) / "requirements.json"
        self.candidate = "a" * 40
        self._write("trust/keys.json", {"schemaVersion": 1, "keys": []})
        contracts = check_ledger.load_pinned_contracts()
        release_bytes = self._write("artifacts/release.tar", b"accepted release package")
        release_entries = [{"path": "artifacts/release.tar", "sha256": digest(release_bytes), "platform": "universal"}]
        artifact_digest_rows = [{key: row[key] for key in ("path", "sha256", "platform")} for row in release_entries]
        artifact_digest_rows.sort(key=lambda item: (item.get("platform", ""), item["path"], item["sha256"]))
        self.ledger.write_text(json.dumps({
            "schemaVersion": 1,
            "candidateSha": self.candidate,
            "releaseBuild": {
                "id": "release-1", "sourceSha": self.candidate, "state": "accepted",
                "artifacts": release_entries,
                "artifactSetSha256": digest(check_ledger.canonical_json(artifact_digest_rows)),
            },
            "requirements": [
                {**contracts[requirement_id], "state": "pending", "receipts": []}
                for requirement_id in sorted(contracts)
            ],
        }))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, name: str, value: object) -> bytes:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
        path.write_bytes(data)
        return data

    def _receipt(self, receipt: dict[str, object]) -> dict[str, str]:
        raw = self._write("receipts/one.json", receipt)
        return {"path": "receipts/one.json", "sha256": digest(raw)}

    def _ledger(self) -> dict[str, object]:
        return json.loads(self.ledger.read_text())

    def _java_row(self, ledger: dict[str, object]) -> dict[str, object]:
        return next(row for row in ledger["requirements"] if row["id"] == "JAVA-LAUNCH")

    def test_pending_and_missing_mandatory_receipt_fail_closed(self) -> None:
        with self.assertRaisesRegex(check_ledger.ValidationError, "pending, missing"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_omitted_requirement_row_fails_closed(self) -> None:
        ledger = self._ledger()
        ledger["requirements"] = [row for row in ledger["requirements"] if row["id"] != "HUMAN-OWNER"]
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "requirement set differs"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_mandatory_requirement_downgrade_fails_closed(self) -> None:
        ledger = self._ledger()
        next(row for row in ledger["requirements"] if row["id"] == "HUMAN-OWNER")["mandatory"] = False
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "downgraded"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_requirement_text_or_approved_slice_cannot_be_weakened(self) -> None:
        ledger = self._ledger()
        next(row for row in ledger["requirements"] if row["id"] == "HUMAN-OWNER")["requirement"] = "Do a quick review"
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "requirement text or slice changed"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_pinned_requirement_contract_file_digest_is_enforced(self) -> None:
        altered = pathlib.Path(self.temp.name) / "approved-requirements.json"
        source = json.loads(check_ledger.PINNED_CONTRACTS_PATH.read_text())
        source["requirements"][0]["requirement"] += " (weakened)"
        altered.write_text(json.dumps(source))
        with mock.patch.object(check_ledger, "PINNED_CONTRACTS_PATH", altered):
            with self.assertRaisesRegex(check_ledger.ValidationError, "semantics differ"):
                check_ledger.load_pinned_contracts()

    def test_trust_config_rejects_public_key_aliases(self) -> None:
        version = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=False)
        if version.returncode:
            self.skipTest("OpenSSL is required for trust-key normalization")
        private = pathlib.Path(self.temp.name) / "private.pem"
        public = self.root / "trust/key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        key_bytes = public.read_bytes()
        entry = {"roles": ["reviewer"], "publicKey": "trust/key.pem", "publicKeySha256": digest(key_bytes)}
        self._write("trust/keys.json", {"schemaVersion": 1, "keys": [{"id": "reviewer-a", **entry}, {"id": "reviewer-b", **entry}]})
        with self.assertRaisesRegex(check_ledger.ValidationError, "aliases one public key"):
            check_ledger._trust_config(self.root, "trust/keys.json")

    def test_receipts_must_join_the_single_release_build_and_artifact_set(self) -> None:
        ledger = self._ledger()
        release_build, accepted_hashes = check_ledger.validate_release_build(self.root, self.candidate, ledger["releaseBuild"])
        wrong = self._write("artifacts/unreviewed.tar", b"unreviewed package")
        evidence = self._write("evidence/build.log", b"build evidence")
        receipt = {
            "schemaVersion": 1, "requirementId": "JAVA-LAUNCH", "kind": "phase", "result": "passed",
            "candidateSha": self.candidate,
            "build": {"id": release_build["id"], "sourceSha": self.candidate, "artifactSetSha256": release_build["artifactSetSha256"]},
            "artifacts": [{"path": "artifacts/unreviewed.tar", "sha256": digest(wrong)}],
            "evidence": [{"path": "evidence/build.log", "sha256": digest(evidence)}],
            "checks": [{"status": "passed", "reached": True}], "attestation": {},
        }
        ref = self._receipt(receipt)
        with self.assertRaisesRegex(check_ledger.ValidationError, "outside the accepted release artifact set"):
            check_ledger.validate_receipt(self.root, ref, "JAVA-LAUNCH", self.candidate, {}, release_build, accepted_hashes)
        receipt["artifacts"] = [{"path": "artifacts/release.tar", "sha256": next(iter(accepted_hashes))}]
        receipt["build"]["id"] = "other-build"
        ref = self._receipt(receipt)
        with self.assertRaisesRegex(check_ledger.ValidationError, "different logical release build"):
            check_ledger.validate_receipt(self.root, ref, "JAVA-LAUNCH", self.candidate, {}, release_build, accepted_hashes)

    def test_platform_receipt_uses_matching_declared_package_from_release_set(self) -> None:
        package = self._write("artifacts/linux.tar", b"Linux x86_64 package")
        ref = {"path": "artifacts/linux.tar", "sha256": digest(package)}
        attestation = {
            "artifacts": [ref],
            "platform": {"os": "Linux", "architecture": "x86_64", "freshProfileInstall": True, "packageSha256": digest(package)},
        }
        check_ledger._validate_special(self.root, "PLATFORM-LINUX", attestation, {digest(package): {"linux-x86_64"}})
        with self.assertRaisesRegex(check_ledger.ValidationError, "package artifact"):
            check_ledger._validate_special(self.root, "PLATFORM-LINUX", attestation, {digest(package): {"macos-arm64"}})

    def test_supply_chain_special_receipt_accepts_hashed_inventory_fields(self) -> None:
        fields = ("sbom", "licenses", "notices", "advisories", "checksums", "provenance")
        supply_chain = {}
        for field in fields:
            raw = self._write(f"supply-chain/{field}.json", f"{field} reviewed\n".encode())
            supply_chain[field] = {"path": f"supply-chain/{field}.json", "sha256": digest(raw)}
        check_ledger._validate_special(self.root, "SUPPLY-CHAIN", {"artifacts": [], "supplyChainArtifacts": supply_chain})

    def test_path_traversal_receipt_is_rejected_before_read(self) -> None:
        ledger = self._ledger()
        self._java_row(ledger).update({"state": "accepted", "receipts": [{"path": "../outside.json", "sha256": "0" * 64}]})
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "escapes"):
            check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {})

    def test_stale_candidate_receipt_is_rejected(self) -> None:
        ledger = self._ledger()
        bad = self._receipt({
            "schemaVersion": 1, "requirementId": "JAVA-LAUNCH", "kind": "phase", "result": "passed",
            "candidateSha": "b" * 40, "build": {"id": "build-1", "sourceSha": "b" * 40},
        })
        self._java_row(ledger).update({"state": "accepted", "receipts": [bad]})
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "stale for this candidate"):
            check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {})

    def test_hash_tampered_receipt_fails(self) -> None:
        ledger = self._ledger()
        self._java_row(ledger).update({"state": "accepted", "receipts": [{"path": "receipts/missing.json", "sha256": "0" * 64}]})
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "missing, unreadable"):
            check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {})

    def test_forged_signature_claim_fails_cryptographic_verification(self) -> None:
        public = self._write("trust/pub.pem", b"not a valid public key\n")
        self._write("trust/keys.json", {"schemaVersion": 1, "keys": [{"id": "reviewer", "roles": ["reviewer"], "publicKey": "trust/pub.pem", "publicKeySha256": digest(public)}]})
        attestation = {"scope": "candidate"}
        signature = self._write("signatures/fake.sig", b"forged")
        evidence = self._write("evidence/log.txt", b"real evidence bytes")
        artifact = self._write("artifacts/app.tar", b"candidate artifact")
        receipt = {
            "schemaVersion": 1, "requirementId": "JAVA-LAUNCH", "kind": "phase", "result": "passed",
            "candidateSha": self.candidate, "build": {"id": "build-1", "sourceSha": self.candidate},
            "artifacts": [{"path": "artifacts/app.tar", "sha256": digest(artifact)}],
            "evidence": [{"path": "evidence/log.txt", "sha256": digest(evidence)}],
            "checks": [{"status": "passed", "reached": True}], "attestation": attestation,
            "signatures": [{"keyId": "reviewer", "role": "reviewer", "path": "signatures/fake.sig", "sha256": digest(signature)}],
        }
        ledger = self._ledger()
        self._java_row(ledger).update({"state": "accepted", "receipts": [self._receipt(receipt)]})
        self.ledger.write_text(json.dumps(ledger))
        failed = subprocess.CompletedProcess(["openssl"], 1, b"", b"signature verification failed")
        seen_payloads: list[bytes] = []

        def reject_and_capture(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            seen_payloads.append(pathlib.Path(argv[argv.index("-in") + 1]).read_bytes())
            return failed

        with mock.patch.object(check_ledger.subprocess, "run", side_effect=reject_and_capture) as verifier:
            with self.assertRaisesRegex(check_ledger.ValidationError, "signature verification failed"):
                check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {"reviewer": {"roles": ["reviewer"], "path": "trust/pub.pem", "sha256": digest(public)}})
        self.assertEqual(verifier.call_args.args[0][0], "openssl")
        self.assertIn(b'"candidateSha":"' + self.candidate.encode(), seen_payloads[0])
        self.assertIn(b'"build":{"id":"build-1"', seen_payloads[0])

    def test_symlink_reference_fails_closed(self) -> None:
        outside = pathlib.Path(self.temp.name) / "outside.log"
        outside.write_text("secret")
        link = self.root / "evidence" / "linked.log"
        link.parent.mkdir()
        link.symlink_to(outside)
        with self.assertRaisesRegex(check_ledger.ValidationError, "symlink"):
            check_ledger.read_evidence(self.root, "evidence/linked.log", digest(b"secret"))

    def test_missing_hash_and_duplicate_json_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(check_ledger.ValidationError, "missing its SHA-256"):
            check_ledger.read_evidence(self.root, "missing.log")
        with self.assertRaisesRegex(check_ledger.ValidationError, "duplicate JSON key"):
            check_ledger._load_json(b'{"candidateSha":"a","candidateSha":"b"}', "receipt")

    def test_usability_observation_rejects_blank_identity_boolean_time_and_nonfinite_time(self) -> None:
        journey = self._write("study/journey.log", b"observed journey")
        scoring = self._write("study/scoring.log", b"scoring notes")
        refs = {
            "journey": {"path": "study/journey.log", "sha256": digest(journey)},
            "scoring": {"path": "study/scoring.log", "sha256": digest(scoring)},
        }
        for participant_id, elapsed in (("", 10), ([], 10), ("p1", True), ("p1", float("inf"))):
            with self.subTest(participant_id=participant_id, elapsed=elapsed):
                with self.assertRaises(check_ledger.ValidationError):
                    check_ledger._validate_special(self.root, "HUMAN-USABILITY", {
                        "participants": [
                            {"participantId": participant_id, "elapsedSeconds": elapsed, "correct": True, **refs},
                            {"participantId": "p2", "elapsedSeconds": 10, "correct": True, **refs},
                        ],
                    })

    def test_openssl_signature_verifies_and_payload_tamper_fails(self) -> None:
        version = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=False)
        if version.returncode or "OpenSSL 3" not in version.stdout:
            self.skipTest("OpenSSL 3 is needed for the detached-signature integration check")
        private = self.root / "trust/private.pem"
        public = self.root / "trust/public.pem"
        signature = self.root / "signatures/attestation.sig"
        payload_file = self.root / "signatures/payload.json"
        for path in (private, public, signature, payload_file):
            path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        payload = check_ledger.canonical_json({"candidateSha": self.candidate, "build": {"id": "build-1"}})
        payload_file.write_bytes(payload)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(payload_file), "-out", str(signature)], check=True, capture_output=True)
        public_bytes, signature_bytes = public.read_bytes(), signature.read_bytes()
        self._write("trust/public.pem", public_bytes)
        self._write("signatures/attestation.sig", signature_bytes)
        trust = {"reviewer": {"roles": ["reviewer"], "path": "trust/public.pem", "sha256": digest(public_bytes)}}
        self.assertEqual(
            check_ledger._verify_signature(self.root, trust, {"keyId": "reviewer", "role": "reviewer", "path": "signatures/attestation.sig", "sha256": digest(signature_bytes)}, payload),
            ("reviewer", "reviewer"),
        )
        with self.assertRaisesRegex(check_ledger.ValidationError, "signature verification failed"):
            check_ledger._verify_signature(self.root, trust, {"keyId": "reviewer", "role": "reviewer", "path": "signatures/attestation.sig", "sha256": digest(signature_bytes)}, payload + b"tampered")


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        for name in ("Cargo.lock", "adapters/java/gradle.lockfile", "adapters/node/package-lock.json", "web/app/package-lock.json"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test lockfile\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], check=True)
        self.base = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.cache = self.root / "cache"
        self.versions_patcher = mock.patch.object(run_gates, "_versions", return_value={})
        self.versions_patcher.start()
        self.addCleanup(self.versions_patcher.stop)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def args(self) -> Namespace:
        return Namespace(repo=str(self.repo), base=self.base, label="P00-test", cache_root=str(self.cache), command_timeout=30)

    def test_failed_gate_stops_and_never_claims_all_passed(self) -> None:
        failure = run_gates.Gate("failure", (sys.executable, "-c", "print('gate failed'); raise SystemExit(9)"))
        later = run_gates.Gate("unreached", (sys.executable, "-c", "raise SystemExit(0)"))
        with mock.patch.object(run_gates, "GATES", (failure, later)):
            self.assertEqual(run_gates.run(self.args()), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertEqual(receipt["decision"], "failed")
        self.assertEqual(len(receipt["gates"]), 2)
        self.assertEqual([gate["status"] for gate in receipt["gates"]], ["failed", "unreached"])
        self.assertEqual(receipt["gates"][0]["exitCode"], 9)
        self.assertEqual(receipt["gates"][0]["status"], "failed")
        self.assertNotIn("ALL GATES PASSED", (self.cache / "release-gates/P00-test/receipt.json").read_text())

    def test_owned_atomic_lease_fails_before_any_gate(self) -> None:
        lease = self.cache / "leases/cargo"
        lease.mkdir(parents=True)
        (lease / "owner.json").write_text('{"pid":123,"label":"owner","token":"' + "f" * 32 + '"}')
        with mock.patch.object(run_gates, "GATES", ()):
            self.assertEqual(run_gates.run(self.args()), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertIn("already owned", receipt["error"])

    def test_timeout_kills_and_drains_spawned_grandchild_before_releasing_leases(self) -> None:
        script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,os.getpgid(child.pid),flush=True); time.sleep(60)"
        gate = run_gates.Gate("tree-timeout", (sys.executable, "-c", script))
        args = self.args()
        args.command_timeout = 0.4
        spawned: list[subprocess.Popen[bytes]] = []
        popen = subprocess.Popen

        def capture_process(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = popen(*argv, **kwargs)
            if kwargs.get("start_new_session"):
                spawned.append(process)
            return process

        with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates.subprocess, "Popen", side_effect=capture_process):
            self.assertEqual(run_gates.run(args), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["exitCode"], 124)
        self.assertIn("owned process tree drained", (self.cache / "release-gates/P00-test" / entry["log"]).read_text())
        child_pid, child_pgid = map(int, (self.cache / "release-gates/P00-test" / entry["log"]).read_text().splitlines()[0].split())
        self.assertEqual(child_pgid, child_pid)
        self.assertNotEqual(child_pgid, spawned[0].pid)
        self.assertFalse(process_running(child_pid))
        self.assertFalse((self.cache / "leases/cargo").exists())
        self.assertFalse((self.cache / "leases/gradle").exists())

    def test_interrupt_kills_and_drains_spawned_grandchild(self) -> None:
        script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,os.getpgid(child.pid),flush=True); time.sleep(60)"
        gate = run_gates.Gate("tree-interrupt", (sys.executable, "-c", script))
        args = self.args()
        args.command_timeout = 10
        spawned: list[subprocess.Popen[bytes]] = []
        popen = subprocess.Popen

        def launch(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = popen(*argv, **kwargs)
            if kwargs.get("start_new_session"):
                spawned.append(process)
                wait = process.wait
                first_wait = True

                def interrupt_once(timeout: float | None = None) -> int:
                    nonlocal first_wait
                    if first_wait:
                        first_wait = False
                        time.sleep(0.25)
                        raise KeyboardInterrupt
                    return wait(timeout=timeout)

                process.wait = interrupt_once  # type: ignore[method-assign]
            return process

        with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates.subprocess, "Popen", side_effect=launch):
            self.assertEqual(run_gates.run(args), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["exitCode"], 130)
        self.assertIn("Gate interrupted; owned process tree drained", (self.cache / "release-gates/P00-test" / entry["log"]).read_text())
        child_pid, child_pgid = map(int, (self.cache / "release-gates/P00-test" / entry["log"]).read_text().splitlines()[0].split())
        self.assertEqual(child_pgid, child_pid)
        self.assertNotEqual(child_pgid, spawned[0].pid)
        self.assertFalse(process_running(child_pid))

    def test_uncertain_process_tree_retains_both_leases_for_manual_recovery(self) -> None:
        script = "import time; time.sleep(60)"
        gate = run_gates.Gate("uncertain-timeout", (sys.executable, "-c", script))
        args = self.args()
        args.command_timeout = 0.2
        spawned: list[subprocess.Popen[bytes]] = []
        popen = subprocess.Popen

        def capture_process(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = popen(*argv, **kwargs)
            if kwargs.get("start_new_session"):
                spawned.append(process)
            return process

        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates.subprocess, "Popen", side_effect=capture_process), mock.patch.object(run_gates, "_stop_owned_process_tree", return_value=False):
                self.assertEqual(run_gates.run(args), 1)
            receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
            self.assertEqual(receipt["decision"], "failed")
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn("could not be confirmed drained", owner["terminationStatus"])
                self.assertEqual(owner["processGroupId"], spawned[0].pid)
                self.assertTrue(owner["ownedProcesses"])
        finally:
            for process in spawned:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_version_probe_timeout_drains_detached_child_and_fails_probe(self) -> None:
        script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,os.getpgid(child.pid),flush=True); time.sleep(60)"
        logs = self.cache / "version-probe-logs"
        child_pid: int | None = None
        probes: list[dict[str, object]] = []
        try:
            with mock.patch.object(run_gates, "VERSION_COMMANDS", (("probe", (sys.executable, "-c", script), "."),)):
                with self.assertRaisesRegex(RuntimeError, "version probe probe failed with exit 124"):
                    REAL_VERSIONS(self.repo, os.environ.copy(), logs, probes, timeout=0.4)
            version_log = logs / "version-probe.log"
            self.assertEqual(version_log.stat().st_mode & 0o777, 0o600)
            child_pid = int(version_log.read_text().splitlines()[0].split()[0])
            self.assertFalse(process_running(child_pid))
            self.assertEqual(probes[0]["status"], "failed")
            self.assertEqual(probes[0]["exitCode"], 124)
            self.assertEqual(probes[0]["logSha256"], digest(version_log.read_bytes()))
        finally:
            if child_pid is None:
                try:
                    version_log = logs / "version-probe.log"
                    child_pid = int(version_log.read_text().splitlines()[0].split()[0])
                except (OSError, ValueError, IndexError):
                    pass
            if child_pid is not None and process_running(child_pid):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_buf_version_probe_uses_workspace_executable(self) -> None:
        self.assertEqual(
            next(item for item in run_gates.VERSION_COMMANDS if item[0] == "buf"),
            ("buf", ("./node_modules/.bin/buf", "--version"), "adapters/node"),
        )

    def test_log_io_failure_preserves_uncertain_tree_and_both_leases(self) -> None:
        for failure_point in ("fsync", "close"):
            with self.subTest(failure_point=failure_point):
                args = self.args()
                args.label = f"P00-log-{failure_point}"
                script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,flush=True); time.sleep(.35)"
                gate = run_gates.Gate(f"log-{failure_point}", (sys.executable, "-c", script))
                args.command_timeout = 5
                stop = mock.patch.object(run_gates, "_stop_and_reap_owned_tree", return_value=False)
                if failure_point == "fsync":
                    inject = mock.patch.object(run_gates, "_sync_log", side_effect=OSError("injected log fsync failure"))
                else:
                    real_close = run_gates._close_log

                    def close_then_fail(log: object) -> None:
                        real_close(log)
                        raise OSError("injected log close failure")

                    inject = mock.patch.object(run_gates, "_close_log", side_effect=close_then_fail)
                child_pid: int | None = None
                try:
                    with mock.patch.object(run_gates, "GATES", (gate,)), stop, inject:
                        self.assertEqual(run_gates.run(args), 1)
                    run_dir = self.cache / "release-gates" / args.label
                    receipt = json.loads((run_dir / "receipt.json").read_text())
                    self.assertIn("could not be confirmed drained", receipt["error"])
                    temporary_logs = list((run_dir / "logs").glob(".*.tmp"))
                    self.assertEqual(len(temporary_logs), 1)
                    child_pid = int(temporary_logs[0].read_text().splitlines()[0])
                    for name in ("cargo", "gradle"):
                        owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                        self.assertTrue(owner["requiresManualRecovery"])
                        self.assertTrue(owner["ownedProcesses"])
                finally:
                    if child_pid is None:
                        try:
                            run_dir = self.cache / "release-gates" / args.label
                            temporary_logs = list((run_dir / "logs").glob(".*.tmp"))
                            if temporary_logs:
                                child_pid = int(temporary_logs[0].read_text().splitlines()[0])
                        except (OSError, ValueError, IndexError):
                            pass
                    if child_pid is not None and process_running(child_pid):
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    for name in ("cargo", "gradle"):
                        lease_path = self.cache / "leases" / name
                        if lease_path.exists():
                            shutil.rmtree(lease_path)

    def test_source_change_during_gate_fails_exact_tree_receipt(self) -> None:
        gate = run_gates.Gate("mutating-gate", (sys.executable, "-c", "open('source-drift.txt','w').write('changed')"))
        later = run_gates.Gate("must-not-run", (sys.executable, "-c", "raise SystemExit(0)"))
        with mock.patch.object(run_gates, "GATES", (gate, later)):
            self.assertEqual(run_gates.run(self.args()), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertEqual(receipt["decision"], "failed")
        self.assertEqual([item["status"] for item in receipt["gates"]], ["failed", "unreached"])
        self.assertIn("source identity changed during gate", receipt["gates"][0]["integrityFailure"])

    def test_non_ancestor_base_fails_before_gate(self) -> None:
        subprocess.run(["git", "-C", str(self.repo), "checkout", "--orphan", "other"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "other"], check=True)
        with mock.patch.object(run_gates, "GATES", ()):
            with self.assertRaisesRegex(ValueError, "ancestor"):
                run_gates.run(self.args())


if __name__ == "__main__":
    unittest.main()
