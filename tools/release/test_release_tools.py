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
            with mock.patch.object(
                run_gates, "_untracked_processes_since",
                return_value=run_gates.UntrackedProcessScan([], [], None, 0),
            ):
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
            command = argv[0] if argv else kwargs.get("args")
            if (kwargs.get("start_new_session") and isinstance(command, (list, tuple))
                    and command and command[0] == sys.executable):
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
                with self.assertRaises((RuntimeError, run_gates.UncertainProcessTree)) as context:
                    REAL_VERSIONS(self.repo, os.environ.copy(), logs, probes, timeout=0.4)
            if isinstance(context.exception, run_gates.UncertainProcessTree):
                self.assertRegex(str(context.exception), "timed-out process tree|post-command ownership scan")
            else:
                self.assertRegex(str(context.exception), "version probe probe failed with exit 124")
            version_log = logs / "version-probe.log"
            self.assertEqual(version_log.stat().st_mode & 0o777, 0o600)
            child_pid = int(version_log.read_text().splitlines()[0].split()[0])
            if process_running(child_pid):
                self.assertIsInstance(context.exception, run_gates.UncertainProcessTree)
            if probes:
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

    def test_repeated_real_fast_version_probes_do_not_misclassify_exited_roots(self) -> None:
        commands = []
        for tool in ("git", "node", "rustc"):
            binary = shutil.which(tool)
            if binary:
                commands.extend((f"{tool}-{index}", (binary, "--version"), ".") for index in range(5))
        self.assertTrue(commands, "at least git should be available for fast version probes")
        logs = self.cache / "fast-version-logs"
        probes: list[dict[str, object]] = []
        with mock.patch.object(run_gates, "VERSION_COMMANDS", tuple(commands)):
            versions = REAL_VERSIONS(self.repo, os.environ.copy(), logs, probes)
        self.assertEqual(len(probes), len(commands))
        self.assertTrue(all(probe["status"] == "passed" and probe["exitCode"] == 0 for probe in probes))
        self.assertEqual(set(versions), {command[0] for command in commands})
        self.assertTrue(all((logs / f"version-{command[0]}.log").is_file() for command in commands))

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

    def test_fast_parent_cannot_leave_an_unobserved_detached_child(self) -> None:
        for index in range(5):
            with self.subTest(index=index):
                args = self.args()
                args.label = f"P00-fast-child-{index}"
                script = "import subprocess,sys; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,flush=True)"
                gate = run_gates.Gate("fast-detached-child", (sys.executable, "-c", script))
                with mock.patch.object(run_gates, "GATES", (gate,)):
                    self.assertEqual(run_gates.run(args), 1)
                run_dir = self.cache / "release-gates" / args.label
                receipt = json.loads((run_dir / "receipt.json").read_text())
                candidates = list((run_dir / "logs").glob(".*.tmp"))
                if not candidates:
                    candidates = list((run_dir / "logs").glob("fast-detached-child.log"))
                self.assertEqual(len(candidates), 1)
                child_pid = int(candidates[0].read_text().splitlines()[0])
                try:
                    if process_running(child_pid):
                        self.assertIn("unconfirmedProcesses", json.loads(
                            (self.cache / "leases/cargo/owner.json").read_text(),
                        ))
                        self.assertIn(str(child_pid), json.dumps(receipt.get("error", "")) + json.dumps(
                            json.loads((self.cache / "leases/cargo/owner.json").read_text()).get("unconfirmedProcesses", []),
                        ))
                    else:
                        self.assertEqual(receipt.get("decision"), "failed")
                    self.assertNotEqual(receipt.get("decision"), "checks_passed_for_review")
                finally:
                    if process_running(child_pid):
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    for name in ("cargo", "gradle"):
                        lease_path = self.cache / "leases" / name
                        if lease_path.exists():
                            shutil.rmtree(lease_path)

    def test_unrelated_concurrent_process_does_not_look_like_an_owned_descendant(self) -> None:
        log_path = self.cache / "unrelated-process.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        unrelated: subprocess.Popen[bytes] | None = None
        real_snapshot = run_gates._process_snapshot
        calls = 0

        def snapshot_with_concurrent_process() -> dict[int, tuple[int, str, str]]:
            nonlocal calls, unrelated
            snapshot = real_snapshot()
            calls += 1
            if calls == 1:
                unrelated = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
            return snapshot

        try:
            with mock.patch.object(run_gates, "_process_snapshot", side_effect=snapshot_with_concurrent_process):
                code, _ = run_gates._run(
                    (sys.executable, "-c", "print('fast gate passed')"), cwd=self.repo,
                    env=os.environ.copy(), timeout=5, log_path=log_path,
                )
            self.assertEqual(code, 0)
            self.assertTrue(log_path.exists())
            self.assertIsNotNone(unrelated)
            self.assertIsNone(unrelated.poll())
        finally:
            if unrelated is not None:
                try:
                    os.killpg(unrelated.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    unrelated.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_delayed_parent_escape_after_quarter_second_retains_both_leases(self) -> None:
        args = self.args()
        args.label = "P00-delayed-child"
        args.command_timeout = 5
        script = "import subprocess,sys,time; time.sleep(.35); child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,flush=True)"
        gate = run_gates.Gate("delayed-detached-child", (sys.executable, "-c", script))
        child_pid: int | None = None
        try:
            with mock.patch.object(run_gates, "GATES", (gate,)):
                self.assertEqual(run_gates.run(args), 1)
            run_dir = self.cache / "release-gates" / args.label
            receipt = json.loads((run_dir / "receipt.json").read_text())
            log_files = list((run_dir / "logs").glob(".*.tmp"))
            if not log_files:
                log_files = list((run_dir / "logs").glob("delayed-detached-child.log"))
            self.assertEqual(len(log_files), 1)
            child_pid = int(log_files[0].read_text().splitlines()[0])
            self.assertRegex(receipt["error"], "not observed as owned descendants|ownership scan incomplete")
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn(
                    child_pid,
                    [item["pid"] for item in owner["unconfirmedProcesses"]],
                )
        finally:
            if child_pid is None:
                try:
                    run_dir = self.cache / "release-gates" / args.label
                    log_files = list((run_dir / "logs").glob(".*.tmp"))
                    if not log_files:
                        log_files = list((run_dir / "logs").glob("delayed-detached-child.log"))
                    if log_files:
                        child_pid = int(log_files[0].read_text().splitlines()[0])
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

    def test_interrupt_during_final_ownership_scan_retains_both_leases_and_candidate_pid(self) -> None:
        args = self.args()
        args.label = "P00-final-scan-interrupt"
        args.command_timeout = 5
        script = (
            "import subprocess,sys,time; time.sleep(.35); "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); "
            "print(child.pid,flush=True)"
        )
        gate = run_gates.Gate("final-scan-interrupt", (sys.executable, "-c", script))
        real_scan = run_gates._untracked_processes_since

        def interrupt_final_scan(baseline: object, owned: object, snapshot: object, log_path: pathlib.Path):
            if "final-scan-interrupt" in log_path.name:
                raise KeyboardInterrupt
            return real_scan(baseline, owned, snapshot, log_path)  # type: ignore[arg-type]

        child_pid: int | None = None
        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(
                run_gates, "_untracked_processes_since", side_effect=interrupt_final_scan,
            ):
                self.assertEqual(run_gates.run(args), 1)
            run_dir = self.cache / "release-gates" / args.label
            receipt = json.loads((run_dir / "receipt.json").read_text())
            log_files = list((run_dir / "logs").glob(".*.tmp"))
            self.assertEqual(len(log_files), 1)
            child_pid = int(log_files[0].read_text().splitlines()[0])
            self.assertEqual(receipt["decision"], "failed")
            self.assertIn("post-command ownership scan could not be completed: KeyboardInterrupt", receipt["error"])
            self.assertTrue(process_running(child_pid), "unconfirmed candidate must not be signaled")
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn(
                    child_pid,
                    [item["pid"] for item in owner["unconfirmedProcesses"]],
                )
                self.assertNotEqual(owner["processGroupId"], child_pid)
        finally:
            if child_pid is None:
                try:
                    run_dir = self.cache / "release-gates" / args.label
                    log_files = list((run_dir / "logs").glob(".*.tmp"))
                    if log_files:
                        child_pid = int(log_files[0].read_text().splitlines()[0])
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

    def test_untracked_scan_budget_exhaustion_retains_leases_without_killing_candidate(self) -> None:
        args = self.args()
        args.label = "P00-scan-budget"
        args.command_timeout = 5
        real_snapshot = run_gates._process_snapshot
        unrelated: subprocess.Popen[bytes] | None = None
        calls = 0

        def snapshot_with_concurrent_process() -> dict[int, tuple[int, str, str]]:
            nonlocal calls, unrelated
            snapshot = real_snapshot()
            calls += 1
            if calls == 1:
                unrelated = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
            return snapshot

        try:
            with mock.patch.object(run_gates, "GATES", (run_gates.Gate("quick", (sys.executable, "-c", "pass")),)), \
                    mock.patch.object(run_gates, "_process_snapshot", side_effect=snapshot_with_concurrent_process), \
                    mock.patch.object(run_gates, "MAX_UNTRACKED_PROCESSES", 0):
                self.assertEqual(run_gates.run(args), 1)
            receipt = json.loads((self.cache / "release-gates" / args.label / "receipt.json").read_text())
            self.assertIn("inspection limit exceeded", receipt["error"])
            self.assertIsNotNone(unrelated)
            self.assertIsNone(unrelated.poll())
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn("inspection limit exceeded", owner["terminationStatus"])
        finally:
            if unrelated is not None:
                try:
                    os.killpg(unrelated.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    unrelated.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            for name in ("cargo", "gradle"):
                lease_path = self.cache / "leases" / name
                if lease_path.exists():
                    shutil.rmtree(lease_path)

    @unittest.skipUnless(run_gates.LSOF_BINARY is not None, "lsof is required for bounded descriptor-probe tests")
    def test_lsof_all_fd_fallback_resolves_closed_stdio_and_detects_inherited_log_fd(self) -> None:
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        baseline: dict[int, tuple[int, str, str]] = {}
        closed_stdio = subprocess.Popen(
            [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        log_stream = log_path.open("ab", buffering=0)
        log_fd_child = subprocess.Popen(
            [sys.executable, "-c", "import os,time; os.dup2(1,3); os.close(1); os.close(2); time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=log_stream, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            time.sleep(0.1)
            real_snapshot = run_gates._process_snapshot()
            snapshot = {
                pid: real_snapshot[pid]
                for pid in (closed_stdio.pid, log_fd_child.pid)
                if pid in real_snapshot
            }
            self.assertEqual(set(snapshot), {closed_stdio.pid, log_fd_child.pid})
            with mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot):
                result = run_gates._untracked_processes_since(baseline, {}, snapshot, log_path)
            self.assertIsNone(result.error)
            self.assertFalse(result.uninspectable)
            self.assertEqual([item["pid"] for item in result.held], [log_fd_child.pid])
            self.assertEqual(result.held[0]["descriptorStatus"], "held")
            # A process with closed stdio is identified by the all-FD fallback
            # and is conclusively distinct from the log-holding candidate.
            self.assertNotIn(closed_stdio.pid, [item["pid"] for item in result.held])
        finally:
            log_stream.close()
            for child in (closed_stdio, log_fd_child):
                if process_running(child.pid):
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_missing_lsof_pid_record_falls_back_and_preserves_uncertain_metadata(self) -> None:
        pid = 424242
        snapshot = {pid: (7, "candidate-start", "S")}
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        calls: list[list[str]] = []

        def lsof(arguments: list[str], _deadline: float) -> run_gates.LsofProbe:
            calls.append(arguments)
            if "-d" in arguments:
                return run_gates.LsofProbe(0, "", "")
            return run_gates.LsofProbe(0, "", "")

        with mock.patch.object(pathlib.Path, "is_dir", return_value=False), \
                mock.patch.object(run_gates, "_run_lsof_fields", side_effect=lsof), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot):
            result = run_gates._untracked_processes_since({}, {}, snapshot, log_path)
        self.assertEqual(len(calls), 2, "missing stdio record must receive an all-FD fallback")
        self.assertNotIn("-d", calls[1])
        self.assertEqual(result.error, "untracked-process descriptor scan could not inspect every live candidate")
        self.assertEqual(result.held, [])
        self.assertEqual(result.uninspectable[0]["pid"], pid)
        self.assertEqual(result.uninspectable[0]["startedAt"], "candidate-start")
        self.assertEqual(result.uninspectable[0]["observedParentPid"], 7)
        self.assertEqual(result.uninspectable[0]["descriptorStatus"], "uninspectable")

    def test_unconfirmed_descriptor_candidates_keep_total_count_and_bounded_sample(self) -> None:
        snapshot = {pid: (1, f"start-{pid}", "S") for pid in range(1000, 1070)}
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        with mock.patch.object(pathlib.Path, "is_dir", return_value=False), \
                mock.patch.object(run_gates, "_run_lsof_fields", return_value=run_gates.LsofProbe(0, "", "")), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot), \
                mock.patch.object(run_gates, "MAX_UNCONFIRMED_SAMPLE", 8):
            result = run_gates._untracked_processes_since({}, {}, snapshot, log_path)
        self.assertEqual(result.candidate_count, 70)
        self.assertEqual(len(result.unconfirmed), 8)
        self.assertEqual([item["pid"] for item in result.unconfirmed], list(range(1000, 1008)))
        self.assertTrue(result.error)

    def test_lsof_probe_enforces_timeout_and_output_byte_budget(self) -> None:
        with mock.patch.object(run_gates, "LSOF_BINARY", sys.executable):
            started = time.monotonic()
            timed_out = run_gates._run_lsof_fields(
                ["-c", "import time; time.sleep(30)"], time.monotonic() + 0.15,
            )
            self.assertEqual(timed_out.error, "time-budget-exceeded")
            self.assertLess(time.monotonic() - started, 2)
            oversized = run_gates._run_lsof_fields(
                ["-c", "import sys,time; sys.stdout.write('x' * 2000000); sys.stdout.flush(); time.sleep(30)"],
                time.monotonic() + 2,
            )
            self.assertEqual(oversized.error, "output-limit-exceeded")
            self.assertLessEqual(len(oversized.stdout.encode()) + len(oversized.stderr.encode()), run_gates.MAX_LSOF_OUTPUT_BYTES + 65536)

    def test_interrupted_descriptor_scan_retains_unconfirmed_candidate_in_both_leases(self) -> None:
        args = self.args()
        args.label = "P00-uninspectable-candidate"
        args.command_timeout = 5
        script = (
            "import subprocess,sys,time; time.sleep(.35); "
            "child=subprocess.Popen([sys.executable,'-c','import os,time; os.close(1); os.close(2); time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); "
            "print(child.pid,flush=True)"
        )
        gate = run_gates.Gate("uninspectable-candidate", (sys.executable, "-c", script))
        child_pid: int | None = None
        with mock.patch.object(run_gates, "_process_holds_log", return_value=None), \
                mock.patch.object(run_gates, "_run_lsof_fields", return_value=run_gates.LsofProbe(0, "", "")), \
                mock.patch.object(run_gates, "GATES", (gate,)):
            try:
                self.assertEqual(run_gates.run(args), 1)
                run_dir = self.cache / "release-gates" / args.label
                logs = list((run_dir / "logs").glob(".*.tmp"))
                self.assertEqual(len(logs), 1)
                child_pid = int(logs[0].read_text().splitlines()[0])
                receipt = json.loads((run_dir / "receipt.json").read_text())
                self.assertIn("could not inspect every live candidate", receipt["error"])
                self.assertTrue(process_running(child_pid), "unconfirmed candidate must not be signaled")
                for name in ("cargo", "gradle"):
                    owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                    self.assertTrue(owner["requiresManualRecovery"])
                    self.assertGreaterEqual(owner["unconfirmedProcessCount"], 1)
                    self.assertEqual(
                        owner["unconfirmedProcessesTruncated"],
                        owner["unconfirmedProcessCount"] > len(owner["unconfirmedProcesses"]),
                    )
                    self.assertTrue(any(
                        item["pid"] == child_pid and item["descriptorStatus"] == "uninspectable"
                        for item in owner["unconfirmedProcesses"]
                    ))
            finally:
                if child_pid is None:
                    try:
                        run_dir = self.cache / "release-gates" / args.label
                        logs = list((run_dir / "logs").glob(".*.tmp"))
                        if logs:
                            child_pid = int(logs[0].read_text().splitlines()[0])
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
