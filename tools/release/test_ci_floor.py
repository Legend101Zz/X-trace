from __future__ import annotations

import copy
import json
import os
import signal
import time
import pathlib
import sys
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

from tools.release import ci_floor, private_roots, run_gates


class CiFloorEvidenceTests(unittest.TestCase):
    source_sha = "a" * 40
    phase_base = "b" * 40
    digest = "c" * 64

    def test_version_probe_uses_first_nonempty_line_after_bounded_whitespace(self) -> None:
        raw = b'\n  \r\nopenjdk version "17.0.1"\nignored later output\n'
        self.assertEqual(run_gates._first_nonempty_version_line(raw), 'openjdk version "17.0.1"')

    def test_source_proofs_hash_exact_clean_git_bytes_and_lockfiles(self) -> None:
        phase_diff = b"reviewed-phase-diff\x00"
        outputs = {
            ("rev-parse", "--verify", "HEAD"): (self.source_sha + "\n").encode(),
            ("rev-parse", "--verify", f"{self.phase_base}^{{commit}}"): (self.phase_base + "\n").encode(),
            ("merge-base", "--is-ancestor", self.phase_base, "HEAD"): b"",
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"): b"",
            ("diff", "--binary", "HEAD"): b"",
            ("diff", "--cached", "--binary", "HEAD"): b"",
            ("diff", "--binary", f"{self.phase_base}...HEAD"): phase_diff,
        }
        with mock.patch.object(ci_floor, "_bounded_git_output",
                               side_effect=lambda _repo, *argv: outputs[tuple(argv)]), \
                mock.patch.object(ci_floor, "_bounded_source_file_sha256", return_value=self.digest) as lock_hash:
            proof = ci_floor._source_proofs(pathlib.Path("/synthetic/repo"), self.source_sha, self.phase_base)
        self.assertEqual(proof["head"], self.source_sha)
        self.assertEqual(proof["phaseBase"], self.phase_base)
        self.assertEqual(proof["workingTreeDigest"], ci_floor.hashlib.sha256(b"\0\0").hexdigest())
        self.assertEqual(proof["phaseDiffSha256"], ci_floor.hashlib.sha256(phase_diff).hexdigest())
        self.assertEqual(len(proof["dependencyLockSha256"]), 4)
        self.assertEqual(lock_hash.call_count, 4)

    def _source_proofs(self) -> dict[str, object]:
        return {
            "head": self.source_sha,
            "phaseBase": self.phase_base,
            "workingTreeDigest": self.digest,
            "phaseDiffSha256": self.digest,
            "dependencyLockSha256": {
                name: self.digest for name in (
                    "Cargo.lock", "adapters/java/gradle.lockfile",
                    "adapters/node/package-lock.json", "web/app/package-lock.json",
                )
            },
        }

    def test_supported_matrix_is_only_the_two_reviewed_pairs(self) -> None:
        for java, node, label in ((17, 22, "jdk17-node22"), (21, 24, "jdk21-node24")):
            with self.subTest(tuple=label), \
                    mock.patch.object(ci_floor.platform, "system", return_value="Linux"), \
                    mock.patch.object(ci_floor.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(ci_floor, "_identity", return_value=(self.source_sha, self.phase_base)), \
                    mock.patch.object(ci_floor, "_verify_tools") as verify:
                self.assertEqual(ci_floor._preflight(Namespace(
                    repo="/public/repo", phase_metadata="workflow.json", expected_head=self.source_sha,
                    java_major=java, node_major=node, tuple=label,
                )), 0)
                verify.assert_called_once_with(pathlib.Path("/public/repo"), expected_java=java, expected_node=node)
        with mock.patch.object(ci_floor, "_identity") as identity:
            with self.assertRaises(ci_floor.FloorInputError):
                ci_floor._preflight(Namespace(
                    repo="/public/repo", phase_metadata="workflow.json", expected_head=self.source_sha,
                    java_major=17, node_major=24, tuple="jdk17-node24",
                ))
            identity.assert_not_called()

    def test_phase_base_requires_unique_full_sha_and_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            metadata = pathlib.Path(temporary) / "ci-floor-phase-metadata.json"
            metadata.write_text(json.dumps({"baselineSha": self.phase_base}), encoding="utf-8")
            os.chmod(metadata, 0o600)
            commands: list[list[str]] = []

            def git(argv: list[str], *, cwd: pathlib.Path | None = None, timeout: float = 20):
                commands.append(argv)
                return ci_floor.subprocess.CompletedProcess(argv, 0, "", "")

            with mock.patch.object(ci_floor, "_run", side_effect=git):
                self.assertEqual(ci_floor._read_phase_base(pathlib.Path("/public/repo"), metadata), self.phase_base)
            self.assertEqual(len(commands), 2)
            metadata.write_text('{"baselineSha":"' + self.phase_base + '","baselineSha":"' + self.phase_base + '"}', encoding="utf-8")
            with self.assertRaises(ci_floor.FloorInputError):
                ci_floor._read_phase_base(pathlib.Path("/public/repo"), metadata)

    def test_full_twenty_three_gate_receipt_uses_finite_ci_specific_json_budget(self) -> None:
        settle = {
            "eligible": True,
            "settled": True,
            "initialIdentities": [
                {"pid": 41001, "startedAt": "public-start-a", "observedParentPid": 40000,
                 "descriptorStatus": "uninspectable", "reason": "ownership-scan-did-not-complete"},
                {"pid": 41002, "startedAt": "public-start-b", "observedParentPid": 40000,
                 "descriptorStatus": "uninspectable", "reason": "ownership-scan-did-not-complete"},
            ],
            "initialCandidateCount": 2,
            "latestIdentities": [],
            "latestCandidateCount": 0,
            "waitSeconds": 0.01,
            "settleWindowSeconds": 120.0,
            "deadlineRemainingSeconds": 119.99,
            "pollCount": 2,
            "globalRescanCount": 3,
            "error": None,
        }
        gates = [{
            "name": gate.name,
            "argv": list(gate.argv),
            "cwd": gate.cwd,
            "exitCode": 0,
            "durationSeconds": 1.25,
            "log": f"logs/{gate.name}.log",
            "logSha256": self.digest,
            "headBefore": self.source_sha,
            "headAfter": self.source_sha,
            "workingTreeDigestBefore": self.digest,
            "workingTreeDigestAfter": self.digest,
            "phaseDiffSha256Before": self.digest,
            "phaseDiffSha256After": self.digest,
            "status": "passed",
            "naturalExitSettle": settle,
        } for gate in run_gates.GATES]
        probes = [{
            "name": name,
            "argv": list(argv),
            "cwd": cwd,
            "exitCode": 0,
            "durationSeconds": 0.125,
            "log": f"logs/version-{name}.log",
            "logSha256": self.digest,
            "status": "passed",
            "naturalExitSettle": settle,
        } for name, argv, cwd in run_gates.VERSION_COMMANDS]
        receipt = {
            "schemaVersion": 1,
            "label": "floor-123456-1-jdk17-node22",
            "phaseBase": self.phase_base,
            "headBefore": self.source_sha,
            "headAfter": self.source_sha,
            "workingTreeDigestBefore": self.digest,
            "workingTreeDigestAfter": self.digest,
            "phaseDiffSha256Before": self.digest,
            "phaseDiffSha256After": self.digest,
            "toolVersions": {name: "public-version" for name, _argv, _cwd in run_gates.VERSION_COMMANDS},
            "versionProbes": probes,
            "cacheKeys": list(run_gates.CACHE_NAMES),
            "restrictedTargetKey": "cargo-target-restricted-public-label",
            "platform": {"system": "Linux", "release": "public-release", "machine": "x86_64"},
            "dependencyLockSha256": {"Cargo.lock": self.digest, "package-lock.json": self.digest},
            "gates": gates,
            "decision": "checks_passed_for_review",
        }
        raw = (json.dumps(receipt, separators=(",", ":")) + "\n").encode()
        self.assertGreater(raw.count(b","), 512)
        self.assertLessEqual(len(raw), ci_floor.MAX_METADATA_BYTES)
        with tempfile.TemporaryFile(dir=self._scratch_root()) as stream:
            stream.write(raw)
            stream.flush()
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._bounded_json_shape(stream.fileno(), len(raw))
            private_roots._bounded_json_shape(
                stream.fileno(), len(raw), maximum_commas=ci_floor.CI_RECEIPT_JSON_BUDGET,
            )
        with self.assertRaises(private_roots.AdmissionError):
            private_roots._loads_bounded_private_json(raw)
        parsed = private_roots._loads_bounded_private_json(
            raw, maximum_nodes=ci_floor.CI_RECEIPT_JSON_BUDGET,
        )
        self.assertEqual(len(parsed["gates"]), 23)
        with self.assertRaises(private_roots.AdmissionError):
            private_roots.read_private_json(
                "/synthetic/not-opened.json",
                maximum_nodes=private_roots.PRIVATE_JSON_BUDGET_LIMIT + 1,
            )

    def test_sanitizer_whitelists_public_fields_and_requires_same_source_suite(self) -> None:
        label = "floor-123456-1-jdk17-node22"
        tests = {
            "schemaVersion": 1,
            "sourceSha": self.source_sha,
            "sourceIdentityVerified": True,
            "testScratchAdmissionVerified": True,
            "suiteModules": list(ci_floor.RELEASE_TEST_MODULES),
            "status": "passed",
            "discoveredCount": 2,
            "discoveredTestIds": sorted([
                "tools.release.test_release_tools.Public.test_ok",
                "tools.release.test_ci_floor.Public.test_ok",
            ]),
            "testCount": 2,
            "failedCount": 0,
            "skippedCount": 0,
            "tests": [
                {"name": name, "status": "passed"} for name in sorted([
                    "tools.release.test_release_tools.Public.test_ok",
                    "tools.release.test_ci_floor.Public.test_ok",
                ])
            ],
            "privateNote": "PRIVATE_TEST_CANARY_4c7f",
        }
        receipt = self._passing_receipt(label)
        receipt["privateNote"] = "PRIVATE_RECEIPT_CANARY_5a31"
        receipt["privateCommandMetadata"] = "PRIVATE_ARGV_CANARY_9f02"
        restricted = next(row for row in receipt["gates"] if row["name"] == "restricted-build")
        private_cargo = "/private/runner/cache/toolchain-cargo-argv-canary/cargo"
        restricted["argv"][0] = private_cargo
        original_which = ci_floor.shutil.which

        def which(name: str, *args: object, **kwargs: object):
            if name == "cargo":
                return private_cargo
            return original_which(name, *args, **kwargs)
        output: list[bytes] = []

        def read(path: pathlib.Path, **kwargs: object):
            if path.name == "release-tool-tests-summary.json":
                return tests
            return receipt

        def version_log(path: pathlib.Path) -> tuple[str, str]:
            name = path.name.removeprefix("version-").removesuffix(".log")
            return self.digest, receipt["toolVersions"][name]

        args = Namespace(
            root="/synthetic/private-root", repo="/public/repo", label=label, expected_head=self.source_sha,
            phase_base=self.phase_base, tuple="jdk17-node22",
        )
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=tests["discoveredTestIds"]), \
                mock.patch.object(ci_floor, "_private_file_sha256", return_value=self.digest), \
                mock.patch.object(ci_floor, "_private_log_digest_and_first_line", side_effect=version_log), \
                mock.patch.object(ci_floor.shutil, "which", side_effect=which), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 0)
        self.assertEqual(len(output), 1)
        public = json.loads(output[0])
        self.assertEqual(public["floorStatus"], "checks_passed_for_review")
        rendered = output[0].decode()
        for canary in (
            "PRIVATE_TEST_CANARY_4c7f", "PRIVATE_RECEIPT_CANARY_5a31",
            "PRIVATE_ARGV_CANARY_9f02", private_cargo,
        ):
            self.assertNotIn(canary, rendered)
        self.assertEqual(public["gateCount"], 23)
        self.assertFalse(public["releaseAcceptance"])

        tests["sourceSha"] = self.phase_base
        output.clear()
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=tests["discoveredTestIds"]), \
                mock.patch.object(ci_floor, "_private_file_sha256", return_value=self.digest), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 1)
        self.assertNotEqual(json.loads(output[0])["floorStatus"], "checks_passed_for_review")

    def test_sanitizer_rejects_unreached_gate_rows_and_mismatched_identity(self) -> None:
        label = "floor-123456-1-jdk21-node24"
        tests = {
            "schemaVersion": 1,
            "sourceSha": self.source_sha,
            "sourceIdentityVerified": True,
            "testScratchAdmissionVerified": True,
            "suiteModules": list(ci_floor.RELEASE_TEST_MODULES),
            "status": "passed",
            "discoveredCount": 2,
            "discoveredTestIds": sorted([
                "tools.release.test_ci_floor.Public.test_ok",
                "tools.release.test_release_tools.Public.test_ok",
            ]),
            "testCount": 2,
            "failedCount": 0,
            "skippedCount": 0,
            "tests": [{"name": name, "status": "passed"} for name in sorted([
                "tools.release.test_ci_floor.Public.test_ok",
                "tools.release.test_release_tools.Public.test_ok",
            ])],
        }
        receipt = self._passing_receipt(label)
        receipt["phaseDiffSha256After"] = "d" * 64
        receipt["gates"][-1]["status"] = "unreached"
        output: list[bytes] = []

        def read(path: pathlib.Path, **kwargs: object):
            return tests if path.name == "release-tool-tests-summary.json" else receipt

        args = Namespace(
            root="/synthetic/private-root", repo="/public/repo", label=label, expected_head=self.source_sha,
            phase_base=self.phase_base, tuple="jdk21-node24",
        )
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=tests["discoveredTestIds"]), \
                mock.patch.object(ci_floor, "_private_file_sha256", return_value=self.digest), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 1)
        public = json.loads(output[0])
        self.assertNotEqual(public["floorStatus"], "checks_passed_for_review")
        self.assertEqual(public["floorStatus"], "invalid")
        self.assertEqual(public["gateCount"], 0)

    def test_sanitizer_recomputes_source_proofs_instead_of_trusting_consistent_labels(self) -> None:
        label = "floor-123456-1-jdk17-node22"
        names = sorted([
            "tools.release.test_ci_floor.Public.test_ok",
            "tools.release.test_release_tools.Public.test_ok",
        ])
        tests = {
            "schemaVersion": 1, "sourceSha": self.source_sha, "sourceIdentityVerified": True,
            "testScratchAdmissionVerified": True, "suiteModules": list(ci_floor.RELEASE_TEST_MODULES),
            "status": "passed", "discoveredCount": 2, "testCount": 2,
            "failedCount": 0, "skippedCount": 0, "discoveredTestIds": names,
            "tests": [{"name": name, "status": "passed"} for name in names],
        }
        receipt = self._passing_receipt(label)
        forged = "d" * 64
        for field in ("workingTreeDigestBefore", "workingTreeDigestAfter",
                      "phaseDiffSha256Before", "phaseDiffSha256After"):
            receipt[field] = forged
        for row in receipt["gates"]:
            for field in ("workingTreeDigestBefore", "workingTreeDigestAfter",
                          "phaseDiffSha256Before", "phaseDiffSha256After"):
                row[field] = forged
        receipt["dependencyLockSha256"] = {name: forged for name in receipt["dependencyLockSha256"]}
        output: list[bytes] = []
        def read(path: pathlib.Path, **_kwargs: object):
            return tests if path.name == "release-tool-tests-summary.json" else receipt
        args = Namespace(root="/synthetic/private-root", repo="/public/repo", label=label,
                         expected_head=self.source_sha, phase_base=self.phase_base, tuple="jdk17-node22")
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=names), \
                mock.patch.object(ci_floor, "_private_file_sha256", return_value=self.digest), \
                mock.patch.object(ci_floor, "_private_log_digest_and_first_line",
                                  side_effect=lambda path: (self.digest, receipt["toolVersions"][path.name.removeprefix("version-").removesuffix(".log")])), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 1)
        self.assertEqual(json.loads(output[0])["floorStatus"], "invalid")

    def test_sanitizer_requires_exact_freshly_discovered_two_module_suite(self) -> None:
        label = "floor-123456-1-jdk17-node22"
        expected = sorted([
            "tools.release.test_ci_floor.Public.test_ok",
            "tools.release.test_release_tools.Public.test_ok",
        ])
        base = {
            "schemaVersion": 1, "sourceSha": self.source_sha, "sourceIdentityVerified": True,
            "testScratchAdmissionVerified": True,
            "suiteModules": list(ci_floor.RELEASE_TEST_MODULES), "status": "passed",
            "discoveredCount": 2, "testCount": 2, "failedCount": 0, "skippedCount": 0,
            "discoveredTestIds": expected,
            "tests": [{"name": name, "status": "passed"} for name in expected],
        }
        variants = {
            "omitted": {**base, "discoveredCount": 1, "testCount": 1,
                        "discoveredTestIds": expected[:1], "tests": base["tests"][:1]},
            "duplicate": {**base, "discoveredTestIds": [expected[0], expected[0]],
                           "tests": [{"name": expected[0], "status": "passed"}] * 2},
            "cross-module": {**base, "discoveredTestIds": ["tools.release.test_other.Public.test_ok", expected[1]],
                             "tests": [{"name": "tools.release.test_other.Public.test_ok", "status": "passed"},
                                       {"name": expected[1], "status": "passed"}]},
        }
        receipt = self._passing_receipt(label)
        args = Namespace(root="/synthetic/private-root", repo="/public/repo", label=label,
                         expected_head=self.source_sha, phase_base=self.phase_base, tuple="jdk17-node22")
        for case, test_summary in variants.items():
            output: list[bytes] = []
            def read(path: pathlib.Path, **_kwargs: object):
                return test_summary if path.name == "release-tool-tests-summary.json" else receipt
            with self.subTest(case=case), mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                    mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                    mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                    mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                    mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=expected), \
                    mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
                self.assertEqual(ci_floor._sanitize_floor(args), 1)
            self.assertNotEqual(json.loads(output[0])["floorStatus"], "checks_passed_for_review")

    def test_sanitizer_rejects_incomplete_per_gate_and_probe_evidence(self) -> None:
        label = "floor-123456-1-jdk21-node24"
        expected = sorted([
            "tools.release.test_ci_floor.Public.test_ok",
            "tools.release.test_release_tools.Public.test_ok",
        ])
        tests = {
            "schemaVersion": 1, "sourceSha": self.source_sha, "sourceIdentityVerified": True,
            "testScratchAdmissionVerified": True,
            "suiteModules": list(ci_floor.RELEASE_TEST_MODULES), "status": "passed",
            "discoveredCount": 2, "testCount": 2, "failedCount": 0, "skippedCount": 0,
            "discoveredTestIds": expected,
            "tests": [{"name": name, "status": "passed"} for name in expected],
        }
        args = Namespace(root="/synthetic/private-root", repo="/public/repo", label=label,
                         expected_head=self.source_sha, phase_base=self.phase_base, tuple="jdk21-node24")
        receipt = self._passing_receipt(label)
        corrupted_rows = {
            "missing-log": lambda row: row.pop("log"),
            "wrong-log-hash": lambda row: row.update(logSha256="0" * 64),
            "wrong-source": lambda row: row.update(headAfter=self.phase_base),
            "wrong-command": lambda row: row.update(argv=["unreviewed-command"]),
            "cleanup-uncertain": lambda row: row.update(cleanupUncertain=True),
            "unsettled": lambda row: row.update(naturalExitSettle={"eligible": True, "settled": False}),
        }
        for case, corrupt in corrupted_rows.items():
            mutated = copy.deepcopy(receipt)
            corrupt(mutated["gates"][0])
            output: list[bytes] = []
            def read(path: pathlib.Path, **_kwargs: object):
                return tests if path.name == "release-tool-tests-summary.json" else mutated
            with self.subTest(case=case), mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                    mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                    mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                    mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                    mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=expected), \
                    mock.patch.object(ci_floor, "_private_file_sha256", return_value=self.digest), \
                    mock.patch.object(ci_floor, "_private_log_digest_and_first_line", side_effect=lambda _path: (self.digest, 'openjdk version "21.0.1"' if "jdk21" in label else 'openjdk version "17.0.1"')) , \
                    mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
                self.assertEqual(ci_floor._sanitize_floor(args), 1)
            self.assertNotEqual(json.loads(output[0])["floorStatus"], "checks_passed_for_review")

        for case in ("missing-version-probe", "bad-version-log-hash"):
            mutated = copy.deepcopy(receipt)
            if case == "missing-version-probe":
                mutated["versionProbes"].pop()
            else:
                mutated["versionProbes"][0]["logSha256"] = "0" * 64
            output = []
            def read_probe_case(path: pathlib.Path, **_kwargs: object):
                return tests if path.name == "release-tool-tests-summary.json" else mutated
            with self.subTest(case=case), mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                    mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read_probe_case), \
                    mock.patch.object(ci_floor, "_source_is_clean", return_value=True), \
                    mock.patch.object(ci_floor, "_source_proofs", return_value=self._source_proofs()), \
                    mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=expected), \
                    mock.patch.object(ci_floor, "_private_file_sha256", return_value=self.digest), \
                    mock.patch.object(ci_floor, "_private_log_digest_and_first_line", side_effect=lambda _path: (self.digest, 'openjdk version "21.0.1"' if "jdk21" in label else 'openjdk version "17.0.1"')) , \
                    mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
                self.assertEqual(ci_floor._sanitize_floor(args), 1)
            self.assertNotEqual(json.loads(output[0])["floorStatus"], "checks_passed_for_review")

    def test_summarize_tests_fails_before_discovery_without_admitted_tmpdir(self) -> None:
        args = Namespace(root="/synthetic/private-root", repo="/public/repo", source_sha=self.source_sha)
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.dict(os.environ, {"TMPDIR": "/tmp/unadmitted", "TMP": "/tmp/unadmitted", "TEMP": "/tmp/unadmitted"}), \
                mock.patch.object(ci_floor.tempfile, "gettempdir", return_value="/tmp"), \
                mock.patch.object(ci_floor, "_discover_release_test_ids") as discover:
            with self.assertRaises(ci_floor.FloorInputError):
                ci_floor._summarize_tests(args)
            discover.assert_not_called()

    def test_utility_supervisor_drains_leader_exit_with_pipe_holding_child(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            pid_file = pathlib.Path(temporary) / "owned-child.json"
            child_code = "import time; time.sleep(30)"
            parent_code = (
                "import json,os,subprocess,sys,time; "
                "child=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
                "open(sys.argv[1],'w').write(json.dumps([os.getpid(),child.pid])); time.sleep(.2)"
            )
            try:
                with self.assertRaises(ci_floor.FloorInputError):
                    ci_floor._run([sys.executable, "-c", parent_code, str(pid_file), child_code], timeout=0.6)
                if pid_file.exists():
                    parent_pid, child_pid = json.loads(pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    self.assertFalse(child is not None and child[1] == parent_pid and child[2] != "" and child[3] not in {"Z", "X"})
            finally:
                if pid_file.exists():
                    parent_pid, child_pid = json.loads(pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    if child is not None and child[1] == parent_pid and child[3] not in {"Z", "X"}:
                        ci_floor._signal_utility_group_members(
                            parent_pid, {child_pid: child[2]}, signal.SIGKILL,
                            deadline=time.monotonic() + 1.0,
                        )

    def test_utility_supervisor_kills_term_ignoring_pipe_holder_within_cleanup_budget(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            pid_file = root / "owned-child.json"
            ready_file = root / "child-ready"
            term_file = root / "term-observed"
            child_code = (
                "import pathlib,signal,sys,time; "
                "signal.signal(signal.SIGTERM,lambda *_: pathlib.Path(sys.argv[2]).write_text('term')); "
                "pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)"
            )
            parent_code = (
                "import json,os,pathlib,subprocess,sys,time\n"
                "child=subprocess.Popen([sys.executable,'-c',sys.argv[3],sys.argv[2],sys.argv[4]])\n"
                "ready=pathlib.Path(sys.argv[2]); deadline=time.monotonic()+3\n"
                "while not ready.exists() and time.monotonic()<deadline:\n"
                " time.sleep(.01)\n"
                "open(sys.argv[1],'w').write(json.dumps([os.getpid(),child.pid]))\n"
                "time.sleep(.2)\n"
            )
            started = time.monotonic()
            try:
                with self.assertRaises(ci_floor.FloorInputError):
                    ci_floor._run(
                        [sys.executable, "-c", parent_code, str(pid_file), str(ready_file), child_code, str(term_file)],
                        timeout=0.6,
                    )
                self.assertLess(time.monotonic() - started, 5.0)
                self.assertTrue(term_file.is_file(), "TERM was delivered before the forced KILL")
                parent_pid, child_pid = json.loads(pid_file.read_text(encoding="utf-8"))
                snapshot = ci_floor._utility_process_snapshot()
                child = snapshot.get(child_pid)
                self.assertFalse(
                    child is not None and child[1] == parent_pid and child[3] not in {"Z", "X"},
                    "TERM-ignoring owned child remains live in utility process group",
                )
            finally:
                if pid_file.exists():
                    parent_pid, child_pid = json.loads(pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    if child is not None and child[1] == parent_pid and child[3] not in {"Z", "X"}:
                        ci_floor._signal_utility_group_members(
                            parent_pid, {child_pid: child[2]}, signal.SIGKILL,
                            deadline=time.monotonic() + 1.0,
                        )

    def _passing_receipt(self, label: str) -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "label": label,
            "phaseBase": self.phase_base,
            "headBefore": self.source_sha,
            "headAfter": self.source_sha,
            "workingTreeDigestBefore": self.digest,
            "workingTreeDigestAfter": self.digest,
            "phaseDiffSha256Before": self.digest,
            "phaseDiffSha256After": self.digest,
            "toolVersions": {
                **{name: "public-version" for name, _argv, _cwd in run_gates.VERSION_COMMANDS},
                "java": f'openjdk version "{21 if "jdk21" in label else 17}.0.1"',
                "node": f'v{24 if "node24" in label else 22}.0.0',
            },
            "dependencyLockSha256": {
                name: self.digest for name in (
                    "Cargo.lock", "adapters/java/gradle.lockfile",
                    "adapters/node/package-lock.json", "web/app/package-lock.json",
                )
            },
            "cacheKeys": list(run_gates.CACHE_NAMES),
            "restrictedTargetKey": f"cargo-target-restricted-{label}",
            "versionProbes": [{
                "name": name, "argv": list(argv), "cwd": cwd,
                "exitCode": 0, "durationSeconds": 0.1,
                "log": f"logs/version-{name}.log", "logSha256": self.digest, "status": "passed",
            } for name, argv, cwd in run_gates.VERSION_COMMANDS],
            "platform": {"system": "Linux", "release": "public-release", "machine": "x86_64"},
            "gates": [{
                "name": gate.name,
                "argv": (["git", "diff", "--check", f"{self.phase_base}...HEAD"] if gate.env == "phase-diff"
                         else [ci_floor.shutil.which("cargo") or "/usr/bin/cargo", *gate.argv[1:]] if gate.env == "restricted"
                         else list(gate.argv)),
                "cwd": gate.cwd,
                "exitCode": 0,
                "durationSeconds": 0.25,
                "log": f"logs/{gate.name}.log",
                "logSha256": self.digest,
                "headBefore": self.source_sha,
                "headAfter": self.source_sha,
                "workingTreeDigestBefore": self.digest,
                "workingTreeDigestAfter": self.digest,
                "phaseDiffSha256Before": self.digest,
                "phaseDiffSha256After": self.digest,
                "status": "passed",
            } for gate in run_gates.GATES],
            "decision": "checks_passed_for_review",
        }

    @staticmethod
    def _scratch_root() -> pathlib.Path:
        value = os.environ.get("XTRACE_TEST_SCRATCH_ROOT")
        if not value:
            raise RuntimeError("XTRACE_TEST_SCRATCH_ROOT is required")
        path = pathlib.Path(value)
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise RuntimeError("test scratch root must be an admitted existing directory")
        return path
