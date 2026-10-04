from __future__ import annotations

import copy
import io
import json
import os
import signal
import stat
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

    def test_private_version_log_reader_hashes_real_bounded_fixture(self) -> None:
        raw = b'\n\r\nGradle 8.14\nignored later line\n'
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            path = pathlib.Path(temporary) / "version.log"
            path.write_bytes(raw)
            def public_fixture_reader(candidate: pathlib.Path) -> int:
                self.assertEqual(candidate, path)
                return os.open(candidate, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))

            with mock.patch.object(ci_floor.private_roots, "open_private_file_read", side_effect=public_fixture_reader):
                digest, first_line = ci_floor._private_log_digest_and_first_line(path)
            self.assertEqual(digest, ci_floor.hashlib.sha256(raw).hexdigest())
            self.assertEqual(first_line, "Gradle 8.14")
            with mock.patch.object(ci_floor, "PRIVATE_VERSION_LOG_READ_SECONDS", 0):
                with mock.patch.object(ci_floor.private_roots, "open_private_file_read", side_effect=public_fixture_reader):
                    with self.assertRaises(ci_floor.FloorInputError):
                        ci_floor._private_log_digest_and_first_line(path)

    def test_source_lock_fifo_is_rejected_after_nonblocking_open(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            path = pathlib.Path(temporary) / "lockfile"
            os.mkfifo(path)
            real_open = os.open
            observed_nonblocking: list[bool] = []

            def checked_open(candidate: object, flags: int, *args: object, **kwargs: object) -> int:
                if pathlib.Path(candidate) == path:
                    observed_nonblocking.append(bool(flags & getattr(os, "O_NONBLOCK", 0)))
                return real_open(candidate, flags, *args, **kwargs)

            with mock.patch.object(ci_floor.os, "open", side_effect=checked_open):
                with self.assertRaises(ci_floor.FloorInputError):
                    ci_floor._bounded_source_file_sha256(path)
            self.assertEqual(observed_nonblocking, [True])

    def test_source_lock_reader_hashes_regular_file_through_nonblocking_fd(self) -> None:
        raw = b"public synthetic lock bytes\x00\xff\n"
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            path = pathlib.Path(temporary) / "lockfile"
            path.write_bytes(raw)
            self.assertEqual(
                ci_floor._bounded_source_file_sha256(path),
                ci_floor.hashlib.sha256(raw).hexdigest(),
            )

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
            "identityUnion": [],
            "identityUnionCount": 2,
            "identityUnionTruncated": False,
            "ownedProbeProcesses": [],
            "ownedProbeProcessCount": 0,
            "cleanupExceptions": [],
            "cleanupExceptionCount": 0,
            "probeEvidenceTruncated": False,
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
                "start=' '.join(subprocess.check_output(['/bin/ps','-o','lstart=','-p',str(child.pid)],text=True).split()); "
                "open(sys.argv[1],'w').write(json.dumps([child.pid,os.getpgid(child.pid),start])); time.sleep(.2)"
            )
            try:
                with self.assertRaises(ci_floor.FloorInputError):
                    ci_floor._run([sys.executable, "-c", parent_code, str(pid_file), child_code], timeout=0.6)
                self.assertTrue(pid_file.is_file(), "the pipe-holding child must publish its process identity")
                child_pid, child_group, child_start = json.loads(pid_file.read_text(encoding="utf-8"))
                self.assertGreater(child_pid, 0)
                self.assertGreater(child_group, 0)
                self.assertTrue(child_start, "the child start identity must be captured before supervision")
                snapshot = ci_floor._utility_process_snapshot()
                child = snapshot.get(child_pid)
                child_is_live = (
                    child is not None and child[1] == child_group and child[2] == child_start
                    and child[3] not in {"Z", "X"}
                )
                self.assertFalse(child_is_live, "the utility supervisor left its pipe-holding child alive")
            finally:
                if pid_file.exists():
                    child_pid, child_group, child_start = json.loads(pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    if (child is not None and child[1] == child_group and child[2] == child_start
                            and child[3] not in {"Z", "X"}):
                        ci_floor._signal_utility_group_members(
                            child_group, {child_pid: child_start}, signal.SIGKILL,
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
                "start=' '.join(subprocess.check_output(['/bin/ps','-o','lstart=','-p',str(child.pid)],text=True).split())\n"
                "open(sys.argv[1],'w').write(json.dumps([child.pid,os.getpgid(child.pid),start]))\n"
                "time.sleep(.2)\n"
            )
            started = time.monotonic()
            try:
                with self.assertRaises(ci_floor.FloorInputError):
                    ci_floor._run(
                        [sys.executable, "-c", parent_code, str(pid_file), str(ready_file), child_code, str(term_file)],
                        timeout=0.6,
                    )
                self.assertTrue(pid_file.is_file(), "the TERM-ignoring child must publish its process identity")
                child_pid, child_group, child_start = json.loads(pid_file.read_text(encoding="utf-8"))
                self.assertGreater(child_pid, 0)
                self.assertGreater(child_group, 0)
                self.assertTrue(child_start, "the child start identity must be captured before supervision")
                snapshot = ci_floor._utility_process_snapshot()
                child = snapshot.get(child_pid)
                child_is_live = (
                    child is not None and child[1] == child_group and child[2] == child_start
                    and child[3] not in {"Z", "X"}
                )
                self.assertFalse(
                    child_is_live,
                    "TERM-ignoring owned child remains live in its original utility process group",
                )
                self.assertLess(time.monotonic() - started, 5.0)
                self.assertTrue(term_file.is_file(), "TERM was delivered before the forced KILL")
            finally:
                if pid_file.exists():
                    child_pid, child_group, child_start = json.loads(pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    if (child is not None and child[1] == child_group and child[2] == child_start
                            and child[3] not in {"Z", "X"}):
                        ci_floor._signal_utility_group_members(
                            child_group, {child_pid: child_start}, signal.SIGKILL,
                            deadline=time.monotonic() + 1.0,
                        )

    def test_bounded_git_supervisor_cleans_exited_leader_pipe_holder(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            pid_file = root / "child-pid"
            entered_file = root / "script-entered"
            prepare_file = root / "prepare-entered"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "open(os.environ['XTRACE_FAKE_GIT_ENTERED_FILE'], 'w').write('entered')\n"
                "import json, pathlib, subprocess, sys, time\n"
                "if sys.argv[1:] == ['--prepare-only']:\n"
                " time.sleep(.1)\n"
                " open(os.environ['XTRACE_FAKE_GIT_PREPARE_FILE'], 'w').write('prepared')\n"
                " sys.exit(0)\n"
                "def publish(path, value):\n"
                " target = pathlib.Path(path)\n"
                " temporary = target.with_name(target.name + '.tmp')\n"
                " temporary.write_text(value)\n"
                " os.replace(temporary, target)\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                "try:\n"
                " start = ' '.join(subprocess.check_output(['/bin/ps','-o','lstart=','-p',str(child.pid)],text=True).split())\n"
                " publish(os.environ['XTRACE_FAKE_GIT_PID_FILE'], json.dumps([child.pid,os.getpgid(child.pid),start]))\n"
                " time.sleep(.15)\n"
                "except BaseException:\n"
                " child.kill(); child.wait(); raise\n",
                encoding="utf-8",
            )
            os.chmod(fake_git, 0o700)
            old_path = os.environ.get("PATH", "/usr/bin:/bin")
            original_snapshot = ci_floor._utility_process_snapshot
            original_popen = ci_floor.subprocess.Popen
            original_os_read = os.read
            snapshot_trace: list[dict[str, object]] = []
            snapshot_trace_omitted = 0
            git_launch: dict[str, object] = {
                "attempted": False,
                "selectedPathEqualsFixture": False,
                "pathCheckExceptionType": None,
                "launched": False,
                "popenExceptionType": None,
                "process": None,
                "stderrFd": None,
            }
            stderr_bytes_observed = 0
            stderr_observation_truncated = False
            stderr_prefix = bytearray()

            def record_popen(*args: object, **kwargs: object) -> object:
                command = args[0] if args else kwargs.get("args")
                is_git = (
                    isinstance(command, (list, tuple)) and bool(command) and command[0] == "git"
                ) or command == "git"
                if is_git:
                    git_launch["attempted"] = True
                    try:
                        selected = ci_floor.shutil.which("git")
                        git_launch["selectedPathEqualsFixture"] = bool(
                            selected is not None and pathlib.Path(selected).resolve() == fake_git.resolve()
                        )
                    except Exception as exc:
                        git_launch["pathCheckExceptionType"] = type(exc).__name__
                try:
                    process = original_popen(*args, **kwargs)
                except BaseException as exc:
                    if is_git:
                        git_launch["popenExceptionType"] = type(exc).__name__
                    raise
                if is_git:
                    git_launch["launched"] = True
                    git_launch["process"] = process
                    stream = getattr(process, "stderr", None)
                    if stream is not None:
                        try:
                            git_launch["stderrFd"] = stream.fileno()
                        except (OSError, ValueError):
                            git_launch["stderrFd"] = None
                return process

            def record_read(descriptor: int, size: int) -> bytes:
                nonlocal stderr_bytes_observed, stderr_observation_truncated
                chunk = original_os_read(descriptor, size)
                if descriptor == git_launch["stderrFd"]:
                    remaining = 65536 - stderr_bytes_observed
                    stderr_bytes_observed += min(len(chunk), max(0, remaining))
                    if len(chunk) > max(0, remaining):
                        stderr_observation_truncated = True
                    if len(stderr_prefix) < 512:
                        stderr_prefix.extend(chunk[:512 - len(stderr_prefix)])
                return chunk

            def stderr_category() -> str:
                sample = bytes(stderr_prefix).lower()
                if not sample:
                    return "empty_or_unobserved"
                if b"bad interpreter" in sample or b"not found" in sample or b"no such file" in sample:
                    return "interpreter_startup"
                if b"permission denied" in sample:
                    return "permission_denied"
                if b"syntaxerror" in sample:
                    return "python_startup_syntax"
                return "other_nonempty"

            def post_cleanup_return_code() -> int | str:
                process = git_launch["process"]
                if process is None:
                    return "not_launched"
                try:
                    code = process.poll()
                except Exception:
                    return "unavailable"
                return code if isinstance(code, int) else "still_running"

            def append_snapshot_trace(item: dict[str, object]) -> None:
                nonlocal snapshot_trace_omitted
                if len(snapshot_trace) < 64:
                    snapshot_trace.append(item)
                else:
                    snapshot_trace_omitted += 1

            def fixture_identity_seen(records: dict[int, tuple[int, int, str, str]]) -> bool:
                if not pid_file.is_file():
                    return False
                try:
                    expected_pid, expected_group, expected_start = json.loads(pid_file.read_text(encoding="utf-8"))
                except (OSError, ValueError, TypeError):
                    return False
                record = records.get(expected_pid)
                return record is not None and record[1] == expected_group and record[2] == expected_start

            def diagnostic() -> str:
                return json.dumps({
                    "fixtureStages": {
                        "scriptEntered": entered_file.is_file(),
                        "childIdentityPublished": pid_file.is_file(),
                        "fakeGitLaunchAttempted": git_launch["attempted"],
                        "fakeGitSelectedPathEqualsFixture": git_launch["selectedPathEqualsFixture"],
                        "fakeGitPathCheckExceptionType": git_launch["pathCheckExceptionType"],
                        "fakeGitPopenLaunched": git_launch["launched"],
                        "fakeGitPopenExceptionType": git_launch["popenExceptionType"],
                        "fakeGitLeaderReturnCode": post_cleanup_return_code(),
                        "fakeGitStderrBytesObservedCapped": stderr_bytes_observed,
                        "fakeGitStderrObservationTruncated": stderr_observation_truncated,
                        "fakeGitStderrCategory": stderr_category(),
                    },
                    "snapshotCalls": snapshot_trace,
                    "omittedSnapshotCalls": snapshot_trace_omitted,
                }, sort_keys=True)

            def record_snapshot(*args: object, **kwargs: object) -> dict[int, tuple[int, int, str, str]]:
                entered = time.monotonic()
                timeout = kwargs.get("timeout", 2.0)
                deadline = kwargs.get("deadline")
                item: dict[str, object] = {
                    "enteredOffsetSeconds": round(entered - started, 6),
                    "timeoutSeconds": timeout if isinstance(timeout, (int, float)) else "invalid",
                    "deadlineRemainingSeconds": round(deadline - entered, 6)
                    if isinstance(deadline, (int, float)) else None,
                }
                try:
                    result = original_snapshot(*args, **kwargs)
                except BaseException as exc:
                    item.update({
                        "exitedOffsetSeconds": round(time.monotonic() - started, 6),
                        "outcome": "exception",
                        "exceptionType": type(exc).__name__,
                        "fixtureIdentitySeen": False,
                    })
                    append_snapshot_trace(item)
                    raise
                item.update({
                    "exitedOffsetSeconds": round(time.monotonic() - started, 6),
                    "outcome": "returned",
                    "fixtureIdentitySeen": fixture_identity_seen(result),
                })
                append_snapshot_trace(item)
                return result

            with mock.patch.dict(os.environ, {
                "XTRACE_FAKE_GIT_PID_FILE": str(pid_file),
                "XTRACE_FAKE_GIT_ENTERED_FILE": str(entered_file),
                "XTRACE_FAKE_GIT_PREPARE_FILE": str(prepare_file),
            }):
                preparation = ci_floor._run([str(fake_git), "--prepare-only"], timeout=2.0)
            self.assertEqual(preparation.returncode, 0, "fake Git prepare-only run must exit cleanly: " + diagnostic())
            self.assertTrue(prepare_file.is_file(), "fake Git preflight must reach post-import preparation: " + diagnostic())
            git_fixture_markers = (entered_file, pid_file, prepare_file)
            for marker in git_fixture_markers:
                marker.unlink(missing_ok=True)
                marker.with_name(marker.name + ".tmp").unlink(missing_ok=True)
            self.assertFalse(any(marker.exists() for marker in git_fixture_markers))

            started = time.monotonic()
            try:
                with mock.patch.dict(os.environ, {
                    "PATH": f"{fake_bin}{os.pathsep}{old_path}",
                    "XTRACE_FAKE_GIT_PID_FILE": str(pid_file),
                    "XTRACE_FAKE_GIT_ENTERED_FILE": str(entered_file),
                }), mock.patch.object(ci_floor, "SOURCE_COMMAND_TIMEOUT_SECONDS", 0.5), \
                        mock.patch.object(ci_floor, "_utility_process_snapshot", side_effect=record_snapshot), \
                        mock.patch.object(ci_floor.subprocess, "Popen", side_effect=record_popen), \
                        mock.patch.object(ci_floor.os, "read", side_effect=record_read):
                    try:
                        ci_floor._bounded_git_output(root, "rev-parse", "--verify", "HEAD")
                    except ci_floor.FloorInputError:
                        pass
                    except Exception as exc:
                        self.fail(
                            "bounded fake Git command raised " + type(exc).__name__ + ": " + diagnostic()
                        )
                    else:
                        self.fail("bounded fake Git command must fail closed: " + diagnostic())
                self.assertTrue(entered_file.is_file(), "fake Git script must reach its first statement: " + diagnostic())
                self.assertTrue(pid_file.is_file(), "fake Git child must publish its process identity: " + diagnostic())
                child_pid, child_group, child_start = json.loads(pid_file.read_text(encoding="utf-8"))
                snapshot = ci_floor._utility_process_snapshot()
                child = snapshot.get(child_pid)
                child_is_live = (
                    child is not None and child[1] == child_group and child[2] == child_start
                    and child[3] not in {"Z", "X"}
                )
                self.assertFalse(child_is_live, "the Git supervisor left its pipe-holding child alive: " + diagnostic())
            finally:
                if pid_file.is_file():
                    child_pid, child_group, child_start = json.loads(pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    if (child is not None and child[1] == child_group and child[2] == child_start
                            and child[3] not in {"Z", "X"}):
                        ci_floor._signal_utility_group_members(
                            child_group, {child_pid: child_start}, signal.SIGKILL,
                            deadline=time.monotonic() + 1.0,
                        )

    def test_stalled_nested_ps_escalates_term_ignorer_within_outer_cleanup_deadline(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            count_file = fake_bin / "ps-count"
            stall_file = fake_bin / "ps-stall-entered"
            script_entered_file = fake_bin / "ps-script-entered"
            stall_armed_file = fake_bin / "main-stall-armed"
            stall_consumed_file = fake_bin / "main-stall-consumed"
            main_snapshot_active_file = fake_bin / "main-snapshot-active"
            main_deadline_file = fake_bin / "main-deadline"
            stall_context_file = fake_bin / "main-stall-context"
            stall_invocation_stage_file = fake_bin / "main-stall-stage"
            prepare_file = fake_bin / "ps-prepare-entered"
            child_pid_file = root / "utility-pid"
            handler_ready_file = root / "term-handler-ready"
            term_file = root / "term-observed"
            fake_ps = fake_bin / "ps"
            fake_ps.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "open(os.path.join(os.path.dirname(__file__), 'ps-script-entered'), 'w').write('entered')\n"
                "import math, pathlib, stat, sys, time\n"
                "if sys.argv[1:] == ['--prepare-only']:\n"
                " time.sleep(.1)\n"
                " pathlib.Path(__file__).with_name('ps-prepare-entered').write_text('prepared')\n"
                " sys.exit(0)\n"
                "def publish(path, value):\n"
                " target = pathlib.Path(path)\n"
                " temporary = target.with_name(target.name + '.tmp')\n"
                " temporary.write_text(value)\n"
                " os.replace(temporary, target)\n"
                "counter = pathlib.Path(__file__).with_name('ps-count')\n"
                "count = int(counter.read_text() or '0') + 1 if counter.exists() else 1\n"
                "publish(counter, str(count))\n"
                "armed = pathlib.Path(__file__).with_name('main-stall-armed')\n"
                "active = pathlib.Path(__file__).with_name('main-snapshot-active')\n"
                "deadline_file = pathlib.Path(__file__).with_name('main-deadline')\n"
                "def bounded_ascii(path):\n"
                " descriptor = None\n"
                " try:\n"
                "  flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)\n"
                "  descriptor = os.open(path, flags)\n"
                "  if not stat.S_ISREG(os.fstat(descriptor).st_mode): return None\n"
                "  raw = os.read(descriptor, 33)\n"
                "  if len(raw) > 32: return None\n"
                "  return raw.decode('ascii')\n"
                " except (OSError, UnicodeError, ValueError):\n"
                "  return None\n"
                " finally:\n"
                "  if descriptor is not None:\n"
                "   try: os.close(descriptor)\n"
                "   except OSError: pass\n"
                "if armed.exists() and bounded_ascii(active) == 'main':\n"
                " try:\n"
                "  main_deadline = float(bounded_ascii(deadline_file) or '')\n"
                "  if not math.isfinite(main_deadline): main_deadline = 0.0\n"
                " except ValueError:\n"
                "  main_deadline = 0.0\n"
                " if time.monotonic() < main_deadline:\n"
                "  os.replace(armed, pathlib.Path(__file__).with_name('main-stall-consumed'))\n"
                "  publish(str(pathlib.Path(__file__).with_name('main-stall-context')), 'main_after_identity')\n"
                "  publish(str(pathlib.Path(__file__).with_name('main-stall-stage')), 'stalling')\n"
                "  publish(str(pathlib.Path(__file__).with_name('ps-stall-entered')), 'entered')\n"
                "  time.sleep(2)\n"
                "  publish(str(pathlib.Path(__file__).with_name('main-stall-stage')), 'delegating')\n"
                "os.execv('/bin/ps', ['/bin/ps', *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            os.chmod(fake_ps, 0o700)
            program = (
                "import json,os,pathlib,signal,subprocess,sys,time\n"
                "def publish(path, value):\n"
                " target=pathlib.Path(path); temporary=target.with_name(target.name+'.tmp')\n"
                " temporary.write_text(value); os.replace(temporary,target)\n"
                "pid=os.getpid(); term_file=pathlib.Path(sys.argv[2])\n"
                "def on_term(*_): publish(term_file, 'term')\n"
                "signal.signal(signal.SIGTERM,on_term)\n"
                "publish(sys.argv[3], 'ready')\n"
                "start=' '.join(subprocess.check_output(['/bin/ps','-o','lstart=','-p',str(pid)],text=True).split())\n"
                "publish(sys.argv[1], json.dumps([pid,os.getpgid(pid),start]))\n"
                "time.sleep(30)\n"
            )
            old_path = os.environ.get("PATH", "/usr/bin:/bin")
            started = time.monotonic()
            original_snapshot = ci_floor._utility_process_snapshot
            original_popen = ci_floor.subprocess.Popen
            snapshot_trace: list[dict[str, object]] = []
            signal_trace: list[dict[str, object]] = []
            exact_signal_identities: list[tuple[int, int, str, int]] = []
            probe_processes: list[tuple[object, float]] = []
            probe_snapshot_trace: list[dict[str, object]] = []
            snapshot_trace_omitted = 0
            signal_trace_omitted = 0
            exact_signal_identities_omitted = 0
            probe_snapshot_trace_omitted = 0
            probe_popen_attempted = False
            probe_popen_launch_failed = False
            probe_snapshot_diagnostic_failed = False
            probe_any_unreaped_boundary = False
            probe_any_unavailable_boundary = False
            probe_snapshot_trace_overflow = False
            probe_rescue_attempted = False
            probe_rescue_reaped = False
            probe_rescue_failed = False
            probe_rescue_deadline_expired = False
            probe_rescue_kill_failed = False
            exact_term_identity_seen = False
            active_signal_signum: int | None = None

            def safe_marker_file(path: pathlib.Path, allowed: set[str]) -> dict[str, object]:
                descriptor: int | None = None
                try:
                    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(path, flags)
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        return {"status": "not_regular"}
                    raw = os.read(descriptor, 33)
                except FileNotFoundError:
                    return {"status": "missing"}
                except (OSError, ValueError) as exc:
                    return {"status": "unavailable", "errorType": type(exc).__name__}
                finally:
                    if descriptor is not None:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                if len(raw) > 32:
                    return {"status": "too_long"}
                try:
                    value = raw.decode("ascii")
                except UnicodeError:
                    return {"status": "invalid"}
                if value not in allowed:
                    return {"status": "invalid"}
                return {"status": "read", "value": value}

            def append_snapshot_trace(item: dict[str, object]) -> None:
                nonlocal snapshot_trace_omitted
                if len(snapshot_trace) < 64:
                    snapshot_trace.append(item)
                else:
                    snapshot_trace_omitted += 1

            def append_signal_trace(item: dict[str, object]) -> None:
                nonlocal signal_trace_omitted
                if len(signal_trace) < 64:
                    signal_trace.append(item)
                else:
                    signal_trace_omitted += 1

            def append_exact_signal_identity(item: tuple[int, int, str, int]) -> None:
                nonlocal exact_signal_identities_omitted
                if len(exact_signal_identities) < 64:
                    exact_signal_identities.append(item)
                else:
                    exact_signal_identities_omitted += 1

            def probe_returncode_summary() -> dict[str, object]:
                total_handles = len(probe_processes)
                omitted = max(0, total_handles - 64)
                summary: dict[str, object] = {
                    "probeCount": min(total_handles, 64),
                    "omittedProbeHandles": min(omitted, 64),
                    "probeHandleOmissionOverflow": omitted > 64,
                    "returncodeKnownCount": 0,
                    "returncodeUnknownCount": 0,
                    "statusUnavailableCount": 0,
                    "ageBuckets": {"lt50ms": 0, "50to99ms": 0, "100to249ms": 0,
                                   "250to499ms": 0, "ge500ms": 0, "unavailable": 0},
                }
                try:
                    now = time.monotonic()
                    age_buckets = summary["ageBuckets"]
                    assert isinstance(age_buckets, dict)
                    for process, launched_at in probe_processes[:64]:
                        try:
                            known = process.returncode is not None  # Deliberately do not poll here.
                            key = "returncodeKnownCount" if known else "returncodeUnknownCount"
                            summary[key] = int(summary[key]) + 1
                        except Exception:
                            summary["statusUnavailableCount"] = int(summary["statusUnavailableCount"]) + 1
                        try:
                            age = max(0.0, now - launched_at)
                            bucket = (
                                "lt50ms" if age < 0.05 else "50to99ms" if age < 0.1
                                else "100to249ms" if age < 0.25 else "250to499ms" if age < 0.5
                                else "ge500ms"
                            )
                            age_buckets[bucket] = int(age_buckets[bucket]) + 1
                        except Exception:
                            age_buckets["unavailable"] = int(age_buckets["unavailable"]) + 1
                    summary["omittedProbeStatuses"] = min(omitted, 64)
                    summary["omittedProbeAgeBuckets"] = min(omitted, 64)
                    summary["probeStatusOmissionOverflow"] = omitted > 64
                except Exception:
                    probe_snapshot_diagnostic_failure()
                    return {
                        "probeCount": min(total_handles, 64),
                        "status": "unavailable",
                    }
                return summary

            def probe_snapshot_diagnostic_failure() -> None:
                nonlocal probe_snapshot_diagnostic_failed
                probe_snapshot_diagnostic_failed = True

            def append_probe_snapshot_boundary(context: str, outcome: str) -> None:
                nonlocal probe_snapshot_trace_omitted, probe_snapshot_trace_overflow
                nonlocal probe_any_unreaped_boundary, probe_any_unavailable_boundary
                try:
                    summary = probe_returncode_summary()
                    if (summary.get("status") == "unavailable"
                            or int(summary.get("statusUnavailableCount", 0)) > 0
                            or int(summary.get("omittedProbeStatuses", 0)) > 0
                            or bool(summary.get("probeStatusOmissionOverflow", False))):
                        probe_any_unavailable_boundary = True
                    if int(summary.get("returncodeUnknownCount", 0)) > 0:
                        probe_any_unreaped_boundary = True
                    item = {
                        "callContext": context,
                        "outcome": outcome,
                        **summary,
                    }
                    if len(probe_snapshot_trace) < 64:
                        probe_snapshot_trace.append(item)
                    else:
                        if probe_snapshot_trace_omitted < 64:
                            probe_snapshot_trace_omitted += 1
                        else:
                            probe_snapshot_trace_overflow = True
                except Exception:
                    probe_any_unavailable_boundary = True
                    probe_snapshot_diagnostic_failure()

            def record_probe_popen(*args: object, **kwargs: object) -> object:
                nonlocal probe_popen_attempted, probe_popen_launch_failed
                command = args[0] if args else kwargs.get("args")
                try:
                    executable = command[0] if isinstance(command, (list, tuple)) and command else None
                    selected_fixture = executable is not None and os.fspath(executable) == os.fspath(fake_ps)
                except (TypeError, ValueError, OSError):
                    selected_fixture = False
                if not selected_fixture:
                    return original_popen(*args, **kwargs)
                probe_popen_attempted = True
                launched_at = time.monotonic()
                try:
                    process = original_popen(*args, **kwargs)
                except BaseException:
                    probe_popen_launch_failed = True
                    raise
                # Retain the exact owned Popen handle for later observation and rescue.
                probe_processes.append((process, launched_at))
                return process

            def safe_count_file() -> dict[str, object]:
                descriptor: int | None = None
                try:
                    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(count_file, flags)
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        return {"status": "not_regular"}
                    raw = os.read(descriptor, 33)
                except FileNotFoundError:
                    return {"status": "missing"}
                except (OSError, ValueError) as exc:
                    return {"status": "unavailable", "errorType": type(exc).__name__}
                finally:
                    if descriptor is not None:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                if len(raw) > 32:
                    return {"status": "too_long"}
                if not raw or not raw.isdigit():
                    return {"status": "invalid"}
                return {"status": "read", "value": int(raw)}

            def safe_count_value() -> int | None:
                value = safe_count_file().get("value")
                return value if isinstance(value, int) else None

            def set_main_snapshot_gate(enabled: bool) -> bool:
                temporary = main_snapshot_active_file.with_name(main_snapshot_active_file.name + ".tmp")
                if not enabled:
                    try:
                        main_snapshot_active_file.unlink(missing_ok=True)
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        try:
                            stall_armed_file.unlink(missing_ok=True)
                        except OSError:
                            pass
                    return False
                try:
                    temporary.write_text("main", encoding="ascii")
                    os.replace(temporary, main_snapshot_active_file)
                    return True
                except OSError:
                    try:
                        stall_armed_file.unlink(missing_ok=True)
                    except OSError:
                        pass
                    return False

            def snapshot_context() -> str:
                if active_signal_signum == signal.SIGTERM:
                    return "term_inner_snapshot"
                if active_signal_signum == signal.SIGKILL:
                    return "kill_inner_snapshot"
                if active_signal_signum is not None:
                    return "signal_inner_snapshot"
                frame = sys._getframe(1)
                for _ in range(32):
                    if frame is None:
                        break
                    if frame.f_code is ci_floor._run.__code__:
                        if "cleanup_started" in frame.f_locals:
                            return "cleanup_snapshot"
                        if frame.f_locals.get("process") is None:
                            return "baseline_snapshot"
                        selector = frame.f_locals.get("selector")
                        if selector is None:
                            return "unknown_run_snapshot"
                        try:
                            return "main_loop_snapshot" if selector.get_map() else "before_reap_snapshot"
                        except Exception:
                            return "unknown_run_snapshot"
                    frame = frame.f_back
                return "outside_run"

            def fixture_identity_seen(records: dict[int, tuple[int, int, str, str]]) -> bool:
                if not child_pid_file.is_file():
                    return False
                try:
                    expected_pid, expected_group, expected_start = json.loads(child_pid_file.read_text(encoding="utf-8"))
                except (OSError, ValueError, TypeError):
                    return False
                record = records.get(expected_pid)
                return record is not None and record[1] == expected_group and record[2] == expected_start

            def diagnostic() -> str:
                return json.dumps({
                    "fixtureStages": {
                        "handlerReady": handler_ready_file.is_file(),
                        "identityPublished": child_pid_file.is_file(),
                        "fakePsScriptEntered": script_entered_file.is_file(),
                        "nestedPsStallEntered": stall_file.is_file(),
                        "mainStallArmed": stall_armed_file.is_file(),
                        "mainStallConsumed": stall_consumed_file.is_file(),
                        "mainSnapshotGate": safe_marker_file(
                            main_snapshot_active_file, {"main", "disabled"},
                        ),
                        "psInvocationCount": safe_count_file(),
                        "mainStallContext": safe_marker_file(
                            stall_context_file, {"main_after_identity"},
                        ),
                        "mainStallStage": safe_marker_file(
                            stall_invocation_stage_file, {"stalling", "delegating"},
                        ),
                    },
                    "snapshotCalls": snapshot_trace,
                    "omittedSnapshotCalls": snapshot_trace_omitted,
                    "signalCalls": signal_trace,
                    "omittedSignalCalls": signal_trace_omitted,
                    "exactSignalIdentityCount": len(exact_signal_identities),
                    "omittedExactSignalIdentities": exact_signal_identities_omitted,
                    "nestedFakePsPopen": {
                        "launchAttempted": probe_popen_attempted,
                        "launchFailed": probe_popen_launch_failed,
                        "capturedHandles": min(len(probe_processes), 64),
                        "omittedHandles": min(max(0, len(probe_processes) - 64), 64),
                        "handleOverflow": len(probe_processes) > 128,
                        "snapshotBoundaries": probe_snapshot_trace,
                        "omittedSnapshotBoundaries": probe_snapshot_trace_omitted,
                        "snapshotBoundaryOverflow": probe_snapshot_trace_overflow,
                        "diagnosticFailure": probe_snapshot_diagnostic_failed,
                        "anyUnreapedBoundary": probe_any_unreaped_boundary,
                        "anyUnavailableBoundary": probe_any_unavailable_boundary,
                        "finalReturncodeState": probe_returncode_summary(),
                        "rescue": {
                            "attempted": probe_rescue_attempted,
                            "reaped": probe_rescue_reaped,
                            "failed": probe_rescue_failed,
                            "deadlineExpired": probe_rescue_deadline_expired,
                            "killFailed": probe_rescue_kill_failed,
                        },
                    },
                }, sort_keys=True)

            def record_snapshot(*args: object, **kwargs: object) -> dict[int, tuple[int, int, str, str]]:
                entered = time.monotonic()
                ps_count_before = safe_count_value()
                timeout = kwargs.get("timeout", 2.0)
                deadline = kwargs.get("deadline")
                call_context = snapshot_context()
                main_context_active = False
                if call_context == "main_loop_snapshot" and isinstance(deadline, (int, float)):
                    try:
                        main_deadline_file.write_text(str(deadline), encoding="ascii")
                    except OSError:
                        pass
                    main_context_active = set_main_snapshot_gate(True)
                else:
                    set_main_snapshot_gate(False)
                item: dict[str, object] = {
                    "callContext": call_context,
                    "enteredOffsetSeconds": round(entered - started, 6),
                    "timeoutSeconds": timeout if isinstance(timeout, (int, float)) else "invalid",
                    "deadlineRemainingSeconds": round(deadline - entered, 6)
                    if isinstance(deadline, (int, float)) else None,
                    "fakePsInvocationCountBefore": ps_count_before,
                    "mainStallArmedBefore": stall_armed_file.is_file(),
                    "mainStallStageBefore": safe_marker_file(
                        stall_invocation_stage_file, {"stalling", "delegating"},
                    ),
                }
                try:
                    result = original_snapshot(*args, **kwargs)
                except BaseException as exc:
                    append_probe_snapshot_boundary(
                        call_context,
                        "exception_floor_input" if isinstance(exc, ci_floor.FloorInputError)
                        else "exception_other",
                    )
                    ps_count_after = safe_count_value()
                    stall_stage_after = safe_marker_file(
                        stall_invocation_stage_file, {"stalling", "delegating"},
                    )
                    if main_context_active:
                        set_main_snapshot_gate(False)
                    item.update({
                        "exitedOffsetSeconds": round(time.monotonic() - started, 6),
                        "outcome": "exception",
                        "exceptionType": type(exc).__name__,
                        "failureCategory": (
                            "snapshot_failed_during_armed_main_stall"
                            if isinstance(exc, ci_floor.FloorInputError)
                            and stall_stage_after.get("value") == "stalling"
                            and stall_context_file.is_file()
                            else "floor_input_error" if isinstance(exc, ci_floor.FloorInputError)
                            else "other_exception"
                        ),
                        "fakePsInvocationCountAfter": ps_count_after,
                        "mainStallArmedAfter": stall_armed_file.is_file(),
                        "mainStallStageAfter": stall_stage_after,
                        "fixtureIdentitySeen": False,
                    })
                    append_snapshot_trace(item)
                    raise
                append_probe_snapshot_boundary(call_context, "returned")
                ps_count_after = safe_count_value()
                stall_stage_after = safe_marker_file(
                    stall_invocation_stage_file, {"stalling", "delegating"},
                )
                identity_seen = fixture_identity_seen(result)
                if main_context_active:
                    set_main_snapshot_gate(False)
                    if identity_seen and not stall_consumed_file.exists():
                        try:
                            stall_armed_file.touch(exist_ok=False)
                        except FileExistsError:
                            pass
                        except OSError:
                            pass
                item.update({
                    "exitedOffsetSeconds": round(time.monotonic() - started, 6),
                    "outcome": "returned",
                    "failureCategory": "none",
                    "fakePsInvocationCountAfter": ps_count_after,
                    "mainStallArmedAfter": stall_armed_file.is_file(),
                    "mainStallStageAfter": stall_stage_after,
                    "fixtureIdentitySeen": identity_seen,
                })
                append_snapshot_trace(item)
                return result

            def rescue_probe_processes() -> None:
                nonlocal probe_rescue_attempted, probe_rescue_reaped
                nonlocal probe_rescue_failed, probe_rescue_deadline_expired
                nonlocal probe_rescue_kill_failed
                deadline = time.monotonic() + 0.25
                for process, _launched_at in probe_processes:
                    try:
                        if process.returncode is not None:
                            continue
                    except Exception:
                        probe_rescue_failed = True
                        continue
                    probe_rescue_attempted = True
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        probe_rescue_deadline_expired = True
                        probe_rescue_failed = True
                        continue
                    try:
                        process.kill()
                    except Exception:
                        probe_rescue_kill_failed = True
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        probe_rescue_deadline_expired = True
                        probe_rescue_failed = True
                        continue
                    try:
                        process.wait(timeout=remaining)
                        if process.returncode is not None:
                            probe_rescue_reaped = True
                        else:
                            probe_rescue_failed = True
                    except Exception:
                        probe_rescue_failed = True

            def any_unreaped_probe_handle() -> bool:
                for process, _launched_at in probe_processes:
                    try:
                        if process.returncode is None:
                            return True
                    except Exception:
                        return True
                return False

            original_signal = ci_floor._signal_utility_group_members

            def record_signal(
                group_id: int, identities: dict[int, str], signum: int, *, deadline: float,
            ) -> bool:
                nonlocal exact_term_identity_seen, active_signal_signum
                entered = time.monotonic()
                expected: tuple[int, int, str] | None = None
                if child_pid_file.is_file():
                    try:
                        expected = tuple(json.loads(child_pid_file.read_text(encoding="utf-8")))  # type: ignore[assignment]
                    except (OSError, ValueError, TypeError):
                        expected = None
                matched = bool(
                    expected is not None and expected[0] in identities
                    and expected[1] == group_id and identities.get(expected[0]) == expected[2]
                )
                for pid, started_at in identities.items():
                    append_exact_signal_identity((group_id, pid, started_at, signum))
                if signum == signal.SIGTERM and expected is not None:
                    exact_term_identity_seen = any(
                        group_id == expected[1] and pid == expected[0]
                        and started_at == expected[2]
                        for pid, started_at in identities.items()
                    ) or exact_term_identity_seen
                prior_signal = active_signal_signum
                active_signal_signum = signum
                try:
                    try:
                        result = original_signal(group_id, identities, signum, deadline=deadline)
                    except BaseException as exc:
                        append_signal_trace({
                            "enteredOffsetSeconds": round(entered - started, 6),
                            "exitedOffsetSeconds": round(time.monotonic() - started, 6),
                            "signum": signum,
                            "identityCount": len(identities),
                            "fixtureIdentityMatched": matched,
                            "deadlineRemainingSeconds": round(deadline - entered, 6),
                            "outcome": "exception",
                            "exceptionType": type(exc).__name__,
                            "failureCategory": "signal_helper_exception",
                        })
                        raise
                    append_signal_trace({
                        "enteredOffsetSeconds": round(entered - started, 6),
                        "exitedOffsetSeconds": round(time.monotonic() - started, 6),
                        "signum": signum,
                        "identityCount": len(identities),
                        "fixtureIdentityMatched": matched,
                        "deadlineRemainingSeconds": round(deadline - entered, 6),
                        "outcome": "returned",
                        "result": result,
                        "failureCategory": (
                            "matched_identity_signal_not_confirmed"
                            if matched and not result else "fixture_identity_not_matched"
                            if not matched else "none"
                        ),
                    })
                    return result
                finally:
                    active_signal_signum = prior_signal

            preparation = ci_floor._run([str(fake_ps), "--prepare-only"], timeout=2.0)
            self.assertEqual(preparation.returncode, 0, "fake ps prepare-only run must exit cleanly: " + diagnostic())
            self.assertTrue(prepare_file.is_file(), "fake ps preflight must reach post-import preparation: " + diagnostic())
            fixture_state_files = (
                count_file, stall_file, script_entered_file, stall_armed_file, stall_consumed_file,
                main_snapshot_active_file, main_deadline_file, stall_context_file,
                stall_invocation_stage_file, prepare_file, child_pid_file,
                handler_ready_file, term_file,
            )
            for marker in fixture_state_files:
                marker.unlink(missing_ok=True)
                marker.with_name(marker.name + ".tmp").unlink(missing_ok=True)
            self.assertFalse(any(marker.exists() for marker in fixture_state_files))
            started = time.monotonic()

            try:
                with mock.patch.dict(os.environ, {"PATH": f"{fake_bin}{os.pathsep}{old_path}"}), \
                        mock.patch.object(ci_floor, "UTILITY_CLEANUP_SECONDS", 0.8), \
                        mock.patch.object(ci_floor, "UTILITY_TERM_GRACE_SECONDS", 0.2), \
                        mock.patch.object(ci_floor, "UTILITY_KILL_SIGNAL_RESERVE_SECONDS", 0.15), \
                        mock.patch.object(ci_floor, "UTILITY_LEADER_REAP_RESERVE_SECONDS", 0.15), \
                        mock.patch.object(ci_floor, "UTILITY_FINAL_SCAN_RESERVE_SECONDS", 0.1), \
                        mock.patch.object(ci_floor, "_utility_process_snapshot", side_effect=record_snapshot), \
                        mock.patch.object(ci_floor, "_signal_utility_group_members", side_effect=record_signal), \
                        mock.patch.object(ci_floor.subprocess, "Popen", side_effect=record_probe_popen):
                    try:
                        ci_floor._run(
                            [sys.executable, "-c", program, str(child_pid_file), str(term_file), str(handler_ready_file)],
                            timeout=0.6,
                        )
                    except ci_floor.FloorInputError:
                        pass
                    except Exception as exc:
                        self.fail("stalled nested ps raised " + type(exc).__name__ + ": " + diagnostic())
                    else:
                        self.fail("stalled nested ps must fail closed: " + diagnostic())
                self.assertTrue(handler_ready_file.is_file(), "child must install TERM handler before supervision: " + diagnostic())
                self.assertTrue(child_pid_file.is_file(), "utility child must publish its process identity: " + diagnostic())
                self.assertTrue(script_entered_file.is_file(), "fake ps must reach its first statement: " + diagnostic())
                self.assertTrue(
                    stall_file.is_file() and stall_consumed_file.is_file()
                    and safe_marker_file(stall_context_file, {"main_after_identity"}).get("value") == "main_after_identity",
                    "the armed one-shot stall must occur in a main snapshot after the real child identity is observed: "
                    + diagnostic(),
                )
                self.assertTrue(probe_popen_attempted, "the real fake-ps helper must be captured: " + diagnostic())
                self.assertFalse(probe_popen_launch_failed, "fake-ps Popen must launch cleanly: " + diagnostic())
                self.assertTrue(probe_processes, "each successful fixture helper launch must retain its exact Popen handle")
                self.assertFalse(probe_snapshot_diagnostic_failed, "helper lifecycle diagnostics must remain available: " + diagnostic())
                self.assertFalse(
                    probe_any_unreaped_boundary,
                    "every wrapped snapshot boundary must observe only already-recorded helper return codes: "
                    + diagnostic(),
                )
                self.assertFalse(
                    probe_any_unavailable_boundary,
                    "every wrapped snapshot boundary must include lifecycle status for every captured helper: "
                    + diagnostic(),
                )
                self.assertFalse(
                    any_unreaped_probe_handle(),
                    "every nested fake-ps Popen must already have a recorded return code before fixture success: "
                    + diagnostic(),
                )
                self.assertGreaterEqual(int(safe_count_file().get("value", 0)), 3, diagnostic())
                self.assertLess(time.monotonic() - started, 1.8, diagnostic())
                self.assertTrue(term_file.is_file(), "the owned term-ignorer must receive TERM before KILL: " + diagnostic())
                child_pid, child_group, child_start = json.loads(child_pid_file.read_text(encoding="utf-8"))
                self.assertTrue(exact_term_identity_seen,
                                "TERM wrapper must observe the exact published PID/group/start tuple: " + diagnostic())
                snapshot = ci_floor._utility_process_snapshot()
                child = snapshot.get(child_pid)
                child_is_live = (
                    child is not None and child[1] == child_group and child[2] == child_start
                    and child[3] not in {"Z", "X"}
                )
                self.assertFalse(child_is_live, "the outer supervisor left its utility child alive: " + diagnostic())
            finally:
                rescue_probe_processes()
                if probe_rescue_failed:
                    self.addCleanup(
                        self.fail,
                        "owned nested fake-ps helper cleanup was not confirmed within the shared rescue deadline: "
                        + diagnostic(),
                    )
                if child_pid_file.is_file():
                    child_pid, child_group, child_start = json.loads(child_pid_file.read_text(encoding="utf-8"))
                    snapshot = ci_floor._utility_process_snapshot()
                    child = snapshot.get(child_pid)
                    if (child is not None and child[1] == child_group and child[2] == child_start
                            and child[3] not in {"Z", "X"}):
                        ci_floor._signal_utility_group_members(
                            child_group, {child_pid: child_start}, signal.SIGKILL,
                            deadline=time.monotonic() + 1.0,
                        )

    def test_run_rechecks_deadline_after_main_snapshot_before_selector_wait(self) -> None:
        class Clock:
            now = 0.0

        clock = Clock()
        identities: dict[int, tuple[int, int, str, str]] = {}

        class Stream:
            def __init__(self, fd: int) -> None:
                self.fd = fd

            def fileno(self) -> int:
                return self.fd

            def close(self) -> None:
                pass

        class Process:
            pid = 41001
            stdout = Stream(101)
            stderr = Stream(102)

            def __init__(self) -> None:
                self.returncode: int | None = None
                self.wait_calls: list[float | None] = []

            def poll(self) -> int | None:
                return self.returncode

            def kill(self) -> None:
                self.returncode = -signal.SIGKILL

            def wait(self, timeout: float | None = None) -> int:
                self.wait_calls.append(timeout)
                if self.returncode is None:
                    self.returncode = -signal.SIGKILL
                return self.returncode

        class Selector:
            def __init__(self) -> None:
                self.entries: dict[object, object] = {}
                self.select_calls: list[float] = []

            def register(self, stream: object, _events: int, data: str) -> None:
                self.entries[stream] = type("Key", (), {"fileobj": stream, "data": data})()

            def unregister(self, stream: object) -> None:
                self.entries.pop(stream, None)

            def get_map(self) -> dict[object, object]:
                return self.entries

            def select(self, timeout: float) -> list[tuple[object, int]]:
                self.select_calls.append(timeout)
                return []

            def close(self) -> None:
                pass

        process = Process()
        selector = Selector()
        snapshot_count = 0
        snapshot_phases: dict[str, int] = {}

        def current_snapshot_phase() -> str:
            frame = sys._getframe(1)
            for _ in range(32):
                if frame is None:
                    break
                if frame.f_code is ci_floor._run.__code__:
                    if "cleanup_started" in frame.f_locals:
                        return "cleanup"
                    if frame.f_locals.get("process") is None:
                        return "baseline"
                    run_selector = frame.f_locals.get("selector")
                    if run_selector is None:
                        return "unknown"
                    try:
                        return "main_loop" if run_selector.get_map() else "before_reap"
                    except Exception:
                        return "unknown"
                frame = frame.f_back
            return "outside_run"

        def snapshot(*_args: object, **_kwargs: object) -> dict[int, tuple[int, int, str, str]]:
            nonlocal snapshot_count
            snapshot_count += 1
            phase = current_snapshot_phase()
            snapshot_phases[phase] = snapshot_phases.get(phase, 0) + 1
            if snapshot_count == 2:
                clock.now += 0.05  # A blocking main snapshot consumes the whole 0.04 s budget.
            return identities

        with mock.patch.object(ci_floor.time, "monotonic", side_effect=lambda: clock.now), \
                mock.patch.object(ci_floor, "_utility_process_snapshot", side_effect=snapshot), \
                mock.patch.object(ci_floor.subprocess, "Popen", return_value=process), \
                mock.patch.object(ci_floor.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(ci_floor.os, "set_blocking"), \
                mock.patch.object(ci_floor.os, "read", return_value=b""), \
                mock.patch.object(ci_floor.os, "kill") as os_kill, \
                mock.patch.object(ci_floor.os, "killpg") as os_killpg, \
                mock.patch.object(ci_floor, "_signal_utility_group_members") as signal_group:
            with self.assertRaises(ci_floor.FloorInputError):
                ci_floor._run(["synthetic"], timeout=0.04)

        self.assertEqual(snapshot_phases, {"baseline": 1, "main_loop": 1, "cleanup": 1})
        self.assertEqual(snapshot_count, sum(snapshot_phases.values()))
        self.assertFalse(selector.select_calls, "an expired main snapshot must not be followed by selector waiting")
        self.assertTrue(process.wait_calls, "cleanup must reap the synthetic Popen-like child")
        signal_group.assert_not_called()
        os_kill.assert_not_called()
        os_killpg.assert_not_called()

    def test_run_rechecks_deadline_after_before_reap_snapshot_before_wait(self) -> None:
        class Clock:
            now = 0.0

        clock = Clock()
        process_pid = 41002
        identity = {process_pid: (1, process_pid, "synthetic-start", "S")}

        class Stream:
            def __init__(self, fd: int) -> None:
                self.fd = fd

            def fileno(self) -> int:
                return self.fd

            def close(self) -> None:
                pass

        class Process:
            pid = process_pid
            stdout = Stream(201)
            stderr = Stream(202)

            def __init__(self) -> None:
                self.returncode: int | None = None
                self.main_wait_calls: list[float | None] = []
                self.cleanup_wait_calls: list[float | None] = []

            def poll(self) -> int | None:
                return self.returncode

            def kill(self) -> None:
                self.returncode = -signal.SIGKILL

            def wait(self, timeout: float | None = None) -> int:
                frame = sys._getframe(1)
                while frame is not None and frame.f_code is not ci_floor._run.__code__:
                    frame = frame.f_back
                target = self.cleanup_wait_calls if frame is not None and "cleanup_started" in frame.f_locals else self.main_wait_calls
                target.append(timeout)
                if self.returncode is None:
                    self.returncode = 0
                return self.returncode

        class Selector:
            def __init__(self) -> None:
                self.entries: dict[object, object] = {}

            def register(self, stream: object, _events: int, data: str) -> None:
                self.entries[stream] = type("Key", (), {"fileobj": stream, "data": data})()

            def unregister(self, stream: object) -> None:
                self.entries.pop(stream, None)

            def get_map(self) -> dict[object, object]:
                return self.entries

            def select(self, _timeout: float) -> list[tuple[object, int]]:
                return [(key, ci_floor.selectors.EVENT_READ) for key in self.entries.values()]

            def close(self) -> None:
                pass

        process = Process()
        selector = Selector()
        snapshot_count = 0
        snapshot_phases: dict[str, int] = {}

        def current_snapshot_phase() -> str:
            frame = sys._getframe(1)
            for _ in range(32):
                if frame is None:
                    break
                if frame.f_code is ci_floor._run.__code__:
                    if "cleanup_started" in frame.f_locals:
                        return "cleanup"
                    if frame.f_locals.get("process") is None:
                        return "baseline"
                    run_selector = frame.f_locals.get("selector")
                    if run_selector is None:
                        return "unknown"
                    try:
                        return "main_loop" if run_selector.get_map() else "before_reap"
                    except Exception:
                        return "unknown"
                frame = frame.f_back
            return "outside_run"

        def snapshot(*_args: object, **_kwargs: object) -> dict[int, tuple[int, int, str, str]]:
            nonlocal snapshot_count
            snapshot_count += 1
            phase = current_snapshot_phase()
            snapshot_phases[phase] = snapshot_phases.get(phase, 0) + 1
            if snapshot_count == 1:
                return {}
            if snapshot_count in {2, 3}:
                if snapshot_count == 3:
                    clock.now += 0.05  # The before-reap snapshot consumes the remaining 0.04 s.
                return identity
            return {}

        with mock.patch.object(ci_floor.time, "monotonic", side_effect=lambda: clock.now), \
                mock.patch.object(ci_floor, "_utility_process_snapshot", side_effect=snapshot), \
                mock.patch.object(ci_floor.subprocess, "Popen", return_value=process), \
                mock.patch.object(ci_floor.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(ci_floor.os, "set_blocking"), \
                mock.patch.object(ci_floor.os, "read", return_value=b""), \
                mock.patch.object(ci_floor.os, "kill") as os_kill, \
                mock.patch.object(ci_floor.os, "killpg") as os_killpg, \
                mock.patch.object(ci_floor, "_signal_utility_group_members", return_value=True) as signal_group:
            with self.assertRaises(ci_floor.FloorInputError):
                ci_floor._run(["synthetic"], timeout=0.04)

        self.assertEqual(snapshot_phases, {
            "baseline": 1, "main_loop": 1, "before_reap": 1, "cleanup": 2,
        })
        self.assertEqual(snapshot_count, sum(snapshot_phases.values()))
        self.assertFalse(process.main_wait_calls, "an expired before-reap snapshot must not reach main process.wait")
        self.assertTrue(process.cleanup_wait_calls, "cleanup must reap the synthetic Popen-like child")
        self.assertTrue(signal_group.called, "cleanup may request identity-checked signaling through the mocked helper")
        os_kill.assert_not_called()
        os_killpg.assert_not_called()

    def test_stalled_cleanup_discovery_preserves_reserved_phases_and_stops_owned_child(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            count_file = fake_bin / "ps-count"
            stall_file = fake_bin / "discovery-stall"
            identity_file = root / "utility-identity"
            fake_ps = fake_bin / "ps"
            fake_ps.write_text(
                f"#!{sys.executable}\n"
                "import os, pathlib, sys, time\n"
                "counter = pathlib.Path(__file__).with_name('ps-count')\n"
                "count = int(counter.read_text() or '0') + 1 if counter.exists() else 1\n"
                "counter.write_text(str(count))\n"
                "if count == 2:\n"
                " pathlib.Path(__file__).with_name('discovery-stall').write_text('entered')\n"
                " time.sleep(2)\n"
                "os.execv('/bin/ps', ['/bin/ps', *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            os.chmod(fake_ps, 0o700)
            program = (
                "import json,os,pathlib,subprocess,sys,time; pid=os.getpid(); "
                "start=' '.join(subprocess.check_output(['/bin/ps','-o','lstart=','-p',str(pid)],text=True).split()); "
                "identity=pathlib.Path(sys.argv[1]); temporary=identity.with_name(identity.name+'.tmp'); "
                "temporary.write_text(json.dumps([pid,os.getpgid(pid),start])); os.replace(temporary,identity); time.sleep(30)"
            )
            old_path = os.environ.get("PATH", "/usr/bin:/bin")
            original_snapshot = ci_floor._utility_process_snapshot
            snapshot_calls = 0
            identity_handshakes: list[float] = []
            cleanup_started: list[float] = []
            cleanup_finished: list[float] = []
            discovery_calls: list[tuple[float, float, float]] = []

            def fail_main_probe_then_stall_discovery(
                *, timeout: float = 2.0, deadline: float | None = None,
            ) -> dict[int, tuple[int, int, str, str]]:
                nonlocal snapshot_calls
                snapshot_calls += 1
                if snapshot_calls == 2:
                    handshake_deadline = time.monotonic() + 0.5
                    while not identity_file.is_file() and time.monotonic() < handshake_deadline:
                        time.sleep(0.01)
                    if not identity_file.is_file():
                        raise ci_floor.FloorInputError
                    child_pid, child_group, child_start = json.loads(identity_file.read_text(encoding="utf-8"))
                    if child_pid <= 0 or child_group <= 0 or not child_start:
                        raise ci_floor.FloorInputError
                    identity_handshakes.append(time.monotonic())
                    raise ci_floor.FloorInputError
                if snapshot_calls == 3:
                    entered = time.monotonic()
                    cleanup_started.append(entered)
                    if deadline is None:
                        raise ci_floor.FloorInputError
                    discovery_calls.append((entered, timeout, deadline))
                    try:
                        return original_snapshot(timeout=timeout, deadline=deadline)
                    finally:
                        cleanup_finished.append(time.monotonic())
                return original_snapshot(timeout=timeout, deadline=deadline)

            real_signal = ci_floor._signal_utility_group_members
            observed_signals: list[tuple[int, int]] = []

            def record_signal(
                group_id: int, identities: dict[int, str], signum: int, *, deadline: float,
            ) -> bool:
                observed_signals.extend((pid, signum) for pid in identities)
                return real_signal(group_id, identities, signum, deadline=deadline)

            try:
                run_started = time.monotonic()
                with mock.patch.dict(os.environ, {"PATH": f"{fake_bin}{os.pathsep}{old_path}"}), \
                        mock.patch.object(ci_floor, "_utility_process_snapshot", side_effect=fail_main_probe_then_stall_discovery), \
                        mock.patch.object(ci_floor, "_signal_utility_group_members", side_effect=record_signal):
                    with self.assertRaises(ci_floor.FloorInputError):
                        ci_floor._run([sys.executable, "-c", program, str(identity_file)], timeout=2.0)
                run_elapsed = time.monotonic() - run_started

                self.assertEqual(snapshot_calls, 3, "the injected main and discovery stages must be reached")
                self.assertEqual(len(identity_handshakes), 1, "main-probe failure must follow the child identity handshake")
                self.assertEqual(len(cleanup_started), 1)
                self.assertEqual(len(cleanup_finished), 1)
                cleanup_elapsed = cleanup_finished[0] - cleanup_started[0]
                self.assertLessEqual(
                    cleanup_elapsed,
                    ci_floor.UTILITY_CLEANUP_SECONDS + 0.25,
                    "stalled cleanup discovery must fit inside the composed cleanup deadline",
                )
                self.assertLessEqual(
                    run_elapsed,
                    cleanup_started[0] - run_started + ci_floor.UTILITY_CLEANUP_SECONDS + 0.25,
                    "the bounded identity handshake must be accounted for before cleanup starts",
                )
                self.assertTrue(stall_file.is_file(), "the cleanup-discovery ps fixture must stall")
                self.assertEqual(observed_signals, [], "unconfirmed process identities must never be signaled")
                self.assertEqual(len(discovery_calls), 1)
                entered, timeout, discovery_deadline = discovery_calls[0]
                remaining = discovery_deadline - entered
                reserved_after_discovery = (
                    ci_floor.UTILITY_TERM_GRACE_SECONDS
                    + ci_floor.UTILITY_KILL_SIGNAL_RESERVE_SECONDS
                    + ci_floor.UTILITY_LEADER_REAP_RESERVE_SECONDS
                    + ci_floor.UTILITY_FINAL_SCAN_RESERVE_SECONDS
                )
                self.assertGreater(remaining, 0)
                self.assertLessEqual(timeout, 0.5)
                self.assertLessEqual(
                    discovery_deadline,
                    entered + timeout + 0.02,
                    "the nested ps cleanup must use the bounded discovery subdeadline",
                )
                self.assertLessEqual(
                    remaining + reserved_after_discovery,
                    ci_floor.UTILITY_CLEANUP_SECONDS,
                    "the nested discovery deadline must preserve later cleanup phases",
                )
                self.assertTrue(identity_file.is_file(), "utility child must publish its identity")
                child_pid, child_group, child_start = json.loads(identity_file.read_text(encoding="utf-8"))
                snapshot = original_snapshot()
                child = snapshot.get(child_pid)
                self.assertIsNone(child, "the direct Popen child must be reaped before the fixture fallback")
            finally:
                if identity_file.is_file():
                    child_pid, child_group, child_start = json.loads(identity_file.read_text(encoding="utf-8"))
                    snapshot = original_snapshot()
                    child = snapshot.get(child_pid)
                    if (child is not None and child[1] == child_group and child[2] == child_start
                            and child[3] not in {"Z", "X"}):
                        ci_floor._signal_utility_group_members(
                            child_group, {child_pid: child_start}, signal.SIGKILL,
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


class CiFloorFailureReasonTests(unittest.TestCase):
    def test_linux_kernel_threads_with_group_zero_are_valid_snapshot_rows(self) -> None:
        raw = (
            b"    1     0     1 Sun Oct  4 16:20:29 2026 Ss\n"
            b"    2     0     0 Sun Oct  4 16:20:29 2026 S\n"
            b"    3     2     0 Sun Oct  4 16:20:29 2026 I<\n"
            b"  101     1   101 Sun Oct  4 16:20:30 2026 Z+\n"
        )
        records = ci_floor._parse_utility_snapshot(raw)
        self.assertEqual(records[2][:2], (0, 0))
        self.assertEqual(records[3][3], "I")
        self.assertEqual(sorted(records), [1, 2, 3, 101])

    def test_malformed_snapshot_rows_still_fail_with_a_fixed_reason(self) -> None:
        cases = {
            "snapshot-line-shape": b"1 0 1 short\n",
            "snapshot-identity-values": b"0 0 1 Sun Oct  4 16:20:29 2026 S\n",
            "snapshot-empty": b"\n",
            "snapshot-not-ascii": "1 0 1 Sun Oct  4 16:20:29 2026 é\n".encode(),
        }
        for reason, raw in cases.items():
            with self.subTest(reason), self.assertRaises(ci_floor.FloorInputError) as caught:
                ci_floor._parse_utility_snapshot(raw)
            self.assertEqual(caught.exception.reason, reason)
        duplicate = b"5 0 1 Sun Oct  4 16:20:29 2026 S\n5 0 1 Sun Oct  4 16:20:29 2026 S\n"
        with self.assertRaises(ci_floor.FloorInputError):
            ci_floor._parse_utility_snapshot(duplicate)

    def test_main_failure_message_carries_a_non_secret_reason_code(self) -> None:
        secret = "SECRET-CANARY-VALUE"

        def failing(_args: object) -> int:
            raise ci_floor.FloorInputError("snapshot-line-shape")

        argv = ["ci_floor", "prepare-private-root", "--root", f"/{secret}"]
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(ci_floor, "_prepare_private_root", side_effect=failing), \
                mock.patch("sys.stderr", stderr):
            code = ci_floor.main()
        self.assertEqual(code, 1)
        message = stderr.getvalue()
        self.assertIn("release floor: preflight or receipt processing failed (reason: FloorInputError/snapshot-line-shape", message)
        self.assertNotIn(secret, message)

    def test_reason_code_names_class_and_site_without_message_text(self) -> None:
        try:
            raise OSError("/home/owner/secret/path token=abc")
        except OSError as exc:
            reason = ci_floor._failure_reason(exc)
        self.assertEqual(reason.split("/")[0], "OSError")
        self.assertNotIn("secret", reason)
        self.assertNotIn("token", reason)

    def test_successful_settle_report_requires_clean_probe_and_union_evidence(self) -> None:
        base = {
            "eligible": True, "settled": True,
            "initialIdentities": [{"pid": 41001, "startedAt": "s", "observedParentPid": 1,
                                   "descriptorStatus": "uninspectable", "reason": "r"}],
            "initialCandidateCount": 1, "latestIdentities": [], "latestCandidateCount": 0,
            "waitSeconds": 120.0004, "settleWindowSeconds": 120.0, "deadlineRemainingSeconds": 0.0,
            "pollCount": 2, "globalRescanCount": 3, "error": None, "identityUnion": [],
            "identityUnionCount": 1, "identityUnionTruncated": False, "ownedProbeProcesses": [],
            "ownedProbeProcessCount": 0, "cleanupExceptions": [], "cleanupExceptionCount": 0,
            "probeEvidenceTruncated": False,
        }
        self.assertTrue(ci_floor._successful_settle_report(base), "a legitimate 120.0004 s success is valid")
        invalid = {
            "too slow": {"waitSeconds": 122.0},
            "probe": {"ownedProbeProcessCount": 1, "ownedProbeProcesses": [{"pid": 1}]},
            "cleanup exception": {"cleanupExceptionCount": 1, "cleanupExceptions": [{"type": "X"}]},
            "union truncated": {"identityUnionTruncated": True},
            "probe truncated": {"probeEvidenceTruncated": True},
            "union below initial": {"identityUnionCount": 0},
            "compacted": {"evidenceListsCompacted": True},
            "missing probe fields": {"ownedProbeProcessCount": None},
        }
        for name, change in invalid.items():
            with self.subTest(name):
                self.assertFalse(ci_floor._successful_settle_report({**base, **change}))
