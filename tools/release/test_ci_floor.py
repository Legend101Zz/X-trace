from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

from tools.release import ci_floor, private_roots, run_gates


class CiFloorEvidenceTests(unittest.TestCase):
    source_sha = "a" * 40
    phase_base = "b" * 40
    digest = "c" * 64

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
            "suiteModules": list(ci_floor.RELEASE_TEST_MODULES),
            "status": "passed",
            "discoveredCount": 2,
            "testCount": 2,
            "failedCount": 0,
            "skippedCount": 0,
            "tests": [
                {"name": "tools.release.test_release_tools.Public.test_ok", "status": "passed"},
                {"name": "tools.release.test_ci_floor.Public.test_ok", "status": "passed"},
            ],
            "privateNote": "PRIVATE_TEST_CANARY_4c7f",
        }
        receipt = self._passing_receipt(label)
        receipt["privateNote"] = "PRIVATE_RECEIPT_CANARY_5a31"
        receipt["gates"][0]["argv"] = ["PRIVATE_ARGV_CANARY_9f02"]
        output: list[bytes] = []

        def read(path: pathlib.Path, **kwargs: object):
            if path.name == "release-tool-tests-summary.json":
                return tests
            return receipt

        args = Namespace(
            root="/synthetic/private-root", label=label, expected_head=self.source_sha,
            phase_base=self.phase_base, tuple="jdk17-node22",
        )
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 0)
        self.assertEqual(len(output), 1)
        public = json.loads(output[0])
        self.assertEqual(public["floorStatus"], "checks_passed_for_review")
        rendered = output[0].decode()
        for canary in ("PRIVATE_TEST_CANARY_4c7f", "PRIVATE_RECEIPT_CANARY_5a31", "PRIVATE_ARGV_CANARY_9f02"):
            self.assertNotIn(canary, rendered)
        self.assertEqual(public["gateCount"], 23)
        self.assertFalse(public["releaseAcceptance"])

        tests["sourceSha"] = self.phase_base
        output.clear()
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 1)
        self.assertNotEqual(json.loads(output[0])["floorStatus"], "checks_passed_for_review")

    def test_sanitizer_rejects_unreached_gate_rows_and_mismatched_identity(self) -> None:
        label = "floor-123456-1-jdk21-node24"
        tests = {
            "schemaVersion": 1,
            "sourceSha": self.source_sha,
            "sourceIdentityVerified": True,
            "suiteModules": list(ci_floor.RELEASE_TEST_MODULES),
            "status": "passed",
            "discoveredCount": 1,
            "testCount": 1,
            "failedCount": 0,
            "skippedCount": 0,
            "tests": [{"name": "tools.release.test_ci_floor.Public.test_ok", "status": "passed"}],
        }
        receipt = self._passing_receipt(label)
        receipt["phaseDiffSha256After"] = "d" * 64
        receipt["gates"][-1]["status"] = "unreached"
        output: list[bytes] = []

        def read(path: pathlib.Path, **kwargs: object):
            return tests if path.name == "release-tool-tests-summary.json" else receipt

        args = Namespace(
            root="/synthetic/private-root", label=label, expected_head=self.source_sha,
            phase_base=self.phase_base, tuple="jdk21-node24",
        )
        with mock.patch.object(ci_floor.private_roots, "admit_directory"), \
                mock.patch.object(ci_floor.private_roots, "read_private_json", side_effect=read), \
                mock.patch.object(ci_floor.private_roots, "atomic_write_private", side_effect=lambda _path, data: output.append(data)):
            self.assertEqual(ci_floor._sanitize_floor(args), 1)
        public = json.loads(output[0])
        self.assertNotEqual(public["floorStatus"], "checks_passed_for_review")
        self.assertEqual(public["floorStatus"], "invalid")
        self.assertEqual(public["gateCount"], 23)

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
            "toolVersions": {name: "public-version" for name, _argv, _cwd in run_gates.VERSION_COMMANDS},
            "platform": {"system": "Linux", "release": "public-release", "machine": "x86_64"},
            "gates": [{
                "name": gate.name,
                "argv": list(gate.argv),
                "cwd": gate.cwd,
                "exitCode": 0,
                "durationSeconds": 0.25,
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
