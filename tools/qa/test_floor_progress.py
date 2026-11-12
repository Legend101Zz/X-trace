import argparse
import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.qa import floor_progress, lane_run, release_floor, rust_timing
from tools.release import ci_floor, private_roots, run_gates
from tools.release.test_release_tools import own_process_snapshot


class FloorProgressTests(unittest.TestCase):
    def setUp(self):
        # Match the runner's private ancestry requirements even without a CI scratch override.
        scratch = os.environ.get("XTRACE_TEST_SCRATCH_ROOT") or pathlib.Path(__file__).resolve().parents[2]
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.repo = self.root / "repo"
        self.args = argparse.Namespace(root=self.root, repo=self.repo, label="floor-1-1-jdk17-node22",
                                       tuple="jdk17-node22")
        self.run_dir = self.root / "release-gates" / self.args.label
        self.run_dir.mkdir(parents=True, mode=0o700)
        self.checkpoint = self.run_dir / floor_progress.CHECKPOINT_NAME
        self.writer = floor_progress.GateCheckpoint()
        sources = {
            "crates/example/Cargo.toml": '[package]\nname = "example-crate"\n',
            "crates/example/src/lib.rs": "mod tests {\n#[test]\nfn waiting() {}\n"
                                         "#[test]\nfn canary_case() {}\n}\n",
            "crates/xtrace-cli/Cargo.toml": '[package]\nname = "xtrace-cli"\n',
            "crates/xtrace-cli/tests/java_premain_spring.rs": f"#[test]\nfn {lane_run.SPRING_ORDER_WAIT_TEST}() {{}}\n",
            "Cargo.lock": "cargo fixture\n",
            "adapters/java/gradle.lockfile": "gradle fixture\n",
            "adapters/node/package-lock.json": "{}\n",
            "web/app/package-lock.json": "{}\n",
        }
        for name, contents in sources.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_COMMITTER_NAME": "Fixture",
               "GIT_AUTHOR_EMAIL": "fixture@example.test", "GIT_COMMITTER_EMAIL": "fixture@example.test"}
        for command in (("init",), ("add", "."), ("commit", "-m", "Fixture")):
            subprocess.run(["git", "-C", str(self.repo), *command], env=env, check=True, capture_output=True)
        head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.args.expected_head = self.args.phase_base = head
        self.proof = {key: value for key, value in ci_floor._source_proofs(self.repo, head, head).items()
                      if key in floor_progress.SOURCE_FIELDS}
        self.test_id = "tools.release.test_release_tools.Fixture.test_passed"
        self.write_json(self.root / "release-tool-tests-summary.json", {
            "schemaVersion": 1, "suiteModules": list(ci_floor.RELEASE_TEST_MODULES),
            "sourceSha": head, "sourceIdentityVerified": True, "testScratchAdmissionVerified": True,
            "testCount": 1, "discoveredCount": 1, "failedCount": 0, "skippedCount": 0, "status": "passed",
            "tests": [{"name": self.test_id, "status": "passed"}],
        })
        self.write_json(self.run_dir / "receipt.json", {
            "decision": "running", "gates": [{"name": ci_floor.EXPECTED_GATE_NAMES[0], "status": "passed"}],
        })

    @staticmethod
    def write_json(path, value):
        private_roots.atomic_write_private(path, json.dumps(value).encode())

    def observe(self, gate, *states):
        for state in states:
            self.writer(self.run_dir, gate, state, self.proof)

    def sanitize(self, *, floor_status="invalid"):
        with mock.patch.object(ci_floor, "_discover_release_test_ids", return_value=[self.test_id]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci_floor._sanitize_floor(self.args), 1)
        summary = json.loads((self.root / "release-floor-summary.json").read_text())
        self.assertEqual((summary["floorStatus"], summary["gateCount"], summary["gates"]), (floor_status, 0, []))
        self.assertFalse(summary["releaseAcceptance"])
        return summary

    def start_rust_gate(self):
        gate = "rust-focused"
        for previous in ci_floor.EXPECTED_GATE_NAMES[:ci_floor.EXPECTED_GATE_NAMES.index(gate)]:
            self.observe(previous, "selected", "started", "completed")
        self.observe(gate, "selected", "started")
        directory = lane_run.prepare_recovery(self.root, directory=floor_progress.rust_directory(self.run_dir, gate))
        return gate, directory

    def rust_state(self, *lines, verify=True):
        metadata = lane_run._checkout_metadata(self.repo, self.args.expected_head)
        index = lane_run.CANARY_INDEX
        observed = rust_timing.Observations(
            metadata.rust_targets, lambda value: lane_run._private(value, index, verified_identifier=True),
            verified_test=lambda name, binary: not verify or metadata.rust_progress_test(name, binary, index))
        observed.line(" Running unittests src/lib.rs (/fixture/private/example_crate-0123456789abcdef)", 1.2341)
        observed.line("running 2 tests", 1.2342)
        for line in lines:
            observed.line(line, 1.2343)
        return {"started": 0, "state": observed.snapshot()}

    def test_job_cancellation_preserves_last_observed_gate_without_passing(self):
        first, second = ci_floor.EXPECTED_GATE_NAMES[:2]
        self.observe(first, "selected", "started", "completed")
        self.observe(second, "selected")
        summary = self.sanitize()
        self.assertEqual(summary["fullReleaseToolTests"]["status"], "passed")
        self.assertEqual(summary["progress"], {
            "status": "observed", "lastObservedGate": second, "commandObservation": "selected",
            "lastCommandStart": first, "lastCommandCompletion": first, "rustGates": {},
        })
        self.observe(second, "started")
        # A cancellation can leave an unfinished temporary write and no receipt.
        temporary = self.checkpoint.with_name(f".{self.checkpoint.name}.{os.getpid()}.tmp")
        private_roots.atomic_write_private(temporary, b'{"version":1,"gates":')
        (self.run_dir / "receipt.json").unlink()
        self.assertEqual(self.sanitize(floor_status="unreached")["progress"], {
            "status": "observed", "lastObservedGate": second, "commandObservation": "started",
            "lastCommandStart": second, "lastCommandCompletion": first, "rustGates": {},
        })

    def test_job_cancellation_preserves_verified_active_rust_progress(self):
        gate, directory = self.start_rust_gate()
        self.write_json(directory / "timing.json", self.rust_state(
            "test tests::waiting has been running for over 60 seconds"))
        summary = self.sanitize()
        progress = summary["progress"]
        self.assertEqual(progress["lastObservedGate"], gate)
        self.assertEqual(progress["commandObservation"], "started")
        self.assertEqual(progress["lastCommandCompletion"], "rust-cli-spring-journey")
        self.assertEqual(progress["rustGates"][gate]["rustProgress"]["lastBinary"], {
            "status": "observed",
            "binary": {"crate": "example-crate", "targetKind": "lib", "targetName": "example_crate"},
            "startedSeconds": 1.234, "harnessResultObserved": False,
            "lastVerifiedTest": {"name": "tests::waiting", "observation": "running-reported", "wallSeconds": 1.234},
        })
        self.assertNotIn("/fixture/private", json.dumps(summary))
        self.assertFalse((self.root / "frag" / f"rust__-__{gate}.json").exists())

    def test_progress_withholds_unverified_names_and_captured_values(self):
        gate, directory = self.start_rust_gate()
        private_roots.atomic_write_private(
            directory / "frag" / "store-singletons-progress.txt",
            b"phase=captured_fixture spans=1 total_ns=1 max_ns=1 acl_probes=0\n"
            b"state=progress completed=captured_value elapsed_ns=1\n")
        for name in ("captured_fixture::waiting", "tests::canary_case", "/fixture/private/value"):
            with self.subTest(name=name):
                # A private checkpoint is reattested at publication even if its writer did not scan it.
                self.write_json(directory / "timing.json", self.rust_state(f"test {name} ... ok", verify=False))
                summary = self.sanitize()
                rust = summary["progress"]["rustGates"][gate]
                self.assertEqual(rust["rustProgress"]["lastBinary"]["lastVerifiedTest"], floor_progress.UNAVAILABLE)
                self.assertEqual(rust["storeProfiles"], floor_progress.UNAVAILABLE)
                for private in (name, "/fixture/private", "captured_fixture", "captured_value"):
                    self.assertNotIn(private, json.dumps(summary))
        state = self.rust_state("test tests::waiting ... ok")
        binary = state["state"]["lastTarget"][0]
        binary["targetName"] = "captured_binary"
        self.write_json(directory / "timing.json", state)
        summary = self.sanitize()
        self.assertEqual(summary["progress"]["rustGates"][gate]["rustProgress"], floor_progress.UNAVAILABLE)
        self.assertNotIn("captured_binary", json.dumps(summary))

    def test_incomplete_progress_is_reported_unavailable(self):
        self.assertEqual(self.sanitize()["progress"], floor_progress.UNAVAILABLE)
        gate, directory = self.start_rust_gate()
        timing_path = directory / "timing.json"
        private_roots.atomic_write_private(timing_path, b'{"started":0,"state":')
        profile = directory / "frag" / "store-singletons-progress.txt"
        private_roots.atomic_write_private(profile, b"state=returned completed=12 elapsed_ns=48")
        self.assertEqual(self.sanitize()["progress"]["rustGates"][gate], {
            "rustProgress": floor_progress.UNAVAILABLE, "storeProfiles": floor_progress.UNAVAILABLE,
            "springPremainOrderWait": floor_progress.UNAVAILABLE,
        })
        timing_path.unlink()
        outside = self.root / "timing.json"
        self.write_json(outside, self.rust_state("test tests::waiting ... ok"))
        timing_path.symlink_to(outside)
        self.assertEqual(self.sanitize()["progress"]["rustGates"][gate]["rustProgress"], floor_progress.UNAVAILABLE)
        record = json.loads(self.checkpoint.read_text())
        for bad_record in ({**record, "source": {**self.proof, "head": "b" * 40}},
                           {**record, "gates": [["../captured_fixture", "completed"]]},
                           {**record, "gates": [[ci_floor.EXPECTED_GATE_NAMES[0], "started"], *record["gates"][1:]]},
                           {**record, "gates": [[ci_floor.EXPECTED_GATE_NAMES[0], "pass"]]}):
            self.write_json(self.checkpoint, bad_record)
            self.assertEqual(self.sanitize()["progress"], floor_progress.UNAVAILABLE)
        private_roots.atomic_write_private(self.checkpoint, b'{"version":1,"gates":')
        self.assertEqual(self.sanitize()["progress"], floor_progress.UNAVAILABLE)

    def test_completed_workspace_publishes_spring_deadline_in_sanitized_summary(self):
        self.check_spring_deadline_summary(interrupt=False)

    def test_interrupted_workspace_recovers_spring_deadline_without_lane_fragment(self):
        self.check_spring_deadline_summary(interrupt=True)

    def check_spring_deadline_summary(self, *, interrupt):
        gate = "rust-workspace"
        valid = b"v1 attestation-mismatch 5 2\n"
        log_only = b"v1 error-request 2 1\n"
        private_values = ("captured-value-731", "/fixture/customer.txt", "b3:0123456789abcdef")
        workload_output = log_only + ("\n".join(private_values) + "\n").encode()
        recovery = floor_progress.rust_directory(self.run_dir, gate)
        record = recovery / "diagnostics" / "spring-premain-order-wait.txt"
        fragment = self.root / "frag" / f"rust__-__{gate}.json"
        # The supervisor checkpoint and the one-shot record can outlive receipt publication.
        (self.run_dir / "receipt.json").unlink()
        (self.root / "release-tool-tests-summary.json").unlink()
        logs = self.run_dir / "logs"
        logs.mkdir(mode=0o700)
        cargo = self.root / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\n"
            "import os, pathlib, signal\n"
            "directory = pathlib.Path(os.environ['XTRACE_CI_DIAG_DIR'])\n"
            "with os.fdopen(os.open(directory / 'spring-premain-order-wait.txt', "
            "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:\n"
            f"    stream.write({valid!r})\n"
            f"os.write(1, {workload_output!r})\n"
            + ("signal.pause()\n" if interrupt else "raise SystemExit(101)\n")
        )
        cargo.chmod(0o700)
        env = {
            **os.environ, "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            # Load the real wrapper from this checkout and attest the fixture's Git tree.
            "PYTHONPATH": str(pathlib.Path(__file__).resolve().parents[2]),
            "GIT_DIR": str(self.repo / ".git"), "GIT_WORK_TREE": str(self.repo),
        }
        for previous in ci_floor.EXPECTED_GATE_NAMES[:ci_floor.EXPECTED_GATE_NAMES.index(gate)]:
            self.observe(previous, "selected", "started", "completed")
        self.observe(gate, "selected")
        snapshot = own_process_snapshot()
        scans = 0
        interrupted = False

        def interrupt_after_record(**kwargs):
            nonlocal scans, interrupted
            processes = snapshot(**kwargs)
            scans += 1
            # Give the supervisor its initial process identity snapshot. The wrapper
            # flushes output only after Cargo closes the record, so no sleep is needed.
            if interrupt and not interrupted and scans >= 3 and record.is_file():
                if log_only in (recovery / "output.log").read_bytes():
                    interrupted = True
                    raise KeyboardInterrupt
            return processes

        with mock.patch.object(run_gates, "_process_snapshot", side_effect=interrupt_after_record), \
                release_floor.configured_floor(self.root, 7200):
            argv = next(item.argv for item in run_gates.GATES if item.name == gate)
            code, _ = run_gates._run(
                argv, cwd=self.repo, env=env, timeout=10, log_path=logs / f"{gate}.log",
                command_observed=lambda state: self.observe(gate, state),
            )
        self.assertEqual(interrupted, interrupt)
        self.assertEqual(code, 130 if interrupt else 101)
        self.assertEqual(record.read_bytes(), valid)
        self.assertIn(log_only, (recovery / "output.log").read_bytes())
        expected = {
            "status": "observed", "phase": "attestation-mismatch", "state": "insufficient-matching-rows",
            "expectedRows": 3, "completeRows": 5, "completeRowsLimit": 16, "matchingRows": 2,
        }
        if interrupt:
            self.assertIn("owned process tree drained", (logs / f"{gate}.log").read_text())
            self.assertFalse(fragment.exists())
        else:
            fragment_text = fragment.read_text()
            self.assertEqual(json.loads(fragment_text)["springPremainOrderWait"], expected)
            for value in (*private_values, valid.decode().strip(), log_only.decode().strip()):
                self.assertNotIn(value, fragment_text)

        def sanitize_artifact():
            argv = [
                "release_floor", "sanitize-floor", "--root", str(self.root), "--repo", str(self.repo),
                "--label", self.args.label, "--tuple", self.args.tuple,
                "--expected-head", self.args.expected_head, "--phase-base", self.args.phase_base,
            ]
            public = io.StringIO()
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(public):
                self.assertEqual(release_floor.main(), 1)
            text = (self.root / "release-floor-summary.json").read_text()
            for value in (*private_values, valid.decode().strip(), log_only.decode().strip(), str(self.root)):
                self.assertNotIn(value, text + public.getvalue())
            summary = json.loads(text)
            self.assertEqual((summary["floorStatus"], summary["gateCount"], summary["gates"]), ("unreached", 0, []))
            self.assertFalse(summary["releaseAcceptance"])
            return summary["progress"]

        def observation():
            return sanitize_artifact()["rustGates"][gate]["springPremainOrderWait"]

        progress = sanitize_artifact()
        self.assertEqual(progress["lastObservedGate"], gate)
        self.assertEqual(progress["commandObservation"], "started" if interrupt else "completed")
        self.assertEqual(progress["rustGates"][gate]["springPremainOrderWait"], expected)

        record.unlink()
        self.assertEqual(observation(), floor_progress.UNAVAILABLE)  # The matching grammar in stdout is ignored.
        private_roots.atomic_write_private(record, valid + workload_output)
        self.assertEqual(observation(), floor_progress.UNAVAILABLE)
        private_roots.atomic_write_private(record, valid)
        record.chmod(0o644)
        self.assertEqual(observation(), floor_progress.UNAVAILABLE)
        record.chmod(0o600)
        moved = recovery.with_name("unverified-recovery")
        recovery.rename(moved)
        recovery.symlink_to(moved, target_is_directory=True)
        self.assertEqual(observation(), floor_progress.UNAVAILABLE)
        recovery.unlink()
        moved.rename(recovery)
        self.assertEqual(observation(), expected)

        self.observe(gate, "selected")
        self.assertEqual(observation(), floor_progress.UNAVAILABLE)
        self.writer(self.run_dir, gate, "started", {**self.proof, "head": "b" * 40})
        self.assertEqual(sanitize_artifact(), floor_progress.UNAVAILABLE)
        self.observe(gate, "started")
        (self.repo / "untracked-fixture.txt").touch()
        self.assertEqual(sanitize_artifact(), floor_progress.UNAVAILABLE)
