"""Regression checks for private Fineract progression; no real processes run here."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import installed_java
import xinstr
from tools.qa import canary

PROJECT = Path(__file__).resolve().parents[1] / "java/fineract"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence = load("fineract_recording_evidence", PROJECT / "harness/recording_evidence.py")
driver = load("fineract_installed", PROJECT / "harness/installed.py")


def harness(root):
    with mock.patch.dict(os.environ, {"XTRACE_CAMPAIGN_ROOT": str(root)}), \
            mock.patch.dict(sys.modules, {"recording_evidence": evidence}):
        return load("fineract_run", PROJECT / "harness/run.py")


class FineractInstalled(unittest.TestCase):
    def runner(self, root):
        (root / "console").mkdir()
        with mock.patch.object(driver.privacy, "PrivacyEvidence"):
            return driver.InstalledCampaign(root, root / "archive", "a" * 64, "b" * 40, Path("/jdk/bin/java"))

    def test_original_eight_workload_shapes_are_all_required(self):
        tracked = json.loads((PROJECT / "baseline-summary.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            run = harness(Path(tmp))
        self.assertEqual(list(evidence.EXPECT), [s.id for s in run.SCENARIOS])
        self.assertEqual(list(evidence.EXPECT), [r["id"] for r in tracked["scenarios"]])
        for row in tracked["scenarios"]:
            self.assertEqual(sum(rule["minCount"] for rule in evidence.EXPECT[row["id"]]), row["requests"])

    def test_archive_refusal_keeps_every_later_phase_unreached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = self.runner(root)
            with mock.patch.object(runner, "prerequisites", return_value=0), \
                    mock.patch.object(runner, "verify_archive", return_value=17), mock.patch.object(runner, "install") as install:
                self.assertEqual(runner.run(), 17)
            install.assert_not_called()
            rows = {r["name"]: r for r in json.loads((root / "phases.json").read_text())["phases"]}
            self.assertEqual(rows["archive-verify"]["exitCode"], 17)
            self.assertEqual(rows["instrumented"]["status"], "unreached")
            self.assertIsNone(rows["baseline"]["exitCode"])

    def test_phase_exception_detail_stays_in_its_private_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = self.runner(root)
            def fail():
                raise ValueError("private-path-and-credential")
            self.assertEqual(runner.phase("baseline", fail), 2)
            self.assertIn("private-path-and-credential", (root / "console/baseline.stderr").read_text())
            self.assertNotIn("private-path-and-credential", (root / "phases.json").read_text())

    def test_driver_removes_inherited_instrumentation_and_body_dumps(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                "JAVA_TOOL_OPTIONS": "private", "XCAMP_LAUNCH_PREFIX": "private", "XCAMP_DUMP_BODIES": "private"}):
            runner = self.runner(Path(tmp))
            for name in (*driver.xcamp.JAVA_OPTIONS_ENV, "XCAMP_LAUNCH_PREFIX", "XCAMP_DUMP_BODIES"):
                self.assertNotIn(name, runner.env)
            self.assertEqual(runner.env["JAVA_HOME"], "/jdk")
            self.assertEqual(runner.env["XCAMP_PLATFORM"], "linux/amd64")

    def test_host_stack_uses_original_reset_and_exact_database_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = harness(Path(tmp))
            for prefix in ((), ("installed xtrace", "run", "--")):
                stack = run.make_stack("owned", prefix)
                self.assertEqual(stack.launch_prefix, prefix)
                self.assertEqual(stack.db_image, run.CAMP["runtime"]["databaseImage"])
                self.assertEqual(stack.extra_db_init, ["CREATE DATABASE fineract_default"])
                self.assertEqual(stack.effect_db, "fineract_default")
                self.assertIn("--server.port={APPPORT}", stack.app_args)
                self.assertEqual(stack.ready_timeout, 900)

    def test_plain_execute_is_not_reinterpreted_as_sql_insert(self):
        rule = evidence.EXPECT["client-create-read-roundtrip"][0]
        detail = {"completion": "complete", "outcome": {"kind": "responded", "httpStatus": 200}, "events": [
            {"kind": "recording_event_kind:request_update", "symbol": f"http.request POST {evidence.CLIENTS}"},
            {"kind": "recording_event_kind:database_start", "interaction": {
                "kind": "interaction_kind:database", "driver": "pgjdbc", "method": "execute",
                "statement_kind": "insert", "table": "m_client"}}]}
        self.assertIn("required-sql-operation-unobserved", evidence.inspect(detail, rule, 200)[0])

    def test_positive_probes_deliver_values_without_mutating_original_workloads_or_echoing_secrets(self):
        values = canary.make_canaries()
        with mock.patch.object(evidence.xcamp, "http_request", side_effect=[dict(status=s) for s in (401, 401, 200, 400)]) as http:
            probes = evidence.inject_probes("http://127.0.0.1:1", values)
        calls = http.call_args_list
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0].kwargs["headers"]["Authorization"], values["authorization-header"])
        read, validation = calls[2], calls[3]
        self.assertTrue(read.args[2].startswith(evidence.OFFICES + "?xt_token="))
        self.assertIn(values["query-token"], read.args[2])
        self.assertEqual(read.kwargs["headers"]["Cookie"], values["cookie-header"])
        self.assertNotEqual(read.kwargs["headers"]["Authorization"], values["authorization-header"])
        payload = json.loads(validation.kwargs["body"])
        self.assertEqual(payload["password"], values["json-body-password"])
        self.assertNotIn("firstname", payload)
        self.assertNotIn("lastname", payload)
        self.assertFalse(payload["active"])
        serialized = json.dumps(probes)
        self.assertTrue(all(value not in serialized for value in values.values()))
        self.assertEqual([p.get("status") for p in probes], [401, 401, 200, 400, None])

    def test_probe_recordings_are_partitioned_by_status_after_verified_workload_boundary(self):
        values = canary.make_canaries()
        with mock.patch.object(evidence.xcamp, "http_request", side_effect=[dict(status=s) for s in (401, 401, 200, 400)]):
            probes = evidence.inject_probes("http://127.0.0.1:1", values)
        details = {}
        for index, (label, method, route, _) in enumerate(evidence.PROBES):
            details[str(index)] = dict(outcome=dict(kind="responded", httpStatus=evidence.PROBE_STATUSES[label]),
                                      events=[dict(kind="recording_event_kind:request_update",
                                                   symbol=f"http.request {method} {route}")])
        # An earlier matching office recording is outside the probe window.
        details["prior"] = details["2"]
        phase = xinstr.OrderedPhase("serial", [], dict(verified=True, snapshotIds=["prior"]))
        with mock.patch.object(evidence, "inspect", return_value=([], True, True)) as inspect:
            judged = evidence.judge_probes(details, [phase], probes)
        self.assertTrue(all(p["passed"] for p in judged))
        self.assertEqual([p["recordings"] for p in judged[:-1]], [1, 1, 1, 1])
        self.assertEqual(inspect.call_args_list[2].args[1]["handler"], evidence.OFFICE_RESOURCE + "retrieveOffices")
        self.assertEqual(inspect.call_args_list[3].args[1]["handler"], evidence.CLIENT_RESOURCE + "create")
        details["duplicate"] = details["2"]
        self.assertFalse(evidence.judge_probes(details, [phase], probes)[2]["passed"])
        phase.boundary["verified"] = False
        self.assertTrue(all(not p["passed"] for p in evidence.judge_probes(details, [phase], probes)[:-1]))

    def test_rejected_positive_request_and_transport_failure_remain_gaps(self):
        values = canary.make_canaries()
        with mock.patch.object(evidence.xcamp, "http_request", side_effect=[dict(status=401), dict(status=401),
                                                                                 OSError("private input"), dict(status=401)]):
            probes = evidence.inject_probes("http://127.0.0.1:1", values)
        judged = evidence.judge_probes({}, [], probes)
        self.assertFalse(judged[2]["passed"])
        self.assertFalse(judged[3]["passed"])
        self.assertIn("probe-delivery-unobserved", judged[2]["problems"])
        self.assertIn("probe-delivery-unobserved", judged[3]["problems"])
        self.assertEqual(probes[2]["surfaces"], [])
        self.assertNotIn("private input", json.dumps(probes))

    def test_route_group_never_establishes_individual_concurrent_isolation(self):
        rules = evidence.EXPECT["concurrent-isolation"]
        requests = []
        details, routes = {}, []
        for index, rule in enumerate(rules):
            ids = []
            for number in range(rule["minCount"]):
                rid = f"{index}-{number}"
                ids.append(rid)
                details[rid] = {}
                requests.append({"label": rid, "request": {"method": rule["method"], "path": rule["route"]},
                                 "response": {"status": 200}})
            routes.append(dict(method=rule["method"], route=rule["route"], recordingIds=ids))
        phase = xinstr.OrderedPhase("burst", [dict(id="concurrent-isolation", requests=requests)],
                                    dict(verified=True, routes=routes, snapshotIds=list(details)))
        with mock.patch.object(evidence, "inspect", return_value=([], True, True)):
            verdicts, groups, _, _, probes = evidence.judge(details, {"concurrent-isolation": rules}, [phase], [])
        self.assertTrue(all(g["passed"] for g in groups))
        self.assertFalse(verdicts["concurrent-isolation"]["passed"])
        self.assertTrue(all("individual-isolation-unobserved" in row["problems"]
                            for row in verdicts["concurrent-isolation"]["expectations"]))
        self.assertFalse(probes[0]["passed"])

    def test_empty_evidence_is_unreached_not_passed(self):
        verdicts, groups, statuses, sources, privacy = evidence.judge({}, evidence.EXPECT, [], [])
        self.assertEqual(len(verdicts), 8)
        self.assertTrue(all(not v["passed"] and v["problems"] == ["scenario-unreached"] for v in verdicts.values()))
        self.assertEqual((groups, statuses, sources), ([], set(), set()))
        self.assertFalse(privacy[0]["passed"])

    def test_mismatched_archive_identity_never_runs_packaged_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = mock.Mock()
            package.verify.return_value = {"ok": True, "package": {"sourceCommit": "c" * 40, "platform": "linux-x86_64"}}
            with mock.patch.object(installed_java, "verifier", return_value=package), \
                    mock.patch.object(installed_java.xcamp, "sha256_file", return_value="a" * 64):
                with self.assertRaises(ValueError):
                    installed_java.installed_package(root / "prefix", root / "archive", "a" * 64, "b" * 40, root / "extract")
            package.verify.assert_called_once_with(root / "archive", run=False)
            package.resolve_root.assert_not_called()

    def test_installed_payload_tamper_is_refused_before_installed_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original"
            original.mkdir()
            (original / "payload").write_bytes(b"verified")
            prefix = root / "prefix"
            current = prefix / "versions/0.0.1"
            current.mkdir(parents=True)
            (current / "payload").write_bytes(b"tampered")
            (prefix / "current").symlink_to("versions/0.0.1", target_is_directory=True)
            archive = root / "archive.tar.gz"
            archive.write_bytes(b"archive")
            package = mock.Mock()
            package.verify.return_value = {"ok": True, "package": {"sourceCommit": "b" * 40, "platform": "linux-x86_64"}}
            package.resolve_root.return_value = original
            with mock.patch.object(installed_java, "verifier", return_value=package), \
                    mock.patch.object(installed_java.private_diagnostic, "run_captured") as run:
                with self.assertRaisesRegex(ValueError, "payload differs"):
                    installed_java.installed_package(prefix, archive, installed_java.xcamp.sha256_file(archive),
                                                    "b" * 40, root / "extract")
            run.assert_not_called()

    def test_private_input_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "input"
            secret.touch(mode=0o600)
            alias = root / "link"
            alias.symlink_to(secret)
            with mock.patch.object(installed_java, "private_dir"):
                with self.assertRaises(ValueError):
                    installed_java.private_file(alias)


if __name__ == "__main__":
    unittest.main()
