"""Privacy boundaries and honest incomplete results for the installed JHipster campaign."""
import importlib.util
import base64
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile
from private_diagnostic import mark_root_admitted

HARNESS = pathlib.Path(__file__).resolve().parents[1] / "java/jhipster/harness"


def load(name):
    spec = importlib.util.spec_from_file_location(name, HARNESS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


public = load("public_result")
sinks = load("collect_sinks")
from campaigns.java.jhipster.harness import evidence  # noqa: E402


class PublicResult(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name).resolve() / "private"
        self.root.mkdir(mode=0o700)
        (self.root.parent / "driver").mkdir(mode=0o700)
        (self.root.parent / "driver/status.json").write_text(json.dumps({
            "schema": "xtrace-jhipster-driver/1", "exitCode": 0}))
        (self.root.parent / "driver/stdout").write_text("installed campaign completed\n")
        (self.root.parent / "driver/stderr").write_text("installed campaign diagnostic capture complete\n")
        mark_root_admitted(self.root)
        self.out = self.root.parent / "public"
        self.secret = "XTCANARY.synthetic.private-value-7890"
        self.canaries = {name: self.secret + "-" + str(i) for i, name in enumerate(public.CANARY_KINDS)}
        self.write("canaries.json", self.canaries)
        self.write("build-status.json", {"schema": "xtrace-jhipster-build/1", "exitCode": 0})
        self.write("phases.json", {"schema": "xtrace-jhipster-phases/1", "sourceCommit": "a" * 40,
                                  "packageSha256": "b" * 64,
                                  "phases": [{"name": name, "status": "passed", "exitCode": 0}
                                             for name in public.PHASES]})
        self.write("package-verification.json", {"schema": "xtrace-package-verification/1", "ok": True,
                                                  "privateDetail": self.secret})
        self.base = "campaign/java/jhipster/"
        for mode in ("baseline", "instrumented"):
            rows = []
            for sid, requests, checks in public.SCENARIOS:
                sent = [{"label": label, "status": public.EXPECT[sid][index]["statuses"][0], "elapsedMs": 0.5}
                        for label, index in public.response_labels(sid).items()]
                items = []
                for index, rule in enumerate(public.EXPECT[sid]):
                    burst = sid == "concurrent-isolation"
                    denied = sid == "anonymous-and-invalid-login-denied" and index < 2
                    problems = ["individual-request-and-principal-attribution-unobserved"] if burst else (
                        ["pre-dispatch-servlet-root-unobserved"] if denied else [])
                    if (sid == "anonymous-and-invalid-login-denied" and index == 2
                            or sid == "admin-and-user-authentication" and index in (2, 3)):
                        problems += ["postgresql-boundary-unobserved", *[
                            f"jdbc-operation-unobserved({verb} {table})" for verb, table in rule["jdbc"]]]
                    if sid == "account-create-read-roundtrip" and index == 1:
                        problems += [f"jdbc-operation-unobserved({verb} {table})" for verb, table in rule["jdbc"]]
                    matched = int(not burst and not denied)
                    items.append(evidence.item(rule, problems,
                                 attribution="ambiguous" if burst else "external-http-only" if denied else "serial-boundary-order",
                                 recordings=matched, statuses=matched, sources=int(bool(rule["handler"])) if matched else 0))
                row = {"id": sid, "requests": sent, "recordingVerdict": {
                       "passed": all(item["passed"] for item in items), "expectations": items, "problems": [],
                       "checkedRequests": len(sent), "recordingsAttributed": sum(item["recordingsMatchingRoute"] for item in items)},
                       "fingerprintEqualsBaseline": True, "privateDetail": self.secret}
                row["scenarioChecksPassed" if mode == "instrumented" else "passed"] = True
                row["workloadChecks" if mode == "instrumented" else "checks"] = [{"passed": True}] * checks
                rows.append(row)
            self.write(self.base + mode + "-1/receipt.json", {
                "project": "jhipster", "instrumented": mode == "instrumented", "releaseAcceptance": False,
                "result": "recorded" if mode == "instrumented" else "passed_baseline_only", "scenarios": rows,
                "burstRouteGroups": [{"evidenceScope": "burst-route-group", "requests": rule["minCount"], "problemRecordings": {},
                                      **evidence.item(rule, [], attribution="route-counts", recordings=rule["minCount"],
                                                      statuses=rule["minCount"], sources=rule["minCount"])}
                                     for rule in public.EXPECT["concurrent-isolation"]],
                "api": {"ok": True, "recordings": 79, "incompleteDetails": 0, "listReadGap": None},
                "workloadsPassed": True, "boundariesVerified": True, "baselineMatched": True,
                "recordingChecksPassed": True,
                "notes": {"canaryProbes": [
                    {"label": "authorization", "surfaces": ["authorization-header"], "status": 401, "passed": True},
                    {"label": "cookie-query-body", "surfaces": ["cookie-header", "query-token", "json-body-password"],
                     "status": 401, "passed": True},
                    {"label": "environment", "surfaces": ["env-var"], "passed": True}]},
                "problemClasses": {"pre-dispatch-servlet-root-unobserved": 2, "postgresql-boundary-unobserved": 3,
                                   "jdbc-operation-unobserved": 4,
                                   "individual-request-and-principal-attribution-unobserved": 4}})
        self.write("data/store.json", {"safe": True})
        self.write(self.base + "instrumented-1/api/recording-safe.json", {"events": []})
        for name in ("boundary-before", "phase-1-api", "phase-2-api", "phase-3-api"):
            self.write(self.base + "instrumented-1/" + name + "/recording-safe.json", {"events": []})
        self.write("sinks/cli/list-00.stdout", {"recordings": []})
        self.write("sinks/cli-status.json", {"complete": True, "artifactComplete": True, "recordings": 79})
        self.write("console/instrumented.stdout", {"result": "recorded"})
        self.write(self.base + "instrumented-1/application.log", {"status": "safe"})
        self.write(self.base + "instrumented-1/viewer.log", {"status": "safe"})
        self.write(self.base + "instrumented-1/boundary-viewer.log", {"status": "safe"})
        with zipfile.ZipFile(self.root / "sinks/recordings.zip", "w") as archive:
            archive.writestr("api-0000.json", '{"events": []}')

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(value))
        return path

    def read(self, relative):
        return json.loads((self.root / relative).read_text())

    def test_only_fixed_counts_statuses_and_validated_identities_survive(self):
        self.assertTrue(public.publish(self.root, self.out))
        self.assertEqual([p.name for p in self.out.iterdir()], ["summary.json"])
        raw = (self.out / "summary.json").read_text()
        self.assertNotIn(self.secret, raw)
        self.assertNotIn(str(self.root), raw)
        summary = json.loads(raw)
        self.assertFalse(summary["releaseAcceptance"])
        self.assertEqual(summary["expected"], {"scenarios": 8, "requests": 77, "checks": 39})
        self.assertEqual(summary["recordingGapProblemCounts"], {"preDispatch": 2, "postgresql": 7, "burst": 4})
        self.assertEqual(summary["individualBurstCorrelation"], "not-observed")
        self.assertEqual(summary["exportBundle"], "not-exercised")
        self.assertTrue(all(row["status"] == "passed" for name, row in summary["privacy"].items()
                            if name not in ("child-stderr", "outer-driver-output")))
        self.assertEqual(summary["privacy"]["child-stderr"]["status"], "not-produced")
        self.assertEqual(summary["privacy"]["outer-driver-output"]["status"], "passed")

    def test_normalized_jdbc_class_from_actual_producer_is_counted(self):
        import xinstr
        path = self.base + "instrumented-1/receipt.json"
        doc = self.read(path)
        normalized = xinstr.problem_classes({"scenario": {"expectations": [
            {"problems": ["jdbc-operation-unobserved(insert private_table)", "postgresql-boundary-unobserved"]}]}})
        self.assertEqual(normalized, {"jdbc-operation-unobserved": 1, "postgresql-boundary-unobserved": 1})
        doc["problemClasses"] = xinstr.problem_classes({row["id"]: row["recordingVerdict"] for row in doc["scenarios"]},
                                                       doc["burstRouteGroups"])
        self.write(path, doc)
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["recordingGapProblemCounts"]["postgresql"], 7)
        self.assertNotIn("private_table", json.dumps(summary))

    def test_wrong_envelope_and_missing_malformed_or_inconsistent_aggregate_are_unknown(self):
        path = self.base + "instrumented-1/receipt.json"
        original = self.read(path)
        for field, value in (("project", "other"), ("instrumented", False), ("releaseAcceptance", True),
                             ("releaseAcceptance", 0), ("problemClasses", None), ("problemClasses", []),
                             ("problemClasses", {}), ("problemClasses", {self.secret: 99}),
                             ("problemClasses", {"jdbc-operation-unobserved": False}),
                             ("problemClasses", {"jdbc-operation-unobserved": 0}),
                             ("problemClasses", {"jdbc-operation-unobserved": -1}),
                             ("problemClasses", {"jdbc-operation-unobserved": public.MAX_COUNT + 1}),
                             ("problemClasses", {"jdbc-operation-unobserved(select private_table)": 1})):
            with self.subTest(field=field, value=value):
                doc = {**original, field: value}
                self.write(path, doc)
                summary, _ = public.build_summary(self.root)
                self.assertEqual(summary["recordingJudgement"], "not-observed")
                self.assertTrue(all(value is None for value in summary["recordingGapProblemCounts"].values()))
                self.assertNotIn("private_table", json.dumps(summary))
        for field in ("project", "instrumented", "releaseAcceptance", "problemClasses"):
            with self.subTest(missing=field):
                doc = dict(original)
                doc.pop(field)
                self.write(path, doc)
                summary, _ = public.build_summary(self.root)
                self.assertEqual(summary["recordingJudgement"], "not-observed")
                self.assertTrue(all(value is None for value in summary["recordingGapProblemCounts"].values()))

    def test_missing_duplicate_or_partial_judge_rows_cannot_supply_aggregate_zeroes(self):
        from copy import deepcopy
        path = self.base + "instrumented-1/receipt.json"
        original = self.read(path)
        for mutation in ("missing-scenario", "duplicate-scenario", "missing-group", "partial-histogram"):
            with self.subTest(mutation=mutation):
                doc = deepcopy(original)
                if mutation == "missing-scenario":
                    doc["scenarios"].pop()
                elif mutation == "duplicate-scenario":
                    doc["scenarios"][-1] = deepcopy(doc["scenarios"][0])
                elif mutation == "missing-group":
                    doc["burstRouteGroups"].pop()
                else:
                    doc["burstRouteGroups"][-1].update(passed=False, problems=["recording-detail-incomplete"])
                self.write(path, doc)
                summary, _ = public.build_summary(self.root)
                self.assertEqual(summary["recordingJudgement"], "not-observed")
                self.assertTrue(all(value is None for value in summary["recordingGapProblemCounts"].values()))

    def test_outer_driver_must_explicitly_pass_even_when_all_inner_evidence_passes(self):
        self.assertTrue(public.publish(self.root, self.out))
        path = self.root.parent / "driver/status.json"
        for code, expected in ((2, "failed"), (None, "not-observed"), ("missing", "unreached")):
            with self.subTest(exitCode=code):
                if code == "missing":
                    path.unlink()
                else:
                    path.write_text(json.dumps({"schema": "xtrace-jhipster-driver/1", "exitCode": code}))
                destination = self.root.parent / ("public-driver-" + str(code))
                self.assertFalse(public.publish(self.root, destination))
                summary = json.loads((destination / "summary.json").read_text())
                self.assertEqual(summary["outerDriver"], {
                    "status": expected, "exitCode": code if type(code) is int else None})
                self.assertEqual(summary["api"]["incompleteDetails"], 0)

    def test_listing_gap_requires_explicit_producer_field(self):
        path = self.base + "instrumented-1/receipt.json"
        receipt = self.read(path)
        self.assertTrue(public.publish(self.root, self.out))
        for index, value in enumerate(("missing", False, True, 0, "", "recordings list HTTP 503")):
            with self.subTest(value=value):
                if value == "missing":
                    receipt["api"].pop("listReadGap", None)
                else:
                    receipt["api"]["listReadGap"] = value
                self.write(path, receipt)
                destination = self.root.parent / ("public-list-gap-" + str(index))
                self.assertFalse(public.publish(self.root, destination))
                summary = json.loads((destination / "summary.json").read_text())
                self.assertIs(summary["api"]["listReadGap"],
                              True if value == "recordings list HTTP 503" else None)
                self.assertEqual(summary["api"]["incompleteDetails"], 0)

    def test_unreached_outer_driver_without_streams_is_not_produced(self):
        for name in ("status.json", "stdout", "stderr"):
            (self.root.parent / "driver" / name).unlink()
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["outerDriver"], {"status": "unreached", "exitCode": None})
        self.assertEqual(summary["privacy"]["outer-driver-output"]["status"], "not-produced")

    def test_pre_receipt_failure_keeps_exact_exit_and_missing_receipt(self):
        phases = self.read("phases.json")
        phases["phases"][-2] = {"name": "instrumented", "status": "failed", "exitCode": 2}
        self.write("phases.json", phases)
        (self.root / (self.base + "instrumented-1/receipt.json")).unlink()
        self.assertFalse(public.publish(self.root, self.out))
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["instrumented"], {"status": "missing", "scenarios": []})
        self.assertEqual(summary["phases"][-2], {"name": "instrumented", "status": "failed", "exitCode": 2})
        self.assertTrue(all(value is None for value in summary["recordingGapProblemCounts"].values()))

    def test_missing_or_partial_surfaces_cannot_be_clean(self):
        (self.root / "sinks/recordings.zip").unlink()
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["privacy"]["recording-artifact"]["status"], "not-observed")
        doc = self.read(self.base + "instrumented-1/receipt.json")
        doc["api"]["incompleteDetails"] = 1
        doc["scenarios"][0]["requests"].pop()
        self.write(self.base + "instrumented-1/receipt.json", doc)
        self.assertFalse(public.publish(self.root, self.out))

    def test_console_does_not_cover_missing_product_logs_or_unreached_probes(self):
        (self.root / (self.base + "instrumented-1/application.log")).unlink()
        (self.root / (self.base + "instrumented-1/viewer.log")).unlink()
        doc = self.read(self.base + "instrumented-1/receipt.json")
        doc["notes"]["canaryProbes"] = []
        self.write(self.base + "instrumented-1/receipt.json", doc)
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["privacy"]["console-output"]["status"], "passed")
        self.assertEqual(summary["privacy"]["application-output"]["status"], "not-observed")
        self.assertEqual(summary["privacy"]["viewer-output"]["status"], "not-observed")
        self.assertTrue(all(row["delivery"] == "not-observed" for row in summary["canaryInjection"]
                            if row["kind"] in public.CANARY_KINDS))

    def test_encoded_canary_in_each_product_sink_reports_failure_without_value(self):
        for relative in ("data/store.json", self.base + "instrumented-1/api/recording-safe.json",
                         "sinks/cli/list-00.stdout", "console/instrumented.stdout"):
            with self.subTest(relative=relative):
                original = (self.root / relative).read_bytes()
                self.write(relative, {"value": base64.b64encode(self.canaries["query-token"].encode()).decode()})
                summary, _ = public.build_summary(self.root)
                self.assertTrue(any(row["status"] == "failed" for row in summary["privacy"].values()))
                self.assertNotIn(self.secret, json.dumps(summary))
                (self.root / relative).write_bytes(original)

    def test_all_live_boundary_sinks_are_scanned_with_final_collection_absent(self):
        project = self.root / (self.base + "instrumented-1")
        (project / "api/recording-safe.json").unlink()
        (project / "api").rmdir()
        (project / "viewer.log").unlink()
        paths = [(project / name / "recording-safe.json", "boundary-api-json")
                 for name in ("boundary-before", "phase-1-api", "phase-2-api", "phase-3-api")]
        paths.append((project / "boundary-viewer.log", "boundary-viewer-output"))
        for path, location in paths:
            with self.subTest(sink=path.relative_to(project).as_posix()):
                original = path.read_bytes()
                path.write_text(json.dumps({"marker": self.canaries["query-token"]}))
                summary, _ = public.build_summary(self.root)
                self.assertEqual(summary["privacy"][location]["status"], "failed")
                self.assertGreater(summary["privacy"][location]["hitClasses"], 0)
                self.assertEqual(summary["privacy"]["api-json"]["status"], "not-observed")
                self.assertEqual(summary["privacy"]["viewer-output"]["status"], "not-observed")
                self.assertNotIn(self.secret, json.dumps(summary))
                path.write_bytes(original)
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["privacy"]["boundary-api-json"]["status"], "passed")
        self.assertEqual(summary["privacy"]["boundary-viewer-output"]["status"], "passed")
        self.assertFalse(public.publish(self.root, self.out))

    def test_captured_child_stderr_marker_fails_without_public_content(self):
        self.write("child-stderr/instrumented-init.json", {
            "schema": "xtrace-private-child-stderr/1", "phase": "instrumented", "child": "init",
            "exitCode": 23, "timedOut": False, "stderrState": "captured"})
        self.write("child-stderr/instrumented-init.stderr", {"marker": self.canaries["query-token"]})
        self.assertFalse(public.publish(self.root, self.out))
        raw = (self.out / "summary.json").read_text()
        result = json.loads(raw)["privacy"]["child-stderr"]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["captureStates"]["captured"], 1)
        self.assertGreater(result["hitClasses"], 0)
        self.assertEqual(result["stdout"], "not-retained-by-existing-tools")
        self.assertNotIn(self.secret, raw)

    def test_unavailable_oversized_and_missing_child_capture_remain_gaps(self):
        for state in ("unavailable", "oversized", "captured"):
            with self.subTest(stderrState=state):
                self.write("child-stderr/instrumented-init.json", {
                    "schema": "xtrace-private-child-stderr/1", "phase": "instrumented", "child": "init",
                    "exitCode": 23, "timedOut": False, "stderrState": state})
                summary, _ = public.build_summary(self.root)
                result = summary["privacy"]["child-stderr"]
                self.assertEqual(result["status"], "gap-child-capture-status" if state == "captured"
                                 else "gap-stderr-" + state)
                self.assertEqual(result["captureStates"][state], 1)
                self.assertEqual(result["stdout"], "not-retained-by-existing-tools")
        self.assertFalse(public.publish(self.root, self.out))

    def test_zip_artifact_is_decompressed_and_scanned(self):
        with zipfile.ZipFile(self.root / "sinks/recordings.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("private.json", self.canaries["cookie-header"])
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["privacy"]["recording-artifact"]["status"], "failed")

    def test_symlink_or_input_bounds_are_not_silently_skipped(self):
        (self.root / "data/linked").symlink_to(self.root / "console", target_is_directory=True)
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["privacy"]["storage"]["status"], "scan-bound-or-unsafe-entry")
        with mock.patch.object(public, "MAX_SCAN_FILE_BYTES", 1):
            summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["privacy"]["api-json"]["status"], "scan-bound-or-unsafe-entry")

    def test_missing_canaries_withholds_all_source_derived_fields(self):
        (self.root / "canaries.json").unlink()
        self.assertFalse(public.publish(self.root, self.out))
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(summary["publication"], "withheld")
        self.assertNotIn("sourceCommit", summary)

    def test_canary_in_allowed_digest_withholds_stage(self):
        self.canaries["query-token"] = "a" * 40
        self.write("canaries.json", self.canaries)
        self.assertFalse(public.publish(self.root, self.out))
        self.assertNotIn("a" * 40, (self.out / "summary.json").read_text())
        self.assertEqual(json.loads((self.out / "summary.json").read_text())["publication"], "withheld")

    def test_boolean_counts_and_contradictory_phase_are_never_passes(self):
        self.assertIsNone(public.count(True))
        self.assertIsNone(public.count(10 ** 20))
        phases = public.phase_summary({"schema": "xtrace-jhipster-phases/1",
                                       "phases": [{"name": "instrumented", "status": "passed", "exitCode": 2}]})
        self.assertEqual(phases[-2], {"name": "instrumented", "status": "invalid", "exitCode": 2})

    def test_invalid_json_is_named_without_parse_error(self):
        path = self.root / (self.base + "baseline-1/receipt.json")
        path.write_text("malformed " + self.secret)
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["baseline"]["status"], "invalid")
        self.assertNotIn(self.secret, json.dumps(summary))

    def test_package_build_failure_before_driver_keeps_exact_exit(self):
        self.write("build-status.json", {"schema": "xtrace-jhipster-build/1", "exitCode": 101})
        (self.root / "phases.json").unlink()
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["packageBuild"], {"status": "failed", "exitCode": 101})
        self.assertTrue(all(row["status"] == "unreached" and row["exitCode"] is None for row in summary["phases"]))
        (self.root / "canaries.json").unlink()
        self.assertFalse(public.publish(self.root, self.out))
        fallback = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(fallback["packageBuild"], {"status": "failed", "exitCode": 101})

    def test_diagnostic_projection_keeps_only_fixed_fields_and_finite_statuses(self):
        for status in public.DIAGNOSTIC_STATUSES:
            with self.subTest(status=status):
                no_failure = status in ("not-required", "gap-invalid-failure-state")
                expected = {"status": status, "phase": None if no_failure else "instrumented",
                            "exitCode": None if no_failure else 23,
                            "retainedStderrStreams": 6 if status == "ciphertext-prepared" else 0,
                            "deeperDiagnostics": "not-retained-by-existing-tools"}
                self.write("diagnostic-status.json", {
                    "schema": "xtrace-jhipster-diagnostic-retention/1", **expected,
                    "rawStderr": self.secret, "path": str(self.root / "private.stderr"),
                    "certificate": self.secret, "privateKey": self.secret,
                    "deeperDiagnostics": self.secret})
                self.assertEqual(public.diagnostic_retention(self.root), expected)
        summary, _ = public.build_summary(self.root)
        self.assertEqual(summary["diagnosticRetention"], expected)
        self.assertNotIn(self.secret, json.dumps(summary))
        self.write("diagnostic-status.json", {
            "schema": "xtrace-jhipster-diagnostic-retention/1", "status": "ciphertext-prepared",
            "phase": "driver", "exitCode": 2, "retainedStderrStreams": 1})
        projected = public.diagnostic_retention(self.root)
        self.assertEqual(projected["status"], "ciphertext-prepared")
        self.assertEqual(projected["phase"], "driver")
        self.assertEqual(projected["exitCode"], 2)

    def test_invalid_diagnostic_fields_are_named_without_echoing_private_content(self):
        valid = {"schema": "xtrace-jhipster-diagnostic-retention/1", "status": "ciphertext-prepared",
                 "phase": "instrumented", "exitCode": 23, "retainedStderrStreams": 2}
        for replacement in ({"status": self.secret}, {"phase": str(self.root)}, {"exitCode": True},
                            {"retainedStderrStreams": True}, {"retainedStderrStreams": 7},
                            {"retainedStderrStreams": 0}, {"status": "gap-stderr-unavailable"},
                            {"phase": "collect-sinks"}):
            with self.subTest(fields=tuple(replacement)):
                self.write("diagnostic-status.json", {**valid, **replacement})
                projected = public.diagnostic_retention(self.root)
                self.assertEqual(projected["status"], "invalid")
                self.assertIsNone(projected["phase"])
                self.assertIsNone(projected["exitCode"])
                self.assertNotIn(self.secret, json.dumps(projected))

    def test_early_failure_fallback_preserves_bounded_diagnostic_status_only(self):
        self.write("build-status.json", {"schema": "xtrace-jhipster-build/1", "exitCode": 101})
        (self.root / "phases.json").unlink()
        (self.root / "canaries.json").unlink()
        self.write("diagnostic-status.json", {
            "schema": "xtrace-jhipster-diagnostic-retention/1", "status": "gap-recipient-unavailable",
            "phase": "package-build", "exitCode": 101, "retainedStderrStreams": 0,
            "deeperDiagnostics": self.secret, "rawStderr": self.secret,
            "certificate": self.secret, "key": self.secret, "path": str(self.root)})
        self.assertFalse(public.publish(self.root, self.out))
        raw = (self.out / "summary.json").read_text()
        fallback = json.loads(raw)
        self.assertEqual(fallback["publication"], "withheld")
        self.assertEqual(fallback["packageBuild"], {"status": "failed", "exitCode": 101})
        self.assertEqual(fallback["diagnosticRetention"], {
            "status": "gap-recipient-unavailable", "phase": "package-build", "exitCode": 101,
            "retainedStderrStreams": 0, "deeperDiagnostics": "not-retained-by-existing-tools"})
        self.assertNotIn(self.secret, raw)
        self.assertNotIn(str(self.root), raw)

    def test_refused_or_absent_root_projects_only_outer_driver_failure(self):
        refused = self.root / "refused"
        self.write("driver/status.json", {"schema": "xtrace-jhipster-driver/1", "exitCode": 2,
                                           "rawStderr": self.secret})
        self.write("driver/diagnostic-status.json", {
            "schema": "xtrace-jhipster-diagnostic-retention/1", "status": "ciphertext-prepared",
            "phase": "driver", "exitCode": 2, "retainedStderrStreams": 1,
            "certificate": self.secret, "path": str(self.root)})
        for exists in (False, True):
            with self.subTest(rootExists=exists):
                if exists:
                    refused.mkdir(mode=0o755)
                    refused.chmod(0o755)
                out = self.root.parent / ("outer-public-" + str(exists))
                self.assertFalse(public.publish(refused, out))
                raw = (out / "summary.json").read_text()
                summary = json.loads(raw)
                self.assertEqual(summary["outerDriver"], {"status": "failed", "exitCode": 2})
                self.assertEqual(summary["diagnosticRetention"]["status"], "ciphertext-prepared")
                self.assertEqual(summary["diagnosticRetention"]["phase"], "driver")
                self.assertEqual(summary["privateRoot"], "unsafe" if exists else "missing")
                self.assertEqual(summary["baseline"]["status"], "not-observed")
                self.assertNotIn(self.secret, raw)
                self.assertNotIn(str(self.root), raw)

    def test_populated_private_root_without_admission_is_never_read(self):
        refused = self.root / "stale-private"
        refused.mkdir(mode=0o700)
        self.write("driver/status.json", {"schema": "xtrace-jhipster-driver/1", "exitCode": 2})
        for name in ("phases.json", "canaries.json", "build-status.json"):
            (refused / name).write_text("malformed private stale content")
        original = public.read_object
        def read(path):
            if path == refused or refused in path.parents:
                raise AssertionError("refused root content was inspected")
            return original(path)
        with mock.patch.object(public, "read_object", side_effect=read), \
                mock.patch.object(public, "scan_sinks", side_effect=AssertionError("refused root was scanned")):
            summary, values = public.build_summary(refused)
        self.assertIsNone(values)
        self.assertEqual(summary["privateRoot"], "unadmitted")
        self.assertEqual(summary["outerDriver"], {"status": "failed", "exitCode": 2})

    def test_admission_signal_is_bound_to_current_directory_identity(self):
        original = self.root
        moved = self.root.parent / "old-root"
        original.rename(moved)
        original.mkdir(mode=0o700)
        with mock.patch.object(public, "scan_sinks", side_effect=AssertionError("replacement root was scanned")):
            summary, values = public.build_summary(original)
        self.assertIsNone(values)
        self.assertEqual(summary["privateRoot"], "unadmitted")


class CollectSinks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name).resolve()
        api = self.root / "campaign/java/jhipster/instrumented-1/api"
        api.mkdir(parents=True)
        (api / "recording-private-id.json").write_text('{"events": []}')

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, args, **kwargs):
        doc = ({"recordings": [{"recording_id": "rec-1"}], "next_after": None} if args[2] == "list"
               else {"recording_id": "rec-1", "events": [{}], "next_cursor": None, "incomplete_evidence": []})
        kwargs["stdout"].write(json.dumps(doc).encode())
        return subprocess.CompletedProcess(args, 0)

    def test_uses_installed_binary_real_cli_contract_and_private_artifact(self):
        with mock.patch.object(sinks.subprocess, "run", side_effect=self.run_cli) as run:
            self.assertTrue(sinks.collect(self.root))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][:3],
                         [str(self.root / "installed X-trace/bin/xtrace"), "recording", "list"])
        self.assertLessEqual(run.call_args.kwargs["timeout"], 30)
        status = json.loads((self.root / "sinks/cli-status.json").read_text())
        self.assertEqual(status["commandExits"], [0, 0])
        self.assertTrue(status["artifactComplete"])
        with zipfile.ZipFile(self.root / "sinks/recordings.zip") as archive:
            self.assertEqual(archive.namelist(), ["api-0000.json"])

    def test_nonzero_preserves_private_output_and_unobserved_cli(self):
        def fail(args, **kwargs):
            kwargs["stderr"].write(b"private transport diagnostic")
            return subprocess.CompletedProcess(args, 7)
        with mock.patch.object(sinks.subprocess, "run", side_effect=fail):
            self.assertFalse(sinks.collect(self.root))
        status = json.loads((self.root / "sinks/cli-status.json").read_text())
        self.assertFalse(status["complete"])
        self.assertEqual(status["commandExits"], [7])
        self.assertEqual((self.root / "sinks/cli/list-00.stderr").read_bytes(), b"private transport diagnostic")

    def test_timeout_is_not_an_exit_zero_or_complete_read(self):
        with mock.patch.object(sinks.subprocess, "run", side_effect=subprocess.TimeoutExpired("private-command", 30)):
            self.assertFalse(sinks.collect(self.root))
        status = json.loads((self.root / "sinks/cli-status.json").read_text())
        self.assertEqual(status["commandExits"], [None])
        self.assertFalse(status["complete"])

    def test_pagination_cycle_cannot_pass(self):
        def cycle(args, **kwargs):
            doc = {"recordings": [{"recording_id": "rec-1"}], "next_after": "rec-1"}
            kwargs["stdout"].write(json.dumps(doc).encode())
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(sinks.subprocess, "run", side_effect=cycle) as run:
            self.assertFalse(sinks.collect(self.root))
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
