"""Judge regressions only; these fixtures are not installed-product evidence."""
from copy import deepcopy
import io
import json
import re
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installed_export_journey as journey  # noqa: E402


class BrowserReceiptTests(unittest.TestCase):
    def row(self, **changes):
        return {"width": 320, "coarse": False, "cases": 0, "status": "fail", "pageErrors": 0,
                "consoleErrors": 0, "externalRequests": 0, "failureSubstage": "preview-focus",
                "failureCase": "all-openapi-yaml", "cleanupFailures": [], **changes}

    def receipt(self, rows=None, **changes):
        return {"schemaVersion": 1, "rows": [self.row()] if rows is None else rows, "cases": [],
                "status": "fail", "failureSubstage": None, "browserCleanup": "pass", **changes}

    def test_partial_original_and_teardown_failures_remain_distinct(self):
        receipt = self.receipt([self.row(cleanupFailures=["context-close", "viewer-stop"],
                                         rawStack="private fixture value")], rawUrl="private fixture value")
        projected = journey.project_browser_receipt(receipt)
        self.assertEqual(projected["viewports"], 0)
        self.assertEqual(projected["downloads"], 0)
        self.assertEqual(projected["browserRows"][0]["failureSubstage"], "preview-focus")
        self.assertEqual(projected["browserRows"][0]["cleanupFailures"], ["context-close", "viewer-stop"])
        self.assertNotIn("private fixture value", json.dumps(projected))

    def test_teardown_only_failure_is_not_a_pass(self):
        projected = journey.project_browser_receipt(self.receipt([
            self.row(failureSubstage=None, failureCase=None, cleanupFailures=["api-evidence-write"])]))
        self.assertEqual(projected["browserRows"][0]["status"], "fail")
        self.assertEqual(projected["viewports"], 0)

    def test_launch_failure_has_no_invented_viewport(self):
        projected = journey.project_browser_receipt(self.receipt([], failureSubstage="browser-launch", browserCleanup="not-reached"))
        self.assertEqual(projected["browserFailureSubstage"], "browser-launch")
        self.assertEqual(projected["browserRows"], [])

    def test_unknown_or_raw_failure_values_are_rejected(self):
        for changes in ({"failureSubstage": "private fixture value"}, {"failureCase": "private fixture value"},
                        {"cleanupFailures": ["private fixture value"]}, {"cleanupFailures": ["viewer-stop", "viewer-stop"]},
                        {"failureSubstage": ["preview-focus"]}, {"pageErrors": True}, {"cases": 11}):
            with self.subTest(changes=changes), self.assertRaises(journey.JourneyFailure):
                journey.project_browser_receipt(self.receipt([self.row(**changes)]))
        with self.assertRaises(journey.JourneyFailure):
            journey.project_browser_receipt(self.receipt(failureSubstage="private fixture value"))

    def test_duplicate_viewports_and_unaccounted_cases_are_rejected(self):
        with self.assertRaisesRegex(journey.JourneyFailure, "browser-receipt-duplicate"):
            journey.project_browser_receipt(self.receipt([self.row(), self.row()]))
        case = {"id": "320-fine", "caseId": "all-openapi-yaml", "scope": "all", "format": "openapi", "yaml": True}
        with self.assertRaisesRegex(journey.JourneyFailure, "browser-receipt-count-parity"):
            journey.project_browser_receipt(self.receipt(cases=[case]))
        with self.assertRaisesRegex(journey.JourneyFailure, "browser-receipt-case-duplicate"):
            journey.project_browser_receipt(self.receipt([self.row(cases=2)], cases=[case, case]))

    def test_complete_matrix_and_browser_cleanup_outcome(self):
        rows, cases = [], []
        for width in journey.WIDTHS:
            for coarse in (False, True):
                rows.append(self.row(width=width, coarse=coarse, cases=10, status="pass", failureSubstage=None, failureCase=None))
                for case_id, (scope, fmt, yaml) in journey.BROWSER_CASES.items():
                    cases.append({"id": f"{width}-{'coarse' if coarse else 'fine'}", "caseId": case_id,
                                  "scope": scope, "format": fmt, "yaml": yaml})
        receipt = self.receipt(rows, cases=cases, status="pass")
        projected = journey.project_browser_receipt(receipt)
        self.assertEqual((projected["viewports"], projected["downloads"], projected["browserStatus"]), (10, 100, "pass"))
        receipt.update(status="fail", browserCleanup="fail")
        projected = journey.project_browser_receipt(receipt)
        self.assertEqual((projected["browserStatus"], projected["browserCleanup"]), ("fail", "fail"))
        receipt["status"] = "pass"
        with self.assertRaisesRegex(journey.JourneyFailure, "browser-receipt-outcome"):
            journey.project_browser_receipt(receipt)

    def test_partial_receipt_cannot_claim_success(self):
        with self.assertRaises(journey.JourneyFailure):
            journey.project_browser_receipt(self.receipt(status="pass"))
        with self.assertRaises(journey.JourneyFailure):
            journey.project_browser_receipt(self.receipt([self.row(status="pass")]))
        with self.assertRaises(journey.JourneyFailure):
            journey.project_browser_receipt(self.receipt([self.row(failureSubstage=None, failureCase=None)]))

    def test_javascript_substages_match_public_projection_vocabulary(self):
        script = (Path(__file__).resolve().parents[2] / "web/app/scripts/installed-export-journey.mjs").read_text()
        stages = set(re.findall(r"stage\('([^']+)'\)", script))
        self.assertEqual(stages, journey.BROWSER_PROGRESS_STAGES - journey.BROWSER_CLEANUP_STAGES)
        cleanup = set(re.findall(r"\['([^']+)', async", script))
        self.assertEqual(cleanup, journey.BROWSER_CLEANUP_STAGES)

    def progress(self, rows=None, cases=None, **changes):
        row = self.row(status="in-progress", failureSubstage=None, failureCase=None,
                       cleanupStatus="not-reached", cleanupStage=None)
        return self.receipt([row] if rows is None else rows, cases=[] if cases is None else cases,
                            schemaVersion=2, identity={"sourceSha": "a" * 40, "packageSha256": "b" * 64},
                            checkpointSequence=7, status="in-progress", browserCleanup="not-reached",
                            current={"rowId": "320-fine", "caseId": "all-openapi-yaml", "stage": "preview-keyboard"}, **changes)

    def test_live_and_interrupted_checkpoints_never_pass_an_unfinished_row(self):
        for status in ("in-progress", "interrupted"):
            with self.subTest(status=status):
                receipt = self.progress()
                receipt["status"] = receipt["rows"][0]["status"] = status
                receipt["rows"][0]["cases"] = 1
                receipt["cases"] = [{"id": "320-fine", "caseId": "all-openapi-yaml", "scope": "all", "format": "openapi", "yaml": True}]
                receipt["current"]["caseId"] = "all-openapi-json"
                projected = journey.project_browser_receipt(receipt, receipt["identity"])
                self.assertEqual((projected["viewports"], projected["downloads"], projected["browserCompletedCases"]), (0, 0, 1))
                self.assertEqual(projected["browserStatus"], status)
                self.assertEqual(projected["browserCurrent"], receipt["current"])

    def test_clean_completed_rows_remain_separate_from_interrupted_cleanup(self):
        first = self.row(cases=10, status="pass", failureSubstage=None, failureCase=None,
                         cleanupStatus="pass", cleanupStage=None)
        second = self.row(width=736, cases=1, status="interrupted", cleanupStatus="in-progress", cleanupStage="api-evidence-write")
        cases = [{"id": "320-fine", "caseId": case_id, "scope": scope, "format": fmt, "yaml": yaml}
                 for case_id, (scope, fmt, yaml) in journey.BROWSER_CASES.items()]
        cases.append({"id": "736-fine", "caseId": "all-openapi-yaml", "scope": "all", "format": "openapi", "yaml": True})
        receipt = self.progress([first, second], cases)
        receipt.update(status="interrupted", current={"rowId": "736-fine", "caseId": "all-openapi-yaml", "stage": "api-evidence-write"})
        projected = journey.project_browser_receipt(receipt)
        self.assertEqual((projected["viewports"], projected["downloads"], projected["browserCompletedCases"]), (1, 10, 11))
        self.assertEqual(projected["browserRows"][1]["cleanupStatus"], "in-progress")
        self.assertEqual(projected["browserCurrent"]["stage"], "api-evidence-write")

    def test_checkpoint_identity_and_fixed_progress_fields_reject_hostile_input(self):
        changes = (
            {"identity": {"sourceSha": "raw-private-value", "packageSha256": "b" * 64}},
            {"identity": {"sourceSha": "a" * 40, "packageSha256": "b" * 64, "path": "raw-private-value"}},
            {"checkpointSequence": True}, {"checkpointSequence": 0},
            {"current": {"rowId": "raw-private-value", "caseId": None, "stage": "preview-keyboard"}},
            {"current": {"rowId": None, "caseId": "all-openapi-yaml", "stage": "preview-keyboard"}},
            {"current": {"rowId": "320-fine", "caseId": None, "stage": "raw-private-value"}},
            {"current": {"rowId": "320-fine", "caseId": None, "stage": ["preview-keyboard"]}},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(journey.JourneyFailure):
                receipt = self.progress()
                receipt.update(change)
                journey.project_browser_receipt(receipt)
        with self.assertRaisesRegex(journey.JourneyFailure, "identity-parity"):
            journey.project_browser_receipt(self.progress(), {"sourceSha": "c" * 40, "packageSha256": "b" * 64})

    def test_pass_before_cleanup_and_unaccounted_completed_case_are_rejected(self):
        receipt = self.progress()
        receipt["rows"][0].update(cases=10, status="pass")
        with self.assertRaisesRegex(journey.JourneyFailure, "row-cleanup"):
            journey.project_browser_receipt(receipt)
        receipt = self.progress()
        receipt["rows"][0]["cases"] = 1
        with self.assertRaisesRegex(journey.JourneyFailure, "count-parity"):
            journey.project_browser_receipt(receipt)
        for cleanup_status, cleanup_stage in (("pass", "viewer-stop"), ("in-progress", None), ("fail", None)):
            with self.subTest(cleanup_status=cleanup_status), self.assertRaises(journey.JourneyFailure):
                receipt = self.progress()
                receipt["rows"][0].update(cleanupStatus=cleanup_status, cleanupStage=cleanup_stage)
                journey.project_browser_receipt(receipt)

    def test_checkpoint_reader_rejects_partial_bytes_permissions_links_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "browser.private.json"
            path.write_text(json.dumps(self.progress()))
            path.chmod(0o600)
            receipt, projected = journey.load_browser_receipt(path)
            self.assertEqual(projected["browserIdentity"], receipt["identity"])
            path.write_text('{"schemaVersion":2,"rows":[')
            with self.assertRaisesRegex(journey.JourneyFailure, "receipt-json"):
                journey.load_browser_receipt(path)
            path.write_text(json.dumps(self.progress()))
            path.chmod(0o644)
            with self.assertRaisesRegex(journey.JourneyFailure, "receipt-permissions"):
                journey.load_browser_receipt(path)
            path.chmod(0o600)
            link = root / "linked.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(journey.JourneyFailure, "receipt-file"):
                journey.load_browser_receipt(link)
            path.write_bytes(b" " * (journey.MAX_BROWSER_RECEIPT + 1))
            with self.assertRaisesRegex(journey.JourneyFailure, "private-file-limit"):
                journey.load_browser_receipt(path)


class ApiEvidenceReceiptTests(unittest.TestCase):
    def evidence(self):
        resources = {name: {"responses": journey.API_MINIMA.get(name, 0), "written": journey.API_MINIMA.get(name, 0)}
                     for name in journey.API_RESOURCES}
        count = sum(group["written"] for group in resources.values())
        counts = {name: 0 for name in journey.API_COUNTS}
        counts.update(requests=count, responses=count, jsonResponses=count, terminalRequests=count, bytesWritten=2 * count)
        return {"schemaVersion": 1, "status": "pass", "sealed": True, "counts": counts,
                "phases": {name: {"started": count, "passed": count, "failed": 0} for name in journey.API_PHASES},
                "resources": resources, "failures": {name: 0 for name in journey.API_CATEGORIES}}

    def receipt(self, passed=False):
        row = {"width": 320, "coarse": False, "cases": 10 if passed else 0, "status": "pass" if passed else "fail",
               "cleanupStatus": "pass", "cleanupStage": None, "pageErrors": 0, "consoleErrors": 0, "externalRequests": 0,
               "failureSubstage": None if passed else "preview-focus", "failureCase": None, "cleanupFailures": [],
               "apiEvidence": self.evidence()}
        cases = [{"id": "320-fine", "caseId": case_id, "scope": scope, "format": fmt, "yaml": yaml}
                 for case_id, (scope, fmt, yaml) in journey.BROWSER_CASES.items()] if passed else []
        return {"schemaVersion": 3, "identity": {"sourceSha": "a" * 40, "packageSha256": "b" * 64},
                "apiEvidenceSource": {"schemaVersion": 2, "transport": "browser-response-with-auth-clone-drain",
                                      "driverSha256": "c" * 64, "collectorSha256": "d" * 64, "visibilitySha256": "e" * 64},
                "checkpointSequence": 8, "status": "fail", "failureSubstage": None, "browserCleanup": "pass",
                "current": {"rowId": None, "caseId": None, "stage": "complete"}, "rows": [row], "cases": cases,
                "heightProbes": [{"width": 320, "height": height, "coarse": False, "status": "pass",
                                  "checks": {name: "not-required" if name == "initialAction" and height == 260 else "pass"
                                             for name in journey.HEIGHT_PROBE_CHECKS}} for height in (450, 260)] if passed else []}

    def test_projection_preserves_fixed_capture_stages_and_source_identity(self):
        receipt = self.receipt()
        projection = journey.project_browser_receipt(receipt, receipt["identity"], receipt["apiEvidenceSource"])
        self.assertEqual(projection["browserRows"][0]["apiEvidence"], receipt["rows"][0]["apiEvidence"])
        self.assertEqual(projection["browserApiEvidenceSource"], receipt["apiEvidenceSource"])
        self.assertEqual(projection["viewports"], 0)
        projection["browserRows"][0]["apiEvidence"]["counts"]["requests"] = 0
        self.assertGreater(receipt["rows"][0]["apiEvidence"]["counts"]["requests"], 0)

    def test_unknown_text_boolean_counters_and_unbalanced_lifetimes_are_rejected(self):
        for mutation in (
                lambda value: value.update(path="private-input-canary"),
                lambda value: value["failures"].update({"private-input-canary": 1}),
                lambda value: value["counts"].update(requests=True),
                lambda value: value["counts"].update(activeRequests=1),
                lambda value: value["phases"]["write"].update(passed=0),
                lambda value: value["resources"]["preview"].update(written=0),
                lambda value: value["counts"].update(pendingCaptures=1),
                lambda value: value["failures"].update({"body-unavailable": 1}),
                lambda value: value.update(sealed=False)):
            with self.subTest(mutation=mutation), self.assertRaises(journey.JourneyFailure):
                value = self.evidence()
                mutation(value)
                journey.project_api_evidence(value, True)

    def test_a_canceled_json_body_is_reported_failed_without_counting_it_as_no_response(self):
        value = self.evidence()
        count = value["counts"]["jsonResponses"]
        value["status"] = "fail"
        value["counts"]["bytesWritten"] -= 2
        for phase in ("body", "bounds", "write"):
            value["phases"][phase].update(started=count - 1, passed=count - 1)
        value["phases"]["finish"].update(passed=count - 1, failed=1)
        value["resources"]["preview"]["written"] -= 1
        value["failures"]["request-aborted"] = 1
        projection = journey.project_api_evidence(value, False)
        self.assertEqual(projection["counts"]["abortedBeforeResponse"], 0)
        self.assertEqual(projection["phases"]["finish"]["failed"], 1)
        with self.assertRaisesRegex(journey.JourneyFailure, "coverage"):
            journey.project_api_evidence(value, True)

    def test_resource_coverage_cannot_be_replaced_by_extra_preview_payloads(self):
        value = self.evidence()
        value["resources"]["preview"]["responses"] += 1
        value["resources"]["preview"]["written"] += 1
        value["resources"]["auth"] = {"responses": 0, "written": 0}
        with self.assertRaisesRegex(journey.JourneyFailure, "coverage"):
            journey.project_api_evidence(value, True)

    def test_source_identity_rejects_old_schema_and_changed_capture_source(self):
        receipt = self.receipt()
        changed = dict(receipt["apiEvidenceSource"], collectorSha256="e" * 64)
        with self.assertRaisesRegex(journey.JourneyFailure, "source-parity"):
            journey.project_browser_receipt(receipt, receipt["identity"], changed)
        receipt["schemaVersion"] = 2
        with self.assertRaisesRegex(journey.JourneyFailure, "source-parity"):
            journey.project_browser_receipt(receipt, receipt["identity"], receipt["apiEvidenceSource"])

    def test_historical_passive_source_cannot_qualify_the_auth_drain_collector(self):
        receipt = self.receipt()
        current = dict(receipt["apiEvidenceSource"])
        receipt["apiEvidenceSource"].update(schemaVersion=1, transport="passive-browser-response")
        historical = journey.project_browser_receipt(receipt)
        self.assertEqual(historical["browserApiEvidenceSource"], receipt["apiEvidenceSource"])
        with self.assertRaisesRegex(journey.JourneyFailure, "source-parity"):
            journey.project_browser_receipt(receipt, receipt["identity"], current)
        receipt["apiEvidenceSource"]["schemaVersion"] = 2
        with self.assertRaisesRegex(journey.JourneyFailure, "browser-api-source"):
            journey.project_browser_receipt(receipt)

    def test_passed_capture_must_have_every_private_payload_with_matching_byte_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = self.receipt(passed=True)
            directory = root / "320-fine"
            directory.mkdir(mode=0o700)
            count = receipt["rows"][0]["apiEvidence"]["counts"]["jsonResponses"]
            for index in range(count):
                path = directory / f"api-{index}.json"
                path.write_bytes(b"{}")
                path.chmod(0o600)
            checkpoint = root / "browser.private.json"
            checkpoint.write_text(json.dumps(receipt))
            checkpoint.chmod(0o600)
            _, projection = journey.load_browser_receipt(checkpoint, receipt["identity"], receipt["apiEvidenceSource"])
            self.assertEqual(projection["viewports"], 1)
            last = directory / f"api-{count - 1}.json"
            last.unlink()
            with self.assertRaisesRegex(journey.JourneyFailure, "api-files"):
                journey.load_browser_receipt(checkpoint)
            last.write_bytes(b"[]")
            last.chmod(0o644)
            with self.assertRaisesRegex(journey.JourneyFailure, "api-files"):
                journey.load_browser_receipt(checkpoint)
            last.chmod(0o600)
            last.write_bytes(b"[] ")
            with self.assertRaisesRegex(journey.JourneyFailure, "api-files"):
                journey.load_browser_receipt(checkpoint)


class HeightProbeReceiptTests(unittest.TestCase):
    def probe(self, height=450, status="in-progress"):
        return {"width": 320, "height": height, "coarse": False, "status": status,
                "checks": {name: "not-required" if name == "initialAction" and height == 260 else "not-reached"
                           for name in journey.HEIGHT_PROBE_CHECKS}}

    def test_partial_and_failed_probes_round_trip_without_credit(self):
        for height in (450, 260):
            for check in ("viewport", "initialAction", "contentScroll", "keyboardAction"):
                if height == 260 and check == "initialAction":
                    continue
                probe = self.probe(height)
                for name in journey.HEIGHT_PROBE_CHECKS:
                    if name == check:
                        break
                    if probe["checks"][name] != "not-required":
                        probe["checks"][name] = "pass"
                rows = [{"width": 320, "coarse": False, "status": "in-progress"}]
                self.assertEqual(journey.project_height_probes([probe], rows, "in-progress"), [probe])
                probe["checks"][check] = "fail"
                probe["checks"]["restore"] = "pass"
                probe["status"] = "fail"
                self.assertEqual(journey.project_height_probes([probe], rows, "fail"), [probe])

    def test_missing_duplicate_wrong_height_and_raw_probe_fields_are_rejected(self):
        rows = [{"width": 320, "coarse": False, "status": "pass"}]
        with self.assertRaisesRegex(journey.JourneyFailure, "coverage"):
            journey.project_height_probes([], rows, "fail")
        rows[0]["status"] = "fail"
        probe = self.probe()
        for probes in ([probe, probe], [dict(probe, height=480)], [dict(probe, coarse=1)],
                       [dict(probe, path="private-input-canary")], [dict(probe, status="pass")]):
            with self.subTest(probes=probes), self.assertRaises(journey.JourneyFailure):
                journey.project_height_probes(probes, rows, "fail")

    def test_full_height_matrix_is_separate_from_the_900_pixel_cases(self):
        rows, probes = [], []
        for width in journey.WIDTHS:
            for coarse in (False, True):
                rows.append({"width": width, "coarse": coarse, "status": "pass"})
                if width in (320, 736):
                    for height in (450, 260):
                        probe = self.probe(height, "pass")
                        probe.update(width=width, coarse=coarse)
                        for name in journey.HEIGHT_PROBE_CHECKS:
                            if probe["checks"][name] != "not-required":
                                probe["checks"][name] = "pass"
                        probes.append(probe)
        self.assertEqual(len(journey.project_height_probes(probes, rows, "pass")), 8)
        self.assertEqual(len(rows), 10)
        with self.assertRaisesRegex(journey.JourneyFailure, "coverage"):
            journey.project_height_probes(probes[:-1], rows, "pass")


class DownloadJudgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "cli"
        self.directory.mkdir()
        self.payload = b"abc"
        (self.directory / "all.sh").write_bytes(self.payload)
        self.download = self.root / "download"
        self.cli = {"revisionId": "pinned", "revisionOrdinal": 1, "contentHash": "a" * 64,
                    "operationCount": 1, "written": True, "preview": False, "omissions": [],
                    "files": [{"path": "all.sh", "bytes": len(self.payload), "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"}]}
        self.preview = {"schemaVersion": 1, "revisionId": "pinned", "revisionOrdinal": 1,
                        "approval": {"revisionId": "pinned", "digest": "c" * 64}, "contentHash": "a" * 64,
                        "emittedOperations": 1, "totalBytes": len(self.payload), "request": {"format": "curl"}, "omissions": [],
                        "files": [{"name": "all.sh", "recipeOrdinal": None, "bytes": len(self.payload), "mode": 0o644, "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"}]}
        self.zip()

    def zip(self, names=("all.sh",), payload=None, mode=stat.S_IFREG | 0o644):
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w") as archive:
            for name in names:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, self.payload if payload is None else payload)
        self.download.write_bytes(result.getvalue())

    def judge(self):
        return journey.judge_download(self.preview, self.cli, self.directory, self.download)

    def test_host_blake3_known_vectors(self):
        self.assertEqual(journey.blake3_bytes(b""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        self.assertEqual(journey.blake3_bytes(b"abc"), self.cli["files"][0]["blake3"])

    def test_matching_fraudulent_metadata_fails(self):
        self.cli["files"][0]["blake3"] = "b" * 64
        self.preview["files"][0]["blake3"] = "b" * 64
        with self.assertRaisesRegex(journey.JourneyFailure, "file-byte-digest"):
            self.judge()

    def test_same_total_different_omission_reason_fails(self):
        self.cli["omissions"] = [{"operationId": "", "what": "request_body", "reason": "no_body_example"}]
        self.preview["omissions"] = [{"format": None, "kind": "request_body", "reason": "secret_shaped", "count": 1}]
        with self.assertRaisesRegex(journey.JourneyFailure, "omission-group-parity"):
            self.judge()

    def test_bundle_omission_normalization(self):
        groups = journey.omission_groups([
            {"operationId": "one", "what": "curl:param:private", "reason": "duplicate_method_path_of:private"},
            {"operationId": "", "what": "future", "reason": "future"},
        ], "bundle")
        self.assertEqual(groups, {("curl", "parameters", "duplicate_method_path"): 1, (None, "other", "other"): 1})

    def test_exact_logical_zip_passes(self):
        self.assertEqual(self.judge(), 1)

    def test_same_size_corruption_fails(self):
        self.zip(payload=b"X" * len(self.payload))
        with self.assertRaisesRegex(journey.JourneyFailure, "zip-bytes"):
            self.judge()

    def test_extra_member_fails(self):
        self.zip(names=("all.sh", "extra.sh"))
        with self.assertRaisesRegex(journey.JourneyFailure, "zip-membership"):
            self.judge()

    def test_executable_or_symlink_mode_fails(self):
        for mode in (stat.S_IFREG | 0o755, stat.S_IFLNK | 0o644):
            with self.subTest(mode=mode):
                self.zip(mode=mode)
                with self.assertRaisesRegex(journey.JourneyFailure, "zip-mode"):
                    self.judge()

    def test_wrong_revision_or_digest_fails(self):
        for field, replacement, reason in (("revisionId", "other", "revision-parity"), ("contentHash", "d" * 64, "digest-parity")):
            with self.subTest(field=field):
                altered = deepcopy(self.preview)
                altered[field] = replacement
                with self.assertRaisesRegex(journey.JourneyFailure, reason):
                    journey.judge_download(altered, self.cli, self.directory, self.download)

    def test_preview_metadata_must_account_for_every_file(self):
        self.preview["files"][0]["blake3"] = "e" * 64
        with self.assertRaisesRegex(journey.JourneyFailure, "file-digest-parity"):
            self.judge()

    def test_unlisted_cli_output_fails(self):
        (self.directory / "stale.json").write_bytes(b"stale")
        with self.assertRaisesRegex(journey.JourneyFailure, "cli-membership"):
            self.judge()

    def test_unaccounted_omission_fails(self):
        self.cli["omissions"] = [{"operationId": "", "what": "request_body", "reason": "no_body_example"}]
        with self.assertRaisesRegex(journey.JourneyFailure, "omission-parity"):
            self.judge()

    def test_raw_download_requires_exact_bytes(self):
        self.preview["request"]["format"] = "openapi"
        self.download.write_bytes(self.payload)
        self.assertEqual(self.judge(), 1)
        self.download.write_bytes(self.payload + b" ")
        with self.assertRaisesRegex(journey.JourneyFailure, "download-bytes"):
            self.judge()

    def test_relative_paths_reject_escape_and_aliases(self):
        for name in ("../secret", "/absolute", "a//b", "./a", "a\\b", "a/../b", "nul\0"):
            with self.subTest(name=name):
                self.assertFalse(journey.safe_member(name))


if __name__ == "__main__":
    unittest.main()
