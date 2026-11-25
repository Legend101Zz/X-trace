"""Safe projection regressions; synthetic judge rows are not campaign evidence."""
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("jhipster_recording_public", Path(__file__).resolve().parents[1] /
                                             "java/jhipster/harness/public_result.py")
public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public)
from campaigns.java.jhipster.harness import evidence  # noqa: E402


class RecordingProjection(unittest.TestCase):
    def document(self):
        rows, groups = [], []
        for sid, requests, _ in public.SCENARIOS:
            burst = sid == "concurrent-isolation"
            items, sent = [], []
            for rule_index, rule in enumerate(evidence.EXPECT[sid]):
                sent.extend({"label": label, "status": rule["statuses"][0], "elapsedMs": 0.5}
                            for label, index in public.response_labels(sid).items() if index == rule_index)
                if burst:
                    items.append(evidence.item(rule, ["individual-request-and-principal-attribution-unobserved"], attribution="ambiguous"))
                    groups.append({"evidenceScope": "burst-route-group", "requests": rule["minCount"], "problemRecordings": {},
                                   **evidence.item(rule, [], attribution="route-counts", recordings=rule["minCount"],
                                                   statuses=rule["minCount"], sources=rule["minCount"] if rule["handler"] else 0)})
                elif rule["preDispatch"]:
                    items.append(evidence.item(rule, ["pre-dispatch-servlet-root-unobserved"], attribution="external-http-only"))
                else:
                    items.append(evidence.item(rule, [], attribution="serial-boundary-order", recordings=1,
                                               statuses=1, sources=int(bool(rule["handler"]))))
            rows.append({"id": sid, "requests": sent, "recordingVerdict": {
                "expectations": items, "problems": [], "checkedRequests": requests,
                "recordingsAttributed": sum(item["recordingsMatchingRoute"] for item in items),
                "passed": all(item["passed"] for item in items)}})
        return {"project": "jhipster", "instrumented": True, "releaseAcceptance": False,
                "scenarios": rows, "burstRouteGroups": groups, "privateValue": "never-publish-this"}

    def scenario(self, projected, sid):
        return next(row for row in projected["scenarios"] if row["id"] == sid)

    def test_response_labels_match_pinned_workload_format_and_worker_principals(self):
        labels = public.response_labels("concurrent-isolation")
        self.assertEqual(len(labels), 49)
        self.assertEqual((labels["create Parallel 00"], labels["reopen Parallel 09"],
                          labels["login admin #0"], labels["account as user #11"]), (2, 3, 0, 1))
        self.assertNotIn("create Parallel 0", labels)
        self.assertNotIn("login admin #1", labels)

    def test_exact_denominators_keep_optional_denials_and_burst_attribution_separate(self):
        projected = public.recording_evidence_summary(self.document())
        self.assertEqual((projected["expectedRequests"], projected["eligibleRoots"], projected["optionalPreDispatchRoots"]), (77, 74, 3))
        self.assertEqual(sum(row["expectedRequests"] for row in projected["scenarios"]), 77)
        self.assertEqual(sum(row["eligibleRoots"] for row in projected["scenarios"]), 74)
        burst = self.scenario(projected, "concurrent-isolation")
        self.assertEqual((burst["expectedRequests"], burst["checkedRequests"], burst["individualRecordingsAttributed"]), (49, 49, 0))
        self.assertEqual((burst["seams"]["root"]["eligibleGroups"], burst["seams"]["root"]["matchedRecordings"]), (4, 49))
        self.assertEqual(burst["seams"]["root"]["observedResponses"], 49)
        self.assertEqual(burst["seams"]["requestAttribution"]["satisfiedRecordings"], 0)
        self.assertEqual(burst["failureClasses"], {"individual-request-and-principal-attribution-unobserved": 4})
        self.assertEqual(burst["recordingVerdict"], "failed")
        self.assertNotIn("never-publish-this", json.dumps(projected))

    def test_burst_group_assertions_differ_from_recording_assertions(self):
        doc = self.document()
        group = doc["burstRouteGroups"][-1]
        problem = "jdbc-operation-unobserved(select bank_account)"
        group.update(passed=False, problems=[problem], problemRecordings={problem: 12})
        burst = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")
        pg = burst["seams"]["postgresql"]
        self.assertEqual(pg["failureClasses"], {"jdbc-operation-unobserved": 1})
        self.assertEqual(pg["recordingFailureAssertions"], {"jdbc-operation-unobserved": 12})
        self.assertEqual((pg["eligibleRequests"], pg["checkedRecordings"], pg["pgjdbcObservedRecordings"]), (24, 24, 24))
        self.assertIsNone(pg["satisfiedRecordings"])
        self.assertEqual(pg["observation"], "observed")
        self.assertEqual(pg["actualExercise"], "unknown-from-receipt")
        self.assertNotIn("private_table", json.dumps(burst))

    def test_serial_coarse_pgjdbc_does_not_prove_sql_operations(self):
        doc = self.document()
        item = doc["scenarios"][2]["recordingVerdict"]["expectations"][1]
        item.update(passed=False, problems=["jdbc-operation-unobserved(insert bank_account)"])
        doc["scenarios"][2]["recordingVerdict"]["passed"] = False
        row = self.scenario(public.recording_evidence_summary(doc), "account-create-read-roundtrip")
        pg = row["seams"]["postgresql"]
        self.assertEqual((pg["pgjdbcObservedRecordings"], pg["checkedRecordings"], pg["satisfiedRecordings"]), (2, 2, 1))
        self.assertEqual(pg["failureClasses"], {"jdbc-operation-unobserved": 1})
        self.assertEqual(row["seams"]["repository"]["failureClasses"], {})

    def test_incomplete_detail_reduces_checked_denominator(self):
        doc = self.document()
        group = doc["burstRouteGroups"][-1]
        problems = ["recording-detail-incomplete", "postgresql-boundary-unobserved", "jdbc-operation-unobserved(select bank_account)"]
        group.update(passed=False, problems=problems, recordingsWithStatus=10, recordingsWithSource=10,
                     problemRecordings=dict(zip(problems, (2, 3, 3))))
        pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
        self.assertEqual((pg["matchedRecordings"], pg["checkedRecordings"], pg["pgjdbcObservedRecordings"]), (24, 22, 19))
        self.assertIsNone(pg["satisfiedRecordings"])

    def test_missing_scenario_and_duplicate_or_partial_group_remain_unknown(self):
        doc = self.document()
        doc["scenarios"].pop(2)
        doc["burstRouteGroups"].append(dict(doc["burstRouteGroups"][-1]))
        projected = public.recording_evidence_summary(doc)
        missing = self.scenario(projected, "account-create-read-roundtrip")
        self.assertIsNone(missing["observedResponses"])
        self.assertIsNone(missing["seams"]["repository"]["matchedRecordings"])
        self.assertIsNone(missing["failureClasses"])
        pg = self.scenario(projected, "concurrent-isolation")["seams"]["postgresql"]
        self.assertIsNone(pg["pgjdbcObservedRecordings"])
        self.assertEqual(pg["observation"], "unknown")
        doc["burstRouteGroups"].pop()
        doc["burstRouteGroups"][-1].pop("problemRecordings")
        pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
        self.assertIsNone(pg["checkedRecordings"])
        self.assertEqual(pg["knownMatchedRecordings"], 12)

    def test_zero_failures_without_inspection_does_not_credit_postgresql(self):
        doc = self.document()
        verdict = doc["scenarios"][2]["recordingVerdict"]
        verdict["passed"] = False
        verdict["recordingsAttributed"] = 0
        verdict["expectations"] = [evidence.item(rule, ["recording-attribution-unavailable"], attribution="unavailable")
                                   for rule in evidence.EXPECT["account-create-read-roundtrip"]]
        pg = self.scenario(public.recording_evidence_summary(doc), "account-create-read-roundtrip")["seams"]["postgresql"]
        self.assertEqual((pg["checkedRecordings"], pg["pgjdbcObservedRecordings"]), (0, 0))
        self.assertEqual((pg["observation"], pg["actualExercise"]), ("not-checked", "unknown-from-receipt"))

    def test_invalid_numbers_unknown_names_and_overlapping_failures_are_bounded(self):
        self.assertIsNone(public.problem_counts({"private value": True}, weighted=True))
        self.assertIsNone(public.problem_counts(["private value"], weighted=True))
        self.assertEqual(public.problem_counts(["private value(secret)"]), {"other": 1})
        doc = self.document()
        group = doc["burstRouteGroups"][-1]
        group["recordingsWithStatus"] = True
        pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
        self.assertIsNone(pg["checkedRecordings"])
        self.assertNotIn("private value", json.dumps(public.recording_evidence_summary(doc)))
        doc = self.document()
        item = doc["scenarios"][4]["recordingVerdict"]["expectations"][3]
        item.update(passed=False, recordingsWithSource=0,
                    problems=["controller-frame-unobserved", "controller-source-unobserved", "controller-exception-type-unobserved"])
        doc["scenarios"][4]["recordingVerdict"]["passed"] = False
        controller = self.scenario(public.recording_evidence_summary(doc), "account-update-and-missing")["seams"]["controller"]
        self.assertEqual(controller["satisfiedRecordings"], 3)  # Both failures concern one serial recording.


    def test_controller_exception_public_counts_distinguish_type_and_linkage(self):
        for token in (evidence.EXCEPTION_TYPE_UNOBSERVED, evidence.EXCEPTION_LINK_UNOBSERVED):
            with self.subTest(token=token):
                doc = self.document()
                verdict = doc["scenarios"][3]["recordingVerdict"]
                item = verdict["expectations"][2]
                item.update(passed=False, problems=[token])
                verdict["passed"] = False
                projected = self.scenario(public.recording_evidence_summary(doc), "account-validation-errors")
                self.assertEqual(projected["failureClasses"], {token: 1})
                self.assertEqual(projected["seams"]["controller"]["failureClasses"], {token: 1})
                self.assertNotIn(evidence.BANK_ALERT, json.dumps(projected))

                item["problems"] = [evidence.EXCEPTION_TYPE_UNOBSERVED, evidence.EXCEPTION_LINK_UNOBSERVED]
                rule = evidence.EXPECT["account-validation-errors"][2]
                self.assertIsNone(public.inspected_item(item, rule, [400]))

    def test_envelope_missing_scenario_and_wrong_or_duplicate_identity_cannot_credit_burst(self):
        for field, value in (("project", "other"), ("instrumented", False), ("instrumented", 1),
                             ("releaseAcceptance", True), ("releaseAcceptance", 0)):
            with self.subTest(field=field, value=value):
                doc = self.document()
                doc[field] = value
                projected = public.recording_evidence_summary(doc)
                self.assertTrue(all(row["observedResponses"] is None and row["observedExpectationGroups"] == 0
                                    for row in projected["scenarios"]))
        for mutation in ("missing", "wrong", "duplicate"):
            with self.subTest(mutation=mutation):
                doc = self.document()
                if mutation == "missing":
                    doc["scenarios"].pop(6)
                elif mutation == "wrong":
                    doc["scenarios"][6]["id"] = "private scenario"
                else:
                    doc["scenarios"].append(dict(doc["scenarios"][6]))
                pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
                self.assertIsNone(pg["pgjdbcObservedRecordings"])
                self.assertEqual(pg["observation"], "unknown")
                self.assertNotIn("private scenario", json.dumps(public.recording_evidence_summary(doc)))

    def test_raw_histogram_must_match_every_inspect_problem_in_both_directions(self):
        problem = "jdbc-operation-unobserved(select bank_account)"
        malformed = [
            ([problem], {}),
            ([], {problem: 1}),
            ([problem], {"jdbc-operation-unobserved(select private_table)": 12}),
            (["jdbc-operation-unobserved(select private_table)"], {"jdbc-operation-unobserved(select private_table)": 12}),
            (["jdbc-operation-unobserved"], {"jdbc-operation-unobserved": 12}),
            (["recording-detail-incomplete"], {}),
            ([problem], {problem: 0}), ([problem], {problem: False}),
            ([problem], {problem: -1}), ([problem], {problem: 1.0}), ([problem], {problem: 13}),
            ([problem, problem], {problem: 12}),
            (["postgresql-boundary-unobserved"], {"postgresql-boundary-unobserved": 12}),
        ]
        for problems, histogram in malformed:
            with self.subTest(problems=problems, histogram=histogram):
                doc = self.document()
                doc["burstRouteGroups"][-1].update(passed=not problems, problems=problems, problemRecordings=histogram)
                pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
                self.assertIsNone(pg["pgjdbcObservedRecordings"])
                self.assertIsNone(pg["checkedRecordings"])
                self.assertEqual(pg["observation"], "unknown")
        doc = self.document()
        doc["burstRouteGroups"][-1].update(passed=False, problems=["burst-boundary-unverified"], problemRecordings={})
        pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
        self.assertEqual(pg["pgjdbcObservedRecordings"], 24)
        self.assertEqual(pg["failureClasses"], {"burst-boundary-unverified": 1})

    def test_malformed_response_shape_label_status_timing_or_multiplicity_is_unknown(self):
        mutations = [
            lambda sent: sent[0].pop("label"), lambda sent: sent[0].pop("status"), lambda sent: sent[0].pop("elapsedMs"),
            lambda sent: sent[0].update(label="private label"), lambda sent: sent[0].update(status=True),
            lambda sent: sent[0].update(status="200"), lambda sent: sent[0].update(status=600),
            lambda sent: sent[0].update(elapsedMs=True), lambda sent: sent[0].update(elapsedMs=-1),
            lambda sent: sent[0].update(elapsedMs=float("inf")), lambda sent: sent[0].update(elapsedMs=float("nan")),
            lambda sent: sent[0].update(elapsedMs=10 ** 1000), lambda sent: sent[0].update(rawValue="private value"),
            lambda sent: sent.__setitem__(1, dict(sent[0])), lambda sent: sent.__setitem__(0, None),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                doc = self.document()
                mutate(doc["scenarios"][2]["requests"])
                row = self.scenario(public.recording_evidence_summary(doc), "account-create-read-roundtrip")
                self.assertIsNone(row["observedResponses"])
                self.assertIsNone(row["seams"]["postgresql"]["pgjdbcObservedRecordings"])
                self.assertEqual(row["recordingVerdict"], "not-observed")
        doc = self.document()
        doc["scenarios"][6]["requests"][0]["label"] = "login admin #1"  # Source assigns odd worker 1 to user.
        pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
        self.assertIsNone(pg["pgjdbcObservedRecordings"])

    def test_valid_failed_http_and_partial_workload_keep_only_backed_evidence(self):
        doc = self.document()
        row = doc["scenarios"][2]
        row["requests"][1]["status"] = 500
        row["recordingVerdict"]["expectations"][1].update(passed=False, problems=["workload-http-status-mismatch"])
        row["recordingVerdict"]["passed"] = False
        projected = self.scenario(public.recording_evidence_summary(doc), row["id"])
        self.assertEqual((projected["observedResponses"], projected["recordingVerdict"]), (3, "failed"))
        self.assertEqual(projected["seams"]["postgresql"]["pgjdbcObservedRecordings"], 2)
        row["requests"].pop()
        row["recordingVerdict"].update(checkedRequests=2, recordingsAttributed=2)
        rule = evidence.EXPECT[row["id"]][-1]
        row["recordingVerdict"]["expectations"][-1] = evidence.item(rule,
            ["workload-request-count-mismatch", "recording-attribution-unavailable"], attribution="unavailable")
        projected = self.scenario(public.recording_evidence_summary(doc), row["id"])
        self.assertEqual((projected["observedResponses"], projected["recordingVerdict"]), (2, "failed"))
        self.assertEqual((projected["seams"]["postgresql"]["matchedRecordings"],
                          projected["seams"]["postgresql"]["pgjdbcObservedRecordings"]), (1, 1))

    def test_duplicate_item_with_wrong_metadata_and_missing_verdict_fields_are_unknown(self):
        doc = self.document()
        duplicate = dict(doc["burstRouteGroups"][-1], expectedStatuses=[500])
        doc["burstRouteGroups"].append(duplicate)
        pg = self.scenario(public.recording_evidence_summary(doc), "concurrent-isolation")["seams"]["postgresql"]
        self.assertIsNone(pg["pgjdbcObservedRecordings"])
        for field in ("checkedRequests", "recordingsAttributed", "passed", "problems"):
            with self.subTest(field=field):
                doc = self.document()
                doc["scenarios"][2]["recordingVerdict"].pop(field)
                pg = self.scenario(public.recording_evidence_summary(doc), "account-create-read-roundtrip")["seams"]["postgresql"]
                self.assertIsNone(pg["pgjdbcObservedRecordings"])


if __name__ == "__main__":
    unittest.main()
