import importlib.util
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import xcamp
import xinstr

PROJECT = pathlib.Path(__file__).resolve().parents[1] / "java/jhipster"
_SPEC = importlib.util.spec_from_file_location("jhipster_evidence", PROJECT / "harness/evidence.py")
evidence = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(evidence)


def campaign_harness(root):
    spec = importlib.util.spec_from_file_location("jhipster_run", PROJECT / "harness/run.py")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict("os.environ", {"XTRACE_CAMPAIGN_ROOT": str(root)}), mock.patch.dict(sys.modules, {"evidence": evidence}):
        spec.loader.exec_module(module)
    return module


def recording(method, route, status, extra=()):
    return {"completion": "complete", "nextCursor": None, "outcome": {"kind": "responded", "httpStatus": status},
            "events": [{"kind": "recording_event_kind:request_update", "symbol": f"http.request {method} {route}"},
                       *extra]}


def request(label, method, path, status):
    return {"label": label, "request": {"method": method, "path": path}, "response": {"status": status}}


class JHipsterEvidence(unittest.TestCase):
    def test_owned_host_launches_observe_bound_port_and_still_require_management_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = campaign_harness(pathlib.Path(tmp))
            for name, prefix in (("baseline", ()), ("instrumented", ("xtrace", "run", "--"))):
                with self.subTest(run=name), mock.patch.dict(xcamp.os.environ, {
                    "XCAMP_APP_MODE": "host", "XCAMP_JAVA": "java", "TMPDIR": tmp,
                    "XCAMP_LAUNCH_PREFIX": ""}):
                    stack = harness.make_stack(name, prefix)
                    with mock.patch.object(stack, "down"), mock.patch.object(stack, "_wait_db"), \
                            mock.patch.object(xcamp, "docker"), \
                            mock.patch.object(xcamp, "published_port", return_value=39452), \
                            mock.patch.object(xcamp.subprocess, "Popen") as launch, \
                            mock.patch.object(stack, "logs", return_value=(
                                "org.springframework.boot.tomcat.TomcatWebServer : "
                                "Tomcat started on port 39451 (http) with context path '/'")), \
                            mock.patch.object(xcamp, "http_request", return_value={
                                "status": 200, "body": b'{"status":"UP"}'}) as request:
                        launch.return_value.poll.return_value = None
                        stack.up()
                    argv = launch.call_args.args[0]
                    self.assertIn("--server.port=0", argv)
                    self.assertIn("--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO", argv)
                    self.assertEqual(argv[:len(prefix)], list(prefix))
                    self.assertEqual(stack.host_port, 39451)
                    self.assertEqual(request.call_args.args[:3],
                                     ("http://127.0.0.1:39451", "GET", "/management/health"))
                    self.assertTrue(stack.ready_ok(200, '{"status":"UP"}'))
                    self.assertFalse(stack.ready_ok(503, '{"status":"UP"}'))
                    self.assertFalse(stack.ready_ok(200, '{"status":"DOWN"}'))

    def test_expectations_match_all_tracked_request_counts(self):
        summary = json.loads((PROJECT / "baseline-summary.json").read_text())
        self.assertEqual(list(evidence.EXPECT), [row["id"] for row in summary["scenarios"]])
        for row in summary["scenarios"]:
            with self.subTest(row=row["id"]):
                checks = evidence.EXPECT[row["id"]]
                self.assertEqual(sum(check["minCount"] for check in checks), row["requests"])
                if row["kind"] == "concurrency":
                    self.assertTrue(all(c["label"] is None and len(c["statuses"]) == 1 for c in checks))
                else:
                    self.assertEqual(len({c["label"] for c in checks}), len(checks))

    def test_pre_dispatch_option_cannot_stand_in_for_admin_success(self):
        expect = {"sc": [evidence.EXPECT["admin-and-user-authentication"][2]]}
        allowed = (("GET", evidence.USERS, 403),)
        work = [("sc", "GET", evidence.USERS)]
        deny = recording("GET", evidence.USERS, 403)
        ok = recording("GET", evidence.USERS, 200)
        denied = xinstr.burst_accounting({"deny": deny}, work, expect, {}, optional_roots=allowed)
        self.assertFalse(denied["verified"])
        present = xinstr.burst_accounting({"deny": deny, "ok": ok}, work, expect, {}, optional_roots=allowed)
        self.assertTrue(present["verified"])
        self.assertEqual(present["recordingIds"], ["ok"])
        self.assertEqual(present["optionalRootIds"], ["deny"])
        double = xinstr.burst_accounting({"deny1": deny, "deny2": deny, "ok": ok}, work, expect, {}, optional_roots=allowed)
        self.assertFalse(double["verified"])

    def test_route_less_filter_root_cannot_be_allocated_to_an_expected_route(self):
        rule = evidence.EXPECT["anonymous-and-invalid-login-denied"][0]
        root = recording("GET", evidence.BANK, 401)
        root["events"][0]["symbol"] = "http.request GET"
        details = {"filter": root}
        boundary = xinstr.burst_accounting(
            details, [], {"sc": [rule]}, {}, optional_roots=(("GET", evidence.BANK, 401),))
        self.assertIsNone(xinstr.request_info(root))
        self.assertFalse(boundary["verified"])
        self.assertEqual(boundary["optionalRootIds"], [])
        self.assertIsNone(evidence.pre_dispatch_recording(
            xinstr.OrderedPhase("serial", [], boundary), details, rule, 401))

    def test_workload_keeps_cleanup_after_burst_even_if_boundary_fails(self):
        ids = ["first", "burst", "delete"]
        phases = ["auth", "concurrency", "error"]
        scenarios = [xcamp.Scenario(sid, sid, kind, None) for sid, kind in zip(ids, phases)]
        sent = [(sid, {"id": sid, "passed": True, "semanticEffectFingerprint": "0" * 64, "elapsedMs": 0,
                       "requests": [request(sid, "GET", "/api/account", 200)]}) for sid in ids]
        stack = mock.Mock(base="http://127.0.0.1:1")
        not_verified = xinstr.burst_accounting({}, [("first", "GET", "/api/account")], {}, {})
        with mock.patch.object(xcamp, "run_scenario", side_effect=[result for _, result in sent]) as run, \
             mock.patch.object(xinstr, "wait_burst_boundary", return_value=not_verified) as boundary, \
             mock.patch("builtins.print"):
            result = xinstr.capture_ordered_phases(stack, scenarios, [], {sid: [{}] for sid in ids}, frozenset(),
                                                   pathlib.Path("unused"), mock.Mock(), {}, 1)
        self.assertEqual([call.args[0].id for call in run.call_args_list], ids)
        self.assertEqual([phase.kind for phase in result], ["serial", "burst", "serial"])
        self.assertTrue(all(not phase.boundary["verified"] for phase in result))
        boundary.assert_called_once()

    def test_same_status_does_not_credit_unrelated_controller_or_h2(self):
        rule = evidence.EXPECT["account-create-read-roundtrip"][1]
        row = recording("POST", evidence.BANK, 201, [
            {"kind": "recording_event_kind:frame_enter", "symbol": "OperationResource.createOperation",
             "sourceBinding": "verified", "source": {"status": "matched", "path": "OperationResource.java", "startLine": 1}},
            {"kind": "recording_event_kind:database_start",
             "interaction": {"kind": "interaction_kind:database", "driver": "h2", "method": "insert", "table": "bank_account"}},
        ])
        problems, has_status, has_source = evidence.inspect(row, rule, 201)
        self.assertTrue(has_status)
        self.assertFalse(has_source)
        self.assertIn("controller-frame-unobserved", problems)
        self.assertIn("postgresql-boundary-unobserved", problems)
        self.assertIn("jdbc-operation-unobserved(insert bank_account)", problems)

    def test_same_recording_can_prove_exact_route_source_repository_and_jdbc(self):
        rule = evidence.EXPECT["account-create-read-roundtrip"][1]
        path = "src/main/java/io/github/jhipster/sample/web/rest/BankAccountResource.java"
        row = recording("POST", evidence.BANK, 201, [
            {"kind": "recording_event_kind:frame_enter",
             "symbol": "BankAccountResource.createBankAccount", "frameId": "controller",
             "sourceBinding": "observed_unattested", "source": {"status": "matched", "path": path, "startLine": 47}},
            {"kind": "recording_event_kind:frame_enter", "symbol": evidence.CRUD + "save",
             "parentFrameId": "controller"},
            {"kind": "recording_event_kind:database_start",
             "interaction": {"kind": "interaction_kind:database", "driver": "pgjdbc", "method": "insert",
                             "table": "bank_account"}},
        ])
        self.assertEqual(evidence.inspect(row, rule, 201), ([], True, True))
        row["events"][0]["symbol"] = "http.request POST /api/other"
        problems, has_status, has_source = evidence.inspect(row, rule, 201)
        self.assertIn("exact-route-root-unobserved", problems)
        self.assertFalse(has_status)
        self.assertFalse(has_source)

    def bank_exception(self, *, update=False):
        rule = (evidence.EXPECT["account-update-and-missing"][3] if update
                else evidence.EXPECT["account-validation-errors"][2])
        path = "src/main/java/io/github/jhipster/sample/web/rest/BankAccountResource.java"
        root = recording(rule["method"], rule["route"], rule["statuses"][0])
        root["recordingId"] = "allocated-recording"
        root["events"][0]["eventId"] = "request"
        anchor = {"kind": "recording_event_kind:frame_enter", "symbol": rule["handler"],
                  "eventId": "controller-enter", "frameId": "enter-frame", "parentEventId": "request",
                  "sourceBinding": "observed_unattested",
                  "source": {"status": "matched", "path": path, "startLine": 47}}
        throwing = {"kind": "recording_event_kind:frame_throw", "symbol": rule["handler"],
                    "eventId": "controller-throw", "frameId": "throw-frame",
                    "parentEventId": anchor["eventId"], "parentFrameId": anchor["frameId"],
                    "source": None, "sourceBinding": "attestation_missing",
                    "exception": {"exceptionType": evidence.BANK_ALERT}}
        root["events"].extend((anchor, throwing))
        return rule, root, anchor, throwing

    def test_normal_source_less_throw_uses_direct_entry_event_for_both_controller_cases(self):
        for update in (False, True):
            with self.subTest(update=update):
                rule, root, anchor, throwing = self.bank_exception(update=update)
                problems, has_status, has_source = evidence.inspect(
                    root, rule, rule["statuses"][0], recording_id="allocated-recording")
                self.assertTrue(has_status and has_source)
                self.assertNotIn(evidence.EXCEPTION_TYPE_UNOBSERVED, problems)
                self.assertNotIn(evidence.EXCEPTION_LINK_UNOBSERVED, problems)
                # A qualified, independently sourced observation also agrees with the direct entry.
                throwing.update(symbol=evidence.REST_PACKAGE + rule["handler"],
                                source=anchor["source"], sourceBinding="verified")
                self.assertEqual(evidence.inspect(
                    root, rule, rule["statuses"][0], recording_id="allocated-recording")[0], problems)

    def test_controller_exception_type_requires_the_pinned_qualified_name(self):
        for wrong in ("BadRequestAlertException", "org.example.BadRequestAlertException", None):
            with self.subTest(wrong=wrong):
                rule, root, _, throwing = self.bank_exception()
                throwing["exception"]["exceptionType"] = wrong
                problems, _, _ = evidence.inspect(root, rule, 400, recording_id="allocated-recording")
                self.assertEqual(problems, [evidence.EXCEPTION_TYPE_UNOBSERVED])

    def test_controller_exception_rejects_invalid_or_conflicting_direct_links(self):
        cases = {
            "missing-parent": {"parentEventId": None},
            "wrong-parent": {"parentEventId": "other-controller"},
            "conflicting-parent-frame": {"parentFrameId": "other-frame"},
            "same-indexed-frame": {"frameId": "enter-frame"},
            "wrong-namespace-method": {"symbol": "org.example.BankAccountResource.createBankAccount"},
            "wrong-method": {"symbol": "BankAccountResource.updateBankAccount"},
            "wrong-throw-source": {"source": {"path": "other/BankAccountResource.java", "status": "matched",
                                              "startLine": 47}, "sourceBinding": "verified"},
            "missing-throw-event": {"eventId": None},
            "async-parent": {"asyncParentEventId": "other-controller"},
        }
        for label, fields in cases.items():
            with self.subTest(label=label):
                rule, root, _, throwing = self.bank_exception()
                throwing.update(fields)
                problems, _, _ = evidence.inspect(root, rule, 400, recording_id="allocated-recording")
                self.assertEqual(problems, [evidence.EXCEPTION_LINK_UNOBSERVED])

    def test_controller_exception_rejects_unrelated_nested_or_ambiguous_events(self):
        for mode in ("duplicate-entry-id", "duplicate-throw-id", "two-throws", "two-anchors",
                     "nested-same-symbol", "unordered"):
            with self.subTest(mode=mode):
                rule, root, anchor, throwing = self.bank_exception()
                if mode == "duplicate-entry-id":
                    root["events"].append({"kind": "recording_event_kind:frame_exit", "eventId": anchor["eventId"]})
                elif mode == "duplicate-throw-id":
                    root["events"].append({"kind": "recording_event_kind:frame_exit", "eventId": throwing["eventId"]})
                elif mode == "two-throws":
                    root["events"].append(dict(throwing, eventId="another-throw"))
                elif mode == "two-anchors":
                    root["events"].insert(2, dict(anchor, eventId="another-entry"))
                elif mode == "nested-same-symbol":
                    root["events"].insert(2, dict(anchor, symbol="OtherService.execute", eventId="inner"))
                    throwing["parentEventId"] = "inner"
                else:
                    root["events"][1:] = [throwing, anchor]
                problems, _, _ = evidence.inspect(root, rule, 400, recording_id="allocated-recording")
                self.assertEqual(problems, [evidence.EXCEPTION_LINK_UNOBSERVED])

    def test_controller_exception_cannot_credit_an_unbound_recording_detail(self):
        for identity in ("another-recording", None):
            with self.subTest(identity=identity):
                rule, root, _, _ = self.bank_exception()
                root["recordingId"] = identity
                self.assertEqual(evidence.inspect(root, rule, 400, recording_id="allocated-recording"),
                                 (["recording-detail-incomplete"], False, False))

    def test_controller_exception_rejects_wrong_route_source_and_gaps(self):
        for mode in ("wrong-route", "extra-route-less-root", "wrong-source", "missing-source",
                     "source-binding", "gap", "incomplete", "incomplete-page"):
            with self.subTest(mode=mode):
                rule, root, anchor, _ = self.bank_exception()
                if mode == "wrong-route":
                    root["events"][0]["symbol"] = "http.request POST /api/other"
                elif mode == "extra-route-less-root":
                    root["events"].append({"kind": "recording_event_kind:request_update",
                                           "symbol": "http.request POST"})
                elif mode == "wrong-source":
                    anchor["source"]["path"] = "other/BankAccountResource.java"
                elif mode == "missing-source":
                    anchor["source"] = None
                elif mode == "source-binding":
                    anchor["sourceBinding"] = "class_bytes_mismatch"
                elif mode == "gap":
                    root["events"].append({"kind": "recording_event_kind:gap", "gap": {"count": "1"}})
                elif mode == "incomplete":
                    root["incompleteEvidence"] = ["gap_event_sequence:3"]
                else:
                    root["nextCursor"] = "unread-page"
                problems, _, _ = evidence.inspect(root, rule, 400, recording_id="allocated-recording")
                self.assertIn(evidence.EXCEPTION_LINK_UNOBSERVED, problems)
                self.assertNotIn(evidence.EXCEPTION_TYPE_UNOBSERVED, problems)

    def test_inherited_crud_needs_exact_declaration_and_parent_chain(self):
        rule = evidence.EXPECT["account-create-read-roundtrip"][1]
        path = "src/main/java/io/github/jhipster/sample/web/rest/BankAccountResource.java"
        handler = {"kind": "recording_event_kind:frame_enter", "symbol": "BankAccountResource.createBankAccount",
                   "eventId": "controller", "sourceBinding": "observed_unattested",
                   "source": {"status": "matched", "path": path, "startLine": 47}}
        other = {"kind": "recording_event_kind:frame_enter", "symbol": "OtherService.perform", "eventId": "other"}
        for symbol, parent in (("com.example.CrudRepository.save", "controller"),
                               ("io.github.jhipster.sample.other.CrudRepository.save", "controller"),
                               ("io.github.jhipster.sample.repository.BankAccountRepository.save", "controller"),
                               (evidence.CRUD + "save", "other"), (evidence.CRUD + "save", None)):
            with self.subTest(symbol=symbol, parent=parent):
                row = recording("POST", evidence.BANK, 201, [handler, other,
                    {"kind": "recording_event_kind:frame_enter", "symbol": symbol, "parentEventId": parent}])
                problems = evidence.inspect(row, rule, 201)[0]
                self.assertIn(f"repository-declaration-unobserved-in-handler({evidence.CRUD}save)", problems)

    def test_admin_find_all_uses_the_sourced_service_and_exact_paging_declaration(self):
        rule = evidence.EXPECT["admin-and-user-authentication"][2]
        parent = {"kind": "recording_event_kind:frame_enter", "symbol": "UserResource.getAllUsers", "eventId": "ctrl",
                  "sourceBinding": "observed_unattested", "source": {"status": "matched",
                  "path": "src/main/java/io/github/jhipster/sample/web/rest/UserResource.java", "startLine": 155}}
        service = {"kind": "recording_event_kind:frame_enter", "symbol": "UserService.getAllManagedUsers",
                   "eventId": "service", "parentEventId": "ctrl", "sourceBinding": "observed_unattested",
                   "source": {"status": "matched", "path": "src/main/java/io/github/jhipster/sample/service/UserService.java",
                              "startLine": 251}}
        repo = {"kind": "recording_event_kind:frame_enter", "symbol": evidence.PAGE_FIND_ALL, "parentEventId": "service"}
        row = recording("GET", evidence.USERS, 200, [parent, service, repo])
        problem = f"repository-declaration-unobserved-in-handler({evidence.PAGE_FIND_ALL})"
        self.assertNotIn(problem, evidence.inspect(row, rule, 200)[0])
        repo["parentEventId"] = "ctrl"
        self.assertIn(problem, evidence.inspect(row, rule, 200)[0])

    def test_group_recording_evidence_does_not_prove_principal_attribution(self):
        sid = "burst"
        rule = evidence.expect(None, "GET", evidence.USERS, (200,))
        sent = [(sid, "GET", evidence.USERS)]
        details = {"real-recording": recording("GET", evidence.USERS, 200)}
        exp = {sid: [rule]}
        boundary = xinstr.burst_accounting(details, sent, exp, {})
        phase = xinstr.OrderedPhase("burst", [{"id": sid, "requests": [request("user", "GET", evidence.USERS, 200)]}],
                                   boundary)
        verdicts, groups, _, _, _ = evidence.judge(details, exp, [phase], [])
        group, = groups
        self.assertTrue(group["passed"])
        self.assertEqual(group["recordingsWithStatus"], 1)
        self.assertFalse(verdicts[sid]["passed"])
        item, = verdicts[sid]["expectations"]
        self.assertEqual(item["problems"], ["individual-request-and-principal-attribution-unobserved"])

    def test_framework_validation_needs_root_and_status_without_fake_controller_source(self):
        rule = evidence.EXPECT["account-validation-errors"][1]
        row = recording("POST", evidence.BANK, 400)
        self.assertEqual(evidence.inspect(row, rule, 400), ([], True, False))
        row["events"].append({"kind": "recording_event_kind:frame_enter", "symbol": evidence.BANK_CREATE})
        self.assertIn("refused-controller-identity-unresolved", evidence.inspect(row, rule, 400)[0])
        row["events"][-1]["symbol"] = evidence.REST_PACKAGE + evidence.BANK_CREATE
        self.assertIn("unexpected-controller-frame", evidence.inspect(row, rule, 400)[0])

    def test_probe_sends_canaries_separately_and_preserves_denial_status_as_external(self):
        canaries = {"authorization-header": "synthetic-header", "cookie-header": "synthetic-cookie",
                    "query-token": "synthetic query", "json-body-password": "synthetic-password"}
        with mock.patch.object(xcamp, "http_request", return_value={"status": 401}) as send:
            probes = evidence.inject_probes("http://127.0.0.1:1", canaries)
        auth, body = send.call_args_list
        self.assertEqual(auth.args[1:], ("GET", evidence.ACCOUNT))
        self.assertEqual(auth.kwargs["headers"], {"Authorization": canaries["authorization-header"]})
        self.assertNotIn("Authorization", body.kwargs["headers"])
        self.assertEqual(body.args[1:], ("POST", evidence.AUTH + "?xt_token=synthetic%20query"))
        self.assertEqual(json.loads(body.kwargs["body"])["password"], canaries["json-body-password"])
        verdicts = evidence.judge_probes({}, [], probes)
        self.assertEqual([v["status"] for v in verdicts[:2]], [401, 401])
        self.assertTrue(all(not v["passed"] for v in verdicts))

    def test_installed_payload_rejects_same_size_analyzer_dependency_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            harness = campaign_harness(root)
            prefix = root / "fresh prefix"
            current = prefix / "versions/0.0.1"
            paths = {
                "bin/xtrace": b"cli",
                "share/xtrace/packs/java/agent/xtrace-java-agent.jar": b"agent",
                "share/xtrace/analyzers/java/bin/xtrace-java-static": b"analyzer",
                "share/xtrace/analyzers/java/lib/dependency.jar": b"runtime one",
                "share/xtrace/VERSION": b"0.0.1\n",
                "install.sh": (PROJECT.parents[2] / "packaging/install.sh").read_bytes(),
            }
            for rel, data in paths.items():
                path = current / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o700)
            (prefix / "bin").mkdir()
            (prefix / "current").symlink_to("versions/0.0.1", target_is_directory=True)
            (prefix / "bin/xtrace").symlink_to("../current/bin/xtrace")
            inventory = "share/xtrace/payload.sha256"
            paths[inventory] = "".join(f"{xcamp.sha256_bytes(data)}  {rel}\n" for rel, data in paths.items()).encode()
            (current / inventory).write_bytes(paths[inventory])
            sha = "c" * 40
            manifest = {"schema": "xtrace-package-manifest/1", "platform": "linux-x86_64", "version": "0.0.1",
                        "sourceCommit": sha, "files": [{"path": rel, "sha256": xcamp.sha256_bytes(data), "size": len(data)}
                                                      for rel, data in paths.items()]}
            (current / "share/xtrace/PACKAGE-MANIFEST.json").write_text(json.dumps(manifest))
            archive = root / "candidate.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(current, arcname="xtrace-0.0.1-linux-x86_64")
            digest = xcamp.sha256_file(archive)
            _, _, proof = harness.installed_package(prefix, archive, digest, sha)
            self.assertEqual(proof["payloadFilesVerified"], len(paths) - 1)
            self.assertEqual(proof["payloadInventorySha256"], xcamp.sha256_bytes(paths[inventory]))
            (current / "share/xtrace/analyzers/java/lib/dependency.jar").write_bytes(b"runtime two")
            with self.assertRaisesRegex(ValueError, "installer did not verify"):
                harness.installed_package(prefix, archive, digest, sha)

    def test_baseline_requires_same_job_actual_jvm_jar_and_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            harness = campaign_harness(root)
            tracked = json.loads((PROJECT / "baseline-summary.json").read_text())
            pin = {**tracked["pin"], "git": {"head": tracked["pin"]["sha"], "trackedClean": True},
                   "hostRunBindingSha256": "a" * 64, "hostJava": {"properties": {"os.name": "Linux", "os.arch": "amd64"},
                                                                  "executableSha256": "b" * 64}}
            rows = [dict(row, passed=True, requests=[{}] * row["requests"], checks=[{"passed": True}] * row["checks"])
                    for row in tracked["scenarios"]]
            doc = {"project": "jhipster", "appMode": "host", "instrumented": False, "result": "passed_baseline_only",
                   "pin": pin, "scenarios": rows}
            receipt = root / "receipt.json"
            receipt.write_text(json.dumps(doc))
            fingerprints, tracked_matches, digest = harness.checked_baseline(receipt, pin)
            self.assertEqual(len(fingerprints), 8)
            self.assertTrue(all(tracked_matches.values()))
            self.assertEqual(digest, xcamp.sha256_file(receipt))
            for key, replacement in (("hostRunBindingSha256", "d" * 64), ("jarSha256", "e" * 64),
                                     ("postgresImageDigest", "f" * 64), ("hostJava", {"properties": pin["hostJava"]["properties"],
                                                                                     "executableSha256": "f" * 64})):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    harness.checked_baseline(receipt, {**pin, key: replacement})
