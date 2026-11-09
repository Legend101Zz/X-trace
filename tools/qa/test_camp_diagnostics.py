import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_diagnostics as cd  # noqa: E402
import canary  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
RID = "01900000-0000-7000-8000-000000000001"
FRAME = "01900000-0000-7000-8000-000000000002"
PARENT = "01900000-0000-7000-8000-000000000003"
OTHER = "01900000-0000-7000-8000-000000000004"
STEPS = (*cd.INSTRUMENTED_STEPS, *cd.FLOW_SOURCES)


def detail(rid=RID, completion="partial"):
    return {"recordingId": rid, "status": completion, "completion": completion,
            "outcome": {"kind": "exception_propagated", "httpStatus": None,
                        "exception": {"message": "private exception text"}},
            "events": [
                {"kind": "recording_event_kind:request_update", "symbol": "http.request GET /owners/{ownerId}", "sequence": "1"},
                {"kind": "recording_event_kind:frame_enter", "sequence": "2", "frameId": FRAME, "parentFrameId": PARENT,
                 "symbol": "org.springframework.samples.petclinic.owner.OwnerController.showOwner", "line": 99,
                 "source": {"path": "/private/source/Owner.java", "startLine": 99, "excerpt": "private source text"}},
                {"kind": "recording_event_kind:line_cursor", "sequence": "3", "frameId": FRAME, "parentFrameId": PARENT,
                 "symbol": "org.springframework.samples.petclinic.owner.OwnerController.showOwner", "line": 103,
                 "bindings": [{"name": "lastName", "value": "private binding text"}]}]}


def save(root, doc, sub=""):
    path = root / sub / ("recording-" + doc["recordingId"] + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
    return path


def summary(path, failed=()):
    path.write_text(json.dumps({"steps": [{"step": s, "status": "fail" if s in failed else "pass"} for s in STEPS]}))


class Projection(unittest.TestCase):
    def test_only_structure_is_copied_and_a_method_extent_is_never_a_line(self):
        doc = detail()
        doc.update({"headers": {"Authorization": "private header text"}, "body": "private body text"})
        row = cd.recording(doc)
        self.assertEqual(row["recordingId"], RID)
        self.assertEqual((row["status"], row["completion"]), ("partial", "partial"))
        self.assertEqual(row["routeTemplate"], "/owners/{ownerId}")
        self.assertEqual(row["outcome"], {"kind": "exception_propagated", "httpStatus": None})
        self.assertEqual(row["eventCountsByKind"], {"frame_enter": 1, "line_cursor": 1, "request_update": 1})
        self.assertEqual(row["eventsObserved"], 3)
        self.assertEqual(row["eventsOmitted"], 0)
        for event in row["events"]:
            self.assertEqual(set(event), {"kind", "sequence", "frameId", "parentFrameId", "symbol", "line"})
        self.assertEqual(row["events"][1], {"kind": "frame_enter", "sequence": "2", "frameId": FRAME,
                                          "parentFrameId": PARENT,
                                          "symbol": "withheld:controller:sha256:" + hashlib.sha256(
                                              doc["events"][1]["symbol"].encode()).hexdigest(), "line": None})
        self.assertEqual(row["events"][2]["line"], 103)
        text = json.dumps(row)
        for forbidden in ("private", "headers", "body", "source", "bindings", "message"):
            self.assertNotIn(forbidden, text)

    def test_all_java_symbols_publish_only_a_layer_and_stable_hash(self):
        for symbol, layer in (
            ("org.springframework.samples.petclinic.owner.OwnerController.showOwner", "controller"),
            ("org.springframework.samples.petclinic.owner.OwnerService.find", "service"),
            ("org.springframework.samples.petclinic.owner.OwnerRepository.find", "repository"),
            ("org.springframework.samples.petclinic.Owner.aliceSmith", "other"),
        ):
            with self.subTest(symbol=symbol):
                self.assertEqual(cd.safe_symbol(symbol), f"withheld:{layer}:sha256:" + hashlib.sha256(symbol.encode()).hexdigest())
        for symbol in (
            "java.lang.String.length", "javax.sql.DataSource.getConnection",
            "jdk.proxy1.$Proxy0.findById", "org.springframework.web.servlet.DispatcherServlet.doDispatch",
            "org.hibernate.Session.find", "org.apache.catalina.core.ApplicationFilterChain.doFilter",
            "org.apache.coyote.Request.getMethod", "org.apache.tomcat.util.buf.MessageBytes.toString",
            "jakarta.servlet.http.HttpServlet.service", "java.lang.Object.<init>", "java.lang.String.<clinit>",
        ):
            with self.subTest(symbol=symbol):
                self.assertEqual(cd.safe_symbol(symbol), "withheld:framework:sha256:" + hashlib.sha256(symbol.encode()).hexdigest())
        for symbol in ("alice.smith", "com.acme.customer.AliceSmith",
                       "org.springframeworkPrivate.AliceSmith.read", "javaPrivate.AliceSmith.read",
                       "org.apache.unlisted.AliceSmith.read", "OwnerController.showOwner"):
            with self.subTest(symbol=symbol):
                withheld = cd.safe_symbol(symbol)
                self.assertRegex(withheld, r"^withheld:other:sha256:[0-9a-f]{64}$")
                self.assertEqual(withheld, cd.safe_symbol(symbol))
                self.assertNotIn(symbol, withheld)
        self.assertNotEqual(cd.safe_symbol("alice.smith"), cd.safe_symbol("alice.jones"))

    def test_http_metadata_keeps_its_exact_allowlist(self):
        for route in cd.ROUTES:
            symbol = "http.request GET " + route
            self.assertEqual(cd.safe_symbol(symbol), symbol)
        for symbol in ("http.response 200", "http.response 599", "http.response unavailable"):
            self.assertEqual(cd.safe_symbol(symbol), symbol)
        for symbol in ("http.response 600", "http.response 200 private", "http.request GET /owners/aliceSmith"):
            self.assertIsNone(cd.safe_symbol(symbol))

    def test_unavailable_and_untrusted_metadata_are_not_inferred(self):
        doc = {"recordingId": "user-data", "status": "secret", "completion": "secret", "outcome": {"kind": "secret", "httpStatus": True},
               "events": [{"kind": "secret", "sequence": "secret", "frameId": "private-path", "parentFrameId": {"value": "secret"},
                           "symbol": "GET /private/data?token=secret", "line": "15"},
                          {"kind": "response", "symbol": "http.response 500"}]}
        row = cd.recording(doc)
        for field in ("recordingId", "status", "completion", "routeTemplate"):
            self.assertIsNone(row[field])
        self.assertEqual(row["outcome"], {"kind": None, "httpStatus": None})  # no response-event fallback
        self.assertEqual(row["events"][0], {"kind": "unrecognized", "sequence": None, "frameId": None,
                                          "parentFrameId": None, "symbol": None, "line": None})
        for symbol in ("http.request GET /owners/123", "http.request GET /owners?lastName=secret",
                       "http.request GET /private/file", "exception: private message", "x" * 257):
            self.assertIsNone(cd.safe_symbol(symbol))
        empty = cd.recording({})
        self.assertFalse(empty["eventsAvailable"])
        self.assertEqual(empty["eventCountsByKind"], {})
        self.assertFalse(cd.recording({"_http": 500, "events": []})["eventsAvailable"])

    def test_event_counts_include_rows_omitted_by_the_cap(self):
        doc = detail()
        doc["events"] = [doc["events"][2]] * (cd.MAX_EVENTS_PER_RECORDING + 2)
        row = cd.recording(doc)
        self.assertEqual(row["eventCountsByKind"], {"line_cursor": cd.MAX_EVENTS_PER_RECORDING + 2})
        self.assertEqual(len(row["events"]), cd.MAX_EVENTS_PER_RECORDING)
        self.assertEqual(row["eventsOmitted"], 2)


class Artifacts(unittest.TestCase):
    def test_non_canary_private_symbols_are_withheld_in_scanned_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            doc = detail()
            # Non-canary suffixes under every formerly trusted namespace, for
            # every event kind: neither syntax nor a package proves identity.
            private_symbols = ["alice.smith"] + [prefix + ".Owner.privateCustomerName" for prefix in (
                "org.springframework.samples.petclinic", "java", "javax", "jdk",
                "org.springframework", "org.hibernate", "org.apache.catalina",
                "org.apache.coyote", "org.apache.tomcat", "jakarta")]
            private_symbols += ["java.alice.smith", "org.springframework.samples.petclinic.Owner.aliceSmith"]
            doc["events"] = [{"kind": kind, "symbol": symbol}
                             for symbol in private_symbols for kind in sorted(cd.KINDS)]
            for index, symbol in enumerate(private_symbols):
                save(root, {**doc, "recordingId": f"01900000-0000-7000-8000-{index:012d}",
                            "events": [event for event in doc["events"] if event["symbol"] == symbol]}, "instrumented/api")
            summary(root / "summary.json", ("recordings-per-scenario",))
            canaries = canary.make_canaries(lambda: "0123456789abcdef")
            out = root / "out"
            cd.write_failures(root / "summary.json", root / "instrumented", root, out, canaries)
            report = json.loads((out / "recordings-per-scenario.json").read_text())
            events = [event for row in report["recordings"] for event in row["events"]]
            self.assertEqual(len(events), len(private_symbols) * len(cd.KINDS))
            for raw in doc["events"]:
                event = cd.recording({"events": [raw]})["events"][0]
                self.assertRegex(event["symbol"], r"^withheld:(?:framework|other):sha256:[0-9a-f]{64}$")
                self.assertEqual(event["symbol"].rsplit(":", 1)[1], hashlib.sha256(raw["symbol"].encode()).hexdigest())
            for event, raw in zip(events, doc["events"]):
                self.assertEqual(event["symbol"], cd.safe_symbol(raw["symbol"]))
            for path in out.glob("*.json"):
                text = path.read_text()
                for private_symbol in private_symbols:
                    self.assertNotIn(private_symbol, text)
                for suffix in ("privateCustomerName", "aliceSmith", "alice.smith"):
                    self.assertNotIn(suffix, text)
            scan = canary.run_scan(canaries, {"recording-diagnostics": [out]}, {"recording-diagnostics": 1})
            self.assertTrue(scan["clean"])

    def test_every_failed_recording_judge_gets_a_skeleton_and_passing_steps_do_not(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            instrumented, flows, out = root / "instrumented", root / "flows", root / "out"
            save(instrumented, detail(), "api")
            for sources in cd.FLOW_SOURCES.values():
                save(flows, detail(), sources[0])
            summary(root / "summary.json", STEPS)
            count = cd.write_failures(root / "summary.json", instrumented, flows, out, {"token": "XTsynthetic-canary"})
            self.assertEqual(count, len(STEPS))
            for step in STEPS:
                report = json.loads((out / f"{step}.json").read_text())
                self.assertEqual(report["step"], step)
                self.assertTrue(report["evidenceAvailable"])
                self.assertEqual(report["recordings"][0]["recordingId"], RID)
            summary(root / "summary.json")
            clean = root / "clean"
            self.assertEqual(cd.write_failures(root / "summary.json", instrumented, flows, clean, {"token": "XTsynthetic-canary"}), 0)
            self.assertEqual([p.name for p in clean.iterdir()], ["index.json"])

    def test_missing_or_unreadable_evidence_is_explicit_for_each_failed_step(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            # A missing summary also requires diagnostics, never a silent success.
            cd.write_failures(root / "missing", root / "missing", root / "missing", root / "out", {"token": "XTsynthetic-canary"})
            for step in STEPS:
                report = json.loads((root / "out" / f"{step}.json").read_text())
                self.assertFalse(report["evidenceAvailable"])
                self.assertEqual(report["recordings"], [])
            raw = root / "api"
            raw.mkdir()
            (raw / "recording-broken.json").write_text("not JSON")
            report = cd.skeleton("frame-values", [raw], [])
            self.assertEqual(report["filesUnreadable"], 1)
            self.assertFalse(report["evidenceAvailable"])

    def test_preexisting_recordings_are_excluded_but_restart_keeps_both_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            summary(root / "summary.json", ("record-stop-flow", "restart-reopen", "active-line-frames"))
            for sub in ("api-before-record-stop", "api-record-stop", "api-focused", "api-focused/before"):
                save(root, detail(OTHER, "complete"), sub)
            for sub in ("api-record-stop", "api-focused", "api-before-restart"):
                save(root, detail(), sub)
            # A stale live probe must not crowd out the final snapshot for this id.
            save(root, detail(completion="complete"), "api-focused/owner")
            save(root, detail(completion="complete"), "api-after-restart")
            cd.write_failures(root / "summary.json", root, root, root / "out", {"token": "XTsynthetic-canary"})
            for step in ("record-stop-flow", "active-line-frames"):
                rows = json.loads((root / "out" / f"{step}.json").read_text())["recordings"]
                self.assertEqual([r["recordingId"] for r in rows], [RID])
            rows = json.loads((root / "out/restart-reopen.json").read_text())["recordings"]
            self.assertEqual([(r["snapshot"], r["completion"]) for r in rows], [(0, "complete"), (1, "partial")])

    def test_caps_are_explicit_and_counts_survive_global_and_byte_limits(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            doc = detail()
            doc["events"] = [doc["events"][2]] * 10
            for i in range(4):
                save(root, {**doc, "recordingId": f"01900000-0000-7000-8000-{i:012d}"})
            with mock.patch.object(cd, "MAX_RECORDINGS", 2), mock.patch.object(cd, "MAX_EVENTS", 3):
                report = cd.skeleton("frame-values", [root], [])
            self.assertEqual(len(report["recordings"]), 2)
            self.assertEqual(report["recordingsOmitted"], 2)
            self.assertEqual(sum(len(r["events"]) for r in report["recordings"]), 3)
            self.assertEqual(sum(r["eventsOmitted"] for r in report["recordings"]), 17)
            for row in report["recordings"]:
                self.assertEqual(row["eventCountsByKind"], {"line_cursor": 10})
            with mock.patch.object(cd, "MAX_BYTES", 3000):
                report = cd.skeleton("frame-values", [root], [])
                self.assertLessEqual(len(cd.encoded(report)), 3000)
                self.assertGreater(sum(r["eventsOmitted"] for r in report["recordings"]), 0)
            with mock.patch.object(cd, "MAX_FILES", 1):
                report = cd.skeleton("frame-values", [root], [])
                self.assertTrue(report["inputTruncated"])
                self.assertEqual(len(report["recordings"]), 1)

    def test_canaries_are_withheld_even_from_valid_symbols_and_scanner_covers_the_skeleton(self):
        canaries = canary.make_canaries(lambda: "0123456789abcdef")
        # Keep exercising the output scrub independently of symbol hashing.
        canaries["recording-id"] = RID
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            doc = detail()
            # A canary is valid Java identifier text; syntax checks alone cannot protect this field.
            doc["events"][2]["symbol"] = "org.springframework.samples.petclinic.Owner." + canaries["query-token"]
            for event in doc["events"]:
                event["bindings"] = [{"value": v} for v in canaries.values()]
                event["interaction"] = {"headers": list(canaries.values()), "path": "/private/user/data"}
            save(root, doc, "instrumented/api")
            summary(root / "summary.json", ("recordings-per-scenario",))
            out = root / "out"
            cd.write_failures(root / "summary.json", root / "instrumented", root, out, canaries)
            report = json.loads((out / "recordings-per-scenario.json").read_text())
            self.assertEqual(report["recordings"][0]["events"][2]["symbol"],
                             "withheld:other:sha256:" + hashlib.sha256(doc["events"][2]["symbol"].encode()).hexdigest())
            self.assertIsNone(report["recordings"][0]["recordingId"])
            self.assertEqual(report["stringsWithheld"], 1)
            locations = {"recording-diagnostics": [out]}
            self.assertTrue(canary.run_scan(canaries, locations, {"recording-diagnostics": 1})["clean"])
            # The same surface must fail the existing scan if a regression emits a canary.
            (out / "planted.json").write_text(json.dumps({"symbol": canaries["query-token"]}))
            scan = canary.run_scan(canaries, locations, {"recording-diagnostics": 1})
            self.assertFalse(scan["clean"])
            self.assertEqual({h["locationClass"] for h in scan["hits"]}, {"recording-diagnostics"})

    def test_oversized_and_symlink_inputs_are_not_copied(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            path = save(root, detail())
            with mock.patch.object(cd, "MAX_INPUT_BYTES", 16):
                self.assertIsNone(cd.load(path))
            linked = root / "linked"
            linked.symlink_to(root, target_is_directory=True)
            self.assertIsNone(cd.load(linked / path.name))

    def test_workflow_cli_requires_canaries_and_writes_to_the_requested_artifact_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            summary(root / "summary.json", ("recordings-per-scenario",))
            save(root, detail(), "instrumented/api")
            argv = ["camp_diagnostics.py", "--summary", str(root / "summary.json"),
                    "--instrumented", str(root / "instrumented"), "--flows", str(root / "flows"),
                    "--out", str(root / "out"), "--canaries", str(root / "canaries.json")]
            with mock.patch.object(sys, "argv", argv):
                self.assertEqual(cd.main(), 1)
                self.assertFalse((root / "out").exists())
                (root / "canaries.json").write_text(json.dumps(canary.make_canaries()))
                self.assertEqual(cd.main(), 0)
            report = json.loads((root / "out/recordings-per-scenario.json").read_text())
            self.assertEqual(report["recordings"][0]["recordingId"], RID)


class Workflow(unittest.TestCase):
    def test_diagnostics_run_before_scanning_and_are_in_the_exact_upload_tree(self):
        text = (ROOT / ".github/workflows/campaigns.yml").read_text()
        start = text.index("      - name: Recording skeletons")
        scan = text.index("      - name: Privacy canary scan")
        final = text.index("      - name: Final privacy re-scan")
        self.assertLess(start, scan)
        self.assertLess(scan, final)
        block = text[start:scan]
        self.assertIn("always()", block)
        self.assertIn('--step recording-diagnostics -- python3 -B tools/qa/camp_diagnostics.py', block)
        self.assertIn('--out "$CAMP_OUT/recording-diagnostics"', block)
        self.assertIn('--canaries "$RUNNER_TEMP/priv/canaries.json"', block)
        self.assertIn("--require recording-diagnostics:1", text)
        self.assertIn('--loc "recording-diagnostics=$CAMP_OUT/recording-diagnostics"', text)
        self.assertIn('--loc "upload-tree=$CAMP_OUT"', text[final:])
        self.assertIn("path: ${{ runner.temp }}/camp-out", text[final:])


if __name__ == "__main__":
    unittest.main()
