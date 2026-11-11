import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_exports as ce  # noqa: E402
import canary  # noqa: E402


CATALOG = {"persisted": True, "catalogRevisionId": "rev", "changes": {"added": 1, "unknown": 0}, "result": {"operations": [{}]}}
COUNTS = {"openapi": 1, "postman": 1, "curl": 1}


def write_bundle(dest):
    dest.mkdir()
    payloads = {
        "openapi.yaml": 'openapi: "3.1.0"\npaths:\n  "/vets":\n    get:\n      operationId: "getVets"\n',
        "collection.postman.json": json.dumps({"item": [{"request": {"method": "GET"}}]}),
        "curl/all.sh": "#!/bin/sh\nprintf '%s\\n' 'sh get-vets.sh'\n",
        "curl/get-vets.sh": "#!/bin/sh\ncurl --request GET \"${BASE_URL}/vets\"\n",
    }
    for name, content in payloads.items():
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    manifest = {"revision_id": "rev", "operation_count": 1, "omissions": [],
                "formats": [{"format": fmt, "operation_count": count} for fmt, count in COUNTS.items()],
                "files": [{"path": name, "bytes": len(content.encode()), "blake3": "0" * 64}
                          for name, content in payloads.items()]}
    (dest / "manifest.json").write_text(json.dumps(manifest))
    (dest / "README.md").write_text("# X-trace developer bundle\n")


def update_manifest(dest, change):
    path = dest / "manifest.json"
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc))


def refresh_sizes(doc, dest):
    for row in doc["files"]:
        row["bytes"] = (dest / row["path"]).stat().st_size


class T(unittest.TestCase):
    def test_judge(self):
        self.assertEqual(ce.judge({f: (9, 0) for f in ce.ALL_FORMATS})[0], "not-implemented")
        self.assertEqual(ce.judge({f: (0, 10) for f in ce.ALL_FORMATS})[0], "pass")
        self.assertEqual(ce.judge({"openapi": (0, 0), "curl": (0, 5)})[0], "fail")  # exit 0 with no output is not a pass
        self.assertEqual(ce.judge({"openapi": (9, 0), "curl": (0, 5)})[0], "fail")  # mixed: not wholly unimplemented
        self.assertEqual(ce.judge({"openapi": (2, 0)})[0], "fail")

    def test_cli_with_fake_binary(self):
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            exe = td / "fake"
            exe.write_text("#!/bin/sh\n"
                           "if [ \"$1\" = scan ]; then echo '{\"persisted\":true,\"catalogRevisionId\":\"rev\",\"result\":{\"operations\":[{}]}}'; exit 0; fi\n"
                           "while [ $# -gt 0 ]; do [ \"$1\" = --output ] && out=$2; [ \"$1\" = --format ] && fmt=$2; shift; done\n"
                           "[ \"$fmt\" = bundle ] && exit 9\necho data > \"$out\"\n")
            exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            summ = td / "s.json"
            subprocess.run([sys.executable, "-B", str(pathlib.Path(ce.__file__)), "--xtrace", str(exe), "--project-dir", str(td),
                            "--analyzer", "real-analyzer", "--out", str(td / "o"), "--file", str(summ), "--project", "p"], check=True, capture_output=True)
            steps = {s["step"]: s for s in json.loads(summ.read_text())["steps"]}
            step = steps["export-formats"]
            self.assertEqual(steps["export-catalog-scan"]["status"], "pass")
            self.assertEqual(steps["export-bundle"]["status"], "not-implemented")
            self.assertEqual((step["step"], step["status"]), ("export-formats", "fail"))

    def test_scan_is_a_required_observed_prerequisite(self):
        for code, doc in ((2, {}), (0, {}), (0, {"persisted": True, "catalogRevisionId": "r", "result": {"operations": []}})):
            with tempfile.TemporaryDirectory() as td, mock.patch.object(ce.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], code, json.dumps(doc))
                steps = ce.run_exports("xtrace", "project", "analyzer", pathlib.Path(td))
                self.assertEqual(run.call_count, 1, "failed scan must not export from a stale catalog")
                self.assertEqual(run.call_args.args[0][1], "scan")
                self.assertIn("spring-mvc", run.call_args.args[0])
                self.assertIn("analyzer", run.call_args.args[0])
                self.assertEqual(dict((n, st) for n, st, _ in steps)["export-formats"], "fail")
                self.assertEqual(dict((n, st) for n, st, _ in steps)["export-bundle"], "fail")
        self.assertEqual(ce.judge({})[0], "fail")

    def test_scan_precedes_every_export_and_stale_files_fail(self):
        calls = []
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td)
            (out / "export-openapi").write_text("stale")
            def execute(args, **kwargs):
                calls.append(args[1])
                if args[1] == "scan":
                    return subprocess.CompletedProcess(args, 0, json.dumps({"persisted": True, "catalogRevisionId": "r", "result": {"operations": [{}]}}))
                fmt = args[args.index("--format") + 1]
                if fmt == "bundle":
                    return subprocess.CompletedProcess(args, 9, "")
                pathlib.Path(args[-1]).write_text("export")
                return subprocess.CompletedProcess(args, 0, "")
            with mock.patch.object(ce.subprocess, "run", side_effect=execute):
                steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", out)}
            self.assertEqual(calls, ["scan", "export", "export", "export"])
            self.assertEqual(steps["export-openapi"], "fail")
            self.assertEqual(steps["export-formats"], "fail")
            self.assertEqual(steps["export-bundle"], "not-implemented")

    def test_successful_bundle_is_exported_and_judged_with_every_format(self):
        calls = []
        with tempfile.TemporaryDirectory() as td:
            def execute(args, **kwargs):
                calls.append(args)
                if args[1] == "scan":
                    return subprocess.CompletedProcess(args, 0, json.dumps({"data": CATALOG}, indent=2))
                fmt = args[args.index("--format") + 1]
                dest = pathlib.Path(args[-1])
                if fmt == "bundle":
                    write_bundle(dest)
                else:
                    dest.mkdir()
                    (dest / "payload").write_text("export")
                return subprocess.CompletedProcess(args, 0, json.dumps({"data": {"written": True, "operationCount": 1}}, indent=2))
            with mock.patch.object(ce.subprocess, "run", side_effect=execute):
                steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", pathlib.Path(td))}
            self.assertEqual(len(calls), 5)
            self.assertEqual(steps["export-bundle"], "pass")
            self.assertEqual(steps["export-formats"], "pass")
            self.assertTrue(all("--json" in call for call in calls))
            for call in calls[1:]:
                self.assertEqual(call[call.index("--revision") + 1], "rev")

    def test_bundle_uses_persisted_revision_counts_instead_of_the_static_scan_subset(self):
        with tempfile.TemporaryDirectory() as td:
            dest = pathlib.Path(td) / "bundle"
            write_bundle(dest)
            # One runtime-only operation was retained in the revision; this scan saw none.
            catalog = {**CATALOG, "result": {"operations": []}}
            self.assertEqual(ce.judge_bundle(dest, catalog, COUNTS)[0], "pass")
            # Without a measured full-revision count the static subset cannot prove equality.
            for changes in (None, {}, {"added": True}, {"added": -1}):
                self.assertEqual(ce.judge_bundle(dest, {**catalog, "changes": changes}, COUNTS)[0], "fail")
            self.assertEqual(ce.judge_bundle(dest, {**catalog, "changes": {"added": 1, "unknown": 1}}, COUNTS)[0], "fail")

    def test_cli_counts_match_bundle_renderers_after_openapi_route_collision(self):
        counts = {"openapi": 1, "postman": 2, "curl": 2}
        catalog = {**CATALOG, "changes": {"added": 2}}
        with tempfile.TemporaryDirectory() as td:
            def execute(args, **kwargs):
                if args[1] == "scan":
                    return subprocess.CompletedProcess(args, 0, json.dumps({"data": catalog}))
                fmt = args[args.index("--format") + 1]
                dest = pathlib.Path(args[-1])
                if fmt == "bundle":
                    write_bundle(dest)
                    (dest / "collection.postman.json").write_text(json.dumps({"item": [{"request": {}}, {"request": {}}]}))
                    recipe = dest / "curl/get-vets-other-scope.sh"
                    recipe.write_text((dest / "curl/get-vets.sh").read_text())

                    def amend(m):
                        m["operation_count"] = 2
                        m["formats"] = [{"format": f, "operation_count": n} for f, n in counts.items()]
                        omission = {"operation_id": "other-scope", "what": "operation", "reason": "duplicate_method_path_of:first"}
                        m["formats"][0]["omissions"] = [omission]
                        m["omissions"] = [{**omission, "what": "openapi:operation"}]
                        m["files"].append({"path": "curl/" + recipe.name, "bytes": recipe.stat().st_size, "blake3": "0" * 64})
                        refresh_sizes(m, dest)
                    update_manifest(dest, amend)
                else:
                    dest.mkdir()
                    (dest / "payload").write_text("export")
                # The CLI's bundle-wide count is 2, but OpenAPI rendered just 1.
                return subprocess.CompletedProcess(args, 0, json.dumps({"data": {"written": True, "operationCount": counts.get(fmt, 2)}}))
            with mock.patch.object(ce.subprocess, "run", side_effect=execute):
                steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", pathlib.Path(td))}
            self.assertEqual(steps["export-bundle"], "pass")
            self.assertEqual(steps["export-formats"], "pass")

    def test_missing_noninteger_or_unwritten_cli_count_cannot_pass_bundle_comparison(self):
        for report in ({"written": True}, {"written": True, "operationCount": True},
                       {"written": True, "operationCount": "1"}, {"written": False, "operationCount": 1}):
            with self.subTest(report=report), tempfile.TemporaryDirectory() as td:
                def execute(args, **kwargs):
                    if args[1] == "scan":
                        return subprocess.CompletedProcess(args, 0, json.dumps(CATALOG))
                    dest = pathlib.Path(args[-1])
                    if args[args.index("--format") + 1] == "bundle":
                        write_bundle(dest)
                    else:
                        dest.mkdir()
                        (dest / "payload").write_text("export")
                    return subprocess.CompletedProcess(args, 0, json.dumps(report))
                with mock.patch.object(ce.subprocess, "run", side_effect=execute):
                    steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", pathlib.Path(td))}
                self.assertEqual(steps["export-bundle"], "fail")
                self.assertEqual(steps["export-formats"], "fail")

    def test_bundle_failure_names_the_failed_contract_without_payload_values(self):
        with tempfile.TemporaryDirectory() as td:
            dest = pathlib.Path(td) / "bundle"
            write_bundle(dest)
            update_manifest(dest, lambda m: m.update(revision_id="private-catalog-value"))
            status, note = ce.judge_bundle(dest, CATALOG, COUNTS)
            self.assertEqual(status, "fail")
            self.assertIn("count or revision", note)
            self.assertNotIn("private-catalog-value", note)

    def test_bundle_rejects_missing_empty_extra_stale_or_linked_files(self):
        changes = [
            lambda d: (d / "README.md").unlink(),
            lambda d: (d / "openapi.yaml").write_text(""),
            lambda d: (d / "unlisted.txt").write_text("unexpected"),
            lambda d: (d / "curl/get-vets.sh").unlink(),
            lambda d: (d / "curl/get-vets.sh").write_text("stale recipe"),
            lambda d: (d / "linked").symlink_to(d / "README.md"),
        ]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as td:
                dest = pathlib.Path(td) / "bundle"
                write_bundle(dest)
                self.assertEqual(ce.judge_bundle(dest, CATALOG, COUNTS)[0], "pass")
                change(dest)
                self.assertEqual(ce.judge_bundle(dest, CATALOG, COUNTS)[0], "fail")

    def test_valid_preexisting_bundle_is_not_evidence_for_this_export(self):
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td)
            write_bundle(out / "export-bundle")
            def execute(args, **kwargs):
                if args[1] == "scan":
                    return subprocess.CompletedProcess(args, 0, json.dumps(CATALOG))
                self.assertNotIn("bundle", args)
                pathlib.Path(args[-1]).write_text("export")
                return subprocess.CompletedProcess(args, 0, '{"written":true,"operationCount":1}')
            with mock.patch.object(ce.subprocess, "run", side_effect=execute) as run:
                steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", out)}
            self.assertEqual(run.call_count, 4)
            self.assertEqual(steps["export-bundle"], "fail")
            self.assertEqual(steps["export-formats"], "fail")

    def test_bundle_rejects_manifest_count_revision_inventory_and_size_lies(self):
        changes = [
            lambda m: m.update(operation_count=2),
            lambda m: m.update(revision_id="stale"),
            lambda m: m["formats"][0].update(operation_count=2),
            lambda m: m["formats"].append(m["formats"][0]),
            lambda m: m["files"].append(m["files"][0]),
            lambda m: m["files"][0].update(path="../outside"),
            lambda m: m["files"][0].update(bytes=999),
            lambda m: m["files"][0].pop("blake3"),
            lambda m: m.pop("omissions"),
        ]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as td:
                dest = pathlib.Path(td) / "bundle"
                write_bundle(dest)
                update_manifest(dest, change)
                self.assertEqual(ce.judge_bundle(dest, CATALOG, COUNTS)[0], "fail")

    def test_bundle_counts_are_measured_from_payloads_not_just_the_manifest(self):
        replacements = {
            "openapi.yaml": 'openapi: "3.1.0"\npaths: {}\n',
            "collection.postman.json": '{"item": []}',
            "curl/get-vets.sh": "echo no recipe\n",
        }
        for name, text in replacements.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                dest = pathlib.Path(td) / "bundle"
                write_bundle(dest)
                (dest / name).write_text(text)
                update_manifest(dest, lambda m: refresh_sizes(m, dest))
                self.assertEqual(ce.judge_bundle(dest, CATALOG, COUNTS)[0], "fail")
        with tempfile.TemporaryDirectory() as td:
            dest = pathlib.Path(td) / "bundle"
            write_bundle(dest)
            self.assertEqual(ce.judge_bundle(dest, CATALOG, {})[0], "fail")
            self.assertEqual(ce.judge_bundle(dest, CATALOG, {**COUNTS, "curl": 2})[0], "fail")

    def test_invalid_bundle_fails_the_aggregate_even_with_exit_zero_and_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            def execute(args, **kwargs):
                if args[1] == "scan":
                    return subprocess.CompletedProcess(args, 0, json.dumps(CATALOG))
                pathlib.Path(args[-1]).mkdir()
                (pathlib.Path(args[-1]) / "junk").write_text("not a bundle")
                return subprocess.CompletedProcess(args, 0, '{"written":true,"operationCount":1}')
            with mock.patch.object(ce.subprocess, "run", side_effect=execute):
                steps = {n: st for n, st, _ in ce.run_exports("xtrace", "project", "analyzer", pathlib.Path(td))}
            self.assertEqual(steps["export-bundle"], "fail")
            self.assertEqual(steps["export-formats"], "fail")

    def test_bundle_privacy_scan_reads_nested_payloads_and_requires_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            dest = pathlib.Path(td) / "bundle"
            write_bundle(dest)
            canaries = canary.make_canaries()
            locs = {"bundle-files": [dest]}
            self.assertTrue(canary.run_scan(canaries, locs, {"bundle-files": 6})["clean"])
            (dest / "curl/get-vets.sh").write_text(canaries["query-token"])
            report = canary.run_scan(canaries, locs, {"bundle-files": 6})
            self.assertFalse(report["clean"])
            self.assertEqual({h["locationClass"] for h in report["hits"]}, {"bundle-files"})
            self.assertNotIn(canaries["query-token"], json.dumps(report))
            self.assertFalse(canary.run_scan(canaries, {"bundle-files": [dest / "missing"]}, {"bundle-files": 6})["clean"])


if __name__ == "__main__":
    unittest.main()
