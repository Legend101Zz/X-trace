"""Hosted scan-to-launch-to-read proof using the real scanners and adapters."""

import argparse
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import time


class JourneyFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise JourneyFailure(code)


class Journey:
    def __init__(self, workspace, cli, root, framework, installed_prefix=None):
        self.workspace = workspace
        self.cli = cli
        self.root = root
        self.framework = framework
        self.installed_prefix = installed_prefix
        self.project = root / "project"
        self.project.mkdir(parents=True)
        self.source = self.project / "src"
        self.source.mkdir()
        self.env = dict(os.environ, XTRACE_DATA_HOME=str(root / "data"))
        if installed_prefix is not None:
            self.env.pop("XTRACE_JAVA_ANALYZER", None)
            self.env.pop("XTRACE_NODE_ANALYZER", None)
            self.env.pop("XTRACE_PREFIX", None)
            self.env.pop("NODE_OPTIONS", None)
            self.env.pop("NODE_PATH", None)
        self.fixture_env = {}
        self.seed = secrets.token_hex(12)

    def call(self, code, *args, expected_exit=0, allow_not_running=False, executable=None):
        try:
            output = subprocess.run([executable or self.cli, *args, "--project-dir", self.project],
                                    env=self.env, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            raise JourneyFailure("cli_deadline_" + code) from None
        require(self.seed.encode() not in output.stdout + output.stderr, "cli_canary")
        if allow_not_running and output.returncode != 0:
            if b'"XTR-LIFECYCLE-NOT-RUNNING"' in output.stdout + output.stderr:
                return None
        require(output.returncode == expected_exit, code)
        try:
            parsed = json.loads(output.stdout)
        except json.JSONDecodeError:
            raise JourneyFailure("invalid_json_" + code) from None
        return parsed.get("data", parsed)

    def check_reconciliation(self, revision, endpoint, confirmed):
        result = self.call("reconcile", "catalog", "reconcile", "--revision", revision, "--json")
        rows = result["reconciliation"]["rows"]
        require(result["revisionId"] == revision and len(rows) == 1
                and (rows[0]["method"], rows[0]["routeTemplate"]) == endpoint
                and rows[0]["status"] == ("confirmed" if confirmed else "static_only")
                and rows[0]["recordingCount"] == (2 if confirmed else 0)
                and result["confirmed"] == int(confirmed)
                and result["unobserved"] == int(not confirmed), "reconciled_recording_count")

    def check_installed_restart(self, revision, endpoint, catalog_id, recording_ids):
        before = None
        try:
            before = self.call("record_installed", "record")
            after = self.call("restart_installed", "restart")
            started = after["started"]["runtime_session_id"]
            require(after["kind"] == "restarted" and after["previously_running"] is True
                    and after["stopped"]["runtime_session_id"] == before["runtime_session_id"]
                    and started != before["runtime_session_id"], "real_restart_session_changed")
            self.check_reconciliation(revision, endpoint, confirmed=True)
            linked = self.call("links_after_daemon_restart", "endpoint", "recordings", catalog_id)["items"]
            require({row["recordingId"] for row in linked} == recording_ids,
                    "restart_preserved_linked_recordings")
        finally:
            # This isolated project has no unrelated daemon. Reconcile even
            # when the start launched a daemon but its command timed out.
            stopped = self.call("stop_installed", "stop", allow_not_running=before is None)
            require(stopped is None or stopped["kind"] == "stopped", "daemon_stopped_after_restart")
        self.check_reconciliation(revision, endpoint, confirmed=True)

    def check_static_refusals(self, scan, app, matched, scope, endpoint, catalog_id):
        conflict_source = self.project / "conflicts"
        conflict_source.mkdir()
        for label in ("First", "Second"):
            (conflict_source / f"{label}.java").write_text(
                "import org.springframework.web.bind.annotation.GetMapping;\n"
                "import org.springframework.web.bind.annotation.RestController;\n"
                f"@RestController public class {label} {{\n"
                '  @GetMapping("/owners/{ownerId}")\n'
                f'  public String {label.lower()}() {{ return "ok"; }}\n'
                "}\n"
            )
        command = list(scan)
        command[command.index("--source") + 1] = conflict_source
        conflict = self.call("conflicting_scan", *command)
        revision = conflict["catalogRevisionId"]
        details = self.call("conflicts", "catalog", "conflicts", "--revision", revision, "--json")
        conflicts = details["conflicts"]
        require(conflict["status"] == "persisted_complete" and len(conflicts) == 1
                and (conflicts[0]["method"], conflicts[0]["routeTemplate"]) == endpoint
                and len(conflicts[0]["handlers"]) == 2 and conflicts[0]["operationId"] == catalog_id,
                "conflict_visible_with_stable_catalog_id")
        self.launch("conflict", app, matched[:1], component=scope, revision=revision)
        # Keep at least one valid claim, so the incomplete discovery run is durably recorded.
        (conflict_source / "Broken.java").write_text("class Broken { @GetMapping(")
        incomplete = self.call("incomplete_scan", *command, expected_exit=10)
        require(incomplete["status"] == "incomplete_recorded"
                and incomplete["catalogRevisionId"] is None and incomplete["runId"],
                "incomplete_scan_without_revision")
        latest = self.call("history_after_incomplete", "catalog", "history", "--json")["revisions"]
        require(len(latest) == 3 and revision in {row["revisionId"] for row in latest},
                "complete_history_survived_incomplete_scan")

    def launch(self, label, app, requests, *, component="owners", revision=None, policy=True):
        args = [self.cli, "run", "--project-dir", self.project]
        if policy:
            args.extend(["--observed-endpoint-policy", "runtime-route-v1",
                         "--application-component", component, "--binding-key", "default",
                         "--observed-endpoint-revision", revision])
        log = self.root / (label + ".log")
        err = self.root / (label + ".stderr")
        with log.open("wb") as output, err.open("wb") as error:
            child = subprocess.Popen([*args, *app], env={**self.env, **self.fixture_env},
                                     stdin=subprocess.DEVNULL, stdout=output, stderr=error)
        try:
            deadline = time.monotonic() + 40
            pattern = rb"^LINK_FIXTURE_READY ([0-9]{1,5})$"
            while time.monotonic() < deadline:
                require(child.poll() is None, "launch_early_exit_" + label)
                match = re.search(pattern, log.read_bytes(), re.MULTILINE)
                if match:
                    break
                time.sleep(0.05)
            else:
                raise JourneyFailure("launch_readiness_" + label)
            port = int(match[1])
            require(0 < port <= 65535, "invalid_bound_port")
            for method, path, status in requests:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.request(method, path + "?trace_token=" + self.seed)
                    response = connection.getresponse()
                    require(response.status == status, "http_status_" + label)
                    response.read()
                finally:
                    connection.close()
            child.send_signal(signal.SIGTERM)
            try:
                status = child.wait(timeout=25)
            except subprocess.TimeoutExpired:
                raise JourneyFailure(f"shutdown_deadline_{self.framework}_{label}") from None
            require(status in (0, 143), "shutdown_" + label)
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            require(self.seed.encode() not in log.read_bytes() + err.read_bytes(), "application_canary")

    def check_installed_scanner_requires_parser(self, payload, scan):
        version = self.root / "scanner-without-parser"
        binary = version / "bin/xtrace"
        binary.parent.mkdir(parents=True)
        shutil.copy2(self.cli.resolve(strict=True), binary)
        shutil.copytree(payload / "analyzers/node",
                        version / "share/xtrace/analyzers/node",
                        ignore=shutil.ignore_patterns("node_modules"))
        result = self.call("missing_installed_parser", *scan, expected_exit=10, executable=binary)
        require(result["catalogRevisionId"] is None and not result["persisted"]
                and result["result"]["completion"] == "incomplete"
                and "analyzer_failed" in result["result"]["incompleteReasons"],
                "missing_parser_must_not_publish")
        print("installed Node scanner: missing parser refused without a catalog revision")

    def check_installed_adapter_rejects_bad_dist(self, adapter):
        # Exercise admission on copies so the verified installation stays byte-identical.
        start = self.root / "must-not-start.cjs"
        marker = self.root / "unexpected-process"
        start.write_text("require('node:fs').writeFileSync(process.argv[2], 'started');\n")
        for variant, failure in (
            ("missing-manifest", b"a Node adapter file is unavailable"),
            ("modified-file", b"the Node adapter distribution digest does not match"),
            ("unlisted-file", b"the Node adapter manifest membership does not match"),
        ):
            candidate = self.root / variant
            shutil.copytree(adapter, candidate)
            if variant == "missing-manifest":
                (candidate / "manifest.sha256").unlink()
            elif variant == "modified-file":
                with (candidate / "register.cjs").open("ab") as target:
                    target.write(b"\n// changed\n")
            else:
                (candidate / "unlisted.cjs").write_text("// unlisted\n")
            result = subprocess.run([
                self.cli, "run", "--project-dir", self.project, "--node-adapter", candidate,
                "--node-mode", "cjs", "--", "node", start, marker,
            ], capture_output=True, timeout=30, env=self.env)
            evidence = result.stdout + result.stderr
            require(result.returncode == 2 and b"XTR-NODE-INVALID-LAUNCH" in evidence
                    and failure in evidence and not marker.exists(), "adapter_rejected_" + variant)
        require(self.call("no_pre_admission_recordings", "recording", "list")["recordings"] == [],
                "unexpected_recording_during_adapter_rejection")
        print("installed Node admission: missing manifest, modified file and unlisted file refused")

    def run(self):
        ws = self.workspace
        self.call("init", "init")
        if self.installed_prefix is not None:
            require(self.call("installed_store_status", "status")["store_schema_version"] == 11,
                    "installed_v11_store")
        if self.framework == "express":
            adapter = ws / "adapters/node/packages/adapter-core/dist"
            if self.installed_prefix is not None:
                payload = (self.installed_prefix / "current/share/xtrace").resolve(strict=True)
                analyzer = None  # The installed CLI discovers its bundled scanner.
                adapter = payload / "packs/node/dist"
                require((payload / "analyzers/node/dist/main.js").is_file()
                        and (adapter / "manifest.sha256").is_file(), "installed_node_payload")
                self.check_installed_adapter_rejects_bad_dist(adapter)
            else:
                analyzer = self.root / "node-analyzer"
                script = ws / "adapters/node/packages/analyzer/dist/main.js"
                analyzer.write_text("#!/bin/sh\nexec node " + shlex.quote(str(script)) + ' "$@"\n')
                analyzer.chmod(0o700)
            src = self.source / "app.js"
            src.write_text("""const express = require('express');
const app = express();
const routes = express.Router();
routes.get('/:ownerId', function owner(_request, response) { response.send('ok'); });
app.use('/owners', routes);
const server = app.listen(0, '127.0.0.1', () => {
  console.log('LINK_FIXTURE_READY ' + server.address().port);
});
process.once('SIGTERM', () => server.close());
""")
            main = self.project / "live.cjs"
            main.write_text(src.read_text() + "\napp.get('/unscanned', (_request, res) => res.send('extra'));\n")
            self.fixture_env["NODE_PATH"] = os.pathsep.join(
                str(ws / "adapters/node" / rel) for rel in
                ("examples/express4-app/node_modules", "node_modules"))
            app = ["--node-adapter", adapter, "--node-mode", "cjs", "--", "node", main]
            endpoint = ("GET", "/owners/{id}")
            matched = [("GET", "/owners/42", 200), ("GET", "/owners/" + self.seed, 200)]
            negatives = [("GET", "/unscanned", 200), ("GET", "/missing", 404)]
        else:
            java = ws / "adapters/java"
            analyzer = java / "static-analyzer/build/install/xtrace-java-static/bin/xtrace-java-static"
            agent = java / "agent-bootstrap/build/agent-dist/xtrace-java-agent.jar"
            if self.installed_prefix is not None:
                payload = (self.installed_prefix / "current/share/xtrace").resolve(strict=True)
                agent = payload / "packs/java/agent/xtrace-java-agent.jar"
                analyzer = None
                require(agent.is_file(), "installed_launch_agent")
            src = self.source / "SpringLinkFixture.java"
            shutil.copyfile(ws / "tools/qa/fixtures/catalog-link/SpringLinkFixture.java", src)
            app = ["--java-agent", agent,
                   "--app-package", "dev.xtrace.catalogfixture", "--", "java", "-cp",
                   os.environ["XTRACE_LINK_SPRING_CLASSPATH"], "dev.xtrace.catalogfixture.SpringLinkFixture",
                   "--server.port=0", "--server.address=127.0.0.1",
                   "--logging.level.root=WARN"]
            endpoint = ("GET", "/owners/{id}")
            matched = [("GET", "/owners/42", 200), ("GET", "/owners/" + self.seed, 200)]
            negatives = []
        scope = f"link-{self.framework}"
        scan = ["scan", "--source", self.source, "--framework", self.framework,
                "--application-component", scope, "--binding-key", "default", "--json"]
        if analyzer is not None:
            scan.extend(["--analyzer", analyzer])
        if self.installed_prefix is not None and self.framework == "express":
            self.check_installed_scanner_requires_parser(payload, scan)
        first = self.call("scan_complete", *scan)
        require(first["status"] == "persisted_complete", "scan_not_complete")
        if self.installed_prefix is not None and self.framework == "express":
            require(first["result"]["analyzer"] == "xtrace-node-static 0.0.1"
                    and first["result"]["rulesetId"] == "express-routes/1", "installed_express_scanner")
        revision = first["catalogRevisionId"]
        listing = self.call("catalog_list", "catalog", "list", "--revision", revision, "--json")
        operations = [op["operationId"] for op in listing["operations"]
                      if (op["method"], op["routeTemplate"]) == endpoint]
        require(len(operations) == 1, "catalog_identity")
        catalog_id = operations[0]
        require(self.call("static_endpoint_list", "endpoint", "list")["items"] == [],
                "scan_claimed_observation")
        if self.installed_prefix is not None:
            self.check_reconciliation(revision, endpoint, confirmed=False)
        original = src.read_text()
        if self.framework == "express":
            changed = original.replace("'/:ownerId'", "'/different'")
        else:
            changed = original.replace('"/owners/{ownerId}"', '"/new-owners/{ownerId}"')
        require(changed != original, "rescan_fixture_changed")
        src.write_text(changed)
        second = self.call("rescan_complete", *scan)
        require(second["catalogRevisionId"] != revision, "expected_distinct_revision")
        self.launch("selected", app, matched + negatives, component=scope, revision=revision)
        self.launch("later_revision", app, matched[:1], component=scope,
                    revision=second["catalogRevisionId"])
        self.launch("wrong_scope", app, matched[:1], component="wrong-scope", revision=revision)
        self.launch("default", app, matched[:1], policy=False)
        if self.installed_prefix is not None and self.framework == "spring-mvc":
            self.check_static_refusals(scan, app, matched, scope, endpoint, catalog_id)
        rows = self.call("endpoint_list", "endpoint", "list")["items"]
        require(len(rows) == 1 and rows[0]["operationId"] == catalog_id
                and (rows[0]["method"], rows[0]["routeTemplate"]) == endpoint
                and rows[0]["applicationComponent"] == scope and rows[0]["binding"] == "default"
                and rows[0]["observationPolicy"] == "runtime-route-v1", "stable_endpoint")
        linked = self.call("endpoint_recordings", "endpoint", "recordings", catalog_id)["items"]
        require(len(linked) == len(matched) and all(row["operationId"] == catalog_id
                    and row["observationPolicy"] == "runtime-route-v1"
                    and row["unmatchedReason"] is None for row in linked), "exact_linked_rows")
        unmatched = self.call("unmatched", "recording", "list", "--unmatched")["items"]
        reasons = ["no_catalog_match", "catalog_revision_unavailable", "observation_policy_missing"]
        if self.framework == "express":
            reasons.extend(["no_catalog_match", "route_template_unavailable_or_ineligible"])
        if self.installed_prefix is not None and self.framework == "spring-mvc":
            reasons.append("no_catalog_match")
        require(sorted(row["unmatchedReason"] for row in unmatched) == sorted(reasons)
                and all(row["operationId"] is None for row in unmatched), "unmatched_reasons")
        ids = {row["recordingId"] for row in linked + unmatched}
        all_rows = self.call("recordings_after_restart", "recording", "list")["recordings"]
        require(ids == {row["recording_id"] for row in all_rows}, "persisted_recording_identity")
        for row in linked:
            detail = self.call("recording_readback", "recording", "show", row["recordingId"])
            require(detail["recording_id"] == row["recordingId"]
                    and detail["completion"] == "complete" and detail["outcome"]["kind"] == "responded",
                    "linked_recording_detail")
        if self.installed_prefix is not None:
            self.check_installed_restart(revision, endpoint, catalog_id, {row["recordingId"] for row in linked})
        print(f"{self.framework}: one stable operation, {len(linked)} linked, {len(unmatched)} unmatched")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("cli", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("--installed-prefix", type=Path)
    parser.add_argument("--framework", choices=("express", "spring-mvc"))
    args = parser.parse_args()
    try:
        if args.installed_prefix is not None:
            require(args.cli == args.installed_prefix / "bin/xtrace"
                    and args.cli.resolve(strict=True) == (args.installed_prefix / "current/bin/xtrace").resolve(strict=True),
                    "public_installer_launcher")
        frameworks = (args.framework,) if args.framework else (
            ("spring-mvc",) if args.installed_prefix is not None else ("express", "spring-mvc")
        )
        for framework in frameworks:
            Journey(args.workspace, args.cli, args.root / framework, framework, args.installed_prefix).run()
    except JourneyFailure as error:
        raise SystemExit(f"catalog link journey failed: {error}") from None
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, http.client.HTTPException) as error:
        raise SystemExit(f"catalog link journey failed: {type(error).__name__}") from None
