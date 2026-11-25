"""Hosted scan-to-launch-to-read proof using the real scanners and adapters."""

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
import sys
import time


class JourneyFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise JourneyFailure(code)


class Journey:
    def __init__(self, workspace, cli, root, framework):
        self.workspace = workspace
        self.cli = cli
        self.root = root
        self.framework = framework
        self.project = root / "project"
        self.project.mkdir(parents=True)
        self.source = self.project / "src"
        self.source.mkdir()
        self.env = dict(os.environ, XTRACE_DATA_HOME=str(root / "data"))
        self.seed = secrets.token_hex(12)

    def call(self, code, *args):
        try:
            output = subprocess.run([self.cli, *args, "--project-dir", self.project], env=self.env,
                                    capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            raise JourneyFailure("cli_deadline_" + code) from None
        require(self.seed.encode() not in output.stdout + output.stderr, "cli_canary")
        require(output.returncode == 0, code)
        try:
            parsed = json.loads(output.stdout)
        except json.JSONDecodeError:
            raise JourneyFailure("invalid_json_" + code) from None
        return parsed.get("data", parsed)

    def launch(self, label, app, requests, *, component="owners", revision=None, policy=True):
        args = [self.cli, "run", "--project-dir", self.project]
        if policy:
            args.extend(["--observed-endpoint-policy", "runtime-route-v1",
                         "--application-component", component, "--binding-key", "default",
                         "--observed-endpoint-revision", revision])
        log = self.root / (label + ".log")
        err = self.root / (label + ".stderr")
        with log.open("wb") as output, err.open("wb") as error:
            child = subprocess.Popen([*args, *app], env=self.env, stdin=subprocess.DEVNULL,
                                     stdout=output, stderr=error)
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

    def run(self):
        ws = self.workspace
        self.call("init", "init")
        if self.framework == "express":
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
            self.env["NODE_PATH"] = os.pathsep.join(str(ws / "adapters/node" / rel) for rel in
                                        ("examples/express4-app/node_modules", "node_modules"))
            app = ["--node-adapter", ws / "adapters/node/packages/adapter-core/dist",
                   "--node-mode", "cjs", "--", "node", main]
            endpoint = ("GET", "/owners/{id}")
            matched = [("GET", "/owners/42", 200), ("GET", "/owners/" + self.seed, 200)]
            negatives = [("GET", "/unscanned", 200), ("GET", "/missing", 404)]
        else:
            java = ws / "adapters/java"
            analyzer = java / "static-analyzer/build/install/xtrace-java-static/bin/xtrace-java-static"
            src = self.source / "SpringLinkFixture.java"
            shutil.copyfile(ws / "tools/qa/fixtures/catalog-link/SpringLinkFixture.java", src)
            app = ["--java-agent", java / "agent-bootstrap/build/agent-dist/xtrace-java-agent.jar",
                   "--app-package", "dev.xtrace.catalogfixture", "--", "java", "-cp",
                   os.environ["XTRACE_LINK_SPRING_CLASSPATH"], "dev.xtrace.catalogfixture.SpringLinkFixture",
                   "--server.port=0", "--server.address=127.0.0.1",
                   "--logging.level.root=WARN"]
            endpoint = ("GET", "/owners/{id}")
            matched = [("GET", "/owners/42", 200), ("GET", "/owners/" + self.seed, 200)]
            negatives = []
        scope = f"link-{self.framework}"
        scan = ["scan", "--source", self.source, "--framework", self.framework, "--analyzer", analyzer,
                "--application-component", scope, "--binding-key", "default", "--json"]
        first = self.call("scan_complete", *scan)
        require(first["status"] == "persisted_complete", "scan_not_complete")
        revision = first["catalogRevisionId"]
        listing = self.call("catalog_list", "catalog", "list", "--revision", revision, "--json")
        operations = [op["operationId"] for op in listing["operations"]
                      if (op["method"], op["routeTemplate"]) == endpoint]
        require(len(operations) == 1, "catalog_identity")
        catalog_id = operations[0]
        require(self.call("static_endpoint_list", "endpoint", "list")["items"] == [],
                "scan_claimed_observation")
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
        print(f"{self.framework}: one stable operation, {len(linked)} linked, {len(unmatched)} unmatched")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        workspace, cli, root = map(Path, sys.argv[1:])
        for framework in ("express", "spring-mvc"):
            Journey(workspace, cli, root / framework, framework).run()
    except JourneyFailure as error:
        raise SystemExit(f"catalog link journey failed: {error}") from None
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, http.client.HTTPException) as error:
        raise SystemExit(f"catalog link journey failed: {type(error).__name__}") from None
