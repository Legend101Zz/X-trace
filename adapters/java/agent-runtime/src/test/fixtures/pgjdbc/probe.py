"""Focused real Spring MVC / pgjdbc / PostgreSQL journey. Runner logs stay private."""

import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time


IMAGE = "postgres:18.3@sha256:7e32e9833a6fb1c92c32552794cb6ed569d51b445a54907d35fc112ef39684db"
EXPECTED = {
    "success": ("execute", "execute", "execute", "executeBatch", "executeBatch", "execute"),
    "failure": ("execute.failed", "execute"),
    "empty": (),
}


class ProbeFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise ProbeFailure(code)


def command(argv, path, env, code, *, timeout=45):
    with path.open("wb") as output, path.with_suffix(".stderr").open("wb") as error:
        result = subprocess.run(argv, env=env, stdout=output, stderr=error, timeout=timeout)
    require(result.returncode == 0, code)
    return path.read_bytes()


def wait_for_ready(process, log):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        require(process.poll() is None, "spring_exit_before_readiness")
        match = re.search(rb"^PGJDBC_READY ([0-9]{1,5})\r?$", log.read_bytes(), re.MULTILINE)
        if match:
            port = int(match[1])
            require(0 < port <= 65535, "spring_invalid_port")
            return port
        time.sleep(0.05)
    raise ProbeFailure("spring_readiness_deadline")


def check_recording(detail):
    require(detail["completion"] == "complete" and detail["next_cursor"] is None,
            "recording_incomplete")
    require(detail["outcome"]["kind"] == "responded"
            and detail["outcome"]["httpStatus"] == 200, "recording_response")
    events = detail["events"]
    routes = [event["symbol"] for event in events
              if (event["symbol"] or "").startswith("http.request GET /jdbc/")]
    require(len(routes) == 1, "recording_route")
    route = routes[0].rsplit("/", 1)[-1]
    require(route in EXPECTED, "unknown_recording_route")
    parents = [event["event_id"] for event in events
               if event["kind"] == "recording_event_kind:frame_enter"
               and event["symbol"] == f"PgJdbcFixture.{route}"]
    require(len(parents) == 1, "missing_controller_frame")
    jdbc = [event for event in events
            if event["kind"] in {"recording_event_kind:database_start",
                                 "recording_event_kind:database_end"}]
    require(len(jdbc) == 2 * len(EXPECTED[route]), "jdbc_boundary_count")
    for index, outcome in enumerate(EXPECTED[route]):
        method = outcome.removesuffix(".failed")
        start, end = jdbc[2 * index:2 * index + 2]
        require(start["kind"] == "recording_event_kind:database_start"
                and start["symbol"] == "pgjdbc." + method
                and start["parent_event_id"] == parents[0], "jdbc_start_parent_or_identity")
        require(end["kind"] == "recording_event_kind:database_end"
                and end["symbol"] == "pgjdbc." + outcome
                and end["parent_event_id"] == start["event_id"], "jdbc_end_parent_or_outcome")
        for event in (start, end):
            metadata = event["interaction"]
            require(metadata is not None and metadata["driver"] == "pgjdbc"
                    and metadata["method"] == method
                    and all(not metadata[field] for field in ("schema", "table", "host"))
                    and event["exception"] is None, "jdbc_privacy_metadata")
    return route


def exercise(root, cli, agent, classpath):
    seed = secrets.token_hex(12)
    name = "xtrace-pgjdbc-" + seed
    env = dict(os.environ, XTRACE_PG_PROBE_SEED=seed, XTRACE_DATA_HOME=str(root / "data"),
               POSTGRES_USER="pgjdbc_user_" + seed, POSTGRES_PASSWORD="pgjdbc_password_" + seed)
    repo = root / "project"
    repo.mkdir()
    project = ["--project-dir", str(repo)]
    out = root / "spring.log"
    err = root / "spring.stderr"
    supervisor = None
    docker_started = False
    try:
        command(["docker", "run", "--detach", "--name", name, "--publish", "127.0.0.1::5432",
                 "--tmpfs", "/var/lib/postgresql", "-e", "POSTGRES_USER", "-e", "POSTGRES_PASSWORD",
                 "-e", "POSTGRES_DB=probe", IMAGE], root / "docker.log", env, "postgres_start",
                timeout=180)
        docker_started = True
        binding = command(["docker", "port", name, "5432/tcp"], root / "port.log", env,
                          "postgres_port")
        match = re.fullmatch(rb"127\.0\.0\.1:([0-9]{1,5})\s*", binding)
        require(match, "postgres_port_not_loopback")
        env["XTRACE_PG_PROBE_URL"] = f"jdbc:postgresql://127.0.0.1:{int(match[1])}/probe"
        command(["docker", "exec", name, "sh", "-c", '''
export PGPASSWORD="$POSTGRES_PASSWORD"
deadline=$(( $(date +%s) + 45 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if psql -w -h 127.0.0.1 -U "$POSTGRES_USER" -d probe -Atq -c "select current_setting('server_version_num') = '180003'" | grep -Fxq t; then
    exit 0
  fi
  sleep 0.25
done
exit 1
'''], root / "database-ready.log", env, "postgres_ready_or_version", timeout=55)

        command([cli, "init", *project], root / "init.log", env, "init")
        args = [cli, "run", *project, "--java-agent", agent, "--app-package", "dev.xtrace.pgfixture",
                "--", "java", "-Xverify:all", "-cp", classpath, "dev.xtrace.pgfixture.PgJdbcFixture",
                "--server.address=127.0.0.1", "--server.port=0", "--spring.main.banner-mode=off",
                "--logging.level.root=WARN"]
        with out.open("wb") as output, err.open("wb") as error:
            supervisor = subprocess.Popen(args, env=env, stdout=output, stderr=error)
        port = wait_for_ready(supervisor, out)
        for route in EXPECTED:
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                client.request("GET", "/jdbc/" + route)
                response = client.getresponse()
                require(response.status == 200 and response.read(1) == b"", "fixture_http_response")
            finally:
                client.close()
        supervisor.send_signal(signal.SIGTERM)
        require(supervisor.wait(timeout=20) in (0, 143), "supervisor_shutdown")

        response = command([cli, "recording", "list", *project, "--limit", "10"],
                           root / "list.log", env, "recording_list")
        page = json.loads(response)
        require(len(page["recordings"]) == len(EXPECTED) and page["next_after"] is None,
                "recording_count_or_unscoped_query")
        observed = set()
        for index, row in enumerate(page["recordings"]):
            log = root / f"recording-{index}.log"
            response = command([cli, "recording", "show", *project, row["recording_id"]],
                               log, env, "recording_show")
            observed.add(check_recording(json.loads(response)))
        require(observed == set(EXPECTED), "recording_case_coverage")
    finally:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.send_signal(signal.SIGTERM)
            try:
                supervisor.wait(timeout=15)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait(timeout=5)
        if docker_started:
            command(["docker", "rm", "-f", name], root / "docker-cleanup.log", env, "postgres_cleanup")
        # Scan the exact captured CLI/application surfaces and bytes written to the local data root.
        # The PostgreSQL readiness log describes the test server itself and is private fixture input.
        token = seed.encode()
        surfaces = [out, err, root / "init.log", root / "init.stderr",
                    root / "list.log", root / "list.stderr",
                    *sorted(root.glob("recording-*.*"))]
        surfaces.extend(path for path in (root / "data").rglob("*") if path.is_file())
        for path in surfaces:
            require(not path.is_file() or token not in path.read_bytes(), "canary_found")
    print("verified=3 recordings; JDBC starts=8; JDBC ends=8; failed=1; no raw canary observed")


def main():
    os.umask(0o077)
    root, cli, agent, classpath = sys.argv[1:]
    version = subprocess.run(["java", "-version"], capture_output=True, timeout=10)
    require(version.returncode == 0 and b'version "21.' in version.stderr, "jdk21")
    exercise(Path(root), cli, agent, classpath)


if __name__ == "__main__":
    try:
        main()
    except ProbeFailure as error:
        raise SystemExit(f"pgjdbc proof failed: {error}") from None
    except (OSError, ValueError, LookupError, TypeError, subprocess.TimeoutExpired, http.client.HTTPException):
        raise SystemExit("pgjdbc proof failed: runner, timeout, or malformed evidence") from None
