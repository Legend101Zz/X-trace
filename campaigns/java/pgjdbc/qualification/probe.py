"""Focused real Spring MVC / pgjdbc / PostgreSQL journey. Runner logs stay private."""

import http.client
import json
import os
from pathlib import Path
import re
import stat
import secrets
import signal
import subprocess
import sys
import time

from owned_postgres import OwnedPostgres, FixtureFailure


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
    require(detail["status"] == detail["completion"] == "complete" and detail["next_cursor"] is None,
            "recording_incomplete")
    require(detail["outcome"]["kind"] == "responded"
            and detail["outcome"]["httpStatus"] == 200, "recording_response")
    events = detail["events"]
    routes = [event["symbol"] for event in events
              if (event["symbol"] or "").startswith("http.request GET /jdbc/")]
    require(len(routes) == 1, "recording_route")
    route = routes[0].rsplit("/", 1)[-1]
    require(route in EXPECTED and routes == [f"http.request GET /jdbc/{route}"], "unknown_recording_route")
    parents = [event["event_id"] for event in events
               if event["kind"] == "recording_event_kind:frame_enter"
               and event["symbol"] == f"PgJdbcFixture.{route}"]
    require(len(parents) == 1 and isinstance(parents[0], str) and parents[0], "missing_controller_frame")
    jdbc = [event for event in events
            if event["kind"] in {"recording_event_kind:database_start",
                                 "recording_event_kind:database_end"}]
    expected_count = 2 * len(EXPECTED[route])
    require(len(jdbc) == expected_count,
            f"jdbc_boundary_count {route}: expected {expected_count}, observed {len(jdbc)}")
    for index, outcome in enumerate(EXPECTED[route]):
        method = outcome.removesuffix(".failed")
        start, end = jdbc[2 * index:2 * index + 2]
        require(start["kind"] == "recording_event_kind:database_start"
                and isinstance(start["event_id"], str) and start["event_id"]
                and start["symbol"] == "pgjdbc." + method
                and start["parent_event_id"] == parents[0], "jdbc_start_parent_or_identity")
        require(end["kind"] == "recording_event_kind:database_end"
                and end["symbol"] == "pgjdbc." + outcome
                and end["parent_event_id"] == start["event_id"], "jdbc_end_parent_or_outcome")
        for event in (start, end):
            metadata = event["interaction"]
            require(metadata is not None and metadata["driver"] == "pgjdbc"
                    and metadata["kind"] == "interaction_kind:database"
                    and metadata["method"] == method
                    and all(not metadata[field] for field in ("schema", "table", "host"))
                    and event["exception"] is None, "jdbc_privacy_metadata")
    return route


def scan_private_surfaces(root, seed, report):
    # Scan each original surface fully; streaming retains canaries spanning chunk boundaries.
    needle = seed.encode()
    surfaces = [root/name for name in ('spring.log', 'spring.stderr', 'init.log', 'init.stderr',
                                       'list.log', 'list.stderr')]
    surfaces.extend(sorted(root.glob('recording-*.*')))
    store = [p for p in (root/'data').rglob('*') if p.is_file()]
    surfaces.extend(store)
    files, matched = 0, 0
    for path in surfaces:
        if not path.is_file():
            continue
        found, tail = False, b''
        with path.open('rb') as stream:
            while chunk := stream.read(1024*1024):
                data = tail + chunk
                found |= needle in data
                tail = data[-(len(needle)-1):]
        files += 1
        matched += int(found)
    report['privacyFiles'] = files
    report['privacyFilesMatched'] = matched
    require(not matched, 'canary_found')
    # A prefix of the run can qualify a match, never the entire clean scan.
    complete = (report['readback'] == 'passed' and len(store) > 0 and
                all(p.is_file() for p in surfaces) and len(list(root.glob('recording-*.log'))) == 3
                and len(list(root.glob('recording-*.stderr'))) == 3)
    report['privacy'] = 'passed' if complete else 'partial'


def run_probe(root, cli, agent, classpath):
    seed = secrets.token_hex(12)
    env = dict(os.environ, XTRACE_PG_PROBE_SEED=seed, XTRACE_DATA_HOME=str(root/'data'),
               POSTGRES_USER='pgjdbc_user_'+seed, POSTGRES_PASSWORD='pgjdbc_password_'+seed)
    report = {key: 'unreached' for key in ('networkCreate', 'containerCreate', 'databaseReady', 'init',
              'springReady', 'workload', 'launcherStop', 'readback', 'privacy', 'databaseStop',
              'containerRelease', 'networkRelease')}
    report.update(schemaVersion=1, kind='installed-pgjdbc-ordinary', releaseAcceptance=False,
                  product=os.environ['PRODUCT'], fixture=os.environ['FIXTURE'], wrapper=os.environ['GITHUB_SHA'],
                  run=int(os.environ['GITHUB_RUN_ID']), attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
                  responses=None, checkedRecordings=None, checkedJdbcStarts=None, checkedJdbcEnds=None,
                  checkedJdbcFailures=None, privacyFiles=None, privacyFilesMatched=None, status='incomplete')
    def save():
        file = root/'receipt.pending'
        with file.open('x') as stream:
            json.dump(report, stream, separators=(',', ':'))
            stream.write('\n')
        file.replace(root/'receipt.json')

    expected_stages = ('databaseReady', 'init', 'springReady', 'workload', 'launcherStop', 'readback',
                       'privacy', 'databaseStop', 'containerRelease', 'networkRelease')
    save()
    db = OwnedPostgres(root, env, report, save)
    process = None
    repo = root/'project'
    repo.mkdir(mode=0o700)
    project = ['--project-dir', str(repo)]
    try:
        db.create(IMAGE)
        report['databaseReady'] = 'attempted'
        save()
        db.ready()
        report['databaseReady'] = 'passed'
        save()
        env['XTRACE_PG_PROBE_URL'] = f'jdbc:postgresql://127.0.0.1:{db.port}/probe'
        report['init'] = 'attempted'
        save()
        command([cli, 'init', *project], root/'init.log', env, 'init')
        report['init'] = 'passed'
        report['springReady'] = 'attempted'
        save()
        args = [cli, 'run', *project, '--java-agent', agent, '--app-package', 'dev.xtrace.pgfixture',
                '--', 'java', '-Xverify:all', '-cp', classpath, 'dev.xtrace.pgfixture.PgJdbcFixture',
                '--server.address=127.0.0.1', '--server.port=0', '--spring.main.banner-mode=off',
                '--logging.level.root=WARN']
        with (root/'spring.log').open('xb') as out, (root/'spring.stderr').open('xb') as err:
            process = subprocess.Popen(args, env=env, stdout=out, stderr=err, stdin=subprocess.DEVNULL)
        port = wait_for_ready(process, root/'spring.log')
        report.update(springReady='passed', workload='attempted', responses=0)
        save()
        for route in EXPECTED:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            try:
                conn.request('GET', '/jdbc/'+route)
                response = conn.getresponse()
                require(response.status == 200 and response.read(1) == b'', 'fixture_http_response')
                report['responses'] += 1
                save()
            finally:
                conn.close()
        report.update(workload='passed', launcherStop='attempted')
        save()
        require(process.poll() is None, 'launcher_early_exit')
        process.send_signal(signal.SIGTERM)
        require(process.wait(timeout=20) in (0, 143), 'supervisor_shutdown')
        report.update(launcherStop='passed', readback='attempted')
        save()
        page = json.loads(command([cli, 'recording', 'list', *project, '--limit', '10'],
                                  root/'list.log', env, 'recording_list'))
        require(len(page['recordings']) == len(EXPECTED) and page['next_after'] is None,
                'recording_count_or_unscoped_query')
        ids = [row['recording_id'] for row in page['recordings']]
        require(len(set(ids)) == 3 and all(isinstance(r, str) and re.fullmatch(
            r'[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', r) for r in ids),
            'inventory_ids')
        report.update(checkedRecordings=0, checkedJdbcStarts=0, checkedJdbcEnds=0, checkedJdbcFailures=0)
        save()
        observed = set()
        for index, rid in enumerate(ids):
            detail = json.loads(command([cli, 'recording', 'show', *project, rid],
                                        root/f'recording-{index}.log', env, 'recording_show'))
            require(detail['recording_id'] == rid and detail['project_id'] == page['project_id'],
                    'detail_identity')
            route = check_recording(detail)
            require(route not in observed, 'duplicate_route')
            observed.add(route)
            jdbc = [event for event in detail['events'] if event['kind'] in
                    ('recording_event_kind:database_start','recording_event_kind:database_end')]
            report['checkedRecordings'] += 1
            report['checkedJdbcStarts'] += sum(e['kind'].endswith('database_start') for e in jdbc)
            report['checkedJdbcEnds'] += sum(e['kind'].endswith('database_end') for e in jdbc)
            report['checkedJdbcFailures'] += sum(e['symbol'].endswith('.failed') for e in jdbc)
            save()
        require(observed == set(EXPECTED), 'recording_case_coverage')
        require((report['checkedJdbcStarts'],report['checkedJdbcEnds'],report['checkedJdbcFailures'])==(8,8,1),
                'checked_boundary_totals')
        report['readback'] = 'passed'
        save()
    finally:
        try:
            if process is not None and process.poll() is None:
                report['launcherStop'] = 'recovery'
                save()
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            try:
                db.release()
            finally:
                report['privacy'] = 'attempted'
                try:
                    scan_private_surfaces(root, seed, report)
                except (OSError, ValueError, ProbeFailure):
                    report['privacy'] = 'failed'
                save()
    require(all(report[key] == 'passed' for key in expected_stages), 'incomplete_stage')
    report['status'] = 'passed'
    save()


def main():
    import hashlib
    os.umask(0o077)
    require(sys.platform == 'linux' and os.getenv('GITHUB_ACTIONS') == 'true'
            and os.getenv('HOST_KIND') == 'github-hosted' and os.getenv('GITHUB_EVENT_NAME') == 'push'
            and os.getenv('GITHUB_RUN_ATTEMPT') == '1' and os.getenv('GITHUB_REPOSITORY') == 'Legend101Zz/X-trace'
            and all(not os.getenv(k) for k in ('DOCKER_HOST','DOCKER_CONTEXT','XTRACE_CAMP_DOCKER_HOST','XTRACE_CAMP_DOCKER_CONFIG')),
            'environment')
    product, fixture, root, prefix = (Path(k).resolve(strict=True) for k in sys.argv[1:5])
    require(len(sys.argv) == 6 and product != fixture and product.parent == fixture.parent
            and Path(__file__).resolve().parent == fixture/'campaigns/java/pgjdbc/qualification',
            'source_roots')
    for directory, envkey in ((product, 'PRODUCT'), (fixture, 'FIXTURE')):
        sha = os.environ[envkey]
        require(re.fullmatch(r'[0-9a-f]{40}', sha) and subprocess.check_output(
            ['git','-C',str(directory),'rev-parse','HEAD'],text=True).strip()==sha and not subprocess.check_output(
            ['git','-C',str(directory),'status','--porcelain','--untracked-files=all']), 'source_identity')
    require(stat.S_IMODE(root.stat().st_mode)==0o700 and not any(root.iterdir()), 'private_fresh_root')
    version = subprocess.run(['java','-version'],capture_output=True,timeout=10)
    require(version.returncode == 0 and b'version "21.' in version.stderr, 'jdk21')
    current=(prefix/'current').resolve(strict=True)
    manifest = json.loads((current/'share/xtrace/PACKAGE-MANIFEST.json').read_text())
    extracted = root.parent/'extract/xtrace-0.0.1-linux-x86_64'
    require(current.is_relative_to(prefix) and manifest['sourceCommit'] == os.environ['PRODUCT']
            and manifest['version'] == '0.0.1' and manifest['platform'] == 'linux-x86_64', 'installed_source')
    for item in ('share/xtrace/PACKAGE-MANIFEST.json', 'bin/xtrace',
                 'share/xtrace/packs/java/agent/xtrace-java-agent.jar'):
        with (current/item).open('rb') as installed, (extracted/item).open('rb') as archive:
            require(hashlib.file_digest(installed,'sha256').digest() ==
                    hashlib.file_digest(archive,'sha256').digest(), 'installed_bytes')
    cli=(prefix/'bin/xtrace').resolve(strict=True)
    require(cli == (current/'bin/xtrace').resolve(strict=True), 'installed_cli')
    agent=current/'share/xtrace/packs/java/agent/xtrace-java-agent.jar'
    driver = root.parent/'lib/BOOT-INF/lib/postgresql.jar'
    require(hashlib.sha256(driver.read_bytes()).hexdigest()=='6e0e4cc2d8cae902084f8a2b18728b073a6fd9d1f87c9d8bff8f298c18185b93', 'pgjdbc_driver')
    classpath = str(root.parent/'classes') + ':' + str(root.parent/'lib/BOOT-INF/lib/*')
    require(sys.argv[5]==classpath, 'fixture_classpath')
    run_probe(root,str(cli),str(agent),classpath)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, LookupError, TypeError, subprocess.SubprocessError,
            http.client.HTTPException, ProbeFailure, FixtureFailure):
        raise SystemExit('pgjdbc ordinary proof incomplete') from None
