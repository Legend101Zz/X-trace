"""Four-width fresh and selected tours against the one genuine installed package."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import traceback

from common import ROOT as SHARED, REPO, binding, identity, load_package, need, private_json, safe_read, served_assets
from tools.release.private_roots import admit_directory, read_private_json
from campaigns.lib import xcamp, xinstr

ROOT = Path(os.environ['PROOF_ROOT'])
SCRIPTS = Path(os.environ['PROOF_SCRIPTS'])
spec = importlib.util.spec_from_file_location('tour_owned_process', SCRIPTS / 'replay-driver.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
OwnedProcess = support.OwnedProcess
ENV = support.ENV
REPORT = dict(schemaVersion=1, kind='assembled-installed-tour', releaseAcceptance=False,
              status='incomplete', stage='identity', empty=None, selected=None, frames=None, completedCells=[], servedAssets=0)
WIDTHS = (320, 736, 1024, 1440)


def checkpoint(stage):
    REPORT['stage'] = stage
    private_json(ROOT / 'safe/report.json', REPORT)


def command(stage, args):
    checkpoint(stage)
    with (ROOT / 'logs' / (stage + '.stdout')).open('xb') as out, (ROOT / 'logs' / (stage + '.stderr')).open('xb') as err:
        subprocess.run(args, cwd=REPO, env=ENV, stdout=out, stderr=err, check=True, timeout=120)


def browse(cli, project, rows, recording_id=None, events=()):
    scenario = 'selected' if recording_id else 'empty'
    checkpoint(scenario + '-viewer')
    with OwnedProcess(scenario + '-viewer', [str(cli), 'open', '--project-dir', str(project), '--viewer', '--no-browser']) as viewer:
        ready = viewer.ready(xinstr.parse_readiness, 60)
        served_assets(ready['origin'], rows)
        receipt_id = os.urandom(32).hex()
        context = ROOT / 'private' / (scenario + '-context.json')
        result = ROOT / 'private' / (scenario + '-result.json')
        # At most 200 CLI events. Groups fit the private reader's 128-entry array bound.
        pairs = [[sequence, event_id] for sequence, event_id in events]
        config = dict(url=ready['url'], widths=list(WIDTHS), recordingId=recording_id,
                      eventGroups=[pairs[start:start+100] for start in range(0, len(pairs), 100)],
                      result=str(result), sourceSha=os.environ['PRODUCT'], receiptId=receipt_id)
        private_json(context, config)
        need(read_private_json(context, maximum_nodes=1024, maximum_commas=1024) == config)
        checkpoint(scenario + '-browser')
        expected = ([dict(kind='empty', width=w) for w in WIDTHS] if not recording_id else
                    [dict(kind=k, width=w) for w in WIDTHS for k in ('manual', 'selected')] +
                    [dict(kind='drag', width=w) for w in (1024, 1440)])
        try:
            with (ROOT / 'logs' / (scenario + '-browser.stdout')).open('xb') as out, (ROOT / 'logs' / (scenario + '-browser.stderr')).open('xb') as err:
                subprocess.run(['node', '--input-type=module', '-', str(context)], cwd=REPO / 'web/app',
                               env=dict(ENV, XTRACE_BROWSER_SCREENSHOT_DIR=str(ROOT / 'shots')),
                               input=(SCRIPTS / 'tour-browser.mjs').read_bytes(), stdout=out, stderr=err, check=True, timeout=120)
        finally:
            for cell in expected:
                checkpoint_file = Path(f"{result}.{cell['kind']}-{cell['width']}")
                if checkpoint_file.exists():
                    need(safe_read(checkpoint_file) == dict(**cell, receiptId=receipt_id, sourceSha=os.environ['PRODUCT']))
                    REPORT['completedCells'].append(cell)
            checkpoint(scenario + '-browser')
        need(safe_read(result) == dict(schema=1, sourceSha=os.environ['PRODUCT'], receiptId=receipt_id,
                                      widths=list(WIDTHS), scenario=scenario, frames=12, checked=expected,
                                      selectedTabletReads=int(recording_id is not None)))
        served_assets(ready['origin'], rows)
        need(viewer.stop() in (0, 143))
    REPORT[scenario] = True
    REPORT['servedAssets'] += 2 * len(rows)
    if recording_id:
        REPORT.update(selectedTabletReads=1)


def run():
    identity()
    shared = load_package()
    REPORT.update(binding(shared))
    cli = Path(shared['prefix']) / 'bin/xtrace'
    agent = Path(shared['prefix']) / 'current/share/xtrace/packs/java/agent/xtrace-java-agent.jar'
    project = ROOT / 'project'
    project.mkdir(mode=0o700)
    shutil.copytree(REPO / 'adapters/java/spring-fixture/src/main/java', project / 'src/main/java')
    command('init', [str(cli), 'init', '--project-dir', str(project)])
    need(support.query(support.list_args(cli, project))['recordings'] == [])
    browse(cli, project, shared['assetDigests'])
    checkpoint('spring-readiness')
    java = Path(ENV['JAVA_HOME']) / 'bin/java'
    with OwnedProcess('spring', [str(cli), 'run', '--project-dir', str(project), '--java-agent', str(agent),
                                '--app-package', 'dev.xtrace.fixture', '--source-root', 'src/main/java',
                                '--observed-endpoint-policy', 'spring-orders-v1', '--application-component', 'spring-fixture',
                                '--binding-key', 'default', '--', str(java), '-jar', shared['fixture'], '--server.port=0',
                                '--server.address=127.0.0.1', '--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO']) as spring:
        port = spring.ready(xcamp.spring_bound_port, 45)
        checkpoint('spring-request')
        response = xcamp.http_request(f'http://127.0.0.1:{port}', 'POST', '/orders?probe=INSTALLED_TOUR_PRIVATE_QUERY',
                                     headers={'Content-Type': 'application/json'},
                                     body=b'{"description":"installed tour","bodyCanary":"INSTALLED_TOUR_PRIVATE_BODY"}', timeout=10)
        need(response['status'] == 201)
        checkpoint('spring-recording')
        rid, events = support.expected_recording(cli, project, include_identities=True)
        checkpoint('spring-shutdown')
        need(spring.stop() == 143 and b'XTR-RUN-CAPTURE-INCOMPLETE' not in spring.errors.read_bytes())
    with socket.socket() as connection:
        connection.settimeout(2)
        need(connection.connect_ex(('127.0.0.1', port)) != 0)
    need(support.expected_recording(cli, project, include_identities=True) == (rid, events))
    browse(cli, project, shared['assetDigests'], rid, events)
    checkpoint('frame-coverage')
    empty = {f'{kind}-{width}{suffix}.png': (width, 844) for width in WIDTHS
             for kind, suffix in (('empty', ''), ('tour', '-step-2'), ('tour', '-step-3'))}
    selected = {f'tour-{width}-{title}.png': (width, 844) for width in WIDTHS for title in ('Find', 'Read', 'Check')}
    support.check_frames(ROOT / 'shots/first-recording', empty)
    support.check_frames(ROOT / 'shots/spring-tour', selected)
    need(set(p.name for p in (ROOT / 'shots').iterdir()) == {'first-recording', 'spring-tour'})
    load_package()
    REPORT.update(status='pass', stage='complete', frames=24, widths=list(WIDTHS))
    private_json(ROOT / 'safe/report.json', REPORT)


if __name__ == '__main__':
    os.umask(0o077)
    admit_directory(ROOT)
    checkpoint('identity')
    try:
        run()
    except Exception:
        with (ROOT / 'logs/driver-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)
        REPORT['status']='fail'
        checkpoint(REPORT['stage'])
        raise SystemExit(1)
