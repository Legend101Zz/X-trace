"""One genuine ordinary Spring recording and the installed Details checks."""
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import traceback

from campaigns.lib import xcamp, xinstr
from common import REPO, binding, identity, load_package, need, private_json, safe_read, served_assets

ROOT = Path(os.environ['PROOF_ROOT'])
SCRIPTS = Path(os.environ['PROOF_SCRIPTS'])
spec = importlib.util.spec_from_file_location('owned_spring', SCRIPTS/'spring-support.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
REPORT = dict(status='incomplete', stage='identity', checked=[])


def checkpoint(stage):
    REPORT['stage'] = stage
    private_json(ROOT/'safe/report.json', REPORT)


def run():
    identity()
    package = load_package()
    REPORT.update(binding(package))
    checkpoint('init')
    cli = Path(package['prefix'])/'bin/xtrace'
    agent = Path(package['prefix'])/'current/share/xtrace/packs/java/agent/xtrace-java-agent.jar'
    project = ROOT/'project'
    project.mkdir(mode=0o700)
    source = Path('adapters/java/spring-fixture/src/main/java')
    shutil.copytree(REPO/source,project/source)
    with (ROOT/'logs/init.stdout').open('xb') as out, (ROOT/'logs/init.stderr').open('xb') as err:
        subprocess.run([str(cli), 'init', '--project-dir', str(project)], cwd=REPO, env=support.ENV,
                       stdout=out, stderr=err, stdin=subprocess.DEVNULL, check=True, timeout=120)
    need(support.query(support.list_args(cli, project))['recordings'] == [])
    checkpoint('spring-readiness')
    java = Path(support.ENV['JAVA_HOME'])/'bin/java'
    with support.OwnedProcess('spring', [str(cli), 'run', '--project-dir', str(project), '--java-agent', str(agent),
            '--app-package', 'dev.xtrace.fixture', '--source-root', str(source), '--',
            str(java), '-jar', package['fixture'], '--server.port=0', '--server.address=127.0.0.1',
            '--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO']) as spring:
        port = spring.ready(xcamp.spring_bound_port, 45)
        checkpoint('spring-request')
        response = xcamp.http_request(f'http://127.0.0.1:{port}', 'GET', '/__fixture/boundary/uncommitted', timeout=10)
        need(response['status'] == 210)
        checkpoint('spring-recording')
        rid, events = support.expected_recording(cli, project, include_identities=True)
        checkpoint('spring-shutdown')
        need(spring.stop() == 143 and b'XTR-RUN-CAPTURE-INCOMPLETE' not in spring.errors.read_bytes())
    with socket.socket() as connection:
        connection.settimeout(2)
        need(connection.connect_ex(('127.0.0.1', port)) != 0)
    need(support.expected_recording(cli, project, include_identities=True) == (rid, events))
    REPORT['verifiedRecordings'] = 1
    nonce = os.urandom(32).hex()
    for mode in ('fine', 'coarse'):
        try:
            checkpoint('viewer')
            with support.OwnedProcess(mode+'-viewer', [str(cli), 'open', '--project-dir', str(project),
                                                     '--viewer', '--no-browser']) as viewer:
                ready = viewer.ready(xinstr.parse_readiness, 60)
                served_assets(ready['origin'], package['assetDigests'])
                REPORT['assetReads'] = REPORT.get('assetReads', 0) + len(package['assetDigests'])
                checkpoint('browser')
                config, result = (ROOT/'private'/f'{mode}-{suffix}.json' for suffix in ('context', 'result'))
                private_json(config, dict(url=ready['url'], mode=mode, recordingId=rid, events=events,
                                          result=str(result), nonce=nonce))
                try:
                    with (ROOT/'logs'/f'{mode}.stdout').open('xb') as out, (ROOT/'logs'/f'{mode}.stderr').open('xb') as err:
                        subprocess.run(['node','--input-type=module','-',str(config)], cwd=REPO/'web/app',
                            env=support.ENV, input=(SCRIPTS/'spring-browser.mjs').read_bytes(), stdout=out,
                            stderr=err, check=True, timeout=120)
                finally:
                    if result.exists():
                        observations = {'identityReadable': True} if mode == 'fine' else {'touchTargets':4}
                        need(safe_read(result) == dict(mode=mode, nonce=nonce, **observations))
                        REPORT['checked'].append(mode)
                        checkpoint('browser')
                need(mode in REPORT['checked'])
                served_assets(ready['origin'], package['assetDigests'])
                REPORT['assetReads'] += len(package['assetDigests'])
                checkpoint('viewer-shutdown')
                need(viewer.stop() in (0, 143))
        except Exception:
            with (ROOT/'logs'/f'{mode}-failure.stderr').open('x') as err:
                traceback.print_exc(file=err)
            failures = REPORT.setdefault('failedChecks', {})
            failures[mode] = REPORT['stage']
            checkpoint(REPORT['stage'])
    need(not REPORT.get('failedChecks'))
    need(load_package() == package)
    REPORT['status'] = 'pass'
    checkpoint('complete')


if __name__ == '__main__':
    os.umask(0o077)
    checkpoint('identity')
    try:
        run()
    except Exception:
        with (ROOT/'logs/driver-exception.stderr').open('x') as err:
            traceback.print_exc(file=err)
        REPORT['status'] = 'fail'
        checkpoint(REPORT['stage'])
        raise SystemExit(1)
