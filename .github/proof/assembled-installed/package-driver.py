"""Hosted-only single unsigned package build and fresh official installation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import traceback

from common import ROOT, REPO, binding, digest, identity, need, private_json, verified_ui

REPORT = {'schemaVersion': 1, 'kind': 'assembled-installed-package', 'releaseAcceptance': False,
          'status': 'fail', 'stage': 'identity', 'exitCode': 1,
          'sourceSha': os.environ['PRODUCT'], 'sourceTree': os.environ['PRODUCT_TREE'],
          'uiManifestSha256': os.environ['EXPECTED_UI_MANIFEST_SHA256']}
ENV = dict(os.environ, XTRACE_DATA_HOME=str(ROOT / 'install-data'))
for key in ('XTRACE_JAVA_ANALYZER', 'XTRACE_NODE_ANALYZER', 'XTRACE_JAVA_PACK', 'XTRACE_JAVA_AGENT',
            'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'):
    ENV.pop(key, None)


def stage(name):
    REPORT.update(stage=name, exitCode=1)
    private_json(ROOT / 'safe/package.json', REPORT)


def command(name, args, cwd=REPO, timeout=3000):
    stage(name)
    with (ROOT / 'logs' / (name + '.stdout')).open('xb') as out, (ROOT / 'logs' / (name + '.stderr')).open('xb') as err:
        try:
            result = subprocess.run(args, cwd=cwd, env=ENV, stdout=out, stderr=err, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            REPORT['exitCode'] = 124
            private_json(ROOT / 'safe/package.json', REPORT)
            raise
    REPORT['exitCode'] = result.returncode
    private_json(ROOT / 'safe/package.json', REPORT)
    need(result.returncode == 0)


def run():
    identity()
    rows = verified_ui(REPO / 'crates/xtrace-daemon/assets/ui')
    command('package', ['python3', '-B', 'packaging/build.py', '--out', str(ROOT / 'dist'),
                        '--work', str(ROOT / 'build'), '--platform', 'linux-x86_64'])
    archives = list((ROOT / 'dist/linux-x86_64').glob('xtrace-*-linux-x86_64.tar.gz'))
    need(len(archives) == 1)
    archive = archives[0]
    REPORT['archiveSha256'] = digest(archive)
    command('verify-dist', ['sh', 'packaging/install.sh', 'verify-dist', str(archive.parent)])
    command('verify-archive', ['python3', '-B', 'packaging/verify_package.py', str(archive), '--repo', str(REPO), '--run-binary'])
    stage('extract')
    extracted = ROOT / 'extracted'
    extracted.mkdir(mode=0o700)
    spec = importlib.util.spec_from_file_location('assembled_package_verifier', REPO / 'packaging/verify_package.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    distribution = verifier.resolve_root(archive, extracted)
    manifest = Path('share/xtrace/PACKAGE-MANIFEST.json')
    need(json.loads((distribution / manifest).read_bytes())['sourceCommit'] == os.environ['PRODUCT'])
    prefix = ROOT / 'fresh installed prefix'
    need(not prefix.exists())
    command('install', ['sh', str(distribution / 'install.sh'), '--prefix', str(prefix), '--data-home', ENV['XTRACE_DATA_HOME']])
    command('verify-install', ['sh', str(prefix / 'current/install.sh'), 'verify', '--prefix', str(prefix)])
    payload = prefix / 'current'
    cli = prefix / 'bin/xtrace'
    agent_name = Path('share/xtrace/packs/java/agent/xtrace-java-agent.jar')
    agent = payload / agent_name
    need(cli.resolve(strict=True) == (payload / 'bin/xtrace').resolve(strict=True))
    for name in (manifest, Path('bin/xtrace'), agent_name):
        need(digest(payload / name) == digest(distribution / name))
    need(verified_ui(payload / 'share/xtrace/web') == rows)
    command('fixture', ['./gradlew', '--no-daemon', '--dependency-verification', 'strict', 'fixtureBootJar'], cwd=REPO / 'adapters/java')
    command('browser-dependencies', ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=REPO / 'web/app')
    command('chromium', ['npm', 'exec', '--', 'playwright', 'install', 'chromium'], cwd=REPO / 'web/app')
    command('b3sum-download', ['apt-get', 'download', 'b3sum'], cwd=ROOT / 'packages')
    debs = list((ROOT / 'packages').glob('b3sum_*.deb'))
    need(len(debs) == 1)
    command('b3sum-extract', ['dpkg-deb', '-x', str(debs[0]), str(ROOT / 'packages/b3')])
    ENV['PATH'] = str(ROOT / 'packages/b3/usr/bin') + os.pathsep + ENV['PATH']
    command('b3sum-vector', ['python3', '-B', '-c', 'from tools.qa.installed_export_journey import blake3_bytes; assert blake3_bytes(b"abc") == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"'])
    stage('clean-source')
    identity()
    fixture = REPO / 'adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar'
    shared = dict(assembledSourceSha=os.environ['ASSEMBLED_SOURCE_SHA'], assembledSourceTree=os.environ['ASSEMBLED_SOURCE_TREE'],
                  verifiedSourceRunId=int(os.environ['VERIFIED_SOURCE_RUN_ID']), sourceSha=os.environ['PRODUCT'], sourceTree=os.environ['PRODUCT_TREE'],
                  uiManifestSha256=os.environ['EXPECTED_UI_MANIFEST_SHA256'], archiveSha256=digest(archive),
                  packageManifestSha256=digest(payload / manifest), installedCliSha256=digest(cli),
                  installedAgentSha256=digest(agent), fixtureSha256=digest(fixture),
                  prefix=str(prefix), archive=str(archive), fixture=str(fixture), assetDigests=rows)
    need(shared['archiveSha256'] == REPORT['archiveSha256'])
    private_json(ROOT / 'private/package.json', shared)
    REPORT.update(binding(shared), status='pass', stage='complete', exitCode=0)
    private_json(ROOT / 'safe/package.json', REPORT)


if __name__ == '__main__':
    os.umask(0o077)
    stage('identity')
    try:
        run()
    except Exception:
        with (ROOT / 'logs/package-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)
        private_json(ROOT / 'safe/package.json', REPORT)
        raise SystemExit(1)
