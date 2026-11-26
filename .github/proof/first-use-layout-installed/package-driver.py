"""Hosted-only single unsigned package build and fresh official installation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import traceback

from common import ROOT, REPO, binding, digest, identity, need, private_json, verified_ui

REPORT = {'schemaVersion': 1, 'kind': 'assembled-installed-package', 'releaseAcceptance': False,
          'status': 'incomplete', 'stage': 'identity', 'exitCode': None,
          'sourceSha': os.environ['PRODUCT'], 'sourceTree': os.environ['PRODUCT_TREE'],
          'uiManifestSha256': os.environ['EXPECTED_UI_MANIFEST_SHA256']}
ENV = dict(os.environ, XTRACE_DATA_HOME=str(ROOT / 'install-data'))
for key in ('XTRACE_JAVA_ANALYZER', 'XTRACE_NODE_ANALYZER', 'XTRACE_JAVA_PACK', 'XTRACE_JAVA_AGENT',
            'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'):
    ENV.pop(key, None)


def stage(name):
    REPORT.update(stage=name, exitCode=None)
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
    need(digest(distribution / 'install.sh') == os.environ['INSTALL_SCRIPT_SHA256'])
    prefix = ROOT / 'fresh installed prefix'
    need(not prefix.exists())
    command('install', ['sh', str(distribution / 'install.sh'), '--prefix', str(prefix), '--data-home', ENV['XTRACE_DATA_HOME']])
    command('verify-install', ['sh', str(prefix / 'current/install.sh'), 'verify', '--prefix', str(prefix)])
    payload = prefix / 'current'
    need(digest(payload / 'install.sh') == os.environ['INSTALL_SCRIPT_SHA256'])
    cli = prefix / 'bin/xtrace'
    agent_name = Path('share/xtrace/packs/java/agent/xtrace-java-agent.jar')
    agent = payload / agent_name
    need(cli.resolve(strict=True) == (payload / 'bin/xtrace').resolve(strict=True))
    for name in (manifest, Path('bin/xtrace'), agent_name):
        need(digest(payload / name) == digest(distribution / name))
    need(verified_ui(payload / 'share/xtrace/web') == rows)
    command('browser-dependencies', ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=REPO / 'web/app')
    command('chromium', ['npm', 'exec', '--', 'playwright', 'install', 'chromium'], cwd=REPO / 'web/app')
    stage('clean-source')
    identity()
    shared = dict(assembledSourceSha=os.environ['ASSEMBLED_SOURCE_SHA'], assembledSourceTree=os.environ['ASSEMBLED_SOURCE_TREE'],
                  verifiedSourceRunId=int(os.environ['VERIFIED_SOURCE_RUN_ID']), verifiedSourceWrapper=os.environ['VERIFIED_SOURCE_WRAPPER'],
                  installedScriptSha256=digest(payload / 'install.sh'), installerJourneyScriptSha256=digest(REPO / 'packaging/test/install_test.sh'),
                  sourceSha=os.environ['PRODUCT'], sourceTree=os.environ['PRODUCT_TREE'],
                  uiManifestSha256=os.environ['EXPECTED_UI_MANIFEST_SHA256'], archiveSha256=digest(archive),
                  packageManifestSha256=digest(payload / manifest), installedCliSha256=digest(cli),
                  installedAgentSha256=digest(agent),
                  prefix=str(prefix), archive=str(archive), assetDigests=rows)
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
        REPORT['status']='fail'
        with (ROOT / 'logs/package-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)
        private_json(ROOT / 'safe/package.json', REPORT)
        raise SystemExit(1)
