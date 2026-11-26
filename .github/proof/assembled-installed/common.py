"""Private proof bindings; no values, URLs or paths enter public receipts."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from tools.release.private_roots import admit_directory, atomic_write_private, read_private_json

REPO = Path.cwd()
ROOT = Path(os.environ['SHARED_ROOT'])
ASSET_PATHS = ('index.html', 'app.js', 'index.css', 'assets/fonts/chivo-latin-400-normal.woff2',
               'assets/fonts/chivo-latin-600-normal.woff2', 'assets/fonts/azeret-mono-latin-400-normal.woff2')


def need(value):
    if not value:
        raise RuntimeError('private proof condition failed')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_json(path, value):
    atomic_write_private(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def identity():
    for revision, key, length in (('HEAD', 'PRODUCT', 40), ('HEAD^{tree}', 'PRODUCT_TREE', 40),
                                  ('HEAD:web/app/scripts/browser-journey.mjs', 'REPLAY_SOURCE_BLOB', 40),
                                  ('HEAD:web/app/scripts/replay-tools-journey.mjs', 'REPLAY_TOOLS_BLOB', 40),
                                  ('HEAD:web/app/scripts/replay-playback-journey.mjs', 'REPLAY_PLAYBACK_BLOB', 40),
                                  ('HEAD:web/app/scripts/replay-tools-report.mjs', 'REPLAY_REPORT_BLOB', 40),
                                  ('HEAD:web/app/scripts/first-recording-journey.mjs', 'TOUR_SOURCE_BLOB', 40),
                                  ('HEAD:web/app/scripts/installed-export-journey.mjs', 'JOURNEY_BLOB', 40)):
        need(re.fullmatch('[0-9a-f]{' + str(length) + '}', os.environ[key]))
        need(subprocess.check_output(['git', 'rev-parse', revision], text=True).strip() == os.environ[key])
    need(re.fullmatch('[0-9a-f]{64}', os.environ['EXPECTED_UI_MANIFEST_SHA256']))
    source = os.environ['ASSEMBLED_SOURCE_SHA']
    source_tree = os.environ['ASSEMBLED_SOURCE_TREE']
    source_parent = os.environ['ASSEMBLED_SOURCE_PARENT_SHA']
    installer_fix = os.environ['INSTALLER_FIX_SHA']
    for commit_or_tree in (source, source_tree, source_parent, installer_fix):
        need(re.fullmatch('[0-9a-f]{40}', commit_or_tree))
    need(subprocess.check_output(['git', 'rev-parse', source + '^{tree}'], text=True).strip() == source_tree)
    need(re.fullmatch('[1-9][0-9]{0,19}', os.environ['VERIFIED_SOURCE_RUN_ID']))
    need(subprocess.check_output(['git', 'show', '-s', '--format=%P', 'HEAD'], text=True).strip() == source)
    need(subprocess.check_output(['git', 'show', '-s', '--format=%P', source], text=True).strip() == source_parent)
    need(subprocess.check_output(['git', 'show', '-s', '--format=%P', source_parent], text=True).strip() == installer_fix)
    for name, key in (('packaging/install.sh', 'INSTALL_SCRIPT_SHA256'),
                      ('packaging/test/install_test.sh', 'INSTALL_TEST_SHA256')):
        need(digest(REPO / name) == os.environ[key])
    changed = subprocess.check_output(['git', 'diff', '--name-only', source, 'HEAD'], text=True).splitlines()
    admitted = {'crates/xtrace-daemon/assets/ui/' + name.removeprefix('assets/') for name in ASSET_PATHS}
    admitted.add('crates/xtrace-daemon/assets/ui/assets.sha256')
    need(changed and set(changed) <= admitted and 'crates/xtrace-daemon/assets/ui/assets.sha256' in changed)
    entries = subprocess.check_output(['git', 'ls-tree', '-r', 'HEAD', '--', 'crates/xtrace-daemon/assets/ui'], text=True).splitlines()
    need(len(entries) == len(admitted) and all(row.startswith('100644 blob ') for row in entries))
    need({row.split('\t', 1)[1] for row in entries} == admitted)
    need(not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all']))


def verified_ui(directory):
    manifest = directory / 'assets.sha256'
    need(manifest.is_file() and not manifest.is_symlink() and digest(manifest) == os.environ['EXPECTED_UI_MANIFEST_SHA256'])
    rows = {}
    for line in manifest.read_text().splitlines():
        sha, name = line.split('  ')
        need(re.fullmatch('[0-9a-f]{64}', sha) and name in ASSET_PATHS and name not in rows)
        member = directory / (name.removeprefix('assets/') if name.startswith('assets/') else name)
        need(member.is_file() and not member.is_symlink() and digest(member) == sha)
        rows[name] = sha
    need(set(rows) == set(ASSET_PATHS))
    return rows


def binding(shared):
    return {key: shared[key] for key in ('sourceSha', 'sourceTree', 'uiManifestSha256', 'archiveSha256',
            'packageManifestSha256', 'installedCliSha256', 'installedAgentSha256', 'fixtureSha256',
            'assembledSourceSha', 'assembledSourceTree', 'verifiedSourceRunId', 'verifiedSourceWrapper',
            'installedScriptSha256', 'installerJourneyScriptSha256')}


def load_package():
    admit_directory(ROOT)
    shared = read_private_json(ROOT / 'private/package.json', maximum_bytes=65536)
    need(shared['assembledSourceSha'] == os.environ['ASSEMBLED_SOURCE_SHA']
         and shared['assembledSourceTree'] == os.environ['ASSEMBLED_SOURCE_TREE']
         and shared['verifiedSourceRunId'] == int(os.environ['VERIFIED_SOURCE_RUN_ID'])
         and shared['verifiedSourceWrapper'] == os.environ['VERIFIED_SOURCE_WRAPPER']
         and shared['installedScriptSha256'] == os.environ['INSTALL_SCRIPT_SHA256']
         and shared['installerJourneyScriptSha256'] == os.environ['INSTALL_TEST_SHA256'])
    need(shared['sourceSha'] == os.environ['PRODUCT'] and shared['sourceTree'] == os.environ['PRODUCT_TREE']
         and shared['uiManifestSha256'] == os.environ['EXPECTED_UI_MANIFEST_SHA256'])
    prefix = ROOT / 'fresh installed prefix'
    fixture = REPO / 'adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar'
    need(shared['prefix'] == str(prefix) and shared['fixture'] == str(fixture))
    archives = list((ROOT / 'dist/linux-x86_64').glob('xtrace-*-linux-x86_64.tar.gz'))
    need(len(archives) == 1 and shared['archive'] == str(archives[0]))
    payload = prefix / 'current'
    need(digest(payload / 'install.sh') == os.environ['INSTALL_SCRIPT_SHA256'])
    cli = prefix / 'bin/xtrace'
    agent = payload / 'share/xtrace/packs/java/agent/xtrace-java-agent.jar'
    need(cli.resolve(strict=True) == (payload / 'bin/xtrace').resolve(strict=True))
    for path, key in ((archives[0], 'archiveSha256'), (cli, 'installedCliSha256'), (agent, 'installedAgentSha256'),
                      (payload / 'share/xtrace/PACKAGE-MANIFEST.json', 'packageManifestSha256'), (fixture, 'fixtureSha256')):
        need(re.fullmatch('[0-9a-f]{64}', shared[key]) and digest(path) == shared[key])
    manifest = json.loads((payload / 'share/xtrace/PACKAGE-MANIFEST.json').read_bytes())
    need(manifest['sourceCommit'] == os.environ['PRODUCT'] and manifest['platform'] == 'linux-x86_64')
    need(verified_ui(payload / 'share/xtrace/web') == shared['assetDigests'] == verified_ui(REPO / 'crates/xtrace-daemon/assets/ui'))
    return shared


def served_assets(origin, rows):
    need(re.fullmatch(r'http://127\.0\.0\.1:[0-9]+', origin))
    connection = http.client.HTTPConnection('127.0.0.1', int(origin.rsplit(':', 1)[1]), timeout=10)
    try:
        for name, sha in rows.items():
            connection.request('GET', '/' if name == 'index.html' else '/' + name)
            response = connection.getresponse()
            data = response.read(20 * 1024 * 1024 + 1)
            need(response.status == 200 and len(data) <= 20 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == sha)
    finally:
        connection.close()


def safe_read(path, limit=65536):
    admit_directory(path.parent)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
         and info.st_nlink == 1 and info.st_size <= limit)
    return read_private_json(path, maximum_bytes=limit)


# The public receipt preserves every named direction and activation check. Only
# the private intermediate groups its four kinds directly after width/pointer.
# This removes one container per viewport under the existing JSON node ceiling.
def compact_replay(report):
    return {**report, 'jumpCells': [[cell['width'], cell['pointer'], *cell['kinds']]
                                    for cell in report['jumpCells']]}


def read_replay(path):
    raw = safe_read(path)
    cells = raw['jumpCells']
    need(type(cells) is list and len(cells) <= 10)
    expanded = []
    for cell in cells:
        need(type(cell) is list and len(cell) == 6)
        width, pointer, *kinds = cell
        need(type(width) is int and width in (320, 736, 1024, 1280, 1440) and pointer in ('fine', 'coarse'))
        need([kind['kind'] for kind in kinds] == ['gap', 'exception', 'database', 'http'])
        for kind in kinds:
            need(set(kind) == {'kind', 'observedCount', 'next', 'previous'})
            need(type(kind['observedCount']) is int and 0 <= kind['observedCount'] <= 100000)
            for direction in ('next', 'previous'):
                row = kind[direction]
                need(set(row) == {'targetAvailable', 'activated', 'absenceReasonChecked'})
                need(type(row['targetAvailable']) is bool and type(row['activated']) is int
                     and type(row['absenceReasonChecked']) is int)
                need((row['activated'], row['absenceReasonChecked']) ==
                     ((1, 0) if row['targetAvailable'] else (0, 1)))
        expanded.append({'width': width, 'pointer': pointer, 'kinds': kinds})
    need(len({(cell['width'], cell['pointer']) for cell in expanded}) == len(expanded))
    return {**raw, 'jumpCells': expanded}
