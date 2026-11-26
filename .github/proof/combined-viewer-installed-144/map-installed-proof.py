"""Run one synthetic Map journey using the ordinary job's verified installation."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from common import ROOT, REPO, digest, identity, load_package, need, private_json, safe_read
from map_package_projection import verify_projection

SOURCE = '48ae5e2306829a52de9c5c054932430fe522bb76'
SOURCE_WRAPPER = '2a508743ed9ca86fde82e248f3e1c345d001165f'
SOURCE_WORKFLOW = '.github/workflows/integrated-map-10k-functional.yml'
SOURCE_WORKFLOW_SHA = 'b7f708e304a320f976198de9223c630d2cc990e613076934ba59e48510a9f046'
SUCCESSOR = '8c8e05f3eeab52ca8fd6822a59ac5018088f4593'
SUCCESSOR_TREE = 'fd86131a4d830eca54668f09a73b8ce987f23ef7'
MAP_RUN = 45835172367
MAP_BRANCH = 'codex/proof-disclosure-map-10k-128'
MAP_WRAPPER = 'e2bdb9a741ec6c3e1dd0d750a2cbb29e32559929'
MAP_WORKFLOW_SHA = 'caf3784c8fd0c28788ab8bc8e4700cd7f310e047352d38b4298415753a83a77e'
MAP_COUNTS = (15124433076, 'integrated-map-10k-bounded-counts', 559,
              'a45598803b7008a4677d048d602f6ee769b8a76d251608715d45f113d5fed927')
MAP_ASSETS = (15123538132, 'integrated-map-generated-viewer', 162521,
              '52a2ca3ca19056f051d34eb96a791bac65ce51f6ffe79edfd8bff924cd0351d2')
MAP_RECEIPT_SHA = 'd992846e45355869d24e09c127b4f6f848eb9e0f76aafbe2f2692ad618992aa2'
MAP_UI_SHA = '507262f9a0b03c7d18bfebc769bdc782321c598a95de0d42812903ac6b672f5d'
HISTORICAL_RUN = 45832326691
HISTORICAL_COUNTS = (15122454743, 'integrated-map-10k-bounded-counts', 559,
                     '0074243492b40706f6613ca8ad67031f8a638b5683a546fbc4daa5c98e82e08d')
HISTORICAL_RECEIPT_SHA = '81b5d98edb7f0e108819dec55fdb3a804bee613139d769d62b8c24e69fbadf9b'
INSTRUMENTS = {
    'tools/qa/replay_scale_browser.mjs': 'b2e50e98964d5f0ea3f4fe9fd942ed7e105a29f8',
    'web/app/scripts/replay-window-journey.mjs': '17af7e78bcc0ca3cb8185e0c00afb7adb4356828',
    'crates/xtrace-cli/tests/replay_scale.rs': '884de7d8241c262185ef3e6d7fe4311a5652b9d9',
    'crates/xtrace-cli/tests/support/replay_scale.rs': '91ce6318131c50a3667adbf11b61a486b02b3dcd',
}
SOURCE_TREE = '8bc2201d0abe56c767d0e42bcb5546bd1cf25863'
DRIVER_SHA = 'fb4de19e757c30228addbc595306ebb24500b26b364e4221fb587311672f7359'
PROOF_SHA = '1ca0f88fd0541bec2ae8957df203182ef1d1c84e7633bbd87f2f1eec1f45420f'
PHASES = {'admission', 'fixture', 'browser', 'verify', 'complete'}
SUBDIR = ROOT / 'map10k'
RESULT = ROOT / 'safe/installed-map-10k.json'
MANIFEST = Path('share/xtrace/PACKAGE-MANIFEST.json')
ASSETS = Path('crates/xtrace-daemon/assets/ui')
FIXTURE_TEST = 'synthetic_ten_thousand_frames_are_complete_ordered_and_navigable'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

def result(stage, status, **evidence):
    need(stage in PHASES)
    private_json(RESULT, dict(schemaVersion=1, kind='same-archive-installed-map-10k-functional',
                             releaseAcceptance=False, status=status, stage=stage,
                             runId=int(os.environ['GITHUB_RUN_ID']),
                             runAttempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
                             sourceSha=os.environ['MAP_PRODUCT'], sourceTree=os.environ['MAP_PRODUCT_TREE'],
                             wrapperSha=os.environ['GITHUB_SHA'], **evidence))

def authenticate_historical_map():
    from qualification import artifact, run
    # The installed product checkout may lack this sibling object. Its exact
    # SHA was checked from Git at binding and must match the authenticated run.
    local_wrapper = subprocess.run(['git', 'cat-file', '-e', SOURCE_WRAPPER + '^{commit}'],
                                   cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   check=False).returncode == 0
    if local_wrapper:
        need(git('show', '-s', '--format=%P', SOURCE_WRAPPER) == SOURCE)
        need(git('diff', '--name-status', SOURCE, SOURCE_WRAPPER) == f'A\t{SOURCE_WORKFLOW}')
        entry = git('ls-tree', SOURCE_WRAPPER, '--', SOURCE_WORKFLOW)
        need(re.fullmatch(rf'100644 blob [0-9a-f]{{40}}\t{re.escape(SOURCE_WORKFLOW)}', entry))
        raw = subprocess.check_output(['git', 'show', SOURCE_WRAPPER + ':' + SOURCE_WORKFLOW], cwd=REPO)
        need(hashlib.sha256(raw).hexdigest() == SOURCE_WORKFLOW_SHA)
    run(HISTORICAL_RUN, SOURCE_WRAPPER, 'codex/proof-integrated-map-10k', SOURCE_WORKFLOW, 'map10k-historical')
    counts = artifact(HISTORICAL_RUN, SOURCE_WRAPPER, HISTORICAL_COUNTS, 'map10k-historical-counts',
                      ('counts.json',))['counts.json']
    need(hashlib.sha256(counts).hexdigest() == HISTORICAL_RECEIPT_SHA)
    receipt = json.loads(counts)
    need(receipt['runId'] == HISTORICAL_RUN and receipt['wrapperSha'] == SOURCE_WRAPPER and receipt['attempt'] == 1
         and receipt['kind'] == 'persisted-map-10k-functional' and receipt['status'] == 'passed'
         and receipt['sourceSha'] == SOURCE and receipt['sourceTree'] == SOURCE_TREE
         and receipt['frames'] == 10000 and receipt['samples'] == 1 and receipt['laterPages'] == 12
         and receipt['navigationChecks'] == 3 and receipt['navigationExtraRequests'] == 0
         and receipt['timingMeasured'] is False and receipt['proofScriptSha256'] == PROOF_SHA)

def authenticate_successor_qualification(product, tree):
    from qualification import root as qualification_root

    # The ordinary qualification stage already authenticates the exact source
    # run and source asset ZIP before installing. Require its own pass receipt.
    admitted = safe_read(qualification_root() / 'safe/qualification.json')
    run_id, wrapper = os.environ['SUCCESSOR_SOURCE_RUN_ID'], os.environ['SUCCESSOR_SOURCE_WRAPPER']
    need(run_id == os.environ['VERIFIED_SOURCE_RUN_ID'] and int(run_id) not in (HISTORICAL_RUN, MAP_RUN)
         and wrapper == os.environ['VERIFIED_SOURCE_WRAPPER'] and wrapper not in (SOURCE_WRAPPER, MAP_WRAPPER))
    for bound, ordinary in (('SUCCESSOR_SOURCE_ASSETS_ID', 'SOURCE_ASSETS_ARTIFACT_ID'),
                            ('SUCCESSOR_SOURCE_ASSETS_BYTES', 'SOURCE_ASSETS_ARCHIVE_SIZE'),
                            ('SUCCESSOR_SOURCE_ASSETS_ZIP_SHA256', 'SOURCE_ASSETS_ARCHIVE_SHA256')):
        need(os.environ[bound] == os.environ[ordinary])
    need(admitted['status'] == 'passed' and admitted['stage'] == 'complete'
         and admitted['product'] == product and admitted['productTree'] == tree
         and admitted['assembledSource'] == SUCCESSOR and admitted['assembledSourceTree'] == SUCCESSOR_TREE
         and admitted['sourceRun'] == int(run_id) and admitted['sourceWrapper'] == wrapper
         and admitted['verifiedGeneratedFiles'] == 7 and admitted['releaseAcceptance'] is False)


def authenticate_successor_map(cli):
    from qualification import ASSETS as PACKAGE_ASSETS, artifact, root as qualification_root, run

    present = subprocess.run(['git', 'cat-file', '-e', MAP_WRAPPER + '^{commit}'],
                             cwd=REPO, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             check=False).returncode == 0
    if present:
        need(git('show', '-s', '--format=%P', MAP_WRAPPER) == SUCCESSOR)
        need(git('diff', '--name-status', SUCCESSOR, MAP_WRAPPER) == f'A\t{SOURCE_WORKFLOW}')
        entry = git('ls-tree', MAP_WRAPPER, '--', SOURCE_WORKFLOW)
        need(re.fullmatch(rf'100644 blob [0-9a-f]{{40}}\t{re.escape(SOURCE_WORKFLOW)}', entry))
        workflow = subprocess.check_output(['git', 'show', MAP_WRAPPER + ':' + SOURCE_WORKFLOW], cwd=REPO)
        need(hashlib.sha256(workflow).hexdigest() == MAP_WORKFLOW_SHA)
    run(MAP_RUN, MAP_WRAPPER, MAP_BRANCH, SOURCE_WORKFLOW, 'map10k-successor')
    counts = artifact(MAP_RUN, MAP_WRAPPER, MAP_COUNTS, 'map10k-successor-counts', ('counts.json',))['counts.json']
    need(hashlib.sha256(counts).hexdigest() == MAP_RECEIPT_SHA)
    receipt = json.loads(counts)
    need(receipt['runId'] == MAP_RUN and receipt['wrapperSha'] == MAP_WRAPPER and receipt['attempt'] == 1
         and receipt['kind'] == 'persisted-map-10k-functional' and receipt['status'] == 'passed'
         and receipt['sourceSha'] == SUCCESSOR and receipt['sourceTree'] == SUCCESSOR_TREE
         and receipt['frames'] == 10000 and receipt['samples'] == 1 and receipt['laterPages'] == 12
         and receipt['navigationChecks'] == 3 and receipt['navigationExtraRequests'] == 0
         and receipt['timingMeasured'] is False and receipt['proofScriptSha256'] == PROOF_SHA)
    assets = artifact(MAP_RUN, MAP_WRAPPER, MAP_ASSETS, 'map10k-successor-assets', PACKAGE_ASSETS)
    need(hashlib.sha256(assets['assets.sha256']).hexdigest() == MAP_UI_SHA == os.environ['MAP_UI_MANIFEST_SHA256'])
    installed = cli.parent.parent / 'current/share/xtrace/web'
    for name, payload in assets.items():
        need(payload == (qualification_root() / 'private/assets' / name).read_bytes()
             == (REPO / ASSETS / name).read_bytes() == (installed / name).read_bytes())


def package_identity():
    identity()
    product = os.environ['MAP_PRODUCT']
    need(product == os.environ['PRODUCT'] == git('rev-parse', 'HEAD'))
    need(os.environ['MAP_PRODUCT_TREE'] == os.environ['PRODUCT_TREE'] == git('rev-parse', 'HEAD^{tree}'))
    need(git('show', '-s', '--format=%P', product) == SUCCESSOR)
    need(git('rev-parse', SUCCESSOR + '^{tree}') == SUCCESSOR_TREE)
    for path, blob in INSTRUMENTS.items():
        need(git('rev-parse', SUCCESSOR + ':' + path) == git('rev-parse', product + ':' + path) == blob)
    need(os.environ['EXPECTED_UI_MANIFEST_SHA256'] == os.environ['MAP_UI_MANIFEST_SHA256'])
    authenticate_successor_qualification(product, os.environ['MAP_PRODUCT_TREE'])
    changed = git('diff', '--name-only', SUCCESSOR, product).splitlines()
    need(changed and all(path.startswith(ASSETS.as_posix() + '/') for path in changed))

    shared = load_package()
    ordinary = safe_read(ROOT / 'safe/package.json')
    need(ordinary.get('status') == 'pass' and ordinary.get('exitCode') == 0)
    projection = verify_projection(ordinary)
    for key in ('sourceSha', 'sourceTree', 'uiManifestSha256', 'archiveSha256',
                'packageManifestSha256', 'installedCliSha256'):
        need(ordinary[key] == shared[key])
    need(shared['archiveSha256'] == digest(Path(shared['archive'])))
    prefix = Path(shared['prefix'])
    payload = prefix / 'current'
    cli = prefix / 'bin/xtrace'
    manifest_path = payload / MANIFEST
    manifest = json.loads(manifest_path.read_bytes())
    entry, = [entry for entry in manifest['files'] if entry['path'] == 'bin/xtrace']
    need(manifest['sourceCommit'] == product and manifest['platform'] == 'linux-x86_64')
    need(digest(manifest_path) == ordinary['packageManifestSha256'])
    need(cli.resolve(strict=True) == (payload / 'bin/xtrace').resolve(strict=True))
    need(entry['mode'] == '0755' and entry['size'] == cli.stat().st_size)
    need(digest(cli) == entry['sha256'] == ordinary['installedCliSha256'])
    return cli, ordinary, projection

def command(label, args, env):
    with (SUBDIR / 'logs' / f'{label}.log').open('xb') as log:
        process = subprocess.run(args, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, check=False)
    need(process.returncode == 0)

def proof_driver():
    original = REPO / 'tools/qa/replay_scale_browser.mjs'
    need(digest(original) == DRIVER_SHA)
    text = original.read_text()
    before = "      const initialKey = await activeKey();"
    after = "      result.actions.push('bounded_later_map_keyboard_end', 'bounded_later_map_keyboard_up', 'bounded_later_map_keyboard_home');"
    need(text.count(before) == text.count(after) == 1)
    text = text.replace(before, '      const requestsBeforeMapKeys = totalRequests;\n' + before)
    text = text.replace(after, "      check(totalRequests === requestsBeforeMapKeys);\n      result.actions.push('bounded_map_keys_no_requests');\n" + after)
    data = text.encode()
    need(hashlib.sha256(data).hexdigest() == PROOF_SHA)
    return data

def verify_report(path, ordinary):
    need(path.is_file() and 0 < path.stat().st_size <= 262144)
    report = json.loads(path.read_bytes())
    conditions = report['conditions']
    provenance = report['provenance']
    need(report['schemaVersion'] == 1 and report['kind'] == 'synthetic_replay_scale_browser'
         and report['synthetic'] is True)
    need(provenance['distribution'] == 'installed' and provenance['declaredSourceSha'] == ordinary['sourceSha']
         and provenance['declaredPackageSha256'] == ordinary['archiveSha256']
         and provenance['binarySha256'] == ordinary['installedCliSha256'])
    need(conditions['samples'] == 1 and conditions['fixtureFrames'] == 10000
         and conditions['laterPages'] == 12 and conditions['verifyMapTreeWindow'] is True)
    sample, = report['samples']
    summary = report['summary']
    need(sample['status'] == 'exercised' and sample['initial'] is None and not sample['failures']
         and sample['externalRequests'] == sample['pageErrors'] == 0)
    need(summary['functionalFailures'] == 0 and summary['completeJourneySamples'] == 1
         and summary['validInitialSamples'] == 0 and summary['samplesOver1500Ms'] is None)
    required = {'initial_steps_and_details_identity_matched', 'constrained_map_dock_next',
                'constrained_map_dock_back', 'later_steps_return_focus_without_requests',
                'bounded_later_map_keyboard_end', 'bounded_later_map_keyboard_up',
                'bounded_later_map_keyboard_home', 'bounded_map_keys_no_requests'}
    required.update(f'load_later_{index}' for index in range(1, 13))
    need(required <= set(sample['actions']))
    end, = [item for item in sample['dom'] if item['phase'] == 'bounded_later_map_end']
    mounted, visible = end['mapTreeRows'], end['visibleMapTreeRows']
    need(type(mounted) is int and type(visible) is int and 0 < visible <= mounted <= 80)
    return dict(mountedAtEnd=mounted, visibleAtEnd=visible)

def main():
    for path in (SUBDIR, SUBDIR / 'logs', SUBDIR / 'fixture'):
        path.mkdir(mode=0o700)
    result('admission', 'failed')
    cli, ordinary, projection = package_identity()
    authenticate_historical_map()
    authenticate_successor_map(cli)
    # Child fixture and browser processes need no GitHub API credentials.
    os.environ.pop('GH_TOKEN', None)
    os.environ.pop('GITHUB_TOKEN', None)
    bindings = {key: ordinary[key] for key in ('archiveSha256', 'packageManifestSha256',
                                               'uiManifestSha256', 'installedCliSha256')}
    fixture = SUBDIR / 'fixture'
    manifest = fixture / 'manifest.json'
    env = dict(os.environ, TMPDIR=str(ROOT / 'tmp'), XTRACE_TEST_PRIVATE_SCRATCH=str(fixture),
               XTRACE_SCALE_FIXTURE_MANIFEST=str(manifest), XTRACE_SCALE_XTRACE=str(cli))
    result('fixture', 'failed', **bindings)
    command('fixture', ['cargo', 'test', '--locked', '-p', 'xtrace-cli', '--test', 'replay_scale',
                        FIXTURE_TEST, '--', '--exact'], env)
    log = (SUBDIR / 'logs/fixture.log').read_bytes()
    need(re.search(rb'^test result: ok\. 1 passed; 0 failed; 0 ignored;', log, re.M))
    need(manifest.is_file() and manifest.stat().st_mode & 0o077 == 0)
    need(digest(cli) == ordinary['installedCliSha256'])

    result('browser', 'failed', **bindings)
    temporary = REPO / 'tools/qa/.installed-map-10k-private.mjs'
    raw_report = SUBDIR / 'logs/map-browser.json'
    with temporary.open('xb') as stream:
        try:
            stream.write(proof_driver())
            stream.flush()
            command('browser', ['node', str(temporary), '--manifest', str(manifest), '--xtrace',
                                str(cli), '--source-sha', ordinary['sourceSha'], '--provenance', 'installed',
                                '--package-sha256', ordinary['archiveSha256'], '--later-pages', '12',
                                '--verify-map-tree-window', '--one-map-tree-sample', '--out', str(raw_report)], env)
        finally:
            temporary.unlink()
    result('verify', 'failed', **bindings)
    observed = verify_report(raw_report, ordinary)
    cli_after, ordinary_after, projection_after = package_identity()
    need(cli_after == cli and ordinary_after == ordinary and projection_after == projection)
    result('complete', 'passed', **bindings, **observed, frames=10000, samples=1, laterPages=12,
           timingMeasured=False, mapKeyRequests=0, stepsReturnRequests=0, proofScriptSha256=PROOF_SHA,
           historicalMapSourceRunId=HISTORICAL_RUN, historicalMapSourceWrapper=SOURCE_WRAPPER,
           historicalMapSourceSha=SOURCE, historicalMapSourceReceiptSha256=HISTORICAL_RECEIPT_SHA,
           successorMapSourceRunId=MAP_RUN, successorMapSourceWrapper=MAP_WRAPPER,
           successorMapSourceReceiptSha256=MAP_RECEIPT_SHA, successorMapAssetsZipSha256=MAP_ASSETS[3],
           successorOrdinarySourceRunId=int(os.environ['SUCCESSOR_SOURCE_RUN_ID']),
           successorOrdinarySourceWrapper=os.environ['SUCCESSOR_SOURCE_WRAPPER'],
           successorOrdinarySourceSha=SUCCESSOR, successorOrdinarySourceTree=SUCCESSOR_TREE,
           successorOrdinarySourceAssetsSha256=os.environ['SUCCESSOR_SOURCE_ASSETS_ZIP_SHA256'])

if __name__ == '__main__':
    os.umask(0o077)
    main()
