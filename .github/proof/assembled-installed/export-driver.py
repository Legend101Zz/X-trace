"""Preserve the tracked export judge, adding served-byte bindings per actual viewer."""
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

from common import ROOT as SHARED, REPO, binding, identity, load_package, need, private_json, safe_read
from tools.qa import installed_export_journey as journey

ROOT = Path(os.environ['PROOF_ROOT'])
SCRIPTS = Path(os.environ['PROOF_SCRIPTS'])
REPORT = dict(schemaVersion=1, kind='assembled-installed-export', releaseAcceptance=False,
              status='fail', stage='identity', countsComplete=False, servedAssets=0)
ALLOWED_REASONS = frozenset(('absolute-prerequisites', 'approval-digest', 'archive-digest', 'archive-manifest', 'b3sum-failed', 'b3sum-known-vector', 'b3sum-prerequisite', 'browser-api-categories', 'browser-api-counts', 'browser-api-coverage', 'browser-api-files', 'browser-api-outcome', 'browser-api-parity', 'browser-api-phases', 'browser-api-schema', 'browser-api-source', 'browser-api-source-parity', 'browser-coverage', 'browser-height-probe-checks', 'browser-height-probe-coverage', 'browser-height-probe-identity', 'browser-height-probe-outcome', 'browser-height-probe-schema', 'browser-height-probes', 'browser-receipt-bounds', 'browser-receipt-case', 'browser-receipt-case-duplicate', 'browser-receipt-count-parity', 'browser-receipt-current', 'browser-receipt-duplicate', 'browser-receipt-errors', 'browser-receipt-file', 'browser-receipt-identity', 'browser-receipt-identity-parity', 'browser-receipt-json', 'browser-receipt-missing', 'browser-receipt-outcome', 'browser-receipt-permissions', 'browser-receipt-row', 'browser-receipt-row-cleanup', 'browser-receipt-row-outcome', 'browser-receipt-row-status', 'browser-receipt-schema', 'browser-receipt-sequence', 'browser-receipt-status', 'browser-receipt-substage', 'browser-receipt-viewport', 'catalog-scope-resolution', 'cli-did-not-write', 'cli-inventory', 'cli-membership', 'cli-metadata', 'command-failed', 'command-output-limit', 'command-timeout', 'digest-parity', 'download-bytes', 'duplicate-preview-name', 'duplicate-recipe-ordinal', 'file-byte-digest', 'file-digest-parity', 'fixture-build-location', 'genuine-recording', 'genuine-scan-scope', 'harness-error', 'host-platform', 'installed-agent', 'installed-cli', 'installed-manifest-parity', 'installed-package-parity', 'logical-export-limit', 'observed-endpoint', 'omission-count', 'omission-group-parity', 'omission-parity', 'operation-parity', 'ordinal-parity', 'package-verification', 'prerequisites', 'preview-inventory', 'preview-mode', 'preview-name', 'preview-schema', 'preview-size', 'privacy-hit-or-coverage-gap', 'private-directory-not-fresh', 'private-file-limit', 'private-parent-permissions', 'project-init', 'provenance-shape', 'recipe-ordinal', 'recording-decoding-incomplete', 'revision-parity', 'scan-incomplete', 'scanned-revision-selection', 'selected-operation-count', 'source-dirty', 'source-revision', 'spring-exited-before-ready', 'spring-handler-not-observed', 'spring-output-drain', 'spring-output-io', 'spring-output-limit', 'spring-port-signal', 'spring-readiness', 'spring-recording-terminal', 'spring-shutdown-status', 'spring-shutdown-timeout', 'spring-workload', 'supported-observed-scope', 'supported-orders-uuid-alias', 'unsafe-cli-member', 'zip-bytes', 'zip-determinism', 'zip-duplicate', 'zip-membership', 'zip-mode', 'zip-path'))
base_run = journey.Runner.run


def instrumented_run(self, args, *positional, **keywords):
    if len(args) == 2 and args == ['node', str(REPO / 'web/app/scripts/installed-export-journey.mjs')]:
        args = ['node', '--import', str(SCRIPTS / 'export-assets-hook.mjs'), args[1]]
    return base_run(self, args, *positional, **keywords)


def checkpoint(stage):
    REPORT['stage'] = stage
    private_json(ROOT / 'safe/report.json', REPORT)


def run():
    identity()
    shared = load_package()
    REPORT.update(binding(shared), journeyBlob=os.environ['JOURNEY_BLOB'])
    private_json(ROOT / 'safe/report.json', REPORT)
    served = ROOT / 'private/export-served.jsonl'
    with served.open('xb'):
        pass
    journey.Runner.run = instrumented_run
    args = []
    for name, value in (('prefix', shared['prefix']), ('package', shared['archive']),
                        ('package-sha256', shared['archiveSha256']), ('source-sha', os.environ['PRODUCT']),
                        ('repo', str(REPO)), ('fixture-jar', shared['fixture']),
                        ('java', str(Path(os.environ['JAVA_HOME']) / 'bin/java')),
                        ('private-dir', str(ROOT / 'journey')), ('summary', str(ROOT / 'private/summary.json'))):
        args.extend(['--' + name, value])
    os.environ['PATH'] = str(SHARED / 'packages/b3/usr/bin') + os.pathsep + os.environ['PATH']
    checkpoint('installed-journey')
    code = journey.main(args)
    summary = safe_read(ROOT / 'private/summary.json')
    need(summary['sourceSha'] == shared['sourceSha'] and summary['packageSha256'] == shared['archiveSha256'])
    need(type(summary.get('packageVerified')) is bool)
    REPORT['packageVerified'] = summary['packageVerified']
    reason = summary.get('reason')
    REPORT['reason'] = reason if reason in ALLOWED_REASONS else ('unclassified' if reason is not None else None)
    private_json(ROOT / 'safe/report.json', REPORT)
    if summary.get('packageVerified') is True:
        for key in ('genuineRequests', 'viewports', 'downloads', 'logicalFilesCompared', 'privacySurfaces'):
            value = summary.get(key)
            need(type(value) is int and 0 <= value <= 100000)
            REPORT[key] = value
        for key in ('sameProjectCatalogLinked', 'supportedOrdersUuidAlias'):
            value = summary.get(key)
            need(type(value) is bool)
            REPORT[key] = value
        _, projection = journey.load_browser_receipt(ROOT / 'journey/browser/browser.private.json',
                expected_identity={'sourceSha': shared['sourceSha'], 'packageSha256': shared['archiveSha256']},
                expected_evidence_source=journey.browser_evidence_source(REPO))
        REPORT.update(projection)
        private_json(ROOT / 'safe/report.json', REPORT)
    need(code == 0 and summary.get('status') == 'pass' and summary.get('packageVerified') is True)
    need(summary['genuineRequests'] == 1 and summary['viewports'] == 10 and summary['downloads'] == 100
         and summary['logicalFilesCompared'] == 480 and summary['privacySurfaces'] == 5)
    need(REPORT['browserStatus'] == 'pass' and REPORT['browserCleanup'] == 'pass')
    checkpoint('served-bindings')
    info = served.lstat()
    import stat
    need(stat.S_ISREG(info.st_mode) and info.st_mode & 0o777 == 0o600 and info.st_uid == os.getuid()
         and info.st_nlink == 1 and info.st_size <= 16384)
    rows = [json.loads(line) for line in served.read_text().splitlines()]
    need(len(rows) == 10)
    expected = {(width, pointer) for width in (320, 736, 1024, 1280, 1440) for pointer in ('fine', 'coarse')}
    need({(row['width'], row['pointer']) for row in rows} == expected)
    for row in rows:
        need(set(row) == {'sourceSha', 'sourceTree', 'archiveSha256', 'uiManifestSha256', 'installedCliSha256',
                          'installedAgentSha256', 'width', 'height', 'pointer', 'servedAssets'})
        need(all(row[key] == shared[key] for key in ('sourceSha', 'sourceTree', 'archiveSha256',
                    'uiManifestSha256', 'installedCliSha256', 'installedAgentSha256')))
        need(row['height'] == 900 and row['servedAssets'] == 6)
    load_package()
    REPORT.update(status='pass', stage='complete', countsComplete=True, servedAssets=60)
    private_json(ROOT / 'safe/report.json', REPORT)


if __name__ == '__main__':
    os.umask(0o077)
    checkpoint('identity')
    try:
        run()
    except Exception:
        with (ROOT / 'logs/driver-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)
        checkpoint(REPORT['stage'])
        raise SystemExit(1)
