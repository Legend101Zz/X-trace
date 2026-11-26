"""Preserve the tracked export judge, adding served-byte bindings per actual viewer."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import traceback

from tools.release.private_roots import open_private_file_read

from common import ROOT as SHARED, REPO, binding, identity, load_package, need, private_json, safe_read
from tools.qa import installed_export_journey as journey
from export_receipt import ALLOWED_REASONS

ROOT = Path(os.environ['PROOF_ROOT'])
SCRIPTS = Path(os.environ['PROOF_SCRIPTS'])
REPORT = dict(schemaVersion=1, kind='assembled-installed-export', releaseAcceptance=False,
              status='fail', stage='identity', countsComplete=False, servedAssets=0)
base_run = journey.Runner.run


def instrumented_run(self, args, *positional, **keywords):
    if len(args) == 2 and args == ['node', str(REPO / 'web/app/scripts/installed-export-journey.mjs')]:
        args = ['node', '--import', str(SCRIPTS / 'export-assets-hook.mjs'), args[1]]
    try:
        return base_run(self, args, *positional, **keywords)
    except Exception:
        if 'failedCommandOrdinal' not in REPORT and 1 <= self.index <= 100000:
            REPORT['failedCommandOrdinal'] = self.index
            path = self.logs / f'{self.index}.status.json'
            if path.exists():
                # A refused or malformed status must not replace the original exception.
                try:
                    observed = safe_read(path)
                    if (set(observed) == {'exitCode', 'timedOut', 'outputLimited'}
                            and type(observed['exitCode']) is int and -255 <= observed['exitCode'] <= 255
                            and all(type(observed[k]) is bool for k in ('timedOut', 'outputLimited'))):
                        REPORT['failedCommandStatus'] = observed
                except Exception:
                    pass
        raise


def checkpoint(stage):
    REPORT['stage'] = stage
    private_json(ROOT / 'safe/report.json', REPORT)


def exception_sites(error, target):
    # Only numerical lines from the pinned module or this reviewed driver may escape.
    tb = error.__traceback__
    lines = []
    while tb is not None:
        if tb.tb_frame.f_code.co_filename == target:
            lines.append(tb.tb_lineno)
        tb = tb.tb_next
    return lines[-8:]


def read_journey(args, shared):
    callback = journey.run
    observed = []

    def observe(options, private, report):
        observed.append(report)
        try:
            return callback(options, private, report)
        except Exception as error:
            if isinstance(error, journey.JourneyFailure) and str(error) in ALLOWED_REASONS:
                REPORT['journeyFailureReason'] = str(error)
            REPORT['journeyFailureLines'] = exception_sites(error, journey.__file__)
            raise

    checkpoint('installed-journey')
    journey.run = observe
    try:
        code = journey.main(args)
    finally:
        journey.run = callback
    REPORT['journeyExit'] = code
    path = ROOT / 'private/summary.json'
    checkpoint('summary-metadata')
    info = path.lstat()
    REPORT['summaryMetadata'] = {'regular': stat.S_ISREG(info.st_mode), 'owner': info.st_uid == os.getuid(),
                                 'mode600': stat.S_IMODE(info.st_mode) == 0o600, 'singleLink': info.st_nlink == 1}
    REPORT['summaryBytes'] = min(info.st_size, 65537)
    checkpoint('summary-open')
    with os.fdopen(open_private_file_read(path), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need(opened.st_dev == path.parent.stat().st_dev)
        size = opened.st_size
        REPORT['summaryBytes'] = min(size, 65537)
        checkpoint('summary-byte-bound')
        need(0 < size <= 65536)
        raw = stream.read(65537)
        need(len(raw) == size)
        with os.fdopen(open_private_file_read(path), 'rb') as reopened:
            need(os.path.samestat(opened, os.fstat(reopened.fileno()))
                 and os.fstat(reopened.fileno()).st_size == size and reopened.read(65537) == raw)
    checkpoint('summary-producer-parity')
    if observed:
        summary, = observed
    else:
        # The tracked runner can fail its prerequisites before entering run().
        summary = safe_read(path)
    canonical = (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode()
    need(canonical == raw)
    REPORT['summarySha256'] = hashlib.sha256(raw).hexdigest()
    checkpoint('summary-identity')
    need(summary.get('schemaVersion') == 1 and summary.get('kind') == 'installed-spring-export-journey'
         and summary.get('releaseEvidence') is False and summary.get('status') in ('pass', 'fail')
         and summary.get('sourceSha') == shared['sourceSha'] and summary.get('packageSha256') == shared['archiveSha256']
         and type(summary.get('packageVerified')) is bool)
    return code, summary


def retain_projection(projection):
    # One validated viewport fits the ordinary private JSON limits. The combined ten do not.
    index = []
    for row in projection['browserRows']:
        width, coarse = row['width'], row['coarse']
        need(type(width) is int and width in journey.WIDTHS and type(coarse) is bool)
        name = f"{width}-{'coarse' if coarse else 'fine'}"
        path = ROOT / 'private' / (name + '.projection.json')
        need(not path.exists())
        private_json(path, row)
        need(safe_read(path) == row)
        raw = (json.dumps(row, sort_keys=True) + '\n').encode()
        index.append({'cell': name, 'sha256': hashlib.sha256(raw).hexdigest()})
    REPORT.update({key: value for key, value in projection.items() if key != 'browserRows'})
    REPORT['browserRowIndex'] = index


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
    code, summary = read_journey(args, shared)
    REPORT['packageVerified'] = summary['packageVerified']
    REPORT['journeyStatus'] = summary['status']
    for key in ('reason', 'browserReceiptFailure'):
        reason = summary.get(key)
        REPORT[key] = reason if isinstance(reason, str) and reason in ALLOWED_REASONS else (
            'unclassified' if reason is not None else None)
    checkpoint('summary-counts')
    for key in ('genuineRequests', 'viewports', 'downloads', 'logicalFilesCompared', 'privacySurfaces'):
        value = summary.get(key)
        need(type(value) is int and 0 <= value <= 100000)
        REPORT[key] = value
    for key in ('sameProjectCatalogLinked', 'supportedOrdersUuidAlias'):
        value = summary.get(key)
        need(type(value) is bool or (key == 'supportedOrdersUuidAlias' and value is None and code != 0))
        REPORT[key] = value
    checkpoint('browser-receipt')
    if summary['packageVerified']:
        _, projection = journey.load_browser_receipt(ROOT / 'journey/browser/browser.private.json',
                expected_identity={'sourceSha': shared['sourceSha'], 'packageSha256': shared['archiveSha256']},
                expected_evidence_source=journey.browser_evidence_source(REPO))
        need(all(summary.get(key) == value for key, value in projection.items()))
        retain_projection(projection)
    checkpoint('journey-verdict')
    need(code == 0 and summary.get('status') == 'pass' and summary.get('packageVerified') is True)
    need(summary['genuineRequests'] == 1 and summary['viewports'] == 10 and summary['downloads'] == 100
         and summary['logicalFilesCompared'] == 480 and summary['privacySurfaces'] == 5)
    need(REPORT['browserStatus'] == 'pass' and REPORT['browserCleanup'] == 'pass')
    checkpoint('served-bindings')
    info = served.lstat()
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
    except Exception as error:
        REPORT['wrapperFailureLines'] = exception_sites(error, __file__)
        if 'journeyFailureLines' not in REPORT:
            REPORT['journeyFailureLines'] = exception_sites(error, journey.__file__)
        if isinstance(error, journey.JourneyFailure) and str(error) in ALLOWED_REASONS:
            REPORT['wrapperFailureReason'] = str(error)
        with (ROOT / 'logs/driver-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)
        checkpoint(REPORT['stage'])
        raise SystemExit(1)
