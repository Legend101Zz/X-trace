"""Admit only closed export proof fields before publication or native collection."""
import hashlib
import json
import os
import re

from common import ROOT, REPO, binding, need, safe_read
from tools.qa import installed_export_journey as journey
from tools.release.private_roots import open_private_file_read

ALLOWED_REASONS = frozenset(('absolute-prerequisites', 'approval-digest', 'archive-digest', 'archive-manifest', 'b3sum-failed', 'b3sum-known-vector', 'b3sum-prerequisite', 'browser-api-categories', 'browser-api-counts', 'browser-api-coverage', 'browser-api-files', 'browser-api-outcome', 'browser-api-parity', 'browser-api-phases', 'browser-api-schema', 'browser-api-source', 'browser-api-source-parity', 'browser-coverage', 'browser-height-probe-checks', 'browser-height-probe-coverage', 'browser-height-probe-identity', 'browser-height-probe-outcome', 'browser-height-probe-schema', 'browser-height-probes', 'browser-receipt-bounds', 'browser-receipt-case', 'browser-receipt-case-duplicate', 'browser-receipt-count-parity', 'browser-receipt-current', 'browser-receipt-duplicate', 'browser-receipt-errors', 'browser-receipt-file', 'browser-receipt-identity', 'browser-receipt-identity-parity', 'browser-receipt-json', 'browser-receipt-missing', 'browser-receipt-outcome', 'browser-receipt-permissions', 'browser-receipt-row', 'browser-receipt-row-cleanup', 'browser-receipt-row-outcome', 'browser-receipt-row-status', 'browser-receipt-schema', 'browser-receipt-sequence', 'browser-receipt-status', 'browser-receipt-substage', 'browser-receipt-viewport', 'catalog-scope-resolution', 'cli-did-not-write', 'cli-inventory', 'cli-membership', 'cli-metadata', 'command-failed', 'command-output-limit', 'command-timeout', 'digest-parity', 'download-bytes', 'duplicate-preview-name', 'duplicate-recipe-ordinal', 'file-byte-digest', 'file-digest-parity', 'fixture-build-location', 'genuine-recording', 'genuine-scan-scope', 'harness-error', 'host-platform', 'installed-agent', 'installed-cli', 'installed-manifest-parity', 'installed-package-parity', 'logical-export-limit', 'observed-endpoint', 'omission-count', 'omission-group-parity', 'omission-parity', 'operation-parity', 'ordinal-parity', 'package-verification', 'prerequisites', 'preview-inventory', 'preview-mode', 'preview-name', 'preview-schema', 'preview-size', 'privacy-hit-or-coverage-gap', 'private-directory-not-fresh', 'private-file-limit', 'private-parent-permissions', 'project-init', 'provenance-shape', 'recipe-ordinal', 'recording-decoding-incomplete', 'revision-parity', 'scan-incomplete', 'scanned-revision-selection', 'selected-operation-count', 'source-dirty', 'source-revision', 'spring-exited-before-ready', 'spring-handler-not-observed', 'spring-output-drain', 'spring-output-io', 'spring-output-limit', 'spring-port-signal', 'spring-readiness', 'spring-recording-terminal', 'spring-shutdown-status', 'spring-shutdown-timeout', 'spring-workload', 'supported-observed-scope', 'supported-orders-uuid-alias', 'unsafe-cli-member', 'zip-bytes', 'zip-determinism', 'zip-duplicate', 'zip-membership', 'zip-mode', 'zip-path'))

STAGES = frozenset(('identity', 'installed-journey', 'summary-metadata', 'summary-open', 'summary-byte-bound',
                    'summary-producer-parity', 'summary-identity', 'summary-counts', 'browser-receipt',
                    'journey-verdict', 'served-bindings', 'complete'))
CELLS = frozenset(f"{width}-{pointer}" for width in journey.WIDTHS for pointer in ('fine', 'coarse'))
SUCCESS = {'replay': 'passed', 'tour': 'pass', 'export': 'pass', 'visuals': 'pass'}
BASE = frozenset(('schemaVersion', 'kind', 'releaseAcceptance', 'status', 'stage', 'countsComplete', 'servedAssets'))
NUMBERS = {'summaryBytes': (0, 65537), 'journeyExit': (0, 1), 'failedCommandOrdinal': (1, 100000),
           'genuineRequests': (0, 1), 'viewports': (0, 10), 'downloads': (0, 100),
           'logicalFilesCompared': (0, 100000), 'privacySurfaces': (0, 5)}
REASONS = frozenset(('reason', 'browserReceiptFailure', 'journeyFailureReason', 'wrapperFailureReason'))
FLAGS = frozenset(('packageVerified', 'sameProjectCatalogLinked', 'supportedOrdersUuidAlias'))
BROWSER = frozenset(('browserCompletedCases', 'browserStatus', 'browserFailureSubstage', 'browserCleanup',
                     'browserIdentity', 'browserCurrent', 'browserCheckpointSequence', 'browserApiEvidenceSource',
                     'browserHeightProbes'))
DIAGNOSTICS = frozenset(('journeyStatus', 'summaryMetadata', 'failedCommandStatus', 'wrapperFailureLines',
                         'journeyFailureLines', 'summarySha256'))


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def canonical(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def cells(rows):
    return {f"{row['width']}-{'coarse' if row['coarse'] else 'fine'}" for row in rows}


def checked_shard(entry, row, directory):
    need(type(entry) is dict and set(entry) == {'cell', 'sha256'})
    name = f"{row['width']}-{'coarse' if row['coarse'] else 'fine'}"
    need(name in CELLS and entry['cell'] == name)
    shard = safe_read(directory / (name + '.projection.json'))
    encoded = canonical(shard)
    need(hashlib.sha256(encoded).hexdigest() == entry['sha256'] and encoded == canonical(row))


def checked_browser(raw, shared):
    # Reconstruct the allowlisted projection from the actual bound private browser receipt.
    # Admitted shards must agree byte-for-byte with these rows, even for a failed journey.
    ext = ROOT / 'export'
    _, projection = journey.load_browser_receipt(ext / 'journey/browser/browser.private.json',
            expected_identity={'sourceSha': shared['sourceSha'], 'packageSha256': shared['archiveSha256']},
            expected_evidence_source=journey.browser_evidence_source(REPO))
    need(set(projection) == BROWSER | {'browserRows', 'downloads', 'viewports'})
    for key in BROWSER | {'downloads', 'viewports'}:
        need(canonical(raw[key]) == canonical(projection[key]))
    index = raw['browserRowIndex']
    rows = projection['browserRows']
    need(type(index) is list and len(index) == len(rows) <= 10)
    for entry, row in zip(index, rows):
        checked_shard(entry, row, ext / 'private')
    return projection


def checked_stage(raw, shared):
    need(type(raw) is dict and BASE <= raw.keys())
    expected = {} if shared is None else binding(shared)
    allowed = BASE | expected.keys() | NUMBERS.keys() | FLAGS | REASONS | BROWSER | DIAGNOSTICS | {
        'journeyBlob', 'browserRowIndex'}
    need(raw.keys() <= allowed)
    need(integer(raw['schemaVersion'], 1, 1) and raw['kind'] == 'assembled-installed-export'
         and raw['releaseAcceptance'] is False and raw['status'] in ('pass', 'fail')
         and raw['stage'] in STAGES and type(raw['countsComplete']) is bool and integer(raw['servedAssets'], 0, 60))
    out = {key: raw[key] for key in BASE}
    if raw['stage'] != 'identity' or 'journeyBlob' in raw or raw.keys() & expected.keys():
        need(shared is not None and all(canonical(raw[key]) == canonical(value) for key, value in expected.items())
             and raw['journeyBlob'] == os.environ['JOURNEY_BLOB'])
        out.update(expected, journeyBlob=os.environ['JOURNEY_BLOB'])
    for key, bounds in NUMBERS.items():
        if key in raw:
            need(integer(raw[key], *bounds))
            out[key] = raw[key]
    for key in FLAGS & raw.keys():
        need(type(raw[key]) is bool or (key == 'supportedOrdersUuidAlias' and raw[key] is None and raw['status'] == 'fail'))
        out[key] = raw[key]
    for key in REASONS & raw.keys():
        need(raw[key] is None or raw[key] in ALLOWED_REASONS | {'unclassified'})
        out[key] = raw[key]
    if 'journeyStatus' in raw:
        need(raw['journeyStatus'] in ('fail', 'pass'))
        out['journeyStatus'] = raw['journeyStatus']
    for key in ('journeyFailureLines', 'wrapperFailureLines'):
        if key in raw:
            lines = raw[key]
            need(type(lines) is list and len(lines) <= 8 and all(integer(line, 1, 2000) for line in lines))
            out[key] = lines
    if 'summaryMetadata' in raw:
        meta = raw['summaryMetadata']
        need(type(meta) is dict and set(meta) == {'owner', 'mode600', 'singleLink', 'regular'}
             and all(type(v) is bool for v in meta.values()))
        out['summaryMetadata'] = meta
    if 'failedCommandStatus' in raw:
        s = raw['failedCommandStatus']
        need('failedCommandOrdinal' in out and type(s) is dict and set(s) == {'exitCode','timedOut','outputLimited'}
             and integer(s['exitCode'], -255, 255) and type(s['timedOut']) is bool and type(s['outputLimited']) is bool)
        out['failedCommandStatus'] = s
    if 'summarySha256' in raw:
        with os.fdopen(open_private_file_read(ROOT / 'export/private/summary.json'), 'rb') as stream:
            n = os.fstat(stream.fileno()).st_size
            need(integer(n, 1, 65536) and n == out['summaryBytes'])
            actual = stream.read(65537)
            need(len(actual) == n and hashlib.sha256(actual).hexdigest() == raw['summarySha256'])
        out['summarySha256'] = hashlib.sha256(actual).hexdigest()
    if raw.keys() & (BROWSER | {'browserRowIndex'}):
        need(shared is not None and out.get('packageVerified') is True and 'summarySha256' in out)
        out.update(checked_browser(raw, shared))
    if raw['status'] == 'pass':
        need(raw['stage'] == 'complete' and raw['countsComplete'] and raw['servedAssets'] == 60
             and 'summarySha256' in out and all(out['summaryMetadata'].values()) and out['journeyExit'] == 0
             and out['journeyStatus'] == 'pass' and all(out[key] is True for key in FLAGS)
             and out['genuineRequests'] == 1 and out['downloads'] == out['browserCompletedCases'] == 100
             and out['logicalFilesCompared'] == 480 and out['privacySurfaces'] == 5 and out['viewports'] == 10
             and out['browserStatus'] == out['browserCleanup'] == 'pass' and out['reason'] is None
             and out['browserReceiptFailure'] is None and cells(out['browserRows']) == CELLS and len(out['browserRows']) == 10)
    else:
        need(not raw['countsComplete'] and raw['stage'] != 'complete')
    return out


def export_report(shared):
    path = ROOT / 'export/safe/report.json'
    if not path.exists():
        return {'status': 'not-reached'}
    try:
        return checked_stage(safe_read(path), shared)
    except Exception:
        return {'status': 'invalid', 'aggregationFailure': 'export-stage-or-rows'}


def export_diagnostic(shared):
    path = ROOT / 'safe/export-diagnostic.json'
    if not path.exists():
        return None
    try:
        raw = safe_read(path)
        expected = binding(shared)
        need(type(raw) is dict and set(raw) == expected.keys() | {
            'schemaVersion', 'kind', 'releaseAcceptance', 'status', 'category', 'reason', 'streams', 'ciphertextSha256'})
        need(all(canonical(raw[key]) == canonical(value) for key, value in expected.items()))
        need(integer(raw['schemaVersion'], 1, 1) and raw['kind'] == 'installed-export-command-diagnostic'
             and raw['releaseAcceptance'] is False and integer(raw['streams'], 0, 2))
        identified = raw['status'] in ('failure-identified', 'encrypted', 'streams-empty')
        need(identified or raw['status'] in ('command-evidence-incomplete', 'summary-unavailable',
                                               'outside-preverification-command-scope'))
        if identified:
            need(raw['category'] in ('git-revision', 'git-status', 'verify-archive', 'verify-installed', 'installer-verify')
                 and raw['reason'] in ('command-failed', 'command-timeout', 'command-output-limit'))
        else:
            need(raw['category'] is None and raw['reason'] is None)
        if raw['status'] == 'encrypted':
            need(raw['streams'] > 0 and isinstance(raw['ciphertextSha256'], str)
                 and re.fullmatch('[0-9a-f]{64}', raw['ciphertextSha256']))
            with os.fdopen(open_private_file_read(ROOT / 'encrypted/export-command-diagnostic.cms'), 'rb') as stream:
                need(0 < os.fstat(stream.fileno()).st_size <= 256 * 1024 * 1024
                     and hashlib.file_digest(stream, 'sha256').hexdigest() == raw['ciphertextSha256'])
        else:
            need(raw['streams'] == 0 and raw['ciphertextSha256'] is None)
        return raw
    except Exception:
        return {'status': 'invalid', 'aggregationFailure': 'export-command-diagnostic'}
