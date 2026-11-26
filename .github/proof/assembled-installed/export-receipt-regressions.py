"""Hosted receipt regressions for export admission and bounded replay persistence."""
import hashlib
import tempfile
from pathlib import Path

import export_receipt as policy
from common import ROOT, compact_replay, need, private_json, read_replay, safe_read


def rejected(call):
    try:
        call()
    except RuntimeError:
        return
    raise AssertionError('expected rejection')


def run():
    with tempfile.TemporaryDirectory(dir=ROOT / 'private') as name:
        root = Path(name)
        stage = root / 'export/safe'
        stage.mkdir(parents=True, mode=0o700)
        policy.ROOT = root
        path = stage / 'report.json'
        failed = dict(schemaVersion=1, kind='assembled-installed-export', releaseAcceptance=False,
                      status='fail', stage='identity', countsComplete=False, servedAssets=0)
        private_json(path, failed)
        need(policy.export_report(None) == failed)
        invalid = {'status': 'invalid', 'aggregationFailure': 'export-stage-or-rows'}

        # The replay writer's success spelling never qualifies an export, with or without rows.
        private_json(path, dict(failed, status='passed'))
        need(policy.export_report(None) == invalid and policy.SUCCESS == {
            'replay': 'passed', 'tour': 'pass', 'export': 'pass', 'visuals': 'pass'})

        # Neither unknown stage nor shard/index fields may enter the public failure report.
        private_json(path, dict(failed, unknownField='private-marker'))
        need(policy.export_report(None) == invalid)
        row = {'width': 320, 'coarse': False}
        cell = '320-fine'
        row_path = stage / (cell + '.projection.json')
        entry = {'cell': cell, 'sha256': hashlib.sha256(policy.canonical(row)).hexdigest()}
        private_json(row_path, row)
        policy.checked_shard(entry, row, stage)
        rejected(lambda: policy.checked_shard(dict(entry, unknownField='private-marker'), row, stage))
        bad = dict(row, unknownField='private-marker')
        private_json(row_path, bad)
        entry['sha256'] = hashlib.sha256(policy.canonical(bad)).hexdigest()
        rejected(lambda: policy.checked_shard(entry, row, stage))
    direction = {'targetAvailable': False, 'activated': 0, 'absenceReasonChecked': 1}
    kinds = [{'kind': k, 'observedCount': 0, 'next': dict(direction), 'previous': dict(direction)}
             for k in ('gap', 'exception', 'database', 'http')]
    cells = [{'width': w, 'pointer': pointer, 'kinds': kinds}
             for w in (320, 736, 1024, 1280, 1440) for pointer in ('fine', 'coarse')]
    # A terminal report has 31 non-cell scalar fields on this immutable proof.
    full = {**{f'field{n}': n for n in range(31)}, 'jumpCells': cells}
    sample = ROOT / 'private/replay-regression.json'
    private_json(sample, full)
    rejected(lambda: safe_read(sample))
    private_json(sample, compact_replay(full))
    assert read_replay(sample) == full
    bad = compact_replay(full)
    bad['jumpCells'][1] = bad['jumpCells'][0]
    private_json(sample, bad)
    rejected(lambda: read_replay(sample))
    print('replayReceiptAdmissionRegressions=3')
    print('exportReceiptAdmissionRegressions=2')


if __name__ == '__main__':
    run()
