"""Two hosted regressions for malformed export receipts; no product or network activity."""
import hashlib
import tempfile
from pathlib import Path

import export_receipt as policy
from common import ROOT, need, private_json


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
    print('exportReceiptAdmissionRegressions=2')


if __name__ == '__main__':
    run()
