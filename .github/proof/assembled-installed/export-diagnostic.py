"""Name a failed export preverification command from its private runner records."""
import os
from pathlib import Path
import sys

from common import ROOT, REPO, binding, load_package, need, private_json, safe_read
from tools.release.private_roots import open_private_file_read
from visuals import encrypt


def command_failure(metadata):
    need(set(metadata) == {'exitCode', 'timedOut', 'outputLimited'})
    need(type(metadata['exitCode']) is int and type(metadata['timedOut']) is bool
         and type(metadata['outputLimited']) is bool)
    if metadata['timedOut']:
        return 'command-timeout'
    if metadata['outputLimited']:
        return 'command-output-limit'
    return 'command-failed' if metadata['exitCode'] else None


def preserve(shared, summary, report):
    prefix = Path(shared['prefix'])
    installed = prefix / 'current'
    verifier = str(REPO / 'packaging/verify_package.py')
    commands = (
        ('git-revision', ['git', '-C', str(REPO), 'rev-parse', 'HEAD']),
        ('git-status', ['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no']),
        ('verify-archive', [sys.executable, verifier, shared['archive'], '--repo', str(REPO), '--run-binary']),
        ('verify-installed', [sys.executable, verifier, str(installed), '--repo', str(REPO), '--run-binary']),
        ('installer-verify', ['sh', str(installed / 'install.sh'), 'verify', '--prefix', str(prefix)]),
    )
    logs = ROOT / 'export/journey/commands'
    for index, (category, argv) in enumerate(commands, 1):
        # Admit only a contiguous prefix of this exact preverification sequence.
        need(safe_read(logs / f'{index}.command.json') == {'argv': argv})
        reason = command_failure(safe_read(logs / f'{index}.status.json'))
        if reason is None:
            continue
        need(reason == summary['reason'])
        report.update(status='failure-identified', category=category, reason=reason)
        private_json(ROOT / 'safe/export-diagnostic.json', report)
        tails = []
        for stream_name in ('stdout', 'stderr'):
            with os.fdopen(open_private_file_read(logs / f'{index}.{stream_name}'), 'rb') as stream:
                length = os.fstat(stream.fileno()).st_size
                stream.seek(max(0, length - 128 * 1024))
                tail = stream.read(128 * 1024)
                need(len(tail) == min(length, 128 * 1024))
            if tail:
                tails.append((stream_name + '.tail', tail))
        if tails:
            report.update(status='encrypted', streams=len(tails),
                          ciphertextSha256=encrypt('export-command-diagnostic.cms', tails))
        else:
            report['status'] = 'streams-empty'
        return
    raise ValueError('no matching preverification command failure')


def main():
    shared = load_package()
    export = ROOT / 'export'
    report = dict(schemaVersion=1, kind='installed-export-command-diagnostic', releaseAcceptance=False,
                  status='summary-unavailable', category=None, reason=None, streams=0, ciphertextSha256=None,
                  **binding(shared))
    receipt = ROOT / 'safe/export-diagnostic.json'
    private_json(receipt, report)
    # The driver binds its compact receipt byte-for-byte to the tracked producer.
    path = export / 'safe/report.json'
    if not path.exists():
        return
    summary = safe_read(path)
    need(all(summary.get(key) == value for key, value in binding(shared).items()))
    if summary.get('journeyStatus') not in ('pass', 'fail'):
        return
    need(type(summary.get('packageVerified')) is bool and summary.get('summarySha256'))
    if (summary['journeyStatus'] == 'fail' and not summary['packageVerified']
            and summary.get('reason') in ('command-failed', 'command-timeout', 'command-output-limit')):
        report['status'] = 'command-evidence-incomplete'
        private_json(receipt, report)
        preserve(shared, summary, report)
    else:
        report['status'] = 'outside-preverification-command-scope'
    private_json(receipt, report)
    if report['status'] == 'encrypted':
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('ready=true\n')


if __name__ == '__main__':
    os.umask(0o077)
    main()
