"""Bounded projection for the hosted preflight-only receipt; no private content."""
import json
import os
from pathlib import Path
import re
import stat

PHASES = {'identity', 'version', 'init', 'list', 'empty', 'receipt'}
SIGNALS = {None, 'SIGTERM', 'SIGKILL', 'other'}
KEYS = {'schemaVersion', 'kind', 'source', 'releaseAcceptance', 'package', 'preflight', 'observation',
        'attachExit', 'processExit', 'receiptValid', 'cleanup', 'status'}


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def read_document(file, *, marker=False):
    try:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 4096):
                return None
            data = stream.read(4097)
            after = os.fstat(stream.fileno())
            if len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return None
            doc = json.loads(data, object_pairs_hook=pairs)
            if marker and (len(data) > 1024 or data != (json.dumps(doc, separators=(',', ':')) + '\n').encode()):
                return None
            return doc if isinstance(doc, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def exit_code(value):
    return value is None or type(value) is int and 0 <= value <= 255


def valid_marker(obs):
    if not isinstance(obs, dict) or set(obs) != {'phase', 'status', 'code', 'signal'}:
        return False
    phase, status, code, signal = (obs[k] for k in ('phase', 'status', 'code', 'signal'))
    return (isinstance(phase, str) and phase in PHASES and status in ('running', 'failed', 'passed')
            and exit_code(code) and isinstance(signal, (str, type(None))) and signal in SIGNALS
            and (code is None or signal is None) and (status != 'passed' or phase == 'receipt')
            and (status == 'failed' or (code is None and signal is None)))


def validate(doc, source):
    if not isinstance(doc, dict) or set(doc) != KEYS or not re.fullmatch('[0-9a-f]{40}', source):
        return False
    package, stage, cleanup = doc['package'], doc['preflight'], doc['cleanup']
    attach, process, receipt, obs = (doc[k] for k in ('attachExit', 'processExit', 'receiptValid', 'observation'))
    if not (type(doc['schemaVersion']) is int and doc['schemaVersion'] == 1
            and doc['kind'] == 'vendure-installed-preflight-only' and doc['source'] == source
            and doc['releaseAcceptance'] is False and package in ('unreached', 'running', 'failed', 'verified')
            and stage in ('unreached', 'running', 'failed', 'passed')
            and cleanup in ('unreached', 'running', 'passed', 'retained', 'failed')
            and doc['status'] in ('incomplete', 'passed') and exit_code(attach) and exit_code(process)
            and (receipt is None or type(receipt) is bool) and (obs is None or valid_marker(obs))):
        return False
    if stage == 'unreached':
        return all(v is None for v in (attach, process, receipt, obs)) and cleanup == 'unreached' and doc['status'] == 'incomplete'
    if package != 'verified':
        return False
    if stage == 'running':
        return all(v is None for v in (attach, process, receipt)) and cleanup == 'unreached' and doc['status'] == 'incomplete'
    if receipt is None:
        return False
    completed = attach == 0 and process == 0 and receipt and obs is not None and obs['status'] == 'passed'
    return (stage == 'passed') == completed and (doc['status'] == 'passed') == (completed and cleanup == 'passed')


def reached_document(doc, source, outcome, image_built):
    if outcome not in ('success', 'failure', 'cancelled', 'timed_out') or not image_built or not validate(doc, source):
        return None
    return doc


def main():
    root = Path(os.environ['PROOF'])
    source = os.environ['PRODUCT']
    doc = read_document(root / 'safe/preflight.json')
    if validate(doc, source) and doc['preflight'] == 'running':
        # A job interruption can leave the last in-container phase beyond the host checkpoint.
        marker = read_document(root / 'pair/installed/control/preflight-observation.json', marker=True)
        if marker and list(marker) == ['phase', 'status', 'code', 'signal'] and valid_marker(marker):
            doc['observation'] = marker
    outcome = os.environ['PREFLIGHT_OUTCOME']
    image_built = os.environ['IMAGE_BUILT'] == 'true'
    doc = reached_document(doc, source, outcome, image_built)
    output = {'schemaVersion': 1, 'kind': 'vendure-preflight-focused-projection', 'source': source,
              'wrapper': os.environ['GITHUB_SHA'], 'runId': int(os.environ['GITHUB_RUN_ID']),
              'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'releaseAcceptance': False,
              'stepOutcome': outcome, 'imageBuilt': True if image_built else None, 'observation': doc,
              'status': 'passed' if doc and doc['status'] == 'passed' and os.environ['PREFLIGHT_OUTCOME'] == 'success' else 'incomplete'}
    path = root / 'safe/projected.json'
    with path.open('x') as stream:
        json.dump(output, stream, sort_keys=True)
        stream.write('\n')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('ready=true\n')
    return 0 if output['status'] == 'passed' else 1


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
