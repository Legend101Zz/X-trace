"""Bounded native lifecycle receipts. All strings and private checkpoint keys are enumerated."""
import json
import os
import re
import stat
from pathlib import Path

OUTCOMES = ('success', 'failure', 'cancelled', 'skipped')
ACTIONS = ('node22', 'java17', 'package', 'node24', 'regressions', 'campaign')
PACKAGE = ('package-toolchain', 'package-build')
PREP = ('image', 'create', 'assets', 'build', 'seed', 'native')
STAGES = ('install', 'initEmptyList', 'seedIdentity', 'nativeBuild', 'restore', 'startup', 'serverStop', 'workerStop')
STARTUP = ('workerContextReady', 'serverListenBanner', 'serverProcessMatched')
STOCK = (None,'already-exited','unverified','live-match')
SIGNALS = (None, 'SIGTERM', 'SIGKILL', 'other')
PHASES = ('identity', 'version', 'init', 'list', 'empty', 'receipt')

def need(ok):
    if not ok:
        raise ValueError('unverified lifecycle evidence')

def pairs(items):
    need(len(items) == len(dict(items)))
    return dict(items)

def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_uid == os.getuid() and a.st_nlink == 1 and 0 < a.st_size <= limit)
        data = stream.read(limit + 1)
        b = os.fstat(stream.fileno())
        need(len(data) == a.st_size == b.st_size and (a.st_mtime_ns, a.st_ctime_ns) == (b.st_mtime_ns, b.st_ctime_ns))
        return data

def keys(doc, names):
    need(type(doc) is dict and set(doc) == set(names))

def reachable(ordered, values, success, missing):
    reached = True
    for key in ordered:
        cell = values.get(key, missing)
        need(reached or cell == missing)
        reached = reached and cell == success

def terminal(row, worker):
    keys(row, ('live','signalled','closed','code','signal','nodeBeforeStop','nodeGone'))
    for k in ('live','signalled','closed'):
        need(type(row[k]) is bool)
    code, signal, gone = row['code'], row['signal'], row['nodeGone']
    # A ChildProcess with a failed spawn can expose a negative libuv error value.
    need((code is None or type(code) is int and -4095 <= code <= 255) and signal in SIGNALS)
    need(code is None or signal is None)
    need(not row['signalled'] or row['live'])
    need(gone is None or type(gone) is bool)
    before = row['nodeBeforeStop']
    need(before in STOCK and (not worker or (gone is None and before is None)))
    need(before is not None or gone is None)
    stopped = row['live'] and row['signalled'] and row['closed']
    clean = code == 0 and signal is None
    return stopped and ((clean or code is None and signal == 'SIGTERM') if worker else clean and gone is True and before == 'live-match')

def validate_preflight(p):
    keys(p, ('phase','status','code','signal'))
    need(p['phase'] in PHASES and p['status'] in ('running','failed','passed') and p['signal'] in SIGNALS)
    need(p['code'] is None or type(p['code']) is int and 0 <= p['code'] <= 255)
    need(p['code'] is None or p['signal'] is None)
    need(p['status'] == 'failed' or (p['code'] is None and p['signal'] is None))
    need(p['status'] != 'passed' or p['phase'] == 'receipt')
    return p

def validate_progress(row):
    keys(row, ('kind','leg','releaseAcceptance','stages','startupEvidence','preflight','serverStop','workerStop',
               'captureIncompleteNotice','databaseRelease','status'))
    need(row['kind'] == 'vendure-native-ordinary' and row['leg'] == 'installed' and row['releaseAcceptance'] is False)
    stages = row['stages']
    need(type(stages) is dict and set(stages) <= set(STAGES))
    need(all(s in ('running','passed','failed') for s in stages.values()))
    reachable(STAGES[:6], stages, 'passed', None)
    for k in STAGES[6:]:
        if k in stages:
            need(stages.get('startup') in ('passed','failed'))
    if 'serverStop' in stages and 'workerStop' in stages:
        need(stages['serverStop'] in ('passed','failed'))
    p = row['preflight']
    if p is not None:
        need(stages.get('initEmptyList') in ('passed','failed'))
        validate_preflight(p)
    if stages.get('initEmptyList') == 'passed':
        need(p is not None and (p['phase'], p['status']) == ('receipt','passed'))
    start = row['startupEvidence']
    keys(start, (*STARTUP,'serverAtJointReady'))
    need(all(type(start[k]) is bool for k in STARTUP) and start['serverAtJointReady'] in STOCK)
    need(not any(start[k] for k in STARTUP) or 'startup' in stages)
    need(not start['serverProcessMatched'] or start['serverListenBanner'])
    need(start['serverAtJointReady'] is None or all(start[k] for k in STARTUP))
    need(stages.get('startup') != 'passed' or start['serverAtJointReady'] == 'live-match')
    for role in ('server','worker'):
        key = role + 'Stop'
        stop = row[key]
        if stop is not None:
            need(stages.get(key) in ('passed','failed'))
            checked = terminal(stop, role == 'worker')
            need((stages[key] == 'passed') == checked)
            if role == 'server':
                need((stop['nodeBeforeStop'] is not None) == start['serverProcessMatched'])
        else:
            need(stages.get(key) != 'passed')
    marker = row['captureIncompleteNotice']
    need(marker is None or type(marker) is bool and row['serverStop'] is not None and row['serverStop']['closed'])
    db = row['databaseRelease']
    need(db in ('unreached','running','passed','retained') and (db == 'unreached' or 'restore' in stages))
    if db == 'passed':
        if 'serverStop' in stages:
            need(row['serverStop'] is not None and row['serverStop']['closed'] and row['serverStop']['nodeGone'] is True)
        if 'workerStop' in stages:
            need(row['workerStop'] is not None and row['workerStop']['closed'])
    need(row['status'] in ('passed','incomplete'))
    exhaustive = all(stages.get(k) == 'passed' for k in STAGES) and db == 'passed' and marker is False
    need((row['status'] == 'passed') == exhaustive)
    return row

def validate(receipt):
    keys(receipt, ('schemaVersion','kind','source','fixture','wrapper','runId','attempt','releaseAcceptance','actions',
                   'stageMarkers','checkpointStatus','checkpoint','preflightFileStatus','preflightFile','complete'))
    need(type(receipt['schemaVersion']) is int and receipt['schemaVersion'] == 1
         and receipt['kind'] == 'native-vendure-direct-child' and receipt['source'] == '3bc74469d586ab1cb421c85e98eff8e3a9d515a9' and receipt['source'] != receipt['fixture'] and receipt['releaseAcceptance'] is False)
    need(type(receipt['attempt']) is int and receipt['attempt'] == 1 and type(receipt['runId']) is int and receipt['runId'] > 0)
    need(all(re.fullmatch('[0-9a-f]{40}', receipt[k]) for k in ('wrapper','source','fixture')))
    actions = receipt['actions']
    keys(actions,ACTIONS)
    need(all(v in OUTCOMES for v in actions.values()))
    for i,k in enumerate(ACTIONS):
        if actions[k] in ('success','failure'):
            need(all(actions[j] == 'success' for j in ACTIONS[:i]))
    markers = receipt['stageMarkers']
    keys(markers, (*PACKAGE,*PREP))
    need(all(v in (None,'running','success','failure') for v in markers.values()))
    for step,names in [('package',PACKAGE),('campaign',PREP)]:
        reachable(names,markers,'success',None)
        need(actions[step] != 'skipped' or all(markers[k] is None for k in names))
        need(actions[step] != 'success' or all(markers[k] == 'success' for k in names))
    evidence = receipt['checkpointStatus']
    row = receipt['checkpoint']
    need(evidence in ('unavailable','invalid','observed') and (row is not None) == (evidence == 'observed'))
    if row is not None:
        validate_progress(row)
        need(markers['native'] in ('running','success','failure') and actions['campaign'] != 'skipped')
        need(markers['native'] != 'success' or row['status'] == 'passed')
    preflight = receipt['preflightFile']
    state = receipt['preflightFileStatus']
    need(state in ('unavailable','invalid','observed') and (preflight is not None) == (state == 'observed'))
    if preflight is not None:
        validate_preflight(preflight)
        need(markers['native'] in ('running','success','failure') and actions['campaign'] != 'skipped')
        if row is not None:
            need('initEmptyList' in row['stages'])
            need(row['preflight'] is None or preflight == row['preflight'])
    complete = all(actions[k]=='success' for k in ACTIONS) and row is not None and row['status']=='passed' and preflight is not None and preflight['status']=='passed'
    need(receipt['complete'] is complete)
    return receipt

def main():
    proof = Path(os.environ['PROOF'])
    markers = {}
    for k in (*PACKAGE,*PREP):
        try:
            data = read(proof/'stages'/k, 32).decode('ascii')
            need(data in ('running\n','success\n','failure\n'))
            markers[k] = data.strip()
        except FileNotFoundError:
            markers[k] = None
    try:
        doc = validate_progress(json.loads(read(proof/'native-installed/progress.private.json', 16384), object_pairs_hook=pairs))
        evidence = 'observed'
    except FileNotFoundError:
        evidence, doc = 'unavailable', None
    except (ValueError,OSError,KeyError,TypeError):
        evidence, doc = 'invalid', None
    # The synchronous CLI helper writes these individual phase checkpoints before
    # its parent can copy the final observation into the native lifecycle report.
    try:
        raw = read(proof/'native-installed/preflight-observation.json',1024)
        preflight = validate_preflight(json.loads(raw,object_pairs_hook=pairs))
        need(list(preflight) == ['phase','status','code','signal'])
        need(raw == (json.dumps(preflight,separators=(',',':'))+'\n').encode())
        preflight_status = 'observed'
    except FileNotFoundError:
        preflight_status, preflight = 'unavailable', None
    except (ValueError,OSError,KeyError,TypeError):
        preflight_status, preflight = 'invalid', None
    actions = {key: os.environ[key.upper()] for key in ACTIONS}
    actual = all(v=='success' for v in actions.values()) and doc is not None and doc['status']=='passed' and preflight is not None and preflight['status']=='passed'
    receipt = validate(dict(schemaVersion=1, kind='native-vendure-direct-child', source=os.environ['PRODUCT'], fixture=os.environ['FIXTURE'],
            wrapper=os.environ['GITHUB_SHA'], runId=int(os.environ['GITHUB_RUN_ID']), attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
            releaseAcceptance=False, actions=actions, stageMarkers=markers, checkpointStatus=evidence, checkpoint=doc, preflightFileStatus=preflight_status, preflightFile=preflight, complete=actual))
    with (proof/'safe/receipt.json').open('x') as out:
        json.dump(receipt,out,sort_keys=True)
        out.write('\n')
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        out.write('complete='+str(actual).lower()+'\n')

if __name__ == '__main__':
    try:
        main()
    except (ValueError,OSError,KeyError,TypeError):
        raise SystemExit('bounded native projection unavailable') from None
