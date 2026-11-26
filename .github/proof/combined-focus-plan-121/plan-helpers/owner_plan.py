"""Reusable hosted Plan browser hook; adds no capture, launch or application request to an existing fixture."""
import argparse
import hashlib
import io
import struct
import tarfile
import zlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import traceback

CHECKS = ('selection','opener','focus-trap','missing-inputs','canonical-revision','review','fresh-consent','approval',
          'atomic-edit','superseded-read','replacement-consent','readback','reload','close-focus','private-persistence','no-external-requests')
ACTIONS = ('create','edit','show','review','approve')
FOCUS_SUBCHECKS = ('reverse-tab-key','reverse-tab-contained','reverse-tab-summary','forward-tab-key','forward-tab-close','catalog-pointerdown',
    'close-button','escape-key','closed-modal-absent','return-opener-visible','return-opener-focused','return-opener-enabled',
    'phone-more-open','compact-tools-hit','compact-tools-open','plan-action-hit','plan-action-open','recording-more-open',
    'modal-visible','initial-close-focus','modal-fit')
FOCUS_ROLES = ('none','document-body','dialog','dialog-close','disclosure-summary','checkbox','text-input','select',
    'textarea','button','link','programmatic-heading','other')


def need(value):
    if not value:
        raise ValueError('private proof predicate')

def read(path, limit=8<<20):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        entry=os.fstat(fd)
        need(stat.S_ISREG(entry.st_mode) and not stat.S_IMODE(entry.st_mode)&0o077 and entry.st_uid==os.getuid()
             and entry.st_nlink==1 and 0<entry.st_size<=limit)
        value=stream.read(limit+1)
    need(len(value)<=limit)
    return json.loads(value)

def digest(path):
    need(path.is_file() and not path.is_symlink())
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def atomic(path, value):
    with path.with_suffix('.tmp').open('w',encoding='utf-8') as stream:
        json.dump(value,stream,sort_keys=True);stream.write('\n')
    path.with_suffix('.tmp').replace(path)

def browser_receipt(value, identity):
    keys={'schemaVersion','kind','sourceSha','sourceTree','wrapperSha','runId','attempt','receiptId','status','stage','cells',
          'routes','observedRoutes','routeCountMeaning','externalRequests','consoleErrors','downloads','privateLeaks','focusDiagnostic','failureLocation','expiry','serverExpiredDrafts','pendingWriteClose'}
    need(type(value) is dict and set(value)==keys and type(value['schemaVersion']) is int and value['schemaVersion']==1
         and value['kind']=='owner-plan-browser')
    need(all(value[k]==v for k,v in identity.items()))
    diagnostic=value['focusDiagnostic']
    if diagnostic is not None:
        need(type(diagnostic) is dict and set(diagnostic)=={'subcheck','state','activeRole','activeTabIndex','insideModal','nativeModal',
             'moreExpanded','moreVisible','activeDisabled','planBusy','openerVisible','openerFocused'})
        need(diagnostic['subcheck'] in FOCUS_SUBCHECKS and diagnostic['state'] in ('started','passed','failed','snapshot-unavailable')
             and diagnostic['activeRole'] in FOCUS_ROLES and diagnostic['activeTabIndex'] in ('negative','zero','positive','none'))
        need(all(type(diagnostic[k]) is bool for k in ('insideModal','nativeModal','activeDisabled')))
        need(all(diagnostic[k] is None or type(diagnostic[k]) is bool for k in ('moreExpanded','moreVisible','planBusy','openerVisible','openerFocused')))
    location=value['failureLocation']
    if location is not None:
        need(type(location) is dict and set(location)=={'file','line','column'} and location['file']=='owner-plan-browser.mjs'
             and type(location['line']) is int and 1<=location['line']<=10000 and type(location['column']) is int and 1<=location['column']<=10000)
    need(value['status'] in ('passed','failed') and value['stage'] in (*CHECKS,'bootstrap','pending-write-close','server-expiry','complete'))
    need(value['expiry'] in ('unreached','server-expired-and-approval-unavailable')
         and type(value['serverExpiredDrafts']) is int and value['serverExpiredDrafts'] in (0,1)
         and (value['expiry']=='server-expired-and-approval-unavailable')==(value['serverExpiredDrafts']==1)
         and value['pendingWriteClose'] in ('unreached','passed'))
    need(value['routeCountMeaning']=='verified-authenticated-response')
    need(type(value['observedRoutes']) is dict and set(value['observedRoutes'])==set(ACTIONS)
         and all(type(v) is int and 0<=v<=1000 for v in value['observedRoutes'].values()))
    need(type(value['routes']) is dict and set(value['routes'])==set(ACTIONS))
    need(all(type(v) is int and 0<=v<=1000 for v in value['routes'].values()))
    need(all(value['routes'][a]<=value['observedRoutes'][a] for a in ACTIONS))
    need(all(type(value[k]) is int and 0<=value[k]<=10000 for k in ('externalRequests','consoleErrors','downloads','privateLeaks')))
    expected=[(w,h,p) for w,h in ((320,640),(736,900),(1024,768),(1280,900),(1440,900)) for p in ('fine','coarse')]
    need(type(value['cells']) is list and len(value['cells'])<=10)
    for cell,expected_cell in zip(value['cells'],expected):
        need(type(cell) is dict and set(cell)=={'width','height','pointer','status','checks'})
        need(type(cell['width']) is int and type(cell['height']) is int and (cell['width'],cell['height'],cell['pointer'])==expected_cell)
        need(cell['status'] in ('attempted','passed','failed') and type(cell['checks']) is dict and set(cell['checks'])==set(CHECKS))
        need(all(v in ('unreached','passed','failed') for v in cell['checks'].values()))
        need(cell['status']!='passed' or all(v=='passed' for v in cell['checks'].values()))
    if value['status']=='passed':
        need(value['serverExpiredDrafts']==1 and value['pendingWriteClose']=='passed')
        need(diagnostic is not None and diagnostic['state']=='passed' and location is None)
        need(value['stage']=='complete' and len(value['cells'])==10 and all(x['status']=='passed' for x in value['cells']))
        need(value['routes']==value['observedRoutes']==dict(create=11,edit=21,show=42,review=31,approve=20) and all(value[k]==0 for k in ('externalRequests','consoleErrors','downloads','privateLeaks')))
    return value

def viewport_png(path, width, height):
    # Bounded native-size screenshot admission; only parsed PNG bytes are encrypted.
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 20*1024*1024
    with path.open('rb') as stream:
        data = stream.read(20*1024*1024+1)
    assert len(data) <= 20*1024*1024 and data.startswith(b'\x89PNG\r\n\x1a\n')
    offset, header, ended, chunks = 8, False, False, []
    while offset + 12 <= len(data):
        length = struct.unpack_from('>I', data, offset)[0]
        end = offset + 12 + length
        assert end <= len(data)
        kind, payload = data[offset+4:offset+8], data[offset+8:offset+8+length]
        assert zlib.crc32(kind + payload) & 0xffffffff == struct.unpack_from('>I', data, offset+8+length)[0]
        if not header:
            assert kind == b'IHDR' and length == 13 and struct.unpack_from('>II', payload) == (width,height)
            depth, color, compression, filtering, interlace = payload[8:]
            assert depth == 8 and color in (2,6) and (compression,filtering,interlace) == (0,0,0)
            row_size = 1 + width * (3 if color == 2 else 4)
            expected = row_size * height
            assert 0 < expected <= (1440*4+1)*900
            header = True
        else:
            assert kind in (b'IDAT', b'IEND')
        if kind == b'IDAT': chunks.append(payload)
        if kind == b'IEND':
            ended = length == 0 and end == len(data)
            break
        offset = end
    assert header and chunks and ended
    decoder, decoded = zlib.decompressobj(), 0
    for payload in chunks:
        while payload:
            pixels = decoder.decompress(payload, min(65536, expected-decoded+1))
            assert not decoder.unused_data and decoded+len(pixels) <= expected
            assert all(pixels[i] <= 4 for i in range((-decoded) % row_size, len(pixels), row_size))
            decoded += len(pixels)
            payload = decoder.unconsumed_tail
    assert decoder.eof and decoded == expected
    return data

def encrypt_frames(root):
    frames=[]
    for width,height in ((320,640),(736,900),(1024,768),(1280,900),(1440,900)):
        for pointer in ('fine','coarse'):
            for phase in ('approved','readback'):
                name=f'plan-{phase}-{pointer}-{width}.png'
                path=root/'browser'/name
                if path.exists():frames.append((name,viewport_png(path,width,height)))
    need(len(frames)<=20)
    if not frames:return 0
    certificate=root/'private/recipient.pem'
    certificate.write_text(os.environ['RECIPIENT_CERT'])
    with (root/'logs/cert.stderr').open('xb') as err:
        cert=subprocess.run(['openssl','x509','-in',str(certificate),'-outform','DER'],stdout=subprocess.PIPE,stderr=err,timeout=60,check=False)
    need(cert.returncode==0 and hashlib.sha256(cert.stdout).hexdigest()=='931ca5323fd14a29782acb5f1e52225f5dc5a94f4d680958de3e685514839dc4')
    payload=io.BytesIO()
    with tarfile.open(fileobj=payload,mode='w:gz') as archive:
        for name,data in frames:
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;info.mtime=0
            archive.addfile(info,io.BytesIO(data))
    encrypted=root/'encrypted';encrypted.mkdir(mode=0o700)
    with (root/'logs/encryption.stderr').open('xb') as err:
        result=subprocess.run(['openssl','cms','-encrypt','-binary','-aes-256-gcm','-outform','DER','-out',str(encrypted/'visuals.cms'),str(certificate)],
            input=payload.getvalue(),stdout=subprocess.DEVNULL,stderr=err,timeout=60,check=False)
    need(result.returncode==0 and (encrypted/'visuals.cms').is_file() and (encrypted/'visuals.cms').stat().st_size>0)
    return len(frames)

def attach_to_existing_fixture(base, cfg):
    """Extend an already-approved ordinary fixture in its existing listener window; never launch or send here."""
    os.umask(0o077)
    repo=Path.cwd().resolve()
    identity={k:cfg[k] for k in ('sourceSha','sourceTree','wrapperSha','runId','attempt','receiptId')}
    need(all(re.fullmatch('[0-9a-f]{40}',identity[k]) for k in ('sourceSha','sourceTree','wrapperSha')))
    need(re.fullmatch('[0-9a-f]{64}',identity['receiptId']))
    need(all(type(identity[k]) is int and 1<=identity[k]<10**16 for k in ('runId','attempt')))
    need(cfg['mode']=='installed')
    need(digest(Path(base.__file__))==cfg['existingDriverSha256'])
    need(subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==identity['sourceSha'])
    need(subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()==identity['sourceTree'])
    # Keep the original thirty-three named stages, package checks, actual capture and zero-send listener intact.
    expected_stages=('identity','build-archive','verify-dist','verify-archive','fresh-install','verify-installed',
        'verify-installed-directory','verify-payload','build-spring','initialize','scan-controller','read-catalog',
        'empty-recordings','spring-ready','ordinary-request','complete-recording','spring-stopped','guard-listener',
        'observed-binding','plan','review','deny-missing-consent','approve','restore-show','edit','superseded-original',
        'replacement-review','deny-predecessor-consent','replacement-approve','replacement-restore-show',
        'stable-recording','zero-connections','owned-cleanup')
    need(tuple(base.STAGES)==expected_stages)
    need(all(base.REPORT[k]==identity[k] for k in ('sourceSha','sourceTree','wrapperSha','runId','attempt')))
    root=Path(cfg['root'])
    need(root.parent==Path(os.environ['RUNNER_TEMP']) and root.name=='xp121ui')
    root.mkdir(mode=0o700,exist_ok=False)
    for sub in ('private','logs','safe','browser'):(root/sub).mkdir(mode=0o700)
    public=dict(schemaVersion=1,kind='installed-owner-plan-no-send',**identity,**base.source_provenance(),
        mode='installed',releaseAcceptance=False,
        installedPackage=True,status='failed',stage='awaiting-existing-fixture',fixtureStages=dict.fromkeys(expected_stages,'unreached'),
        genuineRecordingCount=None,exerciseRequestsSent=None,observedQueuedConnections=None,browser=None,
        cliSha256=None,agentSha256=None,analyzerSha256=None,fixtureSha256=None,archiveSha256=None,durablePlansChecked=0,
        expiryEvidence='unreached',pendingWriteClose='unreached',encryptedFrameCount=0,failure=None)
    public_path=root/'safe/counts.json';atomic(public_path,public)
    binding={};browser=None;docs=[];completed=False
    old_endpoint=base.endpoint
    def endpoint(client,op,rid,event_count):
        project=old_endpoint(client,op,rid,event_count)
        binding.update(origin=client.origin,cookie=client.cookie)
        return project
    base.endpoint=endpoint
    original_lifecycle=base.lifecycle
    def lifecycle(port,project,revision,op,rid):
        nonlocal browser,docs,completed
        original_lifecycle(port,project,revision,op,rid)
        public['stage']='browser';atomic(public_path,public)
        config=dict(**identity,origin=binding['origin'],cookie=binding['cookie'],target=f'http://127.0.0.1:{port}',
                    projectId=project,revisionId=revision,operationId=op['operationId'],operationVersionId=op['operationVersionId'],
                    recordingId=rid,sequences=[event['sequence'] for event in base.recording()[1]],output=str(root/'browser'))
        with (root/'logs/browser.stdout').open('xb') as stdout,(root/'logs/browser.stderr').open('xb') as stderr:
            result=subprocess.run(['node',str(Path(__file__).with_name('owner-plan-browser.mjs'))],input=json.dumps(config).encode(),
                cwd=repo,env=base.ENV,stdout=stdout,stderr=stderr,timeout=900,check=False)
        path=root/'browser/browser.json'
        if path.exists():browser=browser_receipt(read(path,65536),identity);public['browser']=browser;atomic(public_path,public)
        need(result.returncode==0 and browser is not None and browser['status']=='passed')
        docs=read(root/'browser/documents.private.json')
        need(type(docs) is list and len(docs)==125)
        last={}
        for entry in docs:
            need(type(entry) is dict and set(entry)=={'cell','action','doc'} and entry['action'] in ACTIONS
                 and type(entry['cell']) is int and 0<=entry['cell']<10)
            doc=entry['doc'];need(doc['requests_sent']==0 and doc['execution_available'] is False)
            need(doc['project_id']==project and doc['observed_recording']['recording_id']==rid
                 and doc['observed_recording']['operation_id']==op['operationId'])
            need(doc['selected_catalog_operation']['catalog']['revision_id']==revision
                 and doc['selected_catalog_operation']['catalog']['operation_version_id']==op['operationVersionId'])
            last[doc['plan_hash']]=doc
        need(len(last)==32)
        public['stage']='durable-readback';atomic(public_path,public)
        for number,(plan_hash,expected) in enumerate(last.items()):
            actual=base.query(f'browser-durable-{number}','exercise','show','--plan-hash',plan_hash,'--json')
            successors=[entry['doc'] for entry in docs if entry['doc'].get('supersedes')==plan_hash]
            if expected['phase']['phase']!='superseded' and successors:
                successor=successors[-1]
                need(actual['phase']==dict(phase='superseded',replacement_hash=successor['plan_hash'],
                    replacement_created_at=successor['created_at'],previous=expected['phase']))
                need(actual['ready_for_approval'] is False)
                need({k:v for k,v in actual.items() if k not in ('phase','ready_for_approval')}==
                     {k:v for k,v in expected.items() if k not in ('phase','ready_for_approval')})
            else:need(actual==expected)
            public['durablePlansChecked']+=1;atomic(public_path,public)
        need(public['durablePlansChecked']==32 and browser['pendingWriteClose']=='passed' and browser['serverExpiredDrafts']==1)
        public.update(cliSha256=digest(base.CLI),agentSha256=digest(base.PAYLOAD/base.AGENT),
            analyzerSha256=digest(base.PAYLOAD/base.ANALYZER),fixtureSha256=base.REPORT['fixtureSha256'],
            archiveSha256=base.REPORT['archiveSha256'])
        completed=True
    base.lifecycle=lifecycle
    def finalize(error=None):
        public['fixtureStages']=base.REPORT['stages']
        public['genuineRecordingCount']=base.REPORT.get('genuineRecordingCount')
        public['observedQueuedConnections']=base.REPORT.get('observedQueuedConnections')
        try:
            need(error is None and completed and base.REPORT['status']=='passed' and len(base.REPORT['stages'])==33
                 and all(x=='passed' for x in base.REPORT['stages'].values())
                 and public['genuineRecordingCount']==1 and public['observedQueuedConnections']==0
                 and base.REPORT['exerciseRequestsSent']==0)
            public.update(status='passed',stage='complete',exerciseRequestsSent=0,pendingWriteClose='passed',expiryEvidence='server-expired-and-approval-unavailable')
        except Exception:
            public.update(status='failed',failure='existing-fixture-or-browser')
        try:
            public['encryptedFrameCount']=encrypt_frames(root)
            need(public['status']!='passed' or public['encryptedFrameCount']==20)
        except Exception:
            public.update(status='failed',failure='visual-admission-or-encryption')
            (root/'encrypted/visuals.cms').unlink(missing_ok=True)
        atomic(public_path,public)
        return public['status']=='passed'
    return finalize


def main(config_path, existing_driver):
    """Bridge only: invokes the coordinator's approved installed fixture once, with a same-capture extension."""
    os.umask(0o077)
    cfg=read(config_path,65536)
    need(digest(existing_driver)==cfg['existingDriverSha256'])
    spec=importlib.util.spec_from_file_location('approved_existing_installed_fixture',existing_driver)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    finalize=attach_to_existing_fixture(base,cfg)
    error=None
    try:base.main()
    except BaseException as problem:
        error=problem
        # The outer workflow already stores stderr privately. Never publish exception text.
        with (Path(cfg['root'])/'logs/existing-fixture.private').open('x') as stream:traceback.print_exc(file=stream)
    passed=finalize(error)
    return 0 if passed else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config',type=Path);parser.add_argument('--existing-driver',required=True,type=Path)
    args=parser.parse_args()
    raise SystemExit(main(args.config,args.existing_driver))
