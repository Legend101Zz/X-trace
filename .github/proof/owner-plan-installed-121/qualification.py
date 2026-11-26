"""Pinned hosted Actions evidence and exact generated-child admission; no application traffic."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

SOURCE='4e61efab2030be38fac58bb14205549794a94fa1'
SOURCE_TREE='c90c3d8c0bd1c08e23cc648eed5d5c89507fc005'
GENERATED='d0882b896f2d56e8a8f0167f8378335475e51ab9'
GENERATED_TREE='9d867c72d60b0b0e339cf58dc8401c7bf8a5ea44'
SOURCE_RUN=45792966132
UI_MANIFEST='8194a02d9ae76b44fa45a052e42f54bfe0aa8905c0795c94e11455173b168d85'
SOURCE_PARENTS='b32ccdd033432ee121933421e19c80814f806c33 d0581314cc4ecfc90ec6483ea3809fb0e0e4c2a7'
BASELINE='5b3a677e064d051ab698d09556c6731f8464105b'
SOURCE_PATCH='810330681addf17272609329c430a685bbc08c05471b24d3e5b0d42f936d2011'
CONTRACT_RUN=45792578783
CONTRACT_WRAPPER='cff3ffb8c18082791d13adc77fc6a5d4d75f4859'
CONTRACT_WORKFLOW_SHA='60bd9d80be69dbf8dd628df6a7bb92337e9ef5a2b09d8066cf4568b71eee5668'
SOURCE_WRAPPER='e4740022d3a74049c7c2eb7332e231c74c2334e4'
SOURCE_WORKFLOW_SHA='93d942b2265a835986932680979aff4af2b7ccb714de942734bdf71a0bb6cffa'
CONTRACT_ARTIFACT=(15102559579,'owner-plan-source-contract-counts',638,'1fa1f8d92b01dbfa4c8c55a0fb2e5bc5566c43c57edc1f28445dbb0eab82e905')
ASSETS=('index.html','app.js','index.css','fonts/chivo-latin-400-normal.woff2',
        'fonts/chivo-latin-600-normal.woff2','fonts/azeret-mono-latin-400-normal.woff2','assets.sha256')
EXPECTED_CONTRACTS=dict(application=12,private_store=4,real_cli_seeded_recording=7,legacy_fallback=1,
    export_catalog_export=15,export_curl_quoting=4,export_export_core=20,export_golden_curl=8,
    export_golden_openapi=11,export_golden_postman=2,exercise_pure=16,canonical_compatibility=3,
    daemon_current_route_guard=1,daemon_five_authenticated_routes=1)
SOURCE_STAGES=('source-check','web-install','web-api','web-types','syntax-first-recording-journey','syntax-export-journey',
    'syntax-api-evidence','syntax-export-visibility','syntax-real-replay-window','syntax-browser-journey',
    'syntax-replay-tools-journey','syntax-replay-tools-report','syntax-replay-tools-report-test','syntax-replay-window-journey',
    'syntax-replay-playback-journey','syntax-focused-code-journey','syntax-synthetic-step-window-journey','tools-unit',
    'contrast','web-build','web-embed','embedded-parity','generated-assets','java-build','adapter-verify',
    'chromium-install','source-scope','spring-browser','empty-browser')


def need(value):
    if not value:raise ValueError('qualification predicate')


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def pairs(values):
    result={}
    for key,value in values:
        need(key not in result);result[key]=value
    return result


def load(data):
    need(len(data)<=65536)
    return json.loads(data,object_pairs_hook=pairs)


def root():return Path(os.environ['RUNNER_TEMP'])/'xq121'


def read_private(path,limit=65536):
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        entry=os.fstat(fd)
        need(stat.S_ISREG(entry.st_mode) and entry.st_uid==os.getuid() and stat.S_IMODE(entry.st_mode)==0o600
             and entry.st_nlink==1 and entry.st_size<=limit)
        data=stream.read(limit+1);need(len(data)<=limit);return data


def git(*args):return subprocess.check_output(['git',*args],stderr=subprocess.DEVNULL)


def compare_ui(directory):
    source=root()/'private/assets'
    for name in ASSETS:
        expected=source/name;actual=directory/name
        need(actual.is_file() and not actual.is_symlink() and actual.stat().st_size<=20*1024*1024)
        need(digest(actual)==digest(expected))
    need(digest(directory/'assets.sha256')==os.environ['EXPECTED_UI_MANIFEST_SHA256'])


def offline_identity():
    product,tree=os.environ['PRODUCT'],os.environ['PRODUCT_TREE']
    need(product==GENERATED and tree==GENERATED_TREE and os.environ['EXPECTED_UI_MANIFEST_SHA256']==UI_MANIFEST)
    need(git('rev-parse','HEAD').decode().strip()==product and git('rev-parse','HEAD^{tree}').decode().strip()==tree)
    need(git('show','-s','--format=%P','HEAD').decode().strip()==SOURCE)
    need(git('rev-parse',SOURCE+'^{tree}').decode().strip()==SOURCE_TREE)
    need(git('show','-s','--format=%P',SOURCE).decode().strip()==SOURCE_PARENTS)
    # A clean baseline is recomputed from the exact parents, not fetched as a dangling tree.
    need(git('merge-tree','--write-tree',*SOURCE_PARENTS.split()).decode().strip()==BASELINE)
    need(hashlib.sha256(git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',BASELINE,SOURCE)).hexdigest()==SOURCE_PATCH)
    admitted={'crates/xtrace-daemon/assets/ui/'+name for name in ASSETS}
    changed=git('diff','--name-only',SOURCE,'HEAD').decode().splitlines()
    need(len(changed)==3 and set(changed)=={'crates/xtrace-daemon/assets/ui/'+name for name in ('app.js','assets.sha256','index.css')})
    entries=git('ls-tree','-r','HEAD','--','crates/xtrace-daemon/assets/ui').decode().splitlines()
    need(len(entries)==7 and all(row.startswith('100644 blob ') for row in entries)
         and {row.split('\t',1)[1] for row in entries}==admitted)
    for path,sha in (('packaging/install.sh','7623373412edeb406deab5bbf672d8d5653b4a363ec4aa8b850380608f2e0425'),
                     ('packaging/test/install_test.sh','c251607d61e391251eb50e62cb5ca156c89815e31890e2b1276b5f4012d603b8')):
        need(digest(Path(path))==sha)
    need(not git('status','--porcelain','--untracked-files=all'))
    compare_ui(Path('crates/xtrace-daemon/assets/ui'))


def api(endpoint,name,binary=False):
    need(re.fullmatch(r'repos/Legend101Zz/X-trace/actions/(?:runs/[0-9]+(?:/artifacts)?|artifacts/[0-9]+(?:/zip)?)',endpoint))
    out=root()/'private'/name;err=root()/'private'/(name+'.stderr')
    env=dict(os.environ);env.pop('GH_HOST',None)
    with out.open('xb') as stdout,err.open('xb') as stderr:
        result=subprocess.run(['gh','api','--hostname','github.com',endpoint],env=env,stdin=subprocess.DEVNULL,
            stdout=stdout,stderr=stderr,timeout=180,check=False)
    need(result.returncode==0)
    if binary:return out
    return load(read_private(out))


def run(run_id,wrapper,branch,path,label):
    result=api(f'repos/Legend101Zz/X-trace/actions/runs/{run_id}',label+'-run.json')
    need(result['id']==run_id and type(result['run_attempt']) is int and result['run_attempt']==1
         and result['status']=='completed' and result['conclusion']=='success' and result['head_sha']==wrapper
         and result['event']=='push' and result['head_branch']==branch and result['path']==path)


def artifact(run_id,wrapper,spec,label,members):
    artifact_id,name,size,sha=spec
    need(type(artifact_id) is int and artifact_id>0 and type(size) is int and 1<=size<=128*1024*1024
         and re.fullmatch('[0-9a-f]{64}',sha))
    data=api(f'repos/Legend101Zz/X-trace/actions/runs/{run_id}/artifacts',label+'-artifacts.json')
    need(data['total_count']<=100 and len(data['artifacts'])==data['total_count'])
    matches=[row for row in data['artifacts'] if row['id']==artifact_id and row['name']==name]
    need(len(matches)==1)
    meta=api(f'repos/Legend101Zz/X-trace/actions/artifacts/{artifact_id}',label+'-artifact.json')
    for observed in (*matches,meta):
        need(observed['id']==artifact_id and observed['name']==name and observed['size_in_bytes']==size
             and observed['digest']=='sha256:'+sha and observed['expired'] is False
             and observed['workflow_run']['id']==run_id and observed['workflow_run']['head_sha']==wrapper)
    archive=api(f'repos/Legend101Zz/X-trace/actions/artifacts/{artifact_id}/zip',label+'.zip',True)
    need(archive.stat().st_size==size and digest(archive)==sha)
    with zipfile.ZipFile(archive) as zipped:
        infos=zipped.infolist()
        need(len(infos)==len(members) and {i.filename for i in infos}==set(members)
             and all(not i.is_dir() and i.file_size<=20*1024*1024 and i.compress_type in (0,8)
                     and not stat.S_ISLNK(i.external_attr>>16) for i in infos)
             and sum(i.file_size for i in infos)<=120*1024*1024+4096 and zipped.testzip() is None)
        return {name:zipped.read(name) for name in members}


def contracts(doc):
    need(set(doc)=={'attempt','genuineApplicationCapture','kind','packaged','releaseAcceptance','runId','schemaVersion',
                    'sourceSha','sourceTree','stages','status','wrapperSha'})
    need(doc['schemaVersion']==1 and doc['kind']=='owner_plan_source_contracts' and doc['sourceSha']==SOURCE
         and doc['sourceTree']==SOURCE_TREE and doc['wrapperSha']==CONTRACT_WRAPPER and doc['runId']==CONTRACT_RUN
         and doc['attempt']==1 and doc['status']=='passed' and doc['packaged'] is False
         and doc['releaseAcceptance'] is False and doc['genuineApplicationCapture'] is False)
    need(set(doc['stages'])==set(EXPECTED_CONTRACTS))
    need(all(doc['stages'][label]==dict(expected=n,passed=n,status='passed') for label,n in EXPECTED_CONTRACTS.items()))


def source_counts(doc):
    need(doc['schemaVersion']==1 and doc['kind']=='source-built-assembled-viewer'
         and doc['sourceSha']==SOURCE and doc['sourceTree']==SOURCE_TREE and doc['releaseAcceptance'] is False
         and doc['installedPackage'] is False and doc['fullFloor'] is False and doc['status']=='pass'
         and doc['stage']=='complete' and doc['exitCode']==0 and doc['countsComplete'] is True)
    need(doc['unit']==dict(files=31,passed=293,failed=0,ignored=0)
         and doc['spring']==dict(passed=1,failed=0,ignored=0) and doc['empty']==dict(passed=1,failed=0,ignored=0))
    rows=doc['stages']
    need(len(rows)==len(SOURCE_STAGES) and {x['stage'] for x in rows}==set(SOURCE_STAGES)
         and all(set(x)=={'stage','exitCode','timedOut'} and x['exitCode']==0 and x['timedOut'] is False for x in rows))
    need(doc['generatedAssetCount']==7 and doc['encryptedViewportCount']==84 and doc['jumpReceipt']=='validated'
         and doc['jumpCoverage']['status']=='pass' and doc['jumpCoverage']['stage']=='complete'
         and len(doc['jumpCoverage']['viewports'])==10 and all(x['status']=='pass' for x in doc['jumpCoverage']['viewports']))
    need(doc['exportJudge']['status']=='pass' and doc['exportJudge']['verifiedPassed']==51
         and doc['exportJudge']['counts']==dict(testsRun=51,failures=0,errors=0,skipped=0,expectedFailures=0,unexpectedSuccesses=0))
    need(doc['additionalFrameCounts']==dict(compactToolsOpen=6,desktopInlineTools=4,phoneMore=2,firstRecordingTour=12))
    need(len(doc['viewports'])==10 and all(x['capturedStages']==x['expectedStages']==6 and x['assertionsPassed'] is True for x in doc['viewports']))


def main():
    os.umask(0o077)
    target=root();target.mkdir(mode=0o700,exist_ok=False)
    (target/'private').mkdir(mode=0o700);(target/'safe').mkdir(mode=0o700)
    report=dict(schemaVersion=1,kind='owner-plan-installed-prerequisites',releaseAcceptance=False,status='failed',
        stage='contracts-run',product=os.environ['PRODUCT'],productTree=os.environ['PRODUCT_TREE'],
        assembledSource=SOURCE,assembledSourceTree=SOURCE_TREE,contractsRun=CONTRACT_RUN,
        contractsWrapper=CONTRACT_WRAPPER,sourceRun=None,sourceWrapper=SOURCE_WRAPPER)
    def save():
        with (target/'safe/qualification.tmp').open('w') as stream:json.dump(report,stream,sort_keys=True);stream.write('\n')
        (target/'safe/qualification.tmp').replace(target/'safe/qualification.json')
    save()
    try:
        need(os.environ['GITHUB_REPOSITORY']=='Legend101Zz/X-trace')
        run(CONTRACT_RUN,CONTRACT_WRAPPER,'codex/proof-owner-plan-contracts-121','.github/workflows/owner-plan-contracts.yml','contracts')
        need(hashlib.sha256(git('show',CONTRACT_WRAPPER+':.github/workflows/owner-plan-contracts.yml')).hexdigest()==CONTRACT_WORKFLOW_SHA)
        report['stage']='contracts-artifact';save()
        contracts(load(artifact(CONTRACT_RUN,CONTRACT_WRAPPER,CONTRACT_ARTIFACT,'contracts',('counts.json',))['counts.json']))
        run_id=int(os.environ['VERIFIED_SOURCE_RUN_ID']);need(run_id==SOURCE_RUN);report.update(stage='source-run',sourceRun=run_id);save()
        run(run_id,SOURCE_WRAPPER,'codex/proof-owner-plan-source-121','.github/workflows/owner-plan-source.yml','source')
        need(hashlib.sha256(git('show',SOURCE_WRAPPER+':.github/workflows/owner-plan-source.yml')).hexdigest()==SOURCE_WORKFLOW_SHA)
        report['stage']='source-counts';save()
        def spec(prefix,name):
            actual=(int(os.environ[prefix+'_ARTIFACT_ID']),name,int(os.environ[prefix+'_ARCHIVE_SIZE']),os.environ[prefix+'_ARCHIVE_SHA256'])
            expected={'SOURCE_COUNTS':(15103328603,'assembled-viewer-source-counts',1743,'6b032154a4b8ce7e885e17d664e69310bf5303df54fb5e9dbd77d373c8b0d279'),
                'SOURCE_ASSETS':(15104296460,'assembled-viewer-source-generated-assets',160599,'77b68d047b94ddf64b18948336403f93a8afa5a130f79abebbd271f26ce721f5')}
            need(actual==expected[prefix]);return actual
        source_counts(load(artifact(run_id,SOURCE_WRAPPER,spec('SOURCE_COUNTS','assembled-viewer-source-counts'),'source-counts',('counts.json',))['counts.json']))
        report['stage']='source-generated-assets';save()
        assets=artifact(run_id,SOURCE_WRAPPER,spec('SOURCE_ASSETS','assembled-viewer-source-generated-assets'),'source-assets',ASSETS)
        assets_root=target/'private/assets';assets_root.mkdir(mode=0o700)
        for name,data in assets.items():
            path=assets_root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as stream:stream.write(data)
        need(digest(assets_root/'assets.sha256')==os.environ['EXPECTED_UI_MANIFEST_SHA256'])
        rows={}
        for line in assets['assets.sha256'].decode('utf-8').splitlines():
            sha,name=line.split('  ');mapped=name.removeprefix('assets/')
            need(mapped in ASSETS[:-1] and mapped not in rows and re.fullmatch('[0-9a-f]{64}',sha)
                 and hashlib.sha256(assets[mapped]).hexdigest()==sha);rows[mapped]=sha
        need(set(rows)==set(ASSETS[:-1]))
        report['stage']='generated-direct-child';save();offline_identity()
        report.update(status='passed',stage='complete',verifiedGeneratedFiles=7,verifiedContracts=105)
    except Exception:pass
    save()
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
