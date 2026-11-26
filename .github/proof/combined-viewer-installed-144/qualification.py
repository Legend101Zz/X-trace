"""Pinned hosted Actions evidence and exact generated-child admission; no application traffic."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

CONTRACT_SOURCE='4e61efab2030be38fac58bb14205549794a94fa1'
CONTRACT_TREE='c90c3d8c0bd1c08e23cc648eed5d5c89507fc005'
INTEGRATED='4bd45d6ca0d65a39c1e85e2b902edb16a0a59928'
INTEGRATED_TREE='05b8d5a1637849fb11b0648792d342f61fff36d5'
SOURCE_PARENTS='d0882b896f2d56e8a8f0167f8378335475e51ab9 09819855600643b095e13d17d6b7aa67bb511145'
SOURCE_PATCH='c990ffa4198094965dd9dee0e028019453119ae8fda15edde3ac021520ef830f'
FAILED_INTEGRATED_RUN=45801076336
SOURCE_BRANCH='codex/proof-selected-row-density-source-118'
INTEGRATED_WORKFLOW='.github/workflows/phone-plan-integrated-source.yml'
PREFIX='crates/xtrace-daemon/assets/ui/'
# Offline binder substitutes a single closed literal after validating both runs and every asset.
PINS={'product': '7029d80f81e46ab152639945346058b9b6d3447e', 'tree': '2c89d25761e3ccf324d6599dc0aca80c9546858a', 'SOURCE_COUNTS': [15119484396, 'assembled-viewer-source-counts', 1828, 'a81d16b7704d4cd38d28451c68023c75a766a71ec30d6e59a9dc5dff183fd0b3'], 'SOURCE_ASSETS': [15120543103, 'assembled-viewer-source-generated-assets', 161045, 'c4851db60b0ffe5d94c3e9b0c72b3bd6d6bcda4b14eb4b7bdc5b89fdfa04101a'], 'manifest': 'b8c97da2912acf938613c8fef65280c2ef054c559f0454a40363e9d001131b9e', 'SOURCE_VISUALS': [15120478329, 'assembled-viewer-source-encrypted-visuals', 6838852, '0bbcd355ed457462970842c6a3617af808eec69197140c5ff5e861ad478919a8'], 'ciphertext': 'aa1ce96a1cafe7bf14e971f4b9728cfe265bbfa1d507c54553db5d16a42e0de3'}
SELECTION={'additionalStages': [], 'patchSha256': 'a69ab409422c7115319bfbf2ca2dd248824470ec38419c712f5673076024312c', 'paths': {'web/app/scripts/replay-tools-journey.mjs': 'c5ac25c727d16681ab6585c1fae9875ad30cf5299dca4891a0e1f900aaa7dbaf', 'web/app/src/features/events/EventsPanel.tsx': '480d1691d760eff36c51c60c4a9a39456825c2bc9c1f3853dc41d917df0e4c8e', 'web/app/src/features/events/StepsList.tsx': '6ecc84ecc77b305719ae73b49ad3e852e172e5199cca47a7ab616a92f434035a', 'web/app/src/features/events/useStepWindow.ts': '82af3dc1dec4311cd4244379fd02d38c6ae14dbc32aea0e774b091247d520455', 'web/app/src/features/shell/workspace.css': '9a8561810c47d7612fabadf1eb8ea0cecdd9456b2cd8bfb5b20051b4fb29786f'}, 'run': 45826460660, 'source': '4b41175d71caa28d9c25cb1cee6243ad14b95234', 'tree': '0c9c131f5abe44549e5fb6eca752b9c09d76ddf4', 'unitFiles': 32, 'unitTests': 303, 'workflow': '.github/workflows/selected-row-density-source.yml', 'workflowSha256': '1ae86b48d852ebd22d8c5972b5980716f680a9171be945ee43632bcb2c2ed29f', 'wrapper': 'cd17c90738f4be154297473413fa5f7beea0fa17'}
FIRST_USE_SOURCE='db94d2e197543b0fa35b214023e49c108a6a2fae'
FIRST_USE_TREE='e9536d80a3e6ac8438e5e02ad85b776771233f5d'
FIRST_USE_PATCH='cf59b5878b39778dafd5f959cdcbed5aa92beaa30ba333575bc8e164ec75614f'
PREVIOUS_GENERATED='cd850fb9324189f05e0bae1c7f701b518b6d4769'
PREVIOUS_GENERATED_TREE='e91d0ca7e9c51050dcb5c429e835f111634110e4'
SOURCE=SELECTION['source']
SOURCE_TREE=SELECTION['tree']
SOURCE_RUN=SELECTION['run']
SOURCE_WRAPPER=SELECTION['wrapper']
SOURCE_WORKFLOW=SELECTION['workflow']
SOURCE_WORKFLOW_SHA=SELECTION['workflowSha256']
CONTRACT_RUN=45792578783
CONTRACT_WRAPPER='cff3ffb8c18082791d13adc77fc6a5d4d75f4859'
CONTRACT_WORKFLOW_SHA='60bd9d80be69dbf8dd628df6a7bb92337e9ef5a2b09d8066cf4568b71eee5668'
INTEGRATED_WRAPPER='444ec4ff7b10e351aca94e42855bac263a05989d'
INTEGRATED_WORKFLOW_SHA='65b06a8d43fd45bff2d681ef3ae36e6aa34816d6d245a80453a94f6c96b3386c'
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
    'chromium-install','source-scope','spring-browser','empty-browser','spring-map-window')


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
    need(directory.is_dir() and not directory.is_symlink())
    entries=list(directory.rglob('*'))
    need(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in entries))
    need({p.relative_to(directory).as_posix() for p in entries if p.is_file()}==set(ASSETS))
    for name in ASSETS:
        expected=source/name;actual=directory/name
        need(actual.is_file() and not actual.is_symlink() and actual.stat().st_size<=20*1024*1024)
        need(digest(actual)==digest(expected))
    need(digest(directory/'assets.sha256')==os.environ['EXPECTED_UI_MANIFEST_SHA256'])


def git_text(*args):
    return git(*args).decode('utf-8').strip()


def source_identity():
    need(git_text('rev-parse',CONTRACT_SOURCE+'^{tree}')==CONTRACT_TREE)
    need(git_text('rev-parse',INTEGRATED+'^{tree}')==INTEGRATED_TREE)
    need(git_text('show','-s','--format=%P',INTEGRATED)==SOURCE_PARENTS)
    patch=git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',SOURCE_PARENTS.split()[0],INTEGRATED)
    need(hashlib.sha256(patch).hexdigest()==SOURCE_PATCH)
    need(set(SELECTION)=={'source','tree','patchSha256','paths','wrapper','workflow','workflowSha256',
                          'run','unitTests','unitFiles','additionalStages'})
    need(all(isinstance(x,str) and re.fullmatch('[0-9a-f]{40}',x) for x in (SOURCE,SOURCE_TREE,SOURCE_WRAPPER)))
    need(type(SOURCE_RUN) is int and SOURCE_RUN>0 and SOURCE_RUN!=FAILED_INTEGRATED_RUN)
    need(type(SELECTION['unitTests']) is int and SELECTION['unitTests']>=303 and
         type(SELECTION['unitFiles']) is int and SELECTION['unitFiles']>=32)
    need(type(SELECTION['additionalStages']) is list and
         all(re.fullmatch(r'[a-z][a-z0-9-]{0,63}',s) for s in SELECTION['additionalStages']))
    stages=(*SOURCE_STAGES,*SELECTION['additionalStages'])
    need(len(stages)==len(set(stages)))
    need(re.fullmatch(r'\.github/workflows/[a-z][a-z0-9-]*\.yml',SOURCE_WORKFLOW))
    need(git_text('show','-s','--format=%P',FIRST_USE_SOURCE)==INTEGRATED)
    need(git_text('rev-parse',FIRST_USE_SOURCE+'^{tree}')==FIRST_USE_TREE)
    first_patch=git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',INTEGRATED,FIRST_USE_SOURCE)
    need(hashlib.sha256(first_patch).hexdigest()==FIRST_USE_PATCH)
    need(git_text('show','-s','--format=%P',PREVIOUS_GENERATED)==FIRST_USE_SOURCE)
    need(git_text('rev-parse',PREVIOUS_GENERATED+'^{tree}')==PREVIOUS_GENERATED_TREE)
    previous_changes=git_text('diff','--no-renames','--name-status',FIRST_USE_SOURCE,PREVIOUS_GENERATED).splitlines()
    need(previous_changes==['M\t'+PREFIX+name for name in ('app.js','assets.sha256','index.css')])
    need(git_text('rev-parse',SOURCE+'^{tree}')==SOURCE_TREE and git_text('show','-s','--format=%P',SOURCE)==PREVIOUS_GENERATED)
    actual=git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',PREVIOUS_GENERATED,SOURCE)
    need(hashlib.sha256(actual).hexdigest()==SELECTION['patchSha256'])
    changes=git_text('diff','--no-renames','--name-status',PREVIOUS_GENERATED,SOURCE).splitlines()
    expected=SELECTION['paths']
    need(type(expected) is dict and bool(expected) and len(changes)==len(expected))
    for row in changes:
        status,path=row.split('\t')
        need(status in ('M','A') and path in expected and
             path.startswith(('web/app/src/','web/app/scripts/')) and
             git_text('ls-tree',SOURCE,'--',path).startswith('100644 blob ') and
             hashlib.sha256(git('show',SOURCE+':'+path)).hexdigest()==expected[path])
    # Check the complete name/mode/object inventory outside viewer source and its generated output.
    def non_ui(rev):
        return [line for line in git('ls-tree','-rz',rev).split(b'\0') if line and
                not line.split(b'\t',1)[1].startswith((b'web/app/',PREFIX.encode()))]
    need(non_ui(CONTRACT_SOURCE)==non_ui(SOURCE))
    for parent,wrapper,path,sha in (
        (CONTRACT_SOURCE,CONTRACT_WRAPPER,'.github/workflows/owner-plan-contracts.yml',CONTRACT_WORKFLOW_SHA),
        (INTEGRATED,INTEGRATED_WRAPPER,INTEGRATED_WORKFLOW,INTEGRATED_WORKFLOW_SHA),
        (FIRST_USE_SOURCE,'3c7f1d0f036330ce5f6db0fdc9c57ada1261d041','.github/workflows/combined-first-use-source.yml','d9c8dd4c32cdc36830bf015f831c0756b1a491c00a41f12db619ec1f423d7502'),
        (SOURCE,SOURCE_WRAPPER,SOURCE_WORKFLOW,SOURCE_WORKFLOW_SHA)):
        need(git_text('show','-s','--format=%P',wrapper)==parent)
        need(git_text('diff','--name-status',parent,wrapper)=='A\t'+path)
        need(git_text('ls-tree',wrapper,'--',path).startswith('100644 blob '))
        need(hashlib.sha256(git('show',wrapper+':'+path)).hexdigest()==sha)


def generated_identity(product, tree, assets):
    need(re.fullmatch('[0-9a-f]{40}',product) and re.fullmatch('[0-9a-f]{40}',tree))
    need(git_text('rev-parse',product+'^{tree}')==tree and git_text('show','-s','--format=%P',product)==SOURCE)
    paths={PREFIX+name for name in ASSETS}
    entries=git_text('ls-tree','-r',product,'--',PREFIX).splitlines()
    need(len(entries)==len(paths) and all(row.startswith('100644 blob ') for row in entries)
         and {row.split('\t',1)[1] for row in entries}==paths)
    for name in ASSETS:
        need(git('show',product+':'+PREFIX+name)==assets[name])
    changed={PREFIX+name for name in ASSETS if git('show',SOURCE+':'+PREFIX+name)!=assets[name]}
    need(PREFIX+'assets.sha256' in changed and set(git_text('diff','--name-only',SOURCE,product).splitlines())==changed)


def verified_manifest(assets):
    need(set(assets)==set(ASSETS))
    rows={}
    for line in assets['assets.sha256'].decode('utf-8').splitlines():
        sha,name=line.split('  ')
        mapped=name.removeprefix('assets/')
        need(mapped in ASSETS[:-1] and mapped not in rows and re.fullmatch('[0-9a-f]{64}',sha)
             and name==('assets/'+mapped if mapped.startswith('fonts/') else mapped)
             and hashlib.sha256(assets[mapped]).hexdigest()==sha)
        rows[mapped]=sha
    need(set(rows)==set(ASSETS[:-1]))
    return hashlib.sha256(assets['assets.sha256']).hexdigest()


def offline_identity():
    product,tree=os.environ['PRODUCT'],os.environ['PRODUCT_TREE']
    need(product==PINS['product'] and tree==PINS['tree'] and os.environ['EXPECTED_UI_MANIFEST_SHA256']==PINS['manifest'])
    need(git_text('rev-parse','HEAD')==product and git_text('rev-parse','HEAD^{tree}')==tree)
    source_identity()
    assets={name:(root()/'private/assets'/name).read_bytes() for name in ASSETS}
    need(verified_manifest(assets)==PINS['manifest'])
    generated_identity(product,tree,assets)
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
    validate_run(result,run_id,wrapper,branch,path)


def validate_run(result,run_id,wrapper,branch,path):
    need(result['repository']['full_name']=='Legend101Zz/X-trace' and result['head_repository']['full_name']=='Legend101Zz/X-trace')
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
    return packet(archive,size,sha,members)


def packet(archive,size,sha,members):
    need(archive.stat().st_size==size and digest(archive)==sha)
    with zipfile.ZipFile(archive) as zipped:
        infos=zipped.infolist()
        need(len(infos)==len(members) and {i.filename for i in infos}==set(members)
             and all(not i.is_dir() and i.file_size<=20*1024*1024 and i.compress_type in (0,8)
                     and stat.S_IFMT(i.external_attr>>16) in (0,stat.S_IFREG) for i in infos)
             and sum(i.file_size for i in infos)<=120*1024*1024+4096 and zipped.testzip() is None)
        return {name:zipped.read(name) for name in members}


def contracts(doc):
    need(set(doc)=={'attempt','genuineApplicationCapture','kind','packaged','releaseAcceptance','runId','schemaVersion',
                    'sourceSha','sourceTree','stages','status','wrapperSha'})
    need(doc['schemaVersion']==1 and doc['kind']=='owner_plan_source_contracts' and doc['sourceSha']==CONTRACT_SOURCE
         and doc['sourceTree']==CONTRACT_TREE and doc['wrapperSha']==CONTRACT_WRAPPER and doc['runId']==CONTRACT_RUN
         and doc['attempt']==1 and doc['status']=='passed' and doc['packaged'] is False
         and doc['releaseAcceptance'] is False and doc['genuineApplicationCapture'] is False)
    need(set(doc['stages'])==set(EXPECTED_CONTRACTS))
    need(all(doc['stages'][label]==dict(expected=n,passed=n,status='passed') for label,n in EXPECTED_CONTRACTS.items()))


def source_counts(doc):
    need(doc['schemaVersion']==1 and doc['kind']=='source-built-assembled-viewer'
         and doc['sourceSha']==SOURCE and doc['sourceTree']==SOURCE_TREE and doc['releaseAcceptance'] is False
         and doc['installedPackage'] is False and doc['fullFloor'] is False and doc['status']=='pass'
         and doc['stage']=='complete' and doc['exitCode']==0 and doc['countsComplete'] is True)
    need(doc['unit']==dict(files=SELECTION['unitFiles'],passed=SELECTION['unitTests'],failed=0,ignored=0)
         and doc['spring']==dict(passed=1,failed=0,ignored=0) and doc['empty']==dict(passed=1,failed=0,ignored=0))
    need(doc['springWindow']==dict(passed=1,failed=0,ignored=0)
         and doc['springWindowTest']==dict(binary='java_run_spring',
             case='focused_spring_viewer_loads_earlier_and_later_recorded_events',status='pass'))
    rows=doc['stages']
    need(len(rows)==len(SOURCE_STAGES)+len(SELECTION['additionalStages']) and {x['stage'] for x in rows}==set((*SOURCE_STAGES,*SELECTION['additionalStages']))
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
        assembledSource=SOURCE,assembledSourceTree=SOURCE_TREE,contractTestedSource=CONTRACT_SOURCE,contractTestedTree=CONTRACT_TREE,contractsRun=CONTRACT_RUN,
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
        run(run_id,SOURCE_WRAPPER,SOURCE_BRANCH,SOURCE_WORKFLOW,'source')
        need(hashlib.sha256(git('show',SOURCE_WRAPPER+':'+SOURCE_WORKFLOW)).hexdigest()==SOURCE_WORKFLOW_SHA)
        report['stage']='source-counts';save()
        def spec(prefix,name):
            actual=(int(os.environ[prefix+'_ARTIFACT_ID']),name,int(os.environ[prefix+'_ARCHIVE_SIZE']),os.environ[prefix+'_ARCHIVE_SHA256'])
            need(actual==tuple(PINS[prefix]));return actual
        source_counts(load(artifact(run_id,SOURCE_WRAPPER,spec('SOURCE_COUNTS','assembled-viewer-source-counts'),'source-counts',('counts.json',))['counts.json']))
        report['stage']='source-generated-assets';save()
        assets=artifact(run_id,SOURCE_WRAPPER,spec('SOURCE_ASSETS','assembled-viewer-source-generated-assets'),'source-assets',ASSETS)
        assets_root=target/'private/assets';assets_root.mkdir(mode=0o700)
        for name,data in assets.items():
            path=assets_root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as stream:stream.write(data)
        need(digest(assets_root/'assets.sha256')==os.environ['EXPECTED_UI_MANIFEST_SHA256'])
        need(verified_manifest(assets)==PINS['manifest'])
        report['stage']='source-encrypted-packet';save()
        visual=artifact(run_id,SOURCE_WRAPPER,tuple(PINS['SOURCE_VISUALS']),'source-visuals',('visuals.cms',))
        need(hashlib.sha256(visual['visuals.cms']).hexdigest()==PINS['ciphertext'])
        report['stage']='generated-direct-child';save();offline_identity()
        report.update(status='passed',stage='complete',verifiedGeneratedFiles=7,verifiedContracts=105)
    except Exception:pass
    save()
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
