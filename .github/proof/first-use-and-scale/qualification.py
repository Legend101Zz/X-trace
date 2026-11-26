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
SOURCE_BRANCH='codex/proof-first-use-ordinary-source-118'
INTEGRATED_WORKFLOW='.github/workflows/phone-plan-integrated-source.yml'
PREFIX='crates/xtrace-daemon/assets/ui/'
# Offline binder substitutes a single closed literal after validating both runs and every asset.
# An exact-hash checked wrapper file fixes every source, artifact and generated-child input.
PINS=json.loads(Path(__file__).with_name('pins.json').read_bytes())
SELECTION={'source':'2c9a262371f75ce5adaefccffaf9b71dbe1cacd7','tree':'4dac14a5fe4d2d20ce36b9d4e60a41782017b774',
           'run':PINS['sourceRun'],'wrapper':PINS['sourceWrapper'],'workflow':'.github/workflows/map-recording-ordinary-source.yml',
           'workflowSha256':'9bf50605ee95cdb766a3835ab9fd0a311ede49ea677ec49c07f5efe9ab86f947',
           'unitFiles':32,'unitTests':317,'additionalStages':[]}
LINEAGE=(('4b41175d71caa28d9c25cb1cee6243ad14b95234', '0c9c131f5abe44549e5fb6eca752b9c09d76ddf4', 'a69ab409422c7115319bfbf2ca2dd248824470ec38419c712f5673076024312c'), ('c16eca86d480f0e3d5911a237ab1ad6830a45d94', '45634d1cb2570732ac6ce3e89dcde5beb865b3b8', 'c8649f278d85708eab7c115c3f44d13024c1236862e1f6fbf091e4d85e5b3204'), ('48ae5e2306829a52de9c5c054932430fe522bb76', '8bc2201d0abe56c767d0e42bcb5546bd1cf25863', '07e83608cb728d75b5f0ab20ca4eec8daf1d8a71a4c1ea3c35ec6479079735be'), ('4498a3ed4a4ed00ea6e75aea8c3bfa5bd5143c37', '26816725df57fdd9a95b935025209439397e273f', '001ccb3668b71973c8fd8ea75fa717ed3525ab8a60d11dfb3d042017601f69e7'), ('8c8e05f3eeab52ca8fd6822a59ac5018088f4593', 'fd86131a4d830eca54668f09a73b8ce987f23ef7', 'f98aed87ddccb8db2adcda8acc0798a67370ca464c598d7efb891f804e431c0b'))
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
    import historical_qualification as prior
    # Preserve the full original contracts and earlier source lineage. The new
    # viewer is a single reviewed child of that source's verified generated tree.
    prior.source_identity()
    base = prior.PINS['product']
    previous = {name:git('show',base+':'+PREFIX+name) for name in ASSETS}
    need(verified_manifest(previous) == prior.PINS['manifest'])
    prior.generated_identity(base,prior.PINS['tree'],previous)
    need(git_text('show','-s','--format=%P',SOURCE)==base)
    need(git_text('rev-parse',SOURCE+'^{tree}')==SOURCE_TREE)
    diff=git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',base,SOURCE)
    need(hashlib.sha256(diff).hexdigest()=='4dde3c783f2d589598b4c97cf40bf070006f10c57683498b751b8b3474864e79')
    need(SOURCE_RUN==45846737406 and SOURCE_WRAPPER=='644ccc4122c331199bc2985ba82d78327bb8733d')
    need(git_text('show','-s','--format=%P',SOURCE_WRAPPER)==SOURCE)
    need(git_text('diff','--name-status',SOURCE,SOURCE_WRAPPER)=='A\t'+SOURCE_WORKFLOW)
    need(git_text('ls-tree',SOURCE_WRAPPER,'--',SOURCE_WORKFLOW).startswith('100644 blob '))
    need(hashlib.sha256(git('show',SOURCE_WRAPPER+':'+SOURCE_WORKFLOW)).hexdigest()==SOURCE_WORKFLOW_SHA)


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
    generated=PINS['generated']
    need(generated=='8e51f58197a1a3b612c5c9cc13090b76e0f91817' and PINS['generatedTree']=='46dc41cbdc96af48efec115b9fbd9413b7f6bc4a')
    need(generated==os.environ['GENERATED_PRODUCT'] and PINS['generatedTree']==os.environ['GENERATED_TREE'])
    generated_identity(generated,PINS['generatedTree'],assets)
    need(git_text('show','-s','--format=%P',product)==generated)
    changed=git_text('diff','--name-status','--no-renames',generated,product).splitlines()
    need(changed==['M\ttools/qa/replay-scale.md','M\ttools/qa/replay_scale_browser.mjs'])
    benchmark=git('diff','--no-ext-diff','--no-textconv','--no-color','--binary','--full-index',generated,product)
    need(hashlib.sha256(benchmark).hexdigest()==PINS['benchmarkPatch'])
    need(hashlib.sha256(git('show',product+':tools/qa/replay_scale_browser.mjs')).hexdigest()==PINS['benchmarkDriver'])
    need(hashlib.sha256(git('show',product+':tools/qa/replay-scale.md')).hexdigest()==PINS['benchmarkContract'])
    for name in ASSETS:
        need(git('show',product+':'+PREFIX+name)==assets[name])
    for path,sha in (('packaging/install.sh','7623373412edeb406deab5bbf672d8d5653b4a363ec4aa8b850380608f2e0425'),
                     ('packaging/test/install_test.sh','c251607d61e391251eb50e62cb5ca156c89815e31890e2b1276b5f4012d603b8')):
        need(digest(Path(path))==sha)
    need(not git('status','--porcelain','--untracked-files=all'))
    compare_ui(Path('crates/xtrace-daemon/assets/ui'))


def api(endpoint,name,binary=False):
    need(re.fullmatch(r'repos/Legend101Zz/X-trace/actions/(?:runs/[0-9]+(?:/artifacts|/attempts/1/jobs)?|artifacts/[0-9]+(?:/zip)?)',endpoint))
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
        assembledSource=SOURCE,assembledSourceTree=SOURCE_TREE,generatedProduct=PINS['generated'],generatedTree=PINS['generatedTree'],benchmarkPatch=PINS['benchmarkPatch'],contractTestedSource=CONTRACT_SOURCE,contractTestedTree=CONTRACT_TREE,contractsRun=CONTRACT_RUN,
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
        jobs=api(f'repos/Legend101Zz/X-trace/actions/runs/{run_id}/attempts/1/jobs','source-jobs.json')
        need(jobs['total_count']==1 and len(jobs['jobs'])==1)
        job=jobs['jobs'][0]
        need(job['run_id']==run_id and job['run_attempt']==1 and job['head_sha']==SOURCE_WRAPPER and
             job['head_branch']==SOURCE_BRANCH and job['conclusion']=='success' and job['status']=='completed')
        for name in ('Admit reviewed bar and Map sources, density lineage and direct-child wrapper',
                     'Admit fresh private scratch and exact source',
                     'Check named suites build embed and run genuine Spring browser journey privately',
                     'Verify the export download judge on its complete regression suite',
                     'Project bounded progress and encrypt allowlisted viewport frames'):
            rows=[step for step in job['steps'] if step['name']==name]
            need(len(rows)==1 and rows[0]['conclusion']=='success')
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
