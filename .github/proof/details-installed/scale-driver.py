"""Run the five original installed measurements and release only fixed numeric fields."""
import json
import hashlib
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import traceback

from common import ROOT, REPO, binding, digest, identity, load_package, need, private_json, safe_read

WORK = ROOT / 'scale'
DEST = ROOT / 'safe/scale.json'
REPORT = dict(status='incomplete', stage='admission', releaseAcceptance=False, samples=[])
MODES = ('initial_map','initial_steps_return','later_map','later_steps_return')
NAV = ('initial_steps_navigation','initial_map_navigation','later_steps_navigation','later_map_navigation')
LATER = tuple('load_later_' + str(i) for i in range(1,13))
ACTIONS = set(MODES) | set(LATER) | {nav + '_' + direction for nav in NAV for direction in ('next','back')}
STAGES = {'viewer_start','browser_start','catalog','initial_click_response','initial_visible_paint_opportunity',
          'initial_steps','later_steps','page_observations','complete','browser_cleanup','viewer_cleanup','timed_viewer_traffic'} | set(MODES + NAV + LATER)
SUBSTAGES = {'mode_click','mode_pressed','selection_wait','dom_snapshot','dom_assertions','next_click',
             'next_selection_wait','back_click','back_selection_wait','response','row_click','load_click','detail_response',
             'details_identity','details_click','reveal_row','identity_paint','next_event_lookup','default_inspector'}
DOM = ('apiLastPageEvents','apiEventsReturnedCumulative','mountedStepRows','visibleStepRows','loadedRailLabelCount',
       'mapSvgNodes','visibleMapSvgNodes','mapTreeRows','visibleMapTreeRows','documentElements')

def checkpoint(stage):
    REPORT['stage'] = stage
    private_json(DEST, REPORT)

def count(v, ceiling):
    need(type(v) is int and 0 <= v <= ceiling)
    return v

def numeric(v):
    need(type(v) in (int,float) and math.isfinite(v) and v >= 0)
    return v

def label(value, vocab):
    # Preserve new diagnostic classifications privately without exposing arbitrary strings.
    return value if isinstance(value,str) and value in vocab else 'other' if value is not None else None

def project_sample(sample, index):
    need(sample['sample'] == index and sample['status'] in ('exercised','failed'))
    initial = sample['initial']
    if initial is not None:
        for key in ('responseAndUiIdentityMatched','trustedClickCaptured','paintOpportunityObserved','fullInspectorIdentityReadableAtBothFrames'):
            need(initial[key] is True)
        need(re.fullmatch('[0-9a-f]{64}',initial['selectedIdentitySha256']))
        ms = numeric(initial['elapsedMs'])
        need(type(initial['over1500Ms']) is bool and initial['over1500Ms'] == (ms > 1500))
        clicked=initial['detailsTabClickIncluded']
        offset=initial['detailsTabClickOffsetMs']
        need(type(clicked) is bool and (clicked and numeric(offset)<=ms or not clicked and offset is None))
        initial = dict(fullInspectorIdentityReadableAtBothFrames=True,detailsTabClickIncluded=clicked,detailsTabClickOffsetMs=offset,elapsedMs=ms, over1500Ms=ms>1500, firstPageEvents=count(initial['apiFirstPageEvents'],200))
        need(initial['firstPageEvents'] > 0)
    actions = sample['actions']
    need(type(actions) is list and len(actions) <= 128 and len(actions)==len(set(actions)))
    errors = sample['failures']
    need(type(errors) is list and len(errors)<=4)
    failed = []
    for row in errors:
        need(row['code'] in ('journey_failed_or_unreached','cleanup_failed','unexpected_traffic_or_missing_exchange'))
        failed.append(dict(stage=label(row['stage'],STAGES),substage=label(row.get('substage'),SUBSTAGES),code=row['code']))
    out = dict(sample=index,status=sample['status'],stage=label(sample['stage'],STAGES),
               substage=label(sample['substage'],SUBSTAGES),initial=initial,failures=failed,
               laterPages=sum(key in actions for key in LATER),dom=[])
    traffic=sample.get('timedTraffic')
    out['timedTraffic']=(None if traffic is None else {k:count(traffic[k],100000) for k in ('authExchanges','refused')})
    for key in ('pageErrors','externalRequests'):
        v = sample[key]
        out[key] = count(v,100000) if v is not None else None
    need(isinstance(sample['dom'],list) and len(sample['dom'])<=16)
    for row in sample['dom']:
        phase=row['phase']
        public=dict(phase=phase if phase in ('initial_steps','later_steps',*MODES) else 'failure-observation')
        for key in DOM:
            v=row[key]
            public[key] = count(v,1000000) if v is not None else None
        heap=row['browserHeap']
        need(heap['status'] in ('measured','unavailable'))
        public['heapStatus']=heap['status']
        if heap['status']=='measured':
            public['heapUsedBytes']=numeric(heap['usedBytes'])
            public['heapTotalBytes']=numeric(heap['totalBytes'])
        out['dom'].append(public)
    if sample['status']=='exercised':
        need(initial is not None and sample['stage']=='complete' and not errors and ACTIONS <= set(actions))
        need(out['pageErrors']==out['externalRequests']==0 and out['timedTraffic']==dict(authExchanges=1,refused=0))
        need([x['phase'] for x in out['dom']]==['initial_steps','initial_map','initial_steps_return','later_steps','later_map','later_steps_return'])
        transitions=sample['modeTransitions']
        need([x['phase'] for x in transitions]==list(MODES))
        need(all(x['clickCompleted'] is True and x['pressedObserved'] is True and x['selectionMatched'] is True for x in transitions))
    else:
        need(bool(errors))
    return out

def launch(label, args, env):
    with (WORK / 'logs' / (label+'.stdout')).open('xb') as out, (WORK / 'logs' / (label+'.stderr')).open('xb') as err:
        return subprocess.run(args,cwd=REPO,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,check=False).returncode

def main():
    identity()
    package=load_package()
    REPORT.update(binding(package),generatedProduct=os.environ['GENERATED_PRODUCT'],generatedTree=os.environ['GENERATED_TREE'])
    cli=Path(package['prefix'])/'bin/xtrace'
    need(digest(cli)==package['installedCliSha256'])
    fixture=WORK/'fixture'
    fixture.mkdir(mode=0o700)
    manifest=fixture/'manifest.json'
    env=dict(os.environ,TMPDIR=str(ROOT/'tmp'),XTRACE_TEST_PRIVATE_SCRATCH=str(fixture),
             XTRACE_SCALE_FIXTURE_MANIFEST=str(manifest),XTRACE_SCALE_XTRACE=str(cli))
    env.pop('GH_TOKEN',None); env.pop('GITHUB_TOKEN',None)
    checkpoint('fixture')
    rc=launch('fixture',['cargo','test','--locked','-p','xtrace-cli','--test','replay_scale',
                         'synthetic_ten_thousand_frames_are_complete_ordered_and_navigable','--','--exact'],env)
    REPORT['fixtureExit']=rc if rc in range(256) else None
    need(rc==0 and re.search(rb'^test result: ok\. 1 passed; 0 failed; 0 ignored;', (WORK/'logs/fixture.stdout').read_bytes(),re.M))
    doc=safe_read(manifest)
    need(doc['verified_frame_count']==10000 and doc['synthetic'] is True)
    checkpoint('browser')
    driver=REPO/'tools/qa/replay_scale_browser.mjs'
    raw=WORK/'private/report.json'
    rc=launch('browser',['node',str(driver),'--manifest',str(manifest),'--xtrace',str(cli),'--source-sha',package['sourceSha'],
                         '--provenance','installed','--package-sha256',package['archiveSha256'],
                         '--later-pages','12','--cdp-heap','--out',str(raw)],env)
    REPORT['browserExit']=rc if rc in range(256) else None
    checkpoint('verify')
    # The original driver writes the whole five-attempt report even when some samples fail.
    # Higher node and byte ceilings apply to its intentionally rich per-DOM diagnostics.
    import stat
    st=raw.lstat()
    need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_uid==os.getuid() and 0<st.st_size<=2*1024*1024)
    raw_bytes=raw.read_bytes()
    report=json.loads(raw_bytes)
    need(report['schemaVersion']==1 and report['synthetic'] is True and report['kind']=='synthetic_replay_scale_browser')
    need(report['provenance']=={'declaredSourceSha':package['sourceSha'],'distribution':'installed','binarySha256':package['installedCliSha256'],'declaredPackageSha256':package['archiveSha256']})
    c=report['conditions']
    need(c['samples']==5 and c['freshBrowserProcessContextAndViewerPerSample'] is True and c['fixtureFrames']==10000 and c['laterPages']==12 and c['verifyMapTreeWindow'] is False)
    need(c['viewport']==dict(width=1440,height=900) and c['headless'] is True and c['deviceScaleFactor']==1 and c['locale']=='en-US' and c['timezone']=='UTC' and c['colorScheme']=='light' and c['reducedMotion']=='no-preference' and c['cpuOrNetworkThrottling']=='none')
    need(c['timing']=='trusted recording click to visible first selection and fully readable Inspector event identity across two rAF callbacks; includes opening Details when initially closed; no physical-display claim')
    need(c['browserNetworking']=='read-only route allowlist with one viewer bootstrap exchange; Playwright routing disables HTTP cache; service workers blocked')
    need(c['excludedFromTiming']==['fixture seeding','viewer startup','catalog loading'])
    need(isinstance(report['samples'],list) and len(report['samples'])==5)
    for i,s in enumerate(report['samples'],1):
        REPORT['samples'].append(project_sample(s,i))
        checkpoint('verify')
    times=[s['initial']['elapsedMs'] for s in REPORT['samples'] if s['initial'] is not None]
    complete=sum(s['status']=='exercised' for s in REPORT['samples'])
    summary=dict(functionalFailures=5-complete,completeJourneySamples=complete,validInitialSamples=len(times),
                 medianMs=statistics.median(times) if times else None,maxMs=max(times) if times else None,
                 samplesOver1500Ms=sum(x>1500 for x in times),aggregationDecision='unsettled; descriptive statistics only',memoryThreshold='unsettled')
    need(report['summary']==summary)
    REPORT['summary']=summary
    REPORT['privateReportSha256']=hashlib.sha256(raw_bytes).hexdigest()
    need(rc==(0 if complete==5 else 1) and load_package()==package)
    REPORT['status']='exercised' if complete==5 else 'partial'
    checkpoint('complete')
    return rc

if __name__=='__main__':
    os.umask(0o077)
    checkpoint('admission')
    try:
        code=main()
    except Exception:
        with (WORK/'logs/driver-exception.stderr').open('x') as out: traceback.print_exc(file=out)
        checkpoint(REPORT['stage'])
        code=1
    raise SystemExit(code)
