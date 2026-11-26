"""Project only finite installed observations and retain independent partials."""
import os
import re

from common import ROOT, binding, digest, load_package, need, private_json
from public_cells import timing_summary, valid_sample
from tools.release.private_roots import AdmissionError, read_private_json

STAGES = ('qualification', 'package', 'spring', 'scale', 'scale_packet')
PACKAGE_STAGES = {'identity','package','verify-dist','verify-archive','extract','install','verify-install',
                  'fixture','browser-dependencies','chromium','clean-source','complete'}
SPRING_STAGES = {'identity','init','spring-readiness','spring-request','spring-recording','spring-shutdown',
                 'viewer','browser','viewer-shutdown','complete'}
SCALE_STAGES = {'admission','fixture','browser','verify','complete'}


def read(path):
    try:
        value = read_private_json(path, maximum_bytes=65536, maximum_nodes=8192, maximum_commas=8192)
        return value if type(value) is dict else None
    except (OSError, AdmissionError):
        return None


def project(doc, allowed_status, allowed_stage, fields):
    if doc is None or type(doc.get('status')) is not str or type(doc.get('stage')) is not str:
        return None
    if doc['status'] not in allowed_status or doc['stage'] not in allowed_stage:
        return None
    return dict(status=doc['status'],stage=doc['stage'],**{key:doc[key] for key in fields if key in doc})


def main():
    outcomes = {key:os.environ[key.upper()+'_OUTCOME'] for key in STAGES}
    need(all(value in ('success','failure','cancelled','skipped') for value in outcomes.values()))
    def reached(key,path):
        return read(path) if outcomes[key] in ('success','failure','cancelled') else None

    package = reached('package',ROOT/'safe/package.json')
    spring = reached('spring',ROOT/'spring/safe/report.json')
    scale = reached('scale',ROOT/'safe/scale.json')
    packet = reached('scale_packet',ROOT/'safe/scale-packet.json')
    package_admitted = False
    if outcomes['package'] == 'success':
        try:
            expected = binding(load_package())
            package_admitted = bool(package and package.get('status') == 'pass' and package.get('stage') == 'complete'
                                    and all(package.get(k) == v for k,v in expected.items()))
        except (OSError, RuntimeError, KeyError, TypeError, AdmissionError):
            package_admitted = False
        if package_admitted:
            if spring and spring.get('status') == 'pass' and not all(spring.get(k) == v for k,v in expected.items()):
                spring = None
            if scale and scale.get('status') in ('exercised','partial') and not all(scale.get(k) == v for k,v in expected.items()):
                scale = None
    package_public = project(package,{'incomplete','pass','fail'}, PACKAGE_STAGES, ())
    if package_public and package and type(package.get('exitCode')) is int and -255 <= package['exitCode'] <= 255:
        package_public['exitCode'] = package['exitCode']
    spring_public = project(spring, {'incomplete','pass','fail'}, SPRING_STAGES,
                            ('checked','verifiedRecordings','assetReads','failedChecks'))
    scale_public = project(scale, {'incomplete','partial','exercised'}, SCALE_STAGES,
                           ('samples','summary','fixtureExit','browserExit'))
    if spring_public:
        checked = spring_public.get('checked')
        if checked not in ([],['fine'],['coarse'],['fine','coarse']):
            spring_public = None
        else:
            for key,values in (('verifiedRecordings',(1,)),('assetReads',(6,12,18,24))):
                if type(spring_public.get(key)) is not int or spring_public[key] not in values:
                    spring_public.pop(key,None)
            failures = spring_public.pop('failedChecks',{})
            if isinstance(failures,dict):
                safe = {mode: failures[mode] for mode in ('fine','coarse')
                        if failures.get(mode) in ('viewer','browser','viewer-shutdown')}
                if safe:
                    spring_public['failedChecks'] = safe
    if scale_public:
        projected = []
        raw = scale_public.pop('samples',None)
        if type(raw) is list and len(raw) <= 5:
            for index,sample in enumerate(raw,1):
                if not valid_sample(sample,index):
                    break
                projected.append(sample)
        scale_public['samples'] = projected
        summary = scale_public.pop('summary',None)
        if len(projected) == 5 and summary == timing_summary(projected):
            scale_public['summary'] = timing_summary(projected)
        for key in ('fixtureExit','browserExit'):
            value = scale_public.get(key)
            if type(value) is not int or not 0 <= value <= 255:
                scale_public.pop(key,None)
    sealed = False
    if outcomes['scale_packet'] == 'success' and packet and packet.get('status') == 'sealed':
        value = packet.get('ciphertextSha256')
        try:
            sealed = bool(packet.get('samples') == 5 and isinstance(value, str) and re.fullmatch('[a-f0-9]{64}',value)
                          and digest(ROOT/'encrypted/scale.cms') == value)
        except OSError:
            sealed = False
    samples = (scale_public or {}).get('samples',[])
    initial = [sample['initial'] for sample in samples if sample['initial'] is not None]
    clicks = sum(item['detailsTabClickIncluded'] is True for item in initial)
    spring_pass = spring_public == dict(status='pass',stage='complete',checked=['fine','coarse'],verifiedRecordings=1,assetReads=24)
    scale_pass = (scale_public is not None and scale_public['status'] == 'exercised'
                  and scale_public['stage'] == 'complete' and len(samples) == 5 and clicks == 5
                  and scale_public.get('summary',{}).get('completeJourneySamples') == 5)
    complete = all(value == 'success' for value in outcomes.values()) and package_admitted and spring_pass and scale_pass and sealed
    result = dict(kind='installed-details-and-scale',schemaVersion=1,releaseAcceptance=False,
                  status='exercised' if complete else 'partial-or-unavailable',
                  source=os.environ['ASSEMBLED_SOURCE_SHA'],sourceTree=os.environ['ASSEMBLED_SOURCE_TREE'],
                  sourceRunId=int(os.environ['VERIFIED_SOURCE_RUN_ID']),sourceWrapper=os.environ['VERIFIED_SOURCE_WRAPPER'],
                  product=os.environ['PRODUCT'],productTree=os.environ['PRODUCT_TREE'],
                  wrapper=os.environ['GITHUB_SHA'],runId=int(os.environ['GITHUB_RUN_ID']),attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
                  outcomes=outcomes,packageIdentityVerified=package_admitted,originalSamplesEncrypted=sealed,
                  timedViewerShutdown='not-independently-verified',
                  timedDetailsClicks=dict(observedInitialSamples=len(initial),included=clicks,required=5),
                  stages=dict(package=package_public,spring=spring_public,scale=scale_public))
    private_json(ROOT/'safe/combined.json',result)
    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
        stream.write(f'ready=true\nqualified={str(complete).lower()}\n')
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
