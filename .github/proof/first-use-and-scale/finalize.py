"""Combine reached public-only receipts without substituting an absent or interrupted stage."""
import json
import os
import re
from common import ROOT, binding, load_package, need, private_json
from tools.release.private_roots import AdmissionError, read_private_json

def read(path):
    if not path.exists():
        return None
    return read_private_json(path, maximum_bytes=65536, maximum_nodes=8192, maximum_commas=8192)

def sealed_packet(outcome):
    if outcome != 'success':
        return None
    try:
        packet = read(ROOT/'safe/scale-packet.json')
    except (OSError, AdmissionError):
        return None
    if not isinstance(packet, dict) or set(packet) != {'status', 'samples', 'ciphertextSha256'}:
        return None
    if (packet['status'] != 'sealed' or type(packet['samples']) is not int or packet['samples'] != 5
            or not isinstance(packet['ciphertextSha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', packet['ciphertextSha256'])):
        return None
    return packet

def main():
    paths=dict(package=ROOT/'safe/package.json',installer=ROOT/'safe/installer-journey.json',
               tour=ROOT/'tour/safe/report.json',visual=ROOT/'safe/visuals.json',scale=ROOT/'safe/scale.json')
    docs={key:read(path) for key,path in paths.items()}
    outcomes={key:os.environ[key.upper()+'_OUTCOME'] for key in ('qualification',*paths,'scale_packet')}
    need(all(x in ('success','failure','cancelled','skipped') for x in outcomes.values()))
    output=dict(kind='installed-first-use-and-five-sample-scale',schemaVersion=1,releaseAcceptance=False,
                source=os.environ['PRODUCT'],tree=os.environ['PRODUCT_TREE'],generatedProduct=os.environ['GENERATED_PRODUCT'],
                generatedTree=os.environ['GENERATED_TREE'],viewerSource=os.environ['ASSEMBLED_SOURCE_SHA'],
                viewerSourceTree=os.environ['ASSEMBLED_SOURCE_TREE'],wrapper=os.environ['GITHUB_SHA'],
                runId=int(os.environ['GITHUB_RUN_ID']),attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),outcomes=outcomes,
                stages={})
    expected={}
    if outcomes['package']=='success':
        expected=binding(load_package())
    fields={
        'package': {'status','stage','exitCode'},
        'installer': {'status','passed'},
        'tour': {'status','stage','empty','selected','frames','completedCells','servedAssets','widths','selectedTabletReads'},
        'visual': {'status','visualCount','ciphertextSha256','recipientDerSha256'},
        'scale': {'status','stage','fixtureExit','browserExit','samples','summary'}
    }
    for key,doc in docs.items():
        if doc is None:
            need(outcomes[key]!='success')
            output['stages'][key]=None
            continue
        allowed=fields[key] | set(expected) | {'schemaVersion','kind','releaseAcceptance','sourceSha','sourceTree','uiManifestSha256',
                                               'archiveSha256','generatedProduct','generatedTree','privateReportSha256'}
        need(set(doc)<=allowed)
        if outcomes[key]=='success':
            need(doc['status']==('exercised' if key=='scale' else 'pass'))
            need(expected and all(doc.get(k)==v for k,v in expected.items()))
        output['stages'][key]={k:doc[k] for k in fields[key] if k in doc}
    if outcomes['tour']=='success':
        tour=docs['tour']; ordered=[{'kind':'empty','width':w} for w in (320,736,1024,1440)]
        ordered.extend({'kind':k,'width':w} for w in (320,736,1024,1440) for k in ('manual','selected'))
        ordered.extend({'kind':'drag','width':w} for w in (1024,1440))
        need(tour['completedCells']==ordered and tour['frames']==24 and tour['empty'] is True and tour['selected'] is True and tour['selectedTabletReads']==1 and tour['servedAssets']==24)
    if outcomes['visual']=='success': need(docs['visual']['visualCount']==24 and re.fullmatch('[0-9a-f]{64}',docs['visual']['ciphertextSha256']))
    if outcomes['installer']=='success': need(docs['installer']['passed']==32)
    if outcomes['scale']=='success': need(docs['scale']['summary']['completeJourneySamples']==5 and len(docs['scale']['samples'])==5)
    packet=sealed_packet(outcomes['scale_packet'])
    output['encryptedBenchmark']=packet
    # Each projection checks the driver's trusted click offset against the same
    # browser clock as the initial interval. Keep those measurements if another
    # sample began with Details open or if sealing the original report failed.
    samples = (docs['scale'] or {}).get('samples', [])
    initial = [sample['initial'] for sample in samples if sample['initial'] is not None]
    clicked = sum(item['detailsTabClickIncluded'] is True for item in initial)
    output['timedDetailsClicks'] = dict(observedInitialSamples=len(initial), included=clicked, required=5)
    output['packageBinding']=expected or None
    complete = all(v=='success' for v in outcomes.values()) and packet is not None and clicked == 5
    output['status']='exercised' if complete else 'partial-or-unavailable'
    private_json(ROOT/'safe/combined.json',output)
    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('ready=true\n')
    return 0 if output['status']=='exercised' else 1

if __name__=='__main__':
    os.umask(0o077)
    raise SystemExit(main())
