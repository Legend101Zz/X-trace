"""Seal the reviewed benchmark driver's original bounded report for owner inspection."""
import hashlib
import json
import os
import stat
from common import ROOT, binding, load_package, need, private_json
from tools.release.private_roots import admit_directory, read_private_json
from visuals import encrypt

def main():
    public_path=ROOT/'safe/scale.json'
    if not public_path.exists():
        return
    summary=read_private_json(public_path,maximum_bytes=65536,maximum_nodes=8192,maximum_commas=8192)
    if summary.get('stage')!='complete':
        return
    common=load_package()
    need(all(summary.get(k)==v for k,v in binding(common).items()))
    need(len(summary['samples'])==5 and summary['status'] in ('exercised','partial'))
    path=ROOT/'scale/private/report.json'
    admit_directory(path.parent)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        st=os.fstat(stream.fileno())
        need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==os.getuid() and st.st_nlink==1 and 0<st.st_size<=2*1024*1024)
        original=stream.read(st.st_size+1)
        need(len(original)==st.st_size and hashlib.sha256(original).hexdigest()==summary['privateReportSha256'])
    doc=json.loads(original)
    need(doc['provenance']['declaredSourceSha']==common['sourceSha'] and doc['provenance']['binarySha256']==common['installedCliSha256'])
    need(doc['summary']==summary['summary'] and len(doc['samples'])==5)
    sealed=encrypt('scale.cms',[('scale/report.json',original)])
    private_json(ROOT/'safe/scale-packet.json',dict(status='sealed',samples=5,ciphertextSha256=sealed))
    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('ready=true\n')

if __name__=='__main__':
    os.umask(0o077)
    main()
