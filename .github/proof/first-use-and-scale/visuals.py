"""Encrypt only fixed-name native first-use frames reached in this run."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

from common import ROOT, binding, load_package, need, private_json, read_replay, safe_read
from tools.release.private_roots import admit_directory, atomic_write_private
from tools.qa.export_visual_evidence import private_png


def certificate():
    cert = os.environ['RECIPIENT_CERT'].strip()
    match = re.fullmatch(r'-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)\n-----END CERTIFICATE-----', cert)
    need(match)
    der = base64.b64decode(match[1].replace('\n', ''), validate=True)
    need(hashlib.sha256(der).hexdigest() == os.environ['RECIPIENT_DER_SHA256'])
    path = ROOT / 'private/recipient.pem'
    atomic_write_private(path, (cert + '\n').encode('ascii'))
    return path


def encrypt(name, selected):
    need(selected and len({item for item, _ in selected}) == len(selected))
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w:gz') as archive:
        for path, data in selected:
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            archive.addfile(info, io.BytesIO(data))
    output = ROOT / 'encrypted' / name
    with (ROOT / 'logs' / (name + '.stderr')).open('xb') as err:
        result = subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER',
                                 '-out', str(output), str(certificate())], input=payload.getvalue(),
                                stdout=subprocess.DEVNULL, stderr=err, check=False, timeout=60)
    if result.returncode != 0:
        output.unlink(missing_ok=True)
        raise RuntimeError('encryption failed')
    info = output.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
         and info.st_nlink == 1 and 0 < info.st_size <= 256 * 1024 * 1024)
    return hashlib.sha256(output.read_bytes()).hexdigest()



def inventory():
    for width in (320,736,1024,1440):
        for name in (f'empty-{width}.png',f'tour-{width}-step-2.png',f'tour-{width}-step-3.png'):
            yield 'tour/shots/first-recording/'+name,width
        for title in ('Find','Read','Check'):
            yield f'tour/shots/spring-tour/tour-{width}-{title}.png',width


def main():
    admit_directory(ROOT)
    package=load_package()
    selected=[]
    counts=dict(status='incomplete',releaseAcceptance=False,visualCount=0,ciphertextSha256=None,
                recipientDerSha256=os.environ['RECIPIENT_DER_SHA256'],**binding(package))
    dest=ROOT/'safe/visuals.json'
    private_json(dest,counts)
    for name,width in inventory():
        path=ROOT/name
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        for parent in (path.parent,path.parent.parent,ROOT/'tour'):
            admit_directory(parent)
        need(path.lstat().st_nlink==1)
        selected.append((name,private_png(path,width,844)))
    need(len(selected)<=24)
    if selected:
        counts.update(visualCount=len(selected),ciphertextSha256=encrypt('visuals.cms',selected))
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('ready=true\n')
    counts['status']='partial' if selected else 'unavailable'
    source=ROOT/'tour/safe/report.json'
    if source.exists():
        report=safe_read(source)
        if report.get('status')=='pass':
            need(len(selected)==24 and all(report.get(k)==v for k,v in binding(package).items()))
            counts['status']='pass'
    private_json(dest,counts)
    need(counts['status']=='pass')


if __name__=='__main__':
    os.umask(0o077)
    main()
