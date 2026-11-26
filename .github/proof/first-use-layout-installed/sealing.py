"""Seal the original report for the existing dedicated evidence recipient."""
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

from common import ROOT, need
from tools.release.private_roots import atomic_write_private


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
