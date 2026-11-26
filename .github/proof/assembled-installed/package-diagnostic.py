"""Bounded private package-stage tails, encrypted for the pinned existing recipient."""
import os
import stat

from common import ROOT, need, private_json, safe_read
from visuals import encrypt


def main():
    package = safe_read(ROOT / 'safe/package.json')
    if package.get('status') != 'fail' or package.get('stage') != 'package':
        return
    need(package.get('sourceSha') == os.environ['PRODUCT'] and package.get('sourceTree') == os.environ['PRODUCT_TREE'])
    selected, counts = [], []
    for name in ('package.stdout', 'package.stderr', 'package-exception.stderr'):
        path = ROOT / 'logs' / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
                 and info.st_nlink == 1)
            stream.seek(max(0, info.st_size - 128 * 1024))
            data = stream.read(128 * 1024)
        counts.append(dict(stream=name, tailBytes=len(data), truncated=info.st_size > len(data)))
        if data:
            selected.append((name + '.tail', data))
    receipt = dict(schemaVersion=1, kind='assembled-installed-package-diagnostic', releaseAcceptance=False,
                   sourceSha=os.environ['PRODUCT'], sourceTree=os.environ['PRODUCT_TREE'], archiveVerified=False,
                   streams=counts, retained=False, ciphertextSha256=None)
    if selected:
        receipt.update(ciphertextSha256=encrypt('package-diagnostics.cms', selected), retained=True)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('ready=true\n')
    private_json(ROOT / 'safe/package-diagnostic.json', receipt)


if __name__ == '__main__':
    os.umask(0o077)
    main()
