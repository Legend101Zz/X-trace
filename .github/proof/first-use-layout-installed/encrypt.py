"""Encrypt only the three admitted native viewport original names."""
import hashlib
import json
import os

from common import ROOT, load_package, need, private_json, safe_read
from receipts import WIDTHS, valid_driver, width_copied
from sealing import encrypt
from tools.qa.export_visual_evidence import VisualEvidenceFailure, private_png
from tools.release.private_roots import admit_directory


def run():
    load_package()
    admit_directory(ROOT/'shots')
    rows = safe_read(ROOT/'safe/geometry.json') if (ROOT/'safe/geometry.json').exists() else None
    need(rows is None or valid_driver(rows))
    authorized = {row['width'] for row in rows['cells'] if width_copied(row)} if rows else set()
    selected = []
    widths = []
    rejected = False
    for width in WIDTHS:
        path = ROOT/'shots'/f'empty-{width}.png'
        if not path.exists():
            continue
        # An interrupted subprocess can leave a file before its Python
        # checkpoint is projected. Keep it runner-private in that case.
        if width not in authorized:
            continue
        try:
            need(path.lstat().st_nlink == 1)
            frame = private_png(path, width, 844)
        except (OSError, RuntimeError, VisualEvidenceFailure):
            rejected = True
            continue
        selected.append((path.name, frame))
        widths.append(width)
    if selected:
        manifest = dict(schema=1, source=os.environ['ASSEMBLED_SOURCE_SHA'],
                        product=os.environ['PRODUCT'], wrapper=os.environ['GITHUB_SHA'],
                        run=int(os.environ['GITHUB_RUN_ID']), sourceRun=int(os.environ['VERIFIED_SOURCE_RUN_ID']),
                        frames=[dict(name=name, width=width, height=844, sha256=hashlib.sha256(data).hexdigest())
                                for (name, data), width in zip(selected, widths, strict=True)])
        encrypt('native.cms', [*selected, ('originals.json', json.dumps(manifest, sort_keys=True).encode())])
    private_json(ROOT/'safe/encrypted.json', {'widths': widths})
    if selected:
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
            stream.write('ready=true\n')
    need(not rejected)


if __name__ == '__main__':
    os.umask(0o077)
    run()
