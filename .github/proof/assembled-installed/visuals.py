"""Encrypt the closed 144-frame inventory; failed stages retain valid partials only."""
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

from common import ROOT, binding, load_package, need, private_json, safe_read
from export_receipt import SUCCESS, export_report
from tools.release.private_roots import admit_directory, atomic_write_private
from tools.qa.export_visual_evidence import collect_visuals, private_png


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
    sizes = ((320, 640), (736, 900), (1024, 768), (1280, 900), (1440, 900))
    phases = ('filter', 'goto', 'jump', 'tools', 'playback', 'speed')
    selected = {}
    for width, height in sizes:
        for pointer in ('fine', 'coarse'):
            for phase in (*phases, 'compact-tools-open' if width < 1280 else 'desktop-tools-inline'):
                name = f'viewer-replay-{phase}-{pointer}-{width}-viewport.png'
                selected[f'replay/shots/{"existing" if phase in phases else "compact-open"}/{name}'] = (width, height)
    for pointer in ('fine', 'coarse'):
        selected[f'replay/shots/compact-open/viewer-phone-more-{pointer}-320-viewport.png'] = (320, 640)
    for width in (320, 736, 1024, 1440):
        for name in (f'empty-{width}.png', f'tour-{width}-step-2.png', f'tour-{width}-step-3.png'):
            selected['tour/shots/first-recording/' + name] = (width, 844)
        for title in ('Find', 'Read', 'Check'):
            selected[f'tour/shots/spring-tour/tour-{width}-{title}.png'] = (width, 844)
    need(len(selected) == 96)
    return selected


def read_stage(name):
    path = ROOT / name / 'safe/report.json'
    return safe_read(path) if path.exists() else None


def main():
    admit_directory(ROOT)
    counts = dict(schemaVersion=1, kind='assembled-installed-visuals', releaseAcceptance=False,
                  status='fail', replayFrames=0, tourFrames=0, exportFrames=0, visualCount=0,
                  ciphertextSha256=None, recipientDerSha256=os.environ['RECIPIENT_DER_SHA256'])
    out = ROOT / 'safe/visuals.json'
    private_json(out, counts)
    package = safe_read(ROOT / 'safe/package.json')
    if package['status'] != 'pass':
        return
    shared = load_package()
    counts.update(binding(shared))
    replay, tour = (read_stage(name) for name in ('replay', 'tour'))
    selected, missing = [], {'replay': 0, 'tour': 0, 'export': 0}
    # Only fixed names are read; never enumerate diagnostics or private browser files.
    for name, (width, height) in inventory().items():
        path = ROOT / name
        stage = name.split('/')[0]
        try:
            path.lstat()
            for parent in (path.parent, path.parent.parent, ROOT / stage):
                admit_directory(parent)
            info = path.lstat()
            need(info.st_nlink == 1)
            data = private_png(path, width, height)
        except FileNotFoundError:
            missing[stage] += 1
            continue
        selected.append((name, data))
        counts[stage + 'Frames'] += 1
    for name, report, expected in (('replay', replay, 72), ('tour', tour, 24)):
        if report and report.get('status') == SUCCESS[name]:
            need(all(report.get(key) == value for key, value in binding(shared).items()))
            need(counts[name + 'Frames'] == expected and missing[name] == 0)
    export = None
    export_error = None
    export_stage = 'read-report'
    try:
        export = export_report(shared)
        need(export['status'] != 'invalid')
        if export['status'] != 'not-reached':
            export_stage = 'package-binding'
            need(all(export.get(key) == value for key, value in binding(shared).items()))
            positive = (export.get('packageVerified') is True
                        and re.fullmatch('[0-9a-f]{64}', export.get('summarySha256', '')))
            complete_export = export.get('status') == SUCCESS['export']
            need(not complete_export or positive)
            if positive:
                browser = ROOT / 'export/journey/browser'
                export_stage = 'collect-pngs'
                if complete_export or browser.exists():
                    frames, refused = collect_visuals(browser, require_complete=complete_export)
                    admitted = []
                    for name, data in frames:
                        need((browser / name).lstat().st_nlink == 1)
                        admitted.append(('export/' + name, data))
                    need(len(admitted) <= 48)
                    if complete_export:
                        need(len(admitted) == 48 and not any(refused.values()))
                    selected.extend(admitted)
                    counts['exportFrames'] = len(admitted)
    except Exception:
        # Preserve earlier verified native images even when export admission itself fails.
        export_error = export_stage
    counts['exportCollectionFailure'] = export_error
    need(len(selected) <= 144)
    if selected:
        counts['ciphertextSha256'] = encrypt('visuals.cms', selected)
        counts['visualCount'] = len(selected)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('ready=true\n')
    complete = export_error is None and all(report and report.get('status') == SUCCESS[name]
            for name, report in (('replay', replay), ('tour', tour), ('export', export)))
    if complete:
        need((counts['replayFrames'], counts['tourFrames'], counts['exportFrames'], len(selected)) == (72, 24, 48, 144))
        counts['status'] = 'pass'
    else:
        counts['status'] = 'partial' if selected else 'fail'
    private_json(out, counts)
    need(export_error is None and (not complete or counts['status'] == 'pass'))


if __name__ == '__main__':
    os.umask(0o077)
    main()
