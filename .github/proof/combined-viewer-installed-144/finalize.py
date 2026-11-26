"""Publish bounded stage verdicts; skipped/unreached stages never become passes."""
import os

from common import ROOT, binding, load_package, need, private_json, read_replay, safe_read


from export_receipt import CELLS, SUCCESS, cells, export_diagnostic, export_report


def main():
    package = safe_read(ROOT / 'safe/package.json')
    out = dict(schemaVersion=1, kind='assembled-installed-viewer', releaseAcceptance=False, status='fail',
               assembledSourceSha=os.environ['ASSEMBLED_SOURCE_SHA'], assembledSourceTree=os.environ['ASSEMBLED_SOURCE_TREE'],
               sourceSha=os.environ['PRODUCT'], sourceTree=os.environ['PRODUCT_TREE'],
               uiManifestSha256=os.environ['EXPECTED_UI_MANIFEST_SHA256'], package=package)
    for name in ('replay', 'tour'):
        path = ROOT / name / 'safe/report.json'
        reader = read_replay if name == 'replay' else safe_read
        out[name] = reader(path) if path.exists() else {'status': 'not-reached'}
    shared = load_package() if package.get('status') == 'pass' else None
    out['export'] = export_report(shared)
    diagnostic = ROOT / 'safe/package-diagnostic.json'
    out['packageDiagnostic'] = safe_read(diagnostic) if diagnostic.exists() else None
    out['exportDiagnostic'] = export_diagnostic(shared)
    path = ROOT / 'safe/visuals.json'
    out['visuals'] = safe_read(path) if path.exists() else {'status': 'not-reached'}
    private_json(ROOT / 'safe/assembled.json', out)
    installer = ROOT / 'safe/installer-journey.json'
    out['installerJourney'] = safe_read(installer) if installer.exists() else {'status': 'not-reached'}
    complete = package.get('status') == 'pass'
    if complete:
        out.update(binding(shared))
        complete = (out['exportDiagnostic'] is not None and out['exportDiagnostic'].get('status') == 'outside-preverification-command-scope')
        complete = complete and out['installerJourney'] == {'status': 'pass', 'passed': 32, **binding(shared)}
        for name in ('replay', 'tour', 'export', 'visuals'):
            report = out[name]
            passed = report.get('status') == SUCCESS[name]
            if passed:
                need(all(report.get(key) == value for key, value in binding(shared).items()))
            complete = complete and passed
        if complete:
            need(out['replay']['existingFrames'] == 60 and out['replay']['compactOpenFrames'] == 6
                 and out['replay']['desktopInlineFrames'] == 4 and out['replay']['phoneMoreFrames'] == 2
                 and out['replay']['completeRecordings'] == 2 and out['replay']['refreshedCells'] == 10
                 and out['replay']['tabletSwitchCells'] == 2 and out['replay']['phoneKeyboardSwitches'] == 4
                 and out['replay']['coarseDensityWidths'] == [1024, 1280]
                 and len(out['replay']['jumpCells']) == 10 and out['replay']['servedAssets'] == 12)
            need(out['tour']['empty'] is True and out['tour']['selected'] is True and out['tour']['frames'] == 24
                 and out['tour']['handoffs'] == 4 and out['tour']['activeStops'] == 4 and out['tour']['servedAssets'] == 24
                 and out['tour']['selectedTabletReads'] == 1 and out['tour']['widths'] == [320, 736, 1024, 1440])
            need(out['export']['countsComplete'] is True and out['export']['downloads'] == 100
                 and out['export']['logicalFilesCompared'] == 480 and out['export']['privacySurfaces'] == 5
                 and out['export']['viewports'] == 10 and out['export']['servedAssets'] == 60
                 and len(out['export']['browserRows']) == 10 and cells(out['export']['browserRows']) == CELLS)
            need((out['visuals']['replayFrames'], out['visuals']['tourFrames'], out['visuals']['exportFrames'],
                  out['visuals']['visualCount']) == (72, 24, 48, 144))
            out['status'] = 'pass'
    private_json(ROOT / 'safe/assembled.json', out)
    print('assembledInstalledPass=' + str(int(out['status'] == 'pass')))
    raise SystemExit(0 if out['status'] == 'pass' else 1)


if __name__ == '__main__':
    os.umask(0o077)
    main()
