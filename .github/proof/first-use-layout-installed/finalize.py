"""Project finite evidence only. All package and frame digests stay private."""
import os

from common import ROOT, need, private_json, safe_read
from receipts import PACKAGE, RESULTS, WIDTHS, browser_pass, success, valid_driver, width_copied


def optional(name):
    path = ROOT/'safe'/f'{name}.json'
    return safe_read(path) if path.exists() else None


def main():
    outcomes = {name: os.environ[f'{name.upper()}_OUTCOME'] for name in ('root','qualification','package','geometry','encrypt')}
    need(outcomes['root'] == 'success' and all(value in RESULTS for value in outcomes.values()))
    raw = optional('package')
    package = None
    if raw is not None:
        need(outcomes['package'] != 'skipped')
        package = {key: raw[key] for key in ('phase','exitCode') if key in raw}
        package['phase'] = raw['stage']
        need(package['phase'] in PACKAGE and (package['exitCode'] is None or
             type(package['exitCode']) is int and -128 <= package['exitCode'] <= 255))
    driver = optional('geometry')
    need(driver is None or outcomes['geometry'] != 'skipped' and valid_driver(driver))
    encrypted = optional('encrypted')
    if encrypted is not None:
        need(set(encrypted) == {'widths'})
        encrypted = encrypted['widths']
    if encrypted is not None:
        need(type(encrypted) is list and all(type(width) is int and width in WIDTHS for width in encrypted))
        need(encrypted == sorted(set(encrypted)) and outcomes['encrypt'] != 'skipped')
    need(outcomes['package'] != 'success' or package == {'phase':'complete','exitCode':0})
    if outcomes['geometry'] == 'success':
        need(browser_pass(driver))
    need(outcomes['encrypt'] != 'success' or encrypted is not None)
    if encrypted:
        need(driver is not None and set(encrypted) <= {r['width'] for r in driver['cells'] if width_copied(r)})
    passed = success(outcomes,package,driver,encrypted)
    private_json(ROOT/'safe/verdict.json', dict(
        schema=1, releaseAcceptance=False, proof='installed-first-use-layout',
        source=os.environ['ASSEMBLED_SOURCE_SHA'], product=os.environ['PRODUCT'],
        sourceWrapper=os.environ['VERIFIED_SOURCE_WRAPPER'], sourceRun=int(os.environ['VERIFIED_SOURCE_RUN_ID']),
        outcomes=outcomes, package=package, driver=driver, encryptedWidths=encrypted, passed=passed))
    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
        stream.write('ready=true\n')
    need(passed)


if __name__ == '__main__':
    os.umask(0o077)
    main()
