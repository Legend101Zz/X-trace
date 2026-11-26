"""Use the same freshly installed CLI on an actual verified-empty project."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import traceback

from campaigns.lib import xinstr
from common import REPO, ROOT, identity, load_package, need, private_json, safe_read, served_assets
from owned import ENV, OwnedProcess, list_args
from receipts import CHECKS, PHASES, WIDTHS, browser_pass, valid_cell

SCRIPTS = Path(__file__).parent
OUT = ROOT / 'safe/geometry.json'
REPORT = dict(phase='identity', cells=[], packageReverified=False)


def checkpoint(phase):
    REPORT['phase'] = phase
    private_json(OUT, REPORT)


def command(name, args):
    with (ROOT/'logs'/f'{name}.stdout').open('xb') as out, (ROOT/'logs'/f'{name}.stderr').open('xb') as err:
        subprocess.run(args, cwd=REPO, env=ENV, stdout=out, stderr=err, check=True, timeout=30)


def browser(ready, width):
    context = ROOT / 'private' / f'cell-{width}-input.json'
    result = ROOT / 'private' / f'cell-{width}-output.json'
    receipt = secrets.token_hex(32)
    provenance = dict(width=width, receipt=receipt, source=os.environ['PRODUCT'])
    private_json(context, dict(url=ready['url'], result=str(result), shots=str(ROOT/'shots'), **provenance))
    status = None
    with (ROOT/'logs'/f'cell-{width}.stdout').open('xb') as out, (ROOT/'logs'/f'cell-{width}.stderr').open('xb') as err:
        try:
            status = subprocess.run(['node','--input-type=module','-',str(context)], cwd=REPO/'web/app', env=ENV,
                                    input=(SCRIPTS/'geometry-browser.mjs').read_bytes(), stdout=out, stderr=err,
                                    check=False, timeout=120).returncode
        except subprocess.TimeoutExpired:
            pass
    if not result.exists():
        need(status != 0)
        return None
    observed = safe_read(result)
    need({key: observed.pop(key) for key in provenance} == provenance)
    need(observed['phase'] in PHASES)
    checks = [key for key in CHECKS if observed.get(key) is True]
    need(set(observed) == {'phase', *checks})
    return dict(phase=observed['phase'], checks=checks, processPassed=status == 0)


def scenario(cli, project, width, package):
    row = dict(width=width, browser=None, servedBefore=False, servedAfter=False, liveTermRequestAndExitObserved=False)
    REPORT['cells'].append(row)
    checkpoint('cells')
    try:
        with OwnedProcess(f'empty-viewer-{width}', [str(cli),'open','--project-dir',str(project),'--viewer','--no-browser']) as viewer:
            ready = viewer.ready(xinstr.parse_readiness, 60)
            served_assets(ready['origin'], package['assetDigests'])
            row['servedBefore'] = True
            checkpoint('cells')
            observation = browser(ready, width)
            need(valid_cell(dict(row, browser=observation)))
            row['browser'] = observation
            checkpoint('cells')
            served_assets(ready['origin'], package['assetDigests'])
            row['servedAfter'] = True
            checkpoint('cells')
            viewer.stop(require_running=True)
        # This observes liveness, successful direct TERM request, and accepted exit.
        row['liveTermRequestAndExitObserved'] = True
        checkpoint('cells')
    except Exception:
        with (ROOT/'logs'/f'width-{width}-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)


def run():
    identity()
    package = load_package()
    cli = Path(package['prefix'])/'bin/xtrace'
    project = ROOT/'empty-project'
    project.mkdir(mode=0o700)
    checkpoint('init')
    command('init', [str(cli),'init','--project-dir',str(project)])
    command('verify-empty', list_args(cli,project))
    listing = ROOT/'logs/verify-empty.stdout'
    need(0 < listing.stat().st_size <= 65536 and json.loads(listing.read_bytes())['recordings'] == [])
    for width in WIDTHS:
        scenario(cli, project, width, package)
    checkpoint('reverify')
    need(load_package() == package)
    REPORT['packageReverified'] = True
    checkpoint('complete')
    need(browser_pass(REPORT))


if __name__ == '__main__':
    os.umask(0o077)
    checkpoint('identity')
    try:
        run()
    except Exception:
        with (ROOT/'logs/geometry-exception.stderr').open('x') as stream:
            traceback.print_exc(file=stream)
        raise SystemExit(1)
