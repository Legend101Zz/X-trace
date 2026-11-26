"""Finite evidence shapes, shared between hosted projection and verifier."""
WIDTHS = (320, 1024, 1440)
PHASES = ('bootstrap', 'copy', 'frame', 'layout', 'tour-return', 'traffic', 'complete')
CHECKS = ('copy', 'frame', 'layout', 'tourReturn', 'traffic')
DRIVER = ('identity', 'init', 'cells', 'reverify', 'complete')
PACKAGE = ('identity', 'package', 'verify-dist', 'verify-archive', 'extract', 'install',
           'verify-install', 'browser-dependencies', 'chromium', 'clean-source', 'complete')
RESULTS = ('success', 'failure', 'skipped', 'cancelled', 'timed_out')
STEPS = {
    'root': 'Verify all pins and admit fresh private runner root',
    'qualification': 'Require exact contracts and source runs, authenticated generated files and direct child',
    'package': 'Build and independently verify one archive and fresh official install',
    'geometry': 'Observe installed empty-project layout and native controls',
    'encrypt': 'Encrypt only the original native empty-project frames',
    'finalize': 'Reconcile bounded installed first-use evidence',
    'boundedUpload': 'Upload the bounded first-use verdict',
    'visualUpload': 'Upload only encrypted first-use viewport originals',
}
BRANCH = 'codex/proof-first-use-layout-installed-118'
PATH = '.github/workflows/first-use-layout-installed.yml'
BOUNDED = 'first-use-layout-installed-bounded'
VISUAL = 'first-use-layout-installed-native-encrypted'


def valid_cell(cell):
    if type(cell) is not dict or set(cell) != {'width','browser','servedBefore','servedAfter','liveTermRequestAndExitObserved'}:
        return False
    width = cell['width']
    lifecycle = [cell[key] for key in ('servedBefore','servedAfter','liveTermRequestAndExitObserved')]
    if type(width) is not int or width not in WIDTHS or not all(type(flag) is bool for flag in lifecycle):
        return False
    if (lifecycle[1] and not lifecycle[0]) or (lifecycle[2] and not lifecycle[1]):
        return False
    row = cell['browser']
    if row is None:
        return True
    if not lifecycle[0] or type(row) is not dict or set(row) != {'phase','checks','processPassed'}:
        return False
    phase, checks, passed = row['phase'], row['checks'], row['processPassed']
    if phase not in PHASES or type(checks) is not list or type(passed) is not bool:
        return False
    allowed = list(CHECKS[:max(0,PHASES.index(phase)-1)])
    if width != 1440 and 'tourReturn' in allowed:
        allowed.remove('tourReturn')
    return checks == allowed and (not passed or phase == 'complete')


def width_copied(cell):
    return cell['browser'] is not None and 'copy' in cell['browser']['checks']


def browser_pass(driver):
    return (driver is not None and driver['phase'] == 'complete' and driver['packageReverified']
            and [row['width'] for row in driver['cells']] == list(WIDTHS)
            and all(row['servedBefore'] and row['servedAfter'] and row['liveTermRequestAndExitObserved']
                    and row['browser'] and row['browser']['processPassed'] for row in driver['cells']))


def valid_driver(driver):
    if type(driver) is not dict or set(driver) != {'phase','cells','packageReverified'}:
        return False
    phase, cells, package = driver['phase'], driver['cells'], driver['packageReverified']
    return (phase in DRIVER and type(cells) is list and len(cells) <= 3 and all(valid_cell(cell) for cell in cells)
            and [cell['width'] for cell in cells] == list(WIDTHS[:len(cells)])
            and type(package) is bool and package == (phase == 'complete')
            and (not cells or phase in ('cells','reverify','complete'))
            and (phase not in ('reverify','complete') or len(cells) == 3))


def success(outcomes, package, driver, encrypted):
    return (all(outcomes[step] == 'success' for step in ('root','qualification','package','geometry','encrypt'))
            and package == {'phase':'complete','exitCode':0}
            and browser_pass(driver) and encrypted == list(WIDTHS))
