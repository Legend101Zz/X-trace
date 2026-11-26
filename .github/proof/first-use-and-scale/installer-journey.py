"""Run the actual install/upgrade/uninstall journey on this same built archive."""
import os
import re
import subprocess

from common import ROOT, REPO, binding, identity, load_package, need, private_json
from pathlib import Path


def main():
    identity()
    shared = load_package()
    report = dict(status='incomplete', passed=None, **binding(shared))
    destination = ROOT / 'safe/installer-journey.json'
    private_json(destination, report)
    log = ROOT / 'logs/installer-journey.stdout'
    env = dict(os.environ, XTRACE_TEST_PRIVATE_SCRATCH=str(ROOT / 'tmp'))
    with log.open('xb') as out, (ROOT / 'logs/installer-journey.stderr').open('xb') as err:
        proc = subprocess.run(['sh', 'packaging/test/install_test.sh', str(Path(shared['archive']).parent)],
                              cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err, check=False)
    need(0 < log.stat().st_size <= 1 << 20)
    lines = log.read_bytes().splitlines()
    passed = [int(match[1]) for line in lines if (match := re.fullmatch(rb'ok ([0-9]{1,2}) - .+', line))]
    need(passed == list(range(1, len(passed) + 1)) and len(passed) <= 32)
    report['passed'] = len(passed)
    private_json(destination, report)
    need(proc.returncode == 0 and len(passed) == 32 and lines[-1] == b'all 32 checks passed')
    report['status'] = 'pass'
    private_json(destination, report)


if __name__ == '__main__':
    os.umask(0o077)
    main()
