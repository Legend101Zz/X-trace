"""Invoke the single approved installed fixture with its same-capture owner browser extension."""
import hashlib
import json
import os
from pathlib import Path

from owner_plan import main

os.umask(0o077)
root=Path(os.environ['RUNNER_TEMP'])/'xp121'
config=dict(mode='installed',sourceSha=os.environ['PRODUCT'],sourceTree=os.environ['PRODUCT_TREE'],
    wrapperSha=os.environ['GITHUB_SHA'],runId=int(os.environ['GITHUB_RUN_ID']),attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),
    receiptId=os.urandom(32).hex(),root=str(Path(os.environ['RUNNER_TEMP'])/'xp121ui'),
    existingDriverSha256=hashlib.sha256(Path(__file__).with_name('installed.py').read_bytes()).hexdigest())
path=root/'private/owner-plan-config.json'
with path.open('x') as stream:json.dump(config,stream)
raise SystemExit(main(path,Path(__file__).with_name('installed.py')))
