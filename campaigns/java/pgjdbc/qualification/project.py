"""Publish only closed enums, bounded counts, and exact CI source bindings."""
import json
import os
from pathlib import Path
import re
import sys


STAGES = {
    'networkCreate': ('attempted', 'owned'), 'containerCreate': ('attempted', 'owned'),
    'databaseReady': ('attempted', 'passed'), 'init': ('attempted', 'passed'),
    'springReady': ('attempted', 'passed'), 'workload': ('attempted', 'passed'),
    'launcherStop': ('attempted', 'passed', 'recovery'), 'readback': ('attempted', 'passed'),
    'privacy': ('attempted', 'passed', 'partial', 'failed'),
    'databaseStop': ('attempted', 'passed', 'unexpected-exit'),
    'containerRelease': ('attempted', 'passed', 'unverified'),
    'networkRelease': ('attempted', 'passed', 'unverified'),
}
LIMITS = {'responses': 3, 'checkedRecordings': 3, 'checkedJdbcStarts': 8, 'checkedJdbcEnds': 8,
          'checkedJdbcFailures': 1, 'privacyFiles': 1000000, 'privacyFilesMatched': 1000000}
STEPS = ('source', 'fixtureTests', 'buildInstall', 'javaPrerequisites', 'servletPrerequisites', 'pgjdbc')


def require(value):
    if not value:
        raise ValueError('unverified report')


def base(env):
    shas = {key: env[name] for key, name in [('product', 'PRODUCT'), ('fixture', 'FIXTURE'),
                                             ('wrapper', 'GITHUB_SHA')]}
    require(all(re.fullmatch('[a-f0-9]{40}', sha) for sha in shas.values()))
    run, attempt = env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']
    require(re.fullmatch('[1-9][0-9]{0,19}', run) and attempt == '1')
    return dict(schemaVersion=1, kind='installed-pgjdbc-ordinary', releaseAcceptance=False,
                run=int(run), attempt=1, **shas)


def project(raw, outcomes, env):
    out = base(env)
    require(len(outcomes) == len(STEPS) and all(stage in ('success','failure','cancelled','skipped')
                                                for stage in outcomes))
    steps = dict(zip(STEPS, outcomes))
    # A missing receipt after the step started leaves its internal stages unknown.
    initial_stage = 'unreached' if steps['pgjdbc'] == 'skipped' else 'unavailable'
    fields = dict.fromkeys(STAGES, initial_stage)
    fields.update({key: None for key in LIMITS}, status='incomplete')
    if raw is not None:
        require(set(raw) == set(out) | set(fields))
        require(all(type(raw[k]) is type(v) and raw[k] == v for k,v in out.items()))
        for key, options in STAGES.items():
            require(raw[key] in ('unreached', *options))
        for key, limit in LIMITS.items():
            n = raw[key]
            require(n is None or type(n) is int and 0 <= n <= limit)
        require(raw['status'] in ('incomplete','passed'))
        fields = {k: raw[k] for k in fields}
        require(steps['pgjdbc'] != 'skipped')
        require(steps['pgjdbc'] != 'success' or fields['status'] == 'passed')
        for stage, predecessor, required in (
                ('containerCreate','networkCreate','owned'), ('databaseReady','containerCreate','owned'),
                ('init','databaseReady','passed'), ('springReady','init','passed'),
                ('workload','springReady','passed'), ('readback','launcherStop','passed'),
                ('containerRelease','containerCreate','owned'), ('databaseStop','containerCreate','owned'),
                ('networkRelease','networkCreate','owned')):
            require(fields[stage] == 'unreached' or fields[predecessor] == required)
        require((fields['responses'] is None) == (fields['workload'] == 'unreached'))
        require(fields['workload'] != 'passed' or fields['responses'] == 3)
        require(fields['launcherStop'] != 'passed' or fields['workload'] == 'passed')
        totals = tuple(fields[n] for n in ('checkedRecordings','checkedJdbcStarts','checkedJdbcEnds',
                                           'checkedJdbcFailures'))
        possible = {(0,0,0,0), (1,0,0,0), (1,6,6,0), (1,2,2,1), (2,6,6,0),
                    (2,2,2,1), (2,8,8,1), (3,8,8,1)}
        require(totals == (None,)*4 or fields['readback'] != 'unreached' and totals in possible)
        require(fields['readback'] != 'passed' or totals == (3,8,8,1))
        files, matches = fields['privacyFiles'], fields['privacyFilesMatched']
        require((files is None) == (matches is None) and (files is None or matches <= files))
        require(fields['privacy'] != 'passed' or (fields['readback'] == 'passed' and
                files is not None and files >= 13 and matches == 0))
        require(matches in (None,0) or fields['privacy'] == 'failed')
        if fields['status'] == 'passed':
            require(all(fields[k] == ('owned' if k.endswith('Create') else 'passed') for k in STAGES))
            require(all(fields[k] == n for k,n in LIMITS.items() if not k.startswith('privacy')))
            require(fields['privacyFiles'] is not None and fields['privacyFiles'] >= 13
                    and fields['privacyFilesMatched'] == 0)
    else:
        require(steps['pgjdbc'] != 'success')
    return dict(**out, **fields, jobSteps=steps, receipt='observed' if raw is not None else 'unavailable',
                verdict='passed' if fields['status'] == 'passed' and
                all(o == 'success' for o in outcomes) else 'incomplete')


def main():
    source, output = map(Path, sys.argv[1:3])
    raw = None
    if source.exists():
        require(source.stat().st_size <= 16384)
        raw = json.loads(source.read_bytes())
    projected = project(raw, sys.argv[3:], os.environ)
    with output.open('x') as stream:
        json.dump(projected, stream, separators=(',', ':'))
        stream.write('\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError):
        raise SystemExit('pgjdbc bounded projection unavailable') from None
