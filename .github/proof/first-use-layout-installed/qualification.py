"""Authenticate the exact source run and generated assets before package admission."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

REPOSITORY = 'Legend101Zz/X-trace'
LOCK = Path(__file__).with_name('reviewed-source.json')
PREFIX = 'crates/xtrace-daemon/assets/ui/'
ASSETS = ('index.html', 'app.js', 'index.css', 'fonts/chivo-latin-400-normal.woff2',
          'fonts/chivo-latin-600-normal.woff2', 'fonts/azeret-mono-latin-400-normal.woff2', 'assets.sha256')
FIXED_PATHS = ('tools/qa/replay_scale_browser.mjs', 'tools/qa/replay-scale.md',
               'crates/xtrace-cli/tests/replay_scale.rs', 'packaging/install.sh', 'packaging/test/install_test.sh')
MAX_ZIP = 30 * 1024 * 1024
MAX_ASSET = 20 * 1024 * 1024


def need(ok):
    if not ok:
        raise RuntimeError('First-use source qualification predicate failed')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def commit(value):
    need(re.fullmatch(r'[a-f0-9]{40}', value))
    return value


def git_reader(repo):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
    return git


def reviewed():
    value = json.loads(LOCK.read_bytes())
    need(set(value) == {'parent','source','tree','wrapper','workflowDigest','branch','path','artifact','sourceChanges','assetChanges'})
    for key in ('parent','source','tree','wrapper'):
        commit(value[key])
    need(value['parent'] == '10e83a00e052d7349eb3daa7e1d18e75f23696e0')
    need(value['tree'] == '976b3ce4780ac5044d79c4fa3bd8d4e512ff7db0')
    need(re.fullmatch(r'[a-f0-9]{64}',value['workflowDigest']))
    need(value['branch'] == 'codex/proof-first-use-layout-assets-118')
    need(value['path'] == '.github/workflows/first-use-layout-assets.yml')
    need(value['artifact'] == 'first-use-layout-generated-assets')
    need(type(value['sourceChanges']) is list and 0 < len(value['sourceChanges']) <= 8)
    need(value['sourceChanges'] == sorted(set(value['sourceChanges']), key=lambda row: row[2:]))
    need(all(re.fullmatch(r'[AM]\tweb/app/(?:src|scripts)/[a-zA-Z0-9/_.-]+', row)
             and '..' not in row for row in value['sourceChanges']))
    need(type(value['assetChanges']) is list and value['assetChanges'] == sorted(set(value['assetChanges'])))
    need('assets.sha256' in value['assetChanges'] and set(value['assetChanges']) <= set(ASSETS))
    return value


def git_identity(git, source, generated, wrapper, workflow_digest):
    lock = reviewed()
    need((source, wrapper, workflow_digest) == (lock['source'], lock['wrapper'], lock['workflowDigest']))
    for value in (source, generated, wrapper):
        commit(value)
        need(git('cat-file','-t',value) == b'commit\n')
    parents = lambda value: git('show','-s','--format=%P',value).decode().strip()
    need(parents(source) == lock['parent'] and parents(generated) == parents(wrapper) == source)
    need(git('rev-parse',source+'^{tree}').decode().strip() == lock['tree'])
    need(git('diff','--name-status','--no-renames',lock['parent'],source).decode().splitlines() ==
         lock['sourceChanges'])
    need(git('diff','--name-status','--no-renames',source,wrapper).decode() == 'A\t'+lock['path']+'\n')
    need(git('ls-tree',wrapper,'--',lock['path']).startswith(b'100644 blob '))
    need(sha(git('show',wrapper+':'+lock['path'])) == workflow_digest)
    for path in FIXED_PATHS:
        need(git('rev-parse',generated+':'+path) == git('rev-parse',lock['parent']+':'+path))
    for path in ('adapters/java/spring-fixture','adapters/java/gradle/verification-metadata.xml'):
        need(git('rev-parse',generated+':'+path) == git('rev-parse',lock['parent']+':'+path))
    files = git('ls-tree','-r',generated,'--',PREFIX).decode().splitlines()
    need(len(files) == len(ASSETS) and all(row.startswith('100644 blob ') for row in files))
    need({row.split('\t',1)[1] for row in files} == {PREFIX+name for name in ASSETS})
    changed = {PREFIX+name for name in ASSETS
               if git('rev-parse',source+':'+PREFIX+name) != git('rev-parse',generated+':'+PREFIX+name)}
    need(changed == {PREFIX+name for name in lock['assetChanges']})
    need(set(git('diff','--name-only','--no-renames',source,generated).decode().splitlines()) == changed)


def verify_run(run, run_id, wrapper):
    lock = reviewed()
    need(type(run_id) is int and run_id > 0 and run['id'] == run_id)
    need(run['repository']['full_name'] == run['head_repository']['full_name'] == REPOSITORY)
    need(run['head_sha'] == wrapper and run['head_branch'] == lock['branch'] and run['path'] == lock['path']
         and run['event'] == 'push' and run['run_attempt'] == 1
         and run['status'] == 'completed' and run['conclusion'] == 'success')


def select_artifact(document, run_id, wrapper):
    rows = document['artifacts']
    need(document['total_count'] == len(rows) == 1)
    row = rows[0]
    spec = (row['id'], row['size_in_bytes'], row['digest'].removeprefix('sha256:'))
    verify_artifact(row, run_id, wrapper, spec)
    return spec


def verify_artifact(row, run_id, wrapper, spec):
    artifact_id, size, digest = spec
    need(type(artifact_id) is int and artifact_id > 0 and type(size) is int and 0 < size <= MAX_ZIP)
    need(re.fullmatch(r'[a-f0-9]{64}',digest))
    need(row['id'] == artifact_id and row['name'] == reviewed()['artifact'] and row['expired'] is False
         and row['size_in_bytes'] == size and row['digest'] == 'sha256:'+digest
         and row['workflow_run']['id'] == run_id and row['workflow_run']['head_sha'] == wrapper)


def verify_archive(path, spec, git, generated):
    _, size, digest = spec
    need(path.is_file() and not path.is_symlink() and path.stat().st_size == size)
    with path.open('rb') as stream:
        need(hashlib.file_digest(stream,'sha256').hexdigest() == digest)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        need(len(entries) == len(ASSETS) and {entry.filename for entry in entries} == set(ASSETS))
        need(all(not entry.is_dir() and 0 < entry.file_size <= MAX_ASSET and entry.compress_type in (0,8)
                 and stat.S_IFMT(entry.external_attr>>16) in (0,stat.S_IFREG) for entry in entries))
        data = {name:archive.read(name) for name in ASSETS}
    need(all(data[name] == git('show',generated+':'+PREFIX+name) for name in ASSETS))
    rows = ''.join(sha(data[name])+'  '+('assets/' if name.startswith('fonts/') else '')+name+'\n'
                   for name in ASSETS[:-1]).encode()
    need(data['assets.sha256'] == rows)
    return sha(rows)


def offline_identity():
    from common import ROOT
    env = os.environ
    source, generated, wrapper = (env[key] for key in ('ASSEMBLED_SOURCE_SHA','GENERATED_PRODUCT','VERIFIED_SOURCE_WRAPPER'))
    need(env['ASSEMBLED_SOURCE_TREE'] == reviewed()['tree'] and env['PRODUCT'] == generated)
    git = git_reader(Path.cwd())
    need(git('rev-parse',generated+'^{tree}').decode().strip() == env['GENERATED_TREE'] == env['PRODUCT_TREE'])
    git_identity(git, source, generated, wrapper, env['SOURCE_WORKFLOW_SHA256'])
    expected = dict(source=generated, tree=env['GENERATED_TREE'], manifest=env['EXPECTED_UI_MANIFEST_SHA256'])
    from common import safe_read
    need(safe_read(ROOT/'private/source-admitted.json') == expected)


def api(endpoint, name, limit):
    from common import ROOT
    need(re.fullmatch(r'(?:runs/[1-9][0-9]*(?:/artifacts)?|artifacts/[1-9][0-9]*(?:/zip)?)',endpoint))
    target = ROOT/'private'/name
    with target.open('xb') as out, (ROOT/'logs'/f'{name}.stderr').open('xb') as err:
        result = subprocess.run(['gh','api','--hostname','github.com',f'repos/{REPOSITORY}/actions/{endpoint}'],
                                stdout=out,stderr=err,stdin=subprocess.DEVNULL,timeout=180,check=False,
                                env={k:v for k,v in os.environ.items() if k != 'GH_HOST'})
    need(result.returncode == 0 and 0 < target.stat().st_size <= limit)
    return target


def main():
    from common import ROOT, private_json
    env = os.environ
    generated, wrapper = env['GENERATED_PRODUCT'], env['VERIFIED_SOURCE_WRAPPER']
    git = git_reader(Path.cwd())
    git_identity(git, env['ASSEMBLED_SOURCE_SHA'], generated, wrapper, env['SOURCE_WORKFLOW_SHA256'])
    run_id = int(env['VERIFIED_SOURCE_RUN_ID'])
    cap = 65536
    run = json.loads(api(f'runs/{run_id}','source-run.json',cap).read_bytes())
    verify_run(run,run_id,wrapper)
    admission = (int(env['SOURCE_ASSETS_ARTIFACT_ID']),int(env['SOURCE_ASSETS_ARCHIVE_SIZE']),env['SOURCE_ASSETS_ARCHIVE_SHA256'])
    artifacts = json.loads(api(f'runs/{run_id}/artifacts','source-artifacts.json',cap).read_bytes())
    need(select_artifact(artifacts,run_id,wrapper) == admission)
    artifact_id = admission[0]
    verify_artifact(json.loads(api(f'artifacts/{artifact_id}','source-artifact.json',cap).read_bytes()),
                    run_id,wrapper,admission)
    archive = api(f'artifacts/{artifact_id}/zip','source-assets.zip',MAX_ZIP)
    manifest = verify_archive(archive,admission,git,generated)
    need(manifest == env['EXPECTED_UI_MANIFEST_SHA256'])
    private_json(ROOT/'private/source-admitted.json',dict(source=generated,tree=env['GENERATED_TREE'],manifest=manifest))
    offline_identity()


if __name__ == '__main__':
    os.umask(0o077)
    main()
