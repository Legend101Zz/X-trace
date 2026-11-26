"""One disposable foreground PostgreSQL server. Mutating Docker operations use creation receipts."""
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path


class FixtureFailure(Exception):
    pass


def require(ok):
    if not ok:
        raise FixtureFailure('owned PostgreSQL fixture operation unavailable')


def identifier(data):
    if data is None or len(data) > 65:
        return None
    match = re.fullmatch(rb'([a-f0-9]{64})\n?', data)
    return match[1].decode('ascii') if match else None


def read_cid(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and info.st_mode & 0o022 == 0 and 0 < info.st_size <= 65)
        value = stream.read(66)
        after = os.fstat(fd)
        require((info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        result = identifier(value)
        require(result is not None)
        return result


def created_container(cid, output, success):
    returned = identifier(output) if success else None
    require(not success or returned is not None or (cid is not None and output in (None, b'')))
    require(cid is None or returned is None or cid == returned)
    return cid or returned


class OwnedPostgres:
    def __init__(self, root, env, report, save):
        self.root, self.env, self.report, self.save = root, env, report, save
        self.container = self.network = None
        self.control = root/'service-control'
        self.control.mkdir(mode=0o700)
        self.serial = 0

    def mark(self, key, value):
        self.report[key] = value
        self.save()

    def docker(self, args, timeout=45):
        self.serial += 1
        with (self.root/f'engine-{self.serial}.stderr').open('xb') as stderr:
            return subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', *args], env=self.env, stdout=subprocess.PIPE,
                                  stderr=stderr, stdin=subprocess.DEVNULL, timeout=timeout)

    def checked(self, args, timeout=45):
        result = self.docker(args, timeout)
        require(result.returncode == 0)
        return result.stdout

    def create(self, image):
        # The network has no cidfile analogue. Only successful create stdout grants ownership.
        self.mark('networkCreate', 'attempted')
        result = self.docker(['network', 'create', '--driver', 'bridge', 'xtrace-pg-' + secrets.token_hex(12)])
        self.network = identifier(result.stdout) if result.returncode == 0 else None
        require(self.network)
        self.mark('networkCreate', 'owned')
        self.mark('containerCreate', 'attempted')
        cidfile = self.root/'database.cid'
        service = Path(__file__).resolve().with_name('owned-service.pl')
        result = None
        try:
            result = self.docker(['create', '--cidfile', str(cidfile), '--network', self.network,
                                  '--publish', '127.0.0.1::5432', '--tmpfs', '/var/lib/postgresql',
                                  '--init', '--entrypoint', '/usr/bin/perl',
                                  '--mount', f'type=bind,src={service},dst=/xtrace-service.pl,readonly',
                                  '--mount', f'type=bind,src={self.control},dst=/xtrace-service-control,readonly',
                                  '-e', 'POSTGRES_USER', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=probe',
                                  image, '/xtrace-service.pl', '/usr/local/bin/docker-entrypoint.sh', 'postgres'], 180)
        finally:
            self.container = created_container(read_cid(cidfile), result.stdout if result else None,
                                               result is not None and result.returncode == 0)
            if self.container:
                self.mark('containerCreate', 'owned')
        require(result.returncode == 0 and self.container)
        self.checked(['start', self.container])
        port = self.checked(['port', self.container, '5432/tcp'])
        match = re.fullmatch(rb'127\.0\.0\.1:([1-9][0-9]{0,4})\s*', port)
        require(match and int(match[1]) <= 65535)
        self.port = int(match[1])

    def ready(self):
        # The original bounded psql predicate observes a real TCP connection and server version.
        self.checked(['exec', self.container, 'sh', '-c', """
export PGPASSWORD="$POSTGRES_PASSWORD"
deadline=$(( $(date +%s) + 45 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if psql -w -h 127.0.0.1 -U "$POSTGRES_USER" -d probe -Atq -c "select current_setting('server_version_num') = '180003'" | grep -Fxq t; then
    exit 0
  fi
  sleep 0.25
done
exit 1
"""], 55)

    def state(self):
        result = self.checked(['inspect', '--type', 'container', '--format',
                               '{{.Id}} {{.State.Status}} {{.State.ExitCode}}', self.container])
        match = re.fullmatch(self.container.encode() + rb' (created|running|exited) ([0-9]{1,3})\n?', result)
        require(match)
        return match[1].decode(), int(match[2])

    def release_container(self):
        # The in-container parent alone signals its waitable child upon this private request.
        state, _ = self.state()
        if state == 'running':
            self.mark('databaseStop', 'attempted')
            with (self.control/'stop.request').open('x') as stream:
                stream.write('stop\n')
            terminal = self.checked(['wait', self.container], timeout=30)
            require(terminal.strip() == b'0' and self.state() == ('exited', 0))
            self.mark('databaseStop', 'passed')
        elif state == 'exited':
            self.mark('databaseStop', 'unexpected-exit')
        self.mark('containerRelease', 'attempted')
        self.checked(['rm', '-v', self.container])
        require(self.checked(['container', 'ls', '-a', '--no-trunc', '--filter', 'id='+self.container,
                              '--format', '{{.ID}}']).strip() == b'')
        self.mark('containerRelease', 'passed')

    def release(self):
        # A failure retains the ID for the hosted runner; no other handle is substituted.
        try:
            if self.container:
                self.release_container()
        except (FixtureFailure, OSError, subprocess.TimeoutExpired):
            self.mark('containerRelease', 'unverified')
        if self.network:
            self.mark('networkRelease', 'attempted')
            try:
                self.checked(['network', 'rm', self.network])
                require(self.checked(['network', 'ls', '--no-trunc', '--filter', 'id='+self.network,
                                      '--format', '{{.ID}}']).strip() == b'')
                self.mark('networkRelease', 'passed')
            except (FixtureFailure, OSError, subprocess.TimeoutExpired):
                self.mark('networkRelease', 'unverified')
