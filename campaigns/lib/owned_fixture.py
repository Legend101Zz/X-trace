"""Own only creation receipts and direct child handles from this campaign invocation."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Callable

IDENTIFIER = re.compile(r"[0-9a-f]{64}")


class CleanupFailure(RuntimeError):
    """Cleanup failed; retained handles may be released by a later explicit cleanup."""

    def __init__(self, failures, owner=None):
        super().__init__("owned campaign cleanup failed")
        self.failures = tuple(failures)
        self.owner = owner


def cleanup_all(*operations):
    """Attempt every owned release, retaining all failures instead of skipping later handles."""
    failures = []
    for operation in operations:
        try:
            operation()
        except Exception as error:
            failures.append(error)
    if failures:
        raise CleanupFailure(failures)


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError("campaign creation returned no valid identity")
    return value.strip()


def cid_identity(path):
    """A fresh private --cidfile can identify creation even when Docker run failed."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or info.st_size > 128):
            raise ValueError("campaign creation receipt is not a regular private input")
        data = os.read(fd, 129)
        if len(data) != info.st_size:
            raise ValueError("campaign creation receipt changed during admission")
    finally:
        os.close(fd)
    # Docker can leave an empty cidfile when creation itself failed.
    return identifier(data.decode("ascii")) if data else None


@dataclass
class DockerFixture:
    """Track successful IDs; a name or prefix alone never authorizes removal."""
    docker: Callable
    containers: list[str] = field(default_factory=list)
    network: str | None = None

    def create_network(self, name):
        if self.network is not None or not name.startswith("xtrace-camp-"):
            raise ValueError("campaign network creation is not fresh")
        result = self.docker("network", "create", name)
        if result.returncode != 0:
            raise RuntimeError("campaign network creation failed")
        self.network = identifier(result.stdout)

    @contextmanager
    def container_run(self, args):
        """Keep the original run contract, adding only an invocation-private cidfile."""
        if (not args or args[0] != "run" or "--cidfile" in args or args.count("--name") != 1
                or args.index("--name") + 1 == len(args)
                or not args[args.index("--name") + 1].startswith("xtrace-camp-")):
            raise ValueError("campaign run requires one guarded name")
        with tempfile.TemporaryDirectory(prefix="xtrace-cid-") as folder:
            path = Path(folder) / "container.id"
            result = [None]
            try:
                yield [args[0], "--cidfile", str(path), *args[1:]], result
            finally:
                # Never inspect/delete a constructed name after ambiguous creation.
                observed = cid_identity(path)
                if result[0] is not None and result[0].returncode == 0:
                    # Only detached stdout is a Docker creation receipt; attached output belongs to the app.
                    output = result[0].stdout if "-d" in args[:args.index("--name")] else None
                    returned = identifier(output) if isinstance(output, str) and output.strip() else None
                    if observed is not None and returned is not None and observed != returned:
                        raise ValueError("campaign creation receipts disagree")
                    observed = observed or returned
                    if observed is None:
                        raise ValueError("campaign run completed without a creation identity")
                if observed is not None:
                    self.containers.append(observed)

    def run_container(self, args):
        with self.container_run(args) as (argv, result):
            result[0] = self.docker(*argv)
        if result[0].returncode != 0:
            raise RuntimeError("campaign container creation failed")
        return self.containers[-1]  # the synchronous successful run appended its verified ID

    def cleanup(self):
        failures = []
        for identity in reversed(self.containers.copy()):
            try:
                result = self.docker("rm", "-f", "-v", identity, check=False)
                absent = re.fullmatch(r"(?:Error response from daemon: |Error: )No such container: " + re.escape(identity),
                                      (result.stderr or "").strip())
                if result.returncode != 0 and not absent:
                    raise RuntimeError("owned container removal failed")
            except Exception as error:
                failures.append(error)
            else:
                self.containers.remove(identity)
        if self.network is not None:
            try:
                result = self.docker("network", "rm", self.network, check=False)
                absent = re.fullmatch(r"Error response from daemon: network " + re.escape(self.network) + r" not found",
                                      (result.stderr or "").strip())
                if result.returncode != 0 and not absent:
                    raise RuntimeError("owned network removal failed")
            except Exception as error:
                failures.append(error)
            else:
                self.network = None
        if failures:
            raise CleanupFailure(failures, self)


def stop_child(proc, wait):
    """Preserve the full graceful wait, signal only this direct child, and reap it.

    Forced cleanup is still a failed shutdown, including when the child is reaped.
    Its descendants are not inspected or signalled; their state remains unobserved.
    """
    if proc.poll() is not None:
        proc.wait(timeout=0)
        return
    try:
        try:
            proc.terminate()
        except ProcessLookupError:
            if proc.poll() is None:
                raise
            proc.wait(timeout=0)
            return
        proc.wait(timeout=wait)
    except subprocess.TimeoutExpired as timeout:
        if proc.poll() is None:
            proc.kill()
        try:
            # A separate bounded final reap cannot make the expired graceful wait pass.
            proc.wait(timeout=5)
        except Exception as error:
            raise CleanupFailure((timeout, error), proc) from timeout
        raise CleanupFailure((timeout,), proc) from timeout
