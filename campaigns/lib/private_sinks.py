"""Bounded inventories and scans of admitted private campaign sinks.

Inventory paths and scanner details remain private. Callers project only fixed
class names, statuses and bounded counts. Absent, empty, unsafe, mutable or
unscannable targets cannot become a clean sink.
"""
from __future__ import annotations

import hashlib
import gzip
import io
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import sys
import time
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.qa import canary  # noqa: E402
import installed_java  # noqa: E402

MAX_FILES = 8192
MAX_BYTES = 1 << 30
MAX_FILE_BYTES = 64 << 20
STATUSES = frozenset(("passed", "failed", "missing", "empty", "unsafe-or-bound", "changed", "scan-error",
                      "canaries-unavailable", "not-produced", "unreached"))


class CompressionCoverageError(ValueError):
    """A recognized container could not be completely inspected within bounds."""


def _container(data):
    """Recognize framed streams, plus ZIPs with an executable/preamble prefix.

    This does not establish coverage of arbitrary compressed fragments embedded
    in another binary format, raw DEFLATE or dictionary-dependent encodings.
    """
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7 and int.from_bytes(data[:2], "big") % 31 == 0:
        return "zlib"
    if data[:4] == canary.ZSTD_MAGIC or (len(data) >= 4 and data[0] & 0xf0 == 0x50 and data[1:4] == b"\x2a\x4d\x18"):
        return "zstd"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08") or zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"
    return None


def _zstd_bounded(data, limit):
    """Drain an owned decoder concurrently with input; never buffer beyond limit.

    Successful exit is required, including for truncated/concatenated frames.
    The decoder's existing 60-second allowance is not extended.
    """
    executable = shutil.which("zstd")
    if executable is None:
        raise CompressionCoverageError("decoder-unavailable")
    deadline = time.monotonic() + 60
    output = bytearray()
    with subprocess.Popen([executable, "-dc", "--no-progress"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0) as child:
        try:
            with selectors.DefaultSelector() as ready:
                os.set_blocking(child.stdin.fileno(), False)
                os.set_blocking(child.stdout.fileno(), False)
                ready.register(child.stdin, selectors.EVENT_WRITE)
                ready.register(child.stdout, selectors.EVENT_READ)
                offset = 0
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CompressionCoverageError("decoder-timeout")
                    for key, _ in ready.select(remaining):
                        if key.fileobj is child.stdin:
                            try:
                                offset += os.write(child.stdin.fileno(), memoryview(data)[offset:offset + (64 << 10)])
                            except BrokenPipeError:
                                offset = len(data)
                            if offset == len(data):
                                ready.unregister(child.stdin)
                                child.stdin.close()
                        else:
                            chunk = os.read(child.stdout.fileno(), min(64 << 10, limit + 1 - len(output)))
                            if not chunk:
                                ready.unregister(child.stdout)
                            output.extend(chunk)
                            if len(output) > limit:
                                raise CompressionCoverageError("inflate-bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or child.wait(timeout=remaining) != 0:
                raise CompressionCoverageError("invalid-container")
            return bytes(output)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def _raw_hits(data, index, hits):
    for name, encoding, needle in index:
        amount = data.count(needle)
        if amount:
            key = ("sink", name, encoding)
            hits[key] = hits.get(key, 0) + amount


def _scan_container(data, index, hits, budget, depth=0):
    """Scan all decoded bytes or fail closed at the original two-layer depth.

    Expanded bytes share one MAX_INFLATE allowance per admitted file; ZIP member
    enumeration also shares the inventory entry bound. Neither can multiply
    through nesting. Raw bytes and already observed hits survive a coverage gap.
    """
    _raw_hits(data, index, hits)
    kind = _container(data)
    if kind is None:
        return
    if depth >= 2:
        raise CompressionCoverageError("depth-bound")

    def scan_inner(inner):
        if len(inner) > budget[0]:
            raise CompressionCoverageError("inflate-bound")
        budget[0] -= len(inner)
        _scan_container(inner, index, hits, budget, depth + 1)

    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                budget[1] -= len(entries)
                if budget[1] < 0:
                    raise CompressionCoverageError("member-bound")
                for entry in entries:
                    _raw_hits(entry.filename.encode(), index, hits)
                    if entry.file_size > budget[0]:
                        raise CompressionCoverageError("inflate-bound")
                    with archive.open(entry) as stream:
                        inner = stream.read(budget[0] + 1)
                    if len(inner) != entry.file_size:
                        raise CompressionCoverageError("invalid-container")
                    scan_inner(inner)
        elif kind == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                scan_inner(stream.read(budget[0] + 1))
        elif kind == "zlib":
            decoder = zlib.decompressobj()
            inner = decoder.decompress(data, budget[0] + 1)
            if len(inner) > budget[0]:
                raise CompressionCoverageError("inflate-bound")
            # An unconsumed or appended stream is not silently treated as covered.
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise CompressionCoverageError("invalid-container")
            scan_inner(inner)
        else:
            scan_inner(_zstd_bounded(data, budget[0]))
    except CompressionCoverageError:
        raise
    except (OSError, EOFError, ValueError, RuntimeError, NotImplementedError, zlib.error,
            zipfile.BadZipFile, zipfile.LargeZipFile, subprocess.SubprocessError):
        raise CompressionCoverageError("invalid-container") from None


def _scan_files(values, files):
    """Keep the shared scanner for unframed files; strictly scan containers here."""
    index, hits, ordinary, containers, gaps = canary.build_index(values), {}, [], [], []
    for path in files:
        data = path.read_bytes()
        if _container(data) is None:
            ordinary.append(path)
            continue
        containers.append((path, len(data)))
        try:
            _scan_container(data, index, hits, [canary.MAX_INFLATE, MAX_FILES])
        except CompressionCoverageError as error:
            gaps.append(dict(path=str(path.name), reason=str(error)))
        _raw_hits(path.name.encode(), index, hits)
    report = canary.run_scan(values, {"sink": ordinary}, {"sink": len(ordinary)} if ordinary else {})
    ordinary_clean = not ordinary or report.get("clean") is True
    report["scanned"][0]["present"] = bool(files)
    report["scanned"][0]["files"] += len(containers)
    report["scanned"][0]["bytes"] += sum(size for _, size in containers)
    report["hits"].extend(dict(locationClass=where, canary=name, encoding=encoding, count=amount)
                          for (where, name, encoding), amount in sorted(hits.items()))
    if gaps:
        report["uncovered"].append(dict(**{"class": "sink"}, need=len(files), have=len(files) - len(gaps)))
    report["compressionGaps"] = gaps
    report["clean"] = ordinary_clean and not report["hits"] and not report["uncovered"] and bool(files)
    return report


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def valid_canaries(values):
    return (isinstance(values, dict) and set(values) == set(canary.KINDS)
            and all(isinstance(value, str) and 12 <= len(value) <= 1024 for value in values.values())
            and len(set(values.values())) == len(values))


class AdmittedSinks:
    def __init__(self, root):
        self.root = installed_java.private_dir(root)
        info = self.root.lstat()
        self.identity = (info.st_dev, info.st_ino)

    def check_root(self):
        installed_java.private_dir(self.root)
        info = self.root.lstat()
        if (info.st_dev, info.st_ino) != self.identity:
            raise ValueError("admitted private root was replaced")

    def inventory(self, targets):
        self.check_root()
        rows, missing, empty, visited, total = {}, [], [], 0, 0
        for target in targets:
            target = Path(target).absolute()
            if not target.is_relative_to(self.root) or ".." in target.relative_to(self.root).parts:
                raise ValueError("sink escaped admitted root")
            # lstat each ancestor before traversing; never follow a symbolic directory.
            for parent in target.parents:
                if parent == self.root.parent:
                    break
                if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
                    raise ValueError("unsafe sink ancestor")
            if not target.exists() and not target.is_symlink():
                missing.append(str(target.relative_to(self.root)))
                continue
            target_count, target_bytes = len(rows), total
            queue = [target]
            while queue:
                path = queue.pop()
                visited += 1
                if visited > MAX_FILES:
                    raise ValueError("sink entry bound exceeded")
                info = path.lstat()
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError("sink is not owner-only")
                if stat.S_ISDIR(info.st_mode):
                    for child in path.iterdir():
                        queue.append(child)
                        if len(queue) > MAX_FILES:
                            raise ValueError("sink entry bound exceeded")
                elif stat.S_ISREG(info.st_mode):
                    relative = str(path.relative_to(self.root))
                    if relative in rows:
                        continue
                    total += info.st_size
                    if info.st_size > MAX_FILE_BYTES or total > MAX_BYTES or len(rows) >= MAX_FILES:
                        raise ValueError("sink byte bound exceeded")
                    rows[relative] = dict(path=relative, bytes=info.st_size, sha256=digest(path),
                                          device=info.st_dev, inode=info.st_ino, mtime=info.st_mtime_ns,
                                          ctime=info.st_ctime_ns)
                    if any(getattr(path.lstat(), field) != getattr(info, field) for field in (
                            "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid")):
                        raise ValueError("sink changed during inventory")
                else:
                    raise ValueError("sink is not a regular file or directory")
            if stat.S_ISDIR(target.lstat().st_mode) and (len(rows) == target_count or total == target_bytes):
                empty.append(str(target.relative_to(self.root)))
        return dict(files=[rows[key] for key in sorted(rows)], missing=sorted(missing), empty=sorted(empty), bytes=total)

    def scan(self, targets, values, *, optional=False):
        try:
            before = self.inventory(targets)
        except (OSError, ValueError):
            return dict(status="unsafe-or-bound", files=0, bytes=0, hitClasses=0), None
        projection = dict(files=len(before["files"]), bytes=before["bytes"], hitClasses=0)
        if before["missing"]:
            return dict(status="missing", **projection), before
        if before["empty"] or not before["files"] or not before["bytes"]:
            return dict(status="not-produced" if optional and not before["files"] else "empty", **projection), before
        if not valid_canaries(values):
            return dict(status="canaries-unavailable", **projection), before
        try:
            files = [self.root / row["path"] for row in before["files"]]
            report = _scan_files(values, files)
            path_hits = {}
            for row in before["files"]:
                canary.scan_bytes(row["path"].encode(), canary.build_index(values), path_hits, "sink-path")
            report["hits"].extend(dict(locationClass=where, canary=name, encoding=encoding, count=amount)
                                  for (where, name, encoding), amount in sorted(path_hits.items()))
            after = self.inventory(targets)
            status = ("changed" if before != after else "failed" if report["hits"] else
                      "scan-error" if report["uncovered"] or report.get("clean") is not True else "passed")
            return dict(status=status, **{**projection, "hitClasses": len(report["hits"])}), dict(
                before=before, after=after, scanner=report)
        except (OSError, ValueError, TypeError):
            return dict(status="scan-error", **projection), before
