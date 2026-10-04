"""Fail-closed filesystem admission for private release-runner roots.

This module deliberately performs only read-only checks until an existing
immediate parent has passed policy. It is a cooperative local-host boundary,
not protection from a privileged remount or malicious process running as the
same UID.
"""

from __future__ import annotations

import json
import math
import os
import pathlib
import plistlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable


UTILITY_TIMEOUT_SECONDS = 5.0
UTILITY_CLEANUP_SECONDS = 1.0
UTILITY_OUTPUT_LIMIT = 65536
MOUNTINFO_LIMIT = 1024 * 1024
LINUX_LOCAL_FILESYSTEMS = frozenset({"ext4", "xfs", "btrfs"})
_MAC_DF_LINE = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+%)\s+(.+)$")
_MAC_MODE = re.compile(r"^d[rwxstST-]{9}(?:\+@|@\+|[+@.])?$")
_MAC_FILE_MODE = re.compile(r"^-[rwxstST-]{9}(?:\+@|@\+|[+@.])?$")
_MAC_ACE = re.compile(r"^(?: {1,2})?(\d{1,2}): (user|group):([A-Za-z0-9_.$-]{1,128}) (allow|deny) ([a-z_,]+)(?: \(inherited\))?$")
_MOUNT_ESCAPE = re.compile(r"\\(040|011|012|134)")
_MAC_RIGHTS = frozenset({
    "read", "write", "execute", "append", "delete", "list", "search",
    "add_file", "add_subdirectory", "delete_child", "readattr", "writeattr",
    "readextattr", "writeextattr", "readsecurity", "writesecurity", "chown",
    "read_data", "write_data", "append_data",
})
# `chflags(1)` documents BSD `hidden` as hiding an item from GUI clients. This
# visibility flag does not change access-control rules, so admission can accept
# it while continuing to enforce the deny-only ACL checks below.
_MAC_SAFE_FLAGS = frozenset({"sunlnk", "restricted", "hidden"})


class AdmissionError(RuntimeError):
    """The selected directory cannot be proven suitable for private writes."""


def _fail() -> AdmissionError:
    return AdmissionError("private cache admission failed")


def _bounded_utility(argv: list[str]) -> tuple[bytes, bytes]:
    """Run one fixed system utility with bounded output, time, and process group."""
    if not argv or not os.path.isabs(argv[0]) or any("\x00" in item for item in argv):
        raise _fail()
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        selector.close()
        raise _fail() from None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + UTILITY_TIMEOUT_SECONDS
    pending: BaseException | None = None
    success = False
    process_reaped = False
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                raise _fail()
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _fail()
            for key, _events in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if sum(len(value) for value in output.values()) > UTILITY_OUTPUT_LIMIT:
                    raise _fail()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _fail()
        return_code = process.wait(timeout=remaining)
        process_reaped = True
        if return_code != 0:
            raise _fail()
        success = True
    except BaseException as exc:
        pending = exc
    finally:
        cleanup_deadline = time.monotonic() + UTILITY_CLEANUP_SECONDS
        cleanup_ok = True
        if not process_reaped:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_ok = False
            try:
                process.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
            except (OSError, subprocess.SubprocessError):
                cleanup_ok = False
        if process.poll() is None:
            cleanup_ok = False
        try:
            selector.close()
        except OSError:
            cleanup_ok = False
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    cleanup_ok = False
        if not cleanup_ok:
            pending = _fail()
    if pending is not None:
        if isinstance(pending, KeyboardInterrupt):
            raise pending
        raise _fail() from None
    if not success:
        raise _fail()
    return bytes(output["stdout"]), bytes(output["stderr"])


def _reject_control_path(path: pathlib.Path) -> None:
    value = os.fspath(path)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise _fail()


def _absolute_path(path: os.PathLike[str] | str) -> pathlib.Path:
    raw = os.path.expanduser(os.fspath(path))
    _reject_control_path(pathlib.Path(raw))
    if ".." in pathlib.PurePath(raw).parts:
        raise _fail()
    return pathlib.Path(os.path.abspath(raw))


def _parse_macos_acl(output: bytes, path: pathlib.Path, *, directory: bool = True) -> None:
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        raise _fail() from None
    if not lines or len(lines) > 65:
        raise _fail()
    first = lines[0].split(maxsplit=9)
    mode_pattern = _MAC_MODE if directory else _MAC_FILE_MODE
    if (len(first) != 10 or not mode_pattern.fullmatch(first[0])
            or not first[1].isdigit() or not first[5].isdigit()
            or not re.fullmatch(r"[A-Za-z0-9_.$-]{1,128}", first[2])
            or not re.fullmatch(r"[A-Za-z0-9_.$-]{1,128}", first[3])
            or (first[4] != "-" and (not first[4] or any(flag not in _MAC_SAFE_FLAGS for flag in first[4].split(","))
                                    or len(first[4].split(",")) != len(set(first[4].split(",")))) )
            or not re.fullmatch(r"[A-Za-z]{3}", first[6])
            or not first[7].isdigit() or not re.fullmatch(r"(?:\d{2}:\d{2}|\d{4})", first[8])):
        raise _fail()
    if first[9] != os.fspath(path):
        raise _fail()
    acl_lines = lines[1:]
    has_acl_marker = "+" in first[0] or "@" in first[0]
    if ("+" in first[0] and not acl_lines) or (acl_lines and not has_acl_marker):
        raise _fail()
    for expected_index, line in enumerate(acl_lines):
        match = _MAC_ACE.fullmatch(line)
        if match is None or int(match.group(1)) != expected_index:
            raise _fail()
        rights = match.group(5).split(",")
        if not rights or len(set(rights)) != len(rights) or any(right not in _MAC_RIGHTS for right in rights):
            raise _fail()
        if match.group(4) == "allow":
            raise _fail()


def _linux_acl_check(fd: int) -> None:
    try:
        attributes = os.listxattr(fd)
    except (AttributeError, OSError, TypeError):
        raise _fail() from None
    if any(name in {"system.posix_acl_access", "system.posix_acl_default"} for name in attributes):
        raise _fail()


def _decode_mount_path(value: str) -> str:
    if re.search(r"\\(?!040|011|012|134)", value):
        raise _fail()
    return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _linux_filesystem(path: pathlib.Path, info: os.stat_result) -> str:
    fd: int | None = None
    try:
        fd = os.open("/proc/self/mountinfo", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        chunks = bytearray()
        while len(chunks) <= MOUNTINFO_LIMIT:
            chunk = os.read(fd, min(65536, MOUNTINFO_LIMIT + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
    except OSError:
        raise _fail() from None
    finally:
        if fd is not None:
            os.close(fd)
    if len(raw) > MOUNTINFO_LIMIT:
        raise _fail()
    return _linux_filesystem_from_mountinfo(raw, path, info)


def _linux_filesystem_from_mountinfo(raw: bytes, path: pathlib.Path, info: os.stat_result) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _fail() from None
    major, minor = os.major(info.st_dev), os.minor(info.st_dev)
    absolute = os.fspath(path)
    matches: list[tuple[int, str]] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            dev_fields = fields[2].split(":", maxsplit=1)
            mountpoint = _decode_mount_path(fields[4])
            filesystem = fields[separator + 1]
            if len(dev_fields) != 2 or not all(value.isdigit() for value in dev_fields):
                raise ValueError
            if (int(dev_fields[0]), int(dev_fields[1])) != (major, minor):
                continue
            if os.path.commonpath((absolute, mountpoint)) == mountpoint:
                matches.append((len(mountpoint), filesystem))
        except (ValueError, IndexError, OSError):
            raise _fail() from None
    if not matches:
        raise _fail()
    filesystem = max(matches, key=lambda item: item[0])[1]
    if filesystem not in LINUX_LOCAL_FILESYSTEMS:
        raise _fail()
    return filesystem


def _macos_mount(path: pathlib.Path, fd: int, info: os.stat_result) -> None:
    before_path = path.stat(follow_symlinks=False)
    before_fd = os.fstat(fd)
    if _object_signature(before_path) != _object_signature(info):
        raise _fail()
    try:
        df_output, _ = _bounded_utility(["/bin/df", "-P", os.fspath(path)])
        df_text = df_output.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, AdmissionError):
        raise _fail() from None
    lines = df_text.splitlines()
    if len(lines) != 2:
        raise _fail()
    match = _MAC_DF_LINE.fullmatch(lines[1])
    if match is None:
        raise _fail()
    device = match.group(1)
    mountpoint = pathlib.Path(match.group(6))
    if not mountpoint.is_absolute():
        raise _fail()
    try:
        mount_before = mountpoint.stat(follow_symlinks=False)
        if not stat.S_ISDIR(mount_before.st_mode) or mount_before.st_dev != info.st_dev:
            raise _fail()
        plist_output, _ = _bounded_utility(["/usr/sbin/diskutil", "info", "-plist", os.fspath(mountpoint)])
        data = plistlib.loads(plist_output)
        if not isinstance(data, dict):
            raise _fail()
        reported_mount = data.get("MountPoint")
        reported_device = data.get("DeviceNode")
        filesystem = data.get("FilesystemType")
        if (reported_mount != os.fspath(mountpoint) or reported_device != device
                or not isinstance(filesystem, str) or filesystem.casefold() != "apfs"
                or data.get("GlobalPermissionsEnabled") is not True):
            raise _fail()
        mount_after = mountpoint.stat(follow_symlinks=False)
        after_path = path.stat(follow_symlinks=False)
        after_fd = os.fstat(fd)
    except Exception:
        raise _fail() from None
    if (_object_signature(mount_before) != _object_signature(mount_after)
            or mount_before.st_dev != info.st_dev):
        raise _fail()
    if (_object_signature(before_fd) != _object_signature(info)
            or _object_signature(after_fd) != _object_signature(info)
            or _object_signature(after_path) != _object_signature(info)):
        raise _fail()


def _object_signature(info: os.stat_result) -> tuple[int, ...]:
    identity = (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        # Directory contents can change during bounded metadata probes. Keep
        # identity, ownership, and the complete mode bound; entry counts and
        # encoded size remain checked by operations whose contract is emptiness.
        return identity
    return (*identity, info.st_nlink, info.st_size)


def _directory_entry_signature(info: os.stat_result) -> tuple[int, int]:
    return info.st_nlink, info.st_size


def _bounded_json_shape(fd: int, maximum_bytes: int) -> None:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(fd, min(4096, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        raise _fail() from None
    _check_json_shape_bytes(bytes(raw), maximum_bytes)


def _check_json_shape_bytes(raw: bytes, maximum_bytes: int) -> None:
    if len(raw) > maximum_bytes:
        raise _fail()
    depth = 0
    commas = 0
    quoted = False
    escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                quoted = False
            continue
        if byte == ord('"'):
            quoted = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            if depth > 8:
                raise _fail()
        elif byte in (ord("}"), ord("]")):
            depth -= 1
            if depth < 0:
                raise _fail()
        elif byte == ord(","):
            commas += 1
            if commas > 512:
                raise _fail()
    if quoted or depth != 0:
        raise _fail()


def _bounded_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > 64:
        raise _fail()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or len(key) > 128 or key in result:
            raise _fail()
        result[key] = value
    return result


def _bounded_json_value(value: Any) -> bool:
    remaining = [512]

    def inspect(item: Any, depth: int) -> bool:
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 8:
            return False
        if item is None or isinstance(item, (bool, int)):
            return True
        if isinstance(item, float):
            return math.isfinite(item)
        if isinstance(item, str):
            return len(item) <= 8192
        if isinstance(item, list):
            return len(item) <= 128 and all(inspect(child, depth + 1) for child in item)
        if isinstance(item, dict):
            return len(item) <= 64 and all(
                isinstance(key, str) and len(key) <= 128 and inspect(child, depth + 1)
                for key, child in item.items()
            )
        return False

    return inspect(value, 0)


def _loads_bounded_private_json(data: bytes) -> dict[str, Any]:
    def reject_constant(_value: str) -> Any:
        raise _fail()

    try:
        value = json.loads(
            data, object_pairs_hook=_bounded_json_object,
            parse_constant=reject_constant,
        )
    except (ValueError, TypeError):
        raise _fail() from None
    if not isinstance(value, dict) or not _bounded_json_value(value):
        raise _fail()
    return value


def _mount_check(path: pathlib.Path, fd: int, info: os.stat_result) -> None:
    flags = os.fstatvfs(fd).f_flag
    if flags & getattr(os, "ST_RDONLY", 1):
        raise _fail()
    if sys.platform == "darwin":
        _macos_mount(path, fd, info)
    elif sys.platform.startswith("linux"):
        _linux_filesystem(path, info)
    else:
        raise _fail()


def _acl_check(path: pathlib.Path, fd: int) -> None:
    if sys.platform == "darwin":
        try:
            info = os.fstat(fd)
        except OSError:
            raise _fail() from None
        if stat.S_ISDIR(info.st_mode):
            is_directory = True
        elif stat.S_ISREG(info.st_mode):
            is_directory = False
        else:
            raise _fail()
        try:
            output, _ = _bounded_utility(["/bin/ls", "-ldeO", os.fspath(path)])
        except AdmissionError:
            raise _fail() from None
        _parse_macos_acl(output, path, directory=is_directory)
    elif sys.platform.startswith("linux"):
        _linux_acl_check(fd)
    else:
        raise _fail()


def _open_validated_directory(
    path: os.PathLike[str] | str,
    *,
    private_leaf: bool,
    current_uid: int | None = None,
    acl_check: Callable[[pathlib.Path, int], None] | None = None,
    mount_check: Callable[[pathlib.Path, int, os.stat_result], None] | None = None,
) -> tuple[int, tuple[int, int]]:
    """Open every directory component with no-follow and bind checks to fds."""
    acl_check = _acl_check if acl_check is None else acl_check
    mount_check = _mount_check if mount_check is None else mount_check
    candidate = _absolute_path(path)
    uid = os.getuid() if current_uid is None else current_uid
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise _fail()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    opened: list[tuple[pathlib.Path, int, os.stat_result, int | None, bool]] = []
    try:
        root_fd: int | None = None
        try:
            root_fd = os.open(os.fspath(candidate.anchor), flags)
            root_info = os.fstat(root_fd)
        except OSError:
            if root_fd is not None:
                try:
                    os.close(root_fd)
                except OSError:
                    pass
            raise _fail() from None
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid not in {uid, 0}
                or root_info.st_mode & 0o022):
            os.close(root_fd)
            raise _fail()
        opened.append((pathlib.Path(candidate.anchor), root_fd, root_info, None, False))
        acl_check(pathlib.Path(candidate.anchor), root_fd)
        previous_device = root_info.st_dev
        components = candidate.parts[1:]
        for index, component in enumerate(components):
            parent_fd = opened[-1][1]
            prefix = pathlib.Path(candidate.anchor).joinpath(*components[:index + 1])
            try:
                named_before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise _fail() from None
            if stat.S_ISLNK(named_before.st_mode) or not stat.S_ISDIR(named_before.st_mode):
                raise _fail()
            if named_before.st_uid not in {uid, 0} or named_before.st_mode & 0o022:
                raise _fail()
            is_leaf = index == len(components) - 1
            if is_leaf and named_before.st_uid != uid:
                raise _fail()
            if is_leaf and private_leaf and named_before.st_mode & 0o077:
                raise _fail()
            fd: int | None = None
            try:
                fd = os.open(component, flags, dir_fd=parent_fd)
                opened_info = os.fstat(fd)
            except OSError:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise _fail() from None
            check_mount = opened_info.st_dev != previous_device or is_leaf
            opened.append((prefix, fd, opened_info, parent_fd, check_mount))
            if _object_signature(opened_info) != _object_signature(named_before):
                raise _fail()
            acl_check(prefix, fd)
            if check_mount:
                mount_check(prefix, fd, opened_info)
            after_name = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            after_fd = os.fstat(fd)
            if (_object_signature(after_name) != _object_signature(opened_info)
                    or _object_signature(after_fd) != _object_signature(opened_info)):
                raise _fail()
            previous_device = opened_info.st_dev
        if not components:
            raise _fail()
        # Recheck every name against its held descriptor after all utilities ran.
        root_path, root_fd, root_info, _root_parent, _root_mount = opened[0]
        acl_check(root_path, root_fd)
        root_named = os.stat(os.fspath(root_path), follow_symlinks=False)
        root_current = os.fstat(root_fd)
        if (_object_signature(root_named) != _object_signature(root_info)
                or _object_signature(root_current) != _object_signature(root_info)):
            raise _fail()
        for prefix, fd, info, parent_fd, check_mount in opened[1:]:
            if parent_fd is None:
                raise _fail()
            acl_check(prefix, fd)
            if check_mount:
                mount_check(prefix, fd, info)
            named = os.stat(prefix.name, dir_fd=parent_fd, follow_symlinks=False)
            current = os.fstat(fd)
            if (_object_signature(named) != _object_signature(info)
                    or _object_signature(current) != _object_signature(info)):
                raise _fail()
        leaf_fd = opened[-1][1]
        leaf_info = os.fstat(leaf_fd)
        identity = (leaf_info.st_dev, leaf_info.st_ino)
        for _prefix, fd, _info, _parent, _check_mount in opened[:-1]:
            os.close(fd)
        opened = [opened[-1]]
        return leaf_fd, identity
    except BaseException as exc:
        for _prefix, fd, _info, _parent, _check_mount in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass
        if isinstance(exc, (AdmissionError, KeyboardInterrupt, SystemExit)):
            raise
        raise _fail() from None


def admit_directory(path: os.PathLike[str] | str, *, private_leaf: bool = True) -> tuple[int, int]:
    fd, identity = _open_validated_directory(path, private_leaf=private_leaf)
    try:
        return identity
    finally:
        os.close(fd)


def create_private_file(path: os.PathLike[str] | str, *, flags: int, mode: int = 0o600) -> int:
    """Create a no-follow file relative to a validated held parent directory."""
    candidate = _absolute_path(path)
    parent_fd, parent_identity = _open_validated_directory(candidate.parent, private_leaf=True)
    fd: int | None = None
    try:
        fd = os.open(
            candidate.name,
            flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=parent_fd,
        )
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1):
            raise _fail()
        _acl_check(candidate, fd)
        named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        after_acl = os.fstat(fd)
        if (_object_signature(named) != _object_signature(info)
                or _object_signature(after_acl) != _object_signature(info)):
            raise _fail()
        if admit_directory(candidate.parent, private_leaf=True) != parent_identity:
            raise _fail()
        return fd
    except BaseException as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(candidate.name, dir_fd=parent_fd)
            except OSError:
                pass
        if isinstance(exc, (AdmissionError, KeyboardInterrupt, SystemExit)):
            raise
        raise _fail() from None
    finally:
        os.close(parent_fd)


def open_private_file_read(path: os.PathLike[str] | str) -> int:
    candidate = _absolute_path(path)
    parent_fd, parent_identity = _open_validated_directory(candidate.parent, private_leaf=True)
    fd: int | None = None
    try:
        fd = os.open(candidate.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        info = os.fstat(fd)
        named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or _object_signature(info) != _object_signature(named)):
            raise _fail()
        _acl_check(candidate, fd)
        after_acl = os.fstat(fd)
        named_after_acl = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        if (_object_signature(after_acl) != _object_signature(info)
                or _object_signature(named_after_acl) != _object_signature(info)):
            raise _fail()
        if admit_directory(candidate.parent, private_leaf=True) != parent_identity:
            raise _fail()
        return fd
    except BaseException as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if isinstance(exc, (AdmissionError, KeyboardInterrupt, SystemExit)):
            raise
        raise _fail() from None
    finally:
        os.close(parent_fd)


def replace_private_file(
    source: os.PathLike[str] | str,
    destination: os.PathLike[str] | str,
    expected_parent_identity: tuple[int, int],
) -> None:
    source_path = _absolute_path(source)
    destination_path = _absolute_path(destination)
    if source_path.parent != destination_path.parent:
        raise _fail()
    parent_fd, identity = _open_validated_directory(source_path.parent, private_leaf=True)
    try:
        if identity != expected_parent_identity:
            raise _fail()
        fd = os.open(source_path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            named = os.stat(source_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or _object_signature(info) != _object_signature(named)):
                raise _fail()
            _acl_check(source_path, fd)
            after_acl = os.fstat(fd)
            named_after_acl = os.stat(source_path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (_object_signature(after_acl) != _object_signature(info)
                    or _object_signature(named_after_acl) != _object_signature(info)):
                raise _fail()
        finally:
            os.close(fd)
        if admit_directory(source_path.parent, private_leaf=True) != expected_parent_identity:
            raise _fail()
        os.replace(source_path.name, destination_path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    except (OSError, ValueError, TypeError):
        raise _fail() from None
    finally:
        os.close(parent_fd)


def atomic_write_private(path: os.PathLike[str] | str, data: bytes) -> None:
    candidate = _absolute_path(path)
    parent_fd, parent_identity = _open_validated_directory(candidate.parent, private_leaf=True)
    temp_name = f".{candidate.name}.{os.getpid()}.tmp"
    created = False
    fd: int | None = None
    try:
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        created = True
        temp_path = candidate.with_name(temp_name)
        file_info = os.fstat(fd)
        if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.getuid()
                or stat.S_IMODE(file_info.st_mode) != 0o600 or file_info.st_nlink != 1):
            raise _fail()
        named_info = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        if _object_signature(file_info) != _object_signature(named_info):
            raise _fail()
        _acl_check(temp_path, fd)
        checked_info = os.fstat(fd)
        checked_name = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        if (_object_signature(file_info) != _object_signature(checked_info)
                or _object_signature(file_info) != _object_signature(checked_name)):
            raise _fail()
        raw_fd = fd
        fd = None
        try:
            stream = os.fdopen(raw_fd, "wb")
        except BaseException:
            try:
                os.close(raw_fd)
            except OSError:
                pass
            raise
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if admit_directory(candidate.parent, private_leaf=True) != parent_identity:
            raise _fail()
        os.replace(temp_name, candidate.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_fd)


def normalize_directory_path(path: os.PathLike[str] | str) -> pathlib.Path:
    return _absolute_path(path)


def admit_child_location(path: os.PathLike[str] | str) -> None:
    """Admit the immediate parent and any existing child, without creating it."""
    candidate = _absolute_path(path)
    parent_fd, parent_identity = _open_validated_directory(candidate.parent, private_leaf=False)
    try:
        parent_binding = _directory_binding(os.fstat(parent_fd))
        try:
            named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            named = None
        if named is not None:
            admit_directory(candidate, private_leaf=True)
        current_parent = os.fstat(parent_fd)
        if ((current_parent.st_dev, current_parent.st_ino) != parent_identity
                or _directory_binding(current_parent) != parent_binding):
            raise _fail()
    finally:
        os.close(parent_fd)


def preflight_directory(
    path: os.PathLike[str] | str,
    *,
    private_leaf: bool = True,
    must_be_absent: bool = False,
) -> None:
    """Read-only admission of an existing path or nearest safe creation parent."""
    candidate = _absolute_path(path)
    prefix = pathlib.Path(candidate.anchor)
    for component in candidate.parts[1:]:
        prefix /= component
        try:
            info = os.stat(prefix, follow_symlinks=False)
        except FileNotFoundError:
            admit_directory(prefix.parent, private_leaf=False)
            return
        except OSError:
            raise _fail() from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise _fail()
    if must_be_absent:
        raise FileExistsError("private run directory already exists")
    admit_directory(candidate, private_leaf=private_leaf)


def private_json_fits_read_limits(data: bytes, *, maximum_bytes: int = 65536) -> bool:
    """Return whether `data` would pass `read_private_json`'s content bounds.

    Applies the same byte, depth, comma, node, key, list and string limits so a
    writer can prove its record stays readable before atomically replacing it.
    """
    try:
        _check_json_shape_bytes(data, maximum_bytes)
        _loads_bounded_private_json(data)
    except AdmissionError:
        return False
    return True


def read_private_json(path: os.PathLike[str] | str, *, maximum_bytes: int = 65536) -> dict[str, Any]:
    """Read an existing small private JSON file without following a link."""
    candidate = _absolute_path(path)
    parent_fd, parent_identity = _open_validated_directory(candidate.parent, private_leaf=False)
    file_fd: int | None = None
    try:
        parent_binding = _directory_binding(os.fstat(parent_fd))
        file_fd = os.open(candidate.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(file_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > maximum_bytes
                or info.st_dev != parent_identity[0]):
            raise _fail()
        if sys.platform == "darwin":
            output, _ = _bounded_utility(["/bin/ls", "-leO", os.fspath(candidate)])
            _parse_macos_acl(output, candidate, directory=False)
        elif sys.platform.startswith("linux"):
            _linux_acl_check(file_fd)
        _bounded_json_shape(file_fd, maximum_bytes)
        data = bytearray()
        while len(data) <= maximum_bytes:
            chunk = os.read(file_fd, min(4096, maximum_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > maximum_bytes:
            raise _fail()
        current = os.fstat(file_fd)
        parent = os.fstat(parent_fd)
        named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        if (_object_signature(current) != _object_signature(info)
                or _object_signature(named) != _object_signature(info)
                or (parent.st_dev, parent.st_ino) != parent_identity
                or _directory_binding(parent) != parent_binding):
            raise _fail()
        reopened_parent_fd, reopened_parent_identity = _open_validated_directory(candidate.parent, private_leaf=False)
        try:
            reopened_parent_binding = _directory_binding(os.fstat(reopened_parent_fd))
        finally:
            os.close(reopened_parent_fd)
        if reopened_parent_identity != parent_identity or reopened_parent_binding != parent_binding:
            raise _fail()
        if sys.platform == "darwin":
            output, _ = _bounded_utility(["/bin/ls", "-leO", os.fspath(candidate)])
            _parse_macos_acl(output, candidate, directory=False)
        elif sys.platform.startswith("linux"):
            _linux_acl_check(file_fd)
        current_after_acl = os.fstat(file_fd)
        named_after_acl = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_after_acl = os.fstat(parent_fd)
        if (_object_signature(current_after_acl) != _object_signature(info)
                or _object_signature(named_after_acl) != _object_signature(info)
                or _directory_binding(parent_after_acl) != parent_binding):
            raise _fail()
        final_parent_fd, final_parent_identity = _open_validated_directory(candidate.parent, private_leaf=False)
        try:
            if (final_parent_identity != parent_identity
                    or _directory_binding(os.fstat(final_parent_fd)) != parent_binding):
                raise _fail()
        finally:
            os.close(final_parent_fd)
        return _loads_bounded_private_json(bytes(data))
    except AdmissionError:
        raise
    except (OSError, ValueError, TypeError):
        raise _fail() from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def ensure_private_directory(
    path: os.PathLike[str] | str,
    *,
    must_create: bool = False,
) -> tuple[int, int]:
    """Validate an existing private directory or create one safe child."""
    candidate = _absolute_path(path)
    parent = candidate.parent
    parent_fd, parent_identity = _open_validated_directory(parent, private_leaf=False)
    try:
        parent_binding = _directory_binding(os.fstat(parent_fd))
        try:
            named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.mkdir(candidate.name, mode=0o700, dir_fd=parent_fd)
            except OSError:
                raise _fail() from None
            named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        else:
            if must_create:
                raise FileExistsError("private run directory already exists")
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
            raise _fail()
        child_fd, identity = _open_validated_directory(candidate, private_leaf=True)
        try:
            child_from_parent = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
            child_info = os.fstat(child_fd)
            parent_now = os.fstat(parent_fd)
            reopened_parent_fd, reopened_parent_identity = _open_validated_directory(parent, private_leaf=False)
            try:
                reopened_parent_binding = _directory_binding(os.fstat(reopened_parent_fd))
            finally:
                os.close(reopened_parent_fd)
            _acl_check(candidate, child_fd)
            _mount_check(candidate, child_fd, child_info)
            child_after_checks = os.fstat(child_fd)
            named_after_checks = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
            parent_after_checks = os.fstat(parent_fd)
            final_parent_fd, final_parent_identity = _open_validated_directory(parent, private_leaf=False)
            try:
                final_parent_binding = _directory_binding(os.fstat(final_parent_fd))
            finally:
                os.close(final_parent_fd)
            if ((child_from_parent.st_dev, child_from_parent.st_ino) != identity
                    or _directory_binding(parent_now) != parent_binding
                    or reopened_parent_identity != parent_identity
                    or reopened_parent_binding != parent_binding
                    or (parent_after_checks.st_dev, parent_after_checks.st_ino) != parent_identity
                    or _directory_binding(parent_after_checks) != parent_binding
                    or final_parent_identity != parent_identity
                    or final_parent_binding != parent_binding
                    or _object_signature(child_after_checks) != _object_signature(child_info)
                    or _object_signature(named_after_checks) != _object_signature(child_info)):
                raise _fail()
            return identity
        finally:
            os.close(child_fd)
    finally:
        os.close(parent_fd)


def admit_empty_directory(path: os.PathLike[str] | str, expected_identity: tuple[int, int]) -> None:
    """Revalidate a private directory and require its held identity to stay empty."""
    fd, identity = _open_validated_directory(path, private_leaf=True)
    try:
        before = os.fstat(fd)
        if identity != expected_identity:
            raise _fail()
        with os.scandir(fd) as entries:
            if next(entries, None) is not None:
                raise _fail()
        after = os.fstat(fd)
        if (_object_signature(after) != _object_signature(before)
                or _directory_entry_signature(after) != _directory_entry_signature(before)
                or (after.st_dev, after.st_ino) != expected_identity):
            raise _fail()
    except OSError:
        raise _fail() from None
    finally:
        os.close(fd)


def _directory_binding(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode
