from __future__ import annotations

import ctypes
import datetime
import errno
import hashlib
import json
import os
import pathlib
import plistlib
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from argparse import Namespace
from unittest import mock

from tools.release import check_ledger, leased_run, private_roots, provenance, recover_leases, run_gates

REAL_VERSIONS = run_gates._versions


def test_scratch_root() -> pathlib.Path:
    value = os.environ.get("XTRACE_TEST_SCRATCH_ROOT")
    if not value:
        raise RuntimeError("XTRACE_TEST_SCRATCH_ROOT must name an admitted test scratch directory")
    path = pathlib.Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise RuntimeError("XTRACE_TEST_SCRATCH_ROOT must be an existing real directory")
    if path.resolve(strict=True) != path:
        raise RuntimeError("XTRACE_TEST_SCRATCH_ROOT must use its canonical path")
    return path


def attempt_log_from_receipt(run_dir: pathlib.Path) -> pathlib.Path | None:
    """Locate an attempted gate's finalized private log for assertions/cleanup."""
    try:
        receipt = json.loads((run_dir / "receipt.json").read_text())
        gates = receipt.get("gates")
        log_ref = gates[0].get("log") if isinstance(gates, list) and gates else None
        if not isinstance(log_ref, str):
            return None
        log_path = run_dir / log_ref
        if log_path.parent != run_dir / "logs" or not log_path.is_file():
            return None
        return log_path
    except (OSError, ValueError, TypeError, IndexError, AttributeError):
        return None


class PrivateRootAdmissionTests(unittest.TestCase):
    def test_object_signature_ignores_directory_entries_only(self) -> None:
        directory = os.stat_result((stat.S_IFDIR | 0o700, 11, 77, 2, os.getuid(), 0, 64, 0, 0, 0))
        directory_with_churn = os.stat_result(
            (stat.S_IFDIR | 0o700, 11, 77, 5, os.getuid(), 0, 4096, 0, 0, 0),
        )
        self.assertEqual(
            private_roots._object_signature(directory),
            private_roots._object_signature(directory_with_churn),
        )
        for changed in (
            os.stat_result((stat.S_IFDIR | 0o700, 12, 77, 2, os.getuid(), 0, 64, 0, 0, 0)),
            os.stat_result((stat.S_IFDIR | 0o700, 11, 78, 2, os.getuid(), 0, 64, 0, 0, 0)),
            os.stat_result((stat.S_IFDIR | 0o750, 11, 77, 2, os.getuid(), 0, 64, 0, 0, 0)),
            os.stat_result((stat.S_IFDIR | 0o700, 11, 77, 2, os.getuid() + 1, 0, 64, 0, 0, 0)),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(
                    private_roots._object_signature(directory),
                    private_roots._object_signature(changed),
                )
        regular = os.stat_result((stat.S_IFREG | 0o600, 11, 77, 1, os.getuid(), 0, 12, 0, 0, 0))
        changed_regular_links = os.stat_result(
            (stat.S_IFREG | 0o600, 11, 77, 2, os.getuid(), 0, 12, 0, 0, 0),
        )
        changed_regular_size = os.stat_result(
            (stat.S_IFREG | 0o600, 11, 77, 1, os.getuid(), 0, 13, 0, 0, 0),
        )
        self.assertNotEqual(
            private_roots._object_signature(regular),
            private_roots._object_signature(changed_regular_links),
        )
        self.assertNotEqual(
            private_roots._object_signature(regular),
            private_roots._object_signature(changed_regular_size),
        )

    def test_mac_mount_tolerates_synthetic_directory_entry_stat_drift(self) -> None:
        """Synthetic stat drift at os.fstat; real child creation and fd, not admission proof."""
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            mount = pathlib.Path(temporary)
            path = mount / "cache"
            path.mkdir(mode=0o700)
            child = path / "concurrent-child"
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            before = os.fstat(fd)
            real_fstat = os.fstat
            candidate_fstat_calls = 0

            def run_util(argv: list[str]) -> tuple[bytes, bytes]:
                if argv[0] == "/bin/df":
                    child.mkdir(mode=0o700)
                    return (
                        f"Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                        f"/dev/disk3s1 100 10 90 10% {mount}\n".encode(),
                        b"",
                    )
                return plistlib.dumps({
                    "MountPoint": str(mount), "DeviceNode": "/dev/disk3s1",
                    "FilesystemType": "apfs", "GlobalPermissionsEnabled": True,
                }), b""

            def fstat_with_synthetic_entry_drift(target_fd: int) -> os.stat_result:
                nonlocal candidate_fstat_calls
                info = real_fstat(target_fd)
                if target_fd == fd:
                    candidate_fstat_calls += 1
                    if candidate_fstat_calls == 2:
                        self.assertTrue(child.is_dir())
                        fields = list(info)
                        fields[3] += 1
                        fields[6] += 256
                        return os.stat_result(fields)
                return info

            try:
                with mock.patch.object(private_roots, "_bounded_utility", side_effect=run_util), \
                        mock.patch.object(private_roots.os, "fstat", side_effect=fstat_with_synthetic_entry_drift):
                    private_roots._macos_mount(path, fd, before)
                after = real_fstat(fd)
                self.assertTrue(child.is_dir())
                self.assertEqual(candidate_fstat_calls, 2)
                self.assertEqual((before.st_dev, before.st_ino, before.st_uid, before.st_mode),
                                 (after.st_dev, after.st_ino, after.st_uid, after.st_mode))
            finally:
                os.close(fd)

    def test_admit_empty_directory_rejects_entry_inserted_after_empty_scan(self) -> None:
        """Insert a real entry at the final-fstat seam; this is not admission evidence."""
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            child = root / "appears-after-scan"
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            admission_fd = os.dup(fd)
            identity_info = os.fstat(fd)
            identity = (identity_info.st_dev, identity_info.st_ino)
            before_entries = (identity_info.st_nlink, identity_info.st_size)
            real_fstat = os.fstat
            candidate_fstat_calls = 0

            def fstat_with_postscan_child(target_fd: int) -> os.stat_result:
                nonlocal candidate_fstat_calls
                if target_fd == admission_fd:
                    candidate_fstat_calls += 1
                    if candidate_fstat_calls == 2:
                        child.mkdir(mode=0o700)
                        info = real_fstat(target_fd)
                        fields = list(info)
                        fields[3] = max(fields[3], before_entries[0] + 1)
                        fields[6] = max(fields[6], before_entries[1] + 256)
                        return os.stat_result(fields)
                return real_fstat(target_fd)

            try:
                with mock.patch.object(private_roots, "_open_validated_directory", return_value=(admission_fd, identity)), \
                        mock.patch.object(private_roots.os, "fstat", side_effect=fstat_with_postscan_child):
                    with self.assertRaises(private_roots.AdmissionError):
                        private_roots.admit_empty_directory(root, identity)
                self.assertTrue(child.is_dir())
                self.assertEqual(candidate_fstat_calls, 2)
                with self.assertRaises(OSError):
                    real_fstat(admission_fd)
            finally:
                os.close(fd)
                try:
                    os.close(admission_fd)
                except OSError:
                    pass

    def test_private_log_reader_reads_a_regular_fixture_through_validated_fd(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            path = root / "private.log"
            expected = b"public synthetic version fixture\n"
            path.write_bytes(expected)
            os.chmod(path, 0o600)
            identity = (root.stat().st_dev, root.stat().st_ino)

            def opened_parent(candidate: pathlib.Path, **_kwargs: object) -> tuple[int, tuple[int, int]]:
                self.assertEqual(candidate, root)
                return os.open(candidate, os.O_RDONLY | os.O_DIRECTORY), identity

            with mock.patch.object(private_roots, "_open_validated_directory", side_effect=opened_parent), \
                    mock.patch.object(private_roots, "admit_directory", return_value=identity), \
                    mock.patch.object(private_roots, "_acl_check"):
                fd = private_roots.open_private_file_read(path)
            try:
                self.assertEqual(os.read(fd, len(expected) + 1), expected)
            finally:
                os.close(fd)

    def test_private_log_reader_opens_fifo_nonblocking_then_rejects_type(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            fifo = root / "private.log"
            os.mkfifo(fifo, 0o600)
            root_identity = (root.stat().st_dev, root.stat().st_ino)
            real_open = os.open
            observed_nonblocking: list[bool] = []

            def opened_parent(path: pathlib.Path, **_kwargs: object) -> tuple[int, tuple[int, int]]:
                self.assertEqual(path, root)
                return real_open(path, os.O_RDONLY | os.O_DIRECTORY), root_identity

            def checked_open(candidate: object, flags: int, *args: object, **kwargs: object) -> int:
                if candidate == fifo.name:
                    observed_nonblocking.append(bool(flags & getattr(os, "O_NONBLOCK", 0)))
                return real_open(candidate, flags, *args, **kwargs)

            with mock.patch.object(private_roots, "_open_validated_directory", side_effect=opened_parent), \
                    mock.patch.object(private_roots, "admit_directory", return_value=root_identity), \
                    mock.patch.object(private_roots.os, "open", side_effect=checked_open):
                with self.assertRaises(private_roots.AdmissionError):
                    private_roots.open_private_file_read(fifo)
            self.assertEqual(observed_nonblocking, [True])

    def test_actual_macos_ls_headers_allow_deny_only_acl_and_paths_with_spaces(self) -> None:
        workspace = pathlib.Path("/Users/example/Documents/Codex/2026-10-04/workspace with spaces")
        cache = pathlib.Path("/Volumes/Example SSD/.cache/xtrace")
        for mode, nlink, owner, group, flags, size, month, day, year, path in (
            ("drwxr-xr-x", "22", "root", "wheel", "sunlnk", "704", "Feb", "25", "2026", pathlib.Path("/")),
            ("drwxr-xr-x", "64", "root", "wheel", "restricted", "2048", "Feb", "25", "2026", pathlib.Path("/System")),
            ("drwxr-xr-x", "8", "root", "wheel", "restricted", "256", "Feb", "25", "2026", pathlib.Path("/System/Volumes")),
            ("drwxr-xr-x", "4", "root", "wheel", "sunlnk", "128", "Feb", "25", "2026", pathlib.Path("/Users")),
        ):
            header = f"{mode} {nlink} {owner} {group} {flags} {size} {month} {day} {year} {path}\n"
            private_roots._parse_macos_acl(header.encode(), path)
        private_roots._parse_macos_acl(
            f"drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 {workspace}\n".encode(),
            workspace,
        )
        private_roots._parse_macos_acl(
            (f"drwx------@ 88 example staff - 2816 Oct 4 03:00 {cache}\n"
             " 0: group:everyone deny delete\n").encode(),
            cache,
        )
        documents = pathlib.Path("/Users/example/Documents")
        private_roots._parse_macos_acl(
            (f"drwx------@ 9 example staff - 288 Oct 4 00:23 {documents}\n"
             " 0: group:everyone deny delete\n").encode(),
            documents,
        )
        private_roots._parse_macos_acl(
            (f"drwx------@ 9 example staff - 288 Oct 4 00:23 {documents}\n"
             "  0: group:everyone deny delete\n").encode(),
            documents,
        )

    def test_macos_acl_accepts_hidden_visibility_flag_without_weakening_acl_checks(self) -> None:
        library = pathlib.Path("/Users/example/Library")
        header = (
            f"drwx------@ 129 example staff hidden 4128 Jul 19 16:34 {library}\n"
            " 0: group:everyone deny delete\n"
        )
        private_roots._parse_macos_acl(header.encode(), library)
        private_roots._parse_macos_acl(
            header.replace(" staff hidden ", " staff hidden,restricted ").encode(),
            library,
        )

        rejected_payloads = (
            header.replace(" hidden ", " hidden,dataless "),
            header.replace(" hidden ", " hidden,hidden "),
            header.replace(" 0: group:everyone deny delete", " 0: group:everyone allow read"),
        )
        for payload in rejected_payloads:
            with self.subTest(payload=payload), self.assertRaises(private_roots.AdmissionError):
                private_roots._parse_macos_acl(payload.encode(), library)

    def test_macos_acl_rejects_allow_malformed_header_and_wrong_path(self) -> None:
        path = pathlib.Path("/Users/test/parent with spaces")
        good_header = f"drwx------+ 2 test staff - 64 Oct 4 00:23 {path}\n"
        for payload in (
            (good_header + " 0: group:everyone allow read\n").encode(),
            (good_header + " 0: group:everyone allow read (inherited)\n").encode(),
            (good_header + "0: group:everyone allow read (inherited)\n").encode(),
            (good_header + " 1: group:everyone deny delete\n").encode(),
            (good_header + "\t0: group:everyone deny delete\n").encode(),
            f"drwx------ 2 test staff - 64 Oct 4 00:23 {path}\n0: malformed\n".encode(),
            f"drwx------ 2 test staff - 64 Oct 4 00:23 /wrong/path\n".encode(),
            f"drwx------ 2 test staff - 64 Oct 4 00:23 {path}\nextra header field\n".encode(),
            f"drwx------ 2 test staff unknown 64 Oct 4 00:23 {path}\n".encode(),
        ):
            with self.subTest(payload=payload), self.assertRaises(private_roots.AdmissionError):
                private_roots._parse_macos_acl(payload, path)

    def test_macos_acl_check_uses_the_validated_regular_file_kind(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            path = pathlib.Path(temporary) / "owner file.log"
            path.write_bytes(b"synthetic public fixture\n")
            os.chmod(path, 0o600)
            output = f"-rw------- 1 example staff - 24 Oct 4 00:23 {path}\n".encode()
            with path.open("rb") as stream, \
                    mock.patch.object(private_roots.sys, "platform", "darwin"), \
                    mock.patch.object(private_roots, "_bounded_utility", return_value=(output, b"")):
                private_roots._acl_check(path, stream.fileno())
                mismatched_directory_header = output.replace(b"-rw-------", b"drwx------")
                with mock.patch.object(
                    private_roots, "_bounded_utility",
                    return_value=(mismatched_directory_header, b""),
                ), self.assertRaises(private_roots.AdmissionError):
                    private_roots._acl_check(path, stream.fileno())

    def test_atomic_private_write_checks_created_metadata_before_writing(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            destination = root / "receipt.json"
            real_fstat = os.fstat
            identity = (root.stat().st_dev, root.stat().st_ino)

            def opened_parent(path: pathlib.Path, **_kwargs: object) -> tuple[int, tuple[int, int]]:
                self.assertEqual(path, root)
                return os.open(path, os.O_RDONLY | os.O_DIRECTORY), identity

            def wrong_owner(fd: int) -> object:
                info = real_fstat(fd)
                return SimpleNamespace(
                    st_dev=info.st_dev, st_ino=info.st_ino, st_uid=os.getuid() + 1,
                    st_mode=info.st_mode, st_nlink=info.st_nlink, st_size=info.st_size,
                )

            with mock.patch.object(private_roots, "_open_validated_directory", side_effect=opened_parent), \
                    mock.patch.object(private_roots, "admit_directory", return_value=identity), \
                    mock.patch.object(private_roots, "_acl_check"), \
                    mock.patch.object(private_roots.os, "fstat", side_effect=wrong_owner):
                with self.assertRaises(private_roots.AdmissionError):
                    private_roots.atomic_write_private(destination, b"must not be written")
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_atomic_private_write_fails_if_parent_fsync_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            root = pathlib.Path(temporary)
            destination = root / "receipt.json"
            identity = (root.stat().st_dev, root.stat().st_ino)
            real_fsync = os.fsync
            real_fstat = os.fstat
            observed_directory_sync: list[bool] = []
            calls = 0

            def opened_parent(path: pathlib.Path, **_kwargs: object) -> tuple[int, tuple[int, int]]:
                self.assertEqual(path, root)
                return os.open(path, os.O_RDONLY | os.O_DIRECTORY), identity

            def fail_parent_fsync(fd: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    observed_directory_sync.append(stat.S_ISDIR(real_fstat(fd).st_mode))
                    raise OSError("injected parent fsync failure")
                real_fsync(fd)

            with mock.patch.object(private_roots, "_open_validated_directory", side_effect=opened_parent), \
                    mock.patch.object(private_roots, "admit_directory", return_value=identity), \
                    mock.patch.object(private_roots, "_acl_check"), \
                    mock.patch.object(private_roots.os, "fsync", side_effect=fail_parent_fsync):
                with self.assertRaises(OSError):
                    private_roots.atomic_write_private(destination, b"metadata")
            self.assertEqual(calls, 2)
            self.assertEqual(observed_directory_sync, [True])
            self.assertEqual(destination.read_bytes(), b"metadata")

    def test_hash_file_closes_descriptor_when_fdopen_conversion_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            path = pathlib.Path(temporary) / "public fixture.log"
            path.write_bytes(b"public fixture")
            fd = os.open(path, os.O_RDONLY)
            with mock.patch.object(private_roots, "open_private_file_read", return_value=fd), \
                    mock.patch.object(run_gates.os, "fdopen", side_effect=OSError("injected conversion failure")):
                with self.assertRaises(OSError):
                    run_gates._hash_file(path)
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_directory_admission_uses_injected_acl_and_mount_facts(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            child = pathlib.Path(temporary) / "private child"
            child.mkdir(mode=0o700)
            acl_paths: list[pathlib.Path] = []
            mount_paths: list[pathlib.Path] = []

            def acl(path: pathlib.Path, _fd: int) -> None:
                acl_paths.append(path)

            def mount(path: pathlib.Path, _fd: int, _info: os.stat_result) -> None:
                mount_paths.append(path)

            fd, identity = private_roots._open_validated_directory(
                child, private_leaf=True, acl_check=acl, mount_check=mount,
            )
            os.close(fd)
            self.assertEqual(identity, (os.stat(child).st_dev, os.stat(child).st_ino))
            self.assertIn(child, acl_paths)
            self.assertIn(child, mount_paths)

    def test_directory_admission_rejects_writable_parent_and_same_inode_mode_change(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            parent = pathlib.Path(temporary)
            child = parent / "private child"
            child.mkdir(mode=0o700)
            os.chmod(parent, 0o777)
            try:
                with self.assertRaises(private_roots.AdmissionError):
                    private_roots._open_validated_directory(
                        child, private_leaf=True,
                        acl_check=lambda _path, _fd: None,
                        mount_check=lambda _path, _fd, _info: None,
                    )
            finally:
                os.chmod(parent, 0o700)

            def change_mode(path: pathlib.Path, _fd: int, _info: os.stat_result) -> None:
                if path == child:
                    os.chmod(child, 0o750)

            with self.assertRaises(private_roots.AdmissionError):
                private_roots._open_validated_directory(
                    child, private_leaf=True,
                    acl_check=lambda _path, _fd: None,
                    mount_check=change_mode,
                )
            os.chmod(child, 0o700)

    def test_directory_admission_rejects_rename_during_mount_check(self) -> None:
        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            child = pathlib.Path(temporary) / "private child"
            moved = pathlib.Path(temporary) / "moved child"
            child.mkdir(mode=0o700)

            def rename(path: pathlib.Path, _fd: int, _info: os.stat_result) -> None:
                if path == child and child.exists():
                    child.rename(moved)
                    child.mkdir(mode=0o700)

            with self.assertRaises(private_roots.AdmissionError):
                private_roots._open_validated_directory(
                    child, private_leaf=True,
                    acl_check=lambda _path, _fd: None,
                    mount_check=rename,
                )

    def test_private_json_shape_rejects_nonfinite_and_deep_values(self) -> None:
        with tempfile.TemporaryFile() as stream:
            stream.write(b'{"owner":NaN}')
            stream.flush()
            self.assertIsNone(private_roots._bounded_json_shape(stream.fileno(), 64))
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._loads_bounded_private_json(b'{"owner":NaN}')
            self.assertFalse(private_roots._bounded_json_value({"owner": float("inf")}))
            stream.seek(0)
            stream.truncate()
            stream.write((b"[" * 10) + (b"]" * 10))
            stream.flush()
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._bounded_json_shape(stream.fileno(), 64)

    def test_mac_mount_uses_reported_firmlink_mount_and_rejects_noowners_or_device_change(self) -> None:
        path = pathlib.Path("/Users/example/cache with spaces")
        mount = pathlib.Path("/System/Volumes/Data/Users/example")
        candidate_stat = os.stat_result((stat.S_IFDIR | 0o700, 11, 77, 1, os.getuid(), 0, 0, 0, 0, 0))
        mount_stat = os.stat_result((stat.S_IFDIR | 0o755, 12, 77, 1, 0, 0, 0, 0, 0, 0))
        real_path_stat = pathlib.Path.stat

        def path_stat(target: pathlib.Path, *args: object, **kwargs: object) -> os.stat_result:
            del args, kwargs
            if target == path:
                return candidate_stat
            if target == mount:
                return mount_stat
            return real_path_stat(target)

        def run_util(argv: list[str]) -> tuple[bytes, bytes]:
            if argv[:2] == ["/bin/df", "-P"]:
                return (b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s1 100 10 90 10% /System/Volumes/Data/Users/example\n", b"")
            return plistlib.dumps({
                "MountPoint": str(mount), "DeviceNode": "/dev/disk3s1",
                "FilesystemType": "apfs", "GlobalPermissionsEnabled": True,
            }), b""

        with mock.patch.object(pathlib.Path, "stat", path_stat), \
                mock.patch.object(os, "fstat", return_value=candidate_stat), \
                mock.patch.object(private_roots, "_bounded_utility", side_effect=run_util) as utility:
            private_roots._macos_mount(path, 7, candidate_stat)
        self.assertEqual(utility.call_args_list[0].args[0], ["/bin/df", "-P", str(path)])
        self.assertEqual(utility.call_args_list[1].args[0], ["/usr/sbin/diskutil", "info", "-plist", str(mount)])

        def run_noowners(argv: list[str]) -> tuple[bytes, bytes]:
            stdout, stderr = run_util(argv)
            if argv[0] == "/usr/sbin/diskutil":
                return plistlib.dumps({
                    "MountPoint": str(mount), "DeviceNode": "/dev/disk3s1",
                    "FilesystemType": "apfs", "GlobalPermissionsEnabled": False,
                }), b""
            return stdout, stderr

        with mock.patch.object(pathlib.Path, "stat", path_stat), \
                mock.patch.object(os, "fstat", return_value=candidate_stat), \
                mock.patch.object(private_roots, "_bounded_utility", side_effect=run_noowners):
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._macos_mount(path, 7, candidate_stat)

    def test_mac_mount_rejects_candidate_rename_after_utility_probe(self) -> None:
        path = pathlib.Path("/Users/example/cache")
        mount = pathlib.Path("/Volumes/Example")
        initial = os.stat_result((stat.S_IFDIR | 0o700, 11, 77, 1, os.getuid(), 0, 0, 0, 0, 0))
        changed = os.stat_result((stat.S_IFDIR | 0o700, 99, 77, 1, os.getuid(), 0, 0, 0, 0, 0))
        mount_stat = os.stat_result((stat.S_IFDIR | 0o755, 12, 77, 1, 0, 0, 0, 0, 0, 0))
        real_path_stat = pathlib.Path.stat
        path_reads = 0

        def path_stat(target: pathlib.Path, *args: object, **kwargs: object) -> os.stat_result:
            nonlocal path_reads
            del args, kwargs
            if target == path:
                path_reads += 1
                return initial if path_reads == 1 else changed
            if target == mount:
                return mount_stat
            return real_path_stat(target)

        def run_util(argv: list[str]) -> tuple[bytes, bytes]:
            if argv[0] == "/bin/df":
                return (b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s1 100 10 90 10% /Volumes/Example\n", b"")
            return plistlib.dumps({
                "MountPoint": str(mount), "DeviceNode": "/dev/disk3s1",
                "FilesystemType": "apfs", "GlobalPermissionsEnabled": True,
            }), b""

        with mock.patch.object(pathlib.Path, "stat", path_stat), \
                mock.patch.object(os, "fstat", return_value=initial), \
                mock.patch.object(private_roots, "_bounded_utility", side_effect=run_util):
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._macos_mount(path, 7, initial)

        def run_mismatched_device(argv: list[str]) -> tuple[bytes, bytes]:
            stdout, stderr = run_util(argv)
            if argv[0] == "/usr/sbin/diskutil":
                return plistlib.dumps({
                    "MountPoint": str(mount), "DeviceNode": "/dev/disk9",
                    "FilesystemType": "apfs", "GlobalPermissionsEnabled": True,
            }), b""
            return stdout, stderr

        path_reads = 0
        with mock.patch.object(pathlib.Path, "stat", path_stat), \
                mock.patch.object(os, "fstat", return_value=initial), \
                mock.patch.object(private_roots, "_bounded_utility", side_effect=run_mismatched_device):
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._macos_mount(path, 7, initial)

    def test_linux_mountinfo_accepts_only_known_local_filesystems_and_decodes_spaces(self) -> None:
        info = os.stat_result((stat.S_IFDIR | 0o700, 1, os.makedev(8, 1), 1, os.getuid(), 0, 0, 0, 0, 0))
        escaped_mount = "/Volumes/Local\\040SSD"
        record = f"36 25 8:1 / {escaped_mount} rw,relatime - ext4 /dev/sda1 rw\n".encode()
        self.assertEqual(
            private_roots._linux_filesystem_from_mountinfo(record, pathlib.Path("/Volumes/Local SSD/cache"), info),
            "ext4",
        )
        overlay = record.replace(b"ext4", b"overlay")
        with self.assertRaises(private_roots.AdmissionError):
            private_roots._linux_filesystem_from_mountinfo(overlay, pathlib.Path("/Volumes/Local SSD/cache"), info)

    @staticmethod
    def posix_acl(*entries: tuple[int, int]) -> bytes:
        raw = (2).to_bytes(4, "little")
        for tag, perm in entries:
            raw += tag.to_bytes(2, "little") + perm.to_bytes(2, "little") + (0xFFFFFFFF).to_bytes(4, "little")
        return raw

    def acl_outcomes(self, access: object = None, default: object = None) -> mock._patch:
        """Fake os.getxattr: bytes = value, int = errno raised, None = ENODATA."""
        outcomes = {"system.posix_acl_access": access, "system.posix_acl_default": default}

        def fake(fd: int, name: str, *args: object, **kwargs: object) -> bytes:
            outcome = outcomes[name]
            if outcome is None:
                raise OSError(errno.ENODATA, "no data")
            if isinstance(outcome, int):
                raise OSError(outcome, "xattr error")
            return outcome  # type: ignore[return-value]

        return mock.patch.object(private_roots.os, "getxattr", side_effect=fake, create=True)

    def test_linux_acl_absent_or_unsupported_is_accepted(self) -> None:
        for outcome in (None, errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            with self.subTest(outcome=outcome), self.acl_outcomes(outcome, outcome):
                private_roots._linux_acl_check(17)
                private_roots._linux_acl_check(17, private_leaf=False)

    def test_linux_acl_unexpected_errors_and_api_loss_fail_closed(self) -> None:
        for code in (errno.EACCES, errno.EIO, errno.EINVAL, errno.ERANGE, errno.EPERM):
            with self.subTest(code=code), self.acl_outcomes(code, None):
                for leaf in (True, False):
                    with self.assertRaises(private_roots.AdmissionError) as caught:
                        private_roots._linux_acl_check(17, private_leaf=leaf)
                    self.assertEqual(caught.exception.reason, "acl-read-error")
        with mock.patch.object(private_roots.os, "getxattr", side_effect=AttributeError("no xattr API"), create=True):
            with self.assertRaises(private_roots.AdmissionError) as caught:
                private_roots._linux_acl_check(17)
        self.assertEqual(caught.exception.reason, "acl-api-unavailable")

    def test_linux_acl_malformed_values_fail_closed(self) -> None:
        user, group, other, mask, named = 0x01, 0x04, 0x20, 0x10, 0x02
        good = self.posix_acl((user, 7), (group, 0), (other, 0))
        bad = {
            "empty": b"",
            "short header": b"\x02\x00",
            "wrong version": b"\x03\x00\x00\x00" + good[4:],
            "partial entry": good + b"\x00",
            "unknown tag": self.posix_acl((user, 7), (group, 0), (other, 0), (0x40, 0)),
            "bad perm bits": self.posix_acl((user, 7), (group, 8), (other, 0)),
            "missing other": self.posix_acl((user, 7), (group, 0)),
            "duplicate user": self.posix_acl((user, 7), (user, 7), (group, 0), (other, 0)),
            "named without mask": self.posix_acl((user, 7), (named, 4), (group, 0), (other, 0)),
            "too many": self.posix_acl(*[(user, 7)] * 70),
        }
        for name, value in bad.items():
            for leaf in (True, False):
                with self.subTest(name=name, leaf=leaf), self.acl_outcomes(value, None):
                    with self.assertRaises(private_roots.AdmissionError) as caught:
                        private_roots._linux_acl_check(17, private_leaf=leaf)
                    self.assertEqual(caught.exception.reason, "acl-malformed")
        with self.acl_outcomes(good, None):
            private_roots._linux_acl_check(17)

    def test_linux_private_leaf_accepts_only_minimal_zero_permission_acls(self) -> None:
        user, group, other, mask, named, named_group = 0x01, 0x04, 0x20, 0x10, 0x02, 0x08
        minimal_private = self.posix_acl((user, 7), (group, 0), (other, 0))
        with self.acl_outcomes(minimal_private, minimal_private):
            private_roots._linux_acl_check(17)
        extended = {
            "group readable": (self.posix_acl((user, 7), (group, 5), (other, 0)), None, "acl-access-extended"),
            "other readable": (self.posix_acl((user, 7), (group, 0), (other, 4)), None, "acl-access-extended"),
            "named user": (self.posix_acl((user, 7), (named, 0), (group, 0), (mask, 0), (other, 0)), None, "acl-access-extended"),
            "named group": (self.posix_acl((user, 7), (named_group, 0), (group, 0), (mask, 0), (other, 0)), None, "acl-access-extended"),
            "default readable": (None, self.posix_acl((user, 7), (group, 5), (other, 5)), "acl-default-present"),
            "default named": (None, self.posix_acl((user, 7), (named, 0), (group, 0), (mask, 0), (other, 0)), "acl-default-present"),
        }
        for name, (access, default, reason) in extended.items():
            with self.subTest(name), self.acl_outcomes(access, default):
                with self.assertRaises(private_roots.AdmissionError) as caught:
                    private_roots._linux_acl_check(17)
                self.assertEqual(caught.exception.reason, reason)

    def test_linux_ancestor_default_acl_is_ignored_but_write_grants_fail(self) -> None:
        user, group, other, mask, named = 0x01, 0x04, 0x20, 0x10, 0x02
        shared_default = self.posix_acl((user, 7), (named, 5), (group, 5), (mask, 5), (other, 5))
        with self.acl_outcomes(None, shared_default):
            private_roots._linux_acl_check(17, private_leaf=False)
        readable = self.posix_acl((user, 7), (named, 5), (group, 5), (mask, 5), (other, 5))
        with self.acl_outcomes(readable, shared_default):
            private_roots._linux_acl_check(17, private_leaf=False)
        for name, entries in {
            "named user write": ((user, 7), (named, 6), (group, 5), (mask, 6), (other, 5)),
            "group write": ((user, 7), (group, 7), (other, 5)),
            "other write": ((user, 7), (group, 5), (other, 2)),
            "mask write": ((user, 7), (named, 4), (group, 5), (mask, 2), (other, 5)),
        }.items():
            with self.subTest(name), self.acl_outcomes(self.posix_acl(*entries), None):
                with self.assertRaises(private_roots.AdmissionError) as caught:
                    private_roots._linux_acl_check(17, private_leaf=False)
                self.assertEqual(caught.exception.reason, "acl-access-write-grant")

    def test_directory_walk_applies_private_leaf_rules_only_to_the_leaf(self) -> None:
        seen: list[tuple[tuple[int, int], bool]] = []

        def record(fd: int, *, private_leaf: bool = True) -> None:
            info = os.fstat(fd)
            seen.append(((info.st_dev, info.st_ino), private_leaf))

        with tempfile.TemporaryDirectory(dir=test_scratch_root()) as temporary:
            leaf = pathlib.Path(temporary).resolve() / "leaf"
            leaf.mkdir(mode=0o700)
            leaf_id = (leaf.stat().st_dev, leaf.stat().st_ino)
            with mock.patch.object(private_roots.sys, "platform", "linux"), \
                    mock.patch.object(private_roots, "_linux_acl_check", side_effect=record), \
                    mock.patch.object(private_roots, "_mount_check"):
                try:
                    fd, _identity = private_roots._open_validated_directory(leaf, private_leaf=True)
                except private_roots.AdmissionError:
                    fd = None  # host ancestors may be rejected for non-ACL reasons; ACL calls were still recorded
                else:
                    os.close(fd)
        self.assertTrue(seen)
        for identity, strict in seen:
            self.assertEqual(strict, identity == leaf_id)
        self.assertTrue(any(identity == leaf_id for identity, _ in seen) or fd is None)

    def test_new_directory_acls_are_stripped_only_on_linux_and_failures_fail_closed(self) -> None:
        removed: list[str] = []
        modes: list[int] = []
        with mock.patch.object(private_roots.sys, "platform", "linux"), \
                mock.patch.object(private_roots.os, "removexattr", side_effect=lambda fd, name: removed.append(name), create=True), \
                mock.patch.object(private_roots.os, "fchmod", side_effect=lambda fd, mode: modes.append(mode)), \
                mock.patch.object(private_roots.os, "listdir", return_value=[]), \
                mock.patch.object(private_roots, "_linux_acl_check"), \
                mock.patch.object(private_roots.os, "open", return_value=99), \
                mock.patch.object(private_roots.os, "close"):
            private_roots._strip_new_directory_acls(5, "child")
        self.assertEqual(removed, ["system.posix_acl_default", "system.posix_acl_access"])
        self.assertEqual(modes, [0o700])
        # ENODATA while removing is fine; any other error fails closed.
        def enodata(fd: int, name: str) -> None:
            raise OSError(errno.ENODATA, "none")

        def denied(fd: int, name: str) -> None:
            raise OSError(errno.EPERM, "denied")

        with mock.patch.object(private_roots.sys, "platform", "linux"), \
                mock.patch.object(private_roots.os, "fchmod"), mock.patch.object(private_roots.os, "open", return_value=99), \
                mock.patch.object(private_roots.os, "listdir", return_value=[]), mock.patch.object(private_roots, "_linux_acl_check"), \
                mock.patch.object(private_roots.os, "rmdir"), mock.patch.object(private_roots.os, "close"):
            with mock.patch.object(private_roots.os, "removexattr", side_effect=enodata, create=True):
                private_roots._strip_new_directory_acls(5, "child")
            with mock.patch.object(private_roots.os, "removexattr", side_effect=denied, create=True):
                with self.assertRaises(private_roots.AdmissionError) as caught:
                    private_roots._strip_new_directory_acls(5, "child")
        self.assertEqual(caught.exception.reason, "acl-strip-error")
        with mock.patch.object(private_roots.sys, "platform", "darwin"), \
                mock.patch.object(private_roots.os, "open") as opened:
            private_roots._strip_new_directory_acls(5, "child")
        opened.assert_not_called()

    def test_new_directory_is_removed_when_the_post_strip_recheck_fails(self) -> None:
        for name, listing, acl_error, reason in (
            ("planted entry", ["planted"], None, "acl-strip-not-empty"),
            ("non-minimal acl", [], private_roots._fail("acl-access-extended"), "acl-access-extended"),
        ):
            with self.subTest(name), mock.patch.object(private_roots.sys, "platform", "linux"), \
                    mock.patch.object(private_roots.os, "removexattr", create=True), \
                    mock.patch.object(private_roots.os, "fchmod"), mock.patch.object(private_roots.os, "open", return_value=99), \
                    mock.patch.object(private_roots.os, "listdir", return_value=listing), \
                    mock.patch.object(private_roots, "_linux_acl_check", side_effect=acl_error), \
                    mock.patch.object(private_roots.os, "rmdir") as removed, mock.patch.object(private_roots.os, "close"):
                with self.assertRaises(private_roots.AdmissionError) as caught:
                    private_roots._strip_new_directory_acls(5, "child")
                self.assertEqual(caught.exception.reason, reason)
                removed.assert_called_once_with("child", dir_fd=5)

    def test_admission_error_reason_reaches_the_ci_failure_code(self) -> None:
        from tools.release import ci_floor
        try:
            raise private_roots._fail("acl-default-present")
        except private_roots.AdmissionError as exc:
            reason = ci_floor._failure_reason(exc)
        self.assertTrue(reason.startswith("AdmissionError/acl-default-present/"), reason)

    def test_admit_empty_directory_rejects_preexisting_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            child = root / "restricted-target"
            child.mkdir(mode=0o700)
            identity = (os.stat(child).st_dev, os.stat(child).st_ino)
            fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(private_roots, "_open_validated_directory", return_value=(fd, identity)):
                private_roots.admit_empty_directory(child, identity)
            child.joinpath("unexpected").write_text("cached")
            fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY)
            with mock.patch.object(private_roots, "_open_validated_directory", return_value=(fd, identity)):
                with self.assertRaises(private_roots.AdmissionError):
                    private_roots.admit_empty_directory(child, identity)

    def test_utility_probe_error_fails_closed(self) -> None:
        with mock.patch.object(private_roots.subprocess, "Popen", side_effect=OSError("probe unavailable")):
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._bounded_utility(["/usr/sbin/diskutil", "info", "-plist", "/Volumes/test"])

    def test_utility_timeout_and_output_limit_fail_closed(self) -> None:
        with mock.patch.object(private_roots, "UTILITY_TIMEOUT_SECONDS", 0.05):
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._bounded_utility(["/bin/sleep", "2"])
        with mock.patch.object(private_roots, "UTILITY_OUTPUT_LIMIT", 128):
            with self.assertRaises(private_roots.AdmissionError):
                private_roots._bounded_utility(["/usr/bin/yes"])

    def test_preflight_rejects_symlink_and_preexisting_restricted_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(private_roots.AdmissionError):
                private_roots.preflight_directory(link / "child", must_be_absent=True)
            with self.assertRaises(FileExistsError):
                private_roots.preflight_directory(real, must_be_absent=True)

    def test_run_admission_rejection_precedes_all_cache_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            cache = root / "cache-must-not-be-created"
            args = Namespace(repo=str(repo), base=base, label="P00-admission-test", cache_root=str(cache), command_timeout=1)
            reject = private_roots.AdmissionError("private cache admission failed")
            with mock.patch.object(private_roots, "preflight_directory", side_effect=reject), \
                    mock.patch.object(pathlib.Path, "mkdir", side_effect=AssertionError("mkdir called")), \
                    mock.patch.object(os, "mkdir", side_effect=AssertionError("os.mkdir called")), \
                    mock.patch.object(os, "chmod", side_effect=AssertionError("chmod called")), \
                    mock.patch.object(run_gates, "_atomic_write", side_effect=AssertionError("private write called")):
                with self.assertRaises(private_roots.AdmissionError):
                    run_gates.run(args)
            self.assertFalse(cache.exists())

    def test_preexisting_restricted_target_stops_before_cache_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            cache = root / "cache-must-not-be-created"
            args = Namespace(repo=str(repo), base=base, label="P00-fresh-target", cache_root=str(cache), command_timeout=1)
            target = cache / f"cargo-target-restricted-{args.label}"

            def reject_existing_target(path: pathlib.Path, **kwargs: object) -> None:
                del kwargs
                if pathlib.Path(path) == target:
                    raise FileExistsError("private run directory already exists")

            with mock.patch.object(private_roots, "preflight_directory", side_effect=reject_existing_target), \
                    mock.patch.object(pathlib.Path, "mkdir", side_effect=AssertionError("mkdir called")), \
                    mock.patch.object(os, "mkdir", side_effect=AssertionError("os.mkdir called")), \
                    mock.patch.object(os, "chmod", side_effect=AssertionError("chmod called")), \
                    mock.patch.object(run_gates, "_atomic_write", side_effect=AssertionError("private write called")):
                with self.assertRaises(FileExistsError):
                    run_gates.run(args)
            self.assertFalse(cache.exists())


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()



def own_process_snapshot(extra_pids=lambda: ()):
    """Return a `_process_snapshot` replacement that only shows this test's own processes.

    The runner's ownership scan is deliberately global, so on a shared machine (a hosted
    runner or a developer Mac) any unrelated process that starts while a test runs becomes
    an unknown candidate and makes tests that assert exact candidate counts or a clean
    rescan flaky. This wrapper keeps the real `ps` snapshot but filters it to the test
    process, every process ever seen descending from it, and any pid the test names through
    `extra_pids` (for deliberately detached children that are reparented away). The runner
    code, its deadlines and its checks are untouched; only the machine-wide noise input is
    removed.
    """
    real_snapshot = run_gates._process_snapshot
    lock = threading.Lock()
    mine: dict[int, str] = {}

    def snapshot(*, timeout: float = 2.0) -> dict[int, tuple[int, str, str]]:
        full = real_snapshot(timeout=timeout)
        with lock:
            me = os.getpid()
            if me in full:
                mine[me] = full[me][1]
            for pid in extra_pids():
                if pid in full:
                    mine.setdefault(pid, full[pid][1])
            changed = True
            while changed:
                changed = False
                for pid, (ppid, started_at, _state) in full.items():
                    if pid not in mine and ppid in mine and full[ppid][1] == mine[ppid]:
                        mine[pid] = started_at
                        changed = True
            return {pid: record for pid, record in full.items() if mine.get(pid) == record[1]}

    return snapshot


def process_running(pid: int) -> bool:
    record = run_gates._process_snapshot().get(pid)
    return record is not None and record[2] not in {"Z", "X"}


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name) / "evidence"
        self.root.mkdir()
        self.ledger = pathlib.Path(self.temp.name) / "requirements.json"
        self.candidate = "a" * 40
        self._write("trust/keys.json", {"schemaVersion": 1, "keys": []})
        contracts = check_ledger.load_pinned_contracts()
        release_bytes = self._write("artifacts/release.tar", b"accepted release package")
        release_entries = [{"path": "artifacts/release.tar", "sha256": digest(release_bytes), "platform": "universal"}]
        artifact_digest_rows = [{key: row[key] for key in ("path", "sha256", "platform")} for row in release_entries]
        artifact_digest_rows.sort(key=lambda item: (item.get("platform", ""), item["path"], item["sha256"]))
        self.ledger.write_text(json.dumps({
            "schemaVersion": 1,
            "candidateSha": self.candidate,
            "releaseBuild": {
                "id": "release-1", "sourceSha": self.candidate, "state": "accepted",
                "artifacts": release_entries,
                "artifactSetSha256": digest(check_ledger.canonical_json(artifact_digest_rows)),
            },
            "requirements": [
                {**contracts[requirement_id], "state": "pending", "receipts": []}
                for requirement_id in sorted(contracts)
            ],
        }))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, name: str, value: object) -> bytes:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
        path.write_bytes(data)
        return data

    def _receipt(self, receipt: dict[str, object]) -> dict[str, str]:
        raw = self._write("receipts/one.json", receipt)
        return {"path": "receipts/one.json", "sha256": digest(raw)}

    def _ledger(self) -> dict[str, object]:
        return json.loads(self.ledger.read_text())

    def _java_row(self, ledger: dict[str, object]) -> dict[str, object]:
        return next(row for row in ledger["requirements"] if row["id"] == "JAVA-LAUNCH")

    def test_pending_and_missing_mandatory_receipt_fail_closed(self) -> None:
        with self.assertRaisesRegex(check_ledger.ValidationError, "pending, missing"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_omitted_requirement_row_fails_closed(self) -> None:
        ledger = self._ledger()
        ledger["requirements"] = [row for row in ledger["requirements"] if row["id"] != "HUMAN-OWNER"]
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "requirement set differs"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_mandatory_requirement_downgrade_fails_closed(self) -> None:
        ledger = self._ledger()
        next(row for row in ledger["requirements"] if row["id"] == "HUMAN-OWNER")["mandatory"] = False
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "downgraded"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_requirement_text_or_approved_slice_cannot_be_weakened(self) -> None:
        ledger = self._ledger()
        next(row for row in ledger["requirements"] if row["id"] == "HUMAN-OWNER")["requirement"] = "Do a quick review"
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "requirement text or slice changed"):
            check_ledger.check(self.ledger, self.root, self.candidate, "trust/keys.json")

    def test_pinned_requirement_contract_file_digest_is_enforced(self) -> None:
        altered = pathlib.Path(self.temp.name) / "approved-requirements.json"
        source = json.loads(check_ledger.PINNED_CONTRACTS_PATH.read_text())
        source["requirements"][0]["requirement"] += " (weakened)"
        altered.write_text(json.dumps(source))
        with mock.patch.object(check_ledger, "PINNED_CONTRACTS_PATH", altered):
            with self.assertRaisesRegex(check_ledger.ValidationError, "semantics differ"):
                check_ledger.load_pinned_contracts()

    def test_trust_config_rejects_public_key_aliases(self) -> None:
        version = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=False)
        if version.returncode:
            self.skipTest("OpenSSL is required for trust-key normalization")
        private = pathlib.Path(self.temp.name) / "private.pem"
        public = self.root / "trust/key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        key_bytes = public.read_bytes()
        entry = {"roles": ["reviewer"], "publicKey": "trust/key.pem", "publicKeySha256": digest(key_bytes)}
        self._write("trust/keys.json", {"schemaVersion": 1, "keys": [{"id": "reviewer-a", **entry}, {"id": "reviewer-b", **entry}]})
        with self.assertRaisesRegex(check_ledger.ValidationError, "aliases one public key"):
            check_ledger._trust_config(self.root, "trust/keys.json")

    def test_receipts_must_join_the_single_release_build_and_artifact_set(self) -> None:
        ledger = self._ledger()
        release_build, accepted_hashes = check_ledger.validate_release_build(self.root, self.candidate, ledger["releaseBuild"])
        wrong = self._write("artifacts/unreviewed.tar", b"unreviewed package")
        evidence = self._write("evidence/build.log", b"build evidence")
        receipt = {
            "schemaVersion": 1, "requirementId": "JAVA-LAUNCH", "kind": "phase", "result": "passed",
            "candidateSha": self.candidate,
            "build": {"id": release_build["id"], "sourceSha": self.candidate, "artifactSetSha256": release_build["artifactSetSha256"]},
            "artifacts": [{"path": "artifacts/unreviewed.tar", "sha256": digest(wrong)}],
            "evidence": [{"path": "evidence/build.log", "sha256": digest(evidence)}],
            "checks": [{"status": "passed", "reached": True}], "attestation": {},
        }
        ref = self._receipt(receipt)
        with self.assertRaisesRegex(check_ledger.ValidationError, "outside the accepted release artifact set"):
            check_ledger.validate_receipt(self.root, ref, "JAVA-LAUNCH", self.candidate, {}, release_build, accepted_hashes)
        receipt["artifacts"] = [{"path": "artifacts/release.tar", "sha256": next(iter(accepted_hashes))}]
        receipt["build"]["id"] = "other-build"
        ref = self._receipt(receipt)
        with self.assertRaisesRegex(check_ledger.ValidationError, "different logical release build"):
            check_ledger.validate_receipt(self.root, ref, "JAVA-LAUNCH", self.candidate, {}, release_build, accepted_hashes)

    def test_platform_receipt_uses_matching_declared_package_from_release_set(self) -> None:
        package = self._write("artifacts/linux.tar", b"Linux x86_64 package")
        ref = {"path": "artifacts/linux.tar", "sha256": digest(package)}
        attestation = {
            "artifacts": [ref],
            "platform": {"os": "Linux", "architecture": "x86_64", "freshProfileInstall": True, "packageSha256": digest(package)},
        }
        check_ledger._validate_special(self.root, "PLATFORM-LINUX", attestation, {digest(package): {"linux-x86_64"}})
        with self.assertRaisesRegex(check_ledger.ValidationError, "package artifact"):
            check_ledger._validate_special(self.root, "PLATFORM-LINUX", attestation, {digest(package): {"macos-arm64"}})

    def test_supply_chain_special_receipt_accepts_hashed_inventory_fields(self) -> None:
        fields = ("sbom", "licenses", "notices", "advisories", "checksums", "provenance")
        supply_chain = {}
        for field in fields:
            raw = self._write(f"supply-chain/{field}.json", f"{field} reviewed\n".encode())
            supply_chain[field] = {"path": f"supply-chain/{field}.json", "sha256": digest(raw)}
        check_ledger._validate_special(self.root, "SUPPLY-CHAIN", {"artifacts": [], "supplyChainArtifacts": supply_chain})

    def test_path_traversal_receipt_is_rejected_before_read(self) -> None:
        ledger = self._ledger()
        self._java_row(ledger).update({"state": "accepted", "receipts": [{"path": "../outside.json", "sha256": "0" * 64}]})
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "escapes"):
            check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {})

    def test_stale_candidate_receipt_is_rejected(self) -> None:
        ledger = self._ledger()
        bad = self._receipt({
            "schemaVersion": 1, "requirementId": "JAVA-LAUNCH", "kind": "phase", "result": "passed",
            "candidateSha": "b" * 40, "build": {"id": "build-1", "sourceSha": "b" * 40},
        })
        self._java_row(ledger).update({"state": "accepted", "receipts": [bad]})
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "stale for this candidate"):
            check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {})

    def test_hash_tampered_receipt_fails(self) -> None:
        ledger = self._ledger()
        self._java_row(ledger).update({"state": "accepted", "receipts": [{"path": "receipts/missing.json", "sha256": "0" * 64}]})
        self.ledger.write_text(json.dumps(ledger))
        with self.assertRaisesRegex(check_ledger.ValidationError, "missing, unreadable"):
            check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {})

    def test_forged_signature_claim_fails_cryptographic_verification(self) -> None:
        public = self._write("trust/pub.pem", b"not a valid public key\n")
        self._write("trust/keys.json", {"schemaVersion": 1, "keys": [{"id": "reviewer", "roles": ["reviewer"], "publicKey": "trust/pub.pem", "publicKeySha256": digest(public)}]})
        attestation = {"scope": "candidate"}
        signature = self._write("signatures/fake.sig", b"forged")
        evidence = self._write("evidence/log.txt", b"real evidence bytes")
        artifact = self._write("artifacts/app.tar", b"candidate artifact")
        receipt = {
            "schemaVersion": 1, "requirementId": "JAVA-LAUNCH", "kind": "phase", "result": "passed",
            "candidateSha": self.candidate, "build": {"id": "build-1", "sourceSha": self.candidate},
            "artifacts": [{"path": "artifacts/app.tar", "sha256": digest(artifact)}],
            "evidence": [{"path": "evidence/log.txt", "sha256": digest(evidence)}],
            "checks": [{"status": "passed", "reached": True}], "attestation": attestation,
            "signatures": [{"keyId": "reviewer", "role": "reviewer", "path": "signatures/fake.sig", "sha256": digest(signature)}],
        }
        ledger = self._ledger()
        self._java_row(ledger).update({"state": "accepted", "receipts": [self._receipt(receipt)]})
        self.ledger.write_text(json.dumps(ledger))
        failed = subprocess.CompletedProcess(["openssl"], 1, b"", b"signature verification failed")
        seen_payloads: list[bytes] = []

        def reject_and_capture(argv: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
            seen_payloads.append(pathlib.Path(argv[argv.index("-in") + 1]).read_bytes())
            return failed

        with mock.patch.object(check_ledger.subprocess, "run", side_effect=reject_and_capture) as verifier:
            with self.assertRaisesRegex(check_ledger.ValidationError, "signature verification failed"):
                check_ledger.validate_receipt(self.root, self._java_row(ledger)["receipts"][0], "JAVA-LAUNCH", self.candidate, {"reviewer": {"roles": ["reviewer"], "path": "trust/pub.pem", "sha256": digest(public)}})
        self.assertEqual(verifier.call_args.args[0][0], "openssl")
        self.assertIn(b'"candidateSha":"' + self.candidate.encode(), seen_payloads[0])
        self.assertIn(b'"build":{"id":"build-1"', seen_payloads[0])

    def test_symlink_reference_fails_closed(self) -> None:
        outside = pathlib.Path(self.temp.name) / "outside.log"
        outside.write_text("secret")
        link = self.root / "evidence" / "linked.log"
        link.parent.mkdir()
        link.symlink_to(outside)
        with self.assertRaisesRegex(check_ledger.ValidationError, "symlink"):
            check_ledger.read_evidence(self.root, "evidence/linked.log", digest(b"secret"))

    def test_missing_hash_and_duplicate_json_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(check_ledger.ValidationError, "missing its SHA-256"):
            check_ledger.read_evidence(self.root, "missing.log")
        with self.assertRaisesRegex(check_ledger.ValidationError, "duplicate JSON key"):
            check_ledger._load_json(b'{"candidateSha":"a","candidateSha":"b"}', "receipt")

    def test_usability_observation_rejects_blank_identity_boolean_time_and_nonfinite_time(self) -> None:
        journey = self._write("study/journey.log", b"observed journey")
        scoring = self._write("study/scoring.log", b"scoring notes")
        refs = {
            "journey": {"path": "study/journey.log", "sha256": digest(journey)},
            "scoring": {"path": "study/scoring.log", "sha256": digest(scoring)},
        }
        for participant_id, elapsed in (("", 10), ([], 10), ("p1", True), ("p1", float("inf"))):
            with self.subTest(participant_id=participant_id, elapsed=elapsed):
                with self.assertRaises(check_ledger.ValidationError):
                    check_ledger._validate_special(self.root, "HUMAN-USABILITY", {
                        "participants": [
                            {"participantId": participant_id, "elapsedSeconds": elapsed, "correct": True, **refs},
                            {"participantId": "p2", "elapsedSeconds": 10, "correct": True, **refs},
                        ],
                    })

    def test_openssl_signature_verifies_and_payload_tamper_fails(self) -> None:
        version = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=False)
        if version.returncode or "OpenSSL 3" not in version.stdout:
            self.skipTest("OpenSSL 3 is needed for the detached-signature integration check")
        private = self.root / "trust/private.pem"
        public = self.root / "trust/public.pem"
        signature = self.root / "signatures/attestation.sig"
        payload_file = self.root / "signatures/payload.json"
        for path in (private, public, signature, payload_file):
            path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        payload = check_ledger.canonical_json({"candidateSha": self.candidate, "build": {"id": "build-1"}})
        payload_file.write_bytes(payload)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(payload_file), "-out", str(signature)], check=True, capture_output=True)
        public_bytes, signature_bytes = public.read_bytes(), signature.read_bytes()
        self._write("trust/public.pem", public_bytes)
        self._write("signatures/attestation.sig", signature_bytes)
        trust = {"reviewer": {"roles": ["reviewer"], "path": "trust/public.pem", "sha256": digest(public_bytes)}}
        self.assertEqual(
            check_ledger._verify_signature(self.root, trust, {"keyId": "reviewer", "role": "reviewer", "path": "signatures/attestation.sig", "sha256": digest(signature_bytes)}, payload),
            ("reviewer", "reviewer"),
        )
        with self.assertRaisesRegex(check_ledger.ValidationError, "signature verification failed"):
            check_ledger._verify_signature(self.root, trust, {"keyId": "reviewer", "role": "reviewer", "path": "signatures/attestation.sig", "sha256": digest(signature_bytes)}, payload + b"tampered")


EXPECTED_UNKNOWN = run_gates.EXPECTED_UNINSPECTABLE_SCAN


def _unknown(pid: int, start: str | None = None, reason: str = "missing-process-record-after-all-fd-fallback") -> dict[str, object]:
    return {
        "pid": pid, "startedAt": start or _lstart(pid), "observedParentPid": 1,
        "descriptorStatus": "uninspectable", "reason": reason,
    }


def _ident(record: dict[str, object]) -> tuple[int, str]:
    return (record["pid"], record["startedAt"])  # type: ignore[return-value]


def _unknown_scan(*items: dict[str, object], clean: tuple[tuple[int, str], ...] = ()) -> run_gates.UntrackedProcessScan:
    return run_gates.UntrackedProcessScan([], list(items), EXPECTED_UNKNOWN, len(items), [], frozenset(clean))


def _quiet_scan(clean: tuple[tuple[int, str], ...] = ()) -> run_gates.UntrackedProcessScan:
    return run_gates.UntrackedProcessScan([], [], None, 0, [], frozenset(clean))


def _live(*items: dict[str, object]) -> dict[int, tuple[int, str, str]]:
    return {item["pid"]: (1, item["startedAt"], "S") for item in items}  # type: ignore[misc]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class Script:
    """Scripted (snapshot, scan) results; the last step repeats. Each call
    advances the fake clock a little so nothing can spin without time passing."""

    def __init__(self, clock: FakeClock, steps: list[tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]]) -> None:
        self.clock = clock
        self.steps = steps
        self.calls = 0

    def __call__(self, _deadline: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
        step = self.steps[min(self.calls, len(self.steps) - 1)]
        self.calls += 1
        self.clock.now += 0.01
        return step


class SettleAndGlobalQuiescenceTests(unittest.TestCase):
    """Pure-logic coverage of settling, global quiescence and bounded evidence."""

    def settle(self, initial, script, clock, **kwargs):  # type: ignore[no-untyped-def]
        return run_gates._settle_uninspectable_candidates(
            initial, script, duration=kwargs.pop("duration", 4), interval=1,
            monotonic=clock.monotonic, sleep=clock.sleep, **kwargs,
        )

    def global_scan(self, script, clock, *, deadline=10.0, owned=lambda _s: [], **kwargs):  # type: ignore[no-untyped-def]
        return run_gates._final_global_quiescence_scan(
            deadline, script, owned, monotonic=clock.monotonic, sleep=clock.sleep, **kwargs,
        )

    # Rule 1: initial PID+start identity must exit or be positively classified.
    def test_later_clean_scan_alone_never_clears_live_initial_identity(self) -> None:
        clock = FakeClock()
        initial = _unknown(4242)
        script = Script(clock, [(_live(initial), _quiet_scan())])
        result = self.settle([initial], script, clock, duration=3)
        self.assertFalse(result.cleared)
        self.assertEqual(result.last_error, "initial uninspectable process identity survived settling deadline")

    def test_positive_classification_clears_live_initial_identity(self) -> None:
        clock = FakeClock()
        initial = _unknown(4242)
        script = Script(clock, [(_live(initial), _quiet_scan(clean=(_ident(initial),)))])
        result = self.settle([initial], script, clock)
        self.assertTrue(result.cleared)
        self.assertEqual(result.poll_count, 1)

    def test_positive_classification_of_a_different_identity_does_not_clear_initial(self) -> None:
        clock = FakeClock()
        initial = _unknown(4242)
        other = _unknown(4243)
        script = Script(clock, [(_live(initial, other), _quiet_scan(clean=(_ident(other),)))])
        self.assertFalse(self.settle([initial], script, clock, duration=3).cleared)

    def test_pid_reuse_with_new_start_does_not_keep_initial_identity_alive(self) -> None:
        clock = FakeClock()
        initial = _unknown(4242, "old-start")
        reused = _unknown(4242, "new-start")
        script = Script(clock, [(_live(reused), _unknown_scan(reused))])
        result = self.settle([initial], script, clock)
        self.assertTrue(result.cleared, "the exact initial identity exited; the reuse is later churn")
        self.assertEqual({_ident(item) for item in result.identity_union}, {_ident(initial), _ident(reused)})

    def test_settle_clears_on_initial_exit_and_keeps_later_unknown_in_union(self) -> None:
        clock = FakeClock()
        initial, late = _unknown(4242), _unknown(9001)
        script = Script(clock, [(_live(late), _unknown_scan(late))])
        result = self.settle([initial], script, clock)
        self.assertTrue(result.cleared)
        self.assertEqual(result.identity_union_count, 2)
        self.assertFalse(result.identity_union_truncated)

    def test_settle_fails_closed_for_every_unsafe_scan_shape(self) -> None:
        initial = _unknown(4242)
        held = {"pid": 9, "startedAt": "held-start", "descriptorStatus": "held", "reason": "private-log-descriptor-observed"}
        cases = {
            "coverage is incomplete": (_live(initial), run_gates.UntrackedProcessScan([], [initial], EXPECTED_UNKNOWN, 2), None),
            "held descriptor": (_live(initial), run_gates.UntrackedProcessScan([held], [initial], EXPECTED_UNKNOWN, 2), None),
            "owned probe": (_live(initial), run_gates.UntrackedProcessScan([], [initial], EXPECTED_UNKNOWN, 1, [{"pid": 8}]), None),
            "inconsistent": (_live(initial), run_gates.UntrackedProcessScan([], [initial], None, 1), None),
            "inconsistent ": (_live(initial), run_gates.UntrackedProcessScan([], [], EXPECTED_UNKNOWN, 0), None),
            "malformed": (_live(initial), run_gates.UntrackedProcessScan([], [{"pid": "x", "startedAt": "s", "descriptorStatus": "uninspectable"}], EXPECTED_UNKNOWN, 1), None),
            "scanner unavailable": ({}, run_gates.UntrackedProcessScan([], [], "scanner unavailable", 0), None),
            "owned process appeared": ({}, _quiet_scan(), lambda _snapshot: [77]),
        }
        for expected, (snapshot, scan, owned) in cases.items():
            with self.subTest(expected):
                clock = FakeClock()
                result = self.settle([initial], Script(clock, [(snapshot, scan)]), clock, owned_alive=owned)
                self.assertFalse(result.cleared)
                self.assertIn(expected.strip(), result.last_error or "")

    def test_settle_rejects_missing_or_malformed_initial_identity(self) -> None:
        for initial in ([], [{"pid": True, "startedAt": "s", "descriptorStatus": "uninspectable"}],
                        [{"pid": 5, "startedAt": "", "descriptorStatus": "uninspectable"}], [_unknown(5), _unknown(5)]):
            with self.subTest(initial=initial):
                clock = FakeClock()
                result = self.settle(initial, Script(clock, [({}, _quiet_scan())]), clock)
                self.assertFalse(result.cleared)
                self.assertEqual(result.poll_count, 0)

    # Rule 2: production candidates originate in the supplied snapshot only.
    def test_untracked_scan_candidates_originate_only_in_supplied_snapshot(self) -> None:
        start = "Sun Oct  4 21:00:00 2026"
        supplied = {7001: (1, start, "S")}
        clean_pids: set[int] = set()

        def fake_lsof(arguments: list[str], _deadline: float) -> run_gates.LsofProbe:
            pids = [int(item) for item in arguments[-1].split(",")]
            body = "".join(f"p{pid}\nf1\nn/dev/null\n" for pid in pids if pid in clean_pids)
            return run_gates.LsofProbe(0, body, "")

        real_is_dir = pathlib.Path.is_dir

        def fake_is_dir(path: pathlib.Path) -> bool:
            return False if str(path) == "/proc" else real_is_dir(path)

        def scan(baseline: dict, snapshot: dict, recheck: dict, owned: dict | None = None) -> run_gates.UntrackedProcessScan:
            with mock.patch.object(run_gates, "LSOF_BINARY", "/test/lsof"), \
                    mock.patch.object(run_gates, "_run_lsof_fields", side_effect=fake_lsof) as lsof, \
                    mock.patch.object(pathlib.Path, "is_dir", fake_is_dir), \
                    mock.patch.object(run_gates, "_process_snapshot", return_value=recheck):
                result = run_gates._untracked_processes_since(baseline, owned or {}, snapshot, pathlib.Path("/nonexistent/gate.log"))
                del lsof
                return result

        # An identity that exists only in a re-snapshot is never invented.
        result = scan({}, {}, {7001: (1, start, "S")})
        self.assertEqual((result.candidate_count, result.uninspectable, result.error), (0, [], None))
        # A supplied-snapshot candidate with no descriptor record is the exact unknown identity.
        result = scan({}, supplied, supplied)
        self.assertEqual([_ident(item) for item in result.uninspectable], [(7001, start)])
        self.assertEqual(result.error, EXPECTED_UNKNOWN)
        self.assertEqual(result.clean_identities, frozenset())
        # The re-check may remove a candidate (natural exit) but never adds one.
        result = scan({}, supplied, {})
        self.assertEqual((result.candidate_count, result.uninspectable), (0, []))
        result = scan({}, supplied, {7001: (1, "reused-start", "S"), 7002: (1, start, "S")})
        self.assertEqual((result.candidate_count, result.uninspectable), (0, []))
        # Zombie or exited states are not live candidates.
        result = scan({}, {7001: (1, start, "Z")}, {})
        self.assertEqual(result.candidate_count, 0)
        # A candidate with a positive descriptor record is positively classified.
        clean_pids.add(7001)
        result = scan({}, supplied, supplied)
        self.assertEqual((result.uninspectable, result.error), ([], None))
        self.assertEqual(result.clean_identities, frozenset({(7001, start)}))
        # Baseline and owned identities are not candidates.
        result = scan({7001: (1, start, "S")}, supplied, supplied)
        self.assertEqual(result.candidate_count, 0)
        result = scan({}, supplied, supplied, {7001: start})
        self.assertEqual(result.candidate_count, 0)

    # Rule 4: bounded union.
    def test_union_bounds_hostile_input_before_processing(self) -> None:
        touched = [0]

        class Counting(dict):
            def get(self, *args: object) -> object:
                touched[0] += 1
                return super().get(*args)

        records = [
            Counting(pid=index + 1, startedAt=f"s{index}", descriptorStatus="uninspectable", reason="r" * 10_000)
            for index in range(100_000)
        ]
        union = run_gates.UnconfirmedIdentityUnion()
        error = union.add(records)
        self.assertIsNotNone(error)
        self.assertLessEqual(touched[0], run_gates.MAX_UNION_INPUT_RECORDS * 6, "input is bounded before processing")
        self.assertEqual(len(union.sample), run_gates.MAX_UNCONFIRMED_SAMPLE)
        self.assertEqual(union.count, 100_000, "total stays truthful even when input is refused")
        self.assertTrue(union.truncated)
        self.assertTrue(all(len(item["reason"]) <= run_gates.MAX_REASON_CHARS for item in union.sample))
        self.assertLess(len(json.dumps(union.sample)), 64 * 1024)

    def test_union_malformed_records_never_serialize_or_store_raw_values(self) -> None:
        union = run_gates.UnconfirmedIdentityUnion()
        huge = "x" * 5_000_000
        junk = [
            "not-a-record", 7, None, {"pid": True, "startedAt": "s", "descriptorStatus": "uninspectable"},
            {"pid": -1, "startedAt": "s", "descriptorStatus": "uninspectable"},
            {"pid": 5, "startedAt": huge, "descriptorStatus": "uninspectable", "reason": huge},
            {"pid": 6, "startedAt": "s", "descriptorStatus": "weird", "reason": 12},
        ]
        error = union.add(junk)
        self.assertIn("malformed", error or "")
        self.assertLess(len(json.dumps(union.sample)), 4096)
        self.assertTrue(all(
            len(value) <= run_gates.MAX_REASON_CHARS for item in union.sample for value in item.values() if isinstance(value, str)
        ))
        self.assertLessEqual(union.count, len(junk))
        self.assertIsNotNone(run_gates.UnconfirmedIdentityUnion().add("not-a-list"))

    def test_union_dedups_exact_identity_and_flags_dedup_overflow(self) -> None:
        union = run_gates.UnconfirmedIdentityUnion()
        self.assertIsNone(union.add([_unknown(5), _unknown(5)]))
        self.assertIsNone(union.add([_unknown(5)]))
        self.assertEqual((union.count, len(union.sample), union.truncated), (1, 1, False))
        self.assertIsNone(union.add([_unknown(5, "other-start")]))
        self.assertEqual(union.count, 2)
        full = run_gates.UnconfirmedIdentityUnion()
        for chunk in range(0, run_gates.MAX_UNION_KEYS + 10, 50):
            error = full.add([_unknown(pid) for pid in range(chunk + 1, chunk + 51)])
        self.assertIn("exceeded", error or "")
        self.assertTrue(full.truncated)
        self.assertGreaterEqual(full.count, run_gates.MAX_UNION_KEYS)

    def test_bounded_unconfirmed_reports_truthful_total_and_truncation(self) -> None:
        sample, count, truncated = run_gates._bounded_unconfirmed([_unknown(pid) for pid in range(1, 71)])
        self.assertEqual((len(sample), count, truncated), (64, 70, True))
        sample, count, truncated = run_gates._bounded_unconfirmed([_unknown(1)])
        self.assertEqual((len(sample), count, truncated), (1, 1, False))

    # Global quiescence: the c8e549d churn scenario and its fail-closed variants.
    def test_new_unknown_in_first_global_rescan_then_natural_exit_needs_two_quiet_scans(self) -> None:
        clock = FakeClock()
        new = _unknown(9002)
        script = Script(clock, [(_live(new), _unknown_scan(new)), ({}, _quiet_scan()), ({}, _quiet_scan())])
        union = run_gates.UnconfirmedIdentityUnion()
        cleared, latest, error, count = self.global_scan(script, clock, identity_union=union)
        self.assertTrue(cleared, error)
        self.assertEqual(count, 3, "one churn scan plus two subsequent full quiet scans")
        self.assertEqual(latest, [])
        self.assertEqual([_ident(item) for item in union.sample], [_ident(new)])
        self.assertLess(clock.now, 10.0, "same absolute budget")

    def test_new_unknown_after_first_quiet_scan_restarts_the_quiet_count(self) -> None:
        clock = FakeClock()
        first, second = _unknown(9002), _unknown(9003)
        script = Script(clock, [
            (_live(first), _unknown_scan(first)), ({}, _quiet_scan()),
            (_live(second), _unknown_scan(second)), ({}, _quiet_scan()), ({}, _quiet_scan()),
        ])
        cleared, _latest, error, count = self.global_scan(script, clock)
        self.assertTrue(cleared, error)
        self.assertEqual(count, 5)

    def test_unknown_that_stays_live_fails_closed_at_the_original_deadline(self) -> None:
        clock = FakeClock()
        stuck = _unknown(9002)
        script = Script(clock, [(_live(stuck), _unknown_scan(stuck))])
        union = run_gates.UnconfirmedIdentityUnion()
        cleared, latest, error, count = self.global_scan(script, clock, deadline=5.0, identity_union=union)
        self.assertFalse(cleared)
        self.assertIn("unresolved", error or "")
        self.assertEqual(latest, [stuck])
        self.assertGreater(count, 2)
        self.assertEqual(union.count, 1, "the same identity is deduplicated")
        self.assertGreaterEqual(clock.now, 4.9)
        self.assertLessEqual(clock.now, 5.1, "the deadline is not extended")

    def test_global_pending_identity_must_exit_or_be_positively_classified(self) -> None:
        stuck = _unknown(9002)
        # Live and merely absent from the unknown list is not enough.
        clock = FakeClock()
        script = Script(clock, [(_live(stuck), _quiet_scan())])
        cleared, _l, error, _c = self.global_scan(script, clock, deadline=4.0, pending_identities={_ident(stuck)})
        self.assertFalse(cleared)
        self.assertIn("unresolved", error or "")
        # Positive classification resolves it.
        clock = FakeClock()
        script = Script(clock, [(_live(stuck), _quiet_scan(clean=(_ident(stuck),)))])
        cleared, _l, error, count = self.global_scan(script, clock, pending_identities={_ident(stuck)})
        self.assertTrue(cleared, error)
        self.assertEqual(count, 2)
        # An unknown that becomes positively classified later also resolves.
        clock = FakeClock()
        script = Script(clock, [(_live(stuck), _unknown_scan(stuck)), (_live(stuck), _quiet_scan(clean=(_ident(stuck),)))])
        cleared, _l, error, count = self.global_scan(script, clock)
        self.assertTrue(cleared, error)
        self.assertEqual(count, 3)

    def test_global_fails_closed_for_every_unsafe_scan_shape(self) -> None:
        stuck = _unknown(9002)
        held = {"pid": 9, "startedAt": "held-start", "descriptorStatus": "held", "reason": "private-log-descriptor-observed"}
        cases = {
            "live unconfirmed candidate": run_gates.UntrackedProcessScan([held], [], None, 1),
            "live unconfirmed candidate ": run_gates.UntrackedProcessScan([], [], None, 0, [{"pid": 8}]),
            "coverage is incomplete": run_gates.UntrackedProcessScan([], [stuck], EXPECTED_UNKNOWN, 3),
            "late scanner error": run_gates.UntrackedProcessScan([], [], "late scanner error", 0),
            "inconsistent": run_gates.UntrackedProcessScan([], [stuck], None, 1),
            "malformed": run_gates.UntrackedProcessScan([], [{"pid": 0, "startedAt": "s", "descriptorStatus": "uninspectable"}], EXPECTED_UNKNOWN, 1),
        }
        for expected, scan in cases.items():
            with self.subTest(expected):
                clock = FakeClock()
                cleared, _latest, error, count = self.global_scan(Script(clock, [(_live(stuck), scan)]), clock)
                self.assertFalse(cleared)
                self.assertIn(expected.strip(), error or "")
                self.assertEqual(count, 1)
        clock = FakeClock()
        cleared, _latest, error, _count = self.global_scan(
            Script(clock, [({}, _quiet_scan())]), clock, owned=lambda _snapshot: [733],
        )
        self.assertFalse(cleared)
        self.assertIn("owned process", error or "")

    def test_global_union_overflow_across_churn_fails_closed(self) -> None:
        clock = FakeClock()
        steps = []
        for pid in range(1, 80):
            item = _unknown(pid)
            steps.append((_live(item), _unknown_scan(item)))
        union = run_gates.UnconfirmedIdentityUnion()
        cleared, _latest, error, _count = self.global_scan(Script(clock, steps), clock, deadline=1000.0, identity_union=union)
        self.assertFalse(cleared)
        self.assertIn("exceeded", error or "")
        self.assertTrue(union.truncated)
        self.assertEqual(len(union.sample), run_gates.MAX_UNCONFIRMED_SAMPLE)

    def test_global_and_settle_iteration_are_bounded_even_without_time_passing(self) -> None:
        stuck = _unknown(9002)
        calls = [0]

        def frozen(_deadline: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
            calls[0] += 1
            return _live(stuck), _unknown_scan(stuck)

        with mock.patch.object(run_gates, "MAX_SETTLE_ITERATIONS", 5):
            cleared, _l, error, count = run_gates._final_global_quiescence_scan(
                100.0, frozen, lambda _s: [], monotonic=lambda: 0.0, sleep=lambda _s: None,
            )
            self.assertFalse(cleared)
            self.assertIn("iteration limit", error or "")
            self.assertEqual(count, 5)
            result = run_gates._settle_uninspectable_candidates(
                [stuck], frozen, duration=100, monotonic=lambda: 0.0, sleep=lambda _s: None,
            )
            self.assertFalse(result.cleared)
            self.assertEqual(result.poll_count, 5)

    def test_eligibility_requires_complete_well_formed_expected_unknowns(self) -> None:
        good = _unknown(5)
        self.assertTrue(run_gates._natural_exit_settle_eligible(
            _unknown_scan(good), tree_confirmed_drained=True, log_io_failed=False,
        ))
        for scan in (
            run_gates.UntrackedProcessScan([], [good], EXPECTED_UNKNOWN, 2),
            _unknown_scan({"pid": "5", "startedAt": "s", "descriptorStatus": "uninspectable"}),
            _unknown_scan({"pid": 5, "startedAt": "s" * 500, "descriptorStatus": "uninspectable"}),
            _unknown_scan("not-a-dict"),  # type: ignore[arg-type]
        ):
            self.assertFalse(run_gates._natural_exit_settle_eligible(
                scan, tree_confirmed_drained=True, log_io_failed=False,
            ))

    # Rule 3: probe and cleanup-exception evidence.
    def test_probe_evidence_records_exceptions_and_probes_before_absorption(self) -> None:
        evidence = run_gates.ProbeEvidence()
        evidence.add_exception(run_gates.UncertainProbeCleanup({"pid": 11, "startedAt": "p-start", "processGroupId": 11}))
        evidence.add_exception(run_gates.InterruptedProbeCleanup({"pid": 12, "startedAt": None, "processGroupId": 12}))
        evidence.add_exception(RuntimeError("unrelated"))
        evidence.add_probes([{"pid": 11, "startedAt": "p-start", "processGroupId": 11}])
        fields = evidence.report_fields()
        self.assertEqual([item["pid"] for item in fields["ownedProbeProcesses"]], [11, 12])
        self.assertEqual(fields["ownedProbeProcessCount"], 2, "duplicate probe identity is deduplicated")
        self.assertEqual([item["type"] for item in fields["cleanupExceptions"]], ["UncertainProbeCleanup", "InterruptedProbeCleanup"])
        self.assertEqual(fields["cleanupExceptionCount"], 2)
        self.assertFalse(fields["probeEvidenceTruncated"])
        self.assertFalse(evidence.empty)

    def test_probe_evidence_is_bounded_for_hostile_records(self) -> None:
        evidence = run_gates.ProbeEvidence()
        evidence.add_probes([{"pid": index + 1, "startedAt": "s", "reason": "r" * 100_000} for index in range(5000)])
        evidence.add_probes("garbage")
        for _ in range(500):
            evidence.add_exception(run_gates.UncertainProbeCleanup({"pid": 1}))
        fields = evidence.report_fields()
        self.assertLessEqual(len(fields["ownedProbeProcesses"]), run_gates.MAX_PROBE_RECORDS)
        self.assertLessEqual(len(fields["cleanupExceptions"]), run_gates.MAX_CLEANUP_EXCEPTION_RECORDS)
        self.assertEqual(fields["cleanupExceptionCount"], 500)
        self.assertGreater(fields["ownedProbeProcessCount"], run_gates.MAX_PROBE_RECORDS)
        self.assertTrue(fields["probeEvidenceTruncated"])
        self.assertLess(len(json.dumps(fields)), 64 * 1024)

    # Rule 6 and the owner record limit.
    def retain(self, **kwargs: object) -> dict[str, object]:
        lease = run_gates.Lease(pathlib.Path("/nonexistent/lease"), "test-token-value", "label")
        lease.acquired = True
        written: dict[str, object] = {}
        base = {"pid": 1, "label": "label", "token": "test-token-value", "startedAtEpoch": 1}
        with mock.patch.object(private_roots, "admit_directory"), \
                mock.patch.object(private_roots, "read_private_json", return_value=dict(base)), \
                mock.patch.object(run_gates, "_atomic_json", side_effect=lambda _path, value: written.update(value)):
            lease.retain_for_manual_recovery("reason", 5, kwargs.pop("owned", {}), **kwargs)  # type: ignore[arg-type]
        return written

    def test_retention_uses_the_explicit_truncation_flag(self) -> None:
        sample = [_unknown(pid) for pid in range(1, 5)]
        owner = self.retain(unconfirmed_processes=sample, unconfirmed_process_count=4, unconfirmed_processes_truncated=True)
        self.assertIs(owner["unconfirmedProcessesTruncated"], True, "explicit flag wins over count == len(sample)")
        owner = self.retain(unconfirmed_processes=sample, unconfirmed_process_count=4, unconfirmed_processes_truncated=False)
        self.assertIs(owner["unconfirmedProcessesTruncated"], False)
        owner = self.retain(unconfirmed_processes=sample, unconfirmed_process_count=70, unconfirmed_processes_truncated=False)
        self.assertIs(owner["unconfirmedProcessesTruncated"], True, "a count above the sample is always truncation")
        # Older positional callers keep working and infer the flag.
        lease = run_gates.Lease(pathlib.Path("/nonexistent/lease"), "t", "label")
        lease.acquired = True
        written: dict[str, object] = {}
        with mock.patch.object(private_roots, "admit_directory"), \
                mock.patch.object(private_roots, "read_private_json", return_value={}), \
                mock.patch.object(run_gates, "_atomic_json", side_effect=lambda _path, value: written.update(value)):
            lease.retain_for_manual_recovery("reason", 5, {}, sample, 4, [])
        self.assertIs(written["unconfirmedProcessesTruncated"], False)

    def test_retention_keeps_probe_and_cleanup_evidence_and_fits_owner_limits(self) -> None:
        owner = self.retain(
            unconfirmed_processes=[_unknown(pid) for pid in range(1, 65)], unconfirmed_process_count=64,
            owned_probe_processes=[{"pid": 11, "startedAt": "p", "processGroupId": 11, "reason": "probe"}],
            owned_probe_process_count=1,
            cleanup_exceptions=[{"type": "UncertainProbeCleanup"}, {"type": "UncertainProbeCleanup"}, {"type": "InterruptedProbeCleanup"}],
            cleanup_exception_count=3, probe_evidence_truncated=False,
        )
        self.assertEqual(owner["ownedProbeProcesses"][0]["pid"], 11)  # type: ignore[index]
        self.assertEqual(owner["cleanupExceptions"], {"UncertainProbeCleanup": 2, "InterruptedProbeCleanup": 1})
        self.assertEqual(owner["cleanupExceptionCount"], 3)
        self.assertEqual(len(owner["unconfirmedProcesses"]), 64)  # type: ignore[arg-type]
        self.assertIs(owner["unconfirmedProcessesTruncated"], False)
        data = (json.dumps(owner, indent=2, sort_keys=True) + "\n").encode()
        self.assertTrue(private_roots.private_json_fits_read_limits(data))

    def test_retention_trims_oversized_evidence_with_truthful_flags(self) -> None:
        owner = self.retain(
            owned={pid: f"start-{pid}" for pid in range(1, 400)},
            unconfirmed_processes=[_unknown(pid) for pid in range(1, 65)], unconfirmed_process_count=64,
            owned_probe_processes=[{"pid": pid, "startedAt": "p", "processGroupId": pid, "reason": "probe"} for pid in range(1, 65)],
            owned_probe_process_count=64,
        )
        data = (json.dumps(owner, indent=2, sort_keys=True) + "\n").encode()
        self.assertTrue(private_roots.private_json_fits_read_limits(data))
        self.assertIs(owner["ownedProcessesTruncated"], True)
        self.assertEqual(len(owner["ownedProbeProcesses"]), 64, "run-owned probe identities are trimmed last")
        self.assertIsNot(owner.get("probeEvidenceTruncated"), True)
        self.assertEqual(owner["ownedProbeProcessCount"], 64, "the truthful total is preserved")
        self.assertTrue(owner["token"] == "test-token-value" and owner["requiresManualRecovery"])

    def test_retention_trims_unconfirmed_before_probes_when_lengths_tie(self) -> None:
        owner = self.retain(
            unconfirmed_processes=[_unknown(pid) for pid in range(1, 65)], unconfirmed_process_count=64,
            owned_probe_processes=[{"pid": pid, "startedAt": "p", "processGroupId": pid, "reason": "probe"} for pid in range(1, 65)],
            owned_probe_process_count=64,
        )
        self.assertTrue(private_roots.private_json_fits_read_limits((json.dumps(owner, indent=2, sort_keys=True) + "\n").encode()))
        self.assertEqual(len(owner["ownedProbeProcesses"]), 64)  # type: ignore[arg-type]
        self.assertLess(len(owner["unconfirmedProcesses"]), 64)  # type: ignore[arg-type]
        self.assertIs(owner["unconfirmedProcessesTruncated"], True)
        self.assertEqual(owner["unconfirmedProcessCount"], 64, "truthful total preserved")

    def test_receipt_is_compacted_to_stay_readable_with_counts_and_flags_kept(self) -> None:
        records = [_unknown(pid) for pid in range(1, 65)]

        def report() -> dict[str, object]:
            return {
                "eligible": True, "settled": True, "initialIdentities": [dict(item) for item in records],
                "initialCandidateCount": 64, "latestIdentities": [], "latestCandidateCount": 0,
                "identityUnion": [dict(item) for item in records], "identityUnionCount": 64,
                "identityUnionTruncated": False, "ownedProbeProcesses": [], "cleanupExceptions": [],
            }

        manifest = {"schemaVersion": 1, "gates": [{"name": f"g{i}", "naturalExitSettle": report()} for i in range(23)],
                    "versionProbes": [{"name": f"v{i}", "naturalExitSettle": report()} for i in range(9)]}
        data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        self.assertFalse(private_roots.private_json_fits_read_limits(
            data, maximum_nodes=run_gates.RECEIPT_JSON_BUDGET, maximum_commas=run_gates.RECEIPT_JSON_BUDGET,
        ), "the uncompacted receipt is too large to read back")
        written: dict[str, bytes] = {}
        with mock.patch.object(run_gates, "_atomic_json", side_effect=lambda _p, value: written.update(data=json.dumps(value).encode())):
            run_gates._write_receipt(pathlib.Path("/unused/receipt.json"), manifest)
        self.assertTrue(private_roots.private_json_fits_read_limits(
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
            maximum_nodes=run_gates.RECEIPT_JSON_BUDGET, maximum_commas=run_gates.RECEIPT_JSON_BUDGET,
        ))
        first = manifest["gates"][0]["naturalExitSettle"]  # type: ignore[index]
        self.assertEqual(first["initialCandidateCount"], 64)
        self.assertEqual(first["identityUnionCount"], 64)
        self.assertIs(first["evidenceListsCompacted"], True)

    def test_receipt_that_cannot_be_bounded_is_an_error_not_an_unreadable_file(self) -> None:
        manifest = {"schemaVersion": 1, "gates": [{"name": f"g{i}", "extra": list(range(100))} for i in range(60)]}
        with mock.patch.object(run_gates, "_atomic_json") as write:
            with self.assertRaises(RuntimeError):
                run_gates._write_receipt(pathlib.Path("/unused/receipt.json"), manifest)
        write.assert_not_called()

    def test_private_json_limits_reject_what_read_private_json_rejects(self) -> None:
        self.assertTrue(private_roots.private_json_fits_read_limits(b'{"a": [1, 2, 3]}'))
        self.assertFalse(private_roots.private_json_fits_read_limits(json.dumps({"a": list(range(300))}).encode()))
        self.assertFalse(private_roots.private_json_fits_read_limits(b"x" * 70_000))
        self.assertFalse(private_roots.private_json_fits_read_limits(b'{"a": NaN}'))

    def test_retain_uncertain_leases_forwards_every_evidence_field(self) -> None:
        error = run_gates.UncertainProcessTree("uncertain", 77)
        error.owned_processes = {5: "s"}
        error.unconfirmed_processes = [_unknown(5)]
        error.unconfirmed_process_count = 70
        error.unconfirmed_processes_truncated = True
        error.owned_probe_processes = [{"pid": 11}]
        error.owned_probe_process_count = 1
        error.cleanup_exceptions = [{"type": "UncertainProbeCleanup"}]
        error.cleanup_exception_count = 1
        error.probe_evidence_truncated = False
        seen: list[tuple[tuple[object, ...], dict[str, object]]] = []

        class SpyLease:
            def __init__(self, label: str, fail: bool = False) -> None:
                self.label = label
                self.fail = fail

            def retain_for_manual_recovery(self, *args: object, **kwargs: object) -> None:
                seen.append((args, kwargs))
                if self.fail:
                    raise RuntimeError("owner record unavailable")

        failed = run_gates._retain_uncertain_leases([SpyLease("cargo"), SpyLease("gradle", fail=True)], error)  # type: ignore[arg-type]
        self.assertEqual(failed, ["gradle"])
        self.assertEqual(len(seen), 2)
        for args, kwargs in seen:
            self.assertEqual(args[:3], ("uncertain", 77, {5: "s"}))
            self.assertEqual(args[4], 70)
            self.assertIs(kwargs["unconfirmed_processes_truncated"], True)
            self.assertEqual(kwargs["cleanup_exception_count"], 1)
            self.assertEqual(kwargs["owned_probe_process_count"], 1)
            self.assertEqual(kwargs["cleanup_exceptions"], [{"type": "UncertainProbeCleanup"}])
            self.assertIs(kwargs["probe_evidence_truncated"], False)


class RunOwnershipWorldTests(unittest.TestCase):
    """Drive `_run` end to end against a scripted process world.

    Everything the scanner sees is synthetic and uses the real production
    scanner: candidates come from the supplied snapshot, descriptor lookups come
    from a scripted lsof, and every scan step reads the next world.
    """

    ROOT = 4321
    ROOT_START = "root-start"

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=test_scratch_root())
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def world(self, *unknown: dict[str, object], clean: tuple[dict[str, object], ...] = (), raise_exc: BaseException | None = None,
              owned_probe: dict[str, object] | None = None) -> tuple[dict[int, tuple[int, str, str]], set[int], BaseException | None, dict[str, object] | None]:
        snapshot = {self.ROOT: (1, self.ROOT_START, "Z")}
        snapshot.update(_live(*unknown, *clean))
        return snapshot, {item["pid"] for item in clean}, raise_exc, owned_probe  # type: ignore[arg-type, misc]

    def drive(self, worlds: list, *, settle_seconds: float | None = None, provenance_factory: object = None) -> tuple[dict[str, object], run_gates.UncertainProcessTree | None, tuple[int, float] | None]:
        state = {"calls": 0, "scan": 0, "world": worlds[0]}

        def fake_snapshot(*, timeout: float = 2.0) -> dict[int, tuple[int, str, str]]:
            del timeout
            state["calls"] += 1
            if state["calls"] == 1:
                return {}
            if state["calls"] <= 3:
                return {self.ROOT: (1, self.ROOT_START, "S")}
            return dict(state["world"][0])  # type: ignore[index]

        real_bounded = run_gates._bounded_ownership_scan

        def counting_bounded(*args: object, **kwargs: object) -> object:
            state["scan"] += 1
            state["world"] = worlds[min(state["scan"], len(worlds) - 1)]
            return real_bounded(*args, **kwargs)  # type: ignore[arg-type]

        def fake_lsof(arguments: list[str], _deadline: float) -> run_gates.LsofProbe:
            _snapshot, clean, raise_exc, owned_probe = state["world"]  # type: ignore[misc]
            if raise_exc is not None:
                raise raise_exc
            pids = [int(item) for item in arguments[-1].split(",")]
            body = "".join(f"p{pid}\nf1\nn/dev/null\n" for pid in pids if pid in clean)
            return run_gates.LsofProbe(0, body, "", None, owned_probe)

        real_is_dir = pathlib.Path.is_dir
        real_settle = run_gates._settle_uninspectable_candidates
        process = mock.Mock(pid=self.ROOT, returncode=0)
        process.wait.return_value = 0
        process.poll.return_value = 0

        def settle(*args: object, **kwargs: object) -> object:
            if settle_seconds is not None:
                kwargs["duration"] = settle_seconds
            return real_settle(*args, **kwargs)  # type: ignore[arg-type]

        report: dict[str, object] = {}
        self.provenance_report: dict[str, object] = {}
        result: tuple[int, float] | None = None
        failure: run_gates.UncertainProcessTree | None = None
        extra = {"provenance": True, "provenance_report": self.provenance_report} if provenance_factory else {}
        factory_patch = (
            mock.patch.object(run_gates.provenance_module, "Provenance", side_effect=provenance_factory)
            if provenance_factory else mock.patch.dict(os.environ, {})
        )
        with factory_patch, mock.patch.object(run_gates, "_process_snapshot", side_effect=fake_snapshot), \
                mock.patch.object(run_gates.subprocess, "Popen", return_value=process), \
                mock.patch.object(run_gates, "_bounded_ownership_scan", side_effect=counting_bounded), \
                mock.patch.object(run_gates, "_run_lsof_fields", side_effect=fake_lsof), \
                mock.patch.object(run_gates, "LSOF_BINARY", "/test/lsof"), \
                mock.patch.object(pathlib.Path, "is_dir", lambda path: False if str(path) == "/proc" else real_is_dir(path)), \
                mock.patch.object(run_gates, "_settle_uninspectable_candidates", side_effect=settle), \
                mock.patch.object(private_roots, "create_private_file", side_effect=lambda path, flags, mode: os.open(path, flags, mode)):
            try:
                result = run_gates._run(
                    ["gate"], cwd=self.root, env={}, timeout=30,
                    log_path=self.root / f"gate-{id(worlds)}.log", settle_report=report, **extra,
                )
            except run_gates.UncertainProcessTree as exc:
                failure = exc
        return report, failure, result

    def test_new_unknown_in_first_global_rescan_then_natural_exit_succeeds_with_complete_elapsed_time(self) -> None:
        initial, new = _unknown(9001), _unknown(9002)
        report, failure, result = self.drive([
            self.world(initial),   # post-command scan: initial identity unknown
            self.world(),          # settle poll: initial identity exited
            self.world(new),       # first global rescan: a NEW unknown identity appears
            self.world(),          # it exited naturally
            self.world(),          # quiet scan 1
            self.world(),          # quiet scan 2 (repeats)
        ])
        self.assertIsNone(failure, str(failure))
        self.assertIsNotNone(result)
        self.assertIs(report["settled"], True)
        self.assertEqual(report["pollCount"], 1)
        self.assertEqual(report["globalRescanCount"], 3, "one churn scan then two full quiet scans")
        self.assertEqual(report["identityUnionCount"], 2)
        self.assertIs(report["identityUnionTruncated"], False)
        self.assertIsNone(report["error"])
        self.assertGreaterEqual(report["waitSeconds"], 3.0, "elapsed time includes global settling")  # type: ignore[operator]
        self.assertGreater(report["waitSeconds"], report["initialSettleSeconds"])  # type: ignore[operator]
        self.assertLessEqual(report["waitSeconds"] + report["deadlineRemainingSeconds"], run_gates.NATURAL_EXIT_SETTLE_SECONDS + 0.5)  # type: ignore[operator]
        self.assertEqual(report["ownedProbeProcessCount"], 0)

    def test_new_unknown_that_stays_live_fails_closed_without_resetting_the_deadline(self) -> None:
        initial, stuck = _unknown(9001), _unknown(9002)
        report, failure, result = self.drive([
            self.world(initial), self.world(), self.world(stuck),
        ], settle_seconds=4.0)
        self.assertIsNone(result)
        self.assertIsNotNone(failure)
        self.assertIn("clean global ownership rescan", str(failure))
        self.assertIs(report["settled"], False)
        self.assertIn("unresolved", str(report["error"]))
        self.assertLessEqual(report["deadlineRemainingSeconds"], 0.01)  # type: ignore[operator]
        self.assertGreaterEqual(report["waitSeconds"], 3.9)  # type: ignore[operator]
        self.assertLessEqual(report["waitSeconds"], 5.0)  # type: ignore[operator]
        self.assertGreater(report["waitSeconds"], report["initialSettleSeconds"] + 1.0)  # type: ignore[operator]
        assert failure is not None
        self.assertEqual({_ident(item) for item in failure.unconfirmed_processes}, {_ident(initial), _ident(stuck)})
        self.assertEqual(failure.unconfirmed_process_count, 2)
        self.assertFalse(failure.unconfirmed_processes_truncated)

    def test_initial_identity_that_stays_live_is_never_cleared_by_a_later_scan(self) -> None:
        initial = _unknown(9001)
        report, failure, _result = self.drive([self.world(initial), self.world(initial)], settle_seconds=3.0)
        self.assertIsNotNone(failure)
        self.assertIn("could not be cleared", str(failure))
        self.assertEqual(report["globalRescanCount"], 0)
        assert failure is not None
        self.assertEqual([_ident(item) for item in failure.unconfirmed_processes], [_ident(initial)])

    def test_initial_identity_positively_classified_by_the_scanner_is_cleared(self) -> None:
        initial = _unknown(9001)
        report, failure, result = self.drive([
            self.world(initial), self.world(clean=(initial,)), self.world(),
        ])
        self.assertIsNone(failure, str(failure))
        self.assertIsNotNone(result)
        self.assertIs(report["settled"], True)

    def test_cleanup_exceptions_and_probe_identities_reach_receipt_and_owner_error(self) -> None:
        initial = _unknown(9001)
        for exc, kind in (
            (run_gates.UncertainProbeCleanup({"pid": 7001, "startedAt": "probe-start", "processGroupId": 7001}), "UncertainProbeCleanup"),
            (run_gates.InterruptedProbeCleanup({"pid": 7002, "startedAt": None, "processGroupId": 7002}), "InterruptedProbeCleanup"),
        ):
            with self.subTest(kind):
                report, failure, _result = self.drive([self.world(initial), self.world(initial, raise_exc=exc)])
                assert failure is not None
                self.assertIn("settling poll failed", str(report["error"]))
                self.assertEqual([item["pid"] for item in failure.owned_probe_processes], [exc.owned_probe_processes[0]["pid"]])
                self.assertEqual(failure.cleanup_exceptions, [{"type": kind}])
                self.assertEqual(report["cleanupExceptions"], [{"type": kind}])
                self.assertEqual([item["pid"] for item in report["ownedProbeProcesses"]], [exc.owned_probe_processes[0]["pid"]])  # type: ignore[index]
                self.assertEqual(report["ownedProbeProcessCount"], 1)

    def test_probe_returned_by_a_poll_scan_is_retained_before_the_helper_fails_closed(self) -> None:
        initial = _unknown(9001)
        probe = {"pid": 7003, "startedAt": "probe-start", "processGroupId": 7003}
        report, failure, _result = self.drive([self.world(initial), self.world(initial, owned_probe=probe)])
        assert failure is not None
        self.assertIn("owned probe", str(report["error"]))
        self.assertEqual([item["pid"] for item in failure.owned_probe_processes], [7003])
        self.assertEqual(failure.owned_probe_process_count, 1)
        self.assertEqual([item["pid"] for item in report["ownedProbeProcesses"]], [7003])  # type: ignore[index]

    def test_probe_from_the_first_post_command_scan_reaches_receipt_and_owner_error(self) -> None:
        initial = _unknown(9001)
        probe = {"pid": 7005, "startedAt": "probe-start", "processGroupId": 7005}
        report, failure, _result = self.drive([self.world(initial, owned_probe=probe)])
        assert failure is not None
        self.assertNotIn("eligible", report, "a first-scan probe makes the run ineligible for settling")
        self.assertEqual([item["pid"] for item in report["ownedProbeProcesses"]], [7005])  # type: ignore[index]
        self.assertEqual(report["ownedProbeProcessCount"], 1)
        self.assertEqual([item["pid"] for item in failure.owned_probe_processes], [7005])

    def test_global_phase_probe_exception_is_retained(self) -> None:
        initial = _unknown(9001)
        exc = run_gates.UncertainProbeCleanup({"pid": 7004, "startedAt": "probe-start", "processGroupId": 7004})
        report, failure, _result = self.drive([self.world(initial), self.world(), self.world(_unknown(9005), raise_exc=exc)])
        assert failure is not None
        self.assertIn("global ownership rescan failed", str(report["error"]))
        self.assertEqual(failure.cleanup_exceptions, [{"type": "UncertainProbeCleanup"}])
        self.assertEqual([item["pid"] for item in failure.owned_probe_processes], [7004])

    def test_truncated_initial_unknown_set_reports_truncation_and_stays_uncertain(self) -> None:
        many = [_unknown(pid) for pid in range(9001, 9071)]
        _report, failure, result = self.drive([self.world(*many)])
        self.assertIsNone(result)
        assert failure is not None
        self.assertEqual(failure.unconfirmed_process_count, 70)
        self.assertEqual(len(failure.unconfirmed_processes), run_gates.MAX_UNCONFIRMED_SAMPLE)
        self.assertTrue(failure.unconfirmed_processes_truncated)


def _r2_killpg_created_group(pgid: int) -> None:
    """SIGKILL a process group this test created; the caller then wait()s to reap.

    On Darwin, killpg on a group whose only members are unreaped zombies fails
    with EPERM (a fully reaped group gives ESRCH); both mean the group is gone.
    Any other error, and EPERM elsewhere, still propagates.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        if sys.platform != "darwin":
            raise


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=test_scratch_root())
        self.addCleanup(self.temp.cleanup)
        # Runner tests exercise orchestration against public synthetic trees.
        # Host ACL and mount observations are covered by explicit component
        # fixtures, not by treating this scratch tree as private storage.
        self.acl_patcher = mock.patch.object(private_roots, "_acl_check", lambda _path, _fd: None)
        self.mount_patcher = mock.patch.object(private_roots, "_mount_check", lambda _path, _fd, _info: None)
        self.acl_patcher.start()
        self.mount_patcher.start()
        self.addCleanup(self.mount_patcher.stop)
        self.addCleanup(self.acl_patcher.stop)
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        for name in ("Cargo.lock", "adapters/java/gradle.lockfile", "adapters/node/package-lock.json", "web/app/package-lock.json"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test lockfile\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], check=True)
        self.base = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.cache = self.root / "cache"
        self.cache.mkdir(mode=0o700)
        self.versions_patcher = mock.patch.object(run_gates, "_versions", return_value={})
        self.versions_patcher.start()
        self.addCleanup(self.versions_patcher.stop)

    def args(self) -> Namespace:
        return Namespace(repo=str(self.repo), base=self.base, label="P00-test", cache_root=str(self.cache), command_timeout=30)

    def test_natural_exit_settle_clears_only_after_initial_identity_exits(self) -> None:
        clock = [0.0]
        identity = (4242, "candidate-start")
        candidate = {"pid": identity[0], "startedAt": identity[1], "descriptorStatus": "uninspectable", "reason": "missing-process-record-after-all-fd-fallback"}

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        def poll(_remaining: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
            if clock[0] < 1.5:
                snapshot = {identity[0]: (1, identity[1], "S")}
                scan = run_gates.UntrackedProcessScan([], [candidate], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 1)
            else:
                snapshot = {}
                scan = run_gates.UntrackedProcessScan([], [], None, 0)
            return snapshot, scan

        result = run_gates._settle_uninspectable_candidates(
            [candidate], poll, duration=4, interval=1,
            monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertTrue(result.cleared)
        self.assertEqual(result.elapsed_seconds, 2)
        self.assertEqual(result.poll_count, 2)
        self.assertFalse(result.latest_candidates)

    def test_settle_process_and_descriptor_scans_share_one_absolute_deadline(self) -> None:
        clock = [10.0]
        budgets: list[float] = []

        def process_scan(*, timeout: float) -> dict[int, tuple[int, str, str]]:
            budgets.append(timeout)
            clock[0] += 0.75
            return {}

        def descriptor_scan(
            _snapshot: dict[int, tuple[int, str, str]], *, budget_seconds: float,
        ) -> run_gates.UntrackedProcessScan:
            budgets.append(budget_seconds)
            return run_gates.UntrackedProcessScan([], [], None, 0)

        processes, scan = run_gates._bounded_ownership_scan(
            12.0,
            snapshot=process_scan,
            descriptor_scan=descriptor_scan,
            monotonic=lambda: clock[0],
        )
        self.assertEqual(processes, {})
        self.assertIsNone(scan.error)
        self.assertEqual(budgets, [2.0, 1.25])

        clock[0] = 20.0
        descriptor_called = False

        def late_process_scan(*, timeout: float) -> dict[int, tuple[int, str, str]]:
            del timeout
            clock[0] = 21.0
            return {}

        def late_descriptor_scan(
            _snapshot: dict[int, tuple[int, str, str]], *, budget_seconds: float,
        ) -> run_gates.UntrackedProcessScan:
            nonlocal descriptor_called
            del budget_seconds
            descriptor_called = True
            return run_gates.UntrackedProcessScan([], [], None, 0)

        with self.assertRaisesRegex(RuntimeError, "expired before descriptor scan"):
            run_gates._bounded_ownership_scan(
                21.0,
                snapshot=late_process_scan,
                descriptor_scan=late_descriptor_scan,
                monotonic=lambda: clock[0],
            )
        self.assertFalse(descriptor_called, "exhausted poll must not start another scan")

    def test_natural_exit_settle_fails_closed_for_survivors_and_new_holders(self) -> None:
        clock = [0.0]
        identity = (4242, "candidate-start")
        candidate = {"pid": identity[0], "startedAt": identity[1], "descriptorStatus": "uninspectable", "reason": "missing-process-record-after-all-fd-fallback"}

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        def survivor(_remaining: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
            return (
                {identity[0]: (1, identity[1], "S")},
                run_gates.UntrackedProcessScan([], [candidate], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 1),
            )

        result = run_gates._settle_uninspectable_candidates(
            [candidate], survivor, duration=2, interval=1,
            monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertFalse(result.cleared)
        self.assertEqual(result.last_error, "initial uninspectable process identity survived settling deadline")
        self.assertEqual(result.latest_candidates, [candidate])

        clock[0] = 0.0
        holder = {"pid": 5151, "startedAt": "late-start", "descriptorStatus": "held", "reason": "private-log-descriptor-observed"}

        def new_holder(_remaining: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
            return (
                {identity[0]: (1, identity[1], "S"), 5151: (1, "late-start", "S")},
                run_gates.UntrackedProcessScan([holder], [], None, 1),
            )

        result = run_gates._settle_uninspectable_candidates(
            [candidate], new_holder, duration=4, interval=1,
            monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertFalse(result.cleared)
        self.assertEqual(result.latest_candidates, [holder])
        self.assertIn("held descriptor", result.last_error or "")

    def test_natural_exit_settle_admission_excludes_held_owned_and_log_failures(self) -> None:
        unknown = {"pid": 4242, "startedAt": "candidate-start", "descriptorStatus": "uninspectable", "reason": "missing-process-record-after-all-fd-fallback"}
        eligible = run_gates.UntrackedProcessScan([], [unknown], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 1)
        self.assertTrue(run_gates._natural_exit_settle_eligible(
            eligible, tree_confirmed_drained=True, log_io_failed=False,
        ))
        self.assertFalse(run_gates._natural_exit_settle_eligible(
            eligible, tree_confirmed_drained=False, log_io_failed=False,
        ))
        self.assertFalse(run_gates._natural_exit_settle_eligible(
            eligible, tree_confirmed_drained=True, log_io_failed=True,
        ))
        self.assertFalse(run_gates._natural_exit_settle_eligible(
            eligible, tree_confirmed_drained=True, log_io_failed=False,
            prior_uncertainty=True,
        ))
        held = run_gates.UntrackedProcessScan(
            [{"pid": 9, "startedAt": "held", "descriptorStatus": "held"}],
            [unknown], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 2,
        )
        self.assertFalse(run_gates._natural_exit_settle_eligible(
            held, tree_confirmed_drained=True, log_io_failed=False,
        ))
        owned_probe = run_gates.UntrackedProcessScan([], [unknown], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 1, [{"pid": 8}])
        self.assertFalse(run_gates._natural_exit_settle_eligible(
            owned_probe, tree_confirmed_drained=True, log_io_failed=False,
        ))

    def test_diagnostic_log_failure_cannot_be_cleared_by_transient_uninspectable_candidate(self) -> None:
        gate = run_gates.Gate("diagnostic-write", (sys.executable, "-c", "pass"))
        root_snapshot = {4321: (1, "root-start", "S")}
        candidate = {
            "pid": 9876,
            "startedAt": "transient-start",
            "descriptorStatus": "uninspectable",
            "reason": "missing-process-record-after-all-fd-fallback",
        }
        process = mock.Mock(pid=4321, returncode=0)
        process.wait.return_value = 0
        process.poll.return_value = 0
        real_fdopen = os.fdopen
        real_open = os.open
        diagnostic_fds: set[int] = set()
        write_fault_reached = [False]

        def tracking_open(path: object, *args: object, **kwargs: object) -> int:
            fd = real_open(path, *args, **kwargs)
            name = pathlib.Path(os.fsdecode(path)).name
            flags = args[0] if args else kwargs.get("flags", 0)
            if (name.startswith(".diagnostic-write.log.")
                    and isinstance(flags, int)
                    and flags & os.O_WRONLY and flags & os.O_CREAT and flags & os.O_EXCL):
                diagnostic_fds.add(fd)
            return fd

        def selective_fdopen(fd: int, mode: str, *args: object, **kwargs: object) -> object:
            if fd in diagnostic_fds:
                diagnostic_fds.remove(fd)
                return FailingDiagnosticLog(fd, mode)
            return real_fdopen(fd, mode, *args, **kwargs)
        real_popen = subprocess.Popen

        def selective_popen(argv: object, *args: object, **kwargs: object) -> object:
            if isinstance(argv, (list, tuple)) and list(argv) == list(gate.argv):
                return process
            return real_popen(argv, *args, **kwargs)

        class FailingDiagnosticLog:
            def __init__(self, fd: int, mode: str) -> None:
                self.stream = real_fdopen(fd, mode)

            def write(self, _payload: bytes) -> int:
                write_fault_reached[0] = True
                raise OSError("injected diagnostic write failure")

            def flush(self) -> None:
                self.stream.flush()

            def fileno(self) -> int:
                return self.stream.fileno()

            def close(self) -> None:
                self.stream.close()

            def __enter__(self) -> FailingDiagnosticLog:
                return self

            def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
                self.close()

        settle = run_gates.NaturalExitSettle(
            True, 1.0, 1, [], None, time.monotonic() + 120,
        )
        with mock.patch.object(run_gates, "GATES", (gate,)), \
                mock.patch.object(run_gates.subprocess, "Popen", side_effect=selective_popen), \
                mock.patch.object(run_gates, "_process_snapshot", side_effect=[{}, root_snapshot, root_snapshot, root_snapshot, root_snapshot]), \
                mock.patch.object(run_gates, "_owned_processes_alive", return_value=[4321]), \
                mock.patch.object(run_gates, "_stop_and_reap_owned_tree", return_value=True), \
                mock.patch.object(run_gates, "_untracked_processes_since", return_value=run_gates.UntrackedProcessScan(
                    [], [candidate], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 1,
                )), \
                mock.patch.object(run_gates, "_settle_uninspectable_candidates", return_value=settle) as settle_candidates, \
                mock.patch.object(run_gates, "_final_global_quiescence_scan", return_value=(True, [], None, 2)) as global_scan, \
                mock.patch.object(run_gates.os, "open", side_effect=tracking_open), \
                mock.patch.object(run_gates.os, "fdopen", side_effect=selective_fdopen):
            self.assertEqual(run_gates.run(self.args()), 1)

        self.assertTrue(write_fault_reached[0], "diagnostic write injection must be reached")
        settle_candidates.assert_not_called()
        global_scan.assert_not_called()
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["exitCode"], 0, "receipt retains raw child exit without treating it as pass")
        self.assertTrue(entry["cleanupUncertain"])
        self.assertNotIn("naturalExitSettle", entry, "log failure disqualifies the settle path")
        for name in ("cargo", "gradle"):
            owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
            self.assertTrue(owner["requiresManualRecovery"])

    def test_natural_exit_settle_fails_closed_on_scan_error_and_interrupt(self) -> None:
        candidate = {"pid": 4242, "startedAt": "candidate-start", "descriptorStatus": "uninspectable", "reason": "missing-process-record-after-all-fd-fallback"}
        clock = [0.0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        scan_error = run_gates.UntrackedProcessScan([], [], "scanner unavailable", 0)
        result = run_gates._settle_uninspectable_candidates(
            [candidate], lambda _remaining: ({}, scan_error), duration=4,
            interval=1, monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertFalse(result.cleared)
        self.assertEqual(result.last_error, "scanner unavailable")

        def interrupt(_seconds: float) -> None:
            raise KeyboardInterrupt()

        result = run_gates._settle_uninspectable_candidates(
            [candidate], lambda _remaining: ({}, scan_error), duration=4,
            monotonic=lambda: clock[0], sleep=interrupt,
        )
        self.assertFalse(result.cleared)
        self.assertEqual(result.last_error, "settling poll failed: KeyboardInterrupt")

    def test_natural_exit_settle_requires_clean_global_rescan_and_quiescence(self) -> None:
        clock = [0.0]
        scans = [0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        def clean_scan(_remaining: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
            scans[0] += 1
            return {}, run_gates.UntrackedProcessScan([], [], None, 0)

        cleared, latest, error, count = run_gates._final_global_quiescence_scan(
            5, clean_scan, lambda _snapshot: [], monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertTrue(cleared)
        self.assertFalse(latest)
        self.assertIsNone(error)
        self.assertEqual(count, 2)
        self.assertEqual(scans[0], 2)
        self.assertEqual(clock[0], run_gates.NATURAL_EXIT_QUIESCENT_SECONDS)

        # A new unknown identity that stays live is churn that never resolves:
        # it is waited on and fails closed at the one absolute deadline.
        late_unknown = {"pid": 9001, "startedAt": "late-start", "descriptorStatus": "uninspectable", "reason": "late-child"}
        clock[0] = 0.0
        failed, latest, error, count = run_gates._final_global_quiescence_scan(
            5,
            lambda _remaining: ({9001: (1, "late-start", "S")}, run_gates.UntrackedProcessScan([], [late_unknown], run_gates.EXPECTED_UNINSPECTABLE_SCAN, 1)),
            lambda _snapshot: [], monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertFalse(failed)
        self.assertEqual(latest, [late_unknown])
        self.assertGreater(count, 1)
        self.assertIn("unresolved", error or "")
        self.assertEqual(clock[0], 5)

        clock[0] = 0.0
        failed, _latest, error, _count = run_gates._final_global_quiescence_scan(
            5, clean_scan, lambda _snapshot: [733], monotonic=lambda: clock[0], sleep=sleep,
        )
        self.assertFalse(failed)
        self.assertIn("owned process", error or "")

    def test_natural_exit_final_quiescence_fails_on_scan_error_timeout_or_interrupt(self) -> None:
        clock = [0.0]
        clean = run_gates.UntrackedProcessScan([], [], None, 0)
        no_sleep = lambda _seconds: None

        failed, _latest, error, _count = run_gates._final_global_quiescence_scan(
            5,
            lambda _remaining: ({}, run_gates.UntrackedProcessScan([], [], "late scanner error", 0)),
            lambda _snapshot: [], monotonic=lambda: clock[0], sleep=no_sleep,
        )
        self.assertFalse(failed)
        self.assertEqual(error, "late scanner error")

        def late_scan(_remaining: float) -> tuple[dict[int, tuple[int, str, str]], run_gates.UntrackedProcessScan]:
            clock[0] = 6
            return {}, clean

        failed, _latest, error, _count = run_gates._final_global_quiescence_scan(
            5, late_scan, lambda _snapshot: [], monotonic=lambda: clock[0], sleep=no_sleep,
        )
        self.assertFalse(failed)
        self.assertIn("deadline exceeded", error or "")

        clock[0] = 0

        def interrupt(_seconds: float) -> None:
            raise KeyboardInterrupt()

        failed, _latest, error, _count = run_gates._final_global_quiescence_scan(
            5, lambda _remaining: ({}, clean), lambda _snapshot: [],
            monotonic=lambda: clock[0], sleep=interrupt,
        )
        self.assertFalse(failed)
        self.assertEqual(error, "quiescent wait failed: KeyboardInterrupt")

    def test_floor_builds_its_environment_with_the_shared_allowlist_and_private_home(self) -> None:
        gate = run_gates.Gate("env-probe", ("true",))
        captured: dict[str, object] = {}

        def fake_run(argv: list[str], *, cwd: pathlib.Path, env: dict[str, str], timeout: float, log_path: pathlib.Path,
                     settle_report: dict | None = None, **_kwargs: object) -> tuple[int, float]:
            captured.setdefault("env", dict(env))
            os.close(private_roots.create_private_file(log_path, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600))
            return 0, 0.1

        ambient = {"PATH": os.environ.get("PATH", "/usr/bin"), "HOME": "/host/home", "JAVA_HOME": "/opt/jdk", "CI": "true",
                   "GITHUB_TOKEN": "canary-token", "LD_PRELOAD": "/x.so"}
        with mock.patch.dict(os.environ, ambient, clear=True), \
                mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates, "_run", side_effect=fake_run):
            run_gates.run(self.args())
        env = captured["env"]
        self.assertEqual(env["JAVA_HOME"], "/opt/jdk")  # type: ignore[index]
        self.assertEqual(env["CI"], "true")  # type: ignore[index]
        self.assertNotIn("GITHUB_TOKEN", env)  # type: ignore[operator]
        self.assertNotIn("LD_PRELOAD", env)  # type: ignore[operator]
        self.assertEqual(env["HOME"], str(self.cache / "tmp" / "P00-test-home"))  # type: ignore[index]
        self.assertTrue((self.cache / "tmp" / "P00-test-home").is_dir())
        self.assertEqual(env["CARGO_HOME"], str(self.cache / "cargo"))  # type: ignore[index]

    def test_node_generate_normalizer_is_shared_canonical_and_symlink_safe(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node, "node is required for the generated-bindings normalizer test")
        scripts = pathlib.Path(__file__).resolve().parents[2] / "adapters" / "node" / "scripts"
        root = self.root / "gen"
        (root / "sub").mkdir(parents=True)
        (root / "a.ts").write_text("export {};\n\n\n")
        (root / "sub" / "b.ts").write_text("export {};")  # missing trailing newline
        (root / "c.ts").write_text("export {};\n")  # already canonical
        (root / "d.js").write_text("keep\n\n")  # not TypeScript
        outside = self.root / "outside.ts"
        outside.write_text("x;\n\n\n")
        os.symlink(outside, root / "link.ts")
        driver = self.root / "run.mjs"
        driver.write_text(f'import {{ normalizeTree }} from "{(scripts / "generated-normalize.mjs").as_posix()}"; await normalizeTree(process.argv[2]);')
        for _ in range(2):  # idempotent
            subprocess.run([node, str(driver), str(root)], check=True)
            self.assertEqual((root / "a.ts").read_text(), "export {};\n")
            self.assertEqual((root / "sub" / "b.ts").read_text(), "export {};\n", "a missing trailing newline is added")
            self.assertEqual((root / "c.ts").read_text(), "export {};\n")
            self.assertEqual((root / "d.js").read_text(), "keep\n\n")
            self.assertEqual(outside.read_text(), "x;\n\n\n", "symlinks are not followed or rewritten")
        # One shared implementation and template: generate and generate:check cannot diverge.
        generate = (scripts / "generate.mjs").read_text()
        check = (scripts / "check-generated.mjs").read_text()
        for text in (generate, check):
            self.assertIn('from "./generated-normalize.mjs"', text)
            self.assertIn('from "./generated-template.mjs"', text)
        self.assertNotIn("normalizeTree(directory", check, "the checker has no private copy")
        package = json.loads((scripts.parent / "package.json").read_text())
        self.assertEqual(package["scripts"]["generate"], "node scripts/generate.mjs")
        self.assertEqual(package["scripts"]["generate:check"], "node scripts/check-generated.mjs")
        self.assertFalse((scripts.parent / "buf.gen.yaml").exists(), "no second template to drift")

    def test_prewarm_gradle_retries_logs_each_attempt_and_fails_explicitly(self) -> None:
        logs = self.root / "prewarm-logs"
        logs.mkdir()
        props = self.repo / "adapters" / "java" / "gradle" / "wrapper"
        props.mkdir(parents=True)
        (props / "gradle-wrapper.properties").write_text("distributionUrl=x\ndistributionSha256Sum=" + "a" * 64 + "\n")
        calls: list[tuple[list[str], dict]] = []

        def flaky(argv: list[str], **kwargs: object) -> tuple[int, float]:
            calls.append((argv, kwargs))
            return (0 if len(calls) == 3 else 1), 0.1

        result = run_gates.prewarm_gradle(self.repo, {"GRADLE_USER_HOME": "g"}, logs, run=flaky)
        self.assertEqual(result, {"gradle": {"attempts": 3, "exitCode": 0}})
        self.assertEqual([call[0] for call in calls], [["./gradlew", "--no-daemon", "--version"]] * 3)
        self.assertEqual(calls[0][1]["cwd"], self.repo / "adapters" / "java")
        self.assertEqual(calls[0][1]["env"], {"GRADLE_USER_HOME": "g"})
        self.assertEqual(len({call[1]["log_path"] for call in calls}), 3, "a new log per attempt")
        self.assertEqual(run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda *a, **k: (0, 0.1)), {"gradle": {"attempts": 1, "exitCode": 0}})
        with self.assertRaisesRegex(RuntimeError, "prewarm failed after 3 attempts \\(last exit 7\\)"):
            run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda *a, **k: (7, 0.1))
        # Not retried: a missing executable (127), a timeout (124) or a log overflow.
        for code in (127, 124, run_gates.LOG_LIMIT_EXIT_CODE):
            attempts: list[int] = []
            with self.assertRaisesRegex(RuntimeError, f"after 1 attempts \\(last exit {code}\\)"):
                run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda *a, **k: (attempts.append(1), (code, 0.1))[1])
            self.assertEqual(len(attempts), 1)
        # Supervised with a log cap, and with provenance when asked (the floor's setting).
        seen: list[dict] = []
        run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda argv, **k: (seen.append(k), (0, 0.1))[1], provenance=True, provenance_report={})
        self.assertEqual(seen[0]["max_log_bytes"], run_gates.GRADLE_PREWARM_MAX_LOG_BYTES)
        self.assertIs(seen[0]["provenance"], True)
        seen.clear()
        run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda argv, **k: (seen.append(k), (0, 0.1))[1])
        self.assertNotIn("provenance", seen[0])
        # The wrapper must pin a checksum, otherwise nothing is run.
        (props / "gradle-wrapper.properties").write_text("distributionUrl=x\n")
        called: list[int] = []
        with self.assertRaisesRegex(RuntimeError, "does not pin distributionSha256Sum"):
            run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda *a, **k: (called.append(1), (0, 0.1))[1])
        self.assertEqual(called, [])
        (props / "gradle-wrapper.properties").write_text("distributionSha256Sum=" + "z" * 64 + "\n")
        with self.assertRaises(RuntimeError):
            run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda *a, **k: (0, 0.1))
        (props / "gradle-wrapper.properties").unlink()
        with self.assertRaisesRegex(RuntimeError, "unreadable"):
            run_gates.prewarm_gradle(self.repo, {}, logs, run=lambda *a, **k: (0, 0.1))
        import inspect
        self.assertEqual(inspect.signature(REAL_VERSIONS).parameters["timeout"].default, 20, "the 20 s probe budget is unchanged")

    def test_floor_prewarms_under_its_leases_before_the_version_probes_only_when_asked(self) -> None:
        order: list[str] = []
        held: list[bool] = []
        gate = run_gates.Gate("noop", ("true",))

        def fake_prewarm(*args: object, **kwargs: object) -> dict:
            order.append("prewarm")
            held.append((self.cache / "leases" / "cargo").exists() and (self.cache / "leases" / "gradle").exists())
            return {"gradle": {"attempts": 1, "exitCode": 0}}

        def fake_versions(*args: object, **kwargs: object) -> dict:
            order.append("versions")
            return {}

        def fake_run(argv: list[str], *, log_path: pathlib.Path, **_k: object) -> tuple[int, float]:
            os.close(private_roots.create_private_file(log_path, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600))
            return 0, 0.1

        for flag, expected in ((True, ["prewarm", "versions"]), (False, ["versions"])):
            order.clear()
            args = self.args()
            args.label = f"P00-prewarm-{flag}"
            args.prewarm_gradle = flag
            with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates, "prewarm_gradle", side_effect=fake_prewarm), \
                    mock.patch.object(run_gates, "_versions", side_effect=fake_versions), mock.patch.object(run_gates, "_run", side_effect=fake_run):
                run_gates.run(args)
            self.assertEqual(order[:len(expected)], expected)
        self.assertEqual(held, [True], "the distribution is warmed while both leases are held")
        receipt = json.loads((self.cache / "release-gates" / "P00-prewarm-True" / "receipt.json").read_text())
        self.assertEqual(receipt["prewarm"], {"gradle": {"attempts": 1, "exitCode": 0}})
        help_text = subprocess.run([sys.executable, '-B', '-m', 'tools.release.run_gates', '--help'], capture_output=True, text=True, cwd=pathlib.Path(__file__).resolve().parents[2]).stdout
        self.assertIn('--prewarm-gradle', help_text)

    def test_failed_gate_stops_and_never_claims_all_passed(self) -> None:
        failure = run_gates.Gate("failure", (sys.executable, "-c", "print('gate failed'); raise SystemExit(9)"))
        later = run_gates.Gate("unreached", (sys.executable, "-c", "raise SystemExit(0)"))
        with mock.patch.object(run_gates, "GATES", (failure, later)):
            self.assertEqual(run_gates.run(self.args()), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertEqual(receipt["decision"], "failed")
        self.assertEqual(len(receipt["gates"]), 2)
        self.assertEqual([gate["status"] for gate in receipt["gates"]], ["failed", "unreached"])
        self.assertEqual(receipt["gates"][0]["exitCode"], 9)
        self.assertEqual(receipt["gates"][0]["status"], "failed")
        self.assertNotIn("ALL GATES PASSED", (self.cache / "release-gates/P00-test/receipt.json").read_text())

    def test_attempted_cleanup_failure_is_failed_receipt_with_raw_exit_and_partial_log(self) -> None:
        attempted = run_gates.Gate("attempted-java", ("java", "-version"))
        later = run_gates.Gate("later", (sys.executable, "-c", "raise SystemExit(0)"))
        real_replace = os.replace
        rename_fault_reached = [False]

        def uncertain_run(
            _argv: object, *, log_path: pathlib.Path, settle_report: dict[str, object] | None = None,
            **_kwargs: object,
        ) -> tuple[int, float]:
            log_path.write_bytes(b"partial private command log\n")
            os.chmod(log_path, 0o600)
            error = run_gates.UncertainProcessTree("owned tree did not drain", 777)
            error.command_started = True
            error.raw_exit_code = 0
            error.duration_seconds = 1.25
            error.owned_processes = {777: "started"}
            error.unconfirmed_processes = [{"pid": 888, "startedAt": "unknown-start", "descriptorStatus": "uninspectable", "reason": "fixture"}]
            if settle_report is not None:
                settle_report.update({"eligible": False, "error": "test uncertainty"})
            raise error

        def fail_log_rename(
            source: str | os.PathLike[str], destination: str | os.PathLike[str],
            *args: object, **kwargs: object,
        ) -> None:
            if pathlib.Path(destination).name == "attempted-java.log":
                rename_fault_reached[0] = True
                raise OSError("injected log rename failure")
            real_replace(source, destination, *args, **kwargs)

        with mock.patch.object(run_gates, "GATES", (attempted, later)), \
                mock.patch.object(run_gates, "_run", side_effect=uncertain_run), \
                mock.patch.object(run_gates.os, "replace", side_effect=fail_log_rename):
            self.assertEqual(run_gates.run(self.args()), 1)

        self.assertTrue(rename_fault_reached[0], "uncertain log rename injection must be reached")
        run_dir = self.cache / "release-gates/P00-test"
        receipt = json.loads((run_dir / "receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["name"], "attempted-java")
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["exitCode"], 0, "raw zero must not promote an unclean command")
        self.assertEqual(entry["durationSeconds"], 1.25)
        self.assertTrue(entry["cleanupUncertain"])
        self.assertIsNone(entry["headAfter"])
        self.assertIsNone(entry["workingTreeDigestAfter"])
        self.assertTrue(entry["log"].startswith("logs/.attempted-java.log."))
        self.assertEqual(entry["logSha256"], digest(b"partial private command log\n"))
        self.assertEqual(entry["naturalExitSettle"]["error"], "test uncertainty")
        self.assertEqual(receipt["gates"][1]["status"], "unreached")
        for name in ("cargo", "gradle"):
            owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
            self.assertTrue(owner["requiresManualRecovery"])
            self.assertEqual(owner["processGroupId"], 777)

    def test_admission_error_finalizing_uncertain_log_does_not_release_leases(self) -> None:
        attempted = run_gates.Gate("uncertain-log", ("java", "-version"))

        def uncertain_run(
            _argv: object, *, log_path: pathlib.Path, **_kwargs: object,
        ) -> tuple[int, float]:
            log_path.write_bytes(b"partial public synthetic log\n")
            os.chmod(log_path, 0o600)
            error = run_gates.UncertainProcessTree("owned tree did not drain", 777)
            error.command_started = True
            error.raw_exit_code = 0
            error.duration_seconds = 1.25
            error.owned_processes = {777: "started"}
            error.unconfirmed_processes = []
            raise error

        with mock.patch.object(run_gates, "GATES", (attempted,)), \
                mock.patch.object(run_gates, "_run", side_effect=uncertain_run), \
                mock.patch.object(
                    private_roots, "replace_private_file",
                    side_effect=private_roots.AdmissionError("synthetic admission failure"),
                ):
            self.assertEqual(run_gates.run(self.args()), 1)

        for name in ("cargo", "gradle"):
            lease = self.cache / "leases" / name
            self.assertTrue(lease.is_dir(), f"uncertain {name} lease was removed")
            owner = json.loads((lease / "owner.json").read_text())
            self.assertTrue(owner["requiresManualRecovery"])
            self.assertEqual(owner["processGroupId"], 777)
        receipt = json.loads(
            (self.cache / "release-gates" / "P00-test" / "receipt.json").read_text()
        )
        self.assertEqual(receipt["gates"][0]["exitCode"], 0)
        self.assertTrue(receipt["gates"][0]["cleanupUncertain"])
        self.assertIn("unavailable", receipt["gates"][0]["artifactFinalization"])

    def test_normal_return_finalization_failures_remain_attempted_gate_receipts(self) -> None:
        real_replace = os.replace
        real_hash_file = run_gates._hash_file
        real_tree_digest = run_gates._tree_state_digest

        for failure_stage in ("rename", "hash", "source"):
            with self.subTest(stage=failure_stage):
                args = self.args()
                args.label = f"P00-{failure_stage}"
                gate = run_gates.Gate("finalize", (sys.executable, "-c", "pass"))

                def normal_run(
                    _argv: object, *, log_path: pathlib.Path, **_kwargs: object,
                ) -> tuple[int, float]:
                    normal_returned[0] = True
                    log_path.write_bytes(b"command completed before finalization\n")
                    os.chmod(log_path, 0o600)
                    return 0, 0.75

                failure_reached = [False]

                def replace(
                    source: str | os.PathLike[str], destination: str | os.PathLike[str],
                    *args: object, **kwargs: object,
                ) -> None:
                    if failure_stage == "rename" and pathlib.Path(destination).name == "finalize.log":
                        failure_reached[0] = True
                        raise OSError("injected final log rename failure")
                    real_replace(source, destination, *args, **kwargs)

                def hash_file(path: pathlib.Path) -> str:
                    if failure_stage == "hash" and path.name == "finalize.log":
                        failure_reached[0] = True
                        raise OSError("injected final log hash failure")
                    return real_hash_file(path)

                tree_calls = [0]
                normal_returned = [False]

                def tree_digest(repo: pathlib.Path) -> str:
                    tree_calls[0] += 1
                    if failure_stage == "source" and normal_returned[0]:
                        failure_reached[0] = True
                        raise RuntimeError("injected post-command source read failure")
                    return real_tree_digest(repo)

                with mock.patch.object(run_gates, "GATES", (gate,)), \
                        mock.patch.object(run_gates, "_run", side_effect=normal_run), \
                        mock.patch.object(run_gates.os, "replace", side_effect=replace), \
                        mock.patch.object(run_gates, "_hash_file", side_effect=hash_file), \
                        mock.patch.object(run_gates, "_tree_state_digest", side_effect=tree_digest):
                    self.assertEqual(run_gates.run(args), 1)

                self.assertTrue(normal_returned[0], "normal command result must be reached")
                self.assertTrue(failure_reached[0], f"{failure_stage} injection must be reached")
                receipt = json.loads((self.cache / "release-gates" / args.label / "receipt.json").read_text())
                entry = receipt["gates"][0]
                self.assertEqual(entry["name"], "finalize")
                self.assertEqual(entry["status"], "failed")
                self.assertEqual(entry["exitCode"], 0, "raw command result remains visible")
                self.assertEqual(entry["durationSeconds"], 0.75)
                if failure_stage == "source":
                    self.assertEqual(entry["headAfter"], receipt["headBefore"])
                    self.assertIsNone(entry["workingTreeDigestAfter"])
                    self.assertIsNone(entry["phaseDiffSha256After"])
                elif failure_stage == "rename":
                    self.assertIsNone(entry["headAfter"])
                    self.assertIsNone(entry["workingTreeDigestAfter"])
                    self.assertIsNone(entry["phaseDiffSha256After"])
                else:
                    self.assertEqual(entry["headAfter"], receipt["headBefore"])
                    self.assertEqual(entry["workingTreeDigestAfter"], receipt["workingTreeDigestBefore"])
                    self.assertEqual(entry["phaseDiffSha256After"], receipt["phaseDiffSha256Before"])
                self.assertTrue(entry["log"].startswith("logs/"))
                self.assertEqual(receipt["decision"], "failed")

    def test_normal_return_version_log_read_failure_keeps_attempted_probe(self) -> None:
        logs = self.cache / "version-read-failure"
        logs.mkdir(mode=0o700, parents=True)
        log_path = logs / "version-probe.log"
        real_read_bytes = pathlib.Path.read_bytes

        def normal_probe(
            _argv: object, *, log_path: pathlib.Path, **_kwargs: object,
        ) -> tuple[int, float]:
            log_path.write_bytes(b"tool 1.2.3\n")
            os.chmod(log_path, 0o600)
            return 0, 0.5

        def read_bytes(path: pathlib.Path) -> bytes:
            if path == log_path:
                raise OSError("injected version log read failure")
            return real_read_bytes(path)

        probes: list[dict[str, object]] = []
        with mock.patch.object(run_gates, "VERSION_COMMANDS", (("probe", (sys.executable, "--version"), "."),)), \
                mock.patch.object(run_gates, "_run", side_effect=normal_probe), \
                mock.patch.object(pathlib.Path, "read_bytes", read_bytes):
            with self.assertRaisesRegex(RuntimeError, "version probe log could not be read"):
                REAL_VERSIONS(
                    self.repo, os.environ.copy(), logs, probes, names={"probe"},
                )

        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["name"], "probe")
        self.assertEqual(probes[0]["exitCode"], 0)
        self.assertEqual(probes[0]["durationSeconds"], 0.5)
        self.assertEqual(probes[0]["status"], "failed")
        self.assertEqual(probes[0]["logSha256"], digest(b"tool 1.2.3\n"))
        self.assertIn("unavailable", probes[0]["sourceIdentityAfter"])

    def test_pre_spawn_uncertainty_remains_unreached_not_attempted(self) -> None:
        attempted = run_gates.Gate("not-started", ("java", "-version"))

        def pre_spawn(_argv: object, **_kwargs: object) -> tuple[int, float]:
            error = run_gates.UncertainProcessTree("interrupted before spawn", -1)
            error.command_started = False
            raise error

        with mock.patch.object(run_gates, "GATES", (attempted,)), \
                mock.patch.object(run_gates, "_run", side_effect=pre_spawn):
            self.assertEqual(run_gates.run(self.args()), 1)

        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertEqual(receipt["gates"], [{
            "name": "not-started",
            "status": "unreached",
            "reason": "precondition or gate runner error",
        }])
        self.assertFalse((self.cache / "leases/cargo").exists())
        self.assertFalse((self.cache / "leases/gradle").exists())

    def test_attempted_log_io_failure_is_not_reported_as_unreached(self) -> None:
        attempted = run_gates.Gate("log-io", ("java", "-version"))

        def log_io_failure(
            _argv: object, *, log_path: pathlib.Path, **_kwargs: object,
        ) -> tuple[int, float]:
            log_path.write_bytes(b"flushed command output\n")
            os.chmod(log_path, 0o600)
            raise run_gates.AttemptedGateFailure(OSError("injected fsync error"), 7, 2.0)

        with mock.patch.object(run_gates, "GATES", (attempted,)), \
                mock.patch.object(run_gates, "_run", side_effect=log_io_failure):
            self.assertEqual(run_gates.run(self.args()), 1)

        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["exitCode"], 7)
        self.assertFalse(entry["cleanupUncertain"])
        self.assertEqual(entry["logSha256"], digest(b"flushed command output\n"))

    def test_owned_atomic_lease_fails_before_any_gate(self) -> None:
        lease_root = self.cache / "leases"
        lease_root.mkdir(mode=0o700)
        lease = self.cache / "leases/cargo"
        lease.mkdir(mode=0o700)
        owner = lease / "owner.json"
        owner.write_text('{"pid":123,"label":"owner","token":"' + "f" * 32 + '"}')
        owner.chmod(0o600)
        with mock.patch.object(run_gates, "GATES", ()):
            self.assertEqual(run_gates.run(self.args()), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertIn("already owned", receipt["error"])

    def test_timeout_kills_and_drains_spawned_grandchild_before_releasing_leases(self) -> None:
        script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,os.getpgid(child.pid),flush=True); time.sleep(60)"
        gate = run_gates.Gate("tree-timeout", (sys.executable, "-c", script))
        args = self.args()
        args.command_timeout = 0.4
        spawned: list[subprocess.Popen[bytes]] = []
        popen = subprocess.Popen

        def capture_process(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = popen(*argv, **kwargs)
            if kwargs.get("start_new_session"):
                spawned.append(process)
            return process

        with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates.subprocess, "Popen", side_effect=capture_process):
            with mock.patch.object(
                run_gates, "_untracked_processes_since",
                return_value=run_gates.UntrackedProcessScan([], [], None, 0),
            ):
                self.assertEqual(run_gates.run(args), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["exitCode"], 124)
        self.assertIn("owned process tree drained", (self.cache / "release-gates/P00-test" / entry["log"]).read_text())
        child_pid, child_pgid = map(int, (self.cache / "release-gates/P00-test" / entry["log"]).read_text().splitlines()[0].split())
        self.assertEqual(child_pgid, child_pid)
        self.assertNotEqual(child_pgid, spawned[0].pid)
        self.assertFalse(process_running(child_pid))
        self.assertFalse((self.cache / "leases/cargo").exists())
        self.assertFalse((self.cache / "leases/gradle").exists())

    def test_interrupt_kills_and_drains_spawned_grandchild(self) -> None:
        script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,os.getpgid(child.pid),flush=True); time.sleep(60)"
        gate = run_gates.Gate("tree-interrupt", (sys.executable, "-c", script))
        args = self.args()
        args.command_timeout = 10
        spawned: list[subprocess.Popen[bytes]] = []
        popen = subprocess.Popen

        def launch(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = popen(*argv, **kwargs)
            command = argv[0] if argv else kwargs.get("args")
            if (kwargs.get("start_new_session") and isinstance(command, (list, tuple))
                    and command and command[0] == sys.executable):
                spawned.append(process)
                wait = process.wait
                first_wait = True

                def interrupt_once(timeout: float | None = None) -> int:
                    nonlocal first_wait
                    if first_wait:
                        first_wait = False
                        time.sleep(0.25)
                        raise KeyboardInterrupt
                    return wait(timeout=timeout)

                process.wait = interrupt_once  # type: ignore[method-assign]
            return process

        with mock.patch.object(run_gates, "GATES", (gate,)), mock.patch.object(run_gates.subprocess, "Popen", side_effect=launch):
            self.assertEqual(run_gates.run(args), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        entry = receipt["gates"][0]
        self.assertEqual(entry["exitCode"], 130)
        self.assertIn("Gate interrupted; owned process tree drained", (self.cache / "release-gates/P00-test" / entry["log"]).read_text())
        child_pid, child_pgid = map(int, (self.cache / "release-gates/P00-test" / entry["log"]).read_text().splitlines()[0].split())
        self.assertEqual(child_pgid, child_pid)
        self.assertNotEqual(child_pgid, spawned[0].pid)
        self.assertFalse(process_running(child_pid))

    def test_completed_owned_descendant_is_drained_after_parent_exits(self) -> None:
        tracked = self.cache / "completed-owned-child-tracked"
        script = "\n".join((
            "import os, pathlib, subprocess, sys, time",
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)",
            "print(child.pid, os.getpgid(child.pid), flush=True)",
            f"marker = pathlib.Path({str(tracked)!r})",
            "deadline = time.monotonic() + 10",
            "while not marker.exists() and time.monotonic() < deadline:",
            "    time.sleep(.01)",
            "raise SystemExit(0 if marker.exists() else 91)",
        ))
        gate = run_gates.Gate("completed-owned-child", (sys.executable, "-c", script))
        args = self.args()
        args.label = "P00-completed-owned-child"
        spawned: list[subprocess.Popen[bytes]] = []
        real_popen = subprocess.Popen
        track_descendants = run_gates._track_descendants

        def track_and_mark(
            root: tuple[int, str],
            owned: dict[int, str],
            snapshot: dict[int, tuple[int, str, str]],
        ) -> None:
            track_descendants(root, owned, snapshot)
            if len(owned) > 1:
                tracked.write_text("tracked", encoding="utf-8")

        def capture_process(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*argv, **kwargs)
            command = argv[0] if argv else kwargs.get("args")
            if (kwargs.get("start_new_session") and isinstance(command, (list, tuple))
                    and command and command[0] == sys.executable):
                spawned.append(process)
            return process

        child_pid: int | None = None
        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_track_descendants", side_effect=track_and_mark), \
                    mock.patch.object(run_gates.subprocess, "Popen", side_effect=capture_process):
                self.assertEqual(run_gates.run(args), 1)
            receipt = json.loads((self.cache / "release-gates" / args.label / "receipt.json").read_text())
            entry = receipt["gates"][0]
            log = (self.cache / "release-gates" / args.label / entry["log"]).read_text()
            child_pid, child_pgid = map(int, log.splitlines()[0].split())
            self.assertTrue(tracked.exists(), "fixture must confirm positive descendant ownership before parent exit")
            self.assertEqual(entry["exitCode"], 125)
            self.assertIn("Gate left descendant processes running; tree drained", log)
            self.assertNotEqual(child_pgid, spawned[0].pid)
            self.assertFalse(process_running(child_pid))
            self.assertFalse((self.cache / "leases/cargo").exists())
            self.assertFalse((self.cache / "leases/gradle").exists())
        finally:
            if child_pid is None:
                try:
                    log_path = self.cache / "release-gates" / args.label / "logs" / "completed-owned-child.log"
                    child_pid = int(log_path.read_text().splitlines()[0].split()[0])
                except (OSError, ValueError, IndexError):
                    pass
            if child_pid is not None and process_running(child_pid):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for process in spawned:
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_uncertain_process_tree_retains_both_leases_for_manual_recovery(self) -> None:
        script = "import time; time.sleep(60)"
        gate = run_gates.Gate("uncertain-timeout", (sys.executable, "-c", script))
        later = run_gates.Gate("unreached", (sys.executable, "-c", "pass"))
        args = self.args()
        args.command_timeout = 0.2
        spawned: list[subprocess.Popen[bytes]] = []
        popen = subprocess.Popen

        def capture_process(*argv: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = popen(*argv, **kwargs)
            if kwargs.get("start_new_session"):
                spawned.append(process)
            return process

        try:
            with mock.patch.object(run_gates, "GATES", (gate, later)), mock.patch.object(run_gates.subprocess, "Popen", side_effect=capture_process), mock.patch.object(run_gates, "_stop_owned_process_tree", return_value=False):
                self.assertEqual(run_gates.run(args), 1)
            receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
            self.assertEqual(receipt["decision"], "failed")
            self.assertEqual(receipt["gates"][0]["name"], "uncertain-timeout")
            self.assertEqual(receipt["gates"][0]["status"], "failed")
            self.assertTrue(receipt["gates"][0]["cleanupUncertain"])
            self.assertIsNone(receipt["gates"][0]["exitCode"])
            self.assertTrue(receipt["gates"][0]["logSha256"])
            self.assertEqual(receipt["gates"][1]["status"], "unreached")
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn("could not be confirmed drained", owner["terminationStatus"])
                self.assertEqual(owner["processGroupId"], spawned[0].pid)
                self.assertTrue(owner["ownedProcesses"])
        finally:
            for process in spawned:
                _r2_killpg_created_group(process.pid)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_version_probe_timeout_drains_detached_child_and_fails_probe(self) -> None:
        script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,os.getpgid(child.pid),flush=True); time.sleep(60)"
        logs = self.cache / "version-probe-logs"
        child_pid: int | None = None
        probes: list[dict[str, object]] = []
        try:
            with mock.patch.object(run_gates, "VERSION_COMMANDS", (("probe", (sys.executable, "-c", script), "."),)):
                with self.assertRaises((RuntimeError, run_gates.UncertainProcessTree)) as context:
                    REAL_VERSIONS(self.repo, os.environ.copy(), logs, probes, timeout=0.4)
            if isinstance(context.exception, run_gates.UncertainProcessTree):
                self.assertRegex(str(context.exception), "timed-out process tree|post-command ownership scan")
            else:
                self.assertRegex(str(context.exception), "version probe probe failed with exit 124")
            version_log = logs / "version-probe.log"
            self.assertEqual(version_log.stat().st_mode & 0o777, 0o600)
            child_pid = int(version_log.read_text().splitlines()[0].split()[0])
            if process_running(child_pid):
                self.assertIsInstance(context.exception, run_gates.UncertainProcessTree)
            if probes:
                self.assertEqual(probes[0]["status"], "failed")
                self.assertEqual(probes[0]["exitCode"], 124)
                self.assertEqual(probes[0]["logSha256"], digest(version_log.read_bytes()))
        finally:
            if child_pid is None:
                try:
                    version_log = logs / "version-probe.log"
                    child_pid = int(version_log.read_text().splitlines()[0].split()[0])
                except (OSError, ValueError, IndexError):
                    pass
            if child_pid is not None and process_running(child_pid):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_repeated_real_fast_version_probes_do_not_misclassify_exited_roots(self) -> None:
        commands = []
        for tool in ("git", "node", "rustc"):
            binary = shutil.which(tool)
            if binary:
                commands.extend((f"{tool}-{index}", (binary, "--version"), ".") for index in range(5))
        self.assertTrue(commands, "at least git should be available for fast version probes")
        logs = self.cache / "fast-version-logs"
        probes: list[dict[str, object]] = []
        # Real probe processes, but the machine-wide scan sees only this test's own tree, so an
        # unrelated process starting elsewhere on the host cannot look like unowned churn.
        with mock.patch.object(run_gates, "VERSION_COMMANDS", tuple(commands)), \
                mock.patch.object(run_gates, "_process_snapshot", side_effect=own_process_snapshot()):
            versions = REAL_VERSIONS(self.repo, os.environ.copy(), logs, probes)
        self.assertEqual(len(probes), len(commands))
        self.assertTrue(all(probe["status"] == "passed" and probe["exitCode"] == 0 for probe in probes))
        self.assertEqual(set(versions), {command[0] for command in commands})
        self.assertTrue(all((logs / f"version-{command[0]}.log").is_file() for command in commands))

    def test_buf_version_probe_uses_workspace_executable(self) -> None:
        self.assertEqual(
            next(item for item in run_gates.VERSION_COMMANDS if item[0] == "buf"),
            ("buf", ("./node_modules/.bin/buf", "--version"), "adapters/node"),
        )

    def test_log_io_failure_preserves_uncertain_tree_and_both_leases(self) -> None:
        for failure_point in ("fsync", "close"):
            with self.subTest(failure_point=failure_point):
                args = self.args()
                args.label = f"P00-log-{failure_point}"
                script = "import os,subprocess,sys,time; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,flush=True); time.sleep(.35)"
                gate = run_gates.Gate(f"log-{failure_point}", (sys.executable, "-c", script))
                args.command_timeout = 5
                stop = mock.patch.object(run_gates, "_stop_and_reap_owned_tree", return_value=False)
                if failure_point == "fsync":
                    inject = mock.patch.object(run_gates, "_sync_log", side_effect=OSError("injected log fsync failure"))
                else:
                    real_close = run_gates._close_log

                    def close_then_fail(log: object) -> None:
                        real_close(log)
                        raise OSError("injected log close failure")

                    inject = mock.patch.object(run_gates, "_close_log", side_effect=close_then_fail)
                child_pid: int | None = None
                try:
                    with mock.patch.object(run_gates, "GATES", (gate,)), stop, inject:
                        self.assertEqual(run_gates.run(args), 1)
                    run_dir = self.cache / "release-gates" / args.label
                    receipt = json.loads((run_dir / "receipt.json").read_text())
                    self.assertIn("could not be confirmed drained", receipt["error"])
                    log_path = attempt_log_from_receipt(run_dir)
                    self.assertIsNotNone(log_path)
                    assert log_path is not None
                    entry = receipt["gates"][0]
                    self.assertEqual(entry["logSha256"], digest(log_path.read_bytes()))
                    child_pid = int(log_path.read_text().splitlines()[0])
                    for name in ("cargo", "gradle"):
                        owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                        self.assertTrue(owner["requiresManualRecovery"])
                        self.assertTrue(owner["ownedProcesses"])
                finally:
                    if child_pid is None:
                        try:
                            run_dir = self.cache / "release-gates" / args.label
                            log_path = attempt_log_from_receipt(run_dir)
                            if log_path is not None:
                                child_pid = int(log_path.read_text().splitlines()[0])
                        except (OSError, ValueError, IndexError):
                            pass
                    if child_pid is not None and process_running(child_pid):
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    for name in ("cargo", "gradle"):
                        lease_path = self.cache / "leases" / name
                        if lease_path.exists():
                            shutil.rmtree(lease_path)

    def test_fast_parent_cannot_leave_an_unobserved_detached_child(self) -> None:
        for index in range(5):
            with self.subTest(index=index):
                args = self.args()
                args.label = f"P00-fast-child-{index}"
                script = "import subprocess,sys; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,flush=True)"
                gate = run_gates.Gate("fast-detached-child", (sys.executable, "-c", script))
                with mock.patch.object(run_gates, "GATES", (gate,)):
                    self.assertEqual(run_gates.run(args), 1)
                run_dir = self.cache / "release-gates" / args.label
                receipt = json.loads((run_dir / "receipt.json").read_text())
                candidates = list((run_dir / "logs").glob(".*.tmp"))
                if not candidates:
                    candidates = list((run_dir / "logs").glob("fast-detached-child.log"))
                self.assertEqual(len(candidates), 1)
                child_pid = int(candidates[0].read_text().splitlines()[0])
                try:
                    if process_running(child_pid):
                        self.assertIn("unconfirmedProcesses", json.loads(
                            (self.cache / "leases/cargo/owner.json").read_text(),
                        ))
                        self.assertIn(str(child_pid), json.dumps(receipt.get("error", "")) + json.dumps(
                            json.loads((self.cache / "leases/cargo/owner.json").read_text()).get("unconfirmedProcesses", []),
                        ))
                    else:
                        self.assertEqual(receipt.get("decision"), "failed")
                    self.assertNotEqual(receipt.get("decision"), "checks_passed_for_review")
                finally:
                    if process_running(child_pid):
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    for name in ("cargo", "gradle"):
                        lease_path = self.cache / "leases" / name
                        if lease_path.exists():
                            shutil.rmtree(lease_path)

    def test_unrelated_concurrent_process_does_not_look_like_an_owned_descendant(self) -> None:
        log_path = self.cache / "unrelated-process.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        unrelated: subprocess.Popen[bytes] | None = None
        real_snapshot = run_gates._process_snapshot
        calls = 0

        def snapshot_with_concurrent_process(*, timeout: float = 2.0) -> dict[int, tuple[int, str, str]]:
            nonlocal calls, unrelated
            snapshot = real_snapshot(timeout=timeout)
            calls += 1
            if calls == 1:
                unrelated = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(600)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
            return snapshot

        try:
            with mock.patch.object(run_gates, "_process_snapshot", side_effect=snapshot_with_concurrent_process):
                code, _ = run_gates._run(
                    (sys.executable, "-c", "print('fast gate passed')"), cwd=self.repo,
                    env=os.environ.copy(), timeout=5, log_path=log_path,
                )
            self.assertEqual(code, 0)
            self.assertTrue(log_path.exists())
            self.assertIsNotNone(unrelated)
            self.assertIsNone(unrelated.poll())
        finally:
            if unrelated is not None:
                _r2_killpg_created_group(unrelated.pid)
                try:
                    unrelated.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_delayed_parent_escape_after_quarter_second_retains_both_leases(self) -> None:
        args = self.args()
        args.label = "P00-delayed-child"
        args.command_timeout = 5
        script = "import subprocess,sys,time; time.sleep(.35); child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); print(child.pid,flush=True)"
        gate = run_gates.Gate("delayed-detached-child", (sys.executable, "-c", script))
        child_pid: int | None = None
        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_track_descendants", return_value=None):
                self.assertEqual(run_gates.run(args), 1)
            run_dir = self.cache / "release-gates" / args.label
            receipt = json.loads((run_dir / "receipt.json").read_text())
            log_files = list((run_dir / "logs").glob(".*.tmp"))
            if not log_files:
                log_files = list((run_dir / "logs").glob("delayed-detached-child.log"))
            self.assertEqual(len(log_files), 1)
            child_pid = int(log_files[0].read_text().splitlines()[0])
            self.assertRegex(receipt["error"], "not observed as owned descendants|ownership scan incomplete")
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn(
                    child_pid,
                    [item["pid"] for item in owner["unconfirmedProcesses"]],
                )
        finally:
            if child_pid is None:
                try:
                    run_dir = self.cache / "release-gates" / args.label
                    log_files = list((run_dir / "logs").glob(".*.tmp"))
                    if not log_files:
                        log_files = list((run_dir / "logs").glob("delayed-detached-child.log"))
                    if log_files:
                        child_pid = int(log_files[0].read_text().splitlines()[0])
                except (OSError, ValueError, IndexError):
                    pass
            if child_pid is not None and process_running(child_pid):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for name in ("cargo", "gradle"):
                lease_path = self.cache / "leases" / name
                if lease_path.exists():
                    shutil.rmtree(lease_path)

    def test_interrupt_during_final_ownership_scan_retains_both_leases_and_candidate_pid(self) -> None:
        args = self.args()
        args.label = "P00-final-scan-interrupt"
        args.command_timeout = 5
        script = (
            "import subprocess,sys,time; time.sleep(.35); "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True); "
            "print(child.pid,flush=True)"
        )
        gate = run_gates.Gate("final-scan-interrupt", (sys.executable, "-c", script))
        real_scan = run_gates._untracked_processes_since

        def interrupt_final_scan(
            baseline: object, owned: object, snapshot: object, log_path: pathlib.Path,
            **kwargs: object,
        ):
            if "final-scan-interrupt" in log_path.name:
                raise KeyboardInterrupt
            return real_scan(baseline, owned, snapshot, log_path, **kwargs)  # type: ignore[arg-type]

        child_pid: int | None = None
        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_track_descendants", return_value=None), \
                    mock.patch.object(
                        run_gates, "_untracked_processes_since", side_effect=interrupt_final_scan,
                    ):
                self.assertEqual(run_gates.run(args), 1)
            run_dir = self.cache / "release-gates" / args.label
            receipt = json.loads((run_dir / "receipt.json").read_text())
            log_path = attempt_log_from_receipt(run_dir)
            self.assertIsNotNone(log_path)
            assert log_path is not None
            child_pid = int(log_path.read_text().splitlines()[0])
            self.assertEqual(receipt["gates"][0]["logSha256"], digest(log_path.read_bytes()))
            self.assertEqual(receipt["decision"], "failed")
            self.assertIn("post-command ownership scan could not be completed: KeyboardInterrupt", receipt["error"])
            self.assertTrue(process_running(child_pid), "unconfirmed candidate must not be signaled")
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn(
                    child_pid,
                    [item["pid"] for item in owner["unconfirmedProcesses"]],
                )
                self.assertNotEqual(owner["processGroupId"], child_pid)
        finally:
            if child_pid is None:
                try:
                    run_dir = self.cache / "release-gates" / args.label
                    log_path = attempt_log_from_receipt(run_dir)
                    if log_path is not None:
                        child_pid = int(log_path.read_text().splitlines()[0])
                except (OSError, ValueError, IndexError):
                    pass
            if child_pid is not None and process_running(child_pid):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for name in ("cargo", "gradle"):
                lease_path = self.cache / "leases" / name
                if lease_path.exists():
                    shutil.rmtree(lease_path)

    def test_untracked_scan_budget_exhaustion_retains_leases_without_killing_candidate(self) -> None:
        args = self.args()
        args.label = "P00-scan-budget"
        args.command_timeout = 5
        real_snapshot = run_gates._process_snapshot
        unrelated: subprocess.Popen[bytes] | None = None
        calls = 0

        def snapshot_with_concurrent_process(*, timeout: float = 2.0) -> dict[int, tuple[int, str, str]]:
            nonlocal calls, unrelated
            snapshot = real_snapshot(timeout=timeout)
            calls += 1
            if calls == 1:
                unrelated = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                )
            return snapshot

        try:
            with mock.patch.object(run_gates, "GATES", (run_gates.Gate("quick", (sys.executable, "-c", "pass")),)), \
                    mock.patch.object(run_gates, "_process_snapshot", side_effect=snapshot_with_concurrent_process), \
                    mock.patch.object(run_gates, "MAX_UNTRACKED_PROCESSES", 0):
                self.assertEqual(run_gates.run(args), 1)
            receipt = json.loads((self.cache / "release-gates" / args.label / "receipt.json").read_text())
            self.assertIn("inspection limit exceeded", receipt["error"])
            self.assertIsNotNone(unrelated)
            self.assertIsNone(unrelated.poll())
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertIn("inspection limit exceeded", owner["terminationStatus"])
        finally:
            if unrelated is not None:
                _r2_killpg_created_group(unrelated.pid)
                try:
                    unrelated.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            for name in ("cargo", "gradle"):
                lease_path = self.cache / "leases" / name
                if lease_path.exists():
                    shutil.rmtree(lease_path)

    @unittest.skipUnless(run_gates.LSOF_BINARY is not None, "lsof is required for bounded descriptor-probe tests")
    def test_lsof_all_fd_fallback_resolves_closed_stdio_and_detects_inherited_log_fd(self) -> None:
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        baseline: dict[int, tuple[int, str, str]] = {}
        closed_stdio = subprocess.Popen(
            [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        log_stream = log_path.open("ab", buffering=0)
        log_fd_child = subprocess.Popen(
            [sys.executable, "-c", "import os,time; os.dup2(1,3); os.close(1); os.close(2); time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=log_stream, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            time.sleep(0.1)
            real_snapshot = run_gates._process_snapshot()
            snapshot = {
                pid: real_snapshot[pid]
                for pid in (closed_stdio.pid, log_fd_child.pid)
                if pid in real_snapshot
            }
            self.assertEqual(set(snapshot), {closed_stdio.pid, log_fd_child.pid})
            with mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot):
                result = run_gates._untracked_processes_since(baseline, {}, snapshot, log_path)
            self.assertIsNone(result.error)
            self.assertFalse(result.uninspectable)
            self.assertEqual([item["pid"] for item in result.held], [log_fd_child.pid])
            self.assertEqual(result.held[0]["descriptorStatus"], "held")
            # A process with closed stdio is identified by the all-FD fallback
            # and is conclusively distinct from the log-holding candidate.
            self.assertNotIn(closed_stdio.pid, [item["pid"] for item in result.held])
        finally:
            log_stream.close()
            for child in (closed_stdio, log_fd_child):
                if process_running(child.pid):
                    _r2_killpg_created_group(child.pid)
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

    def test_missing_lsof_pid_record_falls_back_and_preserves_uncertain_metadata(self) -> None:
        pid = 424242
        snapshot = {pid: (7, "candidate-start", "S")}
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        calls: list[list[str]] = []

        def lsof(arguments: list[str], _deadline: float) -> run_gates.LsofProbe:
            calls.append(arguments)
            if "-d" in arguments:
                return run_gates.LsofProbe(0, "", "")
            return run_gates.LsofProbe(0, "", "")

        with mock.patch.object(pathlib.Path, "is_dir", return_value=False), \
                mock.patch.object(run_gates, "_run_lsof_fields", side_effect=lsof), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot):
            result = run_gates._untracked_processes_since({}, {}, snapshot, log_path)
        self.assertEqual(len(calls), 2, "missing stdio record must receive an all-FD fallback")
        self.assertNotIn("-d", calls[1])
        self.assertEqual(result.error, "untracked-process descriptor scan could not inspect every live candidate")
        self.assertEqual(result.held, [])
        self.assertEqual(result.uninspectable[0]["pid"], pid)
        self.assertEqual(result.uninspectable[0]["startedAt"], "candidate-start")
        self.assertEqual(result.uninspectable[0]["observedParentPid"], 7)
        self.assertEqual(result.uninspectable[0]["descriptorStatus"], "uninspectable")

    def test_unconfirmed_descriptor_candidates_keep_total_count_and_bounded_sample(self) -> None:
        snapshot = {pid: (1, f"start-{pid}", "S") for pid in range(1000, 1070)}
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        with mock.patch.object(pathlib.Path, "is_dir", return_value=False), \
                mock.patch.object(run_gates, "_run_lsof_fields", return_value=run_gates.LsofProbe(0, "", "")), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot), \
                mock.patch.object(run_gates, "MAX_UNCONFIRMED_SAMPLE", 8):
            result = run_gates._untracked_processes_since({}, {}, snapshot, log_path)
        self.assertEqual(result.candidate_count, 70)
        self.assertEqual(len(result.unconfirmed), 8)
        self.assertEqual([item["pid"] for item in result.unconfirmed], list(range(1000, 1008)))
        self.assertTrue(result.error)

    def test_lsof_probe_enforces_timeout_and_output_byte_budget(self) -> None:
        with mock.patch.object(run_gates, "LSOF_BINARY", sys.executable):
            started = time.monotonic()
            timed_out = run_gates._run_lsof_fields(
                ["-c", "import time; time.sleep(30)"], time.monotonic() + 0.15,
            )
            self.assertEqual(timed_out.error, "time-budget-exceeded")
            self.assertLess(time.monotonic() - started, 2)
            oversized = run_gates._run_lsof_fields(
                ["-c", "import sys,time; sys.stdout.write('x' * 2000000); sys.stdout.flush(); time.sleep(30)"],
                time.monotonic() + 2,
            )
            self.assertEqual(oversized.error, "output-limit-exceeded")
            self.assertLessEqual(len(oversized.stdout.encode()) + len(oversized.stderr.encode()), run_gates.MAX_LSOF_OUTPUT_BYTES + 65536)

    def test_lsof_parser_never_resolves_untrusted_names_and_rejects_ambiguous_log_alias(self) -> None:
        ordinary = run_gates.LsofProbe(0, "p123\nf1\nn/Volumes/other/data.db\n", "")
        with mock.patch.object(run_gates.os.path, "realpath", side_effect=AssertionError("per-name filesystem resolution")):
            parsed, error = run_gates._parse_lsof_fields(ordinary, {123}, "/private/tmp/private-gate.log")
        self.assertIsNone(error)
        self.assertEqual(parsed, ({123}, set()))

        ambiguous = run_gates.LsofProbe(
            0, "p123\nf1\nn/private/tmp/private-gate.log (deleted)\n", "",
        )
        parsed, error = run_gates._parse_lsof_fields(ambiguous, {123}, "/private/tmp/private-gate.log")
        self.assertEqual(error, "query-returned-malformed-fields")
        self.assertEqual(parsed, (set(), set()))

    def test_unreaped_lsof_probe_is_bounded_and_preserves_owned_identity(self) -> None:
        class UnreapableProbe:
            pid = 987654
            returncode = None

            def poll(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                if timeout is None:
                    raise AssertionError("probe wait must always be bounded")
                raise subprocess.TimeoutExpired("lsof", timeout)

        process = UnreapableProbe()
        with mock.patch.object(run_gates.os, "killpg", side_effect=PermissionError), \
                mock.patch.object(run_gates, "_lsof_process_group_state", return_value=None):
            drained, error = run_gates._terminate_lsof_process_group(process, time.monotonic() + 1)  # type: ignore[arg-type]
        self.assertFalse(drained)
        self.assertEqual(error, "probe-signal-failed")
        self.assertIsNone(process.returncode)

    def test_linux_mixed_proc_candidates_keep_inaccessible_live_process_uncertain(self) -> None:
        first_pid, second_pid = 424240, 424241
        snapshot = {
            first_pid: (7, "first-start", "S"),
            second_pid: (8, "second-start", "S"),
        }
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")

        def inspect(pid: int, _log_path: pathlib.Path) -> bool | None:
            return True if pid == first_pid else None

        with mock.patch.object(pathlib.Path, "is_dir", return_value=True), \
                mock.patch.object(run_gates, "_process_holds_log", side_effect=inspect), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=snapshot):
            result = run_gates._untracked_processes_since({}, {}, snapshot, log_path)
        self.assertEqual([item["pid"] for item in result.held], [first_pid])
        self.assertEqual([item["pid"] for item in result.uninspectable], [second_pid])
        self.assertEqual(result.error, "untracked-process descriptor scan could not inspect every live candidate")

    def test_process_fd_inspection_reports_inaccessible_linux_directory(self) -> None:
        pid = 424242
        fd_directory = pathlib.Path(f"/proc/{pid}/fd")
        log_path = self.root / "private-gate.log"
        log_path.write_text("private\n")
        real_is_dir = pathlib.Path.is_dir
        def is_dir(path: pathlib.Path) -> bool:
            if path == fd_directory:
                return False
            return real_is_dir(path)

        with mock.patch.object(pathlib.Path, "is_dir", is_dir):
            self.assertIsNone(run_gates._process_holds_log(pid, log_path))

    def test_probe_interrupt_and_selector_failure_cleanup_are_bounded_and_report_identity(self) -> None:
        class ProbeStream:
            def __init__(self, descriptor: int) -> None:
                self.descriptor = descriptor

            def fileno(self) -> int:
                return self.descriptor

            def close(self) -> None:
                return None

        class UnreapableProbe:
            pid = 987655
            returncode = None
            stdout = ProbeStream(91)
            stderr = ProbeStream(92)

            def poll(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                if timeout is None:
                    raise AssertionError("probe wait must always be bounded")
                raise subprocess.TimeoutExpired("lsof", timeout)

        class FailingSelector:
            def __init__(self, failure: BaseException) -> None:
                self.failure = failure

            def register(self, *_args: object, **_kwargs: object) -> None:
                return None

            def get_map(self) -> dict[int, int]:
                return {1: 1}

            def select(self, _timeout: float) -> list[object]:
                raise self.failure

            def close(self) -> None:
                return None

        for failure in (KeyboardInterrupt(), OSError("selector failure")):
            with self.subTest(failure=type(failure).__name__):
                process = UnreapableProbe()
                selector = FailingSelector(failure)
                with mock.patch.object(run_gates, "LSOF_BINARY", sys.executable), \
                        mock.patch.object(run_gates.subprocess, "Popen", return_value=process), \
                        mock.patch.object(run_gates, "_process_start_identity", return_value="probe-start"), \
                        mock.patch.object(run_gates.selectors, "DefaultSelector", return_value=selector), \
                        mock.patch.object(run_gates.os, "set_blocking"), \
                        mock.patch.object(run_gates.os, "killpg", side_effect=PermissionError), \
                        mock.patch.object(run_gates, "_lsof_process_group_state", return_value=None):
                    if isinstance(failure, KeyboardInterrupt):
                        with self.assertRaises(run_gates.InterruptedProbeCleanup) as raised:
                            run_gates._run_lsof_fields([], time.monotonic() + 1)
                        self.assertEqual(
                            raised.exception.owned_probe_processes[0]["startedAt"], "probe-start",
                        )
                    else:
                        result = run_gates._run_lsof_fields([], time.monotonic() + 1)
                        self.assertEqual(result.error, "probe-not-confirmed-drained")
                        self.assertEqual(result.owned_probe["startedAt"], "probe-start")

    def test_probe_wait_poll_and_stream_close_errors_keep_owned_identity(self) -> None:
        class ProbeStream:
            def __init__(self, descriptor: int, fail_close: bool = False) -> None:
                self.descriptor = descriptor
                self.fail_close = fail_close

            def fileno(self) -> int:
                return self.descriptor

            def close(self) -> None:
                if self.fail_close:
                    raise OSError("injected close failure")

        class ProbeProcess:
            pid = 987657
            returncode = None

            def __init__(self, failure: str, fail_close: bool = False) -> None:
                self.failure = failure
                self.stdout = ProbeStream(95, fail_close)
                self.stderr = ProbeStream(96, fail_close)

            def poll(self) -> int | None:
                if self.failure == "poll":
                    raise OSError("injected poll failure")
                return None

            def wait(self, timeout: float | None = None) -> int:
                if timeout is None:
                    raise AssertionError("probe wait must always be bounded")
                if self.failure in {"wait", "poll"}:
                    raise OSError("injected wait failure")
                return 0

        class FailingSelector:
            def __init__(self, fail_select: bool) -> None:
                self.fail_select = fail_select

            def register(self, *_args: object, **_kwargs: object) -> None:
                return None

            def get_map(self) -> dict[int, int]:
                return {1: 1} if self.fail_select else {}

            def select(self, _timeout: float) -> list[object]:
                raise OSError("injected selector failure")

            def close(self) -> None:
                return None

        for failure in ("wait", "poll"):
            with self.subTest(failure=failure):
                process = ProbeProcess(failure, fail_close=True)
                selector = FailingSelector(True)
                with mock.patch.object(run_gates, "LSOF_BINARY", sys.executable), \
                        mock.patch.object(run_gates.subprocess, "Popen", return_value=process), \
                        mock.patch.object(run_gates, "_process_start_identity", return_value="probe-start"), \
                        mock.patch.object(run_gates.selectors, "DefaultSelector", return_value=selector), \
                        mock.patch.object(run_gates.os, "set_blocking"), \
                        mock.patch.object(run_gates.os, "killpg", side_effect=PermissionError), \
                        mock.patch.object(run_gates, "_lsof_process_group_state", return_value=None):
                    result = run_gates._run_lsof_fields([], time.monotonic() + 1)
                self.assertEqual(result.error, "probe-not-confirmed-drained")
                self.assertEqual(result.owned_probe["pid"], process.pid)
                self.assertEqual(result.owned_probe["startedAt"], "probe-start")

        process = ProbeProcess("none", fail_close=True)
        process.returncode = 0
        selector = FailingSelector(False)
        with mock.patch.object(run_gates, "LSOF_BINARY", sys.executable), \
                mock.patch.object(run_gates.subprocess, "Popen", return_value=process), \
                mock.patch.object(run_gates, "_process_start_identity", return_value="probe-start"), \
                mock.patch.object(run_gates.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(run_gates.os, "set_blocking"), \
                mock.patch.object(run_gates, "_lsof_process_group_state", return_value=False):
            result = run_gates._run_lsof_fields([], time.monotonic() + 1)
        self.assertEqual(result.error, "probe-not-confirmed-drained")
        self.assertEqual(result.owned_probe["pid"], process.pid)
        self.assertEqual(result.owned_probe["reason"], "probe-resource-cleanup-failed")

    def test_interrupt_during_probe_reap_triggers_bounded_cleanup_with_identity(self) -> None:
        class ProbeStream:
            def __init__(self, descriptor: int) -> None:
                self.descriptor = descriptor

            def fileno(self) -> int:
                return self.descriptor

            def close(self) -> None:
                return None

        class InterruptedWaitProbe:
            pid = 987656
            returncode = None
            stdout = ProbeStream(93)
            stderr = ProbeStream(94)

            def poll(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                if timeout is None:
                    raise AssertionError("probe wait must always be bounded")
                raise KeyboardInterrupt

        class EmptySelector:
            def register(self, *_args: object, **_kwargs: object) -> None:
                return None

            def get_map(self) -> dict[int, int]:
                return {}

            def close(self) -> None:
                return None

        process = InterruptedWaitProbe()
        with mock.patch.object(run_gates, "LSOF_BINARY", sys.executable), \
                mock.patch.object(run_gates.subprocess, "Popen", return_value=process), \
                mock.patch.object(run_gates, "_process_start_identity", return_value="probe-start"), \
                mock.patch.object(run_gates.selectors, "DefaultSelector", return_value=EmptySelector()), \
                mock.patch.object(run_gates.os, "set_blocking"), \
                mock.patch.object(run_gates.os, "killpg", side_effect=PermissionError), \
                mock.patch.object(run_gates, "_lsof_process_group_state", return_value=None):
            with self.assertRaises(run_gates.InterruptedProbeCleanup) as raised:
                run_gates._run_lsof_fields([], time.monotonic() + 1)
        self.assertEqual(raised.exception.owned_probe_processes[0]["pid"], process.pid)

    def test_interrupted_descriptor_scan_retains_unconfirmed_candidate_in_both_leases(self) -> None:
        args = self.args()
        args.label = "P00-uninspectable-candidate"
        args.command_timeout = 5
        script = (
            "import subprocess,sys,time; time.sleep(.35); "
            "child=subprocess.Popen([sys.executable,'-c','import os,time; os.close(1); os.close(2); time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); "
            "print(child.pid,flush=True)"
        )
        gate = run_gates.Gate("uninspectable-candidate", (sys.executable, "-c", script))
        child_pid: int | None = None
        probe_identity = {"pid": 654321, "startedAt": "Mon Oct  5 12:00:00 2026", "processGroupId": 654321, "reason": "probe-reap-deadline-exceeded"}
        real_is_dir = pathlib.Path.is_dir
        # The interrupted probe is an lsof probe. Force the scanner's lsof branch on every
        # host: on Linux the /proc branch would otherwise be used, no probe would run, and the
        # candidate would simply exit naturally (correctly) inside the settle window.
        with mock.patch.object(run_gates, "_track_descendants", return_value=None), \
                mock.patch.object(run_gates, "_process_holds_log", return_value=None), \
                mock.patch.object(run_gates, "LSOF_BINARY", "/usr/sbin/lsof"), \
                mock.patch.object(pathlib.Path, "is_dir", lambda path: False if str(path) == "/proc" else real_is_dir(path)), \
                mock.patch.object(run_gates, "_run_lsof_fields", side_effect=run_gates.InterruptedProbeCleanup(probe_identity)), \
                mock.patch.object(run_gates, "GATES", (gate,)):
            try:
                self.assertEqual(run_gates.run(args), 1)
                run_dir = self.cache / "release-gates" / args.label
                receipt = json.loads((run_dir / "receipt.json").read_text())
                log_path = attempt_log_from_receipt(run_dir)
                self.assertIsNotNone(log_path)
                assert log_path is not None
                child_pid = int(log_path.read_text().splitlines()[0])
                self.assertEqual(receipt["gates"][0]["logSha256"], digest(log_path.read_bytes()))
                self.assertIn("InterruptedProbeCleanup", receipt["error"])
                self.assertTrue(process_running(child_pid), "unconfirmed candidate must not be signaled")
                for name in ("cargo", "gradle"):
                    owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                    self.assertTrue(owner["requiresManualRecovery"])
                    self.assertGreaterEqual(owner["unconfirmedProcessCount"], 1)
                    self.assertEqual(
                        owner["unconfirmedProcessesTruncated"],
                        owner["unconfirmedProcessCount"] > len(owner["unconfirmedProcesses"]),
                    )
                    self.assertTrue(any(
                        item["pid"] == child_pid and item["descriptorStatus"] == "uninspectable"
                        for item in owner["unconfirmedProcesses"]
                    ))
                    self.assertEqual(owner["ownedProbeProcesses"], [probe_identity])
            finally:
                if child_pid is None:
                    try:
                        run_dir = self.cache / "release-gates" / args.label
                        log_path = attempt_log_from_receipt(run_dir)
                        if log_path is not None:
                            child_pid = int(log_path.read_text().splitlines()[0])
                    except (OSError, ValueError, IndexError):
                        pass
                if child_pid is not None and process_running(child_pid):
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for name in ("cargo", "gradle"):
                    lease_path = self.cache / "leases" / name
                    if lease_path.exists():
                        shutil.rmtree(lease_path)

    def test_mixed_linux_descriptor_scan_retains_both_leases_without_signaling_candidate(self) -> None:
        args = self.args()
        args.label = "P00-mixed-proc-candidates"
        args.command_timeout = 5
        script = (
            "import subprocess,sys,time; time.sleep(.35); "
            "a=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); "
            "b=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); "
            "print(a.pid,b.pid,flush=True)"
        )
        gate = run_gates.Gate("mixed-proc-candidates", (sys.executable, "-c", script))
        child_pids: list[int] = []
        current_log_path: pathlib.Path | None = None
        real_scan = run_gates._untracked_processes_since
        real_is_dir = pathlib.Path.is_dir
        real_iterdir = pathlib.Path.iterdir
        real_readlink = os.readlink

        def scan(baseline: dict[int, tuple[int, str, str]], owned: dict[int, str],
                 snapshot: dict[int, tuple[int, str, str]], log_path: pathlib.Path, **kwargs: object):
            nonlocal current_log_path
            current_log_path = log_path
            if not child_pids:
                child_pids.extend(int(value) for value in log_path.read_text().split())
            return real_scan(baseline, owned, snapshot, log_path, **kwargs)  # type: ignore[arg-type]

        def is_dir(path: pathlib.Path) -> bool:
            if path == pathlib.Path("/proc"):
                return True
            if path.name == "fd" and path.parent.parent == pathlib.Path("/proc"):
                try:
                    candidate_pid = int(path.parent.name)
                except ValueError:
                    return real_is_dir(path)
                if len(child_pids) == 2 and candidate_pid == child_pids[1]:
                    return False
                if len(child_pids) == 2 and candidate_pid == child_pids[0]:
                    return True
            return real_is_dir(path)

        def iterdir(path: pathlib.Path):
            if len(child_pids) == 2 and path == pathlib.Path(f"/proc/{child_pids[0]}/fd"):
                return iter((path / "1",))
            return real_iterdir(path)

        def readlink(path: pathlib.Path | str) -> str:
            if len(child_pids) == 2 and pathlib.Path(path) == pathlib.Path(f"/proc/{child_pids[0]}/fd/1"):
                if current_log_path is not None:
                    return os.path.realpath(current_log_path)
            return real_readlink(path)

        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_track_descendants", return_value=None), \
                    mock.patch.object(run_gates, "_untracked_processes_since", side_effect=scan), \
                    mock.patch.object(pathlib.Path, "is_dir", is_dir), \
                    mock.patch.object(pathlib.Path, "iterdir", iterdir), \
                    mock.patch.object(run_gates.os, "readlink", side_effect=readlink):
                self.assertEqual(run_gates.run(args), 1)
            run_dir = self.cache / "release-gates" / args.label
            logs = list((run_dir / "logs").glob(".*.tmp"))
            if not logs:
                logs = list((run_dir / "logs").glob("mixed-proc-candidates.log"))
            self.assertEqual(len(logs), 1)
            child_pids = [int(value) for value in logs[0].read_text().split()]
            self.assertEqual(len(child_pids), 2)
            self.assertTrue(all(process_running(pid) for pid in child_pids), "unowned candidates must not be signaled")
            receipt = json.loads((run_dir / "receipt.json").read_text())
            self.assertEqual(receipt["decision"], "failed")
            self.assertIn("descriptor scan could not inspect every live candidate", receipt["error"])
            for name in ("cargo", "gradle"):
                owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
                self.assertTrue(owner["requiresManualRecovery"])
                self.assertGreaterEqual(owner["unconfirmedProcessCount"], 2)
                recorded = {item["pid"]: item for item in owner["unconfirmedProcesses"]}
                self.assertTrue(set(child_pids).issubset(recorded))
                self.assertEqual(recorded[child_pids[0]]["descriptorStatus"], "held")
                self.assertEqual(recorded[child_pids[1]]["descriptorStatus"], "uninspectable")
        finally:
            for pid in child_pids:
                if process_running(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            for name in ("cargo", "gradle"):
                lease_path = self.cache / "leases" / name
                if lease_path.exists():
                    shutil.rmtree(lease_path)

    def test_provenance_classified_non_descendant_is_recorded_and_does_not_block_a_run(self) -> None:
        """Companion to the mixed-candidates test, which keeps provenance OFF (unclassifiable
        candidates must still retain both leases). Here an uninspectable detached process is
        positively classified, so the run passes with evidence and nothing is signaled."""
        args = self.args()
        args.label = "P00-classified-candidate"
        args.command_timeout = 5
        args.provenance = True
        script = (
            "import subprocess,sys,time; time.sleep(.35); "
            "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); "
            f"open({str(self.root / 'detached-child.pid')!r},'w').write(str(c.pid)); "
            "print(c.pid,flush=True)"
        )
        gate = run_gates.Gate("classified-candidate", (sys.executable, "-c", script))
        child_pids: list[int] = []
        real_is_dir = pathlib.Path.is_dir

        class StubProvenance:
            def __init__(self, **_ignored: object) -> None:
                self.recorded: list[dict[str, object]] = []

            def start(self) -> bool:
                return True

            def note_root(self, pid: int) -> None:
                pass

            def observe(self, snapshot: object, baseline: object, owned: object) -> None:
                pass

            def stop(self) -> None:
                pass

            def classify(self, unknowns: list, scan: object, fresh: object, owned: object, deadline: float) -> dict:
                found = {pid: {"pid": pid, "startedAt": started, "classification": provenance.CLASS_SUBREAPER,
                               "uidClass": "other"} for pid, started in unknowns}
                self.recorded.extend(found.values())
                return found

            def report(self) -> dict[str, object]:
                return {"mode": "subreaper", "available": True, "classifiedCount": len(self.recorded),
                        "classifiedIdentities": list(self.recorded)}

        def is_dir(path: pathlib.Path) -> bool:
            # Every candidate's descriptor table is unreadable, like another user's process.
            if path.name == "fd" and path.parent.parent == pathlib.Path("/proc"):
                return False
            return True if path == pathlib.Path("/proc") else real_is_dir(path)

        def gate_children() -> list[int]:
            # The gate records the detached child's pid; it is reparented away from the test
            # tree, so name it explicitly. Unrelated host processes stay invisible.
            try:
                return [int((self.root / "detached-child.pid").read_text())]
            except (OSError, ValueError):
                return []

        try:
            with mock.patch.object(run_gates, "GATES", (gate,)), \
                    mock.patch.object(run_gates, "_track_descendants", return_value=None), \
                    mock.patch.object(run_gates, "_process_snapshot", side_effect=own_process_snapshot(gate_children)), \
                    mock.patch.object(run_gates.provenance_module, "Provenance", StubProvenance), \
                    mock.patch.object(pathlib.Path, "is_dir", is_dir):
                code = run_gates.run(args)
            run_dir = self.cache / "release-gates" / args.label
            receipt = json.loads((run_dir / "receipt.json").read_text())
            logs = list((run_dir / "logs").glob("classified-candidate.log"))
            self.assertEqual(len(logs), 1)
            child_pids = [int(value) for value in logs[0].read_text().split()]
            self.assertEqual(code, 0, receipt.get("error"))
            self.assertEqual(receipt["decision"], "checks_passed_for_review")
            evidence = receipt["gates"][0]["provenance"]
            self.assertEqual(evidence["classifiedCount"], 1)
            self.assertEqual(evidence["classifiedIdentities"][0]["pid"], child_pids[0])
            self.assertEqual(evidence["classifiedIdentities"][0]["classification"], provenance.CLASS_SUBREAPER)
            self.assertTrue(process_running(child_pids[0]), "a classified non-descendant is never signaled")
            self.assertFalse((self.cache / "leases/cargo").exists())
            self.assertFalse((self.cache / "leases/gradle").exists())
        finally:
            for pid in child_pids:
                if process_running(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_source_change_during_gate_fails_exact_tree_receipt(self) -> None:
        gate = run_gates.Gate("mutating-gate", (sys.executable, "-c", "open('source-drift.txt','w').write('changed')"))
        later = run_gates.Gate("must-not-run", (sys.executable, "-c", "raise SystemExit(0)"))
        with mock.patch.object(run_gates, "GATES", (gate, later)):
            self.assertEqual(run_gates.run(self.args()), 1)
        receipt = json.loads((self.cache / "release-gates/P00-test/receipt.json").read_text())
        self.assertEqual(receipt["decision"], "failed")
        self.assertEqual([item["status"] for item in receipt["gates"]], ["failed", "unreached"])
        self.assertIn("source identity changed during gate", receipt["gates"][0]["integrityFailure"])

    def test_non_ancestor_base_fails_before_gate(self) -> None:
        subprocess.run(["git", "-C", str(self.repo), "checkout", "--orphan", "other"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "other"], check=True)
        with mock.patch.object(run_gates, "GATES", ()):
            with self.assertRaisesRegex(ValueError, "ancestor"):
                run_gates.run(self.args())


class LeasedRunTests(unittest.TestCase):
    """Behavior of tools.release.leased_run.

    The filesystem admission layer is replaced by plain-directory equivalents so
    these tests exercise the runner's own logic (lease polling, env, receipt,
    retention, exit codes) deterministically; real private-root admission is
    covered by the admission and RunnerTests suites. `run_gates._run` is faked
    with callables that write the log and return or raise like the real one.
    """

    TOKEN = "ab" * 16

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=test_scratch_root())
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "tracked.txt").write_text("one\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "base"], check=True)
        self.cache = self.root / "cache"
        self.cache.mkdir(mode=0o700)
        self.clock = FakeClock()
        self.lines: list[str] = []

        def identity(path: object) -> tuple[int, int]:
            info = os.stat(path)
            return info.st_dev, info.st_ino

        def preflight(path: object, *, private_leaf: bool = True, must_be_absent: bool = False) -> None:
            if must_be_absent and os.path.lexists(path):
                raise FileExistsError("exists")

        def admit(path: object, *, private_leaf: bool = False) -> tuple[int, int]:
            if not os.path.isdir(path):
                raise private_roots.AdmissionError("private cache admission failed")
            return identity(path)

        def ensure(path: object, *, must_create: bool = False) -> tuple[int, int]:
            if must_create and os.path.lexists(path):
                raise FileExistsError("exists")
            os.makedirs(path, mode=0o700, exist_ok=True)
            return identity(path)

        def atomic_write(path: object, data: bytes) -> None:
            pathlib.Path(os.fspath(path)).write_bytes(data)
            os.chmod(path, 0o600)

        def read_json(path: object, **_kwargs: object) -> dict:
            return json.loads(pathlib.Path(os.fspath(path)).read_text())

        patches = [
            mock.patch.object(private_roots, "preflight_directory", side_effect=preflight),
            mock.patch.object(private_roots, "admit_directory", side_effect=admit),
            mock.patch.object(private_roots, "ensure_private_directory", side_effect=ensure),
            mock.patch.object(private_roots, "atomic_write_private", side_effect=atomic_write),
            mock.patch.object(private_roots, "read_private_json", side_effect=read_json),
            mock.patch.object(private_roots, "open_private_file_read", side_effect=lambda path: os.open(path, os.O_RDONLY)),
            mock.patch.object(private_roots, "replace_private_file", side_effect=lambda src, dst, _identity: os.replace(src, dst)),
            mock.patch.object(private_roots, "normalize_directory_path", side_effect=lambda value: pathlib.Path(value)),
            mock.patch.object(leased_run.secrets, "token_hex", return_value=self.TOKEN),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def args(self, label: str = "leased-test-1", **overrides: object) -> Namespace:
        values = dict(
            repo=str(self.repo), label=label, cache_root=str(self.cache), timeout=30.0, wait=0.0,
            jdk_home=None, expect_unittest=None, argv=["cargo", "build"], pass_env=[],
        )
        values.update(overrides)
        return Namespace(**values)

    def fake_run(self, log: bytes = b"", code: int = 0, raise_exc: BaseException | None = None,
                 mutate: object = None, prov_report: dict | None = None) -> mock._patch:
        captured: dict[str, object] = {}
        self.captured = captured

        def fake(argv: list[str], *, cwd: pathlib.Path, env: dict[str, str], timeout: float,
                 log_path: pathlib.Path, settle_report: dict | None = None,
                 max_log_bytes: int | None = None, provenance: bool = False,
                 provenance_report: dict | None = None) -> tuple[int, float]:
            captured.update(
                provenance=provenance,
                scratch_existed=pathlib.Path(env["XTRACE_TEST_SCRATCH_ROOT"]).is_dir(), max_log_bytes=max_log_bytes,
                home_existed=pathlib.Path(env.get("HOME", "/nonexistent")).is_dir(),
                argv=list(argv), cwd=cwd, env=dict(env), timeout=timeout,
                held=sorted(path.name for path in (self.cache / "leases").iterdir()),
                log_name=pathlib.Path(log_path).name,
            )
            pathlib.Path(log_path).write_bytes(log)
            if prov_report and provenance_report is not None:
                provenance_report.update(prov_report)
            if callable(mutate):
                mutate()
            if raise_exc is not None:
                raise raise_exc
            return code, 0.5

        return mock.patch.object(run_gates, "_run", side_effect=fake)

    def go(self, args: Namespace | None = None) -> int:
        return leased_run.run(
            args or self.args(), monotonic=self.clock.monotonic, sleep=self.clock.sleep, out=self.lines.append,
        )

    def receipt(self, label: str = "leased-test-1") -> dict:
        return json.loads((self.cache / "release-gates" / label / "receipt.json").read_text())

    def leases_present(self) -> list[str]:
        directory = self.cache / "leases"
        return sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []

    def uncertain(self) -> run_gates.UncertainProcessTree:
        error = run_gates.UncertainProcessTree("process tree could not be confirmed drained", 4242)
        error.command_started = True
        error.raw_exit_code = 0
        error.duration_seconds = 2.0
        error.owned_processes = {4243: "owned-start"}
        return error

    def test_passing_run_uses_task_scoped_env_holds_both_leases_and_releases_them(self) -> None:
        jdk = self.root / "jdk"
        (jdk / "bin").mkdir(parents=True)
        (jdk / "bin" / "java").write_text("")
        with self.fake_run(log=b"Ran 3 tests in 0.010s\n\nOK\n"):
            code = self.go(self.args(expect_unittest=3, jdk_home=str(jdk)))
        self.assertEqual(code, leased_run.EXIT_PASSED)
        self.assertEqual(self.captured["held"], ["cargo", "gradle"], "both leases are held while the command runs")
        self.assertEqual(self.leases_present(), [], "leases released after success")
        env = self.captured["env"]
        scratch = self.cache / "tmp" / "leased-test-1-scratch"
        self.assertTrue(self.captured["scratch_existed"], "per-run scratch exists while the command runs")
        self.assertFalse(scratch.exists(), "scratch is removed after a passing run and a successful release")
        self.assertEqual(self.receipt()["scratchCleanup"], "removed")
        self.assertEqual(self.captured["max_log_bytes"], leased_run.MAX_LOG_BYTES)
        expected = {
            "CARGO_HOME": self.cache / "cargo", "CARGO_TARGET_DIR": self.cache / "cargo-target",
            "GRADLE_USER_HOME": self.cache / "gradle", "NPM_CONFIG_CACHE": self.cache / "npm",
            "PLAYWRIGHT_BROWSERS_PATH": self.cache / "playwright", "XDG_CACHE_HOME": self.cache / "xdg",
            "TMPDIR": scratch, "TMP": scratch, "TEMP": scratch,
            "XTRACE_TEST_SCRATCH_ROOT": scratch, "XTRACE_TEST_PRIVATE_SCRATCH": scratch,
        }
        for name, value in expected.items():
            self.assertEqual(env[name], str(value), name)  # type: ignore[index]
        self.assertEqual(env["JAVA_HOME"], str(jdk))  # type: ignore[index]
        self.assertTrue(env["PATH"].startswith(str(jdk / "bin") + os.pathsep))  # type: ignore[index]
        self.assertEqual(self.captured["cwd"], self.repo.resolve())
        self.assertEqual(self.captured["timeout"], 30.0)
        receipt = self.receipt()
        self.assertEqual(receipt["decision"], "passed")
        self.assertEqual(receipt["leaseCleanup"], ["released", "released"])
        self.assertEqual(receipt["unittest"], {"ran": 3, "ok": True, "skipOrExpectedFailureMarker": False})
        summary = json.loads(self.lines[-1])
        self.assertEqual(
            sorted(summary),
            ["decision", "durationSeconds", "exitCode", "label", "leaseCleanup", "logSha256", "receiptWritten"],
        )
        self.assertIs(summary["receiptWritten"], True)
        self.assertEqual(summary["decision"], "passed")
        self.assertEqual(summary["exitCode"], 0)
        self.assertEqual(summary["logSha256"], hashlib.sha256(b"Ran 3 tests in 0.010s\n\nOK\n").hexdigest())
        self.assertEqual(len(self.lines), 1, "exactly one summary line")
        # Sanitized: no token, owner path, repo path or environment in the receipt or summary.
        rendered = json.dumps(receipt) + self.lines[-1]
        for secret in (self.TOKEN, str(self.root), "CARGO_HOME", "TMPDIR"):
            self.assertNotIn(secret, rendered)

    def test_unittest_expectation_requires_exact_count_plain_ok_and_zero_skips(self) -> None:
        cases = {
            "wrong count": (b"Ran 4 tests in 0.1s\n\nOK\n", 0),
            "skips": (b"Ran 3 tests in 0.1s\n\nOK (skipped=1)\n", 0),
            "expected failures": (b"Ran 3 tests in 0.1s\n\nOK (expected failures=1)\n", 0),
            "failed": (b"Ran 3 tests in 0.1s\n\nFAILED (failures=1)\n", 0),
            "no summary": (b"compiled fine\n", 0),
            "nonzero exit": (b"Ran 3 tests in 0.1s\n\nOK\n", 2),
        }
        for index, (name, (log, exit_code)) in enumerate(cases.items()):
            with self.subTest(name):
                label = f"leased-expect-{index}"
                with self.fake_run(log=log, code=exit_code):
                    code = self.go(self.args(label, expect_unittest=3))
                self.assertEqual(code, leased_run.EXIT_FAILED)
                self.assertEqual(self.receipt(label)["decision"], "failed")
                self.assertEqual(self.leases_present(), [])
        label = "leased-expect-ok"
        with self.fake_run(log=b"noise\nRan 3 tests in 0.1s\n\nOK\n"):
            self.assertEqual(self.go(self.args(label, expect_unittest=3)), leased_run.EXIT_PASSED)

    def test_parse_unittest_summary(self) -> None:
        parse = leased_run.parse_unittest_summary
        self.assertEqual(parse(b"Ran 1 test in 0.001s\n\nOK\n"), (1, True, False))
        self.assertEqual(parse(b"Ran 2 tests in 1.0s\n\nOK (skipped=2)\n"), (2, False, True))
        self.assertEqual(parse(b"Ran 2 tests in 1.0s\n\nFAILED (errors=1)\n"), (2, False, False))
        self.assertEqual(parse(b"\xff\xfe garbage"), (None, False, False))
        self.assertEqual(parse(b"Ran 9 tests in 1s\nOK\nRan 5 tests in 1.0s\n\nOK\n"), (5, True, False), "last summary wins")

    def test_dirty_tree_is_allowed_and_recorded_not_refused(self) -> None:
        (self.repo / "tracked.txt").write_text("edited\n")
        (self.repo / "new.txt").write_text("new\n")
        head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()

        def edit_during_run() -> None:
            (self.repo / "new.txt").write_text("changed again\n")

        with self.fake_run(mutate=edit_during_run):
            self.assertEqual(self.go(), leased_run.EXIT_PASSED)
        receipt = self.receipt()
        self.assertEqual(receipt["sourceBefore"]["head"], head)
        self.assertEqual(receipt["sourceBefore"]["dirtyEntries"], 2)
        self.assertEqual(receipt["sourceAfter"]["head"], head)
        self.assertRegex(receipt["sourceBefore"]["statusSha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["sourceBefore"]["workingTreeDigest"], r"^[0-9a-f]{64}$")
        self.assertTrue(receipt["sourceChangedDuringRun"])
        self.assertEqual(receipt["decision"], "passed", "source edits are recorded, not a failure")

    def test_uncertain_process_tree_retains_both_leases_and_blocks_the_next_run(self) -> None:
        with self.fake_run(raise_exc=self.uncertain()):
            code = self.go()
        self.assertEqual(code, leased_run.EXIT_UNCERTAIN)
        self.assertEqual(self.leases_present(), ["cargo", "gradle"], "leases retained for manual recovery")
        for name in LEASE_DIRS:
            owner = json.loads((self.cache / "leases" / name / "owner.json").read_text())
            self.assertIs(owner["requiresManualRecovery"], True)
        receipt = self.receipt()
        self.assertEqual(receipt["decision"], "uncertain_process_tree")
        self.assertEqual(receipt["leaseCleanup"], ["retained", "retained"])
        self.assertEqual(json.loads(self.lines[-1])["leaseCleanup"], ["retained", "retained"])
        before = {name: (self.cache / "leases" / name / "owner.json").read_bytes() for name in LEASE_DIRS}
        # The next run never borrows or breaks them: it reports "retained" at once,
        # even with a long --wait (waiting cannot clear a manual-recovery lease).
        sleeps: list[float] = []
        with self.fake_run() as fake:
            code = leased_run.run(
                self.args("leased-test-2", wait=500.0), monotonic=self.clock.monotonic,
                sleep=sleeps.append, out=self.lines.append,
            )
        self.assertEqual(code, leased_run.EXIT_LEASE_RETAINED)
        self.assertNotEqual(leased_run.EXIT_LEASE_RETAINED, leased_run.EXIT_LEASE_WAIT_EXPIRED)
        self.assertEqual(sleeps, [])
        fake.assert_not_called()
        self.assertEqual(before, {name: (self.cache / "leases" / name / "owner.json").read_bytes() for name in LEASE_DIRS})
        self.assertEqual(json.loads(self.lines[-1])["decision"], "lease_retained_manual_recovery")
        self.assertFalse((self.cache / "release-gates" / "leased-test-2").exists(), "label stays unused")

    def test_attempted_gate_failure_is_a_failed_run_that_releases_leases(self) -> None:
        failure = run_gates.AttemptedGateFailure(OSError("log"), 0, 1.5)
        with self.fake_run(raise_exc=failure):
            self.assertEqual(self.go(), leased_run.EXIT_FAILED)
        self.assertEqual(self.leases_present(), [])
        receipt = self.receipt()
        self.assertEqual(receipt["decision"], "failed")
        self.assertEqual(receipt["exitCode"], 0)

    def test_leases_release_in_reverse_order(self) -> None:
        order: list[str] = []
        real_release = run_gates.Lease.release

        def record(lease: run_gates.Lease) -> None:
            order.append(lease.path.name)
            real_release(lease)

        with self.fake_run(), mock.patch.object(run_gates.Lease, "release", record):
            self.assertEqual(self.go(), leased_run.EXIT_PASSED)
        self.assertEqual(order, ["gradle", "cargo"])

    def test_busy_lease_is_polled_never_borrowed_and_taken_once_free(self) -> None:
        busy = self.cache / "leases" / "gradle"
        busy.mkdir(parents=True)
        (busy / "owner.json").write_text(json.dumps({"pid": 1, "label": "other", "token": "cd" * 16}))
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            self.clock.now += seconds
            if len(sleeps) == 2:
                shutil.rmtree(busy)

        with self.fake_run():
            code = leased_run.run(self.args(wait=100.0), monotonic=self.clock.monotonic, sleep=sleep, out=self.lines.append)
        self.assertEqual(code, leased_run.EXIT_PASSED)
        self.assertEqual(sleeps, [leased_run.LEASE_POLL_SECONDS] * 2)
        self.assertEqual(leased_run.LEASE_POLL_SECONDS, 15.0)
        self.assertGreaterEqual(self.receipt()["waitSeconds"], 30.0)
        self.assertEqual(self.leases_present(), [])

    def test_wait_expiry_returns_the_distinct_code_without_touching_the_foreign_lease(self) -> None:
        busy = self.cache / "leases" / "cargo"
        busy.mkdir(parents=True)
        owner = json.dumps({"pid": 1, "label": "other", "token": "cd" * 16}).encode()
        (busy / "owner.json").write_bytes(owner)
        sleeps: list[float] = []

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            self.clock.now += seconds

        with self.fake_run() as fake:
            code = leased_run.run(self.args(wait=20.0), monotonic=self.clock.monotonic, sleep=sleep, out=self.lines.append)
        self.assertEqual(code, leased_run.EXIT_LEASE_WAIT_EXPIRED)
        self.assertNotIn(code, (leased_run.EXIT_PASSED, leased_run.EXIT_FAILED, leased_run.EXIT_INVALID, leased_run.EXIT_UNCERTAIN))
        self.assertEqual(sleeps, [15.0, 5.0])
        fake.assert_not_called()
        self.assertEqual((busy / "owner.json").read_bytes(), owner)
        self.assertEqual(self.leases_present(), ["cargo"], "no lease of ours was left behind")
        self.assertEqual(json.loads(self.lines[-1])["leaseCleanup"], ["not-acquired"])

    def test_no_wait_means_a_single_attempt(self) -> None:
        (self.cache / "leases" / "gradle").mkdir(parents=True)
        sleeps: list[float] = []
        with self.fake_run():
            code = leased_run.run(self.args(wait=0.0), monotonic=self.clock.monotonic, sleep=sleeps.append, out=self.lines.append)
        self.assertEqual(code, leased_run.EXIT_LEASE_WAIT_EXPIRED)
        self.assertEqual(sleeps, [])

    def test_partial_acquisition_is_rolled_back_on_a_non_busy_error(self) -> None:
        leases = [run_gates.Lease(self.cache / "leases" / name, self.TOKEN, "label") for name in ("cargo", "gradle")]
        with mock.patch.object(leases[1], "acquire", side_effect=private_roots.AdmissionError("private cache admission failed")):
            with self.assertRaises(private_roots.AdmissionError):
                leased_run.acquire_leases(leases, 0.0, monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        self.assertEqual(self.leases_present(), [], "the first lease was released")

    def test_race_on_second_lease_releases_the_first_and_waits(self) -> None:
        leases = [run_gates.Lease(self.cache / "leases" / name, self.TOKEN, "label") for name in ("cargo", "gradle")]
        real_acquire = leases[1].acquire
        attempts = [0]

        def racing_acquire() -> None:
            attempts[0] += 1
            if attempts[0] == 1:
                raise run_gates.LeaseBusy("release builder lease is already owned (pid 1 label other)", False)
            real_acquire()

        with mock.patch.object(leases[1], "acquire", side_effect=racing_acquire):
            acquired = leased_run.acquire_leases(leases, 60.0, monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        self.assertEqual(len(acquired), 2)
        self.assertEqual(attempts[0], 2)
        self.assertEqual(self.clock.now, 15.0)

    def test_new_label_is_required_and_inputs_are_validated(self) -> None:
        with self.fake_run():
            self.assertEqual(self.go(), leased_run.EXIT_PASSED)
            with self.assertRaises(FileExistsError):
                self.go()
        invalid = {
            "label": dict(label="bad label!"),
            "timeout": dict(timeout=0.0),
            "nan timeout": dict(timeout=float("nan")),
            "negative wait": dict(wait=-1.0),
            "no command": dict(argv=[]),
            "expect zero": dict(expect_unittest=0),
            "relative jdk": dict(jdk_home="relative/jdk"),
            "missing jdk": dict(jdk_home=str(self.root / "nojdk")),
        }
        for name, overrides in invalid.items():
            with self.subTest(name):
                with self.fake_run() as fake:
                    with self.assertRaises(ValueError):
                        self.go(self.args(**{"label": "leased-invalid", **overrides}))
                fake.assert_not_called()
                self.assertFalse((self.cache / "release-gates" / "leased-invalid").exists())
                self.assertEqual(self.leases_present(), [])

    def test_cli_parses_arguments_and_maps_errors_to_the_invalid_code(self) -> None:
        captured: list[Namespace] = []
        with mock.patch.object(leased_run, "run", side_effect=lambda args: captured.append(args) or 0):
            code = leased_run.main([
                "--repo", "/r", "--label", "L1", "--cache-root", "/c", "--timeout", "90", "--wait", "30",
                "--jdk-home", "/j", "--expect-unittest", "7", "--", "cargo", "test", "--", "--nocapture",
            ])
        self.assertEqual(code, 0)
        args = captured[0]
        self.assertEqual((args.repo, args.label, args.cache_root, args.timeout, args.wait, args.jdk_home, args.expect_unittest),
                         ("/r", "L1", "/c", 90.0, 30.0, "/j", 7))
        self.assertEqual(args.argv, ["cargo", "test", "--", "--nocapture"])
        with mock.patch.object(leased_run, "run", side_effect=ValueError("bad input")):
            self.assertEqual(leased_run.main(["--repo", "/r", "--label", "L", "--cache-root", "/c", "--timeout", "1", "--", "x"]), leased_run.EXIT_INVALID)
        with mock.patch.object(leased_run, "run", side_effect=private_roots.AdmissionError("private cache admission failed")):
            self.assertEqual(leased_run.main(["--repo", "/r", "--label", "L", "--cache-root", "/c", "--timeout", "1", "--", "x"]), leased_run.EXIT_INVALID)
        with mock.patch.object(leased_run, "run", side_effect=FileExistsError("x")):
            self.assertEqual(leased_run.main(["--repo", "/r", "--label", "L", "--cache-root", "/c", "--timeout", "1", "--", "x"]), leased_run.EXIT_INVALID)

    def test_admission_failure_is_invalid_and_releases_leases(self) -> None:
        with self.fake_run() as fake, mock.patch.object(
            private_roots, "ensure_private_directory",
            side_effect=lambda path, must_create=False: (_ for _ in ()).throw(private_roots.AdmissionError("private cache admission failed"))
            if str(path).endswith("-scratch") else (os.makedirs(path, mode=0o700, exist_ok=True), (os.stat(path).st_dev, os.stat(path).st_ino))[1],
        ):
            code = self.go()
        self.assertEqual(code, leased_run.EXIT_INVALID)
        fake.assert_not_called()
        self.assertEqual(self.leases_present(), [])
        self.assertEqual(self.receipt()["decision"], "failed")

    def test_oversized_log_fails_the_run(self) -> None:
        with self.fake_run(log=b"x" * 100), mock.patch.object(leased_run, "MAX_LOG_BYTES", 10):
            self.assertEqual(self.go(), leased_run.EXIT_FAILED)
        self.assertEqual(self.receipt()["failureReason"], "log-exceeded-bound")

    def test_timeout_is_passed_through_unchanged(self) -> None:
        with self.fake_run():
            self.go(self.args(timeout=1234.5))
        self.assertEqual(self.captured["timeout"], 1234.5)


    def test_live_owner_busy_is_distinct_from_retained_and_typed(self) -> None:
        # A plain RuntimeError that merely contains the old message text is not "busy".
        leases = [run_gates.Lease(self.cache / "leases" / name, self.TOKEN, "label") for name in LEASE_DIRS]
        with mock.patch.object(leases[0], "acquire", side_effect=RuntimeError("release builder lease is already owned (x)")):
            with self.assertRaises(RuntimeError) as caught:
                leased_run.acquire_leases(leases, 0.0, monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        self.assertNotIsInstance(caught.exception, (leased_run.LeaseWaitExpired, leased_run.LeaseRetained))
        # A typed busy error carrying requires_manual_recovery is classified without waiting.
        with mock.patch.object(leases[1], "acquire", side_effect=run_gates.LeaseBusy("owned", True)):
            with self.assertRaises(leased_run.LeaseRetained):
                leased_run.acquire_leases(leases, 500.0, monotonic=self.clock.monotonic, sleep=self.clock.sleep)
        self.assertEqual(self.clock.now, 0.0)
        self.assertEqual(self.leases_present(), [], "anything acquired was rolled back")

    def test_every_owner_record_carries_one_run_start_epoch_despite_slow_acquisition(self) -> None:
        leases = [run_gates.Lease(self.cache / "leases" / name, self.TOKEN, "label") for name in LEASE_DIRS]
        wall = [1_000_000.9]
        real_acquire = leases[1].acquire

        def slow_second_acquire() -> None:
            wall[0] += 7.0  # the second acquisition straddles a second boundary
            real_acquire()

        with mock.patch.object(leases[1], "acquire", side_effect=slow_second_acquire):
            leased_run.acquire_leases(leases, 0.0, monotonic=self.clock.monotonic, sleep=self.clock.sleep,
                                      wall_clock=lambda: wall[0])
        epochs = [json.loads((lease.path / "owner.json").read_text())["startedAtEpoch"] for lease in leases]
        self.assertEqual(epochs, [1_000_000, 1_000_000])

    def test_stamp_run_start_gives_the_same_epoch_to_every_lease(self) -> None:
        leases = [run_gates.Lease(self.cache / "leases" / name, self.TOKEN, "label") for name in LEASE_DIRS]
        self.assertEqual(run_gates.stamp_run_start(leases, lambda: 1234.99), 1234)
        self.assertEqual([lease.started_at_epoch for lease in leases], [1234, 1234])

    def test_lease_acquire_raises_typed_busy_with_recovery_flag(self) -> None:
        for owner, expected in (
            ({"pid": 1, "label": "other", "token": "cd" * 16}, False),
            ({"pid": 1, "label": "other", "token": "cd" * 16, "requiresManualRecovery": True}, True),
        ):
            with self.subTest(expected=expected):
                path = self.cache / f"lease-{expected}"
                path.mkdir()
                (path / "owner.json").write_text(json.dumps(owner))
                with self.assertRaises(run_gates.LeaseBusy) as caught:
                    run_gates.Lease(path, self.TOKEN, "label").acquire()
                self.assertIs(caught.exception.requires_manual_recovery, expected)
        path = self.cache / "lease-unreadable"
        path.mkdir()
        with self.assertRaises(run_gates.LeaseBusy) as caught:
            run_gates.Lease(path, self.TOKEN, "label").acquire()
        self.assertIsNone(caught.exception.requires_manual_recovery)

    def test_label_used_while_waiting_is_refused_and_never_overwritten(self) -> None:
        busy = self.cache / "leases" / "gradle"
        busy.mkdir(parents=True)
        foreign = self.cache / "release-gates" / "leased-test-1"

        def sleep(seconds: float) -> None:
            self.clock.now += seconds
            shutil.rmtree(busy)
            foreign.mkdir(parents=True)
            (foreign / "receipt.json").write_text('{"owner": "someone else"}')

        with self.fake_run() as fake:
            code = leased_run.run(self.args(wait=100.0), monotonic=self.clock.monotonic, sleep=sleep, out=self.lines.append)
        self.assertEqual(code, leased_run.EXIT_INVALID)
        fake.assert_not_called()
        self.assertEqual((foreign / "receipt.json").read_text(), '{"owner": "someone else"}')
        self.assertEqual(sorted(path.name for path in foreign.iterdir()), ["receipt.json"])
        self.assertEqual(self.leases_present(), [], "our leases are released")
        self.assertEqual(json.loads(self.lines[-1])["decision"], "label_in_use")

    def test_retention_exit_code_survives_finalization_failure(self) -> None:
        with self.fake_run(raise_exc=self.uncertain()), \
                mock.patch.object(run_gates, "_hash_file", side_effect=OSError("hash")):
            code = self.go()
        self.assertEqual(code, leased_run.EXIT_UNCERTAIN)
        receipt = self.receipt()
        self.assertEqual(receipt["decision"], "uncertain_process_tree")
        self.assertEqual(receipt["finalizationError"], "OSError")
        self.assertEqual(self.leases_present(), ["cargo", "gradle"])

    def test_receipt_write_failure_is_a_distinct_nonzero_failure(self) -> None:
        real = run_gates._write_receipt
        calls = [0]

        def flaky(path: pathlib.Path, manifest: dict) -> None:
            calls[0] += 1
            if calls[0] > 1:  # the "running" marker succeeds, the final write fails
                raise OSError("disk full")
            real(path, manifest)

        with self.fake_run(), mock.patch.object(run_gates, "_write_receipt", side_effect=flaky):
            code = self.go()
        self.assertEqual(code, leased_run.EXIT_RECEIPT_FAILED)
        self.assertNotIn(code, (0, 1, 2, 3, 75, 76))
        summary = json.loads(self.lines[-1])
        self.assertEqual(summary["decision"], "receipt_write_failed")
        self.assertIs(summary["receiptWritten"], False)
        self.assertEqual(self.leases_present(), [], "leases were still released")
        # A retained tree keeps exit code 3 even when the receipt cannot be written.
        calls[0] = 0
        self.lines.clear()
        with self.fake_run(raise_exc=self.uncertain()), mock.patch.object(run_gates, "_write_receipt", side_effect=flaky):
            self.assertEqual(self.go(self.args("leased-test-3")), leased_run.EXIT_UNCERTAIN)
        self.assertIs(json.loads(self.lines[-1])["receiptWritten"], False)

    def test_running_marker_is_written_before_the_command_starts(self) -> None:
        seen: dict[str, object] = {}

        def inspect() -> None:
            seen.update(json.loads((self.cache / "release-gates" / "leased-test-1" / "receipt.json").read_text()))

        with self.fake_run(mutate=inspect):
            self.go()
        self.assertEqual(seen["decision"], "running")

    def test_environment_is_an_allowlist_plus_task_variables(self) -> None:
        ambient = {
            "PATH": "/usr/bin:/bin", "HOME": "/home/test", "LC_ALL": "C", "LANG": "C",
            "AWS_SECRET_ACCESS_KEY": "canary-secret", "MY_API_TOKEN": "canary-token",
            "GITHUB_TOKEN": "canary-gh", "RUST_LOG": "debug", "RANDOM_VAR": "x",
        }
        with mock.patch.dict(os.environ, ambient, clear=True), self.fake_run():
            self.go(self.args(pass_env=["RUST_LOG"]))
        env = self.captured["env"]
        for name in ("PATH", "HOME", "LC_ALL", "LANG", "RUST_LOG", "CARGO_HOME", "TMPDIR"):
            self.assertIn(name, env)  # type: ignore[operator]
        scratch = self.cache / "tmp" / "leased-test-1-scratch"
        self.assertEqual(env["HOME"], str(scratch / "home"), "HOME is private, not the host HOME")  # type: ignore[index]
        self.assertNotEqual(env["HOME"], "/home/test")  # type: ignore[index]
        self.assertTrue(self.captured["home_existed"])
        receipt = self.receipt()
        self.assertIs(receipt["privateHome"], True)
        self.assertIs(receipt["hostHomePassed"], False)
        for name in ("AWS_SECRET_ACCESS_KEY", "MY_API_TOKEN", "GITHUB_TOKEN", "RANDOM_VAR"):
            self.assertNotIn(name, env)  # type: ignore[operator]
        self.assertEqual(self.receipt()["passedEnvNames"], ["RUST_LOG"])
        for bad in ("lowercase", "MY_TOKEN", "AWS_SECRET_ACCESS_KEY", "1BAD", "A" * 80):
            with self.subTest(bad), self.fake_run() as fake:
                with self.assertRaises(ValueError):
                    self.go(self.args("leased-env-bad", pass_env=[bad]))
                fake.assert_not_called()

    def test_scratch_is_kept_after_failure_and_when_release_fails(self) -> None:
        with self.fake_run(code=3):
            self.assertEqual(self.go(self.args("leased-keep-1")), leased_run.EXIT_FAILED)
        self.assertTrue((self.cache / "tmp" / "leased-keep-1-scratch").is_dir())
        self.assertEqual(self.receipt("leased-keep-1")["scratchCleanup"], "kept")
        with self.fake_run(), mock.patch.object(run_gates.Lease, "release", side_effect=OSError("busy")):
            self.assertEqual(self.go(self.args("leased-keep-2")), leased_run.EXIT_UNCERTAIN)
        self.assertTrue((self.cache / "tmp" / "leased-keep-2-scratch").is_dir())

    def test_host_home_is_passed_only_when_explicitly_requested_and_recorded(self) -> None:
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin", "HOME": "/home/test"}, clear=True), self.fake_run():
            self.go(self.args(pass_env=["HOME"]))
        self.assertEqual(self.captured["env"]["HOME"], "/home/test")  # type: ignore[index]
        receipt = self.receipt()
        self.assertIs(receipt["hostHomePassed"], True)
        self.assertIs(receipt["privateHome"], False)
        self.assertIn("HOME", receipt["passedEnvNames"])

    def test_pass_env_denylist_refuses_code_loading_and_redirecting_names(self) -> None:
        refused = (
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "NODE_OPTIONS", "NODE_PATH",
            "PYTHONPATH", "PYTHONSTARTUP", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS", "JAVA_HOME",
            "MAVEN_OPTS", "BASH_ENV", "ENV", "RUSTC_WRAPPER", "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GRADLE_OPTS", "NPM_CONFIG_REGISTRY",
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "TMPDIR", "PATH", "XDG_CONFIG_HOME", "XTRACE_TEST_SCRATCH_ROOT",
        )
        for name in refused + (
            "CC", "CXX", "LD", "AR", "LDFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "GOFLAGS", "GOPATH", "PERL5OPT", "RUBYOPT", "CLASSPATH",
            "OPENSSL_CONF", "MAKEFLAGS", "MAVEN_ARGS", "EDITOR", "SSH_AUTH_SOCK", "AWS_ACCESS_KEY_ID_X", "DOCKER_HOST", "PKG_CONFIG_PATH", "LIBRARY_PATH",
        ):
            with self.subTest(name), self.fake_run() as fake:
                with self.assertRaises(ValueError):
                    self.go(self.args("leased-deny", pass_env=[name]))
                fake.assert_not_called()
        for name in ("RUST_LOG", "RUST_BACKTRACE", "CI", "FORCE_COLOR"):
            with self.subTest(allowed=name), self.fake_run():
                self.go(self.args(f"leased-allow-{name.lower()}", pass_env=[name]))

    def test_command_allowlist_admits_build_tools_and_refuses_launchers_before_any_lease(self) -> None:
        allowed = (
            ["cargo", "build"], ["./gradlew", "--no-daemon", "test"], ["/usr/bin/npm", "ci"], ["npx", "playwright", "install"],
            ["node", "x.js"], ["git", "status"], ["java", "-version"],
            ["python3.14", "-B", "-m", "unittest", "-v", "tools.release.test_release_tools"],
            ["python3", "-B", "-m", "tools.release.leased_run", "--help"],
        )
        for index, argv in enumerate(allowed):
            with self.subTest(argv=argv), self.fake_run():
                self.assertEqual(self.go(self.args(f"leased-ok-{index}", argv=argv)), leased_run.EXIT_PASSED)
        refused = (
            ["sh", "-c", "cargo build"], ["/bin/bash", "-lc", "x"], ["zsh"], ["open", "-a", "Terminal"], ["launchctl", "submit"],
            ["osascript", "-e", "x"], ["docker", "run", "x"], ["systemd-run", "--user", "x"], ["at", "now"], ["crontab", "-e"],
            ["env", "cargo", "build"], ["rustc", "x.rs"], ["curl", "http://x"],
            ["python3", "-c", "print(1)"], ["python3.14", "script.py"], ["python3", "-m", "http.server"],
            ["python3", "-B", "-m", "pip", "install", "x"], ["python3.14", "-B", "-c", "x"],
        )
        for index, argv in enumerate(refused):
            with self.subTest(argv=argv), self.fake_run() as fake:
                self.lines.clear()
                code = self.go(self.args(f"leased-refused-{index}", argv=argv))
                self.assertEqual(code, leased_run.EXIT_COMMAND_REFUSED)
                fake.assert_not_called()
                self.assertEqual(json.loads(self.lines[-1])["decision"], "command_refused")
                self.assertEqual(self.leases_present(), [], "refused before any lease was taken")
                self.assertFalse((self.cache / "release-gates" / f"leased-refused-{index}").exists())
        self.assertNotIn(leased_run.EXIT_COMMAND_REFUSED, (0, 1, 2, 3, 4, 75, 76))

    def test_argv0_path_forms_must_resolve_inside_the_repo_or_a_path_directory(self) -> None:
        (self.repo / "gradlew").write_text("#!/bin/sh\n")
        outside = self.root / "elsewhere"
        outside.mkdir()
        (outside / "cargo").write_text("#!/bin/sh\n")
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
            leased_run.check_command_allowed(["./gradlew", "test"], self.repo)
            leased_run.check_command_allowed([str(self.repo / "gradlew")], self.repo)
            leased_run.check_command_allowed(["cargo", "build"], self.repo)
            for argv in ([str(outside / "cargo")], ["../elsewhere/cargo"], ["/tmp/definitely-not-a-build-tool/node"]):
                with self.subTest(argv=argv), self.assertRaises(leased_run.CommandRefused):
                    leased_run.check_command_allowed(argv, self.repo)
            link = self.repo / "node"
            os.symlink(outside / "cargo", link)
            with self.assertRaises(leased_run.CommandRefused):
                leased_run.check_command_allowed(["./node"], self.repo)
        self.assertIn("hygiene, not a barrier", leased_run.PROVENANCE_RESIDUAL)
        self.assertIn("arbitrary code", leased_run.PROVENANCE_RESIDUAL)

    def test_env_is_built_by_the_one_shared_policy(self) -> None:
        cache = self.cache
        scratch = self.cache / "tmp" / "x-scratch"
        host = {"PATH": "/opt/tool/bin:/usr/bin", "HOME": "/host/home", "JAVA_HOME": "/opt/jdk", "RUSTUP_HOME": "/opt/rustup",
                "CI": "true", "LC_ALL": "C", "GITHUB_TOKEN": "t", "AWS_SECRET_ACCESS_KEY": "s", "LD_PRELOAD": "/x.so", "HTTPS_PROXY": "http://p"}
        floor_style = run_gates.build_task_env(cache, host, scratch=cache / "tmp", home=cache / "tmp" / "floor-home")
        leased_style = leased_run.build_env(cache, scratch, host, None, (), scratch / "home")
        for env in (floor_style, leased_style):
            for name in ("PATH", "JAVA_HOME", "RUSTUP_HOME", "CI", "LC_ALL"):
                self.assertEqual(env[name], host[name], f"builders keep {name}")
            for name in ("GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "LD_PRELOAD", "HTTPS_PROXY"):
                self.assertNotIn(name, env)
            self.assertNotEqual(env["HOME"], "/host/home")
            self.assertEqual(env["CARGO_HOME"], str(cache / "cargo"))
            self.assertEqual(env["CARGO_TARGET_DIR"], str(cache / "cargo-target"))
            self.assertEqual(env["GRADLE_USER_HOME"], str(cache / "gradle"))
        for env in (floor_style, leased_style):
            self.assertEqual(env["RUSTUP_AUTO_INSTALL"], "0", "a missing toolchain must fail, not install into the host rustup")
        self.assertEqual(floor_style["HOME"], str(cache / "tmp" / "floor-home"))
        self.assertEqual(floor_style["TMPDIR"], str(cache / "tmp"))
        self.assertEqual(leased_style["TMPDIR"], str(scratch))
        # RUSTUP_HOME is derived from the host HOME when absent, so rustup still finds toolchains.
        (self.root / "hosthome" / ".rustup").mkdir(parents=True)
        derived = run_gates.build_task_env(cache, {"PATH": "/usr/bin", "HOME": str(self.root / "hosthome")}, scratch=scratch, home=scratch / "home")
        self.assertEqual(derived["RUSTUP_HOME"], str(self.root / "hosthome" / ".rustup"))
        self.assertEqual(derived["HOME"], str(scratch / "home"))
        none = run_gates.build_task_env(cache, {"PATH": "/usr/bin", "HOME": str(self.root / "nohome")}, scratch=scratch, home=scratch / "home")
        self.assertNotIn("RUSTUP_HOME", none)
        # --jdk-home wins and prefixes PATH; HOME comes from the host only when explicitly passed.
        jdk = run_gates.build_task_env(cache, host, scratch=scratch, home=scratch / "home", jdk_home="/opt/jdk17")
        self.assertEqual((jdk["JAVA_HOME"], jdk["PATH"].split(os.pathsep)[0]), ("/opt/jdk17", "/opt/jdk17/bin"))
        explicit = run_gates.build_task_env(cache, host, scratch=scratch, home=scratch / "home", pass_env=("HOME",))
        self.assertEqual(explicit["HOME"], "/host/home")

    def test_receipt_records_the_provenance_residual_and_scrubs_errors(self) -> None:
        failure = run_gates.AttemptedGateFailure(OSError("/home/test/secret/path failed"), 0, 1.0)
        with self.fake_run(raise_exc=failure):
            self.go()
        receipt = self.receipt()
        self.assertIn("not that it cannot write the builder caches", receipt["provenanceResidual"])
        self.assertIn("allowlist", receipt["provenanceResidual"])
        self.assertNotIn("/home/test", json.dumps(receipt))
        self.assertEqual(leased_run._safe_error(RuntimeError("bad /Users/owner/x/y token")), "bad <path> token")

    def test_source_identity_git_calls_are_scrubbed(self) -> None:
        calls: list[tuple[list[str], dict[str, str]]] = []
        real_run = subprocess.run

        def spy(argv: list[str], *args: object, **kwargs: object) -> object:
            if argv and argv[0] == "git":
                calls.append((list(argv), dict(kwargs.get("env") or {})))
            return real_run(argv, *args, **kwargs)

        with mock.patch.dict(os.environ, {"GIT_SSH_COMMAND": "evil", "GIT_EXEC_PATH": "/x", "HOME": "/home/test"}), \
                mock.patch.object(subprocess, "run", side_effect=spy):
            leased_run._source_identity(self.repo)
        self.assertTrue(calls)
        for argv, env in calls:
            self.assertEqual(argv[1:3], ["-c", "core.fsmonitor=false"])
            self.assertEqual(env["GIT_OPTIONAL_LOCKS"], "0")
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertFalse([name for name in env if name.startswith("GIT_") and name not in {"GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT"}])

    def test_provenance_is_enabled_and_its_evidence_recorded_in_the_receipt(self) -> None:
        report = {
            "mode": "subreaper", "available": True, "overflowed": False, "unavailableReason": "",
            "adoptedOrphanCount": 0, "classifiedCount": 1, "classifiedByClass": {provenance.CLASS_SUBREAPER: 1},
            "classifiedTruncated": False,
            "classifiedIdentities": [{"pid": 900, "startedAt": "s", "classification": provenance.CLASS_SUBREAPER, "uidClass": "other"}],
        }
        with self.fake_run(prov_report=report):
            self.assertEqual(self.go(), leased_run.EXIT_PASSED)
        self.assertIs(self.captured["provenance"], True)
        receipt = self.receipt()
        self.assertEqual(receipt["provenance"]["classifiedCount"], 1)
        self.assertEqual(receipt["provenance"]["classifiedIdentities"][0]["uidClass"], "other")
        self.assertNotIn("unconfirmedProcesses", receipt)

    def test_log_limit_exit_code_is_a_failed_run_with_reason(self) -> None:
        with self.fake_run(code=run_gates.LOG_LIMIT_EXIT_CODE, log=b"partial"):
            self.assertEqual(self.go(), leased_run.EXIT_FAILED)
        self.assertEqual(self.receipt()["failureReason"], "log-exceeded-bound")

    def test_run_enforces_the_log_cap_in_flight_and_stops_only_its_own_tree(self) -> None:
        log_path = self.root / "capped.log"
        code_text = "import sys,time\nsys.stdout.write('x'*4000000)\nsys.stdout.flush()\ntime.sleep(60)\n"
        clean = run_gates.UntrackedProcessScan([], [], None, 0)
        bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        self.addCleanup(lambda: (bystander.kill(), bystander.wait()))
        started = time.monotonic()
        with mock.patch.object(private_roots, "create_private_file", side_effect=lambda path, flags, mode: os.open(path, flags, mode)), \
                mock.patch.object(run_gates, "_untracked_processes_since", return_value=clean):
            code, _duration = run_gates._run(
                [sys.executable, "-c", code_text], cwd=self.root, env=dict(os.environ), timeout=60,
                log_path=log_path, max_log_bytes=1_000_000,
            )
        self.assertEqual(code, run_gates.LOG_LIMIT_EXIT_CODE)
        self.assertLess(time.monotonic() - started, 30, "stopped long before the sleeping child would finish")
        self.assertGreater(log_path.stat().st_size, 1_000_000)
        self.assertIn(b"log exceeded its size limit", log_path.read_bytes())
        self.assertIsNone(bystander.poll(), "an unrelated process was not touched")

    def test_log_cap_is_off_by_default(self) -> None:
        clean = run_gates.UntrackedProcessScan([], [], None, 0)
        with mock.patch.object(private_roots, "create_private_file", side_effect=lambda path, flags, mode: os.open(path, flags, mode)), \
                mock.patch.object(run_gates, "_untracked_processes_since", return_value=clean):
            code, _ = run_gates._run(
                [sys.executable, "-c", "import sys; sys.stdout.write('x'*3000000)"], cwd=self.root,
                env=dict(os.environ), timeout=30, log_path=self.root / "uncapped.log",
            )
        self.assertEqual(code, 0)

class _AlwaysClassify:
    def classify(self, unknowns, scan, fresh, owned, deadline):  # type: ignore[no-untyped-def]
        return {pid: {"pid": pid, "startedAt": started, "classification": provenance.CLASS_SUBREAPER}
                for pid, started in unknowns}


class _NeverClassify:
    def classify(self, *args):  # type: ignore[no-untyped-def]
        return {}



def _lstart(pid: int) -> str:
    """A real `ps lstart` string, distinct per pid, for provenance fixtures (starts are compared by instant)."""
    return f"Sun Sep 27 {pid // 3600:02d}:{pid // 60 % 60:02d}:{pid % 60:02d} 2026"


class ProvenanceTests(unittest.TestCase):
    """Provenance classification with fakes for every syscall, plus real-host observers."""

    RUNNER = 500

    def coalition(self, table: dict[int, int | None], runner: int = 100, **kwargs: object) -> provenance.Provenance:
        values = {self.RUNNER: runner, **table}
        calls: dict[int, int] = {}

        def reader(pid: int) -> int | None:
            calls[pid] = calls.get(pid, 0) + 1
            value = values.get(pid)
            return value(calls[pid]) if callable(value) else value

        item = provenance.Provenance(
            platform="darwin", runner_pid=self.RUNNER, uid=501, coalition_reader=reader,
            facts_reader=kwargs.pop("facts_reader", self.facts), **kwargs,  # type: ignore[arg-type]
        )
        return item

    @staticmethod
    def facts(pids: object, _deadline: float) -> dict[int, tuple[int, str]]:
        return {pid: (0, _lstart(pid)) for pid in pids}  # type: ignore[union-attr]

    @staticmethod
    def snap(*rows: tuple[int, int, str]) -> dict[int, tuple[int, str, str]]:
        return {pid: (ppid, _lstart(pid), state) for pid, ppid, state in rows}

    def classify(self, item: provenance.Provenance, pids: list[int], scan: dict, fresh: dict | None = None,
                 owned: dict[int, str] | None = None) -> dict[int, dict]:
        return item.classify([(pid, _lstart(pid)) for pid in pids], scan, fresh if fresh is not None else scan,
                             owned or {}, time.monotonic() + 5)

    # macOS coalition mode
    def test_parse_ps_uid_reads_signed_display_as_unsigned_32_bit(self) -> None:
        for text, expected in (("-2", 4294967294), ("-1", 4294967295), ("0", 0), ("501", 501), ("4294967295", 4294967295),
                               ("-2147483648", 2147483648)):
            with self.subTest(text):
                self.assertEqual(provenance.parse_ps_uid(text), expected)
        for text in (str(-2**31 - 1), str(2**32), "", "-", "--2", "+2", "1.5", "abc", "-0x2", "1" * 30):
            with self.subTest(text):
                self.assertIsNone(provenance.parse_ps_uid(text))

    def test_read_process_facts_keeps_a_row_whose_uid_ps_prints_negative(self) -> None:
        output = "17842 -2 Thu Oct  8 03:30:08 2026\n1 0 Sun Sep 27 09:43:13 2026\n9 -2147483649 Thu Oct  8 03:30:08 2026\n"
        result = subprocess.CompletedProcess([], 0, stdout=output)
        with mock.patch.object(provenance, "probe_run", return_value=result), \
                mock.patch.object(provenance.os.path, "isfile", return_value=True):
            facts = provenance.read_process_facts([17842, 1, 9], time.monotonic() + 5)
        self.assertEqual(facts, {17842: (4294967294, "Thu Oct 8 03:30:08 2026"), 1: (0, "Sun Sep 27 09:43:13 2026")})

    def test_pid_one_start_time_is_readable_and_earlier_than_this_test(self) -> None:
        # Platform-neutral and never skipped: sysctl kinfo_proc on macOS, /proc on Linux.
        began = time.time()
        epoch = provenance.read_process_start_epoch(1)
        self.assertIsNotNone(epoch)
        self.assertLess(epoch, began)

    def test_coalition_different_and_readable_is_classified_with_evidence(self) -> None:
        item = self.coalition({900: 7})
        self.assertTrue(item.start())
        scan = self.snap((900, 1, "S"))
        result = self.classify(item, [900], scan)
        self.assertEqual(result[900]["classification"], provenance.CLASS_COALITION)
        self.assertEqual((result[900]["uidClass"], result[900]["coalitionId"], result[900]["runCoalitionIds"]), ("other", 7, [100]))
        self.assertEqual(item.report()["classifiedCount"], 1)
        self.assertEqual(item.report()["classifiedByClass"], {provenance.CLASS_COALITION: 1})
        same_uid = provenance.Provenance(
            platform="darwin", runner_pid=self.RUNNER, uid=0, coalition_reader={500: 100, 900: 7}.get,
            facts_reader=self.facts,
        )
        same_uid.start()
        self.assertEqual(self.classify(same_uid, [900], scan)[900]["uidClass"], "same")

    def test_coalition_equal_unreadable_or_inconsistent_stays_uncertain(self) -> None:
        scan = self.snap((900, 1, "S"))
        cases = {
            "equal to the run": {900: 100},
            "unreadable": {900: None},
            "changes between reads": {900: lambda call: 7 if call == 1 else 8},
        }
        for name, table in cases.items():
            with self.subTest(name):
                item = self.coalition(table)  # type: ignore[arg-type]
                item.start()
                self.assertEqual(self.classify(item, [900], scan), {})
                self.assertEqual(item.report()["classifiedCount"], 0)

    def test_coalition_root_command_coalition_also_counts_as_the_run(self) -> None:
        item = self.coalition({4321: 55, 900: 55, 901: 7})
        item.start()
        item.note_root(4321)
        scan = self.snap((900, 1, "S"), (901, 1, "S"))
        result = self.classify(item, [900, 901], scan)
        self.assertEqual(sorted(result), [901])
        self.assertEqual(result[901]["runCoalitionIds"], [55, 100])

    def test_coalition_unreadable_run_coalition_disables_classification(self) -> None:
        item = self.coalition({}, runner=None)  # type: ignore[arg-type]
        self.assertFalse(item.start())
        self.assertEqual(item.unavailable_reason, "coalition-unreadable")
        self.assertEqual(self.classify(item, [900], self.snap((900, 1, "S"))), {})

    def test_pid_reuse_and_stale_identity_are_never_classified(self) -> None:
        scan = self.snap((900, 1, "S"))
        item = self.coalition({900: 7})
        item.start()
        # ps facts report a different start time than the scan identity.
        reused = lambda pids, _d: {pid: (0, "Mon Jan  1 00:00:00 2001") for pid in pids}  # noqa: E731
        item = self.coalition({900: 7}, facts_reader=reused)
        item.start()
        self.assertEqual(self.classify(item, [900], scan), {})
        # The fresh snapshot shows a different process (new start) under the same pid.
        item = self.coalition({900: 7})
        item.start()
        fresh = {900: (1, "Sun Sep 27 10:00:01 2026", "S")}
        self.assertEqual(self.classify(item, [900], scan, fresh), {})
        # The process is gone, a zombie, or owned in the fresh view.
        self.assertEqual(self.classify(item, [900], scan, {}), {})
        self.assertEqual(self.classify(item, [900], scan, self.snap((900, 1, "Z"))), {})
        self.assertEqual(self.classify(item, [900], scan, owned={900: _lstart(900)}), {})
        # The start time changes between the first and the confirming read.
        sequence = iter([{900: (0, _lstart(900))}, {900: (0, "Sun Sep 27 10:00:02 2026")}])
        item = self.coalition({900: 7}, facts_reader=lambda pids, _d: next(sequence))
        item.start()
        self.assertEqual(self.classify(item, [900], scan), {})
        # Missing facts (ps failed) never classify.
        item = self.coalition({900: 7}, facts_reader=lambda pids, _d: {})
        item.start()
        self.assertEqual(self.classify(item, [900], scan), {})

    # Linux subreaper mode
    def subreaper(self, setter: object = None, **kwargs: object) -> provenance.Provenance:
        return provenance.Provenance(
            platform="linux", runner_pid=self.RUNNER, uid=1001,
            subreaper_setter=setter or (lambda enabled: True),  # type: ignore[arg-type]
            facts_reader=kwargs.pop("facts_reader", self.facts), **kwargs,  # type: ignore[arg-type]
        )

    def test_subreaper_failure_means_no_classification_and_nothing_to_undo(self) -> None:
        calls: list[bool] = []
        item = self.subreaper(lambda enabled: calls.append(enabled) or False)
        self.assertFalse(item.start())
        self.assertEqual(item.unavailable_reason, "prctl-failed")
        scan = self.snap((2, 0, "S"), (900, 2, "S"))
        self.assertEqual(self.classify(item, [900], scan), {})
        item.stop()
        self.assertEqual(calls, [True], "a subreaper that was never enabled is not 'disabled' again")

    def test_subreaper_classifies_foreign_processes_whose_chain_never_reaches_the_runner(self) -> None:
        calls: list[bool] = []
        item = self.subreaper(lambda enabled: calls.append(enabled) or True)
        self.assertTrue(item.start())
        scan = self.snap((1, 0, "S"), (2, 0, "S"), (900, 2, "S"), (800, 1, "S"), (self.RUNNER, 1, "S"))
        result = self.classify(item, [900, 800], scan)
        self.assertEqual({pid: record["classification"] for pid, record in result.items()},
                         {900: provenance.CLASS_SUBREAPER, 800: provenance.CLASS_SUBREAPER})
        self.assertEqual(result[900]["uidClass"], "other")
        item.stop()
        self.assertEqual(calls, [True, False])

    def test_subreaper_descendants_orphans_and_unobserved_chains_are_never_classified(self) -> None:
        item = self.subreaper()
        item.start()
        # 600 is our child, 700 its child; both observed while the chain reaches the runner.
        first = self.snap((self.RUNNER, 1, "S"), (600, self.RUNNER, "S"), (700, 600, "S"), (900, 1, "S"))
        item.observe(first, {}, {})
        # 600 exits; 700 is reparented to the subreaper (the runner), not to init.
        later = self.snap((self.RUNNER, 1, "S"), (700, self.RUNNER, "S"), (900, 1, "S"))
        item.observe(later, {}, {})
        self.assertEqual(self.classify(item, [700], later), {}, "an orphan reparented to the runner is a descendant")
        self.assertEqual(self.classify(item, [600, 700], first), {}, "chains reaching the runner are never classified")
        self.assertEqual(sorted(self.classify(item, [900], later)), [900])
        # Observed descendant identity stays excluded even if a later snapshot shows it elsewhere.
        moved = self.snap((self.RUNNER, 1, "S"), (700, 1, "S"))
        self.assertEqual(self.classify(item, [700], moved), {}, "previously a descendant: never classified")
        # A different process reusing the pid has a new start time and is a new identity.
        reuse = {700: (2, "Sun Sep 27 10:00:03 2026", "S"), 2: (0, _lstart(2), "S")}
        reused = item.classify([(700, "Sun Sep 27 10:00:03 2026")], reuse, reuse, {}, time.monotonic() + 5,)
        self.assertEqual(reused, {}, "facts say start-700, not start-new")

    def test_subreaper_inconsistent_chains_and_start_times_stay_uncertain(self) -> None:
        item = self.subreaper()
        item.start()
        missing_parent = {900: (4000, _lstart(900), "S")}
        self.assertEqual(self.classify(item, [900], missing_parent), {})
        cycle = {900: (901, _lstart(900), "S"), 901: (900, _lstart(901), "S")}
        self.assertEqual(self.classify(item, [900], cycle), {})
        absent = self.snap((1, 0, "S"))
        self.assertEqual(self.classify(item, [900], absent), {})
        good = self.snap((900, 1, "S"))
        self.assertEqual(self.classify(item, [900], good, fresh=self.snap((900, self.RUNNER, "S"))), {},
                         "the fresh snapshot shows the chain reaching the runner")
        bad_facts = provenance.Provenance(
            platform="linux", runner_pid=self.RUNNER, subreaper_setter=lambda e: True,
            facts_reader=lambda pids, _d: {pid: (0, "other-start") for pid in pids},
        )
        bad_facts.start()
        self.assertEqual(self.classify(bad_facts, [900], good), {})

    def test_subreaper_descendant_set_overflow_disables_classification(self) -> None:
        item = self.subreaper()
        item.start()
        rows = [(self.RUNNER, 1, "S")] + [(1000 + n, self.RUNNER, "S") for n in range(5)] + [(900, 1, "S")]
        with mock.patch.object(provenance, "MAX_DESCENDANT_IDENTITIES", 3):
            item.observe(self.snap(*rows), {}, {})
        self.assertTrue(item.overflowed)
        self.assertEqual(self.classify(item, [900], self.snap((900, 1, "S"))), {})
        self.assertTrue(item.report()["overflowed"])

    def test_subreaper_orphans_are_adopted_at_once_without_a_grace_period(self) -> None:
        reaped: list[int] = []
        item = self.subreaper(reaper=lambda pid, flags: reaped.append(pid))
        item.start()
        owned: dict[int, str] = {}
        baseline = self.snap((650, self.RUNNER, "S"))
        live = self.snap((self.RUNNER, 1, "S"), (650, self.RUNNER, "S"), (700, self.RUNNER, "S"), (710, 700, "S"))
        item.observe(live, baseline, owned)
        self.assertEqual(owned, {700: _lstart(700)}, "a daemon born just before the root exits is owned immediately")
        self.assertEqual(item.report()["adoptedOrphanCount"], 1)
        # Its zombie is reaped; a zombie that was never adopted is not.
        zombies = self.snap((self.RUNNER, 1, "S"), (700, self.RUNNER, "Z"), (720, self.RUNNER, "Z"))
        item.observe(zombies, baseline, owned)
        self.assertEqual(reaped, [700])

    def test_runners_own_probes_are_excluded_by_identity_not_by_timing(self) -> None:
        item = self.subreaper()
        item.start()
        owned: dict[int, str] = {}
        provenance.register_probe(730)
        live = self.snap((self.RUNNER, 1, "S"), (730, self.RUNNER, "S"), (731, self.RUNNER, "S"))
        item.observe(live, {}, owned)
        self.assertEqual(owned, {731: _lstart(731)}, "the registered ps/lsof helper is skipped, everything else adopted")
        with mock.patch.object(provenance, "PROBE_EXCLUSION_SECONDS", 0.0), mock.patch.object(provenance.time, "monotonic", return_value=time.monotonic() + 60):
            self.assertNotIn(730, provenance.recent_probe_pids())

    def test_probe_run_registers_the_child_pid(self) -> None:
        result = provenance.probe_run([sys.executable, "-c", "import os; print(os.getpid())"], timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn(int(result.stdout), provenance.recent_probe_pids())
        with self.assertRaises(subprocess.SubprocessError):
            provenance.probe_run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.3)

    def test_run_adopts_a_daemon_that_escapes_just_before_the_root_exits_and_never_classifies_it(self) -> None:
        world = RunOwnershipWorldTests()
        world.setUp()
        self.addCleanup(world.temp.cleanup)
        runner = os.getpid()
        daemon_start = _lstart(9100)
        real_class = provenance.Provenance
        factory = lambda **_ignored: real_class(  # noqa: E731
            platform="linux", runner_pid=runner, subreaper_setter=lambda e: True,
            facts_reader=lambda pids, _d: {pid: (0, _lstart(pid)) for pid in pids})
        snapshot, _clean, _raise, _probe = world.world()
        snapshot[9100] = (runner, daemon_start, "S")  # direct child of the runner: a reparented orphan
        stops: list[dict[int, str]] = []
        with mock.patch.object(run_gates, "_stop_and_reap_owned_tree", side_effect=lambda proc, root, owned: stops.append(dict(owned)) or True):
            report, failure, result = world.drive([(snapshot, set(), None, None)], provenance_factory=factory)
        self.assertIsNone(failure, str(failure))
        self.assertEqual(result[0], 125, "a live adopted orphan after the command is drained, not released")
        self.assertEqual(stops and stops[0].get(9100), daemon_start)
        self.assertEqual(world.provenance_report["classifiedCount"], 0)
        self.assertEqual(world.provenance_report["adoptedOrphanCount"], 1)
        # If it cannot be drained the run fails closed.
        with mock.patch.object(run_gates, "_stop_and_reap_owned_tree", return_value=False):
            _report, failure, result = world.drive([(snapshot, set(), None, None)], provenance_factory=factory)
        self.assertIsNone(result)
        self.assertIsNotNone(failure)

    def test_classified_evidence_is_bounded_with_truthful_totals(self) -> None:
        evidence = provenance.ClassifiedEvidence()
        for pid in range(1, 301):
            evidence.add({"pid": pid, "startedAt": f"s{pid}", "classification": provenance.CLASS_SUBREAPER})
        evidence.add({"pid": 1, "startedAt": "s1", "classification": provenance.CLASS_SUBREAPER})
        report = evidence.report()
        self.assertEqual(len(report["classifiedIdentities"]), provenance.MAX_EVIDENCE_RECORDS)
        self.assertEqual(report["classifiedCount"], 300)
        self.assertTrue(report["classifiedTruncated"])
        self.assertLess(len(json.dumps(report)), 64 * 1024)

    def test_unsupported_platform_never_classifies(self) -> None:
        item = provenance.Provenance(platform="freebsd", runner_pid=self.RUNNER, facts_reader=self.facts)
        self.assertFalse(item.start())
        self.assertEqual(item.unavailable_reason, "unsupported-platform")
        self.assertEqual(self.classify(item, [900], self.snap((900, 1, "S"))), {})

    # Scanner and _run integration
    def scan_with(self, prov: object) -> run_gates.UntrackedProcessScan:
        start = "Sun Oct  4 21:00:00 2026"
        supplied = {7001: (1, start, "S")}
        real_is_dir = pathlib.Path.is_dir
        with mock.patch.object(run_gates, "LSOF_BINARY", "/test/lsof"), \
                mock.patch.object(run_gates, "_run_lsof_fields", return_value=run_gates.LsofProbe(0, "", "")), \
                mock.patch.object(pathlib.Path, "is_dir", lambda path: False if str(path) == "/proc" else real_is_dir(path)), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=supplied):
            return run_gates._untracked_processes_since({}, {}, supplied, pathlib.Path("/nonexistent/gate.log"), provenance=prov)

    def test_scanner_moves_classified_unknowns_out_of_the_blocking_list(self) -> None:
        start = "Sun Oct  4 21:00:00 2026"
        class Always:
            def classify(self, unknowns, scan, fresh, owned, deadline):  # type: ignore[no-untyped-def]
                return {pid: {"pid": pid, "startedAt": started, "classification": provenance.CLASS_SUBREAPER} for pid, started in unknowns}

        class Never:
            def classify(self, *args):  # type: ignore[no-untyped-def]
                return {}

        classified = self.scan_with(Always())
        self.assertEqual((classified.uninspectable, classified.error, classified.candidate_count), ([], None, 0))
        self.assertEqual([item["pid"] for item in classified.classified], [7001])
        blocked = self.scan_with(Never())
        self.assertEqual([item["pid"] for item in blocked.uninspectable], [7001])
        self.assertEqual(blocked.error, EXPECTED_UNKNOWN)
        self.assertEqual(blocked.classified, [])
        self.assertEqual(self.scan_with(None).classified, [])

    def test_classified_identities_count_as_resolved_so_settling_does_not_stall(self) -> None:
        """The realistic case: a process stays uninspectable but provenance classifies it on every
        scan. It must resolve at once in both loops, not wait out the 120 s deadline for an exit."""
        start = "Sun Oct  4 21:00:00 2026"
        supplied = {7001: (1, start, "S")}
        initial = [{"pid": 7001, "startedAt": start, "observedParentPid": 1,
                    "descriptorStatus": "uninspectable", "reason": "missing-process-record-after-all-fd-fallback"}]
        clock = FakeClock()

        def poll_with(classifier: object) -> object:
            def poll(_deadline: float) -> tuple[dict, run_gates.UntrackedProcessScan]:
                clock.now += 0.01
                return supplied, self.scan_with(classifier)
            return poll

        scan = self.scan_with(_AlwaysClassify())
        self.assertEqual(scan.resolved_identities, frozenset({(7001, start)}), "classified identities are resolved")
        self.assertEqual(scan.uninspectable, [])
        result = run_gates._settle_uninspectable_candidates(
            initial, poll_with(_AlwaysClassify()), duration=120, interval=1, monotonic=clock.monotonic, sleep=clock.sleep,
        )
        self.assertTrue(result.cleared)
        self.assertEqual(result.poll_count, 1)
        self.assertLess(clock.now, 5.0, "no 120 s stall")
        clock.now = 0.0
        cleared, _latest, error, count = run_gates._final_global_quiescence_scan(
            120, poll_with(_AlwaysClassify()), lambda _s: [], monotonic=clock.monotonic, sleep=clock.sleep,
            pending_identities={(7001, start)},
        )
        self.assertTrue(cleared, error)
        self.assertEqual(count, 2)
        self.assertLess(clock.now, 5.0)
        # Without classification the same identity is still unresolved and fails closed at the deadline.
        clock.now = 0.0
        result = run_gates._settle_uninspectable_candidates(
            initial, poll_with(_NeverClassify()), duration=5, interval=1, monotonic=clock.monotonic, sleep=clock.sleep,
        )
        self.assertFalse(result.cleared)
        self.assertGreaterEqual(clock.now, 5.0)

    def test_more_than_sixty_four_classified_identities_still_resolve_a_pending_one(self) -> None:
        start = "Sun Oct  4 21:00:00 2026"
        supplied = {pid: (1, start, "S") for pid in range(7001, 7001 + 100)}
        real_is_dir = pathlib.Path.is_dir
        with mock.patch.object(run_gates, "LSOF_BINARY", "/test/lsof"), \
                mock.patch.object(run_gates, "_run_lsof_fields", return_value=run_gates.LsofProbe(0, "", "")), \
                mock.patch.object(pathlib.Path, "is_dir", lambda path: False if str(path) == "/proc" else real_is_dir(path)), \
                mock.patch.object(run_gates, "_process_snapshot", return_value=supplied):
            scan = run_gates._untracked_processes_since({}, {}, supplied, pathlib.Path("/nonexistent/gate.log"), provenance=_AlwaysClassify())
        self.assertEqual(len(scan.classified), run_gates.MAX_UNCONFIRMED_SAMPLE, "only a sample is reported")
        self.assertEqual(len(scan.classified_identities), 100)
        self.assertIn((7100, start), scan.resolved_identities, "an identity beyond the first 64 still resolves")
        self.assertEqual(scan.uninspectable, [])

    def test_provenance_facts_are_durable_in_owner_records_and_receipts(self) -> None:
        item = provenance.Provenance(
            platform="darwin", runner_pid=self.RUNNER, coalition_reader={self.RUNNER: 100, 4321: 55}.get, facts_reader=self.facts,
        )
        item.start()
        item.note_root(4321)
        self.assertEqual(item.facts(), {"mode": "coalition", "available": True, "runCoalitionIds": [55, 100], "subreaper": False})
        self.assertEqual(item.report()["runCoalitionIds"], [55, 100])
        linux = self.subreaper()
        linux.start()
        linux.stop()
        self.assertTrue(linux.facts()["subreaper"], "the subreaper fact survives stop()")
        self.assertTrue(linux.report()["subreaper"])
        lease_tests = SettleAndGlobalQuiescenceTests()
        owner = lease_tests.retain(provenance_facts=item.facts())
        self.assertEqual(owner["provenance"], {"mode": "coalition", "available": True, "runCoalitionIds": [55, 100], "subreaper": False})
        hostile = lease_tests.retain(provenance_facts={"mode": "x", "available": 1, "runCoalitionIds": [0, -1, "a", 5] + list(range(9, 40)), "subreaper": "yes"})
        self.assertEqual(hostile["provenance"]["runCoalitionIds"][0], 5)
        self.assertLessEqual(len(hostile["provenance"]["runCoalitionIds"]), 8)
        self.assertIs(hostile["provenance"]["subreaper"], False)
        error = run_gates.UncertainProcessTree("x", 1)
        error.provenance_facts = item.facts()
        seen: list[dict] = []

        class Spy:
            label = "spy"

            def retain_for_manual_recovery(self, *args: object, **kwargs: object) -> None:
                seen.append(kwargs)

        run_gates._retain_uncertain_leases([Spy()], error)  # type: ignore[list-item]
        self.assertEqual(seen[0]["provenance_facts"]["runCoalitionIds"], [55, 100])

    def test_a_failed_run_carries_the_run_coalition_ids_for_recovery(self) -> None:
        world = RunOwnershipWorldTests()
        world.setUp()
        self.addCleanup(world.temp.cleanup)
        real_class = provenance.Provenance
        factory = lambda **_ignored: real_class(  # noqa: E731
            platform="darwin", runner_pid=self.RUNNER, coalition_reader={self.RUNNER: 100, 9001: 100}.get,
            facts_reader=lambda pids, _d: {pid: (0, _lstart(pid)) for pid in pids})
        _report, failure, _result = world.drive([world.world(_unknown(9001))], provenance_factory=factory, settle_seconds=2.0)
        self.assertIsNotNone(failure)
        assert failure is not None
        self.assertEqual(failure.provenance_facts["runCoalitionIds"], [100])

    def test_provenance_start_failure_does_not_leak_the_log_descriptor(self) -> None:
        opened: list[int] = []
        temp = tempfile.TemporaryDirectory(dir=test_scratch_root())
        self.addCleanup(temp.cleanup)

        class Broken:
            def __init__(self, **_ignored: object) -> None:
                pass

            def start(self) -> bool:
                raise OSError("prctl exploded")

            def stop(self) -> None:
                pass

            def report(self) -> dict:
                return {}

        def create(path: object, flags: int, mode: int) -> int:
            fd = os.open(path, flags, mode)
            opened.append(fd)
            return fd

        report: dict = {}
        with mock.patch.object(private_roots, "create_private_file", side_effect=create), \
                mock.patch.object(run_gates.provenance_module, "Provenance", Broken):
            try:
                run_gates._run(
                    [sys.executable, "-c", "pass"], cwd=pathlib.Path(temp.name), env=dict(os.environ), timeout=5,
                    log_path=pathlib.Path(temp.name) / "leak.log", provenance=True, provenance_report=report,
                )
            except (OSError, run_gates.UncertainProcessTree):
                pass
        self.assertTrue(opened)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_run_with_provenance_passes_when_foreign_daemons_are_classified_and_fails_closed_without_it(self) -> None:
        world = RunOwnershipWorldTests()
        world.setUp()
        self.addCleanup(world.temp.cleanup)
        daemon = _unknown(9001)
        real_class = provenance.Provenance
        facts = lambda pids, _d: {pid: (0, _lstart(pid)) for pid in pids}  # noqa: E731
        ok_factory = lambda **_ignored: real_class(  # noqa: E731
            platform="linux", runner_pid=self.RUNNER, subreaper_setter=lambda e: True, facts_reader=facts)
        report, failure, result = world.drive([world.world(daemon)], provenance_factory=ok_factory)
        self.assertIsNone(failure, str(failure))
        self.assertIsNotNone(result)
        self.assertEqual(world.provenance_report["classifiedCount"], 1)
        self.assertEqual(world.provenance_report["classifiedIdentities"][0]["classification"], provenance.CLASS_SUBREAPER)
        self.assertEqual(report, {}, "nothing was left uncertain, so no settle report")
        failing_factory = lambda **_ignored: real_class(  # noqa: E731
            platform="linux", runner_pid=self.RUNNER, subreaper_setter=lambda e: False, facts_reader=facts)
        report, failure, result = world.drive([world.world(daemon)], provenance_factory=failing_factory, settle_seconds=2.0)
        self.assertIsNone(result)
        self.assertIsNotNone(failure, "prctl failure means no classification: fail closed as before")
        self.assertEqual(world.provenance_report["unavailableReason"], "prctl-failed")
        self.assertEqual(world.provenance_report["classifiedCount"], 0)

    # Real host: observe, never fail open
    def test_real_host_provenance_never_classifies_the_runs_own_descendants(self) -> None:
        item = provenance.Provenance()
        started = item.start()
        child = subprocess.Popen(["sleep", "5"], start_new_session=True)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        try:
            snapshot = run_gates._process_snapshot()
            item.observe(snapshot, {}, {})
            identity = (child.pid, snapshot[child.pid][1])
            own = item.classify([identity], snapshot, snapshot, {}, time.monotonic() + 5)
            self.assertEqual(own, {}, "our own child is never classified as a non-descendant")
            others = [(pid, record[1]) for pid, record in snapshot.items() if pid in (1, 2)]
            for _pid, record in item.classify(others, snapshot, snapshot, {}, time.monotonic() + 5).items():
                self.assertIn(record["classification"], (provenance.CLASS_COALITION, provenance.CLASS_SUBREAPER))
            if sys.platform == "darwin":
                coalition = provenance.read_coalition_id(os.getpid())
                self.assertTrue(coalition is None or coalition > 0)
                self.assertEqual(started, coalition is not None)
            elif sys.platform.startswith("linux"):
                self.assertEqual(started, item.available)
        finally:
            item.stop()
        if sys.platform.startswith("linux") and started:
            value = ctypes.c_int(-1)
            ctypes.CDLL(None).prctl(provenance.PR_GET_CHILD_SUBREAPER, ctypes.byref(value), 0, 0, 0)
            self.assertEqual(value.value, 0, "the subreaper flag is cleared when the command ends")

class RecoverLeasesTests(unittest.TestCase):
    """recover_leases with fakes for admission, processes, coalitions, lsof and the clock."""

    LABEL = "P00-control-test-run"
    TOKEN = "feedfacefeedfacefeedfacefeedface"
    RUN_EPOCH = time.mktime((2026, 10, 4, 16, 0, 0, 0, 0, -1))
    SELF_PID = 99999

    @staticmethod
    def lstart(epoch: float) -> str:
        return time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(epoch))

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=test_scratch_root())
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.cache = self.root / "cache"
        for name in (*run_gates.CACHE_NAMES, "leases", "release-gates"):
            (self.cache / name).mkdir(parents=True)
        self.run_dir = self.cache / "release-gates" / self.LABEL
        self.run_dir.mkdir()
        self.clock = FakeClock()
        self.lines: list[str] = []
        self.sleeps: list[float] = []
        self.processes: dict[int, tuple[int, str, str]] = {}
        self.coalitions: dict[int, int | None] = {}
        self.uids: dict[int, int] = {}
        self.holders: list[int] = []
        self.snapshot_calls = 0
        self.on_snapshot: object = None
        self.identities = [(4101, self.lstart(self.RUN_EPOCH + 30)), (4102, self.lstart(self.RUN_EPOCH + 31))]
        self.coalitions[self.SELF_PID] = 100
        self.write_records()

        def identity(path: object) -> tuple[int, int]:
            info = os.stat(path)
            return info.st_dev, info.st_ino

        patches = [
            mock.patch.object(private_roots, "admit_directory", side_effect=lambda path, private_leaf=False: identity(path)
                              if os.path.isdir(path) else (_ for _ in ()).throw(private_roots.AdmissionError("private cache admission failed"))),
            mock.patch.object(private_roots, "read_private_json", side_effect=lambda path, **_k: json.loads(pathlib.Path(os.fspath(path)).read_text())),
            mock.patch.object(private_roots, "open_private_file_read", side_effect=lambda path: os.open(path, os.O_RDONLY)),
            mock.patch.object(private_roots, "create_private_file", side_effect=lambda path, flags, mode: os.open(path, flags, mode)),
            mock.patch.object(private_roots, "ensure_private_directory", side_effect=self.fake_ensure),
            mock.patch.object(private_roots, "normalize_directory_path", side_effect=lambda value: pathlib.Path(value)),
            mock.patch.object(os, "kill", side_effect=AssertionError("recovery must never signal")),
            mock.patch.object(os, "killpg", side_effect=AssertionError("recovery must never signal")),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def fake_ensure(path: object, must_create: bool = False) -> tuple[int, int]:
        if must_create and os.path.lexists(path):
            raise FileExistsError("exists")
        os.makedirs(path, mode=0o700, exist_ok=True)
        info = os.stat(path)
        return info.st_dev, info.st_ino

    def owner_record(self, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "pid": 70001, "label": self.LABEL, "token": self.TOKEN, "startedAtEpoch": int(self.RUN_EPOCH),
            "requiresManualRecovery": True, "terminationStatus": "uncertain",
            "processGroupId": 70001, "ownedProcesses": [{"pid": 4101, "startedAt": self.identities[0][1]}],
            "unconfirmedProcesses": [{"pid": pid, "startedAt": start, "descriptorStatus": "uninspectable"} for pid, start in self.identities],
            "unconfirmedProcessCount": 2, "unconfirmedProcessesTruncated": False,
            "provenance": {"mode": "coalition", "available": True, "runCoalitionIds": [100], "subreaper": False},
        }
        record.update(overrides)
        return record

    def write_records(self, owner: dict | None = None, receipt: dict | None = None) -> None:
        for name in ("cargo", "gradle"):
            lease = self.cache / "leases" / name
            lease.mkdir(exist_ok=True)
            (lease / "owner.json").write_text(json.dumps(owner or self.owner_record()))
        (self.run_dir / "receipt.json").write_text(json.dumps(receipt or {
            "label": self.LABEL, "decision": "uncertain_process_tree",
            "naturalExitSettle": {"initialIdentities": [{"pid": pid, "startedAt": start} for pid, start in self.identities]},
        }))

    def world(self, *rows: tuple[int, int, float, str]) -> None:
        """Replace the process table: (pid, ppid, start epoch offset from the run start, state)."""
        self.processes = {pid: (ppid, self.lstart(self.RUN_EPOCH + offset), state) for pid, ppid, offset, state in rows}

    def context(self, **overrides: object) -> recover_leases.Context:
        def snapshot() -> dict:
            self.snapshot_calls += 1
            if callable(self.on_snapshot):
                self.on_snapshot(self.snapshot_calls)
            return dict(self.processes)

        def facts(pids: object, _deadline: float) -> dict[int, tuple[int, str]]:
            return {pid: (self.uids.get(pid, 0), self.processes[pid][1]) for pid in pids if pid in self.processes}  # type: ignore[union-attr]

        def sleep(seconds: float) -> None:
            self.sleeps.append(seconds)
            self.clock.now += seconds

        values = dict(
            platform="darwin", uid=501, self_pid=self.SELF_PID, sleep=sleep, monotonic=self.clock.monotonic,
            now=lambda: datetime.datetime(2026, 10, 4, 18, 30, 0, tzinfo=datetime.timezone.utc),
            snapshot=snapshot, coalition_reader=lambda pid: self.coalitions.get(pid), facts_reader=facts,
            start_reader=lambda pid: recover_leases.parse_start(self.processes[pid][1]) if pid in self.processes else None,
            inventory=lambda: [(1, "launchd"), (self.SELF_PID, "python3.14")],
            lsof=lambda paths: [{"path": path, "pids": list(self.holders), "error": None} for path in paths],
        )
        values.update(overrides)
        return recover_leases.Context(**values)

    def args(self, **overrides: object) -> Namespace:
        values = dict(cache_root=str(self.cache), label=self.LABEL, receipt=str(self.run_dir / "receipt.json"),
                      execute=False, dry_run=True, confirm_label=None)
        values.update(overrides)
        return Namespace(**values)

    def go(self, ctx: recover_leases.Context | None = None, **overrides: object) -> int:
        return recover_leases.run(self.args(**overrides), ctx or self.context(), out=self.lines.append)

    def summary(self) -> dict:
        return json.loads(self.lines[-1])

    def quiet_world(self) -> None:
        # The recorded identities are gone; a pre-existing session process and a launchd daemon
        # from another coalition exist.
        self.world((1, 0, -86400, "S"), (500, 1, -3000, "S"), (600, 500, 200, "S"), (700, 1, 300, "S"))
        self.coalitions.update({700: 7, 600: 100, 500: 100})

    def test_dry_run_allows_when_everything_is_exited_or_provably_not_a_descendant(self) -> None:
        self.quiet_world()
        code = self.go()
        self.assertEqual(code, recover_leases.EXIT_OK, self.lines)
        summary = self.summary()
        self.assertEqual(summary["decision"], "recovery-allowed")
        self.assertEqual(summary["identityClassCounts"], {"exited": 2})
        self.assertEqual(summary["globalScanUncertain"], [0, 0])
        self.assertTrue((self.cache / "leases" / "cargo" / "owner.json").exists(), "a dry run never touches the leases")
        plan = json.loads((self.run_dir / summary["planFile"]).read_text())
        self.assertEqual(plan["decision"], "recovery-allowed")
        rendered = json.dumps(plan) + json.dumps(summary)
        for secret in (self.TOKEN, str(self.root), "token"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(plan["protocol"]["observations"], 3)
        self.assertEqual(len(plan["observations"]), 3)
        self.assertEqual(len(plan["globalScans"]), 2)
        self.assertEqual(plan["runCoalitionSources"], ["persisted"])
        self.assertEqual(plan["toolSessionCoalitionId"], 100)
        self.assertIn("not that nothing can write the caches", plan["notice"])
        # The three observations and two scans are at least two seconds apart.
        self.assertTrue(all(gap >= 2.0 for gap in self.sleeps), self.sleeps)
        self.assertGreaterEqual(self.clock.now, 2 * 2.0 + 2.0)

    def _check(self, cargo: dict, gradle: dict) -> dict:
        records = {"owners": {"cargo": cargo, "gradle": gradle}, "receipt": {"label": self.LABEL, "decision": "failed"}}
        return recover_leases.check_records(SimpleNamespace(label=self.LABEL), records)  # type: ignore[arg-type]

    def _refusal(self, cargo: dict, gradle: dict) -> list[str]:
        with self.assertRaises(recover_leases.Refused) as caught:
            self._check(cargo, gradle)
        return list(caught.exception.reasons)

    def test_equal_owner_epochs_are_accepted_unchanged(self) -> None:
        facts = self._check(self.owner_record(), self.owner_record())
        self.assertEqual(facts, {"ownerPid": 70001, "runStartEpoch": float(int(self.RUN_EPOCH))})

    def test_small_owner_epoch_skew_is_accepted_and_the_earliest_epoch_is_used(self) -> None:
        base = int(self.RUN_EPOCH)
        for skew in (3, recover_leases.MAX_OWNER_EPOCH_SKEW_SECONDS):
            with self.subTest(skew=skew):
                # Order of the records must not matter.
                for cargo, gradle in ((base, base + skew), (base + skew, base)):
                    facts = self._check(self.owner_record(startedAtEpoch=cargo), self.owner_record(startedAtEpoch=gradle))
                    self.assertEqual(facts["runStartEpoch"], float(base))

    def test_dry_run_recovers_the_observed_three_second_skew(self) -> None:
        self.quiet_world()
        path = self.cache / "leases" / "gradle" / "owner.json"
        record = json.loads(path.read_text())
        record["startedAtEpoch"] += 3
        path.write_text(json.dumps(record))
        self.assertEqual(self.go(), recover_leases.EXIT_OK, self.lines)
        self.assertEqual(self.summary()["decision"], "recovery-allowed")

    def test_owner_epoch_skew_beyond_the_bound_is_refused(self) -> None:
        base = int(self.RUN_EPOCH)
        over = base + int(recover_leases.MAX_OWNER_EPOCH_SKEW_SECONDS) + 1
        self.assertEqual(self._refusal(self.owner_record(), self.owner_record(startedAtEpoch=over)), ["owner-records-disagree"])

    def test_owner_records_with_different_token_pid_or_label_and_skew_are_refused(self) -> None:
        skewed = int(self.RUN_EPOCH) + 3
        for name, change in (("token", {"token": "another-token-value"}), ("pid", {"pid": 70002}),
                             ("label", {"label": "someone-else"}), ("no-token", {"token": None}),
                             ("not-retained", {"requiresManualRecovery": False})):
            with self.subTest(name):
                reasons = self._refusal(self.owner_record(), self.owner_record(startedAtEpoch=skewed, **change))
                self.assertIn("owner-records-disagree" if name in ("token", "pid", "no-token") else
                              ("label-mismatch" if name == "label" else "not-retained"), reasons)
        # A token mismatch is never echoed in the refusal.
        self.assertNotIn(self.TOKEN, json.dumps(self._refusal(self.owner_record(), self.owner_record(startedAtEpoch=skewed, token="x" * 8))))

    def test_huge_or_unbounded_owner_epochs_are_a_structured_refusal(self) -> None:
        base = int(self.RUN_EPOCH)
        for bad in (10**400, 2**53, -(10**400), -1, True, "nan", "inf", float("nan"), 1e300):
            with self.subTest(bad=bad):
                self.assertEqual(self._refusal(self.owner_record(), self.owner_record(startedAtEpoch=bad)), ["owner-records-disagree"])
                self.assertEqual(self._refusal(self.owner_record(startedAtEpoch=bad), self.owner_record(startedAtEpoch=bad)),
                                 ["owner-records-disagree"])
        self.assertEqual(self._check(self.owner_record(startedAtEpoch=2**53 - 1), self.owner_record(startedAtEpoch=2**53 - 1))["runStartEpoch"],
                         float(2**53 - 1))

    def test_invalid_owner_epochs_are_refused(self) -> None:
        base = int(self.RUN_EPOCH)
        for bad in (True, False, -5, 0, "1791406238", None, float("nan"), float("inf")):
            with self.subTest(bad=bad):
                self.assertEqual(self._refusal(self.owner_record(), self.owner_record(startedAtEpoch=bad)), ["owner-records-disagree"])
                self.assertEqual(self._refusal(self.owner_record(startedAtEpoch=bad), self.owner_record(startedAtEpoch=base + 1)),
                                 ["owner-records-disagree"])

    def test_every_refusal_branch_refuses_and_leaves_the_leases_alone(self) -> None:
        def tamper(change: object) -> None:
            self.quiet_world()
            change()  # type: ignore[operator]

        def mismatch_label() -> None:
            record = json.loads((self.cache / "leases" / "gradle" / "owner.json").read_text())
            record["label"] = "someone-else"
            (self.cache / "leases" / "gradle" / "owner.json").write_text(json.dumps(record))

        def not_retained() -> None:
            self.write_records(owner=self.owner_record(requiresManualRecovery=False))

        def disagree() -> None:
            record = json.loads((self.cache / "leases" / "gradle" / "owner.json").read_text())
            record["pid"] = 70002
            (self.cache / "leases" / "gradle" / "owner.json").write_text(json.dumps(record))

        def receipt_label() -> None:
            (self.run_dir / "receipt.json").write_text(json.dumps({"label": "other", "decision": "failed"}))

        def receipt_passed() -> None:
            (self.run_dir / "receipt.json").write_text(json.dumps({"label": self.LABEL, "decision": "passed"}))

        def extra_file() -> None:
            (self.cache / "leases" / "cargo" / "stray.txt").write_text("x")

        def live_recorded_same_coalition() -> None:
            self.processes[4101] = (1, self.identities[0][1], "S")
            self.coalitions[4101] = 100

        def live_recorded_unreadable() -> None:
            self.processes[4101] = (1, self.identities[0][1], "S")
            self.coalitions[4101] = None

        def owner_live() -> None:
            self.processes[70001] = (1, self.lstart(self.RUN_EPOCH - 5), "S")

        def new_same_coalition_process() -> None:
            self.processes[800] = (1, self.lstart(self.RUN_EPOCH + 900), "S")
            self.coalitions[800] = 100

        def new_unreadable_process() -> None:
            self.processes[801] = (1, self.lstart(self.RUN_EPOCH + 900), "S")
            self.coalitions[801] = None

        def holder() -> None:
            self.holders = [4242]

        cases = {
            "label-mismatch": mismatch_label, "not-retained": not_retained, "owner-records-disagree": disagree,
            "receipt-label-mismatch": receipt_label, "receipt-not-failed": receipt_passed,
            "lease-has-extra-files": extra_file, "identity-uncertain": live_recorded_same_coalition,
            "identity-uncertain ": live_recorded_unreadable, "owner-live": owner_live,
            "scan-uncertain": new_same_coalition_process, "scan-uncertain ": new_unreadable_process, "lsof-holder": holder,
        }
        for expected, change in cases.items():
            with self.subTest(expected):
                self.setUp()
                self.lines.clear()
                tamper(change)
                code = self.go()
                self.assertEqual(code, recover_leases.EXIT_REFUSED, self.lines)
                reasons = self.summary()["refusalReasons"]
                self.assertIn(expected.strip(), reasons)
                for name in ("cargo", "gradle"):
                    self.assertTrue((self.cache / "leases" / name / "owner.json").exists())
                self.assertEqual(self.go(execute=True, dry_run=False, confirm_label=self.LABEL), recover_leases.EXIT_REFUSED)
                self.assertTrue((self.cache / "leases" / "cargo").exists())
                self.assertFalse(list(self.run_dir.glob("manual-recovery-*")), "nothing is archived when refused")

    def test_records_that_change_during_the_run_are_refused_as_unstable(self) -> None:
        self.quiet_world()
        replaced = [False]

        def change_owner(call: int) -> None:
            if call == 2 and not replaced[0]:
                replaced[0] = True
                path = self.cache / "leases" / "cargo" / "owner.json"
                record = json.loads(path.read_text())
                record["terminationStatus"] = "edited"
                path.write_text(json.dumps(record))

        self.on_snapshot = change_owner
        self.assertEqual(self.go(), recover_leases.EXIT_REFUSED)
        self.assertIn("records-unstable", self.summary()["refusalReasons"])
        # A swapped lease directory (different inode) is also unstable.
        self.setUp()
        self.quiet_world()
        swapped = [False]

        def swap_dir(call: int) -> None:
            if call == 2 and not swapped[0]:
                swapped[0] = True
                lease = self.cache / "leases" / "gradle"
                saved = self.cache / "leases" / "gradle-old"
                lease.rename(saved)
                lease.mkdir()
                (lease / "owner.json").write_text((saved / "owner.json").read_text())

        self.on_snapshot = swap_dir
        self.assertEqual(self.go(), recover_leases.EXIT_REFUSED)
        self.assertIn("records-unstable", self.summary()["refusalReasons"])

    def test_admission_failure_and_bad_inputs_are_invalid_not_refused(self) -> None:
        self.quiet_world()
        shutil.rmtree(self.cache / "cargo-target")
        with self.assertRaises(recover_leases.InvalidInput):
            self.go()
        self.setUp()
        with self.assertRaises(recover_leases.InvalidInput):
            self.go(receipt=str(self.root / "other" / "receipt.json"))
        with self.assertRaises(recover_leases.InvalidInput):
            self.go(label="bad label!")
        with self.assertRaises(recover_leases.InvalidInput):
            self.go(execute=True, dry_run=False, confirm_label="other")
        with self.assertRaises(recover_leases.InvalidInput):
            self.go(confirm_label=self.LABEL)
        self.assertEqual(recover_leases.main(["--cache-root", str(self.cache), "--label", "bad label!", "--receipt", "x"]), recover_leases.EXIT_INVALID)

    def test_classification_matrix(self) -> None:
        start = self.lstart(self.RUN_EPOCH + 50)
        old = self.lstart(self.RUN_EPOCH - 3600)
        self.world((1, 0, -86400, "S"), (500, 1, -3000, "S"), (610, 500, 100, "S"), (620, 1, 100, "S"), (630, 1, 100, "S"),
                   (640, 1, 100, "Z"), (650, 1, -400, "S"))
        self.coalitions.update({620: 7, 630: 100, 610: 100})
        classifier = recover_leases.Classifier(self.context(), self.RUN_EPOCH, [100])
        outcomes = classifier.classify_many([
            (610, self.lstart(self.RUN_EPOCH + 100)), (620, self.lstart(self.RUN_EPOCH + 100)), (630, self.lstart(self.RUN_EPOCH + 100)),
            (640, self.lstart(self.RUN_EPOCH + 100)), (650, self.lstart(self.RUN_EPOCH - 400)), (999, start),
            (620, "Mon Jan  1 00:00:00 2001"),
        ], self.processes)
        classes = {key: cls for key, (cls, _e) in outcomes.items()}
        self.assertEqual(classes[(610, self.lstart(self.RUN_EPOCH + 100))], "non-descendant-ancestor-predates-run")
        self.assertEqual(outcomes[(610, self.lstart(self.RUN_EPOCH + 100))][1]["ancestorPid"], 500)
        self.assertEqual(classes[(620, self.lstart(self.RUN_EPOCH + 100))], "non-descendant-coalition")
        self.assertEqual(classes[(630, self.lstart(self.RUN_EPOCH + 100))], "uncertain", "equal coalition, ppid 1: could be a daemonized descendant")
        self.assertEqual(classes[(640, self.lstart(self.RUN_EPOCH + 100))], "exited", "zombie")
        self.assertEqual(classes[(650, self.lstart(self.RUN_EPOCH - 400))], "non-descendant-predates-run")
        # Inside the 300 s margin a process is NOT treated as predating the run.
        self.processes[651] = (1, self.lstart(self.RUN_EPOCH - 100), "S")
        self.assertFalse(classifier.predates(self.processes[651][1], 651))
        self.assertEqual(classes[(999, start)], "exited")
        self.assertEqual(classes[(620, "Mon Jan  1 00:00:00 2001")], "exited", "start time differs: PID reuse")
        # Without run coalition ids nothing can be classified by coalition; Linux has no ancestor rule.
        no_ids = recover_leases.Classifier(self.context(), self.RUN_EPOCH, [])
        self.assertEqual(no_ids.classify_many([(620, self.lstart(self.RUN_EPOCH + 100))], self.processes)[(620, self.lstart(self.RUN_EPOCH + 100))][0], "uncertain")
        linux = recover_leases.Classifier(self.context(platform="linux"), self.RUN_EPOCH, [100])
        linux_outcomes = linux.classify_many([(610, self.lstart(self.RUN_EPOCH + 100)), (620, self.lstart(self.RUN_EPOCH + 100))], self.processes)
        self.assertEqual({cls for cls, _e in linux_outcomes.values()}, {"uncertain"})

    def test_observation_requires_every_live_sighting_to_be_classified(self) -> None:
        self.quiet_world()
        pid, start = self.identities[1]  # unconfirmed (not recorded as owned)
        flips = {"count": 0}

        def flicker(call: int) -> None:
            # Live and foreign-coalition on the first sighting, live and same-coalition afterwards.
            self.processes[pid] = (1, start, "S")
            self.coalitions[pid] = 7 if call == 1 else 100

        self.on_snapshot = flicker
        self.assertEqual(self.go(), recover_leases.EXIT_REFUSED)
        self.assertIn("identity-uncertain", self.summary()["refusalReasons"])
        self.setUp()
        self.quiet_world()
        # Live and foreign in every sighting is accepted with evidence.
        self.processes[pid] = (1, start, "S")
        self.coalitions[pid] = 7
        self.assertEqual(self.go(), recover_leases.EXIT_OK, self.lines)
        plan = json.loads((self.run_dir / self.summary()["planFile"]).read_text())
        recorded = next(item for item in plan["identities"] if item["pid"] == pid)
        self.assertEqual(recorded["classification"], "non-descendant-coalition")
        self.assertEqual(recorded["evidence"]["coalitionId"], 7)
        self.assertEqual(recorded["evidence"]["uidClass"], "other")

    def test_identity_evidence_is_collected_from_owner_records_and_receipt_and_bounded(self) -> None:
        receipt = {
            "label": self.LABEL, "decision": "failed",
            "gates": [{"naturalExitSettle": {"identityUnion": [{"pid": 5000 + n, "startedAt": f"s{n}"} for n in range(64)],
                                             "identityUnionTruncated": True}}],
            "provenance": {"classifiedIdentities": [{"pid": 9, "startedAt": "x", "runCoalitionIds": [55]}]},
        }
        self.write_records(receipt=receipt)
        records = recover_leases.read_records(recover_leases.Layout(self.cache, self.LABEL))
        found, truncated = recover_leases.collect_identities(records)
        self.assertIn((4101, self.identities[0][1]), found)
        self.assertEqual(sum(1 for key in found if 5000 <= key[0] < 5064), 64)
        self.assertIn("identityUnionTruncated", truncated)
        self.assertEqual(recover_leases.persisted_coalition_ids(records), [55, 100])
        huge = {"label": self.LABEL, "decision": "failed",
                "a": {"naturalExitSettle": {"identityUnion": [{"pid": 10000 + n, "startedAt": "s"} for n in range(64)]}}}
        for index in range(10):
            huge[f"g{index}"] = {"naturalExitSettle": {"initialIdentities": [{"pid": 20000 + index * 100 + n, "startedAt": "s"} for n in range(64)]}}
        self.write_records(receipt=huge)
        with self.assertRaises(recover_leases.Refused) as caught:
            recover_leases.collect_identities(recover_leases.read_records(recover_leases.Layout(self.cache, self.LABEL)))
        self.assertEqual(caught.exception.reasons, ["evidence-overflow"])

    def test_execute_archives_privately_removes_both_leases_and_never_touches_the_receipt(self) -> None:
        self.quiet_world()
        original_bytes = {name: (self.cache / "leases" / name / "owner.json").read_bytes() for name in ("cargo", "gradle")}
        receipt_bytes = (self.run_dir / "receipt.json").read_bytes()
        fsyncs: list[int] = []
        real_fsync = os.fsync
        with mock.patch.object(os, "fsync", side_effect=lambda fd: (fsyncs.append(fd), real_fsync(fd))[1]):
            code = self.go(execute=True, dry_run=False, confirm_label=self.LABEL)
        self.assertEqual(code, recover_leases.EXIT_OK, self.lines)
        summary = self.summary()
        self.assertTrue(summary["complete"])
        self.assertEqual(summary["removedLeases"], ["cargo", "gradle"])
        self.assertTrue(summary["bothPathsAbsent"])
        for name in ("cargo", "gradle"):
            self.assertFalse((self.cache / "leases" / name).exists())
        self.assertEqual((self.run_dir / "receipt.json").read_bytes(), receipt_bytes, "the failed receipt is never modified")
        archive = next(self.run_dir.glob("manual-recovery-*"))
        self.assertEqual(archive.name, "manual-recovery-20261004T183000Z")
        for name in ("cargo", "gradle"):
            archived = (archive / f"owner-{name}-token-redacted.json").read_text()
            self.assertNotIn(self.TOKEN, archived, "raw lease tokens are never archived")
            redacted = json.loads(archived)
            self.assertEqual(redacted["token"], "sha256:" + hashlib.sha256(self.TOKEN.encode()).hexdigest())
            self.assertEqual(redacted["label"], self.LABEL)
        self.assertEqual((archive / "failed-receipt.json").read_bytes(), receipt_bytes)
        data = (archive / "manual-recovery.json").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), summary["manualRecoverySha256"])
        result = json.loads(data)
        self.assertEqual((result["bothPathsAbsent"], result["failedReceiptUnmodified"], result["privilegeUsed"], result["signalsSent"]),
                         (True, True, False, 0))
        self.assertEqual(result["archive"]["originalOwnerSha256"]["cargo"], hashlib.sha256(original_bytes["cargo"]).hexdigest())
        self.assertGreaterEqual(len(fsyncs), 6, "archive files and both directories are fsynced")
        self.assertNotIn(self.TOKEN, data.decode())
        self.assertNotIn(self.TOKEN, json.dumps(summary))
        for path in archive.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, path.name)

    def test_execute_re_checks_everything_and_refuses_when_the_world_changed(self) -> None:
        self.quiet_world()
        self.assertEqual(self.go(), recover_leases.EXIT_OK)
        # Between the dry run and the execute a new same-coalition daemon appears.
        self.processes[800] = (1, self.lstart(self.RUN_EPOCH + 900), "S")
        self.coalitions[800] = 100
        self.assertEqual(self.go(execute=True, dry_run=False, confirm_label=self.LABEL), recover_leases.EXIT_REFUSED)
        self.assertTrue((self.cache / "leases" / "cargo" / "owner.json").exists())
        self.assertFalse(list(self.run_dir.glob("manual-recovery-*")))

    def test_partial_failure_is_reported_and_recorded(self) -> None:
        self.quiet_world()
        real_rmdir = os.rmdir

        def failing_rmdir(path: object, *args: object, **kwargs: object) -> None:
            if path == "gradle":
                raise OSError("busy")
            real_rmdir(path, *args, **kwargs)  # type: ignore[arg-type]

        with mock.patch.object(os, "rmdir", side_effect=failing_rmdir):
            code = self.go(execute=True, dry_run=False, confirm_label=self.LABEL)
        self.assertEqual(code, recover_leases.EXIT_PARTIAL)
        summary = self.summary()
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["removedLeases"], ["cargo"])
        self.assertFalse(summary["bothPathsAbsent"])
        archive = next(self.run_dir.glob("manual-recovery-*"))
        result = json.loads((archive / "manual-recovery.json").read_text())
        self.assertEqual(result["failure"], "OSError")
        self.assertTrue((archive / "owner-gradle-token-redacted.json").exists(), "originals were archived before anything was removed")
        self.assertEqual(result["status"], "partial")

    def test_execute_refuses_to_remove_a_lease_whose_record_changed_at_the_last_moment(self) -> None:
        self.quiet_world()
        real_remove = recover_leases._remove_lease

        def mutating(layout: object, name: str, expected: dict, identity: tuple[int, int]) -> None:
            if name == "cargo":
                (self.cache / "leases" / "cargo" / "owner.json").write_text(json.dumps({"changed": True}))
            real_remove(layout, name, expected, identity)  # type: ignore[arg-type]

        with mock.patch.object(recover_leases, "_remove_lease", side_effect=mutating):
            code = self.go(execute=True, dry_run=False, confirm_label=self.LABEL)
        self.assertEqual(code, recover_leases.EXIT_PARTIAL)
        self.assertTrue((self.cache / "leases" / "cargo" / "owner.json").exists(), "nothing was unlinked after the last-moment change")
        self.assertTrue((self.cache / "leases" / "gradle").exists())
        self.assertFalse(self.summary()["complete"])

    def test_recovery_makes_no_signals_and_uses_no_privilege(self) -> None:
        self.quiet_world()
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no helper processes in this test")), \
                mock.patch.object(os, "setuid", side_effect=AssertionError("no privilege"), create=True):
            self.assertEqual(self.go(), recover_leases.EXIT_OK)

    def test_recovery_is_refused_without_persisted_provenance_and_there_is_no_operator_override(self) -> None:
        self.quiet_world()
        for name, owner in {
            "no provenance field": {k: v for k, v in self.owner_record().items() if k != "provenance"},
            "provenance unavailable": self.owner_record(provenance={"mode": "coalition", "available": False, "runCoalitionIds": [100], "subreaper": False}),
            "no ids and no subreaper": self.owner_record(provenance={"mode": "coalition", "available": True, "runCoalitionIds": [], "subreaper": False}),
            "hostile ids only": self.owner_record(provenance={"mode": "coalition", "available": True, "runCoalitionIds": [0, -3, "x"], "subreaper": False}),
        }.items():
            with self.subTest(name):
                self.write_records(owner=owner)
                self.lines.clear()
                self.assertEqual(self.go(), recover_leases.EXIT_REFUSED, self.lines)
                self.assertEqual(self.summary()["refusalReasons"], ["no-persisted-provenance"])
                self.assertEqual(self.go(execute=True, dry_run=False, confirm_label=self.LABEL), recover_leases.EXIT_REFUSED)
                self.assertTrue((self.cache / "leases" / "cargo" / "owner.json").exists())
        self.assertNotIn("--run-coalition-id", recover_leases.build_parser().format_help())
        with self.assertRaises(SystemExit):
            recover_leases.build_parser().parse_args(["--cache-root", "/c", "--label", "L", "--receipt", "/r", "--run-coalition-id", "100"])
        self.assertFalse(hasattr(recover_leases, "validate_operator_coalitions"))
        # A subreaper-only record (Linux) is accepted: no coalition rule, only exit/predates.
        self.write_records(owner=self.owner_record(provenance={"mode": "subreaper", "available": True, "runCoalitionIds": [], "subreaper": True}))
        self.world((1, 0, -86400, "S"), (500, 1, -3000, "S"))  # nothing new: no coalition rule exists to classify daemons
        self.lines.clear()
        self.assertEqual(self.go(), recover_leases.EXIT_OK, self.lines)
        plan = json.loads((self.run_dir / self.summary()["planFile"]).read_text())
        self.assertEqual((plan["runCoalitionIds"], plan["runCoalitionSources"]), ([], ["persisted-subreaper-only"]))

    def test_persisted_coalition_ids_are_authoritative(self) -> None:
        self.quiet_world()
        self.coalitions[800] = 100
        self.processes[800] = (1, self.lstart(self.RUN_EPOCH + 900), "S")
        self.assertEqual(self.go(), recover_leases.EXIT_REFUSED)
        self.assertIn("scan-uncertain", self.summary()["refusalReasons"], "a daemon in the persisted run coalition blocks recovery")
        self.setUp()
        self.quiet_world()
        self.assertEqual(self.go(), recover_leases.EXIT_OK, self.lines)
        plan = json.loads((self.run_dir / self.summary()["planFile"]).read_text())
        self.assertEqual((plan["runCoalitionIds"], plan["runCoalitionSources"]), ([100], ["persisted"]))

    def test_recorded_owned_identities_are_cleared_only_by_verified_exit(self) -> None:
        self.quiet_world()
        pid, start = self.identities[0]  # recorded in ownedProcesses
        self.processes[pid] = (1, start, "S")
        self.coalitions[pid] = 7  # foreign coalition: would classify as non-descendant if it were not owned
        self.assertEqual(self.go(), recover_leases.EXIT_REFUSED)
        self.assertIn("identity-uncertain", self.summary()["refusalReasons"])
        self.setUp()
        self.quiet_world()
        self.processes[pid] = (1, start, "S")
        self.processes[500] = (1, self.lstart(self.RUN_EPOCH - 3000), "S")
        self.processes[pid] = (500, start, "S")  # also has a pre-run ancestor
        self.assertEqual(self.go(), recover_leases.EXIT_REFUSED, "heuristics never clear an owned identity")

    def test_parse_start_refuses_dst_ambiguity_and_start_sources_must_agree(self) -> None:
        old_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()
            self.assertIsNone(recover_leases.parse_start("Sun Nov  1 01:30:00 2026"), "repeated fall-back hour is ambiguous")
            self.assertIsNotNone(recover_leases.parse_start("Sun Nov  1 03:30:00 2026"))
            self.assertIsNotNone(recover_leases.parse_start("Sun Jul  5 01:30:00 2026"))
            self.assertIsNone(recover_leases.parse_start("Sun 1 Nov 01:30:00 2026"), "day-first ambiguity")
            self.assertIsNotNone(recover_leases.parse_start("Sun 1 Nov 03:30:00 2026"))
            self.assertIsNotNone(recover_leases.parse_start("Sun  5 Jul 01:30:00 2026"))
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()
        start = self.lstart(self.RUN_EPOCH - 4000)
        self.processes = {900: (1, start, "S")}
        agree = recover_leases.Classifier(self.context(), self.RUN_EPOCH, [100])
        self.assertTrue(agree.predates(start, 900))
        disagree = recover_leases.Classifier(self.context(start_reader=lambda pid: recover_leases.parse_start(start) + 3600), self.RUN_EPOCH, [100])
        self.assertFalse(disagree.predates(start, 900), "a skew between the kernel and ps start times fails closed")
        unreadable = recover_leases.Classifier(self.context(start_reader=lambda pid: None), self.RUN_EPOCH, [100])
        self.assertFalse(unreadable.predates(start, 900))

    def test_kernel_start_reader_agrees_with_ps_for_this_process(self) -> None:
        epoch = provenance.read_process_start_epoch(os.getpid())
        if epoch is None:
            return  # unsupported host: nothing to compare
        ps = subprocess.run(["ps", "-o", "lstart=", "-p", str(os.getpid())], capture_output=True, text=True).stdout.strip()
        parsed = recover_leases.parse_start(ps)
        self.assertTrue(parsed is None or abs(parsed - epoch) <= 2.0, (parsed, epoch))
        self.assertLess(epoch, time.time() + 1)
        self.assertIsNone(provenance.read_process_start_epoch(2**22 + 12345))

    @staticmethod
    def _kinfo(pid: int, seconds: int, size: int = provenance.KINFO_PROC_SIZE) -> bytes:
        raw = bytearray(size)
        raw[0:8] = seconds.to_bytes(8, "little", signed=True)
        raw[40:44] = pid.to_bytes(4, "little", signed=True)
        return bytes(raw)

    def test_kinfo_proc_start_requires_exact_size_and_matching_pid(self) -> None:
        good = self._kinfo(77, 1_790_000_000)
        self.assertEqual(provenance.start_epoch_from_kinfo_proc(good, 77), 1_790_000_000.0)
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(good, 78), "a record for another pid")
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(good[:-1], 77), "short buffer")
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(good + b"\0", 77), "long buffer")
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(b"", 77))
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(None, 77))
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(self._kinfo(77, 0), 77), "zero start time")
        self.assertIsNone(provenance.start_epoch_from_kinfo_proc(self._kinfo(77, -5), 77))

    def test_darwin_start_epoch_uses_the_injected_sysctl_reader_and_fails_closed(self) -> None:
        with mock.patch.object(provenance.sys, "platform", "darwin"), \
                mock.patch.object(provenance.ctypes, "CDLL", side_effect=OSError("no libc")):
            self.assertIsNone(provenance.read_process_start_epoch(5), "ctypes failure is None")
        with mock.patch.object(provenance.sys, "platform", "darwin"):
            self.assertEqual(provenance.read_process_start_epoch(5, kinfo_reader=lambda pid: self._kinfo(pid, 1_700_000_000)),
                             1_700_000_000.0)
            self.assertIsNone(provenance.read_process_start_epoch(5, kinfo_reader=lambda pid: self._kinfo(6, 1_700_000_000)))
            self.assertIsNone(provenance.read_process_start_epoch(5, kinfo_reader=lambda pid: b"short"))
            self.assertIsNone(provenance.read_process_start_epoch(5, kinfo_reader=lambda pid: None))
            self.assertIsNone(provenance.read_process_start_epoch(5, kinfo_reader=mock.Mock(side_effect=OSError("x"))))

    def test_removal_reads_the_record_through_the_lease_descriptor_and_refuses_links(self) -> None:
        self.quiet_world()
        layout = recover_leases.Layout(self.cache, self.LABEL)
        records = recover_leases.read_records(layout)
        admissions = recover_leases.admit_all(layout)
        expected = recover_leases._public_facts(records["ownerFacts"]["cargo"])
        owner_path = self.cache / "leases" / "cargo" / "owner.json"
        os.link(owner_path, self.root / "second-link")  # a second hard link
        with self.assertRaises(recover_leases.Refused):
            recover_leases._remove_lease(layout, "cargo", expected, admissions["leases/cargo"])
        self.assertTrue(owner_path.exists())
        os.unlink(self.root / "second-link")
        data = owner_path.read_bytes()
        owner_path.unlink()
        (self.cache / "leases" / "cargo" / "target.json").write_bytes(data)
        os.symlink("target.json", owner_path)  # a symlink in place of the record
        with self.assertRaises((recover_leases.Refused, OSError)):
            recover_leases._remove_lease(layout, "cargo", expected, admissions["leases/cargo"])
        self.assertTrue((self.cache / "leases" / "cargo").exists())

    def test_post_removal_receipt_reread_failure_still_writes_an_honest_manual_recovery_json(self) -> None:
        self.quiet_world()
        real = recover_leases._file_facts
        removed = {"done": False}
        real_remove = recover_leases._remove_lease

        def tracking(*args: object, **kwargs: object) -> None:
            real_remove(*args, **kwargs)  # type: ignore[arg-type]
            removed["done"] = True

        def failing(path: pathlib.Path) -> dict:
            if removed["done"] and path.name == "receipt.json":
                raise OSError("receipt vanished")
            return real(path)

        with mock.patch.object(recover_leases, "_remove_lease", side_effect=tracking), \
                mock.patch.object(recover_leases, "_file_facts", side_effect=failing):
            code = self.go(execute=True, dry_run=False, confirm_label=self.LABEL)
        self.assertEqual(code, recover_leases.EXIT_PARTIAL)
        archive = next(self.run_dir.glob("manual-recovery-*"))
        result = json.loads((archive / "manual-recovery.json").read_text())
        self.assertIsNone(result["failedReceiptUnmodified"], "unverifiable, reported as such, not assumed")
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["bothPathsAbsent"])
        self.assertFalse(self.summary()["complete"])

    def test_cli_parser(self) -> None:
        parsed = recover_leases.build_parser().parse_args(
            ["--cache-root", "/c", "--label", "L", "--receipt", "/r", "--execute", "--confirm-label", "L"])
        self.assertEqual((parsed.execute, parsed.confirm_label), (True, "L"))
        with self.assertRaises(SystemExit):
            recover_leases.build_parser().parse_args(["--cache-root", "/c", "--label", "L", "--receipt", "/r", "--dry-run", "--execute"])

    def test_parse_start_accepts_exactly_the_two_english_orders(self) -> None:
        month_first = recover_leases.parse_start("Sun Sep 27 09:43:13 2026")
        self.assertIsNotNone(month_first)
        self.assertEqual(recover_leases.parse_start("Sun 27 Sep 09:43:13 2026"), month_first)
        self.assertEqual(recover_leases.parse_start("Sun  7 Sep 09:43:13 2026"), recover_leases.parse_start("Sun Sep  7 09:43:13 2026"))
        for bad in ("garbage", "", "Sun Sept 27 09:43:13 2026", "Sun 27 Sept 09:43:13 2026", "Sun Sep 27 09:43:13", "27 09 2026 09:43:13",
                    "Sun 27 09 09:43:13 2026", "dim. 27 sept. 09:43:13 2026", "So 27 Okt 09:43:13 2026", "Sun 27 Sep 09:43:13 2026 x"):
            with self.subTest(bad=bad):
                self.assertIsNone(recover_leases.parse_start(bad))

    def test_same_start_instant_compares_by_value_across_locales(self) -> None:
        same = provenance.same_start_instant
        self.assertTrue(same("Sun Sep 27 09:43:13 2026", "Sun 27 Sep 09:43:13 2026"))
        self.assertTrue(same("Sun 27 Sep 09:43:13 2026", "Sun 27 Sep 09:43:13 2026"))
        self.assertFalse(same("Sun Sep 27 09:43:13 2026", "Sun 27 Sep 09:43:14 2026"))
        for bad in ("garbage", "", "Sun 27 Sept 09:43:13 2026"):
            with self.subTest(bad=bad):
                self.assertFalse(same(bad, "Sun 27 Sep 09:43:13 2026"))
                self.assertFalse(same("Sun Sep 27 09:43:13 2026", bad))
                self.assertFalse(same(bad, bad), "identical unparsable text is still not proven equal")
        old_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()
            self.assertFalse(same("Sun Nov  1 01:30:00 2026", "Sun 1 Nov 01:30:00 2026"), "DST-ambiguous")
            self.assertTrue(same("Sun Nov  1 03:30:00 2026", "Sun 1 Nov 03:30:00 2026"))
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

    def test_parse_start(self) -> None:
        self.assertIsNotNone(recover_leases.parse_start("Sun Oct  4 16:20:29 2026"))
        self.assertIsNone(recover_leases.parse_start("garbage"))
        self.assertLess(recover_leases.parse_start("Sun Oct  4 16:20:29 2026"), recover_leases.parse_start("Sun Oct  4 16:20:31 2026"))


LEASE_DIRS = ("cargo", "gradle")


if __name__ == "__main__":
    unittest.main()
