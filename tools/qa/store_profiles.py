"""Bounded store diagnostics rebuilt from fixed vocabulary and unsigned numbers."""
from __future__ import annotations

import os
import pathlib
import re
import stat


PROFILES = ("sparse", "singletons", "focused-singletons")
# Keep this vocabulary aligned with the instrumented store phases. Unknown names
# are withheld, never inferred from a filename or copied from diagnostic prose.
PHASES = frozenset("""
fixture admission_loop reject_beyond_segment_cap reopen_and_recover pagination
duplicates_and_barrier_assertions connection_mutex_wait connection_file_admission
writer_mutex_wait read_window_admission read_journal_snapshot read_segment_metadata
read_object_admission read_object_bytes_and_admission read_object_decode
read_frame_verification read_projection read_tail_projection read_navigation read_finalize
segment_encode_and_validate segment_staging_admission segment_logical_write
segment_compression segment_compressed_write segment_object_publication segment_sql_transaction
filesystem_sync_syscall device_sync_syscall segment_directory_sync_and_admission
root_binding_admission root_database_admission snapshot_registry_mutex_wait snapshot_registry_scan
flock_admission flock_wait flock_revalidate journal_sync checkpoint_sync directory_sync
journal_directory_admission publication_rwlock_wait journal_retry_load writer_wait
journal_validation tail_file_admission connection_wait_and_admission journal_sql_validation
snapshot_write_wait journal_append checkpoint_prepare tail_binding_admission checkpoint_publish
segment_validation segment_root_admission segment_commit segment_journal_cleanup
tail_validation tail_root_admission checkpoint_mutex_wait journal_tail
""".split())
TAIL_BYTES = 32 * 1024
# u128 nanoseconds need at most 39 decimal digits; ASCII excludes lookalike digits.
NUMBER = r"[0-9]{1,39}"
HEADER = re.compile(rf"expected_admissions=(?P<expected_admissions>{NUMBER}) "
                    r"counted_journal_syncs=(?P<counted_journal_syncs>true|false)")
ACTIVE = re.compile(rf"elapsed_ns=(?P<elapsed_ns>{NUMBER}) completed=(?P<completed>{NUMBER}) "
                    r"active=(?P<active>[a-z_]{1,64}) *")
STATE = re.compile(rf"state=(?P<state>started|progress|returned|unwinding) "
                   rf"completed=(?P<completed>{NUMBER}) elapsed_ns=(?P<elapsed_ns>{NUMBER})")
MEASUREMENT = re.compile(r"phase=(?P<phase>[a-z_]{1,64}) " + " ".join(
    rf"{key}=(?P<{key}>{NUMBER})" for key in ("spans", "total_ns", "max_ns", "acl_probes")))


def _read(path: pathlib.Path, *, tail: bool = False) -> bytes:
    """Read only regular files, with bounded I/O even for a growing progress file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return b""
            if tail:
                offset = max(0, info.st_size - TAIL_BYTES)
                stream.seek(offset)
                data = stream.read(TAIL_BYTES)
                # A tail may start inside a line. Never attest that suffix.
                return data.partition(b"\n")[2] if offset else data
            return stream.readline(256)
    except OSError:
        return b""


def _record(raw: bytes, grammar: re.Pattern) -> dict | None:
    # Incomplete writes at timeout are not observations of complete records.
    if not raw.endswith(b"\n"):
        return None
    match = grammar.fullmatch(raw[:-1].decode("ascii", errors="replace"))
    if match is None:
        return None
    fields = match.groupdict()
    if any(fields[key] not in PHASES for key in ("phase", "active") if key in fields):
        return None
    return {key: (int(value) if value.isascii() and value.isdigit() else
                  int(value == "true") if key == "counted_journal_syncs" else value)
            for key, value in fields.items()}


def collect(directory: pathlib.Path) -> dict:
    """Retain the last observed values per phase, not the unbounded report history.

    Three fixed profiles, a fixed phase set and 39-digit numbers bound the public
    result independently of input size. Missing or invalid records stay absent.
    """
    result = {}
    for name in PROFILES:
        progress = directory / f"store-{name}-progress.txt"
        profile = {}
        if header := _record(_read(progress), HEADER):
            profile["workload"] = header
        if active := _record(_read(directory / f"store-{name}-active.txt"), ACTIVE):
            profile["active"] = active
        phases = {}
        for line in _read(progress, tail=True).splitlines(keepends=True):
            if state := _record(line, STATE):
                profile["lastReport"] = state
            elif measurement := _record(line, MEASUREMENT):
                phases[measurement.pop("phase")] = measurement
        if phases:
            profile["phases"] = phases
        if profile:
            result[name] = profile
    return result
