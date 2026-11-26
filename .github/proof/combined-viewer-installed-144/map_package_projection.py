"""Bind Map admission to the exact ordinary final receipt without reparsing it."""
import hashlib
import json
import os

from common import ROOT, need, private_json, safe_read
from tools.release.private_roots import open_private_file_read

ASSEMBLED = ROOT / 'safe/assembled.json'
PACKAGE = ROOT / 'safe/package.json'
PROJECTION = ROOT / 'private/assembled-map-package.json'
ASSEMBLED_LIMIT = 262144
PACKAGE_LIMIT = 65536


def canonical(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def snapshot(path, limit):
    with os.fdopen(open_private_file_read(path), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(0 < before.st_size <= limit)
        payload = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        need(len(payload) == before.st_size == after.st_size
             and before.st_mtime_ns == after.st_mtime_ns
             and before.st_ctime_ns == after.st_ctime_ns)
    return payload


def bindings(assembled, package):
    return {
        'version': 1,
        'assembledBytes': len(assembled),
        'assembledSha256': hashlib.sha256(assembled).hexdigest(),
        'packageSha256': hashlib.sha256(package).hexdigest(),
    }


def write_projection(final_receipt):
    assembled = snapshot(ASSEMBLED, ASSEMBLED_LIMIT)
    package = snapshot(PACKAGE, PACKAGE_LIMIT)
    need(assembled == canonical(final_receipt) and package == canonical(final_receipt['package']))
    private_json(PROJECTION, bindings(assembled, package))


def verify_projection(ordinary):
    projection = safe_read(PROJECTION, limit=1024)
    assembled = snapshot(ASSEMBLED, ASSEMBLED_LIMIT)
    package = snapshot(PACKAGE, PACKAGE_LIMIT)
    need(package == canonical(ordinary) and projection == bindings(assembled, package))
    return projection
