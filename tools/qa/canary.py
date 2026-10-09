#!/usr/bin/env python3
"""Privacy canary generation and scanning (PRIVACY-CANARIES), stdlib only.

  gen   : write a PRIVATE canary file (never uploaded, never printed)
  scan  : search named location classes (store, exports, daemon-log, ci-output, ui-json, ...) for every canary
          in raw form and in common encodings; print and record only (location class, canary name, encoding,
          count). A canary value is NEVER printed. Any hit exits 1.
  probe : plant a canary in a temporary directory and prove the scanner finds it in every encoding (a scanner that
          cannot see a planted canary must not be trusted to report "clean")

Compressed containers (gzip, zlib, zip members) are also searched once decompressed, bounded in size. Binary formats
that transform content in other ways (for example a value-dependent compression dictionary) are a documented limit.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import io
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile
import zlib

KINDS = ("authorization-header", "cookie-header", "query-token", "json-body-password", "env-var")
CHUNK = 1 << 20
MAX_INFLATE = 256 << 20


def make_canaries(rng_hex=None) -> dict[str, str]:
    """One unique canary per injection kind. Values are synthetic and carry a recognisable prefix."""
    rng_hex = rng_hex or (lambda: secrets.token_hex(8))
    return {
        "authorization-header": f"Bearer XTCANARY.auth.{rng_hex()}",
        "cookie-header": f"XTCANARY_session={rng_hex()}",
        "query-token": f"XTCANARYqt{rng_hex()}",
        "json-body-password": f"XTcanary-Pw!{rng_hex()}",
        "env-var": f"XTCANARY/env/{rng_hex()}",
    }


def _b64_alignments(raw: bytes, urlsafe: bool) -> list[bytes]:
    """Substrings of base64 output that are independent of the byte offset the value sits at."""
    out = []
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    for pad in range(3):
        text = enc(b"\0" * pad + raw).decode()
        # drop characters influenced by the leading pad bytes and by the final partial group
        start = {0: 0, 1: 2, 2: 3}[pad]
        body = text.rstrip("=")
        body = body[start:len(body) - 2]
        if len(body) >= 8:
            out.append(body.encode())
    return out


def needles(value: str) -> list[tuple[str, bytes]]:
    raw = value.encode()
    found: list[tuple[str, bytes]] = [("raw", raw)]
    found.append(("url-percent", urllib.parse.quote(value, safe="").encode()))
    found.append(("url-percent-all", "".join(f"%{b:02X}" for b in raw).encode()))
    found.append(("url-plus", urllib.parse.quote_plus(value).encode()))
    found.append(("json-escaped", json.dumps(value)[1:-1].encode()))
    found.append(("json-unicode-escaped", "".join(f"\\u{ord(c):04x}" for c in value).encode()))
    found.append(("hex-lower", binascii.hexlify(raw)))
    found.append(("hex-upper", binascii.hexlify(raw).upper()))
    found += [("base64", n) for n in _b64_alignments(raw, False)]
    found += [("base64url", n) for n in _b64_alignments(raw, True)]
    # the secret part alone (after the scheme or the cookie name) is what real leaks usually carry
    for sep in (" ", "="):
        if sep in value:
            tail = value.split(sep, 1)[1]
            if len(tail) >= 12:
                found.append(("raw-secret-part", tail.encode()))
    seen, uniq = set(), []
    for enc, n in found:
        if n not in seen:
            seen.add(n)
            uniq.append((enc, n))
    return uniq


def build_index(canaries: dict[str, str]) -> list[tuple[str, str, bytes]]:
    return [(name, enc, n) for name, value in canaries.items() for enc, n in needles(value)]


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def zstd_decode(data: bytes) -> bytes | None:
    """Decompress a zstd frame with whatever is available (Python 3.14 stdlib, `zstandard`, or the zstd CLI); None if none works."""
    try:
        from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+
        return zstd.decompress(data)
    except Exception:
        pass
    try:
        import zstandard  # type: ignore[import-not-found]
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except Exception:
        pass
    exe = shutil.which("zstd")
    if exe:
        try:
            r = subprocess.run([exe, "-dc", "--no-progress"], input=data, capture_output=True, timeout=60)
            if r.returncode == 0:
                return r.stdout[:MAX_INFLATE]
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def _inflate_variants(data: bytes, undecodable: list | None = None) -> list[bytes]:
    variants = []
    if data[:4] == ZSTD_MAGIC:
        out = zstd_decode(data)
        if out is None:
            if undecodable is not None:
                undecodable.append(1)
        else:
            variants.append(out)
    if data[:2] == b"\x1f\x8b":
        try:
            variants.append(gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_INFLATE))
        except Exception:
            pass
    if data[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        try:
            variants.append(zlib.decompressobj().decompress(data, MAX_INFLATE))
        except Exception:
            pass
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                total = 0
                for info in zf.infolist():
                    if info.file_size > MAX_INFLATE or total + info.file_size > MAX_INFLATE:
                        continue
                    total += info.file_size
                    variants.append(zf.read(info))
        except Exception:
            pass
    return variants


def scan_bytes(data: bytes, index, hits: dict, loc_class: str, depth: int = 0) -> None:
    undecodable: list = []
    for name, enc, needle in index:
        n = data.count(needle)
        if n:
            hits[(loc_class, name, enc)] = hits.get((loc_class, name, enc), 0) + n
    if depth < 2:
        for inner in _inflate_variants(data, undecodable):
            scan_bytes(inner, index, hits, loc_class, depth + 1)
    if undecodable:  # a compressed member the scanner cannot open is never reported as clean
        key = (loc_class, "<undecodable-zstd>", "scanner-limit")
        hits[key] = hits.get(key, 0) + len(undecodable)


def scan_file(path: pathlib.Path, index, hits: dict, loc_class: str) -> int:
    longest = max((len(n) for _, _, n in index), default=1)
    size = path.stat().st_size
    if size <= 64 << 20:
        scan_bytes(path.read_bytes(), index, hits, loc_class)
        return size
    # large files: overlapping chunks (compressed variants are only attempted on small files)
    tail = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            buf = tail + chunk
            for name, enc, needle in index:
                c = buf.count(needle) - tail.count(needle)
                if c > 0:
                    hits[(loc_class, name, enc)] = hits.get((loc_class, name, enc), 0) + c
            tail = buf[-(longest - 1):] if longest > 1 else b""
    return size


def scan_location(loc_class: str, target: pathlib.Path, index, hits: dict) -> dict:
    """Scan a file or a directory tree. Names of files are scanned too (a leaked value in a path counts)."""
    files = bytes_ = 0
    if target.is_file():
        paths = [target]
    elif target.is_dir():
        paths = [p for p in sorted(target.rglob("*")) if p.is_file() and not p.is_symlink()]
    else:
        return {"class": loc_class, "present": False, "files": 0, "bytes": 0}
    for p in paths:
        try:
            bytes_ += scan_file(p, index, hits, loc_class)
            files += 1
            scan_bytes(str(p.relative_to(target) if target.is_dir() else p.name).encode(), index, hits, loc_class)
        except OSError:
            hits[(loc_class, "<unreadable-file>", "io")] = hits.get((loc_class, "<unreadable-file>", "io"), 0) + 1
    return {"class": loc_class, "present": True, "files": files, "bytes": bytes_}


def run_scan(canaries: dict[str, str], locations: dict[str, list[pathlib.Path]]) -> dict:
    index = build_index(canaries)
    hits: dict = {}
    scanned = []
    for loc_class, targets in locations.items():
        agg = {"class": loc_class, "present": False, "files": 0, "bytes": 0}
        for t in targets:
            r = scan_location(loc_class, t, index, hits)
            agg["present"] |= r["present"]
            agg["files"] += r["files"]
            agg["bytes"] += r["bytes"]
        scanned.append(agg)
    rows = [{"locationClass": c, "canary": n, "encoding": e, "count": cnt} for (c, n, e), cnt in sorted(hits.items())]
    return {"schemaVersion": 1, "canaryKinds": sorted(canaries), "needleCount": len(index),
            "scanned": scanned, "hits": rows, "clean": not rows and any(s["present"] for s in scanned)}


def probe() -> int:
    canaries = make_canaries()
    index = build_index(canaries)
    ok = True
    with tempfile.TemporaryDirectory(prefix="xtcanary-probe-") as td:
        root = pathlib.Path(td)
        for name, value in canaries.items():
            for enc, needle in needles(value):
                if enc.startswith("base64"):
                    for pad in range(3):
                        b = (b"x" * pad) + value.encode()
                        data = (base64.urlsafe_b64encode(b) if enc == "base64url" else base64.b64encode(b))
                        hits: dict = {}
                        scan_bytes(b"prefix " + data + b" suffix", index, hits, "probe")
                        if not any(k[1] == name and k[2] == enc for k in hits):
                            ok = False
                            print(f"probe FAILED: {name} not found as {enc} at offset {pad}")
                    continue
                p = root / "planted.bin"
                p.write_bytes(b"leading noise " + needle + b" trailing noise")
                hits = {}
                scan_location("probe", p, index, hits)
                if not any(k[1] == name and k[2] == enc for k in hits):
                    ok = False
                    print(f"probe FAILED: {name} not found as {enc}")
        gz = root / "planted.gz"
        gz.write_bytes(gzip.compress(next(iter(canaries.values())).encode()))
        hits = {}
        scan_location("probe", gz, index, hits)
        if not hits:
            ok = False
            print("probe FAILED: gzip member")
        enc = None
        try:
            from compression import zstd  # type: ignore[import-not-found]
            enc = zstd.compress
        except Exception:
            exe = shutil.which("zstd")
            if exe:
                enc = lambda b: subprocess.run([exe, "-c", "-q"], input=b, capture_output=True, check=True).stdout  # noqa: E731
        if enc is not None:
            zf = root / "planted.xtf.zst"
            zf.write_bytes(enc(b"frame " + next(iter(canaries.values())).encode()))
            hits = {}
            scan_location("probe", zf, index, hits)
            if not any(k[1] in canaries for k in hits):
                ok = False
                print("probe FAILED: zstd member")
        else:
            print("probe note: no zstd encoder here; a zstd member that cannot be decoded is still reported as NOT clean")
        clean = root / "clean.txt"
        clean.write_text("nothing secret here\n")
        hits = {}
        scan_location("probe", clean, index, hits)
        if hits:
            ok = False
            print("probe FAILED: false positive")
    print("canary probe: " + ("pass" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("--out", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--canaries", required=True)
    s.add_argument("--loc", action="append", default=[], metavar="CLASS=PATH",
                   help="location class and a file or directory (repeatable; one class may repeat)")
    s.add_argument("--report", required=True)
    sub.add_parser("probe")
    a = ap.parse_args()
    if a.cmd == "probe":
        return probe()
    if a.cmd == "gen":
        out = pathlib.Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(make_canaries(), fh)
        print(f"canary file written with {len(KINDS)} kinds (values not shown)")
        return 0
    canaries = json.loads(pathlib.Path(a.canaries).read_text())
    locs: dict[str, list[pathlib.Path]] = {}
    for item in a.loc:
        if "=" not in item:
            print("--loc needs CLASS=PATH")
            return 2
        cls, path = item.split("=", 1)
        locs.setdefault(cls, []).append(pathlib.Path(path))
    report = run_scan(canaries, locs)
    pathlib.Path(a.report).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.report).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    for s_ in report["scanned"]:
        print(f"scanned class {s_['class']}: present={s_['present']} files={s_['files']} bytes={s_['bytes']}")
    for h in report["hits"]:
        print(f"CANARY HIT class={h['locationClass']} kind={h['canary']} encoding={h['encoding']} count={h['count']}")
    missing = [s_["class"] for s_ in report["scanned"] if not s_["present"]]
    if missing:
        print("locations absent (nothing scanned): " + ", ".join(missing))
    print("canary scan: " + ("clean" if report["clean"] else "NOT CLEAN"))
    return 0 if report["clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
