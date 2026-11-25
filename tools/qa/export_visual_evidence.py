"""Closed allowlist for private installed-viewer PNGs; never exports payloads or paths."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import struct
import zlib

from tools.release.private_roots import AdmissionError, admit_directory

WIDTHS = (320, 736, 1024, 1280, 1440)
POINTERS = ("fine", "coarse")
PHASES = ("choose.png", "all-openapi-yaml.png", "save.png")
MAX_PNG = 20 * 1024 * 1024
MAX_SCANLINE_BYTES = (max(WIDTHS) * 4 + 1) * 900
INFLATE_BLOCK = 64 * 1024
EXPECTED = {f"{width}-{pointer}/{phase}" for width in WIDTHS for pointer in POINTERS for phase in PHASES}


class VisualEvidenceFailure(Exception):
    """Fixed category only; file paths and image bytes never enter diagnostics."""


def _validate_pixels(chunks: list[bytes], row_size: int, expected: int) -> None:
    """Validate noninterlaced scanlines without allocating an unbounded inflate result."""
    decoder, decoded = zlib.decompressobj(), 0
    try:
        for payload in chunks:
            while payload:
                pixels = decoder.decompress(payload, min(INFLATE_BLOCK, expected - decoded + 1))
                if decoder.unused_data or decoded + len(pixels) > expected:
                    raise VisualEvidenceFailure("visual-png")
                # Filter bytes occur at row boundaries, including across inflate blocks/IDATs.
                if any(pixels[index] > 4 for index in range((-decoded) % row_size, len(pixels), row_size)):
                    raise VisualEvidenceFailure("visual-png")
                decoded += len(pixels)
                payload = decoder.unconsumed_tail
    except zlib.error:
        raise VisualEvidenceFailure("visual-png") from None
    if not decoder.eof or decoded != expected:
        raise VisualEvidenceFailure("visual-png")


def private_png(path: Path, width: int, height: int) -> bytes:
    info = path.lstat()
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_PNG):
        raise VisualEvidenceFailure("visual-file-admission")
    with path.open("rb") as stream:
        data = stream.read(MAX_PNG + 1)
    if len(data) > MAX_PNG or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise VisualEvidenceFailure("visual-png")
    offset, seen_header, ended = 8, False, False
    chunks, row_size, expected = [], 0, 0
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        end = offset + 12 + length
        if end > len(data):
            raise VisualEvidenceFailure("visual-png")
        kind, payload = data[offset + 4:offset + 8], data[offset + 8:offset + 8 + length]
        crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        if zlib.crc32(kind + payload) & 0xffffffff != crc:
            raise VisualEvidenceFailure("visual-png")
        if not seen_header:
            if kind != b"IHDR" or length != 13:
                raise VisualEvidenceFailure("visual-png")
            if struct.unpack_from(">II", payload) != (width, height):
                raise VisualEvidenceFailure("visual-dimensions")
            depth, color, compression, filtering, interlace = payload[8:]
            # Chromium screenshots use 8-bit RGB (or RGBA with transparency), no interlace.
            if depth != 8 or color not in (2, 6) or (compression, filtering, interlace) != (0, 0, 0):
                raise VisualEvidenceFailure("visual-png")
            row_size = 1 + width * (3 if color == 2 else 4)
            expected = row_size * height
            if width <= 0 or height <= 0 or expected > MAX_SCANLINE_BYTES:
                raise VisualEvidenceFailure("visual-png")
            seen_header = True
        elif kind not in (b"IDAT", b"IEND"):
            # This is the screenshot encoding allowlist, not a general PNG decoder.
            raise VisualEvidenceFailure("visual-png")
        if kind == b"IDAT":
            chunks.append(payload)
        if kind == b"IEND":
            ended = length == 0 and end == len(data)
            break
        offset = end
    if not (seen_header and chunks and ended):
        raise VisualEvidenceFailure("visual-png")
    _validate_pixels(chunks, row_size, expected)
    return data


def collect_visuals(browser: Path, *, require_complete: bool):
    """A passing proof needs exactly 30 valid frames; failed proofs retain valid partial frames."""
    admit_directory(browser)
    selected, refused = [], {"missing": 0, "unsafe": 0, "invalid": 0}
    for width in WIDTHS:
        for pointer in POINTERS:
            directory = browser / f"{width}-{pointer}"
            try:
                admit_directory(directory)
            except (OSError, ValueError, AdmissionError):
                refused["unsafe" if directory.exists() or directory.is_symlink() else "missing"] += len(PHASES)
                continue
            for phase in PHASES:
                try:
                    data = private_png(directory / phase, width, 900)
                except FileNotFoundError:
                    refused["missing"] += 1
                    continue
                except (OSError, ValueError, VisualEvidenceFailure):
                    refused["invalid"] += 1
                    continue
                selected.append((f"{width}-{pointer}/{phase}", data))
    if require_complete and (set(name for name, _ in selected) != EXPECTED or len(selected) != 30 or any(refused.values())):
        raise VisualEvidenceFailure("visual-coverage")
    return selected, refused
