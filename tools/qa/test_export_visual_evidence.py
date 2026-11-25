"""Synthetic PNG admission regressions; not rendered-viewer evidence."""
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from tools.qa.export_visual_evidence import EXPECTED, MAX_PNG, POINTERS, WIDTHS, VisualEvidenceFailure, collect_visuals, frame_heights, private_png


SIGNATURE = b"\x89PNG\r\n\x1a\n"


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)


def header(width, height, *, depth=8, color=2, compression=0, filtering=0, interlace=0):
    return chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, compression, filtering, interlace))


def png(width, height, *, raw=None, compressed=None, color=2):
    if compressed is None:
        if raw is None:
            raw = (b"\0" + b"\0" * width * (3 if color == 2 else 4)) * height
        compressed = zlib.compress(raw)
    return SIGNATURE + header(width, height, color=color) + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")


class VisualEvidenceTests(unittest.TestCase):
    def assert_invalid_png(self, data, width=320, height=900):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / "private-name.png"
            path.write_bytes(data)
            path.chmod(0o600)
            with self.assertRaises(VisualEvidenceFailure) as failure:
                private_png(path, width, height)
            self.assertEqual(str(failure.exception), "visual-png")

    def fixture(self, root, complete=True):
        for width in WIDTHS if complete else (320,):
            for pointer in POINTERS if complete else ("fine",):
                directory = root / f"{width}-{pointer}"
                directory.mkdir(mode=0o700)
                for phase, height in (frame_heights(width) if complete else {"choose.png": 900}).items():
                    path = directory / phase
                    path.write_bytes(png(width, height))
                    path.chmod(0o600)

    def test_original_thirty_and_linked_and_short_frames_are_required_on_pass(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            self.fixture(root)
            selected, refused = collect_visuals(root, require_complete=True)
            self.assertEqual(sum(name.split("/")[1] in ("choose.png", "all-openapi-yaml.png", "save.png") for name, _ in selected), 30)
            self.assertEqual(len(selected), 48)
            self.assertEqual({name for name, _ in selected}, EXPECTED)
            self.assertFalse(any(refused.values()))
            (root / "736-fine/save.png").unlink()
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-coverage"):
                collect_visuals(root, require_complete=True)

    def test_failed_run_preserves_only_valid_partial_frames(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            self.fixture(root, complete=False)
            selected, refused = collect_visuals(root, require_complete=False)
            self.assertEqual([name for name, _ in selected], ["320-fine/choose.png"])
            self.assertEqual(refused["missing"], 47)
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-coverage"):
                collect_visuals(root, require_complete=True)

    def test_wrong_dimensions_crc_and_unsafe_file_fail_without_projecting_paths(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / "private-name.png"
            path.write_bytes(png(320, 450))
            path.chmod(0o600)
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-dimensions"):
                private_png(path, 320, 900)
            data = bytearray(png(320, 900)); data[-1] ^= 1
            path.write_bytes(data)
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-png"):
                private_png(path, 320, 900)
            path.write_bytes(png(320, 900)); path.chmod(0o644)
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-file-admission"):
                private_png(path, 320, 900)
            link = path.with_name("linked.png"); os.symlink(path, link)
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-file-admission"):
                private_png(link, 320, 900)

    def test_empty_or_invalid_idat_is_not_reviewable_evidence(self):
        for compressed in (b"", b"not-a-zlib-stream", zlib.compress(b"")):
            with self.subTest(stream=compressed):
                self.assert_invalid_png(png(320, 900, compressed=compressed))

    def test_truncated_or_trailing_zlib_data_is_rejected(self):
        compressed = zlib.compress((b"\0" + b"\0" * 320 * 3) * 900)
        for damaged in (compressed[:-1], compressed[:-4], compressed + b"trailing", compressed + zlib.compress(b"")):
            with self.subTest(size=len(damaged)):
                self.assert_invalid_png(png(320, 900, compressed=damaged))

    def test_scanlines_need_exact_pixel_byte_count(self):
        raw = (b"\0" + b"\0" * 320 * 3) * 900
        for damaged in (raw[:-1], raw + b"\0", raw + b"\0" * (8 * 1024 * 1024)):
            with self.subTest(size=len(damaged)):
                self.assert_invalid_png(png(320, 900, raw=damaged))

    def test_invalid_filter_at_any_row_is_rejected(self):
        raw = bytearray((b"\0" + b"\0" * 320 * 3) * 900)
        for row, invalid_filter in ((0, 5), (450, 255), (899, 6)):
            damaged = raw.copy()
            damaged[row * (1 + 320 * 3)] = invalid_filter
            with self.subTest(row=row):
                self.assert_invalid_png(png(320, 900, raw=damaged))

    def test_rgb_and_rgba_filters_cross_bounded_inflate_and_idat_boundaries(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / "frame.png"
            for color, channels in ((2, 3), (6, 4)):
                # Every filter is legal; pixel bytes deliberately exceed filter values.
                raw = b"".join(bytes((row % 5,)) + bytes((17, 99, 250, 201)[:channels]) * 3 for row in range(10))
                compressed = zlib.compress(raw)
                data = (SIGNATURE + header(3, 10, color=color)
                        + b"".join(chunk(b"IDAT", compressed[index:index + 3]) for index in range(0, len(compressed), 3))
                        + chunk(b"IEND", b""))
                path.write_bytes(data)
                path.chmod(0o600)
                with self.subTest(color=color), patch("tools.qa.export_visual_evidence.INFLATE_BLOCK", 7):
                    self.assertEqual(private_png(path, 3, 10), data)

    def test_unsupported_header_encodings_are_rejected(self):
        for encoding in ({"depth": 16}, {"color": 0}, {"color": 3}, {"compression": 1},
                         {"filtering": 1}, {"interlace": 1}):
            data = SIGNATURE + header(320, 900, **encoding) + chunk(b"IDAT", b"") + chunk(b"IEND", b"")
            with self.subTest(encoding=encoding):
                self.assert_invalid_png(data)

    def test_dimension_bound_applies_before_decompression(self):
        for width, height in ((0, 900), (320, 0), (1440, 1201), (0xffffffff, 0xffffffff)):
            with self.subTest(width=width, height=height):
                self.assert_invalid_png(png(width, height, compressed=b""), width, height)

    def test_chunk_order_truncation_and_trailing_file_data_are_rejected(self):
        valid = png(320, 900)
        image_data = chunk(b"IDAT", zlib.compress((b"\0" + b"\0" * 320 * 3) * 900))
        ihdr, end = header(320, 900), chunk(b"IEND", b"")
        for damaged in (valid[:-1], valid + b"trailing", valid + end,
                        SIGNATURE + ihdr + ihdr + image_data + end,
                        SIGNATURE + image_data + ihdr + end,
                        SIGNATURE + ihdr + end,
                        SIGNATURE + ihdr + image_data,
                        SIGNATURE + ihdr + image_data + chunk(b"IEND", b"extra"),
                        SIGNATURE + ihdr + chunk(b"PLTE", b"\0\0\0") + image_data + end,
                        SIGNATURE + ihdr + image_data + chunk(b"tEXt", b"key\0value") + image_data + end):
            with self.subTest(size=len(damaged)):
                self.assert_invalid_png(damaged)

    def test_incorrect_idat_crc_is_rejected(self):
        data = bytearray(png(320, 900))
        data[len(SIGNATURE) + len(header(320, 900)) + 8] ^= 1
        self.assert_invalid_png(data)

    def test_oversize_file_is_refused_before_reading(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / "frame.png"
            with path.open("wb") as stream:
                stream.truncate(MAX_PNG + 1)
            path.chmod(0o600)
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-file-admission"):
                private_png(path, 320, 900)

    def test_invalid_pixel_stream_prevents_complete_visual_collection(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / "320-fine/choose.png").write_bytes(png(320, 900, compressed=b""))
            selected, refused = collect_visuals(root, require_complete=False)
            self.assertEqual(len(selected), 47)
            self.assertEqual(refused, {"missing": 0, "unsafe": 0, "invalid": 1})
            with self.assertRaisesRegex(VisualEvidenceFailure, "visual-coverage"):
                collect_visuals(root, require_complete=True)
