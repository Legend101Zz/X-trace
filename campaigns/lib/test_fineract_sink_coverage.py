"""Hosted regression cases for complete, bounded private compressed scans."""
import gzip
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

import installed_java
from private_sinks import AdmittedSinks, CompressionCoverageError, _zstd_bounded
from tools.qa import canary


def archive(entries, *, compression=zipfile.ZIP_DEFLATED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as stream:
        for name, data in entries:
            stream.writestr(name, data)
    return output.getvalue()


class CompressedSinkCoverage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "run"
        self.root.mkdir(mode=0o700)
        self.values = canary.make_canaries()
        # System temporary ancestors are outside this unit fixture's scope;
        # file ownership, modes, identity and post-scan inventory stay real.
        self.admission = mock.patch.object(installed_java, "private_dir", side_effect=lambda p: Path(p).absolute())
        self.admission.start()
        self.sinks = AdmittedSinks(self.root)

    def tearDown(self):
        self.admission.stop()
        self.temp.cleanup()

    def scan(self, data):
        path = self.root / "sink.bin"
        with path.open("wb") as stream:
            os.chmod(path, 0o600)
            stream.write(data)
        return self.sinks.scan([path], self.values)

    def assert_gap(self, data, reason=None):
        projection, private = self.scan(data)
        self.assertEqual(projection["status"], "scan-error")
        self.assertFalse(private["scanner"]["clean"])
        self.assertEqual(private["scanner"]["uncovered"], [dict(**{"class": "sink"}, need=1, have=0)])
        self.assertEqual(len(private["scanner"]["compressionGaps"]), 1)
        if reason is not None:
            self.assertEqual(private["scanner"]["compressionGaps"][0]["reason"], reason)

    def test_complete_clean_containers_and_unframed_file_pass(self):
        for data in (b"ordinary clean bytes", gzip.compress(b"clean"), zlib.compress(b"clean"),
                     archive([("inner.txt", b"clean")]), archive([]),
                     b"executable preamble" + archive([("inner.txt", b"clean")]),
                     gzip.compress(zlib.compress(b"clean"))):
            with self.subTest(container=data[:4]):
                projection, private = self.scan(data)
                self.assertEqual(projection["status"], "passed")
                self.assertTrue(private["scanner"]["clean"])
                self.assertEqual(private["scanner"]["compressionGaps"], [])

    def test_malformed_and_truncated_recognized_formats_are_uncovered(self):
        for data in (b"\x1f\x8bnot-a-gzip", gzip.compress(b"clean")[:-1],
                     b"\x78\x9cnot-a-zlib", zlib.compress(b"clean")[:-1],
                     b"PK\x03\x04not-a-zip", archive([("inner", b"clean")])[:-10]):
            with self.subTest(container=data[:4]):
                self.assert_gap(data, "invalid-container")

    def test_bad_checksums_are_not_covered(self):
        for data in (gzip.compress(b"clean"), zlib.compress(b"clean")):
            with self.subTest(container=data[:4]):
                self.assert_gap(data[:-1] + bytes((data[-1] ^ 0xff,)), "invalid-container")
        data = bytearray(archive([("inner", b"clean")], compression=zipfile.ZIP_STORED))
        offset = data.index(b"clean")
        data[offset] ^= 0xff
        self.assert_gap(bytes(data), "invalid-container")

    def test_expansion_limit_is_not_a_clean_truncated_scan(self):
        for data in (gzip.compress(b"x" * 33), zlib.compress(b"x" * 33), archive([("inner", b"x" * 33)])):
            with self.subTest(container=data[:4]), mock.patch.object(canary, "MAX_INFLATE", 32):
                self.assert_gap(data, "inflate-bound")

    def test_exact_expansion_limit_remains_covered(self):
        for data in (gzip.compress(b"x" * 32), zlib.compress(b"x" * 32), archive([("inner", b"x" * 32)])):
            with self.subTest(container=data[:4]), mock.patch.object(canary, "MAX_INFLATE", 32):
                self.assertEqual(self.scan(data)[0]["status"], "passed")

    def test_zip_member_total_and_nested_expansion_share_budget(self):
        data = archive([("first", b"x" * 20), ("second", b"x" * 20)])
        with mock.patch.object(canary, "MAX_INFLATE", 32):
            self.assert_gap(data, "inflate-bound")
        inner = gzip.compress(b"x" * 24)
        with mock.patch.object(canary, "MAX_INFLATE", len(inner) + 23):
            self.assert_gap(gzip.compress(inner), "inflate-bound")

    def test_zip_entry_bound_is_not_silently_skipped(self):
        data = archive([("first", b"clean"), ("second", b"clean")])
        with mock.patch("private_sinks.MAX_FILES", 1):
            self.assert_gap(data, "member-bound")

    def test_compressed_leaf_at_original_depth_limit_is_uncovered(self):
        data = gzip.compress(zlib.compress(archive([("inner", b"clean")])))
        self.assert_gap(data, "depth-bound")

    def test_zlib_trailing_stream_or_bytes_cannot_hide_content(self):
        for suffix in (b"trailing bytes", zlib.compress(self.values["query-token"].encode())):
            self.assert_gap(zlib.compress(b"clean") + suffix, "invalid-container")

    def test_gzip_concatenated_members_are_all_scanned(self):
        projection, private = self.scan(gzip.compress(b"clean") + gzip.compress(self.values["query-token"].encode()))
        self.assertEqual(projection["status"], "failed")
        self.assertTrue(any(row["canary"] == "query-token" for row in private["scanner"]["hits"]))

    def test_framed_zlib_headers_beyond_shared_scanner_subset_are_scanned(self):
        encoder = zlib.compressobj(wbits=9)
        data = encoder.compress(self.values["query-token"].encode()) + encoder.flush()
        self.assertNotIn(data[:2], (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"))
        self.assertEqual(self.scan(data)[0]["status"], "failed")

    def test_canaries_in_containers_member_names_and_nested_payloads_fail(self):
        secret = self.values["query-token"].encode()
        for data in (gzip.compress(secret), zlib.compress(secret), archive([("inner", secret)]),
                     archive([(secret.decode(), b"clean")]), archive([("inner", gzip.compress(secret))]),
                     b"preamble" + archive([("inner", secret)])):
            with self.subTest(container=data[:4]):
                projection, private = self.scan(data)
                self.assertEqual(projection["status"], "failed")
                self.assertTrue(any(row["canary"] == "query-token" for row in private["scanner"]["hits"]))

    def test_prior_observed_hit_survives_a_later_zip_coverage_gap(self):
        data = archive([("first", self.values["query-token"].encode()), ("later", b"x" * 100)])
        with mock.patch.object(canary, "MAX_INFLATE", 80):
            projection, private = self.scan(data)
        self.assertEqual(projection["status"], "failed")
        self.assertFalse(private["scanner"]["clean"])
        self.assertTrue(private["scanner"]["uncovered"])
        self.assertTrue(any(row["canary"] == "query-token" for row in private["scanner"]["hits"]))

    def test_zstd_decoder_unavailable_is_uncovered(self):
        with mock.patch("private_sinks.shutil.which", return_value=None):
            self.assert_gap(canary.ZSTD_MAGIC + b"frame", "decoder-unavailable")
            self.assert_gap(b"\x50\x2a\x4d\x18\x00\x00\x00\x00", "decoder-unavailable")

    def test_zstd_never_uses_unbounded_shared_decoder(self):
        with mock.patch("private_sinks._zstd_bounded", return_value=b"clean") as decoder, \
                mock.patch.object(canary, "zstd_decode", side_effect=AssertionError("unbounded decoder reached")):
            self.assertEqual(self.scan(canary.ZSTD_MAGIC + b"frame")[0]["status"], "passed")
        decoder.assert_called_once_with(canary.ZSTD_MAGIC + b"frame", canary.MAX_INFLATE)

    def test_real_zstd_frames_are_decoded_or_explicitly_uncovered(self):
        def frame(body):
            self.assertLess(len(body), 256)
            return canary.ZSTD_MAGIC + bytes((0x20, len(body))) + ((len(body) << 3) | 1).to_bytes(3, "little") + body

        clean = frame(b"clean")
        secret = frame(self.values["query-token"].encode())
        if shutil.which("zstd") is None:
            self.assert_gap(clean, "decoder-unavailable")
            self.assert_gap(secret, "decoder-unavailable")
        else:
            self.assertEqual(self.scan(clean)[0]["status"], "passed")
            self.assertEqual(self.scan(clean + secret)[0]["status"], "failed")
            self.assert_gap(clean[:-1], "invalid-container")
            with mock.patch.object(canary, "MAX_INFLATE", 4):
                self.assert_gap(clean, "inflate-bound")

    def decoder_fixture(self, body):
        path = self.root / "decoder"
        path.write_text("#!" + sys.executable + "\n" + body + "\n")
        path.chmod(0o700)
        return mock.patch("private_sinks.shutil.which", return_value=str(path))

    def test_owned_decoder_drains_output_while_writing_input(self):
        body = "import os\nwhile True:\n chunk = os.read(0, 4096)\n if not chunk: break\n os.write(1, chunk)"
        payload = b"x" * (512 << 10)
        with self.decoder_fixture(body):
            self.assertEqual(_zstd_bounded(payload, len(payload)), payload)

    def test_owned_decoder_overflow_and_nonzero_exit_are_gaps(self):
        body = "import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'x' * 33)"
        with self.decoder_fixture(body):
            with self.assertRaisesRegex(CompressionCoverageError, "inflate-bound"):
                _zstd_bounded(b"input", 32)
        body = "import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'clean')\nsys.exit(2)"
        with self.decoder_fixture(body):
            with self.assertRaisesRegex(CompressionCoverageError, "invalid-container"):
                _zstd_bounded(b"input", 32)

    def test_owned_decoder_timeout_is_a_gap_and_child_is_reaped(self):
        children = []
        start = subprocess.Popen

        def capture(*args, **kwargs):
            child = start(*args, **kwargs)
            children.append(child)
            return child

        with self.decoder_fixture("import sys\nsys.stdin.buffer.read()"), \
                mock.patch("private_sinks.subprocess.Popen", side_effect=capture), \
                mock.patch("private_sinks.time.monotonic", side_effect=(0, 61)):
            with self.assertRaisesRegex(CompressionCoverageError, "decoder-timeout"):
                _zstd_bounded(b"input", 32)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())


if __name__ == "__main__":
    unittest.main()
