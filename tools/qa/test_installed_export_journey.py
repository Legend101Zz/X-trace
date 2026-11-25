"""Judge regressions only; these fixtures are not installed-product evidence."""
from copy import deepcopy
import io
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installed_export_journey as journey  # noqa: E402


class DownloadJudgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "cli"
        self.directory.mkdir()
        self.payload = b"abc"
        (self.directory / "all.sh").write_bytes(self.payload)
        self.download = self.root / "download"
        self.cli = {"revisionId": "pinned", "revisionOrdinal": 1, "contentHash": "a" * 64,
                    "operationCount": 1, "written": True, "preview": False, "omissions": [],
                    "files": [{"path": "all.sh", "bytes": len(self.payload), "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"}]}
        self.preview = {"schemaVersion": 1, "revisionId": "pinned", "revisionOrdinal": 1,
                        "approval": {"revisionId": "pinned", "digest": "c" * 64}, "contentHash": "a" * 64,
                        "emittedOperations": 1, "totalBytes": len(self.payload), "request": {"format": "curl"}, "omissions": [],
                        "files": [{"name": "all.sh", "recipeOrdinal": None, "bytes": len(self.payload), "mode": 0o644, "blake3": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"}]}
        self.zip()

    def zip(self, names=("all.sh",), payload=None, mode=stat.S_IFREG | 0o644):
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w") as archive:
            for name in names:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, self.payload if payload is None else payload)
        self.download.write_bytes(result.getvalue())

    def judge(self):
        return journey.judge_download(self.preview, self.cli, self.directory, self.download)

    def test_host_blake3_known_vectors(self):
        self.assertEqual(journey.blake3_bytes(b""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        self.assertEqual(journey.blake3_bytes(b"abc"), self.cli["files"][0]["blake3"])

    def test_matching_fraudulent_metadata_fails(self):
        self.cli["files"][0]["blake3"] = "b" * 64
        self.preview["files"][0]["blake3"] = "b" * 64
        with self.assertRaisesRegex(journey.JourneyFailure, "file-byte-digest"):
            self.judge()

    def test_same_total_different_omission_reason_fails(self):
        self.cli["omissions"] = [{"operationId": "", "what": "request_body", "reason": "no_body_example"}]
        self.preview["omissions"] = [{"format": None, "kind": "request_body", "reason": "secret_shaped", "count": 1}]
        with self.assertRaisesRegex(journey.JourneyFailure, "omission-group-parity"):
            self.judge()

    def test_bundle_omission_normalization(self):
        groups = journey.omission_groups([
            {"operationId": "one", "what": "curl:param:private", "reason": "duplicate_method_path_of:private"},
            {"operationId": "", "what": "future", "reason": "future"},
        ], "bundle")
        self.assertEqual(groups, {("curl", "parameters", "duplicate_method_path"): 1, (None, "other", "other"): 1})

    def test_exact_logical_zip_passes(self):
        self.assertEqual(self.judge(), 1)

    def test_same_size_corruption_fails(self):
        self.zip(payload=b"X" * len(self.payload))
        with self.assertRaisesRegex(journey.JourneyFailure, "zip-bytes"):
            self.judge()

    def test_extra_member_fails(self):
        self.zip(names=("all.sh", "extra.sh"))
        with self.assertRaisesRegex(journey.JourneyFailure, "zip-membership"):
            self.judge()

    def test_executable_or_symlink_mode_fails(self):
        for mode in (stat.S_IFREG | 0o755, stat.S_IFLNK | 0o644):
            with self.subTest(mode=mode):
                self.zip(mode=mode)
                with self.assertRaisesRegex(journey.JourneyFailure, "zip-mode"):
                    self.judge()

    def test_wrong_revision_or_digest_fails(self):
        for field, replacement, reason in (("revisionId", "other", "revision-parity"), ("contentHash", "d" * 64, "digest-parity")):
            with self.subTest(field=field):
                altered = deepcopy(self.preview)
                altered[field] = replacement
                with self.assertRaisesRegex(journey.JourneyFailure, reason):
                    journey.judge_download(altered, self.cli, self.directory, self.download)

    def test_preview_metadata_must_account_for_every_file(self):
        self.preview["files"][0]["blake3"] = "e" * 64
        with self.assertRaisesRegex(journey.JourneyFailure, "file-digest-parity"):
            self.judge()

    def test_unlisted_cli_output_fails(self):
        (self.directory / "stale.json").write_bytes(b"stale")
        with self.assertRaisesRegex(journey.JourneyFailure, "cli-membership"):
            self.judge()

    def test_unaccounted_omission_fails(self):
        self.cli["omissions"] = [{"operationId": "", "what": "request_body", "reason": "no_body_example"}]
        with self.assertRaisesRegex(journey.JourneyFailure, "omission-parity"):
            self.judge()

    def test_raw_download_requires_exact_bytes(self):
        self.preview["request"]["format"] = "openapi"
        self.download.write_bytes(self.payload)
        self.assertEqual(self.judge(), 1)
        self.download.write_bytes(self.payload + b" ")
        with self.assertRaisesRegex(journey.JourneyFailure, "download-bytes"):
            self.judge()

    def test_relative_paths_reject_escape_and_aliases(self):
        for name in ("../secret", "/absolute", "a//b", "./a", "a\\b", "a/../b", "nul\0"):
            with self.subTest(name=name):
                self.assertFalse(journey.safe_member(name))


if __name__ == "__main__":
    unittest.main()
