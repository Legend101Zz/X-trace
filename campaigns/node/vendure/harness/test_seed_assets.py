"""Synthetic archive failure cases; not a real Vendure preparation receipt."""
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

import seed_assets


class SeedAssets(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "harness").mkdir()
        patch = mock.patch.object(seed_assets, "HERE", self.root / "harness")
        patch.start()
        self.addCleanup(patch.stop)

    def archive(self, extra=()):
        archive = self.root / "create.tgz"
        with tarfile.open(archive, "w:gz") as stream:
            for name, data in [("initial-data.json", b"{}"), ("products.csv", b"name\nfixture"), ("images/a.png", b"fixture"), *extra]:
                member = tarfile.TarInfo("package/assets/" + name)
                member.size = len(data)
                stream.addfile(member, io.BytesIO(data))
        self.pin(archive)
        return archive

    def pin(self, archive):
        value = {"starter": {"package": {"tarballSha256": hashlib.sha256(archive.read_bytes()).hexdigest()}}}
        (self.root / "campaign.json").write_text(json.dumps(value))

    def test_retention_requires_a_fresh_regular_destination_and_preserves_its_bytes(self):
        archive = self.archive()
        target = self.root / "retained.tgz"
        seed_assets.retain(archive, target)
        self.assertEqual(target.read_bytes(), archive.read_bytes())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        target.write_bytes(b"previous archive")
        with self.assertRaises(FileExistsError):
            seed_assets.retain(archive, target)
        self.assertEqual(target.read_bytes(), b"previous archive")
        linked = self.root / "linked.tgz"
        linked.symlink_to(target)
        with self.assertRaises(FileExistsError):
            seed_assets.retain(archive, linked)
        self.assertEqual(target.read_bytes(), b"previous archive")

    def test_wrong_source_pin_leaves_no_retained_archive(self):
        archive = self.archive()
        archive.write_bytes(b"changed")
        target = self.root / "retained.tgz"
        with self.assertRaises(ValueError):
            seed_assets.retain(archive, target)
        self.assertFalse(target.exists())

    def test_exact_regular_inputs_are_verified_with_hashes_only(self):
        archive, target = self.archive(), self.root / "assets"
        seed_assets.prepare(archive, target)
        result = seed_assets.verify(archive, target)
        self.assertEqual(result["files"], 3)
        self.assertNotIn("products.csv", json.dumps(result))
        self.assertNotIn("fixture", json.dumps(result))

    def test_changed_missing_extra_and_linked_inputs_fail(self):
        archive, target = self.archive(), self.root / "assets"
        seed_assets.prepare(archive, target)
        product = target / "products.csv"
        product.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            seed_assets.verify(archive, target)
        product.unlink()
        with self.assertRaises(ValueError):
            seed_assets.verify(archive, target)
        product.write_bytes(b"name\nfixture")
        (target / "extra").write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            seed_assets.verify(archive, target)
        (target / "extra").unlink()
        product.unlink()
        product.symlink_to(target / "initial-data.json")
        with self.assertRaises(ValueError):
            seed_assets.verify(archive, target)

    def test_changed_archive_fails_before_extraction(self):
        archive = self.archive()
        archive.write_bytes(b"untrusted tarball")
        target = self.root / "assets"
        with self.assertRaises(ValueError):
            seed_assets.prepare(archive, target)
        self.assertFalse(target.exists())

    def test_unsafe_and_duplicate_archive_names_fail(self):
        for name in ("../escaped", "images/../../escaped", "products.csv"):
            with self.subTest(name=name):
                archive = self.archive(((name, b"unexpected"),))
                with self.assertRaises(ValueError):
                    seed_assets.archive_inputs(archive)
        self.assertFalse((self.root / "escaped").exists())

    def test_links_in_archive_and_existing_destination_are_not_followed(self):
        archive = self.archive()
        with tarfile.open(archive, "w:gz") as stream:
            member = tarfile.TarInfo("package/assets/images/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../outside"
            stream.addfile(member)
        self.pin(archive)
        with self.assertRaises(ValueError):
            seed_assets.archive_inputs(archive)
        archive = self.archive()
        target = self.root / "assets"
        target.mkdir()
        with self.assertRaises(FileExistsError):
            seed_assets.prepare(archive, target)
