"""The public tree contains reviewed facts and verifiable immutable byte references."""

import argparse
import pathlib
import tempfile
import unittest

from tools.qa import camp_publication as publication, canary


class CampaignPublication(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = pathlib.Path(scratch.name)
        self.private = self.root / "private"
        self.private.mkdir()
        self.public = self.root / "public"
        self.canaries = canary.make_canaries(lambda: "1234567890aabbcc")
        self.args = argparse.Namespace(
            private=self.private, public=self.public, project="petclinic",
            candidate="a" * 40, run_id="1", campaign=self.root / "campaign.json",
            canaries=self.private / "canaries.json", baseline=self.private / "baseline.json",
            instrumented=self.private / "instrumented.json",
        )
        self.summary = self.private / "summary.json"
        publication.write(self.summary, {"project": "petclinic", "steps": [
            {"step": "workload", "status": "pass", "note": self.canaries["authorization-header"]},
        ]})
        publication.write(self.args.campaign, {
            "project": "petclinic", "upstream": {"sha": "b" * 40}, "scenarios": [{"id": "check"}],
        })
        publication.write(self.args.canaries, self.canaries)
        publication.write(self.args.baseline, {"scenarios": [{"id": "check", "passed": True}]})
        publication.write(self.args.instrumented, {"scenarios": [{
            "id": "check", "scenarioChecksPassed": True, "semanticEffectFingerprint": "d" * 64,
            "recordingVerdict": {"passed": True}, "stdout": self.canaries["query-token"],
        }]})
        publication.write(self.private / "privacy-canary-report.json",
                          {"clean": True, "scanned": [{"files": 5}], "hits": [], "uncovered": []})
        (self.private / "package.sha256").write_text("c" * 64 + "\n", encoding="ascii")
        (self.private / "application.log").write_text(self.canaries["query-token"], encoding="ascii")

    def test_success_keeps_frozen_summary_and_exact_named_hashes(self):
        self.assertTrue(publication.publish(self.args))
        receipt = publication.read(self.public / publication.RECEIPT)
        publication.verify_references(self.public, receipt)
        self.assertEqual(receipt["build"]["archiveSha256"], "c" * 64)
        self.assertNotEqual(receipt["artifacts"][0]["sha256"], "c" * 64)
        self.assertEqual(receipt["result"], "passed")
        self.assertTrue(receipt["nonRelease"])
        self.assertTrue(receipt["attestation"]["scenarios"][0]["recordingExpectationsPassed"])
        self.assertFalse((self.public / "application.log").exists())
        self.assertNotIn("stdout", (self.public / "instrumented-receipt.json").read_text())
        self.assertNotIn("note", (self.public / "summary.json").read_text())
        self.assertEqual(publication.read(self.public / "publication.json"),
                         {"receiptGeneration": "succeeded", "finalPrivacyScan": "passed"})
        self.assertEqual(len(publication.read(self.summary)["steps"]), 3)
        for name in ("summary.json", "package.sha256"):
            target = self.public / name
            original = target.read_bytes()
            target.write_bytes(original + b"changed")
            with self.assertRaises(ValueError):
                publication.verify_references(self.public, receipt)
            target.write_bytes(original)

    def test_missing_canaries_yields_fixed_fallback(self):
        self.args.canaries.unlink()
        self.assertFalse(publication.publish(self.args))
        self.assertEqual({p.name for p in self.public.iterdir()}, {"summary.json", "publication.json"})
        self.assertEqual(publication.read(self.public / "publication.json")["finalPrivacyScan"], "missing-canaries")
        self.assertEqual(publication.read(self.summary)["steps"][-1]["status"], "fail")

    def test_canary_hit_cannot_publish_candidate_files(self):
        canary_value = "leaked-campaign-identifier"
        publication.write(self.args.canaries, {"fixture": canary_value})
        publication.write(self.summary, {"project": "petclinic", "steps": [
            {"step": canary_value, "status": "pass"},
        ]})
        self.assertFalse(publication.publish(self.args))
        self.assertFalse((self.public / publication.RECEIPT).exists())
        self.assertNotIn(canary_value, (self.public / "summary.json").read_text())
        self.assertEqual(publication.read(self.public / "publication.json")["finalPrivacyScan"], "failed")

    def test_missing_required_raw_evidence_is_generation_failure(self):
        self.args.instrumented.unlink()
        self.assertFalse(publication.publish(self.args))
        self.assertEqual(publication.read(self.public / "publication.json"),
                         {"receiptGeneration": "failed", "finalPrivacyScan": "unreached"})
