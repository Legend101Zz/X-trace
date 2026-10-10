import json
import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_purge as cp  # noqa: E402


class T(unittest.TestCase):
    def test_keeps_only_reports_and_a_note_free_summary(self):
        with tempfile.TemporaryDirectory() as td:
            r = pathlib.Path(td)
            (r / "summary.json").write_text(json.dumps({"steps": [{"step": "a", "status": "fail", "note": "SECRET-NOTE"}]}))
            (r / "privacy-canary-report.json").write_text("{}")
            (r / "instrumented-receipt.json").write_text("{}")
            (r / "browser").mkdir()
            (r / "browser" / "s.png").write_text("x")
            removed = cp.purge(r)
            self.assertEqual(sorted(removed), ["browser", "instrumented-receipt.json"])
            self.assertEqual(sorted(p.name for p in r.iterdir()), ["privacy-canary-report.json", "summary.json"])
            text = (r / "summary.json").read_text()
            self.assertNotIn("SECRET-NOTE", text)
            self.assertEqual(json.loads(text)["steps"], [{"step": "a", "status": "fail", "note": ""}])

    def test_unreadable_summary_still_purges(self):
        with tempfile.TemporaryDirectory() as td:
            r = pathlib.Path(td)
            (r / "summary.json").write_text("not json")
            (r / "x.txt").write_text("x")
            cp.purge(r)
            self.assertEqual(json.loads((r / "summary.json").read_text())["steps"], [])
            self.assertFalse((r / "x.txt").exists())


if __name__ == "__main__":
    unittest.main()
