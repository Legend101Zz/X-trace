"""Failure/readiness regressions; only the hosted real driver proves capture."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "java/jhipster/harness/focused_fixture.py"
SPEC = importlib.util.spec_from_file_location("jhipster_focused_fixture", PATH)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FocusedFixture(unittest.TestCase):
    def test_owned_bound_port_signal_is_saved_privately_without_readiness_http(self):
        process = mock.Mock(stdout=io.BytesIO(b"Tomcat started on port 12345 (http)\n"))
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(fixture.xcamp, "http_request") as http:
            log = Path(tmp) / "owned.stdout"
            port = fixture.wait_port(process, log, fixture.time.monotonic() + 1)
            self.assertEqual(port, 12345)
            self.assertEqual(log.read_bytes(), b"Tomcat started on port 12345 (http)\n")
        http.assert_not_called()

    def test_early_process_end_or_missing_startup_signal_is_not_ready(self):
        for content, code in ((b"private log without a bound port\n", None),
                              (b"Tomcat started on port 12345 (http)\n", 1)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                process = mock.Mock(stdout=io.BytesIO(content))
                process.poll.return_value = code
                with self.assertRaises(ValueError):
                    fixture.wait_port(process, Path(tmp) / "owned.stdout", fixture.time.monotonic() + 1)

    def test_api_read_failure_is_terminal_and_clears_live_deadline(self):
        client = mock.Mock()
        fail = {"ok": False, "details": {}, "reason": "private response and path"}
        with mock.patch.object(fixture.xinstr, "collect_api", return_value=fail) as collect:
            with self.assertRaises(ValueError):
                fixture.read_until(client, Path("unused"), lambda api: True, fixture.time.monotonic() + 1)
        self.assertEqual(collect.call_count, 1)
        self.assertIsNone(client.deadline)

    def test_admission_failure_publishes_only_fixed_unreached_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / "public"
            private = "private-root-token"
            with mock.patch.object(fixture.installed, "prepare_root", side_effect=ValueError(private)), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                code = fixture.main(["--private-root", str(root / private), "--archive", str(root / private),
                                     "--source-sha", private, "--package-sha256", private,
                                     "--java", str(root / private), "--fixture", str(root / private),
                                     "--public-out", str(public)])
            raw = (public / "summary.json").read_text()
            summary = json.loads(raw)
            self.assertEqual(code, 1)
            self.assertEqual(summary["status"], "failed")
            self.assertEqual(set(summary["checks"].values()), {"unreached"})
            self.assertIsNone(summary["inventory"])
            self.assertIsNone(summary["cli"])
            self.assertNotIn(private, raw + output.getvalue())
            self.assertNotIn(str(root), raw + output.getvalue())


if __name__ == "__main__":
    unittest.main()
