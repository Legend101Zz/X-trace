import base64
import gzip
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import canary  # noqa: E402


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.c = canary.make_canaries()
        self.td = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def scan(self, **locs):
        return canary.run_scan(self.c, {k: [v] for k, v in locs.items()})

    def test_unique_per_kind_and_run(self):
        other = canary.make_canaries()
        self.assertEqual(set(self.c), set(canary.KINDS))
        self.assertEqual(len(set(self.c.values())), len(canary.KINDS))
        self.assertTrue(set(self.c.values()).isdisjoint(other.values()))

    def test_clean_tree_is_clean(self):
        (self.root / "a.txt").write_text("hello\n")
        r = self.scan(store=self.root)
        self.assertTrue(r["clean"])
        self.assertEqual(r["hits"], [])

    def test_absent_location_is_not_clean(self):
        r = self.scan(store=self.root / "missing")
        self.assertFalse(r["clean"])
        self.assertFalse(r["scanned"][0]["present"])

    def test_raw_hit_reports_class_not_value(self):
        (self.root / "seg.bin").write_bytes(b"\0\1" + self.c["query-token"].encode() + b"\2")
        r = self.scan(store=self.root)
        self.assertFalse(r["clean"])
        self.assertEqual({(h["locationClass"], h["canary"]) for h in r["hits"]}, {("store", "query-token")})
        blob = json.dumps(r)
        for v in self.c.values():
            self.assertNotIn(v, blob)

    def test_encodings_found(self):
        v = self.c["json-body-password"].encode()
        cases = {
            "b64": base64.b64encode(b"user:" + v),
            "b64url": base64.urlsafe_b64encode(b"xx" + v),
            "hex": v.hex().encode(),
            "pct": __import__("urllib.parse").parse.quote(v.decode(), safe="").encode(),
        }
        for label, data in cases.items():
            p = self.root / f"{label}.bin"
            p.write_bytes(b"..." + data + b"...")
        r = self.scan(exports=self.root)
        encs = {h["encoding"] for h in r["hits"] if h["canary"] == "json-body-password"}
        # base64 and base64url needles are deduplicated when the alphabets coincide for this value
        self.assertTrue({"hex-lower", "url-percent"} <= encs and bool(encs & {"base64", "base64url"}), encs)

    def test_gzip_member_found(self):
        (self.root / "x.gz").write_bytes(gzip.compress(self.c["env-var"].encode()))
        r = self.scan(store=self.root)
        self.assertTrue(any(h["canary"] == "env-var" for h in r["hits"]))

    def test_zstd_member_is_decoded_or_reported_undecodable(self):
        payload = self.c["json-body-password"].encode()
        frame = None
        try:
            from compression import zstd  # Python 3.14
            frame = zstd.compress(b"x" * 10 + payload)
        except Exception:
            import shutil
            import subprocess
            if shutil.which("zstd"):
                frame = subprocess.run(["zstd", "-c", "-q"], input=b"x" * 10 + payload, capture_output=True).stdout
        if frame is None:  # no encoder here: hand-built raw-block frame (magic, single-segment header, one raw block)
            body = b"x" * 10 + payload
            size = len(body)
            frame = (canary.ZSTD_MAGIC + bytes([0x20 | 0x00, size]) if size < 256 else b"") + \
                (((size << 3) | 1).to_bytes(3, "little") + body if size < 256 else b"")
        (self.root / "o.xtf.zst").write_bytes(frame)
        r = self.scan(store=self.root)
        kinds = {h["canary"] for h in r["hits"]}
        # either the member was opened and the canary found, or the scanner says it could not look: never "clean"
        self.assertFalse(r["clean"])
        self.assertTrue("json-body-password" in kinds or "<undecodable-zstd>" in kinds, kinds)

    def test_file_name_is_scanned(self):
        (self.root / (self.c["query-token"] + ".txt")).write_text("x")
        r = self.scan(store=self.root)
        self.assertFalse(r["clean"])

    def test_cookie_secret_part_alone(self):
        secret = self.c["cookie-header"].split("=", 1)[1]
        (self.root / "log.txt").write_text(f"cookie value {secret}\n")
        r = self.scan(**{"daemon-log": self.root})
        # sixteen hex characters are shorter than the 12-char floor only if the part is short; here it matches
        self.assertTrue(r["hits"], "secret part of a cookie must be found on its own")

    def test_probe_passes(self):
        self.assertEqual(canary.probe(), 0)

    def test_cli_scan_exit_codes_and_no_value_in_output(self):
        cf = self.root / "c.json"
        cf.write_text(json.dumps(self.c))
        d = self.root / "d"
        d.mkdir()
        (d / "f").write_text("clean")
        exe = [sys.executable, "-B", str(pathlib.Path(canary.__file__))]
        ok = subprocess.run([*exe, "scan", "--canaries", str(cf), "--loc", f"store={d}", "--report", str(self.root / "r.json")],
                            capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        (d / "f").write_text(self.c["authorization-header"])
        bad = subprocess.run([*exe, "scan", "--canaries", str(cf), "--loc", f"store={d}", "--report", str(self.root / "r2.json")],
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        for v in self.c.values():
            self.assertNotIn(v, bad.stdout + bad.stderr)
        self.assertIn("CANARY HIT class=store", bad.stdout)


if __name__ == "__main__":
    unittest.main()
