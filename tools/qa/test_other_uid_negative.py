import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.qa import other_uid_negative as ou  # noqa: E402


def make_store(base: pathlib.Path, with_db=True, with_objects=True, mode_file=0o600) -> pathlib.Path:
    store = base / "store"
    store.mkdir(mode=0o700)
    os.chmod(store, 0o700)
    proj = store / "projects" / "p1"
    proj.mkdir(parents=True)
    for d in (store / "projects", proj):
        os.chmod(d, 0o700)
    if with_db:
        (proj / "metadata.sqlite3").write_bytes(b"db")
        os.chmod(proj / "metadata.sqlite3", mode_file)
    if with_objects:
        (proj / "objects").mkdir()
        os.chmod(proj / "objects", 0o700)
        (proj / "objects" / "o1").write_bytes(b"x")
        os.chmod(proj / "objects" / "o1", 0o600)
    return store


class FakeRunner:
    """Simulates the other user: control paths succeed, every store path is denied (or allowed when asked)."""

    def __init__(self, store, allow=None, err="cat: x: Permission denied", rc=1, control_rc=0, parent=None,
                 parent_rc=0):
        self.store, self.allow, self.err, self.rc, self.control_rc = str(store), allow, err, rc, control_rc
        self.parent, self.parent_rc = parent, parent_rc
        self.calls = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        target = argv[-1]
        if self.parent is not None and target == self.parent:
            return self.parent_rc, ""
        if target in ("/usr/bin", "/etc/hosts"):
            return self.control_rc, ""
        if self.allow and target.startswith(self.allow):
            return 0, ""
        assert target.startswith(self.store)
        return self.rc, self.err


class NegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_denied_everywhere_passes_and_counts_targets(self):
        store = make_store(self.base)
        runner = FakeRunner(store)
        n = ou.run_negative(store, "xtother", runner)
        # root + projects + p1 + objects (4 listings) + db + object file (2 reads)
        self.assertEqual(n, 6)
        self.assertEqual(runner.calls[0], ["sudo", "-n", "-u", "xtother", "/bin/ls", "--", "/usr/bin"])
        self.assertEqual(runner.calls[1], ["sudo", "-n", "-u", "xtother", "/bin/cat", "--", "/etc/hosts"])
        self.assertEqual(runner.calls[2], ["sudo", "-n", "-u", "xtother", "/bin/ls", "--", str(store)])
        self.assertEqual(len(runner.calls), 2 + 6)
        self.assertTrue(all(c[:4] == ["sudo", "-n", "-u", "xtother"] for c in runner.calls))

    def test_parent_positive_control_runs_and_must_pass(self):
        store = make_store(self.base)
        runner = FakeRunner(store, parent=str(self.base))
        n = ou.run_negative(store, "xtother", runner, parent=self.base)
        self.assertEqual(n, 6)
        self.assertIn(["sudo", "-n", "-u", "xtother", "/bin/ls", "-ld", "--", str(self.base)], runner.calls)
        with self.assertRaisesRegex(ou.CheckError, "parent-not-traversable"):
            ou.run_negative(store, "xtother", FakeRunner(store, parent=str(self.base), parent_rc=1), parent=self.base)

    def test_missing_store_fails(self):
        with self.assertRaisesRegex(ou.CheckError, "store-missing"):
            ou.run_negative(self.base / "nope", "xtother", FakeRunner(self.base))

    def test_store_without_database_or_files_fails(self):
        store = make_store(self.base, with_db=False, with_objects=False)
        with self.assertRaisesRegex(ou.CheckError, "store-empty"):
            ou.run_negative(store, "xtother", FakeRunner(store))
        (self.base / "x").mkdir()
        store2 = make_store(self.base / "x", with_db=False)
        with self.assertRaisesRegex(ou.CheckError, "store-no-database"):
            ou.run_negative(store2, "xtother", FakeRunner(store2))

    def test_open_mode_or_symlink_in_store_fails(self):
        store = make_store(self.base, mode_file=0o644)
        with self.assertRaisesRegex(ou.CheckError, "store-mode-open"):
            ou.run_negative(store, "xtother", FakeRunner(store))
        base2 = self.base / "b2"
        base2.mkdir()
        store2 = make_store(base2)
        os.symlink("/etc/hosts", store2 / "link")
        with self.assertRaisesRegex(ou.CheckError, "store-symlink"):
            ou.run_negative(store2, "xtother", FakeRunner(store2))

    def test_other_user_reading_is_a_failure(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "other-user-access-allowed"):
            ou.run_negative(store, "xtother", FakeRunner(store, allow=str(store)))

    def test_failure_that_is_not_a_permission_denial_fails(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "probe-not-a-permission-denial"):
            ou.run_negative(store, "xtother", FakeRunner(store, err="sudo: unknown user xtother"))
        with self.assertRaisesRegex(ou.CheckError, "probe-not-a-permission-denial"):
            ou.run_negative(store, "xtother", FakeRunner(store, err="No such file or directory"))

    def test_positive_control_failure_fails(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "control-failed"):
            ou.run_negative(store, "xtother", FakeRunner(store, control_rc=1))

    def test_bad_user_name_rejected(self):
        store = make_store(self.base)
        for bad in ("Root", "a b", "x;rm", "ab", "../x"):
            with self.assertRaisesRegex(ou.CheckError, "bad-user-name"):
                ou.run_negative(store, bad, FakeRunner(store))


class MarkerTests(unittest.TestCase):
    def test_marker_roundtrip_and_rejects(self):
        with tempfile.TemporaryDirectory() as d:
            m = pathlib.Path(d) / "sub" / "m"
            self.assertFalse(ou.marker_ok(m))
            ou.write_marker(m, 6)
            self.assertTrue(ou.marker_ok(m))
            m.write_text("other-uid-negative ok targets=0 control=ok\n")
            self.assertFalse(ou.marker_ok(m))
            m.write_text("anything")
            self.assertFalse(ou.marker_ok(m))

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ou.main(argv)
        return rc, buf.getvalue()

    def test_verify_marker_fails_when_check_never_ran(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.run_main(["verify-marker", "--marker", str(pathlib.Path(d) / "m")])
            self.assertEqual(rc, 1)
            self.assertIn("FAIL", out)
            self.assertNotIn(d, out)

    def test_check_with_missing_store_fails_removes_stale_marker_and_leaks_no_path(self):
        with tempfile.TemporaryDirectory() as d:
            m = pathlib.Path(d) / "m"
            ou.write_marker(m, 3)
            hosted = ou.is_hosted_runner
            ou.is_hosted_runner = lambda *a, **k: True
            try:
                rc, out = self.run_main(["check", "--store-root", str(pathlib.Path(d) / "gone"), "--parent", d,
                                         "--user", "xtother", "--marker", str(m)])
            finally:
                ou.is_hosted_runner = hosted
            self.assertEqual(rc, 1)
            self.assertFalse(m.exists())
            self.assertEqual(out.strip(), "other-uid check FAIL store-missing")
            self.assertNotIn(d, out)

    def test_check_success_writes_marker_via_injected_runner(self):
        with tempfile.TemporaryDirectory() as d:
            store = make_store(pathlib.Path(d))
            m = pathlib.Path(d) / "ok.marker"
            original = ou.default_runner
            hosted = ou.is_hosted_runner
            ou.default_runner = FakeRunner(store, parent=d)
            ou.is_hosted_runner = lambda *a, **k: True
            try:
                rc, out = self.run_main(["check", "--store-root", str(store), "--parent", d, "--user", "xtother",
                                         "--marker", str(m)])
            finally:
                ou.default_runner = original
                ou.is_hosted_runner = hosted
            self.assertEqual(rc, 0)
            self.assertTrue(ou.marker_ok(m))
            self.assertNotIn(d, out)


class UserTests(unittest.TestCase):
    def test_pick_uid_skips_taken(self):
        self.assertEqual(ou.pick_uid([501, 7700, 7701]), 7702)
        self.assertEqual(ou.pick_uid([]), ou.FIRST_FREE_UID)

    def test_hosted_runner_guard(self):
        ok = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        self.assertTrue(ou.is_hosted_runner(ok, "darwin"))
        self.assertFalse(ou.is_hosted_runner(ok, "linux"))
        self.assertFalse(ou.is_hosted_runner({}, "darwin"))
        self.assertFalse(ou.is_hosted_runner({"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}, "darwin"))

    def test_create_user_refuses_off_runner(self):
        buf = io.StringIO()
        saved = {k: os.environ.pop(k, None) for k in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT")}
        try:
            with contextlib.redirect_stdout(buf):
                rc = ou.main(["create-user", "--user", "xtother"])
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
        self.assertEqual(rc, 2)
        self.assertIn("not-a-hosted-macos-runner", buf.getvalue())


if __name__ == "__main__":
    unittest.main()


class CommandSequenceTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.saved = (ou._sh, ou.is_hosted_runner)
        ou.is_hosted_runner = lambda *a, **k: True
        self.addCleanup(self.restore)

    def restore(self):
        ou._sh, ou.is_hosted_runner = self.saved

    def fake_sh(self, fail_at=None, ids=None):
        def sh(argv):
            self.calls.append(list(argv))
            if argv[:2] == ["dscl", "."] and "/Users" in argv:
                return 0, "root 0\nrunner 501\n"
            if argv[:2] == ["dscl", "."] and "/Groups" in argv:
                return 0, "staff 20\nadmin 80\n"
            if argv[:2] == ["id", "-u"]:
                return 0, "7700\n"
            if argv[:2] == ["id", "-g"]:
                return 0, "7700\n"
            if fail_at is not None and len([c for c in self.calls if c[:2] == ["sudo", "-n"]]) == fail_at:
                return 1, ""
            return 0, ""
        ou._sh = sh

    def run_cmd(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ou.main(argv)
        return rc, buf.getvalue()

    def test_create_user_step_order_and_dedicated_group(self):
        self.fake_sh()
        rc, out = self.run_cmd(["create-user", "--user", "xtother"])
        self.assertEqual(rc, 0, out)
        sudo = [c[4:] for c in self.calls if c[:2] == ["sudo", "-n"]]
        self.assertEqual(sudo[0], ["-create", "/Groups/xtother"])
        self.assertEqual(sudo[1], ["-create", "/Groups/xtother", "PrimaryGroupID", "7700"])
        self.assertEqual(sudo[2], ["-create", "/Users/xtother"])
        self.assertIn(["-create", "/Users/xtother", "UniqueID", "7700"], sudo)
        self.assertIn(["-create", "/Users/xtother", "PrimaryGroupID", "7700"], sudo)
        self.assertNotIn(["-create", "/Users/xtother", "PrimaryGroupID", "20"], sudo)
        self.assertEqual(len(sudo), 8)

    def test_create_user_failure_stops_with_fixed_phrase(self):
        self.fake_sh(fail_at=3)
        rc, out = self.run_cmd(["create-user", "--user", "xtother"])
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "other-uid create-user FAIL dscl")
        self.assertEqual(len([c for c in self.calls if c[:2] == ["sudo", "-n"]]), 3)

    def test_delete_user_removes_user_and_group(self):
        self.fake_sh()
        rc, out = self.run_cmd(["delete-user", "--user", "xtother"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "other-uid delete-user ok")
        self.assertEqual([c[4:] for c in self.calls],
                         [["-delete", "/Users/xtother"], ["-delete", "/Groups/xtother"]])

    def test_check_refuses_off_hosted_runner_without_sudo(self):
        ou.is_hosted_runner = lambda *a, **k: False
        self.fake_sh()
        rc, out = self.run_cmd(["check", "--store-root", "/x/s", "--parent", "/x", "--user", "xtother",
                                "--marker", "/x/m"])
        self.assertEqual(rc, 2)
        self.assertEqual(out.strip(), "other-uid check FAIL not-a-hosted-macos-runner")
        self.assertEqual(self.calls, [])
