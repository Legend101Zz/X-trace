import contextlib
import io
import os
import pathlib
import re
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


NO_ACL = lambda path: "-rw-------  1 u  g  2 Jan  1 00:00 x\n"  # noqa: E731


class FakeRunner:
    """Simulates the other user: control paths succeed, every store path is denied (or allowed when asked)."""

    def __init__(self, store, allow=None, err="cat: x: Permission denied", rc=1, control_rc=0, parent=None,
                 parent_rc=0, write_rc=1, write_err=None, mutate=None, wcontrol_rc=0):
        self.store, self.allow, self.err, self.rc, self.control_rc = str(store), allow, err, rc, control_rc
        self.parent = str(parent) if parent is not None else str(pathlib.Path(self.store).parent)
        self.parent_rc = parent_rc
        self.write_rc, self.write_err, self.mutate = write_rc, write_err or err, mutate
        self.wcontrol_rc = wcontrol_rc
        self.calls = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        tool, target = argv[4], argv[-1]
        if tool == "/bin/sh":
            return self.wcontrol_rc, ("" if self.wcontrol_rc == 0 else "sh: Permission denied")
        if tool in ("/usr/bin/touch", "/bin/mv", "/bin/cp"):
            if self.mutate:
                self.mutate()
            return self.write_rc, ("" if self.write_rc == 0 else self.write_err)
        if target == self.parent or target.endswith(ou.CANARY_NAME):
            return self.parent_rc, ""
        if target in ("/usr/bin", "/etc/hosts"):
            return self.control_rc, ""
        if self.allow and target.startswith(self.allow):
            return 0, ""
        assert target.startswith(self.store)
        return self.rc, self.err


def negative(store, runner, **kw):
    return ou.run_negative(store, "xtother", runner, parent=store.parent, acl_reader=NO_ACL, **kw)


class NegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_denied_everywhere_passes_and_counts_targets(self):
        store = make_store(self.base)
        runner = FakeRunner(store)
        n = negative(store, runner)
        # root + projects + p1 + objects (4 listings) + db + object file (2 reads) + 4 write probes
        self.assertEqual(n, 10)
        self.assertEqual(runner.calls[0], ["sudo", "-n", "-u", "xtother", "/bin/ls", "--", "/usr/bin"])
        self.assertEqual(runner.calls[1], ["sudo", "-n", "-u", "xtother", "/bin/cat", "--", "/etc/hosts"])
        self.assertEqual(runner.calls[2], ou.write_control_argv("xtother"))
        self.assertEqual(runner.calls[3], ["sudo", "-n", "-u", "xtother", "/bin/ls", "--", str(self.base)])
        self.assertEqual(runner.calls[4], ["sudo", "-n", "-u", "xtother", "/bin/cat", "--",
                                           str(self.base / ou.CANARY_NAME)])
        self.assertEqual(len(runner.calls), 5 + 10)
        self.assertTrue(all(c[:4] == ["sudo", "-n", "-u", "xtother"] for c in runner.calls))
        self.assertEqual((self.base / ou.CANARY_NAME).stat().st_mode & 0o777, 0o644)

    def test_parent_positive_control_must_pass(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "parent-not-traversable"):
            negative(store, FakeRunner(store, parent_rc=1))

    def test_layout_must_be_parent_and_store(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "layout-unreachable"):
            ou.run_negative(store, "xtother", FakeRunner(store), parent=None, acl_reader=NO_ACL)
        with self.assertRaisesRegex(ou.CheckError, "layout-unreachable"):
            ou.run_negative(store, "xtother", FakeRunner(store), parent=self.base / "other", acl_reader=NO_ACL)

    def test_acl_allow_entry_fails_with_fixed_phrase(self):
        store = make_store(self.base)
        bad = lambda path: "-rw-------+ 1 u g 2 Jan 1 x\n 0: user:other allow read\n"  # noqa: E731
        with self.assertRaisesRegex(ou.CheckError, "^store-acl-allow$"):
            ou.run_negative(store, "xtother", FakeRunner(store), parent=self.base, acl_reader=bad)
        deny_only = lambda path: "-rw-------+ 1 u g 2 Jan 1 x\n 0: group:everyone deny delete\n"  # noqa: E731
        ou.run_negative(store, "xtother", FakeRunner(store), parent=self.base, acl_reader=deny_only)

    def test_acl_reader_errors_are_fixed_phrases(self):
        store = make_store(self.base)

        def boom(path):
            raise ou.CheckError("store-acl-unreadable")
        with self.assertRaisesRegex(ou.CheckError, "store-acl-unreadable"):
            ou.run_negative(store, "xtother", FakeRunner(store), parent=self.base, acl_reader=boom)

    def test_write_probes_cover_create_rename_and_overwrite(self):
        store = make_store(self.base)
        runner = FakeRunner(store)
        negative(store, runner)
        writes = [c[4:] for c in runner.calls if c[4] in ("/usr/bin/touch", "/bin/mv", "/bin/cp")]
        db = str(store / "projects" / "p1" / "metadata.sqlite3")
        self.assertIn(["/usr/bin/touch", "--", str(store / ".xtrace-probe-new")], writes)
        self.assertIn(["/usr/bin/touch", "--", str(store / "projects" / "p1" / ".xtrace-probe-new")], writes)
        self.assertIn(["/bin/mv", "-f", "--", db, db + ".xtrace-probe-moved"], writes)
        self.assertIn(["/bin/cp", "-f", "--", "/etc/hosts", db], writes)

    def test_successful_write_is_a_failure(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "other-user-write-allowed"):
            negative(store, FakeRunner(store, write_rc=0))

    def test_side_effect_after_probes_fails(self):
        store = make_store(self.base)
        db = store / "projects" / "p1" / "metadata.sqlite3"

        def mutate():
            db.write_bytes(b"changed-content")
        with self.assertRaisesRegex(ou.CheckError, "store-modified"):
            negative(store, FakeRunner(store, mutate=mutate))
        base2 = self.base / "b2"
        base2.mkdir()
        store2 = make_store(base2)

        def create():
            (store2 / "new").write_bytes(b"x")
            os.chmod(store2 / "new", 0o600)
        with self.assertRaisesRegex(ou.CheckError, "store-modified"):
            negative(store2, FakeRunner(store2, mutate=create))

    def test_eperm_is_inconclusive_not_a_pass(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "probe-inconclusive"):
            negative(store, FakeRunner(store, err="ls: x: Operation not permitted"))
        with self.assertRaisesRegex(ou.CheckError, "probe-inconclusive"):
            negative(store, FakeRunner(store, write_err="touch: x: Operation not permitted"))

    def test_cap_is_logged_with_counts(self):
        store = make_store(self.base)
        lines = []
        negative(store, FakeRunner(store), log=lines.append)
        self.assertEqual(lines, [])
        ou.MAX_TARGETS = 4
        try:
            negative(store, FakeRunner(store), log=lines.append)
        finally:
            ou.MAX_TARGETS = 40
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^check targets-capped total=6 kept=\d+$")

    def test_missing_store_fails(self):
        with self.assertRaisesRegex(ou.CheckError, "store-missing"):
            ou.run_negative(self.base / "nope", "xtother", FakeRunner(self.base / "nope"), parent=self.base, acl_reader=NO_ACL)

    def test_store_without_database_or_files_fails(self):
        store = make_store(self.base, with_db=False, with_objects=False)
        with self.assertRaisesRegex(ou.CheckError, "store-empty"):
            negative(store, FakeRunner(store))
        (self.base / "x").mkdir()
        store2 = make_store(self.base / "x", with_db=False)
        with self.assertRaisesRegex(ou.CheckError, "store-no-database"):
            negative(store2, FakeRunner(store2))

    def test_open_mode_or_symlink_in_store_fails(self):
        store = make_store(self.base, mode_file=0o644)
        with self.assertRaisesRegex(ou.CheckError, "store-mode-open"):
            negative(store, FakeRunner(store))
        base2 = self.base / "b2"
        base2.mkdir()
        store2 = make_store(base2)
        os.symlink("/etc/hosts", store2 / "link")
        with self.assertRaisesRegex(ou.CheckError, "store-symlink"):
            negative(store2, FakeRunner(store2))

    def test_other_user_reading_is_a_failure(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "other-user-access-allowed"):
            negative(store, FakeRunner(store, allow=str(store)))

    def test_failure_that_is_not_a_permission_denial_fails(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "probe-not-a-permission-denial"):
            negative(store, FakeRunner(store, err="sudo: unknown user xtother"))
        with self.assertRaisesRegex(ou.CheckError, "probe-not-a-permission-denial"):
            negative(store, FakeRunner(store, err="No such file or directory"))

    def test_positive_control_failure_fails(self):
        store = make_store(self.base)
        with self.assertRaisesRegex(ou.CheckError, "control-failed"):
            negative(store, FakeRunner(store, control_rc=1))

    def test_write_control_must_pass_before_write_probes(self):
        store = make_store(self.base)
        runner = FakeRunner(store, wcontrol_rc=1)
        with self.assertRaisesRegex(ou.CheckError, "write-control-failed"):
            negative(store, runner)
        self.assertFalse([c for c in runner.calls if c[4] in ("/usr/bin/touch", "/bin/mv", "/bin/cp")])
        ok = FakeRunner(store)
        negative(store, ok)
        control = [c for c in ok.calls if c[4] == "/bin/sh"]
        self.assertEqual(len(control), 1)
        self.assertIn("mktemp -d", control[0][-1])
        self.assertNotIn(str(store), control[0][-1])

    def test_fifo_in_store_fails(self):
        store = make_store(self.base)
        os.mkfifo(store / "pipe", 0o600)
        with self.assertRaisesRegex(ou.CheckError, "store-special-entry"):
            negative(store, FakeRunner(store))

    def test_first_snapshot_oserror_is_fixed_phrase(self):
        store = make_store(self.base)
        original = ou._snapshot

        def boom(root, db):
            raise OSError(2, "gone", str(db))
        ou._snapshot = boom
        try:
            with self.assertRaisesRegex(ou.CheckError, "^store-unreadable$"):
                negative(store, FakeRunner(store))
        finally:
            ou._snapshot = original

    def test_bad_user_name_rejected(self):
        store = make_store(self.base)
        for bad in ("Root", "a b", "x;rm", "ab", "../x"):
            with self.assertRaisesRegex(ou.CheckError, "bad-user-name"):
                ou.run_negative(store, bad, FakeRunner(store), parent=self.base, acl_reader=NO_ACL)


class MarkerTests(unittest.TestCase):
    def test_marker_roundtrip_and_rejects(self):
        with tempfile.TemporaryDirectory() as d:
            m = pathlib.Path(d) / "sub" / "m"
            self.assertFalse(ou.marker_ok(m))
            self.assertTrue(ou.write_marker(m, 6, "123"))
            self.assertTrue(ou.marker_ok(m))
            self.assertTrue(ou.marker_ok(m, "123"))
            self.assertFalse(ou.marker_ok(m, "124"))
            for bad in ("targets=0", "targets=1", "targets=06"):
                m.write_text(f"other-uid-negative ok {bad} control=ok run=123\n")
                self.assertFalse(ou.marker_ok(m), bad)
            m.write_text("other-uid-negative ok targets=6 control=ok\n")
            self.assertFalse(ou.marker_ok(m))
            m.write_text("anything")
            self.assertFalse(ou.marker_ok(m))

    def run_main(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ou.main(argv)
        return rc, buf.getvalue()

    def test_verify_marker_fails_without_run_id(self):
        with tempfile.TemporaryDirectory() as d:
            m = pathlib.Path(d) / "m"
            ou.write_marker(m, 3, "7")
            saved = os.environ.pop("GITHUB_RUN_ID", None)
            try:
                rc, out = self.run_main(["verify-marker", "--marker", str(m)])
                self.assertEqual((rc, out.strip()), (1, "other-uid verify-marker FAIL run-id-missing"))
                os.environ["GITHUB_RUN_ID"] = "7"
                rc, out = self.run_main(["verify-marker", "--marker", str(m)])
                self.assertEqual((rc, out.strip()), (0, "other-uid verify-marker ok"))
            finally:
                os.environ.pop("GITHUB_RUN_ID", None)
                if saved is not None:
                    os.environ["GITHUB_RUN_ID"] = saved

    def test_verify_marker_fails_when_check_never_ran(self):
        os.environ["GITHUB_RUN_ID"] = "7"
        self.addCleanup(os.environ.pop, "GITHUB_RUN_ID", None)
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.run_main(["verify-marker", "--marker", str(pathlib.Path(d) / "m")])
            self.assertEqual(rc, 1)
            self.assertIn("FAIL", out)
            self.assertNotIn(d, out)

    def test_check_with_missing_store_fails_removes_stale_marker_and_leaks_no_path(self):
        with tempfile.TemporaryDirectory() as d:
            m = pathlib.Path(d) / "m"
            ou.write_marker(m, 3, "7")
            os.environ["GITHUB_RUN_ID"] = "7"
            self.addCleanup(os.environ.pop, "GITHUB_RUN_ID", None)
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

    def test_check_without_run_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            saved = os.environ.pop("GITHUB_RUN_ID", None)
            hosted = ou.is_hosted_runner
            ou.is_hosted_runner = lambda *a, **k: True
            try:
                rc, out = self.run_main(["check", "--store-root", d, "--parent", d, "--user", "xtother",
                                         "--marker", str(pathlib.Path(d) / "m")])
            finally:
                ou.is_hosted_runner = hosted
                if saved is not None:
                    os.environ["GITHUB_RUN_ID"] = saved
            self.assertEqual((rc, out.strip()), (1, "other-uid check FAIL run-id-missing"))

    def test_unwritable_marker_prints_fixed_phrase_only(self):
        with tempfile.TemporaryDirectory() as d:
            blocker = pathlib.Path(d) / "file"
            blocker.write_text("x")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ok = ou.write_marker(blocker / "sub" / "m", 6, "1")
            self.assertFalse(ok)
            self.assertEqual(buf.getvalue().strip(), "other-uid check FAIL marker-unwritable")
            self.assertNotIn(d, buf.getvalue())

    def test_check_success_writes_marker_via_injected_runner(self):
        with tempfile.TemporaryDirectory() as d:
            store = make_store(pathlib.Path(d))
            m = pathlib.Path(d) / "ok.marker"
            original = ou.default_runner
            hosted = ou.is_hosted_runner
            ou.default_runner = FakeRunner(store, parent=d)
            ou.is_hosted_runner = lambda *a, **k: True
            acl = ou.default_acl_reader
            ou.default_acl_reader = NO_ACL
            os.environ["GITHUB_RUN_ID"] = "55"
            self.addCleanup(os.environ.pop, "GITHUB_RUN_ID", None)
            try:
                rc, out = self.run_main(["check", "--store-root", str(store), "--parent", d, "--user", "xtother",
                                         "--marker", str(m)])
            finally:
                ou.default_runner = original
                ou.is_hosted_runner = hosted
                ou.default_acl_reader = acl
            self.assertEqual(rc, 0)
            self.assertTrue(ou.marker_ok(m, "55"))
            self.assertFalse(ou.marker_ok(m, "56"))
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
                rc = ou.main(["create-user", "--user", "xtother", "--created-marker", "/nonexistent/created"])
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
        self.assertEqual(rc, 2)
        self.assertIn("not-a-hosted-macos-runner", buf.getvalue())



class CommandSequenceTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.exists = False
        self.saved = (ou._sh, ou.is_hosted_runner)
        ou.is_hosted_runner = lambda *a, **k: True
        self.tmp = tempfile.TemporaryDirectory()
        self.created = str(pathlib.Path(self.tmp.name) / "created")
        self.saved_run = os.environ.get("GITHUB_RUN_ID")
        os.environ["GITHUB_RUN_ID"] = "99"
        self.addCleanup(self.restore)

    def restore(self):
        ou._sh, ou.is_hosted_runner = self.saved
        self.tmp.cleanup()
        os.environ.pop("GITHUB_RUN_ID", None)
        if self.saved_run is not None:
            os.environ["GITHUB_RUN_ID"] = self.saved_run

    def fake_sh(self, fail_at=None, ids=None):
        def sh(argv):
            self.calls.append(list(argv))
            if argv[:3] == ["dscl", ".", "-read"]:
                return (0, "UniqueID: 7") if self.exists else (56, "")
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
        rc, out = self.run_cmd(["create-user", "--user", "xtother", "--created-marker", self.created])
        self.assertEqual(rc, 0, out)
        sudo = [c[4:] for c in self.calls if c[:2] == ["sudo", "-n"]]
        self.assertEqual(sudo[0], ["-create", "/Groups/xtother"])
        self.assertEqual(sudo[1], ["-create", "/Groups/xtother", "PrimaryGroupID", "7700"])
        self.assertEqual(sudo[2], ["-create", "/Users/xtother"])
        self.assertIn(["-create", "/Users/xtother", "UniqueID", "7700"], sudo)
        self.assertIn(["-create", "/Users/xtother", "PrimaryGroupID", "7700"], sudo)
        self.assertNotIn(["-create", "/Users/xtother", "PrimaryGroupID", "20"], sudo)
        self.assertEqual(len(sudo), 8)

    def test_create_user_refuses_existing_account(self):
        self.fake_sh()
        self.exists = True
        rc, out = self.run_cmd(["create-user", "--user", "xtother", "--created-marker", self.created])
        self.assertEqual((rc, out.strip()), (2, "other-uid create-user FAIL account-exists"))
        self.assertEqual([c for c in self.calls if c[:2] == ["sudo", "-n"]], [])

    def test_create_user_failure_stops_with_fixed_phrase(self):
        self.fake_sh(fail_at=3)
        rc, out = self.run_cmd(["create-user", "--user", "xtother", "--created-marker", self.created])
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "other-uid create-user FAIL dscl")
        self.assertEqual(len([c for c in self.calls if c[:2] == ["sudo", "-n"]]), 3)

    def test_delete_user_refuses_account_not_created_by_this_run(self):
        self.fake_sh()
        rc, out = self.run_cmd(["delete-user", "--user", "xtother", "--created-marker", self.created])
        self.assertEqual((rc, out.strip()), (0, "other-uid delete-user skipped-not-created-by-this-run"))
        pathlib.Path(self.created).write_text("other-uid-created run=98\n")  # another run's marker
        rc, out = self.run_cmd(["delete-user", "--user", "xtother", "--created-marker", self.created])
        self.assertIn("skipped-not-created-by-this-run", out)
        self.assertEqual(self.calls, [])

    def test_create_user_records_marker_then_delete_consumes_it(self):
        self.fake_sh()
        self.assertEqual(self.run_cmd(["create-user", "--user", "xtother", "--created-marker", self.created])[0], 0)
        self.assertEqual(pathlib.Path(self.created).read_text(), "other-uid-created run=99\n")
        self.assertEqual(self.run_cmd(["delete-user", "--user", "xtother", "--created-marker", self.created])[0], 0)
        self.assertFalse(pathlib.Path(self.created).exists())

    def test_create_user_refusal_leaves_no_marker(self):
        self.fake_sh()
        self.exists = True
        self.run_cmd(["create-user", "--user", "xtother", "--created-marker", self.created])
        self.assertFalse(pathlib.Path(self.created).exists())

    def test_delete_user_removes_user_and_group(self):
        self.fake_sh()
        pathlib.Path(self.created).write_text("other-uid-created run=99\n")
        rc, out = self.run_cmd(["delete-user", "--user", "xtother", "--created-marker", self.created])
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


if __name__ == "__main__":
    unittest.main()
