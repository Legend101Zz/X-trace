import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import camp_lifecycle as cl  # noqa: E402


def fake(td: pathlib.Path, body: str) -> str:
    p = td / "xtrace"
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


class T(unittest.TestCase):
    def test_find_pid(self):
        self.assertEqual(cl.find_pid({"ok": True, "data": {"daemon": {"pid": 4242}}}), 4242)
        self.assertIsNone(cl.find_pid({"data": {"pid": 1}}))
        self.assertIsNone(cl.find_pid([]))

    def test_exit_nine_is_not_implemented(self):
        with tempfile.TemporaryDirectory() as d:
            x = fake(pathlib.Path(d), "exit 9\n")
            self.assertEqual(cl.judge(x, d, dict(os.environ))[0], "not-implemented")

    def test_record_without_pid_fails(self):
        with tempfile.TemporaryDirectory() as d:
            x = fake(pathlib.Path(d), 'echo \'{"ok":true}\'\n')
            self.assertEqual(cl.judge(x, d, dict(os.environ))[0], "fail")

    def test_dead_pid_after_record_fails(self):
        with tempfile.TemporaryDirectory() as d:
            x = fake(pathlib.Path(d), 'echo \'{"data":{"pid":2147483000}}\'\n')
            self.assertEqual(cl.judge(x, d, dict(os.environ))[0], "fail")

    def test_full_flow_pass_and_stop_that_leaves_daemon_fails(self):
        with tempfile.TemporaryDirectory() as d:
            td = pathlib.Path(d)
            # a daemon stand-in the fake `stop` ends by pid (the fake knows its own pid file)
            script = (f'case "$1" in record) sleep 30 >/dev/null 2>&1 & echo $! > "{td}/pid"; echo "{{\\"data\\":{{\\"pid\\":$!}}}}";;\n'
                      f'stop) kill $(cat "{td}/pid") 2>/dev/null; sleep 0.3;; esac\n')
            x = fake(td, script)
            st, note = cl.judge(x, d, dict(os.environ))
            self.assertEqual(st, "pass", note)
            stay = fake(td, f'case "$1" in record) sleep 30 >/dev/null 2>&1 & echo $! > "{td}/pid2"; echo "{{\\"data\\":{{\\"pid\\":$!}}}}";; stop) :;; esac\n')
            orig = cl.time.sleep
            cl.time.sleep = lambda s: None
            try:
                st, _ = cl.judge(stay, d, dict(os.environ))
            finally:
                cl.time.sleep = orig
                try:
                    os.kill(int((td / "pid2").read_text()), 15)
                except (OSError, ValueError):
                    pass
            self.assertEqual(st, "fail")


if __name__ == "__main__":
    unittest.main()
