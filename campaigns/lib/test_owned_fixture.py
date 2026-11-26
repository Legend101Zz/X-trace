"""Deterministic ownership fixtures; no Docker, application or PID signals run here."""
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import owned_fixture as owned
import xcamp
import xinstr

NETWORK, DATABASE, APPLICATION = "a" * 64, "b" * 64, "c" * 64


def result(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def cid(args, identity):
    Path(args[args.index("--cidfile") + 1]).write_text(identity + "\n")


class Containers(unittest.TestCase):
    def test_collision_does_not_remove_any_constructed_name(self):
        docker = mock.Mock(side_effect=RuntimeError("name collision"))
        fixture = owned.DockerFixture(docker)
        with self.assertRaisesRegex(RuntimeError, "collision"):
            fixture.run_container(["run", "-d", "--name", "xtrace-camp-app"])
        fixture.cleanup()
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(fixture.containers, [])

    def test_partial_run_failure_keeps_its_private_creation_id_for_cleanup(self):
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == "run":
                cid(args, DATABASE)
                raise RuntimeError("start failed after create")
            return result()
        fixture = owned.DockerFixture(docker)
        with self.assertRaisesRegex(RuntimeError, "start failed"):
            fixture.run_container(["run", "-d", "--name", "xtrace-camp-db"])
        self.assertEqual(fixture.containers, [DATABASE])
        fixture.cleanup()
        self.assertEqual(calls[-1], ("rm", "-f", "-v", DATABASE))
        self.assertEqual(fixture.containers, [])

    def test_successful_detached_run_binds_both_receipts_and_fresh_paths(self):
        paths = []
        def docker(*args, **kwargs):
            if args[0] == "run":
                path = Path(args[args.index("--cidfile") + 1])
                self.assertFalse(path.exists())
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                paths.append(path)
                cid(args, APPLICATION)
                return result(out=APPLICATION + "\n")
            return result()
        fixture = owned.DockerFixture(docker)
        for _ in range(2):
            fixture.run_container(["run", "-d", "--name", "xtrace-camp-app"])
            fixture.cleanup()
        self.assertNotEqual(paths[0], paths[1])
        self.assertTrue(all(not p.parent.exists() for p in paths))

    def test_empty_failed_create_receipt_never_adopts_a_foreign_name(self):
        docker = mock.Mock()
        def fail(*args, **kwargs):
            Path(args[args.index("--cidfile") + 1]).write_text("")
            raise RuntimeError("creation refused")
        docker.side_effect = fail
        fixture = owned.DockerFixture(docker)
        with self.assertRaises(RuntimeError):
            fixture.run_container(["run", "-d", "--name", "xtrace-camp-existing"])
        fixture.cleanup()
        self.assertEqual(docker.call_count, 1)

    def test_missing_or_disagreeing_success_receipts_fail_closed(self):
        for conflicting in (False, True):
            def docker(*args, **kwargs):
                if args[0] == "run":
                    if conflicting:
                        cid(args, DATABASE)
                    return result(out=APPLICATION if conflicting else "")
                return result()
            fixture = owned.DockerFixture(docker)
            with self.subTest(conflicting=conflicting), self.assertRaises(ValueError):
                fixture.run_container(["run", "-d", "--name", "xtrace-camp-app"])
            self.assertEqual(fixture.containers, [])

    def test_conflicting_app_identity_cannot_be_removed_during_partial_stack_rollback(self):
        stack = xcamp.Stack(project="petclinic", jdk_image="jdk", jar=Path("app.jar"), app_args=[],
                            app_port=8080, ready_path="/health", db_name="db", mode="docker")
        conflicting = "d" * 64
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[:2] == ("network", "create"):
                return result(out=NETWORK)
            if args[0] == "run":
                if args[args.index("--name") + 1] == stack.db_container_name:
                    cid(args, DATABASE)
                    return result(out=DATABASE)
                cid(args, conflicting)
                return result(out=APPLICATION)
            return result()
        with mock.patch.object(xcamp, "docker", side_effect=docker), mock.patch.object(stack, "_wait_db"):
            with self.assertRaisesRegex(ValueError, "disagree"):
                stack.up()
        self.assertEqual([call for call in calls if call[0] == "rm" or call[:2] == ("network", "rm")],
                         [("rm", "-f", "-v", DATABASE), ("network", "rm", NETWORK)])

    def test_baseline_collision_never_reads_logs_for_an_unacquired_application(self):
        stack = xcamp.Stack(project="petclinic", jdk_image="jdk", jar=Path("app.jar"), app_args=[],
                            app_port=8080, ready_path="/health", mode="docker")
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(
                xcamp, "docker", side_effect=RuntimeError("network collision")) as docker:
            dest = Path(folder) / "baseline"
            with self.assertRaisesRegex(RuntimeError, "network collision"):
                xcamp.run_baseline(project="petclinic", pin={}, make_stack=lambda _: stack, scenarios=[],
                                   out_dir=dest, norm_extra=[], adaptations=[], harness_files=[])
            self.assertEqual((dest / "application.log").read_text(), "")
        docker.assert_called_once_with("network", "create", stack.net)

    def test_linked_and_nonregular_creation_receipts_are_not_followed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "foreign"
            target.write_text(APPLICATION)
            link = root / "container.id"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                owned.cid_identity(link)
            self.assertEqual(target.read_text(), APPLICATION)
            link.unlink()
            link.mkdir()
            with self.assertRaises(ValueError):
                owned.cid_identity(link)

    def test_failed_cleanup_retains_only_failed_ids_and_retries_them(self):
        calls = []
        failing = True
        def docker(*args, **kwargs):
            calls.append(args)
            return result(1, err="removal refused") if failing and args[-1] == DATABASE else result()
        fixture = owned.DockerFixture(docker, containers=[DATABASE, APPLICATION], network=NETWORK)
        with self.assertRaises(owned.CleanupFailure):
            fixture.cleanup()
        self.assertEqual(fixture.containers, [DATABASE])
        self.assertIsNone(fixture.network)
        self.assertEqual(calls, [("rm", "-f", "-v", APPLICATION), ("rm", "-f", "-v", DATABASE), ("network", "rm", NETWORK)])
        failing = False
        calls.clear()
        fixture.cleanup()
        self.assertEqual(calls, [("rm", "-f", "-v", DATABASE)])

    def test_already_auto_removed_owned_id_is_idempotent_but_other_errors_fail(self):
        docker = mock.Mock(return_value=result(1, err="Error response from daemon: No such container: " + APPLICATION))
        fixture = owned.DockerFixture(docker, containers=[APPLICATION])
        fixture.cleanup()
        self.assertEqual(fixture.containers, [])
        fixture.containers.append(APPLICATION)
        docker.return_value = result(1, err="Error response from daemon: No such container: " + DATABASE)
        with self.assertRaises(owned.CleanupFailure):
            fixture.cleanup()
        self.assertEqual(fixture.containers, [APPLICATION])

    def test_network_cleanup_failure_is_retryable_without_releasing_other_invocations(self):
        docker = mock.Mock(return_value=result(1, err="network still in use"))
        fixture = owned.DockerFixture(docker, network=NETWORK)
        other = owned.DockerFixture(docker, containers=[APPLICATION])
        with self.assertRaises(owned.CleanupFailure) as failure:
            fixture.cleanup()
        self.assertIs(failure.exception.owner, fixture)
        self.assertEqual(fixture.network, NETWORK)
        self.assertEqual(other.containers, [APPLICATION])
        docker.return_value = result()
        fixture.cleanup()
        self.assertIsNone(fixture.network)
        self.assertTrue(all(call.args == ("network", "rm", NETWORK) for call in docker.call_args_list))

    def test_ordinary_stack_success_tears_down_its_exact_ids_in_reverse_order(self):
        stack = xcamp.Stack(project="petclinic", jdk_image="jdk", jar=Path("app.jar"), app_args=[], app_port=8080,
                             ready_path="/health", db_name="db", mode="docker")
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[:2] == ("network", "create"):
                return result(out=NETWORK)
            if args[0] == "run":
                identity = DATABASE if args[args.index("--name") + 1] == stack.db_container_name else APPLICATION
                cid(args, identity)
                return result(out=identity)
            return result()
        with mock.patch.object(xcamp, "docker", side_effect=docker), mock.patch.object(stack, "_wait_db"), \
                mock.patch.object(stack, "_wait_ready"), mock.patch.object(xcamp, "published_port", return_value=12345) as port:
            stack.up()
            self.assertEqual(stack._owned.containers, [DATABASE, APPLICATION])
            self.assertEqual((stack.db, stack.app), (DATABASE, APPLICATION))
            port.assert_called_once_with(APPLICATION, 8080)
            self.assertTrue(all(call[call.index("--network") + 1] == NETWORK for call in calls if call[0] == "run"))
            stack.logs()
            self.assertEqual(calls[-1], ("logs", APPLICATION))
            stack.psql("select 1")
            self.assertEqual(calls[-1][:2], ("exec", DATABASE))
            stack.down()
            self.assertEqual(stack.logs(), "")
        self.assertEqual(calls[-3:], [("rm", "-f", "-v", APPLICATION), ("rm", "-f", "-v", DATABASE), ("network", "rm", NETWORK)])

    def test_partial_stack_startup_removes_only_successfully_created_objects(self):
        stack = xcamp.Stack(project="fineract", jdk_image="jdk", jar=Path("app.jar"), app_args=[], app_port=8080,
                             ready_path="/health", db_name="db", mode="docker")
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[:2] == ("network", "create"):
                return result(out=NETWORK)
            if args[0] == "run":
                if args[args.index("--name") + 1] == stack.db_container_name:
                    cid(args, DATABASE)
                    return result(out=DATABASE)
                raise RuntimeError("app name collision")
            return result()
        with mock.patch.object(xcamp, "docker", side_effect=docker), mock.patch.object(stack, "_wait_db"):
            with self.assertRaisesRegex(RuntimeError, "collision"):
                stack.up()
        removals = [call for call in calls if call[0] == "rm" or call[:2] == ("network", "rm")]
        self.assertEqual(removals, [("rm", "-f", "-v", DATABASE), ("network", "rm", NETWORK)])
        self.assertTrue(all(stack.app_container_name not in call and stack.db_container_name not in call and stack.net not in call for call in removals))

    def test_network_collision_never_runs_any_cleanup_command(self):
        stack = xcamp.Stack(project="petclinic", jdk_image="jdk", jar=Path("app.jar"), app_args=[], app_port=8080,
                             ready_path="/health", mode="docker")
        with mock.patch.object(xcamp, "docker", side_effect=RuntimeError("network name collision")) as docker:
            with self.assertRaisesRegex(RuntimeError, "collision"):
                stack.up()
        self.assertEqual(docker.call_count, 1)

    def test_build_timeout_releases_only_its_cid_and_keeps_original_timeout(self):
        calls = []
        def run(argv, **kwargs):
            self.assertEqual(kwargs["timeout"], 7200)
            self.assertIn("--rm", argv)
            cid(argv, APPLICATION)
            raise subprocess.TimeoutExpired(argv, 7200)
        def docker(*args, **kwargs):
            calls.append(args)
            return result()
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(xcamp.subprocess, "run", side_effect=run), \
                mock.patch.object(xcamp, "_docker_env", return_value={}), mock.patch.object(xcamp, "docker", side_effect=docker):
            with self.assertRaises(subprocess.TimeoutExpired):
                xcamp.docker_build("fineract", Path(folder), "jdk", "build", {}, Path(folder)/"build.log", timeout=7200)
        self.assertEqual(calls, [("rm", "-f", "-v", APPLICATION)])

    def test_build_collision_never_removes_the_existing_named_container(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(xcamp.subprocess, "run", return_value=result(125)), \
                mock.patch.object(xcamp, "_docker_env", return_value={}), mock.patch.object(xcamp, "docker") as docker:
            self.assertEqual(xcamp.docker_build("petclinic", Path(folder), "jdk", "build", {}, Path(folder)/"build.log"), 125)
        docker.assert_not_called()

    def test_build_cleanup_failure_retains_the_owned_handle_for_explicit_retry(self):
        def run(argv, **kwargs):
            cid(argv, APPLICATION)
            return result()
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(xcamp.subprocess, "run", side_effect=run), \
                mock.patch.object(xcamp, "_docker_env", return_value={}), \
                mock.patch.object(xcamp, "docker", return_value=result(1, err="removal refused")) as docker:
            with self.assertRaises(owned.CleanupFailure) as failed:
                xcamp.docker_build("petclinic", Path(folder), "jdk", "build", {}, Path(folder)/"build.log")
            fixture = failed.exception.owner
            self.assertEqual(fixture.containers, [APPLICATION])
            docker.return_value = result()
            fixture.cleanup()
            self.assertEqual(fixture.containers, [])


class Processes(unittest.TestCase):
    def child(self, **kwargs):
        return mock.Mock(pid=12345, stdout=io.StringIO(), **kwargs)

    def test_graceful_stop_keeps_full_original_wait_and_reaps_only_direct_child(self):
        child = self.child()
        child.poll.return_value = None
        owned.stop_child(child, 90)
        child.terminate.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=90)
        child.kill.assert_not_called()

    def test_forced_shutdown_reaps_direct_child_but_never_passes(self):
        child = self.child()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("own child", 15), -9]
        with self.assertRaises(owned.CleanupFailure):
            owned.stop_child(child, 15)
        self.assertEqual(child.wait.call_args_list, [mock.call(timeout=15), mock.call(timeout=5)])
        child.kill.assert_called_once_with()

    def test_unreaped_child_handle_remains_available_for_explicit_stack_cleanup(self):
        stack = xcamp.Stack(project="petclinic", jdk_image="jdk", jar=Path("app.jar"), app_args=[], app_port=8080,
                             ready_path="/health", mode="host")
        child = self.child()
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("own child", 90)
        stack._proc = child
        with self.assertRaises(owned.CleanupFailure):
            stack.down()
        self.assertIs(stack._proc, child)
        child.poll.return_value = -9
        child.wait.side_effect = None
        stack.down()
        self.assertIsNone(stack._proc)
        self.assertEqual(stack.launcher_exit, -9)

    def test_already_exited_child_is_reaped_without_signalling(self):
        child = self.child()
        child.poll.return_value = 0
        owned.stop_child(child, 90)
        child.wait.assert_called_once_with(timeout=0)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_all_cleanup_callbacks_run_and_all_failures_remain_visible(self):
        first, second = RuntimeError("first"), ValueError("second")
        operations = [mock.Mock(side_effect=first), mock.Mock(side_effect=second), mock.Mock()]
        with self.assertRaises(owned.CleanupFailure) as caught:
            owned.cleanup_all(*operations)
        self.assertEqual(caught.exception.failures, (first, second))
        self.assertTrue(all(operation.call_count == 1 for operation in operations))

    def test_viewer_early_exit_reaps_and_closes_pipe_before_returning_failure(self):
        child = self.child()
        child.poll.return_value = 2
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(xinstr.subprocess, "Popen", return_value=child), \
                mock.patch("select.select", return_value=([], [], [])):
            with self.assertRaisesRegex(RuntimeError, "viewer exited early"):
                xinstr.start_viewer("xtrace", Path(folder), {}, Path(folder)/"viewer.log")
        child.wait.assert_called_once_with(timeout=0)
        child.terminate.assert_not_called()
        self.assertTrue(child.stdout.closed)

    def test_partial_viewer_line_expires_at_original_deadline_and_reaps_owned_child(self):
        child = self.child()
        child.stdout = mock.Mock()
        child.stdout.fileno.return_value = 19
        child.poll.return_value = None
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(xinstr.subprocess, "Popen", return_value=child), \
                mock.patch.object(xinstr.os, "set_blocking") as nonblocking, \
                mock.patch("select.select", return_value=([child.stdout], [], [])) as select_ready, \
                mock.patch.object(xinstr.os, "read", return_value=b'{"origin":') as read, \
                mock.patch.object(xinstr.time, "monotonic", side_effect=[1, 60.75, 61]):
            with self.assertRaisesRegex(RuntimeError, "readiness line not seen"):
                xinstr.start_viewer("xtrace", Path(folder), {}, Path(folder)/"viewer.log")
        nonblocking.assert_called_once_with(19, False)
        select_ready.assert_called_once_with([child.stdout], [], [], 0.25)
        read.assert_called_once_with(19, 65536)
        child.terminate.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=15.0)
        child.stdout.close.assert_called_once_with()

    def test_coalesced_viewer_lines_are_consumed_before_another_pipe_wait(self):
        child = self.child()
        child.stdout = mock.Mock()
        child.stdout.fileno.return_value = 19
        child.poll.return_value = None
        chunk = b'notice\n{"origin":"local","url":"ready"}\n'
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(xinstr.subprocess, "Popen", return_value=child), \
                mock.patch.object(xinstr.os, "set_blocking") as nonblocking, \
                mock.patch("select.select", return_value=([child.stdout], [], [])) as select_ready, \
                mock.patch.object(xinstr.os, "read", return_value=chunk), \
                mock.patch.object(xinstr.time, "monotonic", side_effect=[1, 1, 1]):
            proc, ready = xinstr.start_viewer("xtrace", Path(folder), {}, Path(folder)/"viewer.log")
        self.assertIs(proc, child)
        self.assertEqual(ready, {"origin": "local", "url": "ready"})
        nonblocking.assert_called_once_with(19, False)
        select_ready.assert_called_once()
        child.terminate.assert_not_called()

    def test_barrier_timeout_reaps_only_its_direct_exec_and_stays_failed(self):
        stack = xcamp.Stack(project="petclinic", jdk_image="jdk", jar=Path("app.jar"), app_args=[], app_port=8080,
                             ready_path="/health", db_name="db")
        stack._db_id = DATABASE
        stack._owned.containers.append(DATABASE)
        child = self.child(stdin=mock.Mock())
        child.stdout = io.BytesIO(b"1\n")
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("own barrier", 10), 0]
        with mock.patch.object(xcamp.subprocess, "Popen", return_value=child), \
                mock.patch("select.select", return_value=([child.stdout], [], [])):
            with self.assertRaises(subprocess.TimeoutExpired):
                with stack.hold_owner_writes():
                    pass
        self.assertEqual(child.wait.call_args_list, [mock.call(timeout=10), mock.call(timeout=10)])
        child.terminate.assert_called_once_with()
        child.kill.assert_not_called()
        self.assertTrue(child.stdout.closed)


if __name__ == "__main__":
    unittest.main()
