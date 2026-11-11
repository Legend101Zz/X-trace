import pathlib
import io
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xcamp


class Ports(unittest.TestCase):
    def stack(self, **kw):
        return xcamp.Stack(project="petclinic", jdk_image="jdk", jar=pathlib.Path("app.jar"),
                           app_args=["--server.port={APPPORT}"], app_port=8080, ready_path="/health", **kw)

    def test_bound_port_requires_a_started_server_message(self):
        self.assertIsNone(xcamp.spring_bound_port("Tomcat initialized with port 0 (http)"))
        self.assertEqual(xcamp.spring_bound_port("Tomcat started on port 39451 (http) with context path '/'"), 39451)
        self.assertEqual(xcamp.spring_bound_port("Tomcat started on port(s): 45678 (http)"), 45678)
        self.assertIsNone(xcamp.spring_bound_port("Tomcat started on port 0 (http)"))

    def test_host_starts_with_zero_and_discovers_actual_port_before_http(self):
        stack = self.stack(mode="host")
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(xcamp.os.environ, {"XCAMP_JAVA": "java", "TMPDIR": td}), \
             mock.patch.object(stack, "down"), mock.patch.object(xcamp, "docker"), \
             mock.patch.object(xcamp.subprocess, "Popen") as launch, \
             mock.patch.object(stack, "logs", return_value="Tomcat started on port 39451 (http)"), \
             mock.patch.object(xcamp, "http_request", return_value={"status": 200, "body": b"UP"}) as request:
            launch.return_value.poll.return_value = None
            stack.up()
            self.assertIn("--server.port=0", launch.call_args.args[0])
            self.assertEqual(stack.host_port, 39451)
            self.assertEqual(request.call_args.args[0], "http://127.0.0.1:39451")

    def test_docker_allocates_both_host_bindings(self):
        stack = self.stack(mode="host", db_name="petclinic")
        with mock.patch.object(stack, "down"), mock.patch.object(stack, "_wait_db"), \
             mock.patch.object(stack, "_wait_ready"), mock.patch.object(xcamp, "docker") as docker, \
             mock.patch.object(xcamp, "published_port", return_value=39452), \
             tempfile.TemporaryDirectory() as td, mock.patch.dict(xcamp.os.environ, {"XCAMP_JAVA": "java", "TMPDIR": td}), \
             mock.patch.object(xcamp.subprocess, "Popen"):
            stack.up()
            db_run = next(c.args for c in docker.call_args_list if c.args[0] == "run")
            self.assertIn("127.0.0.1::5432", db_run)
            self.assertEqual(stack.db_host_port, 39452)
        stack = self.stack(mode="docker")
        with mock.patch.object(stack, "down"), mock.patch.object(stack, "_wait_ready"), \
             mock.patch.object(xcamp, "docker") as docker, mock.patch.object(xcamp, "published_port", return_value=39453):
            stack.up()
            app_run = next(c.args for c in docker.call_args_list if c.args[0] == "run")
            self.assertIn("127.0.0.1::8080", app_run)
            self.assertEqual(stack.host_port, 39453)

    def test_docker_binding_must_be_one_valid_loopback_port(self):
        for text in ("0.0.0.0:1234", "127.0.0.1:0", "127.0.0.1:70000", "", "127.0.0.1:1\n127.0.0.1:2"):
            with mock.patch.object(xcamp, "docker", return_value=subprocess.CompletedProcess([], 0, text)):
                with self.assertRaises(RuntimeError):
                    xcamp.published_port("app", 8080)

    def test_database_readiness_requires_tcp_query_not_init_socket(self):
        stack = self.stack(db_name="petclinic")
        with mock.patch.object(xcamp, "docker", side_effect=[
            subprocess.CompletedProcess([], 0, "ready"), subprocess.CompletedProcess([], 0, "1\n")
        ]) as docker, mock.patch.object(xcamp.time, "sleep") as sleep:
            stack._wait_db()
            self.assertIn("-h", docker.call_args.args)
            self.assertIn("127.0.0.1", docker.call_args.args)
            self.assertIn(f"PGPASSWORD={stack.db_password}", docker.call_args.args)
            sleep.assert_not_called()

    def test_pacing_precedes_request_and_never_delays_observed_completion(self):
        events = []
        response = {"status": 200, "headers": {}, "body": b"OK", "elapsedMs": 1}
        with mock.patch.object(xcamp.time, "sleep", side_effect=lambda seconds: events.append(("pace", seconds))), \
             mock.patch.object(xcamp, "http_request", side_effect=lambda *a, **kw: events.append(("request", a[2])) or response):
            ctx = xcamp.Ctx(stack=self.stack(), base="http://127.0.0.1:1234", pace=0.4)
            ctx.http("GET", "/vets")
        self.assertEqual(events, [("pace", 0.4), ("request", "/vets")])

    def test_owner_write_barrier_requires_lock_acknowledgement_and_releases_on_error(self):
        stack = self.stack(db_name="petclinic")
        for acknowledged in (True, False):
            proc = mock.Mock(stdin=mock.Mock(), stdout=io.BytesIO(b"1\n" if acknowledged else b""))
            entered = False
            with self.subTest(acknowledged=acknowledged), mock.patch.object(xcamp.subprocess, "Popen", return_value=proc) as launch, \
                    mock.patch("select.select", return_value=([proc.stdout], [], [])), mock.patch.object(xcamp.time, "sleep") as sleep:
                with self.assertRaisesRegex(RuntimeError, "probe interrupted" if acknowledged else "not acknowledged"):
                    with stack.hold_owner_writes():
                        entered = True
                        proc.stdin.close.assert_not_called()
                        raise RuntimeError("probe interrupted")
                self.assertEqual(entered, acknowledged)
                self.assertEqual(launch.call_args.args[0][:4], ["docker", "exec", "-i", stack.db])
                proc.stdin.write.assert_called_once_with(b"BEGIN; LOCK TABLE owners IN SHARE MODE; SELECT 1;\n")
                proc.stdin.flush.assert_called_once()
                proc.stdin.close.assert_called_once()
                proc.wait.assert_called_once_with(timeout=10)
                self.assertTrue(proc.stdout.closed)
                sleep.assert_not_called()

    def test_owner_write_barrier_silence_never_admits_a_request(self):
        stack = self.stack(db_name="petclinic")
        proc = mock.Mock()
        with mock.patch.object(xcamp.subprocess, "Popen", return_value=proc), \
                mock.patch("select.select", return_value=([], [], [])):
            with self.assertRaisesRegex(RuntimeError, "not acknowledged"):
                with stack.hold_owner_writes():
                    self.fail("an unobserved lock must not admit the request")
        proc.stdout.readline.assert_not_called()
        proc.stdin.close.assert_called_once()

    def test_owner_write_barrier_rejects_other_campaign_databases(self):
        stack = self.stack(db_name="petclinic")
        stack.project = "other"
        with mock.patch.object(xcamp.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(RuntimeError, "requires the Petclinic"):
                with stack.hold_owner_writes():
                    self.fail("wrong database")
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
