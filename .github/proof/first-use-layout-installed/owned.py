import os
import queue
import signal
import subprocess
import threading

from common import ROOT, REPO, need


ENV = dict(os.environ, XTRACE_DATA_HOME=str(ROOT / 'data-home'))
for name in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'XTRACE_JAVA_AGENT',
             'XTRACE_JAVA_PACK', 'XTRACE_NODE_PACK', 'XTRACE_NODE_ANALYZER', 'XTRACE_JAVA_ANALYZER'):
    ENV.pop(name, None)


class OwnedProcess:
    def __init__(self, label, args):
        self.label = label
        self.errors = ROOT / "logs" / (label + ".stderr")
        with self.errors.open("xb") as err:
            self.child = subprocess.Popen(args, cwd=REPO, env=ENV, stdout=subprocess.PIPE, stderr=err, start_new_session=True)
        self.messages = queue.Queue(maxsize=1)
        self.drain = None
        self.drain_ok = False

    def __enter__(self):
        return self

    def ready(self, extract, timeout):
        def read():
            reported = False
            with (ROOT / "logs" / (self.label + ".stdout")).open("xb") as out, self.child.stdout as stream:
                try:
                    for line in iter(lambda: stream.readline(65537), b""):
                        need(len(line) <= 65536 and out.tell() + len(line) <= 4 * 1024 * 1024)
                        out.write(line)
                        if not reported:
                            value = extract(line.decode("utf-8", "replace"))
                            if value is not None:
                                self.messages.put(value)
                                reported = True
                    self.drain_ok = True
                finally:
                    if not reported:
                        self.messages.put(None)
        self.drain = threading.Thread(target=read, daemon=True)
        self.drain.start()
        value = self.messages.get(timeout=timeout)
        need(value is not None and self.child.poll() is None)
        return value

    def stop(self, require_running=False):
        # Only this thread polls or waits. The drain thread reads the pipe.
        live = self.child.poll() is None
        if require_running:
            need(live)
        if live:
            try:
                os.kill(self.child.pid, signal.SIGTERM)
            except ProcessLookupError:
                if require_running:
                    raise
        try:
            code = self.child.wait(timeout=25)
        except subprocess.TimeoutExpired:
            if self.child.poll() is None:
                self.child.kill()
            self.child.wait(timeout=5)
            raise
        if self.drain:
            self.drain.join(timeout=5)
            need(not self.drain.is_alive() and self.drain_ok)
        if require_running:
            need(code in (0, 143))
        return code

    def __exit__(self, *_):
        if self.child.returncode is None or (self.drain and self.drain.is_alive()):
            self.stop()


def list_args(cli, project):
    return [str(cli), "recording", "list", "--project-dir", str(project), "--limit", "200"]
