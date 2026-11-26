"""Owned ordinary process and recording readback reused from the installed tour."""
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import threading
import time
import uuid

from common import need


ROOT = Path(os.environ["PROOF_ROOT"])
REPO = Path.cwd()
ENV = dict(os.environ, XTRACE_DATA_HOME=str(ROOT / "data-home"))
for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "XTRACE_JAVA_AGENT", "XTRACE_JAVA_PACK",
            "XTRACE_NODE_ANALYZER", "XTRACE_JAVA_ANALYZER"):
    ENV.pop(key, None)
def query(args, timeout=10):
    result = subprocess.run(args, cwd=REPO, env=ENV, capture_output=True, check=True, timeout=timeout)
    need(len(result.stdout) <= 16 * 1024 * 1024)
    return json.loads(result.stdout)


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

    def stop(self):
        if self.child.poll() is not None:
            raise RuntimeError('owned child exited before requested shutdown')
        # Popen.terminate may silently ignore a child that exited after poll.
        # Send to this unreaped direct child's PID and preserve any signal error.
        os.kill(self.child.pid, signal.SIGTERM)
        return self.wait_after_stop()

    def wait_after_stop(self):
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
        return code

    def __exit__(self, exc_type, *_):
        try:
            if self.child.poll() is None:
                self.stop()
            elif self.drain and self.drain.is_alive():
                self.wait_after_stop()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            if exc_type is None:
                raise
            # Retain the causal failure in the stage receipt and record cleanup privately.
            import traceback
            with (ROOT/'logs'/(self.label+'-cleanup.stderr')).open('x') as err:
                traceback.print_exc(file=err)


def list_args(cli, project):
    return [str(cli), "recording", "list", "--project-dir", str(project), "--limit", "200"]


def expected_recording(cli, project, *, other_ids=frozenset(), include_identities=False):
    wait_until = time.monotonic() + 30
    while time.monotonic() < wait_until:
        listing = query(list_args(cli, project), timeout=max(0.1, min(5, wait_until - time.monotonic())))
        rows = listing["recordings"]
        ids = {row["recording_id"] for row in rows}
        need(listing["next_after"] is None and len(ids) == len(rows) and other_ids <= ids
             and len(rows) <= 1 + len(other_ids))
        fresh = [row for row in rows if row["recording_id"] not in other_ids]
        if fresh and fresh[0]["completion"] == "complete":
            rid = fresh[0]["recording_id"]
            need(str(uuid.UUID(rid)) == rid and uuid.UUID(rid).version == 7)
            detail = query([str(cli), "recording", "show", rid, "--limit", "200", "--project-dir", str(project)])
            need(detail["recording_id"] == rid and detail["completion"] == "complete" and detail["next_cursor"] is None
                 and detail["outcome"]["kind"] == "responded" and detail["outcome"]["httpStatus"] == 210)
            events = detail["events"]
            need(1 < len(events) <= 200 and any(event["symbol"] == "ServletBoundaryController.uncommitted" for event in events))
            sequences = [event["sequence"] for event in events]
            need(all(isinstance(item, str) and re.fullmatch("[0-9]+", item) for item in sequences)
                 and all(int(a) < int(b) for a, b in zip(sequences, sequences[1:])))
            if include_identities:
                identities = [(event['sequence'], event['event_id']) for event in events]
                need(all(isinstance(event_id, str) and event_id for _, event_id in identities))
                need(len({event_id for _, event_id in identities}) == len(identities))
                return rid, identities
            return rid, sequences
        time.sleep(0.1)
    raise TimeoutError("recording deadline")
