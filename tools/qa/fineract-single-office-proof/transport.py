"""Read only the ordinary app operation and authenticated recording pages from their observed ports."""
from contextlib import contextmanager
import http.client
import json
import os
import re
import select
import signal
import subprocess
import time
from urllib.parse import urlsplit

import xinstr
import fineract_office_observation as observer
from installed_sinks import MAX_OUTPUT
from receipt import check


@contextmanager
def deadline(end, error=TimeoutError):
    # Inactivity timeouts alone allow an indefinitely trickling body. These calls run
    # on the hosted driver's main thread. Nested timeouts retain the earlier deadline.
    remaining = end - time.monotonic()
    if remaining <= 0:
        raise error("read deadline expired")
    def expired(*_):
        raise error("read deadline expired")
    old = signal.getsignal(signal.SIGALRM)
    prior, _ = signal.getitimer(signal.ITIMER_REAL)
    previous_end = time.monotonic() + prior if prior else None
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(remaining, prior) if prior else remaining)
    try:
        yield
        if time.monotonic() >= end:
            raise error("read deadline expired")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
        if previous_end is not None:
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, previous_end - time.monotonic()))


class StartupDeadline(BaseException):
    """Escape the ordinary health probe's recoverable Exception handler at the hard limit."""


def read_body(response, limit):
    # Unambiguous framing is required for an evidence-bearing response. A parsable
    # JSON prefix and EOF do not prove the complete framed message was received.
    lengths = response.headers.get_all("Content-Length", [])
    encodings = response.headers.get_all("Transfer-Encoding", [])
    if len(lengths) == 1 and not encodings:
        field = lengths[0].strip()
        check(re.fullmatch(r"[0-9]{1,19}", field) and int(field) <= limit)
        size = int(field)
        payload = response.read(size)
        check(len(payload) == size)
        return payload
    check(not lengths and len(encodings) == 1 and encodings[0].strip().lower() == "chunked"
          and response.version == 11 and response.chunked and response.fp is not None)
    # HTTPResponse discards trailers permissively at EOF. Inspect the actual
    # framing stream and require the terminating empty trailer line.
    parts = bytearray()
    framing = 0
    while True:
        line = response.fp.readline(128)
        match = re.fullmatch(rb"([0-9a-fA-F]{1,16})\r\n", line)
        check(match is not None)
        framing += len(line)
        check(framing <= 1 << 20)
        size = int(match[1], 16)
        if size == 0:
            check(response.fp.readline(3) == b"\r\n")
            return bytes(parts)
        check(size <= limit - len(parts))
        part = response.fp.read(size)
        check(len(part) == size and response.fp.read(2) == b"\r\n")
        parts.extend(part)
        framing += 2


def request(port, method, path, body, headers, end, limit):
    check(type(port) is int and 1 <= port <= 65535 and 0 < limit <= MAX_OUTPUT)
    with deadline(end):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=min(60, end - time.monotonic()))
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            data = read_body(response, limit)
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            conn.close()


class Client(xinstr.ViewerClient):
    def __init__(self, ready, end):
        origin = ready["origin"]
        parsed = urlsplit(origin)
        check(parsed.port and origin == f"http://127.0.0.1:{parsed.port}"
              and ready["url"].startswith(origin + "/"))
        token = xinstr.bootstrap_token(ready["url"])
        check(token is not None)
        super().__init__(origin)
        self.pages = []
        self.deadline = end
        self.remaining = MAX_OUTPUT
        self.exchange(token)

    def _req(self, method, path, body=None):
        auth = method == "POST" and path == "/api/v1/auth/exchange" and self.cookie is None
        check(auth or (method == "GET" and self.cookie and
              re.fullmatch(r"/api/v1/recordings(?:\?limit=200(?:&after=[0-9a-f-]{36})?|/"
                           r"[0-9a-f-]{36}\?limit=1000(?:&cursor=[a-zA-Z0-9_.%-]+)?)", path)))
        headers = {"Host": f"127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin",
                   "X-XTrace-Client": "viewer-v1", "Accept": "application/json"}
        if auth:
            headers.update(Origin=self.origin)
            headers["Content-Type"] = "application/json"
        else:
            headers["Cookie"] = self.cookie
        status, response_headers, payload = request(self.port, method, path, body, headers, self.deadline,
                                                   self.remaining)
        self.remaining -= len(payload)
        return status, response_headers, payload

    def get(self, path):
        status, doc = super().get(path)
        if path.startswith("/api/v1/recordings?") and status == 200:
            self.pages.append(doc)
        return status, doc

    def snapshot(self, folder, project, end, *, paired=True):
        self.pages = []
        self.deadline = end
        self.remaining = MAX_OUTPUT
        with deadline(end):
            result = xinstr.collect_api(self, folder, fineract_pair=True, fineract_phase=paired)
            if not result["ok"]:
                return None, result
            inventory = observer.inventory(project, self.pages)
        return inventory, result


def read_ready(proc, end):
    buf = bytearray()
    with deadline(end):
        while proc.poll() is None:
            readable, _, _ = select.select([proc.stdout], [], [], max(0, end - time.monotonic()))
            if not readable:
                raise TimeoutError("viewer readiness")
            data = os.read(proc.stdout.fileno(), 65536)
            check(data)
            buf.extend(data)
            check(len(buf) <= 1 << 20)
            while (pos := buf.find(b"\n")) >= 0:
                line = buf[:pos]
                del buf[:pos + 1]
                ready = xinstr.parse_readiness(line.decode("utf-8", "replace"))
                if ready:
                    check(proc.poll() is None)
                    return ready
        raise RuntimeError("viewer exited")


def release_process(proc, wait):
    if proc.poll() is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            check(proc.poll() is not None)
    return proc.wait(timeout=wait)


@contextmanager
def viewer(cli, project, log, finish):
    with log.open("xb") as output:
        proc = subprocess.Popen([cli, "open", "--project-dir", str(project), "--viewer", "--no-browser"],
                                stdout=subprocess.PIPE, stderr=output, start_new_session=True)
    try:
        ready = read_ready(proc, time.monotonic() + 60)
        yield Client(ready, time.monotonic() + 60)
    finally:
        try:
            finish(proc)
        finally:
            proc.stdout.close()


class OfficeRead:
    def __init__(self, stack, run, end, doc, save):
        self.stack, self.run, self.end, self.doc, self.save = stack, run, end, doc, save

    def http(self, method, path, *, headers):
        check(self.stack._proc.poll() is None and method == "GET" and path == observer.phase.OFFICE_LIST_ROUTE
              and headers == self.run.H and self.doc["businessAttempts"] == 0)
        self.doc["businessAttempts"] = 1
        self.save()
        status, _, data = request(self.stack.host_port, method, path, None, headers,
                                  min(self.end, time.monotonic() + 15), 1 << 20)
        self.doc["http200"] = status == 200
        self.save()
        return {"status": status, "text": data.decode("utf-8")}

    def check(self, label, good):
        check(label == "authenticated office list contains seeded head office" and type(good) is bool
              and self.doc["seedPredicate"] is None)
        self.doc["seedPredicate"] = good
        self.save()
        check(good)
