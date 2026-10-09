"""PTY harness for the xtrace-tui tests: runs a command on a pseudo-terminal, plays a script of
steps, and prints one JSON document {output, exit}. Standard library only.

Script steps (argv[3], JSON list): ["send", "text"], ["wait", "substring", seconds],
["resize", cols, rows], ["sleep", seconds]. A failed wait is recorded, not hidden.
"""
import fcntl
import json
import os
import pty
import select
import struct
import sys
import termios
import time


def set_size(fd, cols, rows):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def main():
    cols, rows = (int(x) for x in sys.argv[1].split("x"))
    script = json.loads(sys.argv[2])
    argv = sys.argv[3:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
    set_size(fd, cols, rows)
    out = bytearray()
    failures = []
    pos = 0

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                out.extend(data)
        return True

    alive = pump(0.3)
    for step in script:
        kind = step[0]
        if kind == "send":
            os.write(fd, step[1].encode())
            alive = pump(0.1)
        elif kind == "sleep":
            alive = pump(step[1])
        elif kind == "resize":
            set_size(fd, step[1], step[2])
        elif kind == "wait":
            end = time.time() + step[2]
            needle = step[1].encode()
            while time.time() < end and needle not in out[pos:]:
                if not pump(0.05):
                    break
            found = out.find(needle, pos)
            if found < 0:
                failures.append("never saw: " + step[1])
            else:
                pos = found + len(needle)
    # Give the child time to exit on its own, then reap it.
    deadline = time.time() + 3
    status = None
    while time.time() < deadline:
        pump(0.05)
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
    if status is None:
        os.kill(pid, 9)
        _, status = os.waitpid(pid, 0)
        failures.append("child did not exit; killed")
    code = os.waitstatus_to_exitcode(status)
    print(json.dumps({"output": out.decode("utf-8", "replace"), "exit": code, "failures": failures}))


main()
