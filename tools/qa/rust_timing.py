"""Bounded Cargo test observations; output names require immutable checkout metadata."""
from __future__ import annotations

import json
import math
import os
import pathlib
import re
import selectors
import subprocess
import time
import tomllib
from dataclasses import dataclass

MAX_EVENTS = 1024
MAX_LINE = 16384
UNVERIFIED = "<unverified>"
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+) \((.+)\)$")
DOC_TESTS = re.compile(r"^\s*Doc-tests ([A-Za-z0-9_-]+)$")
FINISHED = re.compile(r"^\s*Finished `test` profile .* target\(s\) in \S+$")
RESULT = re.compile(r"^test result: (?:ok|FAILED)\. \d+ passed; \d+ failed; \d+ ignored;")
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


@dataclass(frozen=True)
class Target:
    crate: str
    kind: str
    name: str
    path: str

    def public(self) -> dict:
        return {"crate": self.crate, "targetKind": self.kind, "targetName": self.name}


def checkout_targets(sources: dict[str, str]) -> set[Target]:
    """Derive Cargo's conventional and explicit targets from HEAD blobs only."""
    targets = set()
    for manifest, source in sources.items():
        root = pathlib.PurePosixPath(manifest).parent
        if root.parts[:1] != ("crates",) or pathlib.PurePosixPath(manifest).name != "Cargo.toml":
            continue
        try:
            data = tomllib.loads(source)
        except tomllib.TOMLDecodeError:
            continue
        package = data.get("package", {})
        crate = package.get("name")
        if not isinstance(crate, str) or not NAME.fullmatch(crate):
            continue

        def add(kind, name, path):
            if (isinstance(name, str) and NAME.fullmatch(name) and isinstance(path, str)
                    and not pathlib.PurePosixPath(path).is_absolute() and ".." not in pathlib.PurePosixPath(path).parts
                    and str(root / path) in sources):
                targets.add(Target(crate, kind, name, path))

        lib = data.get("lib", {})
        if "lib" in data or package.get("autolib", True):
            add("lib", lib.get("name", crate.replace("-", "_")), lib.get("path", "src/lib.rs"))
        for kind, directory, automatic in (("bin", "src/bin", "autobins"), ("test", "tests", "autotests"),
                                            ("example", "examples", "autoexamples"), ("bench", "benches", "autobenches")):
            explicit = data.get(kind, [])
            if kind == "bin" and package.get(automatic, True) and not explicit:
                add("bin", crate, "src/main.rs")
            for entry in explicit:
                name = entry.get("name")
                path = entry.get("path")
                if path is None:
                    path = "src/main.rs" if kind == "bin" and str(root / "src/main.rs") in sources else f"{directory}/{name}.rs"
                add(kind, name, path)
            if package.get(automatic, True):
                for filename in sources:
                    path = pathlib.PurePosixPath(filename)
                    if not path.is_relative_to(root / directory):
                        continue
                    relative = path.relative_to(root / directory)
                    if any(target.crate == crate and target.kind == kind and target.path == str(path.relative_to(root))
                           for target in targets):
                        continue
                    if len(relative.parts) == 1 and relative.suffix == ".rs":
                        add(kind, relative.stem, f"{directory}/{relative}")
                    elif len(relative.parts) == 2 and relative.name == "main.rs":
                        add(kind, relative.parts[0], f"{directory}/{relative}")
    return targets


class Observations:
    """Wall offsets are observed boundaries, never inferred test or compiler CPU time."""

    def __init__(self, targets, private):
        self.targets = targets
        self.private = private
        self.events = []
        self.omitted = 0
        self.unverified = 0
        self.active = None
        self.harness_completed = False
        self.compilation = None
        self.execution_started = None
        self.revision = 0

    def _binary(self, value):
        """Reattest checkpoint identities with the same HEAD targets as live output."""
        allowed = [target.public() for target in self.targets]
        allowed += [{**target.public(), "targetKind": "doctest"}
                    for target in self.targets if target.kind == "lib"]
        if (isinstance(value, dict) and value in allowed
                and not any(self.private(part) for part in value.values())):
            return value.copy()
        return UNVERIFIED

    def snapshot(self):
        """Bounded private state; active identity survives the event cap."""
        return {"events": self.events, "omitted": self.omitted, "unverified": self.unverified,
                "active": self.active, "harnessCompleted": self.harness_completed,
                "compilation": self.compilation, "executionStarted": self.execution_started}

    @classmethod
    def restore(cls, state, targets, private):
        """Rebuild only typed timing facts, never copy checkpoint fields to a fragment."""
        result = cls(targets, private)

        def seconds(value):
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("invalid timing offset")
            return value

        def optional(value):
            return None if value is None else seconds(value)

        if not isinstance(state, dict) or not isinstance(state.get("events"), list) or len(state["events"]) > MAX_EVENTS:
            raise ValueError("invalid timing checkpoint")
        for row in state["events"]:
            event = row["event"]
            if event not in {"start", "completion"}:
                raise ValueError("invalid timing event")
            rebuilt = {"binary": result._binary(row["binary"]), "event": event,
                       "wallSeconds": seconds(row["wallSeconds"])}
            if event == "completion":
                observation = row["observation"]
                if observation not in {"libtest-result", "next-cargo-target-upper-bound", "cargo-exit-upper-bound"}:
                    raise ValueError("invalid timing boundary")
                rebuilt.update(elapsedSeconds=seconds(row["elapsedSeconds"]), observation=observation)
            result.events.append(rebuilt)
        for key in ("omitted", "unverified"):
            if type(state[key]) is not int or state[key] < 0:
                raise ValueError("invalid timing count")
            setattr(result, key, state[key])
        active = state["active"]
        if active is not None:
            if not isinstance(active, list) or len(active) != 2:
                raise ValueError("invalid active timing target")
            result.active = result._binary(active[0]), seconds(active[1])
        if type(state["harnessCompleted"]) is not bool:
            raise ValueError("invalid harness state")
        result.harness_completed = state["harnessCompleted"]
        result.compilation = optional(state["compilation"])
        result.execution_started = optional(state["executionStarted"])
        return result

    def _emit(self, row):
        if len(self.events) < MAX_EVENTS:
            self.events.append(row)
        else:
            self.omitted += 1

    def _complete(self, wall, observation, *, retain=False):
        if self.active is not None:
            binary, started = self.active
            if not self.harness_completed:
                self._emit({"binary": binary, "event": "completion", "wallSeconds": round(wall, 3),
                            "elapsedSeconds": round(max(0, wall - started), 3), "observation": observation})
            if retain:
                self.harness_completed = True
            else:
                self.active = None

    def line(self, line, wall):
        line = ANSI.sub("", line)
        if FINISHED.fullmatch(line) and self.compilation is None:
            self.compilation = round(wall, 3)
            self.revision += 1
        running = RUNNING.fullmatch(line)
        docs = DOC_TESTS.fullmatch(line)
        if running or docs:
            self.revision += 1
            self._complete(wall, "next-cargo-target-upper-bound")
            if self.execution_started is None:
                self.execution_started = wall
            if running:
                path, executable = running.groups()
                stem = pathlib.PurePosixPath(executable).name
                artifact = re.fullmatch(r"(.+)-[0-9a-f]{16}(?:\.exe)?", stem)
                candidates = [target for target in self.targets if artifact and target.path == path
                              and target.name.replace("-", "_") == artifact[1].replace("-", "_")]
            else:
                candidates = [target for target in self.targets if target.kind == "lib" and target.name == docs[1]]
            if len(candidates) == 1 and not any(self.private(value) for value in candidates[0].public().values()):
                binary = candidates[0].public()
                if docs:
                    binary["targetKind"] = "doctest"
                binary = self._binary(binary)
            else:
                binary = UNVERIFIED
                self.unverified += 1
            self.active = binary, wall
            self.harness_completed = False
            self._emit({"binary": binary, "event": "start", "wallSeconds": round(wall, 3)})
        elif RESULT.match(line):
            # A result is the harness's completion boundary, but destructors or
            # exit hooks may still hang. Keep its identity until Cargo advances.
            self._complete(wall, "libtest-result", retain=True)
            self.revision += 1

    def finish(self, wall, timed_out):
        running = []
        if self.active is not None:
            binary, started = self.active
            if timed_out:
                running.append({"binary": binary, "elapsedSeconds": round(max(0, wall - started), 3),
                                "harnessResultObserved": self.harness_completed, "processExit": "not-observed"})
            else:
                self._complete(wall, "cargo-exit-upper-bound")
        return {"events": self.events, "eventsOmitted": self.omitted, "unverifiedBinaries": self.unverified,
                "compilationFinishedSeconds": self.compilation,
                "compilationObservation": "cargo-finished" if self.compilation is not None else "not-observed",
                "executionStartedSeconds": (round(self.execution_started, 3) if self.execution_started is not None else None),
                "executionElapsedSeconds": (round(max(0, wall - self.execution_started), 3)
                                            if self.execution_started is not None else None),
                "executionObservation": "first-cargo-target-to-command-end" if self.execution_started is not None else "not-observed",
                "runningAtTimeout": running, "wallSeconds": round(wall, 3)}


def is_test_command(command):
    return len(command) >= 2 and tuple(command[:2]) == ("cargo", "test") and "--no-run" not in command


def run(command, *, log, cwd, env, timeout, observations, checkpoint=None):
    """Observe the same merged stream previously written directly to a private file.

    A shared pipe preserves the write order of Cargo boundaries and harness results.
    One monotonic deadline covers compilation and execution. Killing and reaping
    the direct child on timeout preserves the lane's subprocess.run policy.
    """
    started = time.monotonic()
    revision = -1

    def persist():
        nonlocal revision
        if checkpoint is not None and observations.revision != revision:
            # Replace a bounded snapshot atomically. A supervisor can use the
            # previous complete snapshot even if SIGKILL interrupts this write.
            payload = json.dumps({"started": started, "state": observations.snapshot()}).encode("ascii")
            temporary = checkpoint.with_suffix(".tmp")
            with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as stream:
                stream.write(payload)
            temporary.replace(checkpoint)
            revision = observations.revision

    persist()
    pending = b""
    oversized = False
    timed_out = False
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, env=env) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(proc.stdout.fileno(), False)
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        timed_out = True
                        proc.kill()
                        break
                    ready = selector.select(min(remaining, 0.1))
                    for key, _ in ready:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            if pending and not oversized:
                                observations.line(pending.decode("utf-8", "replace"), time.monotonic() - started)
                                persist()
                            continue
                        log.write(chunk)
                        log.flush()  # supervisor recovery must see output before the wrapper exits
                        for part in chunk.splitlines(keepends=True):
                            if not oversized:
                                pending += part
                                if len(pending) > MAX_LINE:
                                    pending = b""
                                    oversized = True
                            if part.endswith(b"\n"):
                                if not oversized:
                                    observations.line(pending.decode("utf-8", "replace").rstrip("\r\n"),
                                                      time.monotonic() - started)
                                pending = b""
                                oversized = False
                        persist()
                    # Cargo may exit while a descendant still holds a pipe. Do not
                    # add a wait that the former file-backed run did not have.
                    if not ready and proc.poll() is not None:
                        break
                try:
                    code = proc.wait(timeout=max(0, timeout - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    proc.kill()
                    code = proc.wait()
        except BaseException:
            proc.kill()
            proc.wait()
            raise
    wall = time.monotonic() - started
    timing = observations.finish(wall, timed_out)
    observations.revision += 1
    persist()  # Also retain completion if the supervisor interrupts publication.
    return subprocess.CompletedProcess(command, 124 if timed_out else code), timed_out, timing
