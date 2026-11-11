"""CI floor entry point with task-scoped Rust diagnostics, using the lane publisher.

Both execution and strict receipt validation use the same instrumented gate list.
The underlying supervisor, 23 gates, flags and budgets remain in run_gates; build
and package tasks never receive the test-only feature or diagnostics directory.
"""
from __future__ import annotations

import argparse
import contextlib
import pathlib
import sys
from dataclasses import replace

from tools.release import ci_floor, run_gates

RUST_TEST_GATES = frozenset({"rust-cli-spring-journey", "rust-focused", "rust-workspace"})
DIAGNOSTIC_FEATURE = "xtrace-private-storage/ci-diagnostics"


def instrumented_gates(gates, root: pathlib.Path, timeout: int):
    """Wrap only Rust tests; insert Cargo options before any libtest arguments."""
    result = []
    for gate in gates:
        if gate.name not in RUST_TEST_GATES:
            result.append(gate)
            continue
        if (gate.argv[:2] != ("cargo", "test") or "--release" in gate.argv
                or any(arg == "--profile" or arg.startswith("--profile=") for arg in gate.argv)):
            raise ValueError("floor diagnostics require a debug Cargo test gate")
        command = list(gate.argv)
        boundary = command.index("--") if "--" in command else len(command)
        command[boundary:boundary] = ["--features", DIAGNOSTIC_FEATURE]
        wrapped = ("python3", "-B", "-m", "tools.qa.lane_run", "run", "--suite", "rust", "--step", gate.name,
                   "--out", str(root / "frag"), "--private-log-dir", str(root),
                   "--ci-diagnostics", "--timeout", str(timeout), "--", *command)
        result.append(replace(gate, argv=wrapped))
    return tuple(result)


@contextlib.contextmanager
def configured_floor(root: pathlib.Path, timeout: int):
    original = run_gates.GATES
    run_gates.GATES = instrumented_gates(original, root, timeout)
    try:
        yield
    finally:
        run_gates.GATES = original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "sanitize-floor"))
    args, forwarded = parser.parse_known_args()
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--cache-root" if args.action == "run" else "--root", required=True)
    # Match the supervisor's existing per-command deadline; the outer supervisor
    # still enforces it, including wrapper overhead and process-tree cleanup.
    options.add_argument("--command-timeout", type=int, default=7200)
    known, remaining = options.parse_known_args(forwarded)
    root = pathlib.Path(known.cache_root if args.action == "run" else known.root)
    if args.action == "sanitize-floor":
        # The QA option belongs to the gate configuration, not ci_floor's parser.
        forwarded = ["--root", known.root, *remaining]
    with configured_floor(root, known.command_timeout):
        original_argv = sys.argv
        sys.argv = [original_argv[0], *([] if args.action == "run" else ["sanitize-floor"]), *forwarded]
        try:
            return run_gates.main() if args.action == "run" else ci_floor.main()
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    raise SystemExit(main())
