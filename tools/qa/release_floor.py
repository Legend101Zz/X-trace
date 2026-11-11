"""CI floor entry point with task-scoped Rust diagnostics, using the lane publisher.

Both execution and strict receipt validation use the same instrumented gate list.
The underlying supervisor, 23 gates, flags and budgets remain in run_gates; build
and package tasks never receive the test-only feature or diagnostics directory.

The supervisor finalizes timeouts after cleanup from private bounded checkpoints.
This keeps the original deadline and survives wrapper startup delays or SIGKILL;
an earlier inner timer alone cannot guarantee either. Recovery uses the same HEAD
validation, diagnostic reader, privacy scan and fragment publisher as normal runs.
"""
from __future__ import annotations

import argparse
import contextlib
import pathlib
import sys
from dataclasses import replace

from tools.qa import lane_run
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
    original_run = run_gates._run
    configured = instrumented_gates(original, root, timeout)
    wrapped = {gate.argv: lane_run.parser().parse_args(gate.argv[4:])
               for gate in configured if gate.name in RUST_TEST_GATES}

    def supervised_run(argv, **kwargs):
        args = wrapped.get(tuple(argv))
        if args is None:
            return original_run(argv, **kwargs)
        # The parent survives _run's deadline and process-tree cleanup. Capture
        # HEAD metadata here too: recovery must not attest a changed working tree.
        metadata = lane_run._checkout_metadata()
        directory = lane_run.prepare_recovery(root)
        kwargs["env"] = {**kwargs["env"], "XTRACE_LANE_RECOVERY_DIR": str(directory)}
        code, duration = original_run(argv, **kwargs)
        if code == 124:
            # Always replace even an existing fragment: the outer deadline may
            # have expired while the wrapper was publishing its normal result.
            lane_run.recover_timeout(args, directory, metadata, duration)
        return code, duration

    run_gates.GATES = configured
    run_gates._run = supervised_run
    try:
        yield
    finally:
        run_gates._run = original_run
        run_gates.GATES = original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "sanitize-floor"))
    args, forwarded = parser.parse_known_args()
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--cache-root" if args.action == "run" else "--root", required=True)
    # Keep the existing deadline. If it kills lane_run first, the supervising
    # process finalizes its checkpoint after the owned tree has drained.
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
