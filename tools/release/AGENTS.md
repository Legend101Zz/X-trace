# tools/release: notes for agents

- Python stdlib only; run modules as `python3 -B -m tools.release.<name>` from the repo root.
- `run_gates.py` is the 23-gate floor (the `GATES` tuple). `ci_floor.py` provides CI glue for Linux and hosted macOS.
  `check_ledger.py` checks the release ledger and pins a digest of the requirement-row contracts, so changing a row's
  `requirement` text means updating that pinned digest and its tests in the same change. `leased_run.py` and
  `private_roots.py` admit only private roots on volumes with ownership enabled.
- `test_release_tools.py` is about 5,900 lines; CI runs its classes with `XTRACE_TEST_SCRATCH_ROOT` from
  `tools/dev/env.sh`.
- The `RunnerTests` process-tree tests are known to be nondeterministic on slow runners (`docs/STATE.md`). Fix them
  with injected process snapshots and clocks, never with retries or longer deadlines.
