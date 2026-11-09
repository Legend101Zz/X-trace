# xtrace-cli: notes for agents

- The `xtrace` binary. Commands live in `src/commands.rs` plus one module per command family (`attach.rs`,
  `scan.rs`, `catalog_cmd.rs`, `tui.rs`, `export.rs`, `exercise.rs`, ...). Output is one JSON document on stdout, and an
  error is one JSON document on stderr with an `XTR-...` code. Exit codes follow ADR 0010 §4; `9` means "not implemented".
- Integration tests (`tests/*.rs`) spawn the real binary. These need no built adapters: `daemon_command`,
  `doctor_journey`, `record_scope`, `scan_fixture`, `stub_commands` (and mostly `lifecycle_journey`). Every other test
  needs the built Java agent/fixture, the Node packages and/or Playwright Chromium (`tools/dev/prep.sh --adapters
  --browsers`). Run those on CI.
- `java_run_spring` must run with `--test-threads=1`.
- Tests that run `init` panic without `XTRACE_TEST_PRIVATE_SCRATCH` ("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is
  required"). Source `tools/dev/env.sh` first.
- Known nondeterministic tests here: `node_run_http.rs` `auto_mode_records_cjs_and_esm_entries_once_each` and
  `lifecycle_journey.rs` `stale_record_naming_a_zombie_is_cleaned_up_by_stop_and_restart` (see `docs/STATE.md`).
