# Synthetic replay scale fixture (#94)

This test-only helper creates a **new** private scratch project with the actual `xtrace init`,
writes 10,000 synthetic call entry/exit events through `SqliteRecordingPersistence`, and finishes
with the ordered event-ID digest and the existing standard event cap (16,384). It creates no
product command, opens no existing project, uses no direct SQL and is absent from package output.
Every symbol is labeled `SyntheticReplayScale`; no source lines, values, request duration or
real-application timing are claimed.

The input contains 500 balanced, 20-event call trees, with ten distinct symbols, three distinct
entry siblings under each request, and explicit fixture parent event IDs (maximum indexed depth
three). Request roots have children and sibling leaf symbols differ, preventing the Map's
adjacent identical sibling-leaf rule from collapsing the input into one repeated node.

The regression reads all frames through actual CLI `recording show --limit 200` cursor pages.
It verifies exactly 10,000 distinct frame identities, event order and cross-page previous/next
edges, terminal completion, the persisted event cap/count and zero capacity/adapter drops. An
independently reopened store then exercises the same `aroundFrame` and frame-navigation use
cases used by the viewer, with the anchor three frames from the end. This proves synthetic
replay correctness only. It does not measure DOM size, rendering, latency or a real framework.
Every frame's observed parent identity, kind, symbol and depth is checked; the first window
also checks the three different request-child symbols. Page and first-window counts are
reported as observed, rather than assuming 50 full pages: the production 256-KiB event-projection
cap and 16-MiB verified-input cap can bound a page before its 200-event limit. The regression
checks serialized projection width against the production constant. Backward cursors belong
to #95; this fixture verifies forward pagination and `aroundFrame` independently.

## Focused Linux hosted check

Prerequisites: a Linux runner, the repository's Rust toolchain/native Rust build prerequisites,
locked Cargo dependencies, and existing owner-only dev cache and short scratch roots as
described in `tools/dev/README.md`. Source the dev environment in the same shell. Java/Node
adapters, a browser and a package build are **not** needed for this focused test.

```bash
source tools/dev/env.sh
cargo test --locked -p xtrace-cli --test replay_scale \
  synthetic_ten_thousand_frames_are_complete_ordered_and_navigable \
  -- --exact --nocapture
```

Run this on GitHub Actions, not on a development Mac. The test emits one aggregate line named
`synthetic_replay_scale` with verified frame count, first-window size, page count, near-tail
window size, completion and capacity drops. It never prints project paths or event bodies.
Keep raw runner diagnostics private; a job summary may contain the aggregate line and the
command's real exit status. Do not reinterpret a failed or unreached test as a pass.

## Retain this same store for later embedded-viewer measurement

To keep the newly generated project after the check passes, set a **new** private manifest file
directly inside the admitted scratch directory before the same command:

```bash
source tools/dev/env.sh
export XTRACE_SCALE_FIXTURE_MANIFEST="$XTRACE_TEST_PRIVATE_SCRATCH/replay-scale.json"
cargo test --locked -p xtrace-cli --test replay_scale \
  synthetic_ten_thousand_frames_are_complete_ordered_and_navigable \
  -- --exact --nocapture
```

The manifest is created with mode 0600 and `create_new`; an existing file or symlink is refused.
The helper retains only its fresh, randomly named mode-0700 fixture directory. Without this
variable, the temporary project is removed on drop. The private manifest contains
`fixture_root`, `project_dir`, `data_home`, `project_id`, `recording_id`, `verified_frame_count`
and an explicit synthetic label. Never publish or upload the manifest or store.

A later measurement can read the manifest privately, set `XTRACE_DATA_HOME` to its `data_home`,
and pass its `project_dir` to the supported `xtrace open --project-dir` path. Select its
`recording_id`; do not create a replacement database or mock API. Browser/DOM evidence must
be collected and assessed separately. The test starts no daemon and leaves no process running.

Optionally set `XTRACE_SCALE_XTRACE` to an absolute path to a supported, installed `xtrace`
binary before running the test. Both initialization and every cursor-page read then use that
binary, while writes still use this checkout's persistence implementation. This requires
matching schema/package compatibility. It is not, by itself, an installed-viewer journey.
