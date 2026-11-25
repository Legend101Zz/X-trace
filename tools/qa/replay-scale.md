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

## Embedded browser measurement (#98)

`tools/qa/replay_scale_browser.mjs` consumes that retained private manifest and starts the
normal foreground `xtrace open --viewer --no-browser` with its project directory and data
home. It uses the existing `web/app/node_modules/@playwright/test` installation and its
Chromium browser. Run on Linux GitHub Actions after the focused #94 verification, a build of
the intended embedded viewer (or a supported package installation), and browser prerequisites.
No Vite server, request mocking, direct database reads or production instrumentation is used.

```bash
source tools/dev/env.sh
node tools/qa/replay_scale_browser.mjs \
  --manifest "$XTRACE_SCALE_FIXTURE_MANIFEST" \
  --xtrace "$XTRACE_MEASUREMENT_BINARY" \
  --out "$XTRACE_TEST_PRIVATE_SCRATCH/replay-browser.json" \
  --source-sha "$XTRACE_MEASUREMENT_SOURCE_SHA" \
  --provenance source-built \
  --later-pages 12 --cdp-heap
```

All three input/output paths stay private. `--out` must be a new file; output is mode 0600.
`--source-sha` is the coordinator's declared 40-character product-source revision; it is not
inferred from this script's checkout. The driver computes the actual executable SHA-256.
For an installed product, use `--provenance installed --package-sha256 "$XTRACE_PACKAGE_SHA256"`;
the package hash is declared by the caller and must come from independently verified package
bytes. The report distinguishes declarations from the measured binary hash. No path, token,
URL, trace body, screenshot or raw error text is emitted. Do not upload the manifest/store.

Flags: `--manifest`, `--xtrace`, `--out`, `--source-sha` and `--provenance` are required.
`--package-sha256` is required for installed provenance; `--cdp-heap` is optional.
`--later-pages` accepts 1–49 additional pages and defaults to 12. Twelve crosses the current
2,000-event retained-window cap with 200-event responses; the report records actual returned
and mounted counts rather than assuming those widths. Every requested later load must execute.
There are always five attempts, each with a new foreground viewer, browser process, context
and page. Failures are retained; attempts are never repeated. An unreached action fails its
journey rather than becoming a timing sample. Exit 0 means all functional journeys were
exercised, 1 means at least one failed, and 2 means setup or output failed. Timing overruns are
reported individually; these exit codes do not decide the unsettled performance aggregation.

The fixed baseline is headless Chromium, 1440×900 CSS pixels, scale factor 1, en-US, UTC,
light color scheme, normal motion and no CPU/network throttling. Browser processes and caches
are fresh per sample; OS/filesystem caches are uncontrolled and may be warm. Catalog loading,
fixture generation and viewer startup precede timing. A synchronous capture listener records
`performance.now()` on the actual trusted recording click. The end uses that same clock,
after the selected first step remains visible with the correct recording and inspector event
identity across two requestAnimationFrame callbacks. This observes an intervening rendering opportunity,
not physical display completion. No scroll, forced click, CSS alteration or DOM replacement is
used to make the initial row visible. A layout that hides it fails; #97 may need integration.

The exact successful detail response is checked against the manifest project/recording,
cursor, completion, capacity and synthetic event identities. The visible selected sequence
and inspector identity match its first event; the Map's selected frame subsequently matches
that same response frame. Identity digests bind private events without serializing their IDs.
After the initial measurement, actual Steps/Map buttons and Next/Back navigation must work
in both modes. Later pages are loaded through the real button and each newly returned window
is selected through an actual row click, then navigation and both mode switches are repeated.
Playwright may scroll normal controls into view for these untimed actions. No API fixture or
fallback to another recording replaces an unreachable action.

The mode-0600 JSON file and stdout contain the same sanitized schema-version-1 report:

- `provenance`: declared source/package and computed executable hashes.
- `conditions`: browser/viewport/runner CPU, timing, cache and DOM measurement scopes.
- `samples`: all five attempts, bounded stage/failure codes, validated initial milliseconds,
  relation to 1,500 ms, API first-window count and selected-identity digest; successful actions
  and DOM snapshots for initial/later Steps, Map and return to Steps. `initial` is null when
  initial measurement was not established. A later failure retains valid initial timing.
- Each DOM snapshot separates cumulative API events and the last API window from the loaded
  rail label, mounted rail rows, viewport-hit-tested visible rows, SVG graph nodes, accessible
  tree rows, visible tree rows and all document elements. Counts cover the current DOM and
  mode, not the whole recording or React heap. Optional CDP `Runtime.getHeapUsage` reports
  this page target's JS heap separately; it is not browser RSS, a forced-GC result or a budget.
  Unsupported heap measurement has an explicit status.
- `summary`: valid initial and complete-journey counts, functional failure count, descriptive
  median/max initial milliseconds and count over 1,500 ms. Failed initial attempts remain
  visible and contribute no invented time. Aggregation and memory thresholds stay unsettled.

A synthetic baseline does not establish real-framework stress performance, installed-package
behavior unless installed provenance was exercised, or release acceptance. Those journeys
remain separate evidence under #7.
