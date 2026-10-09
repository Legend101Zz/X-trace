# ADR 0010: Replay navigation extras, catalog CLI naming and one exit-code table

- Status: Accepted (contract owner, v0.01 unattended run, wave 1)
- Date: 2026-10-09
- Amends: `docs/plans/x-trace/03a-domain-and-storage.md` (replay navigation),
  `docs/plans/x-trace/03b-protocol-and-api.md` section 9.3 (routes) and
  `docs/plans/x-trace/03d` section 2 (CLI names and exit codes). This is the
  Gate 3 amendment note AGENTS.md requires for those three documents.
- Context: the approved Gate 3 text defines navigation, the replay routes and
  the CLI surface in prose. Implementing the v0.01 replay read model needs a
  few additions the text does not spell out, and two places where the code
  already follows a different convention than the planning text. None of them
  weakens a promise the approved plan makes; this ADR records them so the next
  reader does not have to infer which side is authoritative.

## Decision

### 1. Navigation semantics conform to the approved text

`previous`, `next`, `into`, `over` and `out` keep the Gate 3 definitions in
03a: `into` is the next child frame, otherwise `next`; `over` is the first
subsequent frame at the same or lower depth; `out` is the first subsequent
frame below the current depth. They are resolved only by the server over the
frame index (migration v8: `depth`, `parent_seq`, `async_parent_seq`, `kind`,
`honesty_flags`, `indexed_v`). Clients never infer the tree. "Go to parent" is
a separate client action that uses the `parentFrameId` the server exposes.

The wire form of a navigation result is internally tagged: `{"state":"target",
"frameId":...}`, `{"state":"boundary"}` or `{"state":"unavailable","reason":...}`
with the closed reason set `partial_frontier`, `legacy_unindexed`,
`depth_overflow`, `orphan_parent`, `not_navigable`. `target` and `boundary` are
byte-identical to the previous encoding; `unavailable` gains the reason.

Honesty rules that bind the implementation: a parent exists only when it was
observed (an unobserved parent makes the frame a root flagged
`orphan_parent`); `next` past the last persisted frame of a recording that is
not verified complete is `unavailable{partial_frontier}`, never `boundary`;
rows written before migration v8 stay `indexed_v = 0` and answer
`unavailable{legacy_unindexed}` for `into`, `over` and `out` while
`previous`/`next` keep working; there is no backfill and no subtree column.

### 2. Additive extras beyond the approved routes

The approved routes `navigate`, `frames` and `graph` are implemented as
written. The following are additive and are the part this ADR newly accepts:

- `GET /api/v1/recordings/{id}?aroundFrame=<frameId>`: a window whose middle
  element is the anchor frame; mutually exclusive with `cursor`; sets
  `anchorFrameId`.
- `GET /api/v1/recordings/{id}?projection=structure`: outline fields only
  (sequence, frame ids, depth, kind, symbol, monotonic time, gap, source
  binding, line, whether bindings exist), no navigation table, so a large
  recording's outline fits a small number of calls.
- `GET /api/v1/recordings/{id}/frames/{frameId}/navigation`: every action of
  one frame in a single call.
- The `kinds=` filter on `previous`/`next` and the `kind=gap|error|interaction`
  plus `dir=next|previous` jump on `navigate`.

Until the server populates them these routes are registered and answer
`501 XTR-REPLAY-NOT-IMPLEMENTED` behind the same origin, client-header and
session guards as every other viewer route. A 501 is never a success shape.

### 3. Catalog CLI naming diverges from 03d section 2

03d names the catalog commands `history runs|catalog|compare` and
`endpoint list --revision`. The CLI registers `xtrace catalog
list|history|diff|conflicts|runs` and `xtrace scan`. The catalog lane may remap
names to the 03d spellings inside its own module without a new decision; the
registered top-level entries and their stub behaviour do not change.

### 4. One exit-code table

The CLI has exactly one mapping from error category to exit code
(`exit_code_for_category` in `crates/xtrace-cli/src/error.rs`):

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | internal error or cancelled |
| 2 | validation (invalid argument, malformed input) |
| 3 | not found |
| 4 | conflict or corruption |
| 5 | resource or transport |
| 6 | compatibility (schema or protocol mismatch) |
| 7 | permission |
| 8 | policy (including "approval required") |
| 9 | not implemented (`CliError::NotImplemented`, `XTR-CLI-NOT-IMPLEMENTED`) |
| 10 | partial result (`CliError::Partial`, `XTR-CLI-PARTIAL`) |

The numbers in 03d for approval-required and partial results are superseded by
8 and 10 respectively. Commands registered ahead of their implementation exit 9
with a message; they never exit 0 and never print a success document.

## Consequences

- X and the TUI may rely on the 501 routes existing and on the encoding of
  navigation results; they must treat a 501 as "not available in this build".
- The server-side navigation implementation, the vector files and the
  population of migration v8 follow in later increments; this ADR is the
  prerequisite for authoring the navigation vectors.
- Reading the planning text and the code disagree only in the places listed
  here; everywhere else the approved text stands.
