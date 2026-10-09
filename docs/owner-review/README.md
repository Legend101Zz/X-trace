# Owner review checklist (HUMAN-OWNER)

Status: checklist only. The owner has not reviewed anything through it. Receipts for HUMAN-OWNER require the
`release-owner` signature over `reviewedJourneys` that include all six named journeys below, bound to the accepted
release build id and artifact set hash. CI artifacts help the owner look; they are never the review.

## How to use

For each journey: perform it yourself on the candidate package, note the build id shown by `xtrace --version`, and
tick it only if what you saw matched the expectation. Anything unclear is a no, written down.

## Journeys (names are fixed by `tools/release/check_ledger.py`)

| Journey id | Do this | Expect | Where CI shows a rehearsal |
|---|---|---|---|
| fresh_install | Install the package in a clean profile, `xtrace init`, `xtrace --version`, uninstall | no leftovers outside the install root and data home | package workflow, install journey |
| linear_canvas_tui | Open the viewer on the petclinic recording; Linear, then Canvas, then `xtrace tui` | the same request, outcome and frames in all three; no horizontal scroll at phone width | campaigns workflow browser screenshots at 320, 736 and 1280 px, TUI PTY transcript |
| attach_failure | Start the app with a wrong or missing agent path | a clear refusal with a stable error code, the app unharmed | none listed here; check the Rust suites of the lane workflow |
| partial_capture | Kill the app mid-request | a recording sealed as partial, shown as partial in all views | none listed here; check the Rust suites of the lane workflow |
| exercise | Run `xtrace exercise` | exercised routes listed, recordings produced | not yet automated here |
| exports | Export every format and open the results in the target tools | files open; no secret appears in them | `export-formats` and the privacy scan in the campaigns workflow |

## Reading a campaigns run honestly

- A step marked `not-implemented` means the product could not do it; it is not a pass and not a skip.
- The privacy scan is clean only when every required surface was scanned and found at least one file; the step note
  lists classes and file counts, never a canary value.
- Receipts uploaded by CI are marked NON-RELEASE and unsigned. They never replace `evidence/v0.01`.

## Sign-off (owner fills in)

Build id: ______  Artifact set sha256: ______  Date: ______
Journeys passed: fresh_install [ ]  linear_canvas_tui [ ]  attach_failure [ ]  partial_capture [ ]  exercise [ ]  exports [ ]
Notes:
