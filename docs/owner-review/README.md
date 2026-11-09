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
| fresh_install | Install the package in a clean profile, `xtrace init`, `xtrace --version`, uninstall | no leftovers outside the install root and data home | package workflow, install journey (Linux x86_64 only since 2026-10-10) |
| linear_canvas_tui | Open the viewer on the petclinic recording; Linear, then Canvas, then `xtrace tui` | the same request, outcome and frames in all three; no horizontal scroll at phone width | campaigns workflow browser screenshots at 320, 736 and 1280 px, TUI PTY transcript |
| attach_failure | Start the app with a wrong or missing agent path | a clear refusal with a stable error code, the app unharmed | none listed here; check the Rust suites of the lane workflow |
| partial_capture | Kill the app mid-request | a recording sealed as partial, shown as partial in all views | none listed here; check the Rust suites of the lane workflow |
| exercise | Run `xtrace exercise` | exercised routes listed, recordings produced | not yet automated here |
| exports | Export OpenAPI, Postman, cURL and a developer bundle; open the results in the target tools | routes and path parameters in OpenAPI; placeholder requests in Postman; shell recipes in cURL; all three plus hashes, counts and omissions in the bundle; no secret appears | `export-formats` and the privacy scan in the campaigns workflow |

For exports, use `xtrace export --format <FORMAT> --preview` first, then
`--output <DIR>` with a fresh or empty private directory (0700). Non-empty
destinations are refused. Publication uses one directory rename; files are 0600.
Check that a route is observed only in its recorded component and binding.
All known handler symbols and conflicts must be visible. Single-claim handlers
keep their source start line. End lines, multi-claim locations and individual
confidence are unavailable through the read port and must appear as gaps,
with the highest confidence named explicitly.
OpenAPI cannot hold two operations at the same method/path: inspect its
omissions and count. Postman and cURL retain both scopes. The bundle manifest
has counts per format and a null policy digest with an omission when unavailable.
No format includes observed bodies. Missing revisions or operations exit 3;
invalid usage exits 2; a secret-shaped value exits 8 without writing output.

## Reading a campaigns run honestly

- A step marked `not-implemented` means the product could not do it; it is not a pass and not a skip.
- The privacy scan is clean only when every required surface was scanned and found at least one file; the step note
  records only the exit code. Classes, file counts and hit locations (never a canary value) are in the CI log and in
  `privacy-canary-report.json`; a second scan of the exact upload tree (`privacy-canary-report-final.json`) runs last, and
  on any hit CI uploads only the reports and a summary without notes.
- Receipts uploaded by CI are marked NON-RELEASE and unsigned. They never replace `evidence/v0.01`.

## Sign-off (owner fills in)

Build id: ______  Artifact set sha256: ______  Date: ______
Journeys passed: fresh_install [ ]  linear_canvas_tui [ ]  attach_failure [ ]  partial_capture [ ]  exercise [ ]  exports [ ]
Notes:
