# X-trace: current state

The one place for "where are we". Rewrite it (do not append) at the end of every working session. History lives in
`docs/progress.md` and in git. Last updated: 2026-11-11.

## Release status

- Target: **v0.01** (package version 0.0.1). Acceptance is the 55-row ledger `evidence/v0.01/requirements.json`
  (issue #1). **0 of 55 rows are accepted**: 35 in progress, 8 not started, 6 failing, 6 blocked.
- Failing rows: JAVA-MVC, REPLAY-SOURCE, REPLAY-OUTCOME, REPLAY-TUI, CAMPAIGN-PETCLINIC, CAMPAIGN-FINERACT.
- Blocked rows: EXPORT-POSTMAN (credentials), PLATFORM-LINUX (release key), HUMAN-USABILITY (participants),
  HUMAN-OWNER, REVIEWS-EXACT, DISTRIBUTED-RECHECK (end of release).
- How work happens now: ADR 0012 (Codex workers, Claude orchestrator, heavy tests on GitHub, pull requests,
  merge rules scaled to risk, GitHub issues for tickets and wave tracking).
- The owner decided on 2026-11-11 that development CI is Linux-only (ADR 0012 amendment). Merges require Linux
  `ci-ok` and clean reviews. Before release, the owner runs `tools/dev/macos-release-check.sh` locally on a Mac
  and fixes failures. Remaining macOS failures are deferred to that check.

## Work map (GitHub issues)

Older docs also name this work as sessions S1–S7, phases P01–P10, slices 1–9 and waves. Use issue numbers in new
work.

| Issue | Session | Phases | Scope | Key ledger rows |
|---|---|---|---|---|
| #3 | S1 | P01–P02 | Core evidence contracts + real Spring MVC replay (Petclinic) | JAVA-MVC, REPLAY-SOURCE/LINE/FRAMES/OUTCOME/NAV, CAMPAIGN-PETCLINIC |
| #4 | S2 | P03 | Static/runtime catalog, history, basic Canvas + TUI | CATALOG-*, REPLAY-CANVAS, REPLAY-TUI |
| #5 | S3 | P04 | Java breadth: WebFlux, Servlet/Jersey, interactions, launchers, attach | JAVA-*, MATRIX |
| #6 | S4 | P05 | Node: loader, HTTP/Express/Fastify/Nest, sources, interactions, workers | NODE-*, PROCESS-LINKAGE |
| #7 | S5 | P06–P07 | Replay UX, accessibility, performance, exports, exercise | REPLAY-*, UX-ACCESSIBILITY, PERFORMANCE, EXPORT-*, EXERCISE-* |
| #8 | S6 | P07B–P08 | Release-candidate packages + six real campaigns on one build | INSTALL-*, CAMPAIGN-* |
| #9 | S7 | P09–P10 | Hardening, supply chain, platforms, humans, final reviews, publish | RECOVERY-*, SECURITY-*, PRIVACY-*, PLATFORM-*, SUPPLY-CHAIN, HUMAN-*, REVIEWS-EXACT |

Epic: #2. Close an issue only when every box is ticked with evidence on merged `main`.

## Wave 2 delivered

PR #38 merged as `f92f0bf`. It delivered Spring MVC capture on Petclinic, export, lifecycle, focused capture,
a durable journal, a CI diagnostics channel, and the macOS native ACL fast path in `xtrace-macos-acl`.
Linux `ci-ok` passed on `8d2a9b1` in run `43024028230`; both release floors passed 23/23.
The Petclinic campaign in run `43024105219` passed 37 of 45 steps. The other eight were reported, not passed.

## Next work, in order

Start Wave 3 on `wave/w3`. Read issue #3 first, then #4. Finish the remaining #3 Petclinic campaign gaps:

- `baseline-jar-sha-vs-pinned`: the observed jar hash differed from the pinned hash.
- `unpaced-load-not-exercised`: serial requests were paced; the agent admits at most eight unwritten recordings.
- `analyzer-source-accommodation`: the analyzer was built from source, not shipped in the candidate package.
- `tui-navigation-accommodation`: routes were checked in detail, not in the list.
- `overhead-measurement`: paced load and possible capture drops qualify the measurement; no budget was applied.
- `flow-accommodations`: flows used request budgets, pacing and an acknowledged database wait.
- `privacy-scope`: focused capture and exception message redaction have the reported scope.
- `campaign-receipt-artifact`: the receipt was unsigned and non-release.

Carry forward the two review minors: the caught-panic test hard-codes line 171 in `scope.rs`, and a store test
mutex can be poisoned after a workload failure. The ctime-only admission refusal is still unexplained; diagnostics
now attribute it. Investigate the deferred macOS failures at the release check.

Then work on #4, followed by #5 and #6 in parallel, #7, #8 and #9. Close an issue only when every box is ticked
with evidence on merged `main`.

## Known nondeterministic tests (fix; never retry to green)

- `crates/xtrace-cli/tests/lifecycle_journey.rs` `stale_record_naming_a_zombie_is_cleaned_up_by_stop_and_restart`
  (#14): the test now waits for the zombie state and its failure message shows the exit code and stderr, but the
  2026-10-10 failure's cause is unproven. If it recurs, read that message first.
- `adapters/java/attach-helper` `JavaAttachAcceptanceTest` still picks a free port before starting the Spring
  fixture, the race fixed in #21 for the Rust journeys (#22).

## Branches

- Wave 3 starts on `wave/w3`, from main at `f92f0bf`.
- Wave branches (`wave/<n>`) are deleted after their merge and a green post-merge `main`.

## Waiting for the owner

- D1 answered 2026-11-09: compile only locally; tests run on GitHub.
- D3 answered 2026-11-09: risk-scaled merge reviews accepted; full ADR 0006 protocol only for release candidates.
- D2 amended 2026-11-11: Linux CI gates development merges; the owner checks macOS locally at release.
- Ratify: ADR 0008 Amendment 1, the first ADR 0006 addendum of 2026-10-10, the ADR 0009 addendum, ADR 0011, and the
  migration renumbering (v9 = `recording_limitations`, v10 = `session_health`, catalog links take the next free version).
- Usability question Q5 asks which Canvas node "took the longest", but the product records no per-node time
  (honesty rule R2). Either change the question or add real per-frame timing.
- For the release: an Ed25519 release/ledger key and trust configuration, at least two usability participants plus a
  scorer, the owner's review of the named journeys (`docs/owner-review/README.md`), and optional Postman credentials.
- UI: Figma-style mocks are being made in Claude Design. The chosen design becomes the spec for #7.
