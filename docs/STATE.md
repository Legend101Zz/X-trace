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
- Development merges require Linux `ci-ok` and clean reviews. Do not wait for, trigger or require macOS CI.
  At release, the owner runs `tools/dev/macos-release-check.sh` locally on a Mac; fix failures before release.
- The per-check `/bin/ls` cost was found and replaced by native ACL checks. The JDK 21 macOS suite took 718 s on
  `a7a4268`, down from over 3000 s. Remaining macOS test failures are deferred to the release check.

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

## Next work, in order

1. **Wave 2 = #3:** finish the three pushed, unmerged branches. Merge `origin/main` into each; never rebase pushed
   history.
   - `ultra/r2w2-qb`: real Petclinic harness flows and product outcome kinds.
   - `ultra/r2w2-xb`: `xtrace export` for OpenAPI/Postman/cURL.
   - `ultra/r2w2-jb`: final HTTP status read after view rendering, and source roots relative to the project. Not yet
     reviewed.

   Then the product gaps: Spring Data repository frames (JDK proxies), the agent's limit of 8 unwritten
   recordings, TUI rows showing only ids, line events not reaching the read API. Done when the Petclinic campaign
   is green with zero not-implemented steps.
2. **#4**, then **#5** and **#6** in parallel, then **#7** (the UI is built from the new design handoff), **#8**,
   then **#9**.

Wave 1 (#18, PR #20, merged as `931f917`) removed the races behind the scan, Node HTTP, release-tool runner,
`pack_inventory` and Spring fixture test failures (#12, #13, #15, #16, #21), recorded the owner's ADR 0012 answers
(#17) and added the hosted macOS workflow (#19). Its head passed `ci-ok` on three runs and `macos-ok`.

## Known nondeterministic tests (fix; never retry to green)

- `crates/xtrace-cli/tests/lifecycle_journey.rs` `stale_record_naming_a_zombie_is_cleaned_up_by_stop_and_restart`
  (#14): the test now waits for the zombie state and its failure message shows the exit code and stderr, but the
  2026-10-10 failure's cause is unproven. If it recurs, read that message first.
- `adapters/java/attach-helper` `JavaAttachAcceptanceTest` still picks a free port before starting the Spring
  fixture, the race fixed in #21 for the Rust journeys (#22).

## Branches

- On 2026-11-09, with the owner's approval, about 130 merged or throwaway remote branches were deleted. Only
  `main` and the unmerged keepers `ultra/r2w2-qb`, `ultra/r2w2-xb`, `ultra/r2w2-jb` remain. `ultra/r2w3-r4` is
  gone; it raised a test deadline and added a retry.
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
