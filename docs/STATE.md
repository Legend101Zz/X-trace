# X-trace: current state

The one place for "where are we". Rewrite it (do not append) at the end of every working session. History lives in
`docs/progress.md` and in git. Last rewritten: 2026-11-09.

## Release status

- Target: **v0.01** (package version 0.0.1). Acceptance is the 55-row ledger `evidence/v0.01/requirements.json`
  (issue #1). **0 of 55 rows are accepted**: 35 in progress, 8 not started, 6 failing, 6 blocked.
- Failing rows: JAVA-MVC, REPLAY-SOURCE, REPLAY-OUTCOME, REPLAY-TUI, CAMPAIGN-PETCLINIC, CAMPAIGN-FINERACT.
- Blocked rows: EXPORT-POSTMAN (credentials), PLATFORM-LINUX (release key), HUMAN-USABILITY (participants),
  HUMAN-OWNER, REVIEWS-EXACT, DISTRIBUTED-RECHECK (end of release).
- How work happens now: ADR 0012 (Codex workers, Claude orchestrator, heavy tests on GitHub, pull requests,
  merge rules scaled to risk).

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

1. **Make main's CI clean.** Fix the nondeterministic tests below deterministically: inject clocks and process
   snapshots, have tests remove their own scratch, and have the `pack_inventory` test list only a directory it owns.
   Prove each fix with at least three CI runs on the exact head.
2. **#3:** finish the three pushed, unmerged branches. Merge `origin/main` into each; never rebase pushed history.
   - `ultra/r2w2-qb`: real Petclinic harness flows and product outcome kinds.
   - `ultra/r2w2-xb`: `xtrace export` for OpenAPI/Postman/cURL.
   - `ultra/r2w2-jb`: final HTTP status read after view rendering, and source roots relative to the project. Not yet
     reviewed.

   Then the product gaps: Spring Data repository frames (JDK proxies), the agent's limit of 8 unwritten
   recordings, TUI rows showing only ids, line events not reaching the read API. Done when the Petclinic campaign
   is green with zero not-implemented steps.
3. **#4**, then **#5** and **#6** in parallel, then **#7** (the UI is built from the new design handoff), **#8**,
   then **#9**.

## Known nondeterministic tests (fix; never retry to green)

- `tools/release/test_release_tools.py` `RunnerTests` process-tree tests (slow runners).
- `crates/xtrace-cli/tests/node_run_http.rs` `auto_mode_records_cjs_and_esm_entries_once_each`.
- `crates/xtrace-cli/tests/lifecycle_journey.rs` `stale_record_naming_a_zombie_is_cleaned_up_by_stop_and_restart`.
- `crates/xtrace-runtime/src/pack_inventory.rs`
  `partial_snapshot_copy_uses_production_cleanup_and_reports_uncertain_replacement`: it lists the whole shared test
  scratch under a 4,096-entry bound, so it fails once leftover scratch from other tests passes that bound.

## Branches

- Keep (unmerged work): `ultra/r2w2-qb`, `ultra/r2w2-xb`, `ultra/r2w2-jb`.
- Do not reuse `ultra/r2w3-r4`. It raised a test deadline and added a retry.
- Many `ultra/*` diagnostic and campaign-trigger branches remain on the remote. They are candidates for cleanup
  with the owner's approval.

## Waiting for the owner

- Confirm or change the ADR 0012 defaults:
  - D1: local unit tests allowed.
  - D2: a hosted macOS job replaces the leased Mac floor.
  - D3: merge rules scaled to risk.
- Ratify: ADR 0008 Amendment 1, the first ADR 0006 addendum of 2026-10-10, the ADR 0009 addendum, ADR 0011, and the
  migration renumbering (v9 = `recording_limitations`, catalog links = v10).
- Usability question Q5 asks which Canvas node "took the longest", but the product records no per-node time
  (honesty rule R2). Either change the question or add real per-frame timing.
- For the release: an Ed25519 release/ledger key and trust configuration, at least two usability participants plus a
  scorer, the owner's review of the named journeys (`docs/owner-review/README.md`), and optional Postman credentials.
- UI: Figma-style mocks are being made in Claude Design. The chosen design becomes the spec for #7.
