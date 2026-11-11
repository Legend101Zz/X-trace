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

## Wave 3 handoff

[Draft PR #70](https://github.com/Legend101Zz/X-trace/pull/70) tracks `wave/w3`; the tracker is
[#69](https://github.com/Legend101Zz/X-trace/issues/69). Main remains at `f92f0bf`. Wave changes are not merged:

- `ef29c58` implements the two carried review minors. Independent review found no issues.
- `94fa938` implements [#22](https://github.com/Legend101Zz/X-trace/issues/22) attach port and readiness
  diagnostics. The Java attach-helper and four Rust test binaries compile; formatting and diff checks passed.
  No tests ran locally. #22 remains open. Both readiness reviews are complete, with no blocker or major findings.
  One review has no actionable findings. The other found a minor race at
  `crates/xtrace-cli/tests/common/spring_readiness.rs:84`: stdout disconnect can be reported before the stderr
  reader samples an already-produced diagnostic. The existing test drains stderr before formatting the failure.
  Carry this to the next fix batch under the minor rule, preserving deadlines and bounded waiting on inherited pipes.

Post-merge main CI [43042206403](https://github.com/Legend101Zz/X-trace/actions/runs/43042206403), attempt 4,
completed with four failing jobs, all verified as apt DNS setup failures; tests were not reached in those jobs.
Only the failed jobs were rerun as attempt 5, which is pending.
The first wave CI [43057483505](https://github.com/Legend101Zz/X-trace/actions/runs/43057483505) on `6a46c76`
likewise failed apt DNS setup in release-tool-tests before tests; it provides no green acceptance.
Broader feature work and merge remain gated on green main and exact-head CI. No macOS CI is requested.

After infrastructure clears, finish [#3](https://github.com/Legend101Zz/X-trace/issues/3):

1. [#32](https://github.com/Legend101Zz/X-trace/issues/32): exact export claims and a truthful policy digest.
2. [#36](https://github.com/Legend101Zz/X-trace/issues/36): observed per-request burst correlation.
3. [#52](https://github.com/Legend101Zz/X-trace/issues/52): bounded observed cause types, with an explicitly
   scoped contract/ADR ticket.
4. Then [#4](https://github.com/Legend101Zz/X-trace/issues/4), followed by #5 and #6 in parallel, #7, #8 and #9.

Integrate and review the work, obtain exact-head Linux CI, and run a fresh packaged Petclinic campaign before
assessing #3 acceptance. Close an issue only when every box has evidence on merged `main`. See `docs/INDEX.md`
for the plans and release documents.

## Petclinic accommodations and remaining evidence

The Wave 2 campaign reported these gaps; they are not passes for missing evidence:

- The observed baseline jar hash differed from the pinned hash.
- Serial load was paced, with request budgets and an acknowledged database wait; unpaced load was not exercised.
  Possible capture drops qualify the overhead measurement; no budget was applied.
- The analyzer was built from source; packaging it belongs to #8. TUI routes were checked in detail, not in the list.
- Focused capture and exception message redaction have the reported privacy scope.
- The campaign receipt was unsigned and non-release. Release acceptance needs accepted campaign receipts.

The ctime-only admission refusal is still unexplained; diagnostics now attribute it.

## Known nondeterministic test (fix; never retry to green)

[#14](https://github.com/Legend101Zz/X-trace/issues/14) remains open: the historical zombie lifecycle failure log lacks the
actual stop status and stderr, so its cause remains unknown. The current test waits for zombie state and reports
status and stderr. No speculative fix is justified. If it recurs, preserve those diagnostics and the exact CI head.
Three green exact-head runs remain unestablished.

## Branches

- `wave/w3` is based on main at `f92f0bf`; readiness reviews are complete and green CI is pending.
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
