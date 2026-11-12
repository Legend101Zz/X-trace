# X-trace: current state

The one place for "where are we". Rewrite it (do not append) at the end of every working session. History lives in
`docs/progress.md` and in git. Last updated: 2026-11-12.

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

[Draft PR #70](https://github.com/Legend101Zz/X-trace/pull/70) tracks `wave/w3` under
[#69](https://github.com/Legend101Zz/X-trace/issues/69). Main remains at `f92f0bf`. The current batch is
unmerged and awaits fresh exact-head Linux CI. `ef29c58` delivered the caught-panic source-line and workload-poison
fixes.

- [#22](https://github.com/Legend101Zz/X-trace/issues/22) adds attach port and readiness diagnostics. The latest
  local change also addresses the carried stderr reporting race with coordination capped by the original startup
  deadline. Four CLI test binaries compile; formatting and diff checks passed. Review found no blocker or major;
  one minor remains: the inherited-stderr regression does not cover the 250 ms grace cap with a longer caller
  deadline. Carry a synchronized case that verifies readiness reports while stderr remains open and before that
  deadline to the next fix batch. Runtime verification awaits CI. #22 remains open.
- [#71](https://github.com/Legend101Zz/X-trace/issues/71) tracks the floor timeout diagnosis. The local diagnostics
  change publishes bounded, validated gate, command and Rust progress and fixed store profiles through the existing
  sanitize and upload path, separate from strict receipt acceptance. It cannot promise artifacts if the runner is
  lost or teardown is skipped. Nine Python modules compile. Reviews found no blocker or major; one minor remains:
  final failure-summary framing can leave `harnessResultObserved` false. Carry it to the next fix batch.
- The local storage change replaces per-envelope SQL point queries for frame verification with one inclusive range
  query per decoded segment in the existing read transaction. Source work-count analysis identified at least
  1,958,576 point queries in the focused replay. Row checks, admission, snapshot, XTF verification, budgets and
  whole-recording honesty remain in place. Store check, Clippy, library test compilation, formatting and diff checks
  passed. Reviews found no blocker or major; one minor is that the counter checks the current range statement and
  could miss a future additional statement. Carry it to the next fix batch. Runtime equivalence, the query-count
  assertion and floor timing await CI; the effect of batching on floor runtime remains unmeasured.

Post-merge main CI [43042206403](https://github.com/Legend101Zz/X-trace/actions/runs/43042206403) attempt 5
completed with Ubuntu DNS setup failures. Wave run
[43061181831](https://github.com/Legend101Zz/X-trace/actions/runs/43061181831) attempt 2 passed
release-tool-tests, main gates, Java 17/21, Node and the JDK 21/Node 24 floor (23/23). The JDK 17/Node 22
floor hit the 120-minute job limit and `ci-ok` failed. Its sanitizer rejected an incomplete receipt and upload
succeeded; the rejected summary's zero gate count does not establish that no tests ran. The focused store binary
completed in 3202.711 seconds, compared with 2152.296 seconds focused and 2167.236 seconds workspace on the
JDK 21 floor. A missing workspace fragment leaves the command active at cancellation unknown. The real timeout was
not rerun. New regressions await CI; no local runtime tests ran and no deadlines or budgets changed.

To finish [#3](https://github.com/Legend101Zz/X-trace/issues/3), address #32 (exact export claims and policy
digest), #36 (observed per-request burst correlation), and #52 (bounded observed cause types with a scoped
contract/ADR ticket), then #4, #5 and #6 in parallel, #7, #8 and #9. Integrate and review the work, obtain
exact-head Linux `ci-ok` and clean reviews, and run a fresh packaged Petclinic campaign before assessing #3.
No fresh campaign has run for this batch. Close an issue only with evidence for every box on merged `main`.

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

- `wave/w3` is based on main at `f92f0bf`; the reviewed batch awaits fresh exact-head CI.
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
