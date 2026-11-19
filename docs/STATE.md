# X-trace: current state

The one place for "where are we". Rewrite it (do not append) at the end of every working session. History lives in
`docs/progress.md` and in git. Last updated 2026-11-19.

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

PR #70 merged on 2026-11-12 as `be441c59892e323287da10cf1dc7a495c6a615f7` under the owner's one-time
waiver of the pre-merge CI requirement. The reviewed changes included Linux private-storage admission
corrections and diagnostics for attach readiness, Spring shutdown, acknowledgement failures, and floor progress.
#22 closed with attach readiness evidence and the waiver recorded.
[PR #70](https://github.com/Legend101Zz/X-trace/pull/70) · [#22](https://github.com/Legend101Zz/X-trace/issues/22)

Linux `ci-ok` failed on that exact merged head. The JDK 21 / Node 24 floor passed all 23 gates. The JDK 17 /
Node 22 floor passed 17 gates and failed the Rust workspace gate with six failing tests. The separate gates job
also failed. [Main CI 43214553598](https://github.com/Legend101Zz/X-trace/actions/runs/43214553598)

- The gates job's store index retry test failed during fixture SQLite open with a private-storage permission
  error. The log gives no underlying operation. The retry assertions were never reached.
- The JDK 17 / Node 22 workspace CLI unit test failed while creating a private fixture directory. Its sanitized
  admission record showed a ctime-only mismatch at the directory snapshot. The metadata writer and any connection to
  the store fixture failure remain unknown.
- The JDK 17 / Node 22 premain classfile-mutation phase observed three of four expected complete matching order
  recordings after shutdown, with drain-expired and incomplete markers. The missing recording's failure stage
  remains unresolved. Four redirect-source tests hit a complete-recording wait with no cause attributed.

The store library test binary passed both Rust gates on both floors. It took about 3,022 seconds focused and
2,918 seconds workspace on JDK 17 / Node 22, versus 2,041 and 2,052 seconds on JDK 21 / Node 24. On the
JDK 17 / Node 22 focused gate, the `focused-singletons` recovery profile took about 1,739 seconds, with the
largest recorded span totals in checkpoint publication (446 seconds) and connection-file admission (289 seconds).
The `sparse` recovery profile took about 1,248 seconds, led by segment object publication (200 seconds) and
segment SQL transactions (131 seconds). The profiles measure exclusive phase time on the profiled test thread.
[Main CI 43214553598](https://github.com/Legend101Zz/X-trace/actions/runs/43214553598)

PR #70 batched frame-verification SQL to one inclusive range query per decoded segment. Source analysis counted
at least 1,958,576 point queries in the prior focused replay. The active operation during the earlier 120-minute
timeout and the wall-time impact of batching remain unverified.
[Earlier CI 43061181831](https://github.com/Legend101Zz/X-trace/actions/runs/43061181831/attempts/2)

The later cancelled JDK 17 / Node 22 floor on `9763435` retained verified progress in the Rust workspace
store binary. The `focused-singletons` profile last recorded 85,760 of 131,072 admissions, with
`segment_sql_transaction` as its last active phase. The incomplete floor receipt was invalid.
[Cancelled CI 43189678475](https://github.com/Legend101Zz/X-trace/actions/runs/43189678475)

#71 requires bounded and verified cancellation evidence, source-grounded evidence of the costly test or phase,
treatment of any supported cause, all original gates and budgets, and green Linux `ci-ok` on the exact reviewed
head. The trackers cover the reliability follow-up and current CI outcome. #69 also tracks the carried minor
review findings.
[#71](https://github.com/Legend101Zz/X-trace/issues/71) · [#69](https://github.com/Legend101Zz/X-trace/issues/69)

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

## Known nondeterministic test (fix; never retry to green)

[#14](https://github.com/Legend101Zz/X-trace/issues/14) remains open: the historical zombie lifecycle failure log lacks the
actual stop status and stderr, so its cause remains unknown. The current test waits for zombie state and reports
status and stderr. No speculative fix is justified. If it recurs, preserve those diagnostics and the exact CI head.
Three green exact-head runs remain unestablished.

## Branches

- `w3/r10` at `92035672552c0f053d573f97fbd0b6263e430bdb` preserves #32 export work. OpenAPI still needs
  full alternate operation metadata when scopes share a method and path.
- `w3/r15` at `8658657d22e17573480cfd9d2a6cf16513c4b0ba` preserves #36 campaign harness work. Reconcile
  the inherited export changes before integration.
- `w3/r16` at `b504b19942a7ec8575a8de645665623730ccf753` preserves unreviewed private-admission test work.
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
