# X-trace: current state

The one place for "where are we". Rewrite it (do not append) at the end of every working session. History lives in
`docs/progress.md` and in git. Last updated 2026-11-24.

## Release status

- Target: **v0.01** (package version 0.0.1). Acceptance is the 55-row ledger `evidence/v0.01/requirements.json`
  (issue #1). **0 of 55 rows are accepted**: 35 in progress, 8 not started, 6 failing, 6 blocked.
- Failing: JAVA-MVC, REPLAY-SOURCE, REPLAY-OUTCOME, REPLAY-TUI, CAMPAIGN-PETCLINIC, CAMPAIGN-FINERACT.
- Blocked: EXPORT-POSTMAN (credentials), PLATFORM-LINUX (release key), HUMAN-USABILITY (participants),
  HUMAN-OWNER, REVIEWS-EXACT, DISTRIBUTED-RECHECK (end of release). Implementation or a green development CI run
  alone does not accept a row: acceptance needs signed receipts checked against the owner's trust configuration.
- ADR 0012 governs workers, GitHub verification and risk-scaled reviews. Development merges need Linux `ci-ok`
  on the exact head and clean reviews. At release, the owner runs `tools/dev/macos-release-check.sh` locally and
  fixes failures; PLATFORM-MAC also needs a fresh-profile install of the exact unsigned release package on a real Mac.

## Main and CI baseline

Verified `origin/main` at `bc3cfb57b1307372dc2d7bf933a044c36147b990`, merge of
[PR #74](https://github.com/Legend101Zz/X-trace/pull/74); #73 merged as `fb01e4da` before it. At this baseline
there was no open PR. Issues #45, #53, #71 and #72 were closed; #69, #3, #14, #32, #36, #52, #57 and #68
remained open. Check GitHub again before acting; this is a measured baseline, not a live status feed.

[Main CI 44669637782](https://github.com/Legend101Zz/X-trace/actions/runs/44669637782) is red: the JDK 17 /
Node 22 floor's `web-tests` gate exited 1 after 12 gates passed; ten later gates were not reached. The available
floor result does not distinguish a Vitest failure from a contrast failure or exclude npm failing before either
subcommand started. The JDK 21 / Node 24 floor passed all
23 gates. The separate general gates job passed 86 Vitest tests and 20 contrast pairs using Node 22.23.4 and npm
10.9.9. These job results do not identify the floor failure's cause or make it a pass. Raw floor logs were ephemeral.
[PR #74 CI 44618525107](https://github.com/Legend101Zz/X-trace/actions/runs/44618525107) passed on its exact PR
head `5f6fc38d23999964a02d92175f2a5a3cf372dfab`; that is not a green post-merge main run.

A later [focused probe 45372494960](https://github.com/Legend101Zz/X-trace/actions/runs/45372494960) on exact
baseline `bc3cfb57b1307372dc2d7bf933a044c36147b990`, Ubuntu 24.04, JDK 17 and Node 22.23.4 passed the
original 11 Node and web gates under the floor supervisor and private environment: nine files and 86 Vitest tests,
and 20 contrast pairs, passed. It omitted the Java and Rust prerequisite workloads. It is neither a full-floor pass
nor evidence of the cause of the earlier failure.

[PR #75 CI 45374832325](https://github.com/Legend101Zz/X-trace/actions/runs/45374832325) on the previous
reviewed head did not pass: the JDK 21 / Node 24 floor stopped at `rust-workspace` with exit 101 after 17 gates
passed; five later gates were not reached. Rust reported 1,225 tests passed and one failed. `web-tests` passed
on both tuples, and the JDK 17 / Node 22 floor passed 23/23 gates. The general and separate Java and Node jobs
passed. The failing `java_premain_spring` classfile-mutation phase observed 3 of 4 orders, incomplete/drain expired
and session-wide queued signals; no order segment evidence was observed. The gate command did not time out. These observations do not establish the cause.

The fixture has a sequencing gap: an instrumented readiness GET could overlap the target order's shutdown window.
A candidate preserves the GET, original deadline, immediate post-order signal and post-stop assertions; its success
is not established by the reviewed run. The earlier run below also observed 3 of 4 in this phase on JDK 17, so the
root cause remains unproven.

The subsequent repeat batch produced one full exact-head pass in three: [run 45406286260](https://github.com/Legend101Zz/X-trace/actions/runs/45406286260)
attempt 1 passed both floors at 23/23 gates. In attempt 2, the JDK 17 floor failed while receiving Express 4
readiness, before requests; the failure category is withheld. The JDK 21 floor failed in the Rust-focused
`capacity_drops…` test at Finish, line 1091. The same test also observed
`AclState`/`Snapshot` ctime-only immediate-parent depth -1 at Finish/RootBinding; their association is unknown.
[Run 45421543777](https://github.com/Legend101Zz/X-trace/actions/runs/45421543777) failed in general gates on
a sparse acknowledgement: `JournalOpenOrCreate` admission `Deadline` at iteration 3557. Spring passed in that
job. These findings do not establish historical causes or candidate success.

Earlier [main CI 43214553598](https://github.com/Legend101Zz/X-trace/actions/runs/43214553598) after PR #70
had separate private-storage admission and Java recording failures; their historical causes were not all established.
#71 closed on evidence from PR #73's exact reviewed head and both full floors; the subsequent main run above failed
before Rust. Do not infer that main is green or that every historical intermittent failure has been explained. Preserve failing-run evidence and never retry an unexplained failure until green.

## Next work

1. Resolve the current red main based on evidence. Preserve every gate, assertion and budget; an unreached gate is
   not a pass. Verify the exact reviewed head and post-merge main under ADR 0012 before new feature work.
2. Continue [#69](https://github.com/Legend101Zz/X-trace/issues/69) and
   [#3](https://github.com/Legend101Zz/X-trace/issues/3): finish #32 export claims and policy digest, integrate
   #36's observed burst-correlation harness with honest ambiguity where individual correlation is unavailable, and
   address #52 bounded observed cause types with a scoped contract/ADR ticket. Review #69's carried minor findings.
   Then proceed through #4, #5 and #6 in parallel, followed by #7, #8 and #9. Issue #2 is the epic.
3. For #3, integrate and review the work, obtain exact-head Linux `ci-ok` and clean reviews, and run a fresh
   packaged Petclinic campaign before assessing its boxes. No fresh campaign for this batch is established here.
   Close an issue only when every box has evidence on merged `main`.
4. Keep [#57](https://github.com/Legend101Zz/X-trace/issues/57) and
   [#68](https://github.com/Legend101Zz/X-trace/issues/68) separate and open. #57 requires evidence for recovery,
   consistent live-read snapshots, cleanup, macOS checkpoint full sync and cost without weakening durability.
   #68 requires the cause and durable/readable completion at Finish acknowledgement, plus investigation of any
   distinct macOS failures and timeouts. A closed CI-performance ticket does not establish either issue's criteria.

## Known nondeterministic test

[#14](https://github.com/Legend101Zz/X-trace/issues/14) remains open. The historical zombie lifecycle failure
log lacks the stop status and stderr, so its cause is unknown. The current test waits for zombie state and reports
status and stderr. Preserve those diagnostics and the exact head if it recurs; three green runs on the same exact
head remain unestablished. Do not retry to green or claim a speculative fix.

## Saved branches

- `w3/r10` at `92035672552c0f053d573f97fbd0b6263e430bdb` preserves #32 export work. OpenAPI still needs
  full alternate operation metadata when scopes share a method and path; runtime verification remains.
- `w3/r15` at `8658657d22e17573480cfd9d2a6cf16513c4b0ba` preserves #36 campaign harness work. Its merge-base
  with `w3/r10` is `ca86bfaa4844de7e335d85379dc4be1cace59bfd`, which includes three export commits shared by
  both branches but absent from main. Reconcile that ancestry and export work before integration.
- `w3/r16` at `b504b19942a7ec8575a8de645665623730ccf753` preserves unreviewed private-admission test work;
  it is not validated or included in #70.

## Petclinic evidence boundaries

The later [Petclinic campaign 43201696564](https://github.com/Legend101Zz/X-trace/actions/runs/43201696564)
on `74480481aef5537f431c54e361e7e0aaadab2a7a` reported 37 passes and eight reported steps; its package verifier
passed, but its receipt was non-release and it is not current-head evidence. The earlier Wave 2 campaign also passed
37 of 45 steps; its eight accommodations are reported gaps, not passes. The
baseline jar hash differed from the pin; serial load was paced with request budgets and an acknowledged database
wait, and possible capture drops qualify the overhead measurement. The analyzer was built from source; packaging
belongs to #8. TUI routes were checked in detail, not in the list. Focused capture and exception-message redaction
have the reported privacy scope. The receipt was unsigned and non-release; release acceptance needs accepted receipts.

## Waiting for the owner

- Ratify ADR 0008 Amendment 1, the first ADR 0006 addendum of 2026-10-10, the ADR 0009 addendum, ADR 0011, and
  the migration renumbering (v9 = `recording_limitations`, v10 = `session_health`, catalog links take the next free
  version).
- Usability question Q5 asks which Canvas node "took the longest", but the product records no per-node time
  (honesty rule R2). Either change the question or add real per-frame timing.
- For release: an Ed25519 release/ledger key and trust configuration, at least two usability participants plus a
  scorer, the owner's review of the named journeys (`docs/owner-review/README.md`), and optional Postman credentials.
- UI: Figma-style mocks are being made in Claude Design. The chosen design becomes the spec for #7.
