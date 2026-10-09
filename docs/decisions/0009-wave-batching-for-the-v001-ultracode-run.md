# ADR 0009: Wave batching for the v0.01 unattended run

- Status: Accepted (owner authorization, 2026-10-09, for one run only)
- Date: 2026-10-09
- Amends: ADR 0006 (v0.01 integration and acceptance mechanics), for the
  duration of one owner-authorized unattended batch. Outside that batch,
  ADR 0006 applies unchanged.
- Context: ADR 0006 accepts work one phase at a time (P01–P10), with a
  per-phase integration checkpoint, a per-phase leased macOS floor, three
  reviews per phase and a merge to `main` per accepted phase. The session plan
  on epic #2 groups those phases into seven sessions (S1–S7, issues #3–#9),
  each with four software-factory approval gates. AGENTS.md lets the owner
  authorize a bounded multi-phase autonomous batch as an exception to the
  per-phase approval stop, provided that the authorization names its scope and
  deadline, is recorded in the execution checkpoint, and does not waive any
  slice gate. On 2026-10-09 the owner authorized one such batch: a single
  unattended run of at most ten hours toward issue #1, with three build waves in
  place of the seven per-session phases. This ADR records how that batch
  integrates and accepts work. It changes no product contract.

## Decision

### 1. Scope and limits of the batch

- Scope: all remaining P01–P10 work toward issue #1, except owner-only actions.
- Deadline: a hard stop ten hours after the recorded start, with a feature
  freeze at eight hours thirty minutes. After the freeze, only fixes that make
  campaigns or evidence pass are allowed.
- No tag, no GitHub release, no package publication and no announcement in
  this batch.
- Owner-only inputs stay owner-only. Rows that need them (Apple Developer ID
  and notarization, Ed25519 release-key custody, usability participants, the
  owner's own review, a published release for the distributed recheck, Postman
  credentials) are prepared and recorded as blocked on the named input. Test
  keys are used only where marked non-release.

### 2. Waves replace per-session phases

- Wave 0 sets up: the plan, the shared-contract specification, and additive CI
  plumbing (a path-filtered lane workflow and a campaign workflow on GitHub
  Actions).
- Waves 1, 2 and 3 are build waves. Each wave has lanes with a fixed per-file
  write ownership (one writer per path; files not listed belong to the
  contracts lane). Each lane works on its own branch under `ultra/` and its own
  worktree.
- Lane workers may push their own lane branches (never with force to a branch
  they do not own, never to `main`). Only the root merges into a wave
  integration branch or into `main`. This amends ADR 0006 §4, which kept every
  push with the root.
- Wave integration branches are named `ultra/w<N>-integration` and release
  candidate branches `ultra/rc-*`; both trigger `ci.yml` and `package.yml`
  (an additive trigger change only).

### 3. Wave acceptance (replaces per-phase acceptance for this batch)

At the end of each build wave, on the exact integration head:

1. Every lane included in the wave has a green lane workflow run on its final
   head. A lane that is not green is left out of the wave merge and recorded.
2. The root integrates the green lanes with `git merge --no-ff`.
3. In parallel on the integration head:
   - full CI in Actions: every `ci.yml` job (including the Linux x86_64 23-gate
     floor on both tuples), `package.yml`, every lane suite, and the relevant
     campaigns;
   - three separate, fresh reviews (architecture, security and privacy, build
     and integration), each finding checked by two or three adversarial
     refuters; a finding survives only if most refuters fail to refute it;
     surviving findings become fix tasks with delta re-reviews;
   - the leased macOS arm64 23-gate floor, after a leased macOS clippy run.
4. Repairs, then re-verification of only what changed.
5. A no-ff merge to `main` and a push. Post-merge `main` CI and a post-merge
   macOS floor run next; a failure there is fixed before any new feature work.

Everything in ADR 0006 §2 that is about evidence quality still holds: results
count only for the exact SHA they ran on, a failed or unreached gate is a
failed candidate, reviews are pinned to the candidate SHA and diff digest, and
skips, unreached code or synthetic traces never count as a pass.

### 4. Requirement rows

- Receipts from earlier waves are progress, not acceptance. A row can be
  accepted only with receipts from the exact final candidate SHA and its build
  artifacts, on the platform tuple the row names, from real applications and
  runtimes, after the reviews, and only when `tools/release/check_ledger.py`
  passes for it.
- Every row that is not accepted at the end of the batch is written down as in
  progress, blocked on a named owner input, or failing with the test and run
  that fail. No row is left blank or stated optimistically.

### 5. Process records

- The owner's authorization is recorded verbatim in the private execution
  checkpoint before the first merge.
- Software-factory per-gate approvals are waived for this batch; the root
  still writes condensed product, architecture and program-design notes per
  lane, plus a plan with the file-ownership table, before lanes start.
- At the end of the batch the root writes a `docs/progress.md` entry, updates
  `evidence/v0.01/requirements.json` and `evidence/v0.01/workflow.json`
  honestly, comments on the touched issues, and leaves an owner review packet
  (`docs/releases/v0.01-owner-review.md`) for the human-owner row.

## Alternatives considered

- **Keep per-session phases with approval stops.** Not possible unattended; the
  owner chose one batch.
- **Merge lanes to `main` as they finish.** Skips the cross-lane review and the
  floor on the combined head; rejected.
- **Accept rows as soon as a wave proves them.** Earlier waves change the code
  the row depends on, so only the final candidate can carry acceptance.

## Consequences

- Fewer, larger merges to `main`, each with the full acceptance protocol.
- Heavy and parallel testing moves to GitHub Actions; the local Mac runs only
  the leased floors and macOS-only journeys.
- A wave that cannot pass acceptance in time stays pushed and unmerged, with
  the reason recorded; the batch never trades correctness for the deadline.
