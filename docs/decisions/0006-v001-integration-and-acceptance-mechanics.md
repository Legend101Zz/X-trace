# ADR 0006: v0.01 integration and acceptance mechanics

- Status: Accepted (root decision 2026-10-04)
- Date: 2026-10-04
- Context: Twelve unmerged `slice/v001-*` branches carry overlapping,
  unaccepted preparation (conflict hotspots: `crates/xtrace-cli/src/{error,output}.rs`,
  `crates/xtrace-runtime/{Cargo.toml,src/lib.rs}`, `crates/xtrace-store/src/connection.rs`,
  `tools/release/test_release_tools.py`). `docs/releases/v0.01.md` and
  `evidence/v0.01/workflow.json` (both on `slice/v001-release-control`) define
  phases P00-P10 and the 23-gate floor in `tools/release/run_gates.py`, but no
  document fixes where the work is consolidated, which platforms must run it,
  which CI counts, how reviews are pinned, how receipts are recorded, or who may
  merge. AGENTS.md assigns merge to the orchestrator alone. This ADR proposes
  those mechanics; it changes no product contract.

## Decision

### 1. Consolidation base

- `slice/v001-integration` is created from `main` at
  `3e47895f90e6a78e08b1d808d4498e4595f71a5d` by root only. It is the single
  consolidation base for v0.01. Lane branches never merge into each other and
  never into `main`.
- Root merges accepted lane branches into `slice/v001-integration` with
  `git merge --no-ff <branch>` in dependency order (a merge commit per lane keeps
  the lane diff reviewable and revertable; no cherry-picks, no rebases of
  already-pushed history). Order, from the topology digest:
  1. release/CI tooling (`ci-floor` or `control-admission` as base, resolving
     `tools/release/test_release_tools.py` once; `release-control`'s unaccepted
     handoff and WIP patch blobs are not merged);
  2. `java-evidence`; 3. `shared-replay`, then `catalog-core` (one
     schema-version alignment, one migration numbering pass); 4. `java-attach`,
     `private-storage`, `java-cli-attach`; 5. `pointer-init`, `pack-verifier`
     (gated on review: its tip is a WIP checkpoint); 6. `node-capture` last, with
     the four conflicting CLI/runtime files hand-resolved.
- `Cargo.lock` and generated bindings (protobuf, OpenAPI client, embedded web
  assets) are regenerated after every merge, never hand-merged; `check:api`,
  `check:embedded` and `generate:check` must be clean before the next merge.
- Shared contracts (domain, protocol/proto, OpenAPI, SQLite migrations, XTF,
  redaction vocabulary, replay navigation, capability manifest) have one write
  owner per phase, assigned by root. A lane that needs a contract change lists the
  exact diff hunks in its report (as the lane rules already require); root applies
  it on the integration branch.
- A phase "starts" at an immutable phase-base SHA on `slice/v001-integration` and
  ends at a candidate SHA. The phase-base SHA is the `--base` value for every gate
  and diff check of that phase.
- `slice/v001-integration` pushes trigger the existing `ci.yml`
  (`push: branches: main, slice/**`), so it gets CI without workflow changes.
  Only root pushes it.

### 2. Phase acceptance

A phase candidate (a specific head SHA) is accepted only when **all** of the
following hold for that exact SHA; nothing is carried over from an earlier SHA
(no stale CI, no stale gate receipt, no stale review).

1. **Floor on macOS arm64, leased.** `tools/release/run_gates.py` runs all 23
   gates from a clean checkout of the candidate, with `--base <phase-base SHA>`,
   a unique `--label <phase>-candidate-<letter>`, the task-private cache root, and
   both real builder leases (cargo and gradle). Exit 0 and every gate `passed` and
   `reached`. A failed or unreached gate is a failed candidate; the receipt is
   immutable and the fix gets a new label. The runner is the only thing that may
   produce the floor receipt; hand-run commands do not substitute.
2. **GitHub CI on ubuntu x86_64.** Every job of `ci.yml` is green on the exact
   head SHA (read from the check-runs of that SHA, never from the branch's latest
   run), covering Java 17 and 21 and Node 22 and 24 (Node 24 is added; today only
   Node 22 runs), `gates`, `release-tool-tests`, `java-client`, `node-client`.
   `cargo clippy`/`test` in CI use `--locked` to match the floor.
3. **macOS arm64 CI job (new requirement).** A job on a GitHub-hosted Apple
   silicon runner (`macos-14`, or the then-current arm64 label) runs on every
   phase candidate that touches `cfg(unix)`/macOS-specific code, the broker
   (ADR 0004), private storage, attach, or packaging, and on every candidate from
   P04 onward and from P07B onward unconditionally. It runs: `cargo build/test
   --locked --workspace`, the Java strict Gradle build on JDK 17 and 21, the Node
   workspace on Node 22 and 24, the packaged-journey tests that can run
   unattended, and the other-UID broker negative (the hosted runner permits a
   second local user). It must run without skips for the rows it claims. Local
   macOS floor runs and the hosted job are complementary: the job proves a clean
   machine, the local run proves the leased builder discipline.
4. **Three independent reviews**: architecture, security/privacy,
   build/integration. Reviewers are separate agents/sessions from the
   implementer(s) and from each other, each pinned in the report header to the
   candidate SHA, the phase-base SHA, and the SHA-256 of
   `git diff <phase-base>...<candidate>`. A review of a different SHA is void.
   Findings are fixed on a new candidate SHA and the affected reviewer re-reviews
   the delta (or the whole diff when the delta touches a shared contract).
5. **Root full-diff review** of the actual phase diff (every line) before the
   merge decision, recorded as a root review artifact.
6. **Requirement-specific suites** named in the phase (conformance, real
   CLI/browser/TUI journeys, privacy canaries, failure injection, performance)
   pass and are listed in the receipt with their exact commands.

### 3. Evidence and receipts

- Public, sanitized evidence lives under `evidence/v0.01/`; raw logs stay in the
  task cache and are referenced by relative name and SHA-256, never copied into
  tracked files. No absolute home paths, tokens, nonces, keys, lease contents, or
  owner process lists appear in tracked evidence.
- Per phase and candidate: `evidence/v0.01/phases/<phase>/<label>/` with
  `phase-receipt.json` containing: phase id; phase-base and candidate SHAs;
  `run_gates` receipt SHA-256 and per-gate status; CI run IDs, job names,
  conclusions and head SHA for ubuntu and macOS; the three review reports' SHA-256
  and verdicts; the root-review artifact SHA-256; requirement row IDs touched;
  commands and results for the phase suites; open defects. `check_ledger.py`
  conventions apply: relative symlink-free paths, SHA-256 referenced, canonical
  fields, fail-closed on any missing or unreached item.
- Requirement rows change from `pending` to `accepted` only through signed
  receipts verified by `check_ledger.py` against an owner-authenticated trust
  config; a phase receipt is evidence for a row, not acceptance of it. The
  ledger has no waiver state, so rows needing unavailable authority stay pending
  (PLATFORM-MAC, SUPPLY-CHAIN signing, HUMAN-*, connected Postman).
- `docs/progress.md` gets one checkpoint per accepted phase (SHAs, receipt hash,
  CI ids, remaining work), written by root after postmerge verification.
- A rejected candidate is preserved: its receipt and reviews stay in place and are
  marked `rejected`, so history shows what failed and why.

### 4. Merge and release authority

- **Root-only.** Lane workers commit locally on their assigned branch and report.
  Only root may push, create/merge PRs, merge into `slice/v001-integration`, merge
  into `main`, tag, or publish. Workers never run `git push`, never rewrite pushed
  history, and never touch `main`.
- After a phase passes section 2 on `slice/v001-integration`, root merges it to
  `main` with `git merge --no-ff`, pushes, and requires fresh postmerge floor
  gates on the merged `main` SHA and green main CI before the checkpoint is
  written. The mandate authorizes these merges (M:70-77); it does not waive any
  gate.
- A release tag or public publication happens only after P10 (final independent
  reviews, real human usability and owner acceptance, distributed-artifact
  recheck) with every mandatory ledger row accepted for the exact release build
  (M:238-247).

### 4a. Gate placement per phase (summary)

| Phase | Floor (macOS arm64, leased) | CI ubuntu | macOS arm64 CI job | Reviews |
|---|---|---|---|---|
| P01-P03 | yes | yes | if cfg(unix)/store/runtime touched | 3 |
| P04, P05 | yes | yes (Java 17/21, Node 22/24) | yes | 3 |
| P06, P07 | yes | yes | yes (browser journeys where runnable) | 3 |
| P07B | yes | yes | yes, plus package build | 3 |
| P08 | yes | yes | yes | 3 |
| P09 | yes | yes (Linux x86_64 package) | yes (macOS arm64 package) | 3 |
| P10 | yes | yes | yes | final 3 + human + distributed recheck |

## Alternatives considered

- **Merge lane branches straight into `main`.** Puts unreviewed, mutually
  conflicting preparation on the release branch and breaks "one phase = one
  reviewable diff against a pinned base".
- **A rebase-based linear stack.** Rewrites pushed history and loses the per-lane
  merge boundaries reviewers use.
- **Rely only on the local macOS floor.** Does not prove a clean machine, Linux
  x86_64, or other-UID behavior; local Docker on this host is Linux aarch64 and is
  not Linux x86_64 evidence.
- **Rely only on GitHub CI.** CI cannot take the leased private builder caches the
  floor requires and cannot prove the owner workstation path.
- **One combined review.** Collapses the architecture/security/build separation the
  mandate asks for (M:211-212).
- **Waivers for unavailable external inputs.** The ledger deliberately has none;
  renaming a gate is a downgrade (M:248-250).

## Consequences

- CI gains a Node 24 matrix entry and a macOS arm64 job; both must be added
  before P04/P05 acceptance and before any claim about macOS in the matrix.
  Hosted runner minutes become a release dependency.
- The immutable phase base makes `git diff --check <base>...HEAD` (gate 23) and
  review diff digests reproducible; it also means a phase base must never be a
  floating ref.
- Lanes can run in parallel only against clean ownership boundaries; contract
  changes serialize through root, which is the slow path by design.
- Evidence volume grows; reports must stay sanitized, so tooling that emits them
  must be tested for path/token leakage.

## Test and evidence obligations

- `slice/v001-integration` creation is recorded (base SHA, creator, date) in
  `docs/progress.md` before the first merge.
- Each lane merge records: lane head SHA, merge commit SHA, conflict list and
  resolution summary, regenerated-artifact checks.
- A script check (extend `tools/release/test_release_tools.py`) proves a phase
  receipt is rejected when: the CI head SHA differs from the candidate; any job is
  missing or skipped; a review's diff digest differs; the macOS job is absent for a
  phase that requires it; the floor receipt label was reused.
- CI workflow test: the macOS job fails if the other-UID broker test is skipped.
- The first accepted phase demonstrates the complete receipt end to end (dry run
  through `check_ledger.py` with test signing keys) before real receipts are cut.
- Postmerge: after each root merge to `main`, record main SHA, floor receipt hash,
  main CI run id.

## Open questions

1. Is the hosted macOS arm64 runner an acceptable "fresh machine" for PLATFORM-MAC
   preparation, given that signing/notarization still needs the owner's identity?
2. Should `slice/v001-integration` merge to `main` after every accepted phase
   (per M:213) or batch several phases while keeping gates per phase? This ADR
   assumes per phase.
3. Who is the owner-authenticated signer for phase receipts before release keys
   exist (test keys only, marked non-release)?
4. Retention of rejected-candidate evidence: keep in-tree or in the private cache
   with only hashes tracked?
5. Should `ci-floor` or `control-admission` be the tooling base? They diverge after
   `1d3a2d1` and conflict in `tools/release/test_release_tools.py`; root decides.

## Root decision (2026-10-04)

Decided by the root orchestrator under the owner's autonomous v0.01 launch authorization. These answers close the open questions above and supersede any conflicting text in this ADR.

1. Hosted macOS arm64 runners are acceptable for platform preparation CI and fresh-profile rehearsal. PLATFORM-MAC acceptance still requires signed/notarized artifacts (owner input).
2. Integration merges to `main` per accepted phase. Phases with mutual dependencies may share one integration checkpoint, but each phase keeps its own gate/evidence record.
3. Phase receipts before release keys exist are signed with test keys marked non-release. Release receipts need the owner-authenticated trust configuration (owner input).
4. Rejected-candidate raw evidence stays in the private cache; only sanitized hashes and summaries are tracked in-tree.
5. The tooling base is `slice/v001-control-admission`, which absorbs ci-floor and release-control (control lane round 2).
