# ADR 0012: Agent workforce, GitHub-hosted verification and risk-scaled merges

- Status: Accepted where it records the owner's instructions of 2026-11-09: Codex workers with a Claude orchestrator
  (decision 1), heavy tests on GitHub only (decision 2), builds on the SSD with cleanup (decision 3). The local
  unit-test allowance in decision 2 and decisions 4–6 are defaults adopted the same day, pending owner
  confirmation; until the owner changes them, they apply.
- Date: 2026-11-09
- Amends: ADR 0006 (integration and acceptance mechanics) and ADR 0009 (wave batching): the merge protocol and
  the leased macOS floor requirement. Supersedes every rule that limits which agents or models may work on this
  repository (in `AGENTS.md`, `docs/releases/v0.01.md`, `docs/plans/x-trace/04-vertical-slices.md`,
  `evidence/v0.01/workflow.json` and the continuation prompt).
- Context: the earlier runs used one Opus root with Sonnet workers and a heavy local protocol: three reviewers plus
  refuters per finding, a leased 23-gate floor on the owner's Mac, and a MERGE-GATE file for every merge. One
  10-hour run cleared about a ninth of the open work. The owner's private run state (session kit, ledgers, the
  leased-runner wrapper and the Linux devbox wrapper) was deleted on purpose to free disk space, so the local floor
  can no longer run as written. Release acceptance (`evidence/v0.01/requirements.json`, issue #1) is unchanged.

## Decision

### 1. Who does the work (owner instruction)

- **Workers** are OpenAI Codex CLI agents on `gpt-6.1-sol` (default for product code and tests) or
  `gpt-6.1-terra` (documentation, mechanical edits, reviews of Sol-written code). The owner may change this split.
- **The orchestrator** is a Claude Code session (Opus). It writes tickets, launches workers, reviews every diff,
  commits, opens pull requests, reads CI and merges. Workers never push, merge, tag, publish or write issues.
- Workers run under a locked-down launcher: the owner's personal Codex configuration is not loaded, memories,
  sub-agents, plugins, apps, MCP servers, web search and network access are off, and the sandbox is
  `workspace-write`, limited to the ticket's worktree plus the build-cache volume. The sandbox also blocks
  `git commit`, so the orchestrator commits each reviewed diff under the owner's identity.
- Each ticket has an owned path set, frozen acceptance tests the worker may read but not edit, and an explicit
  "infeasible" exit. A diff that edits a frozen test, adds `#[ignore]`/`test.skip`/a quarantine, raises a deadline
  or weakens an assertion is rejected without review.

### 2. Where tests run (owner instruction)

- Heavy verification runs only on GitHub Actions: integration and journey tests, the 23-gate floors, packaging,
  campaigns and browser runs.
- Locally, agents run only fast checks: compiling, the unit tests of the crate or package they touched, one test file, and
  type checks (`tools/dev/check.sh`). This is a default (owner question D1). If the owner says compile only,
  `check.sh` drops the unit tests.
- Every change reaches `main` through a pull request whose CI is green on the exact head commit.

### 3. Where builds live (owner instruction)

- Build outputs, dependency caches and test scratch live on the owner's external SSD, on an APFS volume with
  ownership enabled (private-storage admission refuses `noowners` volumes; see ADR 0008). Two roots are set per
  machine and never committed: `XTRACE_DEV_CACHE` (dependency caches and per-worktree Cargo build directories) and
  `XTRACE_DEV_SCRATCH` (short-path private test scratch). `tools/dev/env.sh` derives every path from them.
- `tools/dev/clean.sh` removes the build and scratch directories of worktrees that no longer exist, between
  waves. It is a dry run unless `--apply` is given, never touches an active worktree's directories, and never
  deletes anything outside the two roots.

### 4. macOS evidence (default, owner question D2)

- The leased macOS 23-gate floor is no longer a merge requirement.
- macOS evidence for merges will come from a GitHub-hosted macOS arm64 job (free for public repositories). It is
  added in a follow-up after the known nondeterministic tests are fixed. Until it exists, merges rely on the Linux
  floors and say so in the pull request.
- This reverses the owner's 2026-10-10 decision to run no hosted macOS jobs, so it is the owner's call (D2).
- No release candidate is accepted without macOS evidence for that exact candidate (the hosted job, or the leased
  floor on a real Mac) unless the owner waives it in writing.
- PLATFORM-MAC acceptance still requires a fresh-profile install of the exact unsigned release package on a real
  Mac (ADR 0006, second addendum of 2026-10-10).

### 5. Merge rules scaled to risk (default, owner question D3)

| Change | Required before merge |
|---|---|
| Docs, evidence notes, agent instructions | CI green on the exact head |
| Product code, tests, tooling | CI green on the exact head + one independent review by a different model than the writer + the orchestrator's own read of the whole diff |
| Shared contracts (Protobuf/OpenAPI schemas, SQLite migrations, XTF, redaction vocabulary, replay navigation), security or privacy paths, release tooling, CI workflows | as above, with two independent reviews |
| Release candidate (`ultra/rc-*`) | the full ADR 0006 protocol, with the leased macOS floor replaced as in decision 4 |

- "CI green" means the `ci-ok` check of `ci.yml` on the exact head, plus any workflow the ticket names. Trigger
  the others on the branch when the change touches them: `gh workflow run lane.yml --ref <branch> -f suite=<suite>`
  (adapters, web, TUI suites), `gh workflow run package.yml --ref <branch>` (packaging), and an
  `ultra/campaign/<project>` branch push for campaigns (capture semantics).
- Before merging, the branch must contain the current `main` (merge `origin/main` into it, never rebase pushed
  history), and CI must be green on that head, so the tested tree is the merged tree.
- After every merge, `main` CI must be green before new feature work. A red `main` that cannot be fixed within 60
  minutes is reverted with `git revert -m 1`.
- Flakes: record the failing run before any re-run. A green re-run is not a clean pass until the cause is fixed.
  Never retry until green.
- One review round plus at most one fix round per finding. After that the orchestrator decides, or escalates to
  the owner.

### 6. Release acceptance stays strict

- No requirement row becomes `accepted` without signed receipts checked against the owner's trust configuration
  (`tools/release/check_ledger.py`).
- The REVIEWS-EXACT row no longer names a model. It requires independent architecture/security and
  build/integration reviews of the exact release candidate, each by another vendor's model than the writer's (for
  example, Claude reviewing Codex-written code), plus the orchestrator's complete diff review, exact gates, CI and
  post-merge checks.

## Consequences

- Faster merges for ordinary work. Each ticket's evidence is its pull request, its CI run and the review
  record, not a private run folder.
- Until the hosted macOS job exists, a macOS-only regression can reach `main` and is caught later, either by that
  job or by the release-candidate protocol.
- The rule text in older documents is historical where it describes past runs (`docs/progress.md` entries); current
  rules live in `AGENTS.md`, this ADR and `docs/STATE.md`.
