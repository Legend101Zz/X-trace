# ADR 0012: Agent workforce, GitHub-hosted verification and risk-scaled merges

- Status: Accepted for decisions 1–3 (owner instruction, 2026-11-09). Decisions 4–6 are defaults adopted the same day,
  pending owner confirmation; until the owner changes them, they apply.
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
  ownership enabled (private-storage admission refuses `noowners` volumes; see ADR 0008). One cache root is set
  per machine in `XTRACE_DEV_CACHE`; the path is never committed. `tools/dev/env.sh` derives every cache and scratch
  path from it, with one Cargo build directory per worktree and a shared size-capped compiler cache.
- `tools/dev/clean.sh` removes finished tickets' build and scratch directories and prunes old caches between
  waves. It is a dry run unless `--apply` is given, and it never touches anything outside the cache root.

### 4. macOS evidence (default, owner question D2)

- The leased macOS 23-gate floor is no longer a merge requirement.
- macOS evidence for merges will come from a GitHub-hosted macOS arm64 job (free for public repositories). It is
  added in a follow-up after the known nondeterministic tests are fixed. Until it exists, merges rely on the Linux
  floors and say so in the pull request.
- PLATFORM-MAC acceptance still requires a fresh-profile install of the exact unsigned release package on a real
  Mac (ADR 0006, second addendum of 2026-10-10).

### 5. Merge rules scaled to risk (default, owner question D3)

| Change | Required before merge |
|---|---|
| Docs, evidence notes, agent instructions | CI green on the exact head |
| Product code, tests, tooling | CI green on the exact head + one independent review by a different model than the writer + the orchestrator's own read of the whole diff |
| Shared contracts (Protobuf/OpenAPI schemas, SQLite migrations, XTF, redaction vocabulary, replay navigation), security or privacy paths, release tooling, CI workflows | as above, with two independent reviews |
| Release candidate (`ultra/rc-*`) | the full ADR 0006 protocol, with the leased macOS floor replaced as in decision 4 |

- Flakes: record the failing run before any re-run. A green re-run is not a clean pass until the cause is fixed.
  Never retry until green.
- One review round plus at most one fix round per finding. After that the orchestrator decides, or escalates to
  the owner.

### 6. Release acceptance stays strict

- No requirement row becomes `accepted` without signed receipts checked against the owner's trust configuration
  (`tools/release/check_ledger.py`).
- The REVIEWS-EXACT row no longer names a model. It requires independent architecture/security and
  build/integration reviews of the exact release candidate, each by a model other than the one that wrote the
  code, plus the orchestrator's complete diff review, exact gates, CI and post-merge checks.

## Consequences

- Faster merges for ordinary work. Each ticket's evidence is its pull request, its CI run and the review
  record, not a private run folder.
- Until the hosted macOS job exists, a macOS-only regression can reach `main` and is caught later, either by that
  job or by the release-candidate protocol.
- The rule text in older documents is historical where it describes past runs (`docs/progress.md` entries); current
  rules live in `AGENTS.md`, this ADR and `docs/STATE.md`.
