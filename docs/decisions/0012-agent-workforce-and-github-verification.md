# ADR 0012: Agent workforce, GitHub-hosted verification and risk-scaled merges

- Status: On 2026-11-09 the owner accepted decisions 1–3, D2 (decision 4, hosted macOS replacing the leased floor
  as a merge requirement) and D3 (decision 5, risk-scaled reviews), and changed D1 (decision 2) to compile only
  locally. Decision 6 remains a default pending owner confirmation; defaults apply until changed.
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

The macOS requirements in decisions 2, 4 and 5 and the consequences below are superseded by the amendment at the
end of this ADR. The original text is retained as history.

### 1. Who does the work (owner instruction)

- **Workers** are OpenAI Codex CLI agents on `gpt-6.1-sol` (default for product code and tests) or
  `gpt-6.1-terra` (documentation, mechanical edits, reviews of Sol-written code). The owner may change this split.
- **The orchestrator** is a Claude Code session (Opus). It writes tickets, launches workers, reviews every diff,
  commits, opens pull requests, reads CI and merges. Workers never push, merge, tag, publish or write issues.
- Owner amendment 2026-11-09: Claude only orchestrates and reviews; Codex workers do all code, test, docs, ADR and merge-conflict writing (`gpt-6.1-sol` for code, `gpt-6.1-terra` for docs). The orchestrator writes tickets, commits reviewed worker diffs under the owner's identity, opens pull requests, watches CI, merges and closes issues.
- Owner amendment 2026-11-09: the identity rule applies to new commits; commits before this date keep their original `opencode` author and old trailers. Pushed history is never rewritten.
- Workers run under a locked-down launcher: the owner's personal Codex configuration is not loaded, memories,
  sub-agents, plugins, apps, MCP servers and web search are off, and the sandbox is
  `workspace-write`, limited to the ticket's worktree plus the build-cache volume. The sandbox also blocks
  `git commit`, so the orchestrator commits each reviewed diff under the owner's identity.
- Changed by the owner on 2026-11-09: workers may use network access inside the sandbox only to fetch dependencies
  from lockfiles (`cargo fetch --locked`, `npm ci`, or Gradle with strict verification). No new or upgraded
  dependencies are allowed unless the ticket says so. Web search remains off.
- Each ticket has an owned path set, frozen acceptance tests the worker may read but not edit, and an explicit
  "infeasible" exit. A diff that edits a frozen test, adds `#[ignore]`/`test.skip`/a quarantine, raises a deadline
  or weakens an assertion is rejected without review.

### 2. Where tests run (owner instruction)

- Heavy verification runs only on GitHub Actions: integration and journey tests, the 23-gate floors, packaging,
  campaigns and browser runs.
- The original D1 default allowed local unit tests and one test file.
- Changed by the owner on 2026-11-09: workers and the orchestrator only compile locally; no tests run locally.
  Allowed checks are `cargo check`, `cargo clippy`, `cargo test --no-run`, `cargo fmt --check`, TypeScript
  typecheck, Gradle `compileJava compileTestJava`, `tools/dev/check.sh py:<module>` (without bytecode), `bash -n`, `git diff --check`,
  and pure static checks such as the web contrast script (`tools/dev/check.sh`).
- Owner clarification on 2026-11-09: tickets are batched into one pull request per wave; GitHub tests (`ci-ok`, plus
  `macos-ok`) gate that wave merge and release candidates; single tickets do not get their own CI runs.
- Small docs-only pull requests still need `ci-ok` green on the exact head before merge.
  Other heavy GitHub suites (`lane.yml`, `package.yml`, campaign branches) run at release-candidate merges, and otherwise
  only when a ticket's acceptance needs them, such as a campaign fix, at the orchestrator's choice.

### 3. Where builds live (owner instruction)

- Build outputs, dependency caches and test scratch live on the owner's external SSD, on an APFS volume with
  ownership enabled (private-storage admission refuses `noowners` volumes; see ADR 0008). Two roots are set per
  machine and never committed: `XTRACE_DEV_CACHE` (dependency caches and per-worktree Cargo build directories) and
  `XTRACE_DEV_SCRATCH` (short-path private test scratch). `tools/dev/env.sh` derives every path from them.
- `tools/dev/clean.sh` removes the build and scratch directories of worktrees that no longer exist, between
  waves. It is a dry run unless `--apply` is given, never touches an active worktree's directories, and never
  deletes anything outside the two roots.

### 4. macOS evidence (accepted, owner answer D2)

- Accepted by the owner on 2026-11-09 (D2).
- The leased macOS 23-gate floor is no longer a merge requirement.
- The GitHub-hosted macOS arm64 job in `macos.yml` (free for public repositories) supplies macOS evidence;
  `macos-ok` must be green on the exact head for wave merges and release candidates.
- `macos.yml` runs on pushes to `wave/**` and `ultra/rc-*`, or by `workflow_dispatch`, not on every pull request.
- This reverses the owner's 2026-10-10 decision to run no hosted macOS jobs.
- PLATFORM-MAC acceptance still requires a fresh-profile install of the exact unsigned release package on a real
  Mac (ADR 0006, second addendum of 2026-10-10).

### 5. Merge rules scaled to risk (accepted, owner answer D3)

The owner accepted D3 on 2026-11-09: reviews scale with risk as below; the full ADR 0006 protocol applies only
at release candidates.

| Change | Required before merge |
|---|---|
| Docs, evidence notes, agent instructions | CI green on the exact head |
| Product code, tests, tooling | CI green on the exact head + one independent review by a different model than the writer + the orchestrator's own read of the whole diff |
| Shared contracts (Protobuf/OpenAPI schemas, SQLite migrations, XTF, redaction vocabulary, replay navigation), security or privacy paths, release tooling, CI workflows | as above, with two independent reviews |
| Release candidate (`ultra/rc-*`) | the full ADR 0006 protocol, with the leased macOS floor replaced as in decision 4 |

- The original default triggered the other workflows when a change touched them.
- Changed by the owner on 2026-11-09: "CI green" means the `ci-ok` check of `ci.yml` on the exact head, plus
  `macos-ok` for wave merges and release candidates, and any workflow the ticket names.
  Run `lane.yml`, `package.yml` and campaign branches at release-candidate merges,
  and otherwise only when ticket acceptance needs them, at the orchestrator's choice. Trigger them with
  `gh workflow run lane.yml --ref <branch> -f suite=<suite>`, `gh workflow run package.yml --ref <branch>`,
  or an `ultra/campaign/<project>` branch push, respectively.
- Every ticket has a GitHub issue labeled `agent-ticket`, plus `flaky-test` where it fits. Each wave has a tracking
  issue with a checklist (Wave 1 is #18). Pull requests use `Refs #N`, never closing keywords. The orchestrator closes
  an issue only after the fix is merged and post-merge `main` CI is green, with a comment naming the merge commit
  and CI run.
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

- Tickets share their wave's pull request and GitHub test runs; evidence includes that pull request, its CI runs
  and the review record.
- Hosted macOS evidence gates wave merges and release candidates without requiring the leased Mac floor.
- The rule text in older documents is historical where it describes past runs (`docs/progress.md` entries); current
  rules live in `AGENTS.md`, this ADR and `docs/STATE.md`.

## Amendment: macOS verification at release (2026-11-11)

The owner decided to use Linux tests during development because macOS tests take too long. This supersedes the
hosted macOS merge and release-candidate requirements and push triggers in decisions 2, 4 and 5 and the consequences
above. Hosted macOS CI no longer runs per push; `macos.yml` is available by manual dispatch. Agents must not wait
for, trigger or require macOS CI during development.

Merges require Linux `ci-ok` on the exact head and clean reviews under decision 5. At release, the owner runs
`tools/dev/macos-release-check.sh` locally on a Mac. Fix any failures before release. PLATFORM-MAC still requires
the fresh-profile install of the exact unsigned release package on a real Mac.
