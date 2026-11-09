# X-trace: agent instructions

X-trace records what a Java/Spring or Node/Express backend actually did for each HTTP request, on the developer's
machine, and replays it step by step (web viewer, TUI, CLI). It is local-first and read-only. Its core rule is
honesty: it shows only what was observed and names every gap. Current state: `docs/STATE.md`. Doc map:
`docs/INDEX.md`. How agents work on this repo (roles, merges, models): `docs/decisions/0012-agent-workforce-and-github-verification.md`.

## Start here

1. Read `docs/STATE.md` (current main, open work, known flakes). Do not read every plan; `docs/INDEX.md` says
   which doc answers which question.
2. Read the `AGENTS.md` in the area you change, if there is one (listed under "Map").
3. Set up the environment once per shell: `source tools/dev/env.sh` (needs `XTRACE_DEV_CACHE` and
   `XTRACE_DEV_SCRATCH`; see `tools/dev/README.md`).

## Map

| Path | What | Area notes |
|---|---|---|
| `crates/` | Rust workspace (12 crates). `xtrace-domain` (pure types), `xtrace-application` (use cases), `xtrace-protocol` (generated XTP/XTF), `xtrace-ingest`, `xtrace-store` (SQLite + XTF segments), `xtrace-daemon` (loopback ingest + viewer API), `xtrace-cli` (the `xtrace` binary), `xtrace-runtime` (launch/attach/packs), `xtrace-private-storage`, `xtrace-tui`, `xtrace-export`, `xtrace-exercise` | `crates/xtrace-cli/AGENTS.md`, `crates/xtrace-store/AGENTS.md` |
| `adapters/java/` | Gradle: JVM agent (bootstrap + runtime), attach helper, static analyzer, Spring fixture app | `adapters/java/AGENTS.md` |
| `adapters/node/` | npm workspaces: Node loader/adapter, protocol codegen, analyzer | `adapters/node/AGENTS.md` |
| `web/app/` | React 19 + TS + Vite viewer, embedded into the daemon | `web/app/AGENTS.md` |
| `schema/` | Protobuf, OpenAPI (`schema/xtp-client/openapi.yaml`), fixtures incl. `schema/fixtures/replay/honesty-strings.json` | shared contract, see "Contracts" |
| `tools/release/` | 23-gate floor runner, ledger checker, CI floor helper | `tools/release/AGENTS.md` |
| `tools/qa/`, `campaigns/` | lane CI tooling; real-project campaigns (Petclinic, JHipster, Fineract, Directus, Medusa, Vendure) | |
| `tools/dev/` | env, prep, fast checks, cache cleanup | `tools/dev/README.md` |
| `evidence/v0.01/` | release ledger (`requirements.json`, 55 rows) and phase plan (`workflow.json`) | |
| `docs/` | plans, ADRs (`docs/decisions/`), release spec, progress log | `docs/INDEX.md` |

## Commands

Local checks are compile-only. Run the checks for what you touched; all tests run on GitHub:

```bash
tools/dev/check.sh rust:<crate>            # cargo check + clippy for one crate
tools/dev/check.sh rust:<crate>:<test>     # compile one integration test binary (--no-run)
tools/dev/check.sh java[:<module>]         # Gradle compileJava + compileTestJava, strict verification
tools/dev/check.sh node                    # generate:check + typecheck
tools/dev/check.sh web                     # typecheck + contrast; web:<file> is rejected
tools/dev/check.sh py:<module>             # python3 -B -m py_compile on the module file
tools/dev/check.sh fmt                     # cargo fmt --check
tools/dev/check.sh diff                    # whitespace / end-of-file check (CI gate 23)
```

All tests run on GitHub Actions (ADR 0012). Heavy suites include: the full workspace tests, CLI journey tests that need built
adapters, the 23-gate floors, packaging, campaigns and browser runs. Read CI with
`gh -R Legend101Zz/X-trace run view <id> --log-failed`. `tools/dev/prep.sh` (fetch dependencies, build adapters)
needs the network and runs outside any agent sandbox.

## Traps (each one has cost a past run real time)

- **Test scratch must be private.** Tests that run `xtrace init` need `TMPDIR` and `XTRACE_TEST_PRIVATE_SCRATCH`
  set to owner-only (0700) dirs on a volume with ownership enabled, with a short path. A `noowners` volume or `/tmp`
  gives admission errors that look like product bugs. `tools/dev/env.sh` sets this up. Never set them by hand.
- **CLI integration tests need built adapters.** 10 of 16 `crates/xtrace-cli/tests/*.rs` binaries use the built
  Java agent/fixture, the Node packages and Playwright Chromium. A bare `cargo test --workspace` on a fresh
  checkout fails. Leave those to CI.
- **Generated and embedded files change together.** OpenAPI → `web/app/src/api.generated.ts` (`npm run
  check:api`); Protobuf → `adapters/node/packages/protocol/src/gen` (`npm run generate:check`); web app →
  `crates/xtrace-daemon/assets/ui/` (`npm run embed`, `check:embedded`). Never hand-edit generated files.
- **Honesty rules are product law** (ADR 0003 §7). An "active line" exists only from a recorded line event; a
  method's line range is never shown as one. Absence is "not observed", never "did not run". No invented timing,
  values or parent links. Partial never looks complete. UI copy comes from `honesty-strings.json`.
- **No trailing whitespace and no blank lines at the end of a file**; end every file with a newline. CI gate 23
  runs `git diff --check`.
- **Big files.** `crates/xtrace-store/src/recording_store.rs` (7.7k lines), `tools/release/test_release_tools.py`
  (5.9k), `tools/release/run_gates.py` (2.6k). Read the part you need (grep first). Do not reformat them.
- **Known nondeterministic tests** are listed in `docs/STATE.md`. If one fails on your change, say so; never
  retry until green, and never mark a re-run green as clean.

## Rules

- **Never weaken a test, gate, budget, timeout or CI job**: no deleting or loosening assertions, `#[ignore]`,
  `test.skip`, quarantines, retries or raised deadlines. A skipped or unreached step is never a pass. If a task needs
  any of that, stop and report it as infeasible.
- **Real evidence**: a feature is done only when a real framework application runs through the packaged product
  path; mocks and fakes alone never complete it. Tests cover failure and privacy cases, not only the happy path.
- **Contracts**: Protobuf/OpenAPI schemas, SQLite migrations, the XTF format, the redaction vocabulary and replay
  navigation change only in a ticket that says so, with an ADR when semantics change.
- **Git**: work in your own worktree and branch. Workers do not commit, push or merge; the orchestrator reviews,
  commits and opens the pull request. Every change reaches `main` through a PR whose required check `ci-ok` is
  green on the exact head, with current `main` merged in (ADR 0012 §5). No closing keywords (`fixes #N`,
  `closes #N`) in commits, PR titles or PR bodies. Every ticket has an issue; use `Refs #N` in PRs and a tracking
  issue with a checklist for each wave (ADR 0012 §5).
- **Forbidden commands**: `pkill`, `killall`, kill by pattern, `kill $(pgrep ...)`, `sudo`, `diskutil`,
  `docker ... prune`, `rm -rf` outside your worktree or the dev cache. Signal only PIDs you started.
- **Public repository**: never commit secrets, captured values, owner-specific absolute paths or raw logs.
- **Code quality**: keep the dependency direction in `docs/plans/x-trace/02-architecture.md`; small focused
  modules, typed errors, explicit invariants, deterministic tests (no sleeps to synchronize; wait for an observable
  signal). Document public items where the contract is not obvious. No placeholder implementations or dead code.
  Comments explain intent, invariants and traps, not syntax.
- **Licenses**: learn from reference projects, but copy code only after checking license compatibility and
  recording attribution.

## Definition of done (for a ticket)

The ticket's acceptance criteria are met; compile-only checks for every touched area pass; generated and embedded
files are regenerated; `tools/dev/check.sh diff` is clean; your report lists every command you ran with its real
result. Tests run on GitHub; CI on the pull request is the final verdict.
