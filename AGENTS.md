# X-trace implementation instructions

The approved product, architecture, program design, and vertical-slice plan under `docs/plans/x-trace/` are authoritative. Read all of them before changing code. If implementation evidence shows a contract is wrong, stop at that boundary and propose an ADR; do not silently redesign shared contracts.

## Delivery discipline

- Work only on the assigned slice and its acceptance criteria.
- Prefer the smallest real end-to-end implementation over broad scaffolding.
- A slice must exercise a real framework application through the packaged product path. Mocks alone do not complete a slice.
- Do not change shared domain semantics, Protobuf/OpenAPI schemas, SQLite migrations, XTF format, redaction vocabulary, or replay navigation without explicit orchestrator review.
- Use GPT-6 Terra or Luna agents for implementation and review work when delegation is useful; select Medium or High reasoning for the complexity of the bounded slice. The main orchestrator remains responsible for decomposition, architecture coherence, and independent review and testing.
- Commit coherent changes on the assigned branch. Agents must not merge or push `main`; the orchestrator alone reviews, verifies, and may merge or push after the required approval.
- Never include secrets, credentials, captured private data, or local absolute paths in source, fixtures, logs, snapshots, evidence, or commits.

## Approval-gated phase workflow

Every phase follows this fixed boundary: `Phase -> Implement -> Review -> Verify -> Status -> user approval -> Next phase`.

- The orchestrator defines a small, verifiable phase and its acceptance checks before implementation. Work may use multiple bounded agents for implementation, review, debugging, or architecture checks, but their output is untrusted until independently reviewed and tested by the orchestrator.
- After review and verification, stop. The phase status report must enumerate: completed work; files or behavior changed; tests and verification run; issues or decisions; remaining work; and the exact next proposed phase.
- Do not start, merge, push, schedule, or continue the next phase until the user explicitly approves that proposed next phase. No background automation may continue implementation across an approval boundary.
- The user may explicitly authorize a bounded multi-phase autonomous batch as an exception to the per-phase approval stop. That authorization is approval only for the named batch scope and deadline; record it in the execution checkpoint before continuing. This does not waive any slice gate: each slice still requires its own implementation, independent review, verification, and merge decision before moving forward. Do not merge an unreviewed or unverified slice, exceed the authorized scope/deadline, or infer authorization from urgency or silence. Provide the user a consolidated review of the completed batch afterward.

## Code quality

- Keep dependency direction aligned with `02-architecture.md` and crate/package ownership in `03-program-design.md`.
- Use descriptive names, small focused modules, typed errors, explicit invariants, and deterministic behavior.
- Document public Rust items with useful rustdoc, public Java APIs with Javadoc, and exported TypeScript APIs with TSDoc where the contract is not obvious.
- Developer comments must explain design intent, invariants, safety constraints, compatibility traps, or non-obvious tradeoffs. Do not narrate obvious syntax or leave generated comment noise.
- Avoid speculative abstractions, placeholder implementations, dead code, and acceptance-path `TODO`s.
- Tests accompany behavior and cover failure/privacy cases as well as the happy path.
- Formatting, lint, build, and relevant test commands must pass with no ignored failures before handoff.

## Storage and caches

Keep large build/cache data on the external SSD whenever the tool allows it. Point every cache at one cache root on that drive, written here as `<CACHE>`. The real path is machine-specific: set it locally and never commit it.

```text
CARGO_HOME=<CACHE>/cargo
CARGO_TARGET_DIR=<CACHE>/cargo-target
GRADLE_USER_HOME=<CACHE>/gradle
XDG_CACHE_HOME=<CACHE>/xdg
PNPM_HOME=<CACHE>/pnpm
NPM_CONFIG_CACHE=<CACHE>/npm
```

Release-gate builds run through `tools/release/leased_run.py`, which admits a private root only on a volume with ownership enabled; a `noowners` mount is refused.

Do not commit caches, generated build output, or owner-specific absolute paths.

## Reference posture

Use the primary references and repositories listed in `02-architecture.md`. Learn from their boundaries, compatibility practices, and tests. Copy code only when license compatibility and attribution are explicitly verified; architectural inspiration is not permission to copy.
