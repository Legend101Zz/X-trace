# X-trace implementation instructions

The approved product, architecture, program design, and vertical-slice plan under `docs/plans/x-trace/` are authoritative. Read all of them before changing code. If implementation evidence shows a contract is wrong, stop at that boundary and propose an ADR; do not silently redesign shared contracts.

## Delivery discipline

- Work only on the assigned slice and its acceptance criteria.
- Prefer the smallest real end-to-end implementation over broad scaffolding.
- A slice must exercise a real framework application through the packaged product path. Mocks alone do not complete a slice.
- Do not change shared domain semantics, Protobuf/OpenAPI schemas, SQLite migrations, XTF format, redaction vocabulary, or replay navigation without explicit orchestrator review.
- Commit coherent changes on the assigned branch. The orchestrator reviews, verifies, and merges to `main`.
- Never include secrets, credentials, captured private data, or local absolute paths in source, fixtures, logs, snapshots, evidence, or commits.

## Code quality

- Keep dependency direction aligned with `02-architecture.md` and crate/package ownership in `03-program-design.md`.
- Use descriptive names, small focused modules, typed errors, explicit invariants, and deterministic behavior.
- Document public Rust items with useful rustdoc, public Java APIs with Javadoc, and exported TypeScript APIs with TSDoc where the contract is not obvious.
- Developer comments must explain design intent, invariants, safety constraints, compatibility traps, or non-obvious tradeoffs. Do not narrate obvious syntax or leave generated comment noise.
- Avoid speculative abstractions, placeholder implementations, dead code, and acceptance-path `TODO`s.
- Tests accompany behavior and cover failure/privacy cases as well as the happy path.
- Formatting, lint, build, and relevant test commands must pass with no ignored failures before handoff.

## Storage and caches

Keep large build/cache data on the external SSD whenever the tool allows it:

```text
CARGO_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/cargo
CARGO_TARGET_DIR=/Volumes/Mrigesh SSD/.cache/xtrace/cargo-target
GRADLE_USER_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/gradle
XDG_CACHE_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/xdg
PNPM_HOME=/Volumes/Mrigesh SSD/.cache/xtrace/pnpm
```

Do not commit caches or generated build output.

## Reference posture

Use the primary references and repositories listed in `02-architecture.md`. Learn from their boundaries, compatibility practices, and tests. Copy code only when license compatibility and attribution are explicitly verified; architectural inspiration is not permission to copy.

