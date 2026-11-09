# Documentation index

One line per document: what it answers and when to read it. Start with `docs/STATE.md`. Plans and ADRs are the
approved contracts; if code and a contract disagree, raise it instead of silently picking one.

## Always

- `AGENTS.md`: commands, traps, rules (plus the `AGENTS.md` in the area you change).
- `docs/STATE.md`: where the release stands, what is next, known flakes, owner decisions pending.
- `docs/decisions/0012-agent-workforce-and-github-verification.md`: how agents work here (roles, PRs, merge rules).

## Product and architecture (read the part you need)

- `docs/plans/x-trace/01-product.md`: what X-trace is for, primary journey, screens, endpoint states, non-goals.
- `docs/plans/x-trace/02-architecture.md`: components, dependency direction, tech stack.
- `docs/plans/x-trace/02a-language-framework-support.md`: support levels and what may be claimed.
- `docs/plans/x-trace/03-program-design.md`: crate/package ownership, performance budgets.
- `docs/plans/x-trace/03a-domain-and-storage.md`: domain model, ids, catalog, storage.
- `docs/plans/x-trace/03b-protocol-and-api.md`: XTP agent protocol and the client/viewer API.
- `docs/plans/x-trace/03c-runtime-adapters.md`: Java and Node adapter design.
- `docs/plans/x-trace/03d-clients-config-export-verification.md`: web/TUI/CLI behavior, exports, exercise, verification.
- `docs/plans/x-trace/04-vertical-slices.md`: slice acceptance lists (older numbering; map in `docs/STATE.md`).
- `docs/plans/x-trace/05-slice-1c4-recording-persistence.md`, `06-slice-1e3-observed-catalog.md`: detailed slice specs.
- `docs/plans/x-trace/00-status.md`: plan-level status notes (historical; `docs/STATE.md` is current).
- `docs/plans/x-trace/mockups/`: the first UI mockups (superseded by the new design round; several shown values are
  not backed by the product).

## Decisions (ADRs, `docs/decisions/`)

- 0001 operation ids and endpoint fingerprints · 0002 recording id read compatibility · 0003 runtime line/value/outcome
  probes and the honesty rules (§7) · 0004 signed language packs · 0005 framework seam scope for campaigns · 0006
  integration and acceptance mechanics (amended by 0012) · 0007 process provenance · 0008 private-storage admission ·
  0009 wave batching (amended by 0012) · 0010 replay navigation extras, catalog CLI, exit codes · 0011 recording
  limitations · 0012 agent workforce, GitHub verification, risk-scaled merges.

## Release

- `docs/releases/v0.01.md`: the release specification and acceptance bar.
- `docs/releases/v0.01-owner-review.md`, `docs/owner-review/README.md`: the owner's journeys and how to review them.
- `docs/usability/README.md`: the human usability protocol.
- `docs/releases/v0.01-continuation-prompt.md`: the prompt that starts the next orchestrator session.
- `evidence/v0.01/requirements.json` (ledger), `evidence/v0.01/workflow.json` (phase plan): machine-read; edit with care.

## Development and operations

- `tools/dev/README.md`: environment, prep, fast checks, cache cleanup.
- `docs/development/setup.md`: full developer setup and acceptance commands per component.
- `docs/packaging.md`: packages, supply chain, signing.
- `docs/security-local.md`: the local security model.
- `tools/release/README.md`: the 23-gate floor and release tools.
- `campaigns/README.md`: real-project campaigns.
- `docs/progress.md`: chronological log of past runs (long; read only for history).
