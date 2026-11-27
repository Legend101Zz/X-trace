# ADR 0019: Worker and child-process session linkage and explicit correlation gaps

- Status: **proposed**; process-linkage slice (`PROCESS-LINKAGE`) for issue #136.
- Date: 2026-11-27.
- Refs #136, #7. Supplements ADR 0003 (`0003-runtime-line-value-and-outcome-probes.md` addendum for `GapReason` values `10`, `11` and `InteractionKind::PROCESS`), ADR 0011 (`0011-recording-limitations.md`), and ADR 0012 (`0012-agent-workforce-and-github-verification.md` §2).

## Context

Node.js and JVM applications routinely offload work across `worker_threads.Worker`, `child_process.{spawn,fork,execFile}`, and `java.lang.ProcessBuilder.start()`. Historically, X-trace kept launcher injection private to the root application via `restoreLauncherEnvironment()` (Node `capture-start.cts` / `start-capture.ts`) so `NODE_OPTIONS` and `XTRACE_BOOTSTRAP_PATH` never leak into child processes or worker threads, while providing no durable linkage model or runtime boundary observation for spawned workers/children. Without explicit boundary records, uninstrumented child work or detached workers silently disappeared without a declared gap, and supported worker/child runtime sessions had no project-safe correlation ledger.

## Decision

### 1. Bounded domain model (`xtrace-domain::process_linkage`)

`crates/xtrace-domain/src/process_linkage.rs` defines the language-neutral linkage vocabulary:

- `SpawnKind`: `NodeWorker` (`node_worker`), `NodeChildProcess` (`node_child_process`), and `JvmFork` (`jvm_fork`).
- `SessionLinkStatus`: `Linked` (`linked`), `UninstrumentedGap` (`uninstrumented_gap`), and `CorrelationLost` (`correlation_lost`).
- `RuntimeSessionLink`: holds strictly bounded metadata (`SessionLinkId`, optional `parent_recording_id`, required `parent_session_id`, optional `child_recording_id`, optional `child_session_id`, `spawn_kind`, `status`, optional `gap_reason`, optional 32-byte BLAKE3-256 `correlation_token_hash`, and `created_at_ms`).
- **Privacy invariant**: `RuntimeSessionLink` excludes raw command paths, raw `argv`, raw environment maps, `workerData` payloads, and raw correlation tokens. Correlation tokens are hashed with domain separation (`hash_correlation_token`) before persistence.
- **Structural invariants** (`RuntimeSessionLink::validate`): `Linked` requires `child_session_id` and `gap_reason == None`; `UninstrumentedGap` requires `child_session_id == None`, `child_recording_id == None`, and `gap_reason` in `{ChildProcessNotInstrumented, BootstrapConsumed}`; `CorrelationLost` requires `child_recording_id == None` and `gap_reason == Some(CorrelationLost)`; self-links (`parent_session_id == child_session_id` or identical recording IDs) are rejected.

### 2. SQLite v12 migration and store (`xtrace-store`)

Migration `v0012_process_linkage` appends the `STRICT` `runtime_session_links` table and bumps `CURRENT_SCHEMA_VERSION` to `12`, leaving migrations `v1..v11` verbatim and untouched:

- Foreign keys on `parent_recording_id` and `child_recording_id` to `recordings(recording_id)` enforce recording integrity when present, while allowing session-scoped links without an active recording.
- SQL `CHECK` constraints mirror `RuntimeSessionLink::validate` so malformed states, negative timestamps, non-32-byte hashes, and self-links are rejected in SQL.
- Indexes on `(parent_session_id, created_at_ms, link_id)`, partial `parent_recording_id`, partial `child_session_id`, and partial `child_recording_id` support bounded deterministic queries.
- `SqliteProcessLinkageStore` (`crates/xtrace-store/src/process_linkage_store.rs`) implements `ProcessLinkagePort` (`record_session_link`, `list_child_links`, `list_child_links_for_recording`, `find_parent_link`, `find_parent_link_by_recording`) with idempotent replay on identical `link_id` and `Conflict` on mismatched replay.

### 3. Application reconciliation (`xtrace-application::process_linkage`)

`ProcessLinkageService` provides `link_child_session`, `record_uninstrumented_gap`, `record_correlation_lost`, `record_gap`, and `reconcile_child_session`:

- Incoming child handshakes are linked only when a `ParentSpawnClaim` exists, `spawn_kind` matches, parent/child identities differ, and the child's hashed correlation token matches `expected_token_hash`.
- Missing, malformed, or mismatched correlation tokens never fabricate a `Linked` record; reconciliation fails closed to an explicit `CorrelationLost` gap when a parent claim exists and returns `NotFound` when no parent session exists.

### 4. Node adapter boundary (`process-linkage.cts`)

`adapters/node/packages/adapter-core/src/process-linkage.cts` integrates with `modules.cts`, `manifest.cts`, `capture-start.cts`, `worker-core.ts`, and `REQUIRED_DIST_FILES` (`"process-linkage.cjs"`):

- Wraps `worker_threads.Worker` and `child_process.{spawn,fork,execFile}` with re-entrancy protection and `captureSuppressed()` isolation (wrapping X-trace's own `transport-worker.js` creation in `withoutCapture`).
- **Environment isolation preserved**: never reads, copies, or injects `NODE_OPTIONS`, `XTRACE_BOOTSTRAP_PATH`, `XTRACE_NODE_ORIGINAL_OPTIONS`, or `XTRACE_NODE_OPTIONS_WAS_SET`; `restoreLauncherEnvironment()` and `preload-environment.test.ts` remain untouched.
- Emits bounded explicit gap events (`child-process-not-instrumented`, or `correlation-lost` for `eval: true` / detached worker boundaries) when child instrumentation is absent, and provides `registerChildSessionLink` / single-use `withOptInChildLink` for explicit opt-in linkage (failing closed with `bootstrap-consumed` or `correlation-lost` on reuse or mismatch).

### 5. Java agent boundary (`ProcessLinkageBridge` + `ProcessLinkageInstrumentation`)

- `ProcessLinkageInstrumentation` transforms `java.lang.ProcessBuilder.start()` via ByteBuddy `RETRANSFORMATION` with `assureReadEdgeFromAndTo` on bootstrap-visible `ProcessLinkageBridge`, ignoring all other classes and never inspecting `ProcessBuilder.command()` or `ProcessBuilder.environment()`.
- Uninstrumented `ProcessBuilder.start()` emits `BootstrapBridge.CHILD_PROCESS_NOT_INSTRUMENTED_SYMBOL` (`GAP_REASON_CHILD_PROCESS_NOT_INSTRUMENTED`), while verified single-use `ProcessLinkageBridge.withOptInChildLink` / `registerChildSessionLink` emits `BootstrapBridge.PROCESS_LINK_SYMBOL` (`RECORDING_EVENT_KIND_ASYNC_LINK` with `INTERACTION_KIND_PROCESS`, `driver = "jvm"`, `method = "fork"`), failing closed to `GAP_REASON_BOOTSTRAP_CONSUMED` or `GAP_REASON_CORRELATION_LOST` otherwise.
- `agent-manifest.json` and `RecordingWriter.sendCapabilities` advertise `process_linkage`.

## Verification

Per ADR 0012 §2, local verification in this slice is strictly compile-only (`cargo fmt --all --check`, `cargo check --workspace --all-targets --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `tools/dev/check.sh java`, TypeScript `--noEmit`, and `git diff --check`). Hosted CI executes the Rust, Node, and Java unit and integration suites added here.
