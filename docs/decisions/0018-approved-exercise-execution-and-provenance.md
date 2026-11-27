# ADR 0018: approved exercise execution and provenance

- Status: **proposed**; execution and ephemeral provenance slice (`EXERCISE-EXEC`, `EXERCISE-PROVENANCE`) for issue #136.
- Date: 2026-11-27.
- Refs #136, #121, #7. Supplements ADR 0017 (`0017-private-owner-reviewed-exercise-plans.md`), ADR 0003, `03a-domain-and-storage.md` §7.4, and `03d-clients-config-export-verification.md` §8.

## Context

ADR 0017 established private, expiring, owner-reviewed exercise plans (`Draft -> Reviewed -> Approved -> Consumed` / `Superseded`) with atomic `consume_once` compare-and-swap reservation, canonical BLAKE3 lifecycle hashing, opaque credential references, and literal loopback target syntax validation. Until now, no execution engine, connect-time destination guard, credential-resolution boundary, or SQLite provenance linkage existed, and `xtrace exercise run` returned exit code 9.

## Decision

### 1. Fail-closed approved execution boundary (`EXERCISE-EXEC`)

Execution requires an explicit operator command (`xtrace exercise run --plan-hash <hash> --plan-id <id> --confirm-owned-development-target`) or direct invocation of the application execution service. Automatic, background, or unapproved execution never occurs.

1. **Plan & approval gate**:
   - Before consuming approval, the execution service checks explicit operator confirmation (`confirm_owned_development_target == true`), verifies the plan identity (`plan_hash` and `plan_id`), verifies trusted wall time (`created_at <= now < expires_at` and monotonic relative to the prior transition), and requires `ExercisePhase::Approved` with exact matching item consent and ready inputs.
   - `ExercisePlanService::consume_once` performs the durable compare-and-swap transition `Approved -> Consumed` **before** persisting initial run provenance, resolving credentials, or opening any socket.
   - Consumed plans can never be re-run or re-armed. Ambiguous transport or timeout failures after write start are recorded as `delivery_unknown` and never retried.
2. **Loopback-only connect-time revalidation & transport isolation**:
   - Target syntax is restricted to canonical `http://127.0.0.1:<port>` or `http://[::1]:<port>` with an explicit nonzero port, no userinfo, no path, no query, no fragment, and `operator_owned_development == true`.
   - Before credential resolution or socket connection, an injectable `DnsResolver` trait resolves `(host, port)` and every returned `SocketAddr` is re-validated: non-empty result, matching port, strict loopback IP (`127.0.0.1` or `::1` only, matching the literal target), rejecting any non-loopback, unspecified, link-local, private, public, IPv4-mapped IPv6 (`::ffff:127.0.0.1`), or mixed address list (`non_loopback_destination` / `dns_resolution_failed`).
   - The transport connects directly to the validated `SocketAddr` with zero proxy resolution (`HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` ignored), `Connection: close`, and zero redirects (`3xx` responses are refused immediately with `redirect_refused` without following `Location`).
3. **Bounds enforcement (`ExecutionBounds`)**:
   - Concurrency is strictly `1` and request start rate is strictly `1` request/second (`ExecutionGate`).
   - Per-request and total execution timeouts are bounded at `10` seconds.
   - Encoded wire request size is bounded at `131_072` bytes (body max `65_536` bytes); response header bytes are bounded at `65_536` bytes and response body bytes at `1_048_576` bytes (1 MiB).
   - `X-XTrace-Exercise-Item: <item_id>` is emitted authoritatively using the lifecycle-rebased UUIDv8 item ID (`canonical::item_uuid(plan_hash, operation_id)`). Operator inputs cannot supply `x-xtrace-exercise-item` or other transport-control headers.
4. **Just-in-time secret isolation**:
   - `CredentialReference` handles are resolved only after `consume_once` and loopback IP validation succeed, through an injectable `CredentialResolver` trait returning a zeroize-on-drop, redacted-`Debug` `CredentialSecret`.
   - In the CLI, optional `--credentials-file <path>` reads an owner-private (`0700` parent, `0600` regular file, no-follow) JSON handle map through `xtrace-private-storage`; omitting it fails closed if the plan contains any `CredentialReference`.
   - Resolved credential bytes enter only the ephemeral `PreparedWireRequest` buffer (zeroized on drop, redacted in `Debug`) and are never logged, returned in receipts/errors, or persisted in SQLite.
5. **Crate layering (`--locked` compatibility)**:
   - `xtrace-exercise::executor` remains IO- and async-runtime-free (`core::net` types and injectable `DnsResolver`, `CredentialResolver`, `HttpTransport` traits) so `xtrace-exercise` keeps its zero-networking-crate invariant and `Cargo.lock` remains unchanged.
   - `xtrace-application::exercise::exec` owns `ExerciseExecutionService`, combining `ExercisePlanService::consume_once`, `xtrace_exercise::executor`, and `ExerciseProvenancePort`.
   - `xtrace-cli::exercise` implements the concrete `tokio::net::TcpStream` HTTP/1.1 loopback transport and wires `xtrace exercise run` (retaining the exit-9 fallback when `--plan-hash` is omitted) and `xtrace exercise provenance`.

### 2. Ephemeral provenance persistence (`EXERCISE-PROVENANCE`, migration v11)

Migration `v0011_exercise_provenance` appends three `STRICT` SQLite tables (preserving migrations `v1..v10` verbatim and bumping `CURRENT_SCHEMA_VERSION` to `11`):

- `exercise_runs`: keyed by UUIDv7 `exercise_run_id`, foreign-keyed to `projects(project_id)`, storing `plan_id`, `plan_hash`, sanitized `target_origin` (`http://127.0.0.1:<port>` or `http://[::1]:<port>`), `status` (`reserved`, `running`, `succeeded`, `failed`, `delivery_unknown`), bounded closed-vocabulary `failure_class`, `started_at`, and `finished_at`.
- `exercise_items`: keyed by `(exercise_run_id, exercise_item_id)`, storing `project_id`, `operation_id`, `method`, `route_template` (never interpolated inputs), `effect`, `status`, `failure_class`, `http_status`, `request_bytes`, `response_bytes`, and `duration_ms`.
- `exercise_recording_links`: keyed by `(exercise_run_id, exercise_item_id, recording_id)` with `UNIQUE (project_id, recording_id)` and composite foreign keys to both `exercise_items(project_id, exercise_run_id, exercise_item_id)` and `recordings(project_id, recording_id)`, establishing explicit project-scoped `exercise_item_id -> recording_id` linkage compatible with ADR 0002 recording IDs.

Legacy databases upgrade to v11 with zero backfilled exercise rows. Private operator inputs, request/response bodies, headers, and credential handles/secrets are never persisted in SQLite provenance tables.

## Remaining work and evidence boundary

- Automatic correlation of daemon-ingested `RecordingStarted.exercise_item_id` (proto field 14) into `exercise_recording_links` inside `xtrace-daemon`/`xtrace-store` ingestion remains separate from this slice; explicit provenance linking (`SqliteExerciseProvenanceStore::link_recording` and `xtrace exercise provenance --link-item ... --recording-id ...`) persists and queries the linkage cleanly.
- Per ADR 0012 §2, local verification in this slice is compile-only (`cargo check`, `cargo clippy`, `fmt`, `diff`); hosted CI executes unit tests and end-to-end packaged journeys before release acceptance.
