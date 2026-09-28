# Program Design: X-trace

**Gate:** 3, approved 2026-09-28  
**Date:** 2026-09-28  
**Depends on:** approved Product and Architecture gates  
**Scope:** executable contracts, module ownership, state machines, algorithms, commands, failure semantics, compatibility, and verification. It deliberately does not split the work into implementation slices or tickets; that belongs to Gate 4.

## 1. Design outcome

The implementation is one local product with three independently versioned boundaries:

1. **Core boundary:** Rust domain and application crates own all product truth and transitions.
2. **Adapter boundary:** Java and Node.js language packs emit facts and events through XTP-Agent; they never write product storage or invent UI state.
3. **Client boundary:** web, TUI, and CLI issue the same commands and queries through XTP-Client or the in-process Rust facade.

All persistent and wire formats are designed so a later Python, Ruby, Go, or Rust pack adds capabilities without adding language-specific branches to the core domain.

The design is split into four reviewable appendices:

- [Domain and storage](03a-domain-and-storage.md)
- [Protocols and client API](03b-protocol-and-api.md)
- [Runtime adapters](03c-runtime-adapters.md)
- [Clients, configuration, exports, and verification](03d-clients-config-export-verification.md)

## 2. Non-negotiable invariants

These rules are enforced in types, database constraints, protocol validation, and tests:

1. An inferred path can never become an observed frame without a `RecordingId`.
2. An operation is stable across handler refactors when method, normalized route, application component, and transport binding remain stable. Handler identity is versioned evidence, not part of the operation ID.
3. Every durable claim records provenance, source, source revision, producer version, and first/last catalog revision.
4. A recording is immutable after finalization. Recovery may change `recording_status` from `recording` to `partial`, but never rewrite accepted event objects.
5. Every value is one of `captured`, `redacted`, `truncated`, `unavailable`, or `dropped`; empty and unknown are never conflated.
6. Adapter-originated timestamps are useful evidence but never the sole total-order key. Per-session sequence numbers establish adapter order.
7. A request thread must never block indefinitely on capture. Optional detail is shed before structural events.
8. Web and TUI cannot access SQLite, trace objects, or raw agent messages.
9. Repository source is displayed as matching evidence only when its content hash matches the recording. Otherwise the UI shows a mismatch or an allowed captured excerpt.
10. Every scan, capture, attach, exercise, export, Postman connection, purge, and migration is an explicit run or auditable operation.
11. No secret value is persisted in configuration, logs, exports, browser state, or Postman metadata.
12. Every public error has a stable code, user-safe message, retryability, and optional structured remediation.

## 3. Workspace and ownership

```text
x-trace/
  Cargo.toml
  rust-toolchain.toml
  deny.toml
  justfile
  crates/
    xtrace-domain/
    xtrace-application/
    xtrace-protocol/
    xtrace-ingest/
    xtrace-store/
    xtrace-runtime/
    xtrace-exercise/
    xtrace-export/
    xtrace-daemon/
    xtrace-cli/
    xtrace-tui/
    xtrace-testkit/
  agents/
    java/
      settings.gradle.kts
      agent-core/
      agent-bootstrap/
      attach-helper/
      static-analyzer/
      instrumentation-api/
      instrumentation-servlet-javax/
      instrumentation-servlet-jakarta/
      instrumentation-spring-webmvc/
      instrumentation-spring-webflux/
      instrumentation-jdbc/
      instrumentation-http-clients/
      fixtures/
    node/
      package.json
      packages/
        protocol/
        adapter-core/
        loader-cjs/
        loader-esm/
        instrumentation-http/
        instrumentation-express/
        instrumentation-fastify/
        instrumentation-nest/
        instrumentation-koa/
        static-analyzer/
        fixtures/
  schema/
    xtp-agent/
    xtp-client/
    config/
    fixtures/
  web/
    app/
    generated/
    e2e/
  examples/
  docs/
    adr/
    compatibility/
```

### 3.1 Rust crate responsibilities

| Crate | Owns | Must not own |
|---|---|---|
| `xtrace-domain` | IDs, entities, value/provenance types, state transitions, reconciliation primitives | Tokio, SQL, HTTP, Protobuf, UI |
| `xtrace-application` | commands, queries, use-case services, authorization/safety policy, ports | concrete storage, process APIs, UI |
| `xtrace-protocol` | generated Protobuf/OpenAPI types and explicit translation to domain DTOs | domain decisions |
| `xtrace-ingest` | connection workers, ordering validation, correlation, batching, backpressure | SQLite schema, UI fanout policy |
| `xtrace-store` | bundled SQLite, object store, migrations, recovery, retention | use-case policy |
| `xtrace-runtime` | launch, attach, process discovery, adapter package selection | Java/Node framework logic |
| `xtrace-exercise` | request-plan synthesis and bounded execution | silent approval, credential persistence |
| `xtrace-export` | deterministic OpenAPI/Postman/cURL projections | network upload policy |
| `xtrace-daemon` | lifecycle, HTTP/WebSocket adapters, auth, dependency wiring | domain rules in handlers |
| `xtrace-cli` | command parsing, prompts, stable machine output | duplicated use cases |
| `xtrace-tui` | terminal rendering and input mapping | direct storage reads |
| `xtrace-testkit` | protocol fixtures, fake clock, sample apps, conformance harness | production-only behavior |

`xtrace-domain` forbids `unsafe` and all I/O. `xtrace-application` may depend on async traits but not Tokio concrete types. Infrastructure implements ports.

### 3.2 Core application facade

The shared facade is intentionally command/query oriented:

```rust
pub trait XTraceApplication: Send + Sync {
    async fn execute(&self, command: Command, ctx: RequestContext)
        -> Result<CommandReceipt, AppError>;
    async fn query(&self, query: Query, ctx: RequestContext)
        -> Result<QueryResult, AppError>;
    fn subscribe(&self, filter: EventFilter, ctx: RequestContext)
        -> Result<EventStream, AppError>;
}
```

Commands are state-changing intentions; queries are read-only projections. The HTTP API, TUI controller, and CLI all translate into this facade. No client receives a repository or database handle.

Commands:

- `InitializeProject`
- `StartScan`
- `StartLaunchCapture`
- `StartAttachCapture`
- `ArmFocusedCapture`
- `StopRuntimeSession`
- `CreateExercisePlan`
- `ApproveExercisePlan`
- `CancelRun`
- `CreateExport`
- `ConnectPostman`
- `PublishPostmanCollection`
- `UpdateProjectPolicy`
- `PreviewRetention`
- `ApplyRetention`

Queries:

- `GetProject`, `GetDaemonHealth`, `ListRuns`, `GetRun`
- `ListCatalogRevisions`, `CompareCatalogRevisions`
- `ListOperations`, `GetOperation`, `ListRecordings`
- `GetRecording`, `GetReplayWindow`, `GetFrame`, `GetSourceArtifact`
- `GetCaptureCapabilities`, `GetInstalledLanguagePacks`
- `GetExercisePlan`, `PreviewExport`, `GetExport`

Every command accepts a client-generated idempotency key. Retrying a completed key returns the original receipt; reusing a key with different input returns `XTR-COMMAND-409`.

## 4. Aggregate boundaries

The domain uses small aggregates rather than one project-sized object:

- **Project aggregate:** repository identity, configuration reference, active policy versions.
- **Catalog aggregate:** one immutable revision plus reconciled operation versions and claims.
- **RuntimeSession aggregate:** one process/adapter handshake, capability snapshot, and capture lifecycle.
- **Recording aggregate:** one correlated request execution, ordered event segments, completion and gap summary.
- **ExercisePlan aggregate:** immutable reviewed request candidates and approval decision.
- **Export aggregate:** exact input revision, policy, formats, hashes, and optional delivery receipt.

Cross-aggregate workflows run in application services and commit through an outbox. Domain objects never perform I/O.

## 5. State machines

### 5.1 Run

```text
requested -> preparing -> running -> succeeded
                    |         |  \-> partial
                    |         \----> failed
                    \--------------> cancelled
```

- `requested` is durable before external work starts.
- `preparing` resolves repository, adapter, target process, policy, and locks.
- `running` means at least one external effect or worker has begun.
- `partial` is a successful durable result with declared gaps.
- terminal states are immutable.
- cancellation is cooperative; if a process cannot be stopped, the run becomes `failed` with remediation rather than claiming cancellation.

### 5.2 Runtime session

```text
created -> authenticating -> negotiating -> active -> draining -> closed
             |                 |           |           |
             +-----------------+-----------+----------> failed
```

Only `active` sessions may create recordings. `draining` accepts required completion/drop markers but rejects new recordings. Capability negotiation is stored with the session.

### 5.3 Recording

```text
opened -> recording -> finalizing -> complete
              |             |  \-> partial
              |             \----> invalid
              \------------------> abandoned (recovery only)
```

- A structural `RecordingStarted` opens the aggregate.
- Required end markers and segment durability precede `complete`.
- Any drop, disconnect, unsupported boundary, or crash becomes a gap and normally yields `partial`, not `invalid`.
- `invalid` is reserved for untrustworthy identity/order/correlation violations.
- `abandoned` is converted to `partial` or `invalid` during recovery before it is visible to clients.

### 5.4 Exercise plan

```text
draft -> ready_for_review -> approved -> executing -> completed
              |                 |           |  \-> partial
              |                 |           \----> failed
              |                 \---------------> expired
              \---------------------------------> rejected
```

Approval hashes the canonical plan. Any change to target, inputs, credentials reference, endpoint selection, budgets, or mutation classification invalidates approval and returns the plan to `ready_for_review`.

### 5.5 Export

```text
requested -> projecting -> ready -> delivered
                  |          |  \-> delivery_failed
                  \---------> failed
```

Local export ends at `ready`. Postman delivery is a separate explicit transition, so a network failure never loses the local collection.

## 6. Concurrency and task ownership

The daemon uses one root cancellation token and supervised task groups:

```text
daemon supervisor
  adapter listener
    connection reader -> validator -> session ingress channel
  ingest coordinator
    recording assembler shards -> segment writer
  metadata writer (single SQLite writer queue)
  query pool
  HTTP/WebSocket server
  process supervisor
  retention/recovery worker (explicit or startup only)
```

Rules:

- one bounded queue per boundary; no unbounded Tokio channel;
- one SQLite metadata writer serializes write transactions; read queries use a bounded pool;
- recording assemblers are sharded by `RecordingId`, so all events for one recording are processed in order without a global lock;
- object compression and hashing run in a bounded blocking pool;
- WebSocket delivery is lossy for replaceable progress notifications but never the storage path;
- shutdown order is listener stop, ingress drain, segment seal, metadata commit, client notification, discovery-file removal;
- every spawned task is named, supervised, and joined; detached tasks are forbidden.

Initial capacities are configuration constants with tested defaults, not magic literals:

| Boundary | Default | Behavior at capacity |
|---|---:|---|
| Adapter socket decode | 64 batches | stop reading briefly; TCP/TLS backpressure |
| Validated ingest | 256 batches | issue throttle level 1, then 2 |
| Per-recording assembly | 2,048 events | drop optional detail with explicit notice |
| SQLite commands | 1,024 operations | producers await off request threads |
| WebSocket client | 128 notifications | coalesce progress; disconnect persistently slow clients |

Adapters apply a priority ladder: request lifecycle and error markers, interaction boundaries, method frames, line cursors, values. Lower-priority events are shed first.

## 7. Error contract

All public errors use:

```rust
pub struct AppError {
    pub code: ErrorCode,
    pub category: ErrorCategory,
    pub message: UserSafeMessage,
    pub retry: RetryAdvice,
    pub remediation: Vec<Remediation>,
    pub correlation_id: CorrelationId,
    pub details: BTreeMap<String, SafeScalar>,
}
```

Categories are `validation`, `not_found`, `conflict`, `compatibility`, `permission`, `policy`, `resource`, `transport`, `corruption`, `internal`, and `cancelled`.

Stable code families:

| Prefix | Area | Example |
|---|---|---|
| `XTR-PROJECT-*` | repository/project identity | repository moved or config invalid |
| `XTR-ADAPTER-*` | pack selection/handshake | incompatible protocol major |
| `XTR-ATTACH-*` | running process attach | JVM disallows dynamic agent loading |
| `XTR-CAPTURE-*` | recording | value budget exhausted |
| `XTR-STORE-*` | database/objects/migration | object hash mismatch |
| `XTR-PLAN-*` | exercise safety | approval hash changed |
| `XTR-EXPORT-*` | projection/delivery | Postman authentication rejected |
| `XTR-CLIENT-*` | local API/session | invalid origin or expired browser token |
| `XTR-COMMAND-*` | command semantics | idempotency conflict |

Internal errors retain a source chain in owner-only diagnostic logs. Captured values and secrets are never formatted into an error chain.

## 8. Configuration model

Precedence is fixed:

```text
command flags > environment variables > repository .xtrace/config.toml
> user config > built-in defaults
```

Configuration is parsed into a typed effective config and validated before a run is created. The run stores a sanitized canonical snapshot and its hash. Unknown fields fail by default; an explicit compatibility mode may warn for a newer minor schema.

Repository configuration may contain:

- source roots and application packages;
- launch profiles and non-secret environment variable names;
- inclusion/exclusion patterns;
- redaction rules and capture budgets;
- endpoint grouping and base URL hints;
- safe exercise environment declarations;
- retention policy;
- export folder rules.

Secrets are referenced by logical name and resolved from environment, prompt, or OS credential store at execution time.

## 9. Versioning policy

X-trace release versions use SemVer, but compatibility is evaluated separately for each boundary:

- **XTP-Agent:** major/minor in every envelope. Same major negotiates capabilities; a new required field requires a major bump.
- **XTP-Client:** versioned under `/api/v1`; additive response fields are minor-compatible. Removing or changing semantics creates `/api/v2`.
- **SQLite schema:** monotonic integer, forward-only migrations, backup before any migration that rewrites data.
- **XTF object:** major/minor header. Readers support all object majors produced by the current and previous X-trace major release, or migrate explicitly.
- **Config:** `schema_version` with strict validation and an `xtrace config migrate --dry-run` command.
- **Language packs:** independent SemVer plus protocol range, runtime range, framework range, and capability matrix.

Supported runtime policy for the first compatibility campaign:

- Java fixture lanes start with JDK 17, 21, and 25. Framework claims are made only for combinations that pass fixtures; native-image binaries are detected-only in v1 unless a separate instrumented path is proven.
- Node fixture lanes start with the currently supported LTS lines, Node 22 and 24 as of 2026-09-28. Node 26 remains Preview while it is Current. The matrix follows upstream lifecycle rather than hard-coding perpetual support.
- Spring coverage is split by generation and namespace. The fixture campaign begins with Spring Boot 4.1/4.0 and the published stable 3.5/3.4/3.3 lines, then labels every combination according to actual results rather than marketing it broadly.

The published manifest, not these planning examples, is the runtime truth.

## 10. Performance and resource budgets

These are release gates measured on declared sample applications and hardware profiles:

| Scenario | Gate |
|---|---:|
| Idle daemon RSS | <= 120 MiB excluding browser |
| Idle instrumented app overhead | <= 2% throughput loss at p50; <= 3% at p95 |
| Standard capture overhead | <= 10% throughput loss and <= 10% p95 latency increase |
| Focused capture | <= 30% p95 latency increase for the armed endpoint; clearly labelled |
| Request-thread capture enqueue | p99 <= 200 microseconds before degradation |
| New completed recording visible | p95 <= 750 ms after response completion |
| Open a 10,000-frame recording | initial replay window <= 1.5 s |
| Endpoint list query, 10,000 operations | p95 <= 200 ms warm |
| Clean shutdown | <= 5 s before forced partial finalization |

Budgets are measured, not assumed. A missed budget blocks a Supported claim or lowers the capability status.

## 11. Security and privacy mechanics

- The daemon binds loopback only and chooses a random port.
- Adapter transport uses TLS 1.3 with an ephemeral daemon certificate pinned by the launch/attach bootstrap. A per-session secret authenticates the adapter after the secure channel is established.
- The web bootstrap token appears only in the URL fragment, is single-use, and is exchanged for a same-site HTTP-only cookie.
- Project directories and bootstrap files are owner-only. Stale discovery records must pass PID, process-start-time, port, and nonce checks.
- Redaction runs in adapters before values enter transport. The daemon runs a second policy audit before storage and export.
- Values use depth, element, string, object, per-event, and per-recording budgets.
- Browser state stores IDs and UI choices only, never captured values or credentials.
- Postman keys live in the OS credential store. Stored metadata includes only workspace/collection IDs and delivery receipts.
- Product telemetry is off by default; local diagnostics contain counters, versions, codes, and correlation IDs only.

## 12. Coding standards and CI topology

Required root commands:

```text
just bootstrap
just format
just lint
just test
just test-protocol
just test-fixtures java
just test-fixtures node
just test-e2e web
just test-e2e tui
just test-security
just test-performance
just dist
```

CI lanes:

1. schema lint and breaking-change detection;
2. Rust format, Clippy, unit/property tests, docs, MSRV, dependency and license checks;
3. Java format/static analysis/unit/advice tests plus forked-JVM matrix;
4. Node format/lint/type/unit plus CJS/ESM/framework matrix;
5. cross-language protocol goldens;
6. SQLite migration and crash-recovery fixtures;
7. privacy canaries across storage, logs, API, and exports;
8. web accessibility, keyboard, visual, and real-daemon journeys;
9. TUI snapshot plus pseudo-terminal journeys;
10. scheduled compatibility and performance campaigns. Scheduled CI never causes work in a user's repository.

The repository denies generated drift, warnings, undocumented unsafe code, direct domain-to-infrastructure imports, and distributable licenses outside the approved policy.

## 13. Observability of X-trace itself

Local diagnostics use structured events with stable names:

- daemon lifecycle;
- adapter connection/capability negotiation;
- queue utilization and throttle transitions;
- segments written and bytes stored;
- recordings complete/partial/invalid;
- migration/recovery outcomes;
- command duration and error code.

Diagnostics never include source text, route parameter values, headers, bodies, SQL parameters, local-variable values, or environment values. `xtrace doctor --bundle` previews the exact sanitized files before writing a support bundle.

## 14. Gate 3 acceptance decisions

Approval of Gate 3 accepts:

1. the crate/package ownership and inward dependency rules in this document;
2. stable operation identity separated from versioned handler evidence;
3. immutable catalog revisions, runs, recordings, trace objects, and exports;
4. the command/query facade shared by CLI, TUI, and web;
5. explicit state machines for runs, sessions, recordings, exercise plans, and exports;
6. sharded per-recording ingestion, a serialized SQLite metadata writer, bounded queues, and priority-based degradation;
7. the public error taxonomy and idempotent command contract;
8. strict typed configuration with secret references rather than stored secrets;
9. independently versioned protocol, API, store, object, config, and language-pack boundaries;
10. TLS-pinned adapter transport and the two-stage redaction model;
11. the initial performance budgets and verification lanes;
12. the detailed schemas, messages, adapter internals, client state, export rules, and tests in the four appendices.

Gate 4 may divide these approved contracts into visible vertical slices, but it may not weaken them silently. Any boundary change requires an ADR and a Gate 3 amendment.

## 15. Current primary references

- [Node.js release lifecycle](https://nodejs.org/en/about/previous-releases)
- [Spring Boot stable versions](https://docs.spring.io/spring-boot/spring-projects.html)
- [Spring Boot system requirements](https://docs.spring.io/spring-boot/system-requirements.html)
- [OpenAPI 3.1 specification](https://spec.openapis.org/oas/v3.1.0)
- [Postman Create Collection API and Collection v2.1 requirement](https://learning.postman.com/api-docs/api-reference/collections/create-collection)
- [Postman OpenAPI and collection import behavior](https://learning.postman.com/docs/getting-started/importing-and-exporting/importing-data)
- References already evaluated in the approved [Architecture](02-architecture.md#reference-repositories-and-reuse-posture)
