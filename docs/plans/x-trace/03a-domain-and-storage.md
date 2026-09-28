# Gate 3 Appendix A: Domain and Storage

**Status:** approved with Gate 3 on 2026-09-28  
**Purpose:** define identity, provenance, replay ordering, reconciliation, persistence, object durability, and recovery precisely enough that implementations do not invent incompatible meanings.

## 1. Identifier and hash rules

- Public entity IDs are UUIDv7 values encoded as lowercase canonical strings. They are time-sortable without making timestamps authoritative.
- Content identities use BLAKE3-256 encoded as lowercase hexadecimal and tagged with the algorithm, for example `b3:…`.
- Database rows store UUIDs as 16-byte blobs and hashes as 32-byte blobs. APIs use strings.
- Wall-clock timestamps use UTC RFC 3339 with microsecond precision. Durations and event ordering use monotonic nanoseconds from the adapter process.
- Paths stored for source navigation are repository-relative UTF-8 paths with `/` separators. Raw absolute source paths never cross the client API.

Nominal Rust newtypes prevent accidental mixing:

```rust
ProjectId, RunId, CatalogRevisionId, OperationId, OperationVersionId,
ClaimId, RuntimeSessionId, RecordingId, FrameId, InteractionId,
SourceArtifactId, PolicyId, ExercisePlanId, ExportId, SegmentId
```

## 2. Operation identity and normalization

`OperationId` represents the HTTP operation a developer recognizes. It is not a handler-method ID.

Canonical input:

```text
project_id
application_component
transport = "http"
binding = normalized virtual-host/base-path identity
method = uppercase HTTP method
route_template = normalized framework-neutral route
```

Normalization:

1. Decode framework escape syntax without decoding a literal encoded slash.
2. Ensure one leading slash; collapse repeated separators except when a framework declares them meaningful.
3. Remove a trailing slash except for `/`; preserve a separate strict-slash claim.
4. Convert framework parameters (`:id`, `<id>`, `{id:[0-9]+}`) to `{id}` while preserving the original template and constraint as claim metadata.
5. Normalize parameter names only for identity comparison: `/users/{id}` and `/users/{userId}` are the same route shape. The preferred display name comes from the highest-confidence current claim.
6. Sort/normalize declared media types, but do not include them in `OperationId`; their change creates a new `OperationVersion`.
7. If two handlers genuinely share the same method/route/binding, retain one operation with conflicting claims and a visible ambiguity rather than manufacturing two API operations.

The ID is `BLAKE3(canonical CBOR input)`. An `OperationVersionId` hashes the operation ID plus the reconciled signature, handler claim set, schemas, security, provenance, and lifecycle state.

## 3. Core types

```rust
pub enum ProvenanceKind {
    StaticInferred,
    RuntimeDiscovered,
    Observed,
    PartialObservation,
    ImportedSpec,
    UserDeclared,
}

pub struct EvidenceRef {
    pub provenance: ProvenanceKind,
    pub producer: ProducerIdentity,
    pub source_revision: SourceRevisionId,
    pub runtime_session: Option<RuntimeSessionId>,
    pub recording: Option<RecordingId>,
    pub source: Option<SourceRange>,
    pub confidence: Option<Confidence>,
    pub reason_code: Option<EvidenceReason>,
}

pub enum CapturedValue {
    Captured { shape: ValueShape, preview: SafePreview, digest: ContentHash },
    Redacted { rule_id: PolicyRuleId, shape_hint: Option<ValueShape> },
    Truncated { preview: SafePreview, original_size_lower_bound: u64, limit: u64 },
    Unavailable { reason: UnavailableReason },
    Dropped { reason: DropReason, drop_notice: DropNoticeId },
}

pub enum FrameKind {
    Request, Framework, Method, Line, Interaction, Exception, Response, Gap,
}

pub struct Frame {
    pub id: FrameId,
    pub recording_id: RecordingId,
    pub position: ReplayPosition,
    pub parent: Option<FrameId>,
    pub async_parent: Option<FrameId>,
    pub kind: FrameKind,
    pub symbol: Option<SymbolRef>,
    pub source: Option<SourceRange>,
    pub values: Vec<ValueBinding>,
    pub result: Option<CapturedValue>,
    pub evidence: EvidenceRef,
}
```

`SafePreview` is already redacted and budgeted. It is not a general string wrapper and cannot be constructed outside the privacy module.

## 4. Replay ordering and navigation

Each adapter event carries:

- `session_seq`: strictly increasing for the runtime session;
- `recording_seq`: strictly increasing within a recording;
- `monotonic_ns`: adapter monotonic time;
- `thread_or_task_id` and optional `async_context_id`;
- `parent_event_id` and optional `async_parent_event_id`.

Validation rules:

- a repeated sequence with the same payload digest is an idempotent retry;
- a repeated sequence with a different digest invalidates the session;
- a forward sequence gap opens a `GapFrame` and requests retransmission when supported;
- a late event inside the retransmission window is inserted before finalization;
- after finalization, late events are rejected and logged as a session diagnostic; recordings are not rewritten.

`ReplayPosition` is assigned by the recording assembler after validation:

```rust
pub struct ReplayPosition {
    pub ordinal: u64,
    pub depth: u32,
    pub branch: u32,
    pub elapsed_ns: u64,
}
```

Navigation is a projection over the immutable frame graph:

- **next/previous:** adjacent visible ordinal under the active filter;
- **step into:** next child frame, otherwise next;
- **step over:** first subsequent frame at the same or lower depth;
- **step out:** first subsequent frame below the current depth;
- **jump to interaction/error/gap:** indexed frame kinds;
- **play:** repeated next using recorded elapsed time capped by a UI speed policy, not real execution.

Canvas and Linear mode use the same selected `FrameId` and replay projection.

## 5. Catalog reconciliation

Inputs are immutable `EndpointClaim`s. Each claim contains producer identity, claim kind, operation-key fields, handler identity, schema/media/security hints, source range, confidence, and catalog visibility.

For each scan or runtime discovery run:

1. Validate and normalize every claim.
2. Group claims by `OperationId`.
3. Rank fields independently, not whole claims: observed/runtime-discovered facts outrank imported/user/static facts for runtime handler identity; explicit specs may outrank inference for schemas; user exclusion policy always wins for capture eligibility.
4. Preserve every contributing and conflicting claim.
5. Build a reconciled `OperationVersion` and deterministic digest.
6. Compare with the previous visible version:
   - no prior operation: `added`;
   - same digest: `unchanged`;
   - different digest: `changed` with field-level delta;
   - prior operation missing from the complete current claim set: `removed`;
   - missing from an incomplete scan: `unknown`, never `removed`.
7. Commit all entries atomically as a new `CatalogRevision`.

A runtime claim can augment the current revision without silently mutating it. The daemon creates a new revision whose cause is `runtime_discovery` and links it to the session/run.

## 6. Path hypotheses

Static paths are directed graphs, not linear call lists:

```rust
pub struct PathHypothesis {
    pub operation_id: OperationId,
    pub nodes: Vec<HypothesisNode>,
    pub edges: Vec<HypothesisEdge>,
    pub producer: ProducerIdentity,
    pub source_revision: SourceRevisionId,
    pub confidence: Confidence,
    pub limitations: Vec<LimitationCode>,
}
```

Edges record reasons such as direct call, interface dispatch, dependency-injection binding, route binding, annotation, data-access declaration, or outbound-client declaration. Alternative targets remain alternatives. A hypothesis never contributes replay frames.

## 7. SQLite schema

SQLite uses `STRICT` tables, foreign keys, WAL mode, `synchronous=NORMAL` during normal operation, and `synchronous=FULL` for migration checkpoints and backup metadata. The store adapter owns all SQL.

### 7.1 Identity and configuration

```text
schema_meta(
  singleton PK CHECK singleton=1,
  schema_version, min_reader_version, migrated_at, app_version
)

projects(
  project_id PK, canonical_repo_hash UNIQUE, display_name,
  created_at, last_opened_at, config_schema_version,
  effective_config_hash, active_capture_policy_id, active_redaction_policy_id
)

source_revisions(
  source_revision_id PK, project_id FK, vcs_kind, commit_id,
  dirty_tree_hash, worktree_fingerprint, captured_at,
  UNIQUE(project_id, commit_id, dirty_tree_hash)
)

policies(
  policy_id PK, project_id FK, policy_kind, schema_version,
  canonical_json, digest, created_at, UNIQUE(project_id, policy_kind, digest)
)

adapter_manifests(
  manifest_id PK, language, adapter_name, adapter_version,
  protocol_min, protocol_max, canonical_json, signature_identity, digest UNIQUE
)
```

### 7.2 Runs and catalog

```text
runs(
  run_id PK, project_id FK, run_kind, status, requested_at,
  started_at, finished_at, source_revision_id FK,
  effective_config_hash, requested_by, idempotency_key,
  result_summary_json, error_code,
  UNIQUE(project_id, idempotency_key)
)

catalog_revisions(
  catalog_revision_id PK, project_id FK, ordinal,
  parent_revision_id FK NULL, cause_run_id FK,
  completeness, created_at, digest,
  UNIQUE(project_id, ordinal), UNIQUE(project_id, digest)
)

operations(
  operation_id PK, project_id FK, transport, method,
  normalized_route_shape, application_component, binding_key,
  first_revision_id FK
)

operation_versions(
  operation_version_id PK, operation_id FK, signature_json,
  display_route, lifecycle_state, digest UNIQUE
)

endpoint_claims(
  claim_id PK, operation_id FK, producer_manifest_id FK NULL,
  provenance, claim_json, source_revision_id FK,
  runtime_session_id FK NULL, recording_id FK NULL,
  first_seen_revision_id FK, last_seen_revision_id FK, digest
)

catalog_entries(
  catalog_revision_id FK, operation_id FK, operation_version_id FK,
  change_kind, delta_json, observed_recording_count,
  PRIMARY KEY(catalog_revision_id, operation_id)
)
```

`claim_json`, `signature_json`, and deltas are validated canonical JSON owned by the store translation layer. They do not replace typed domain objects.

### 7.3 Sessions and recordings

```text
runtime_sessions(
  runtime_session_id PK, project_id FK, run_id FK,
  manifest_id FK, status, pid, process_start_time,
  runtime_name, runtime_version, framework_facts_json,
  capabilities_json, connected_at, closed_at, close_reason
)

recordings(
  recording_id PK, project_id FK, runtime_session_id FK,
  operation_id FK NULL, source_revision_id FK,
  status, opened_at, completed_at, duration_ns,
  request_summary_json, response_summary_json,
  capture_policy_id FK, redaction_policy_id FK,
  frame_count, interaction_count, gap_count,
  root_segment_id FK NULL, completion_reason
)

recording_segments(
  recording_id FK, segment_ordinal, object_hash,
  first_recording_seq, last_recording_seq, event_count,
  uncompressed_bytes, compressed_bytes, checksum,
  PRIMARY KEY(recording_id, segment_ordinal)
)

frame_index(
  recording_id FK, frame_id, ordinal, parent_frame_id NULL,
  async_parent_frame_id NULL, frame_kind, depth, elapsed_ns,
  segment_ordinal, segment_offset, source_artifact_id NULL,
  source_start_line NULL, source_end_line NULL,
  PRIMARY KEY(recording_id, frame_id),
  UNIQUE(recording_id, ordinal)
)

source_artifacts(
  source_artifact_id PK, project_id FK, source_revision_id FK,
  repo_relative_path, content_hash, language, line_count,
  excerpt_object_hash NULL,
  UNIQUE(project_id, source_revision_id, repo_relative_path, content_hash)
)
```

The frame index contains navigation metadata only; values and full payloads stay in immutable segments.

### 7.4 Exercise and export

```text
exercise_plans(
  exercise_plan_id PK, project_id FK, catalog_revision_id FK,
  state, canonical_plan_json, plan_hash, created_at,
  reviewed_at NULL, approved_at NULL, expires_at NULL,
  approval_actor NULL, execution_run_id FK NULL
)

exercise_items(
  exercise_plan_id FK, item_ordinal, operation_id FK,
  effect_class, request_template_json, credential_refs_json,
  state, recording_id FK NULL, error_code NULL,
  PRIMARY KEY(exercise_plan_id, item_ordinal)
)

exports(
  export_id PK, project_id FK, run_id FK,
  catalog_revision_id FK, policy_id FK, formats_json,
  state, manifest_object_hash NULL, created_at, completed_at NULL,
  delivery_kind NULL, delivery_receipt_json NULL, error_code NULL
)
```

## 8. Immutable object store

Project data directory:

```text
<user-data>/xtrace/projects/<project-id>/
  metadata.sqlite3
  metadata.sqlite3-wal
  daemon.json
  objects/b3/<first-two>/<remaining-hash>.xtf.zst
  sources/b3/<first-two>/<remaining-hash>.src.zst
  exports/<export-id>/
  staging/<recording-id>/
  backups/
```

An XTF segment contains:

```text
magic "XTF1"
format major/minor
header length + canonical protobuf header
length-delimited event envelopes
footer: event count, sequence range, uncompressed digest
zstd frame checksum
```

Default sealing thresholds are the first of 4 MiB uncompressed, 2,000 events, or 2 seconds. Large individual events are rejected by the protocol before segmenting.

### 8.1 Commit protocol

1. Write the uncompressed logical segment to an owner-only staging file while hashing.
2. Flush, compress to a second temporary file, and verify the footer/digest.
3. `fsync` the compressed file.
4. Rename atomically into the content-addressed object path; an existing matching object is safe deduplication.
5. In one SQLite transaction, insert `recording_segments`, frame-index rows, recording counters, and an outbox notification.
6. Commit SQLite, then remove staging files.

If the process crashes before step 5, the object is unreferenced and collected after recovery grace. If it crashes after step 5, the immutable object is authoritative.

## 9. Startup recovery

Recovery obtains the project lock before serving clients:

1. Validate SQLite integrity and schema compatibility.
2. Resolve any interrupted migration from its journal.
3. Verify referenced objects exist and match hashes; quarantine corruption without deleting evidence.
4. Inspect nonterminal runtime sessions and runs against process identity.
5. Seal valid staging segments or discard invalid temporary bytes.
6. Finalize open recordings as `partial` with `daemon_restart`, or `invalid` if identity/order cannot be trusted.
7. Mark stale sessions `failed` or `closed` with an exact reason.
8. Replay the transactional outbox to rebuild missed client notifications.
9. Delete unreferenced objects only after the configured recovery grace period and a successful reference scan.

Recovery is idempotent and has crash-injection tests at every commit step.

## 10. Migrations and backups

- Migrations are compiled into the binary, numbered, checksummed, and forward-only.
- Opening a newer unsupported schema fails without mutation.
- Before a rewrite migration, the daemon checkpoints WAL and uses SQLite's online backup API into `backups/pre-vNN-<timestamp>.sqlite3`.
- Object-format migrations create new objects and switch references transactionally; they never rewrite an object in place.
- `xtrace store migrate --dry-run` reports required disk, backup path, and incompatible old readers.
- Release CI upgrades fixtures from every released schema version and verifies semantic queries, not just row counts.

## 11. Retention

Retention candidates are calculated by age, total bytes, per-operation recording count, and pin state. A preview lists recordings, exports, and reclaimable bytes. Applying retention:

1. creates a retention run;
2. marks metadata tombstones transactionally;
3. moves unshared objects to OS trash when supported, otherwise requires explicit permanent-deletion acknowledgement;
4. removes rows only after object disposition succeeds;
5. never deletes catalog history required by retained recordings.

Referenced source excerpts and deduplicated objects are removed only when their reference count reaches zero.
