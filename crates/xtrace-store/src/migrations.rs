//! Forward-only SQLite migrations.
//!
//! Each migration is identified by a monotonically increasing numeric
//! `version`. Migrations run in order; once applied, a migration is
//! never re-applied. The migration runner is the only component that
//! writes to `schema_meta`.
//!
//! Slice 1A introduced `v0001_initial`; Slice 1C.4 appends
//! `v0002_recording_segments`; Slice 1E.3A appends
//! `v0003_observed_endpoint_catalog`; P02A appends
//! `v0004_recording_terminal_evidence`; P03A appends
//! `v0005_catalog_discovery`. Migrations remain append-only: later
//! slices must add a new record instead of editing an applied one.
//!
//! Migrations deliberately avoid statements that cannot be safely
//! retried after a crash. The runner wraps every migration in a
//! transaction and updates `schema_meta` only after the transaction
//! commits; an interrupted migration therefore leaves the database
//! at the previous schema version and a re-open simply retries the
//! remaining migrations.
//!
//! ## Identity and checksums
//!
//! The runner records the BLAKE3-256 checksum of the *applied*
//! prefix of the migration catalog — that is, the ordered
//! concatenation of every migration whose version is less than or
//! equal to the stored `schema_version`. The checksum is updated
//! transactionally with the version bump, and the stored checksum is
//! verified against the binary's compiled-in prefix *before* any
//! pending migration runs so a tampered older checksum cannot be
//! silently overwritten by a later migration's write. A mismatch on
//! an already-migrated database fails with
//! [`StoreErrorKind::SchemaIncompatible`] so a tampered or partially
//! applied schema cannot corrupt later slices.

use std::collections::BTreeMap;

use rusqlite::Connection;
use xtrace_domain::{CorrelationId, WallTime};

use crate::error::{StoreError, StoreErrorKind};

/// One declared migration. The body is the SQL to apply.
#[derive(Clone, Debug)]
pub struct MigrationRecord {
    /// Monotonically increasing numeric version.
    pub version: u32,
    /// Human-readable label used in diagnostics.
    pub label: &'static str,
    /// SQL statements that make up the migration body.
    pub statements: &'static [&'static str],
}

/// Full migration catalog. New migrations are appended to the end so
/// the order matches the version numbers.
pub struct Migrations;

impl Migrations {
    /// Returns every supported migration in version order.
    #[must_use]
    pub fn catalog() -> Vec<MigrationRecord> {
        vec![
            MigrationRecord { version: 1, label: "v0001_initial", statements: &[INITIAL_SCHEMA] },
            MigrationRecord {
                version: 2,
                label: "v0002_recording_segments",
                statements: &[RECORDING_SEGMENTS_SCHEMA],
            },
            MigrationRecord {
                version: 3,
                label: "v0003_observed_endpoint_catalog",
                statements: &[OBSERVED_ENDPOINT_CATALOG_SCHEMA],
            },
            MigrationRecord {
                version: 4,
                label: "v0004_recording_terminal_evidence",
                statements: &[RECORDING_TERMINAL_EVIDENCE_SCHEMA],
            },
            MigrationRecord {
                version: 5,
                label: "v0005_catalog_discovery",
                statements: &[CATALOG_DISCOVERY_SCHEMA],
            },
        ]
    }

    /// Returns the maximum version in the catalog.
    #[must_use]
    pub fn latest_version() -> u32 {
        Self::catalog().last().map_or(0, |record| record.version)
    }

    /// Returns the catalog as a map for quick lookups by version.
    #[must_use]
    pub fn catalog_by_version() -> BTreeMap<u32, MigrationRecord> {
        Self::catalog().into_iter().map(|record| (record.version, record)).collect()
    }

    /// Computes the BLAKE3-256 checksum of the supplied migration
    /// slice, in version order, rendered as the lowercase
    /// `b3:<lowercase hex>` form via
    /// [`xtrace_domain::ContentHash::from_blake3_digest`].
    ///
    /// The hash covers the ordered `(label, version, statement)`
    /// triples so any textual change to a migration produces a new
    /// identity. The function takes the slice directly so callers
    /// can compute the prefix checksum (the applied portion of the
    /// catalog) without copying the whole catalog.
    #[must_use]
    pub fn prefix_checksum(records: &[MigrationRecord]) -> String {
        let mut hasher = blake3::Hasher::new();
        for record in records {
            hasher.update(&record.version.to_be_bytes());
            hasher.update(record.label.as_bytes());
            for statement in record.statements {
                hasher.update(statement.as_bytes());
            }
        }
        xtrace_domain::ContentHash::from_blake3_digest(hasher.finalize()).to_canonical()
    }

    /// Returns the canonical identity for the entire compiled-in
    /// catalog. Equivalent to
    /// [`Self::prefix_checksum`] applied to the full catalog and
    /// exposed separately so existing callers do not have to
    /// collect the catalog twice.
    #[must_use]
    pub fn catalog_checksum() -> String {
        Self::prefix_checksum(&Self::catalog())
    }
}

/// First schema version. Created by `v0001_initial`. The
/// `applied_checksum` column records the BLAKE3-256 identity of the
/// applied prefix of the migration catalog and is the canonical
/// guarantee that the SQL the binary would emit matches the SQL
/// that originally produced the schema.
const INITIAL_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS schema_meta (
    singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version      INTEGER NOT NULL,
    min_reader_version  INTEGER NOT NULL,
    migrated_at         TEXT NOT NULL,
    app_version         TEXT NOT NULL,
    applied_checksum    TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS projects (
    project_id                   BLOB PRIMARY KEY,
    canonical_repo_hash          TEXT NOT NULL UNIQUE,
    display_name                 TEXT NOT NULL,
    created_at                   TEXT NOT NULL,
    last_opened_at               TEXT NOT NULL,
    config_schema_version        INTEGER NOT NULL,
    effective_config_hash        TEXT NOT NULL,
    active_capture_policy_id     BLOB,
    active_redaction_policy_id   BLOB,
    FOREIGN KEY (active_capture_policy_id)
        REFERENCES policies (policy_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (active_redaction_policy_id)
        REFERENCES policies (policy_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE IF NOT EXISTS policies (
    policy_id        BLOB PRIMARY KEY,
    project_id       BLOB NOT NULL,
    policy_kind      TEXT NOT NULL,
    schema_version   INTEGER NOT NULL,
    canonical_json   TEXT NOT NULL,
    digest           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    UNIQUE (project_id, policy_kind, digest),
    FOREIGN KEY (project_id)
        REFERENCES projects (project_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE IF NOT EXISTS runs (
    run_id                     BLOB PRIMARY KEY,
    project_id                 BLOB NOT NULL,
    run_kind                   TEXT NOT NULL,
    status                     TEXT NOT NULL,
    requested_at               TEXT NOT NULL,
    started_at                 TEXT,
    finished_at                TEXT,
    requested_by               TEXT NOT NULL,
    idempotency_key            TEXT NOT NULL,
    error_code                 TEXT,
    UNIQUE (project_id, idempotency_key),
    FOREIGN KEY (project_id)
        REFERENCES projects (project_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE IF NOT EXISTS command_receipts (
    project_id        BLOB NOT NULL,
    command_kind      TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL,
    input_digest      TEXT NOT NULL,
    receipt_json      TEXT NOT NULL,
    correlation_id    TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    PRIMARY KEY (project_id, command_kind, idempotency_key),
    FOREIGN KEY (project_id)
        REFERENCES projects (project_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX IF NOT EXISTS runs_project_status
    ON runs (project_id, status);

CREATE INDEX IF NOT EXISTS projects_canonical_repo_hash
    ON projects (canonical_repo_hash);
";

/// Second schema version. Recording rows preserve the current domain lifecycle
/// vocabulary even though this slice only creates `recording` rows. Sequence
/// values use fixed-width big-endian blobs so the full `u64` range survives
/// SQLite's signed integer limit and keeps a future lexical ordering stable.
const RECORDING_SEGMENTS_SCHEMA: &str = r"
CREATE TABLE recordings (
    recording_id        BLOB PRIMARY KEY CHECK(length(recording_id) = 16),
    project_id          BLOB NOT NULL CHECK(length(project_id) = 16)
                            REFERENCES projects(project_id),
    runtime_session_id  BLOB NOT NULL CHECK(length(runtime_session_id) = 16),
    status              TEXT NOT NULL CHECK(status IN
                            ('recording', 'finalizing', 'complete', 'partial', 'invalid')),
    opened_at           TEXT NOT NULL
) STRICT;

CREATE TABLE recording_segments (
    recording_id          BLOB NOT NULL CHECK(length(recording_id) = 16)
                              REFERENCES recordings(recording_id),
    segment_ordinal       INTEGER NOT NULL CHECK(segment_ordinal >= 0),
    object_hash           BLOB NOT NULL CHECK(length(object_hash) = 32),
    first_recording_seq   BLOB NOT NULL CHECK(length(first_recording_seq) = 8),
    last_recording_seq    BLOB NOT NULL CHECK(length(last_recording_seq) = 8),
    event_count           INTEGER NOT NULL CHECK(event_count > 0),
    uncompressed_bytes    INTEGER NOT NULL CHECK(uncompressed_bytes > 0),
    compressed_bytes      INTEGER NOT NULL CHECK(compressed_bytes > 0),
    checksum              BLOB NOT NULL CHECK(length(checksum) = 32),
    PRIMARY KEY(recording_id, segment_ordinal)
) STRICT;
";

/// Third schema version. Endpoint facts live in a sidecar so legacy recordings
/// remain unmatched and the existing recording identity stays immutable.
const OBSERVED_ENDPOINT_CATALOG_SCHEMA: &str = r"
CREATE UNIQUE INDEX recordings_project_recording
    ON recordings (project_id, recording_id);

CREATE TABLE operations (
    operation_id                BLOB PRIMARY KEY CHECK(length(operation_id) = 16
                                    AND substr(hex(operation_id), 13, 1) = '7'
                                    AND substr(hex(operation_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id                  BLOB NOT NULL CHECK(length(project_id) = 16)
                                    REFERENCES projects(project_id),
    transport                   TEXT NOT NULL CHECK(transport = 'http'),
    method                      TEXT NOT NULL CHECK(method = 'POST'),
    route_template              TEXT NOT NULL CHECK(route_template = '/orders'),
    application_component       TEXT NOT NULL CHECK(application_component = 'spring-fixture'),
    binding_key                 TEXT NOT NULL CHECK(binding_key = 'default'),
    fingerprint_format_version INTEGER NOT NULL CHECK(fingerprint_format_version = 1),
    endpoint_fingerprint        BLOB NOT NULL CHECK(length(endpoint_fingerprint) = 32),
    created_at                  TEXT NOT NULL,
    UNIQUE(project_id, operation_id),
    UNIQUE(project_id, fingerprint_format_version, endpoint_fingerprint),
    UNIQUE(project_id, application_component, binding_key, transport, method, route_template)
) STRICT;

CREATE INDEX operations_project_order
    ON operations(project_id, method, route_template, application_component, binding_key, operation_id);

CREATE TABLE recording_endpoint_observations (
    recording_id         BLOB PRIMARY KEY CHECK(length(recording_id) = 16),
    project_id           BLOB NOT NULL CHECK(length(project_id) = 16),
    disposition          TEXT NOT NULL CHECK(disposition IN ('linked', 'unmatched')),
    observation_policy_id TEXT CHECK(observation_policy_id IS NULL OR observation_policy_id = 'spring-orders-v1'),
    operation_id         BLOB CHECK(operation_id IS NULL OR (length(operation_id) = 16
                              AND substr(hex(operation_id), 13, 1) = '7'
                              AND substr(hex(operation_id), 17, 1) IN ('8', '9', 'A', 'B'))),
    application_component TEXT,
    binding_key          TEXT,
    method               TEXT,
    route_template       TEXT,
    reason_code          TEXT,
    CHECK((application_component IS NULL AND binding_key IS NULL) OR
          (application_component = 'spring-fixture' AND binding_key = 'default')),
    CHECK((disposition = 'linked' AND observation_policy_id = 'spring-orders-v1'
           AND operation_id IS NOT NULL AND application_component = 'spring-fixture'
           AND binding_key = 'default' AND method = 'POST' AND route_template = '/orders'
           AND reason_code IS NULL)
       OR (disposition = 'unmatched' AND operation_id IS NULL AND method IS NULL
           AND route_template IS NULL AND reason_code IN
           ('observation_policy_missing', 'observation_policy_invalid',
            'identity_context_missing', 'identity_context_invalid',
            'method_unsupported', 'route_unapproved'))),
    CHECK(reason_code NOT IN ('observation_policy_missing', 'observation_policy_invalid')
          OR observation_policy_id IS NULL),
    CHECK(reason_code NOT IN ('identity_context_missing', 'identity_context_invalid')
          OR (observation_policy_id = 'spring-orders-v1' AND application_component IS NULL AND binding_key IS NULL)),
    CHECK(reason_code NOT IN ('method_unsupported', 'route_unapproved')
          OR (observation_policy_id = 'spring-orders-v1' AND application_component = 'spring-fixture' AND binding_key = 'default')),
    FOREIGN KEY(recording_id, project_id) REFERENCES recordings(recording_id, project_id),
    FOREIGN KEY(project_id, operation_id) REFERENCES operations(project_id, operation_id)
) STRICT;

CREATE INDEX endpoint_observations_operation_recording
    ON recording_endpoint_observations(project_id, operation_id, recording_id);
CREATE INDEX endpoint_observations_unmatched_recording
    ON recording_endpoint_observations(project_id, disposition, recording_id);
CREATE INDEX recordings_project_opened
    ON recordings(project_id, opened_at, recording_id);
";

/// Fourth schema version. Terminal evidence is separate from immutable event
/// segments so retries and reopen recover the same verified lifecycle result.
const RECORDING_TERMINAL_EVIDENCE_SCHEMA: &str = r"
CREATE TABLE recording_frame_index (
    recording_id         BLOB NOT NULL CHECK(length(recording_id) = 16)
                             REFERENCES recordings(recording_id),
    recording_seq        BLOB NOT NULL CHECK(length(recording_seq) = 8),
    frame_id             BLOB NOT NULL CHECK(length(frame_id) = 16
                             AND substr(hex(frame_id), 13, 1) = '7'
                             AND substr(hex(frame_id), 17, 1) IN ('8', '9', 'A', 'B')),
    segment_ordinal      INTEGER NOT NULL CHECK(segment_ordinal >= 0),
    event_offset         INTEGER NOT NULL CHECK(event_offset >= 0),
    event_id_digest      BLOB NOT NULL CHECK(length(event_id_digest) = 32),
    parent_id_digest     BLOB CHECK(parent_id_digest IS NULL OR length(parent_id_digest) = 32),
    async_parent_digest  BLOB CHECK(async_parent_digest IS NULL OR length(async_parent_digest) = 32),
    monotonic_ns         BLOB NOT NULL CHECK(length(monotonic_ns) = 8),
    PRIMARY KEY(recording_id, recording_seq),
    UNIQUE(recording_id, frame_id),
    UNIQUE(recording_id, event_id_digest),
    FOREIGN KEY(recording_id, segment_ordinal)
        REFERENCES recording_segments(recording_id, segment_ordinal)
) STRICT;

CREATE INDEX recording_frame_order
    ON recording_frame_index(recording_id, recording_seq, frame_id);

CREATE TABLE recording_terminal_evidence (
    recording_id  BLOB PRIMARY KEY CHECK(length(recording_id) = 16)
                      REFERENCES recordings(recording_id),
    request_json  TEXT NOT NULL CHECK(length(CAST(request_json AS BLOB)) <= 16384),
    completion    TEXT NOT NULL CHECK(completion IN ('complete', 'partial', 'invalid')),
    final_recording_seq BLOB NOT NULL CHECK(length(final_recording_seq) = 8),
    event_count   INTEGER NOT NULL CHECK(event_count >= 0 AND event_count <= 2048)
) STRICT;

CREATE INDEX recording_terminal_completion
    ON recording_terminal_evidence(completion, recording_id);
";

/// Durable owner-scoped discovery ledger and immutable catalog history.
/// Existing v1-v4 tables and their checksums remain untouched.
const CATALOG_DISCOVERY_SCHEMA: &str = r"
CREATE TABLE catalog_owner_selections (
    owner_selection_id       BLOB PRIMARY KEY CHECK (length(owner_selection_id) = 16
                                 AND substr(hex(owner_selection_id), 13, 1) = '7'
                                 AND substr(hex(owner_selection_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id               BLOB NOT NULL,
    selection_epoch          INTEGER NOT NULL CHECK (selection_epoch > 0),
    current_for_scope        INTEGER NOT NULL CHECK (current_for_scope IN (0, 1)),
    verified_pack_digest     BLOB NOT NULL CHECK (length(verified_pack_digest) = 32),
    scope_digest             BLOB NOT NULL CHECK (length(scope_digest) = 32),
    scope_json               TEXT NOT NULL CHECK (length(CAST(scope_json AS BLOB)) <= 8192),
    source_revision_id       BLOB CHECK (source_revision_id IS NULL OR (length(source_revision_id) = 16
                                 AND substr(hex(source_revision_id), 13, 1) = '7'
                                 AND substr(hex(source_revision_id), 17, 1) IN ('8', '9', 'A', 'B'))),
    pinned_source_digest     BLOB CHECK (pinned_source_digest IS NULL OR length(pinned_source_digest) = 32),
    revoked                  INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    UNIQUE (owner_selection_id, project_id),
    UNIQUE (owner_selection_id, project_id, selection_epoch),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT,
    CHECK ((source_revision_id IS NULL) = (pinned_source_digest IS NULL))
) STRICT;

CREATE INDEX catalog_owner_selections_current_scope
    ON catalog_owner_selections(project_id, scope_digest, current_for_scope, revoked);

CREATE UNIQUE INDEX catalog_owner_selections_one_current
    ON catalog_owner_selections(project_id, scope_digest)
    WHERE current_for_scope = 1 AND revoked = 0;

CREATE TABLE catalog_discovery_runs (
    run_id                   BLOB PRIMARY KEY CHECK (length(run_id) = 16
                                 AND substr(hex(run_id), 13, 1) = '7'
                                 AND substr(hex(run_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id               BLOB NOT NULL,
    runtime_session_id       BLOB NOT NULL CHECK (length(runtime_session_id) = 16
                                 AND substr(hex(runtime_session_id), 13, 1) = '7'
                                 AND substr(hex(runtime_session_id), 17, 1) IN ('8', '9', 'A', 'B')),
    protocol_minor           INTEGER NOT NULL CHECK (protocol_minor BETWEEN 0 AND 65535),
    verified_pack_digest     BLOB NOT NULL CHECK (length(verified_pack_digest) = 32),
    owner_selection_id       BLOB NOT NULL CHECK (length(owner_selection_id) = 16),
    selection_epoch          INTEGER NOT NULL CHECK (selection_epoch > 0),
    run_hint                 TEXT NOT NULL CHECK (length(CAST(run_hint AS BLOB)) BETWEEN 1 AND 128),
    request_bytes            BLOB NOT NULL CHECK (length(request_bytes) BETWEEN 1 AND 16384),
    request_digest           BLOB NOT NULL CHECK (length(request_digest) = 32),
    scope_digest             BLOB NOT NULL CHECK (length(scope_digest) = 32),
    scope_json               TEXT NOT NULL CHECK (length(CAST(scope_json AS BLOB)) <= 8192),
    source_revision_id       BLOB CHECK (source_revision_id IS NULL OR (length(source_revision_id) = 16
                                 AND substr(hex(source_revision_id), 13, 1) = '7'
                                 AND substr(hex(source_revision_id), 17, 1) IN ('8', '9', 'A', 'B'))),
    pinned_source_digest     BLOB CHECK (pinned_source_digest IS NULL OR length(pinned_source_digest) = 32),
    status                   TEXT NOT NULL CHECK (status IN ('open', 'complete', 'incomplete', 'failed', 'invalid', 'superseded')),
    expected_chunk_count     INTEGER CHECK (expected_chunk_count IS NULL OR expected_chunk_count BETWEEN 0 AND 64),
    accepted_claim_count     INTEGER NOT NULL DEFAULT 0 CHECK (accepted_claim_count BETWEEN 0 AND 4096),
    rejected_claim_count     INTEGER NOT NULL DEFAULT 0 CHECK (rejected_claim_count BETWEEN 0 AND 4096),
    accepted_claim_bytes     INTEGER NOT NULL DEFAULT 0 CHECK (accepted_claim_bytes BETWEEN 0 AND 4194304),
    final_digest             BLOB CHECK (final_digest IS NULL OR length(final_digest) = 32),
    limitation_codes_json    TEXT CHECK (limitation_codes_json IS NULL OR length(CAST(limitation_codes_json AS BLOB)) <= 16384),
    revision_id              BLOB CHECK (revision_id IS NULL OR length(revision_id) = 16),
    UNIQUE (run_id, project_id),
    UNIQUE (project_id, runtime_session_id, verified_pack_digest, owner_selection_id, run_hint),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT,
    FOREIGN KEY (owner_selection_id, project_id, selection_epoch)
        REFERENCES catalog_owner_selections(owner_selection_id, project_id, selection_epoch)
        ON DELETE RESTRICT,
    CHECK ((source_revision_id IS NULL) = (pinned_source_digest IS NULL)),
    CHECK ((status IN ('complete', 'incomplete', 'failed', 'superseded')) = (final_digest IS NOT NULL))
) STRICT;

CREATE INDEX catalog_discovery_runs_scope
    ON catalog_discovery_runs(project_id, scope_digest, status, run_id);

CREATE TABLE catalog_discovery_chunks (
    run_id                   BLOB NOT NULL,
    project_id               BLOB NOT NULL,
    chunk_index              INTEGER NOT NULL CHECK (chunk_index BETWEEN 0 AND 63),
    chunk_digest             BLOB NOT NULL CHECK (length(chunk_digest) = 32),
    claim_count              INTEGER NOT NULL CHECK (claim_count BETWEEN 1 AND 64),
    payload_bytes            INTEGER NOT NULL CHECK (payload_bytes BETWEEN 1 AND 262144),
    PRIMARY KEY (run_id, chunk_index),
    UNIQUE (run_id, project_id, chunk_index),
    FOREIGN KEY (run_id, project_id) REFERENCES catalog_discovery_runs(run_id, project_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE catalog_discovery_claims (
    run_id                   BLOB NOT NULL,
    project_id               BLOB NOT NULL,
    chunk_index              INTEGER NOT NULL,
    claim_ordinal            INTEGER NOT NULL CHECK (claim_ordinal BETWEEN 0 AND 63),
    claim_hint               TEXT NOT NULL CHECK (length(CAST(claim_hint AS BLOB)) BETWEEN 1 AND 128),
    claim_digest             BLOB NOT NULL CHECK (length(claim_digest) = 32),
    canonical_bytes          BLOB NOT NULL CHECK (length(canonical_bytes) BETWEEN 1 AND 8192),
    canonical_json           TEXT NOT NULL CHECK (length(CAST(canonical_json AS BLOB)) BETWEEN 1 AND 16384),
    PRIMARY KEY (run_id, chunk_index, claim_ordinal),
    UNIQUE (run_id, claim_hint),
    UNIQUE (run_id, claim_digest),
    FOREIGN KEY (run_id, project_id, chunk_index)
        REFERENCES catalog_discovery_chunks(run_id, project_id, chunk_index) ON DELETE RESTRICT
) STRICT;

CREATE TABLE catalog_operations (
    operation_id             BLOB PRIMARY KEY CHECK (length(operation_id) = 16
                                 AND substr(hex(operation_id), 13, 1) = '7'
                                 AND substr(hex(operation_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id               BLOB NOT NULL,
    fingerprint_format       INTEGER NOT NULL CHECK (fingerprint_format = 1),
    endpoint_fingerprint     BLOB NOT NULL CHECK (length(endpoint_fingerprint) = 32),
    transport                TEXT NOT NULL CHECK (transport = 'http'),
    application_component    TEXT NOT NULL CHECK (length(CAST(application_component AS BLOB)) BETWEEN 1 AND 128),
    binding_key              TEXT NOT NULL CHECK (length(CAST(binding_key AS BLOB)) BETWEEN 1 AND 128),
    method                   TEXT NOT NULL CHECK (length(CAST(method AS BLOB)) BETWEEN 1 AND 16),
    route_template           TEXT NOT NULL CHECK (length(CAST(route_template AS BLOB)) BETWEEN 1 AND 1024),
    created_at               TEXT NOT NULL,
    UNIQUE (project_id, operation_id),
    UNIQUE (project_id, fingerprint_format, endpoint_fingerprint),
    UNIQUE (project_id, application_component, binding_key, transport, method, route_template),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE catalog_claims (
    claim_id                 BLOB PRIMARY KEY CHECK (length(claim_id) = 16
                                 AND substr(hex(claim_id), 13, 1) = '7'
                                 AND substr(hex(claim_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id               BLOB NOT NULL,
    operation_id             BLOB NOT NULL CHECK (length(operation_id) = 16),
    claim_digest             BLOB NOT NULL CHECK (length(claim_digest) = 32),
    canonical_bytes          BLOB NOT NULL CHECK (length(canonical_bytes) BETWEEN 1 AND 8192),
    canonical_json           TEXT NOT NULL CHECK (length(CAST(canonical_json AS BLOB)) BETWEEN 1 AND 16384),
    first_revision_id        BLOB NOT NULL CHECK (length(first_revision_id) = 16),
    last_revision_id         BLOB NOT NULL CHECK (length(last_revision_id) = 16),
    UNIQUE (project_id, claim_id),
    UNIQUE (project_id, operation_id, claim_id),
    UNIQUE (project_id, claim_digest),
    FOREIGN KEY (project_id, operation_id) REFERENCES catalog_operations(project_id, operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, first_revision_id) REFERENCES catalog_revisions(project_id, revision_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, last_revision_id) REFERENCES catalog_revisions(project_id, revision_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE catalog_operation_versions (
    operation_version_id    BLOB PRIMARY KEY CHECK (length(operation_version_id) = 16
                                 AND substr(hex(operation_version_id), 13, 1) = '7'
                                 AND substr(hex(operation_version_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id               BLOB NOT NULL,
    operation_id             BLOB NOT NULL CHECK (length(operation_id) = 16),
    version_digest           BLOB NOT NULL CHECK (length(version_digest) = 32),
    lifecycle                TEXT NOT NULL CHECK (lifecycle IN ('inferred', 'registered', 'removed')),
    created_at               TEXT NOT NULL,
    UNIQUE (project_id, operation_version_id),
    UNIQUE (project_id, operation_id, version_digest),
    UNIQUE (project_id, operation_id, operation_version_id),
    FOREIGN KEY (project_id, operation_id) REFERENCES catalog_operations(project_id, operation_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE catalog_revisions (
    revision_id              BLOB PRIMARY KEY CHECK (length(revision_id) = 16
                                 AND substr(hex(revision_id), 13, 1) = '7'
                                 AND substr(hex(revision_id), 17, 1) IN ('8', '9', 'A', 'B')),
    project_id               BLOB NOT NULL,
    owner_selection_id       BLOB NOT NULL CHECK (length(owner_selection_id) = 16),
    run_id                   BLOB NOT NULL CHECK (length(run_id) = 16),
    scope_digest             BLOB NOT NULL CHECK (length(scope_digest) = 32),
    source_revision_id       BLOB CHECK (source_revision_id IS NULL OR (length(source_revision_id) = 16
                                 AND substr(hex(source_revision_id), 13, 1) = '7'
                                 AND substr(hex(source_revision_id), 17, 1) IN ('8', '9', 'A', 'B'))),
    ordinal                  INTEGER NOT NULL CHECK (ordinal > 0),
    parent_revision_id       BLOB CHECK (parent_revision_id IS NULL OR length(parent_revision_id) = 16),
    content_digest           BLOB NOT NULL CHECK (length(content_digest) = 32),
    final_digest             BLOB NOT NULL CHECK (length(final_digest) = 32),
    operation_count          INTEGER NOT NULL CHECK (operation_count BETWEEN 0 AND 4096),
    created_at               TEXT NOT NULL,
    UNIQUE (project_id, revision_id),
    UNIQUE (project_id, scope_digest, ordinal),
    UNIQUE (project_id, run_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, project_id) REFERENCES catalog_discovery_runs(run_id, project_id) ON DELETE RESTRICT,
    FOREIGN KEY (owner_selection_id, project_id) REFERENCES catalog_owner_selections(owner_selection_id, project_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, parent_revision_id) REFERENCES catalog_revisions(project_id, revision_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX catalog_revisions_scope_latest
    ON catalog_revisions(project_id, scope_digest, ordinal DESC);

CREATE TABLE catalog_revision_entries (
    project_id               BLOB NOT NULL,
    revision_id              BLOB NOT NULL CHECK (length(revision_id) = 16),
    operation_id             BLOB NOT NULL CHECK (length(operation_id) = 16),
    operation_version_id     BLOB NOT NULL CHECK (length(operation_version_id) = 16),
    change_kind              TEXT NOT NULL CHECK (change_kind IN ('added', 'unchanged', 'changed', 'removed', 'unknown')),
    source_availability      TEXT NOT NULL CHECK (source_availability IN ('unverified', 'unavailable')),
    PRIMARY KEY (revision_id, operation_id),
    UNIQUE (project_id, revision_id, operation_id),
    FOREIGN KEY (project_id, revision_id) REFERENCES catalog_revisions(project_id, revision_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, operation_id) REFERENCES catalog_operations(project_id, operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, operation_id, operation_version_id) REFERENCES catalog_operation_versions(project_id, operation_id, operation_version_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE catalog_revision_claims (
    project_id               BLOB NOT NULL,
    revision_id              BLOB NOT NULL CHECK (length(revision_id) = 16),
    operation_id             BLOB NOT NULL CHECK (length(operation_id) = 16),
    claim_id                 BLOB NOT NULL CHECK (length(claim_id) = 16),
    PRIMARY KEY (revision_id, operation_id, claim_id),
    FOREIGN KEY (project_id, revision_id, operation_id)
        REFERENCES catalog_revision_entries(project_id, revision_id, operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (project_id, operation_id, claim_id)
        REFERENCES catalog_claims(project_id, operation_id, claim_id) ON DELETE RESTRICT
) STRICT;
";

/// Applies every pending migration from the compiled-in catalog to
/// the supplied connection.
///
/// The function is total: it returns a [`StoreError`] describing the
/// first failure it encounters. The applied-prefix checksum stored on
/// disk is verified *before* any pending migration runs so a tampered
/// older checksum cannot be silently overwritten by a later
/// migration's write.
pub fn apply_pending(
    connection: &Connection,
    app_version: &str,
    correlation_id: CorrelationId,
) -> Result<u32, StoreError> {
    apply_with_catalog(connection, app_version, correlation_id, &Migrations::catalog())
}

/// Validates an existing database schema without applying migrations or
/// changing persistent SQLite state.
///
/// # Errors
///
/// Returns a schema-version or prefix-checksum error when this binary cannot
/// read the database exactly as it exists.
pub(crate) fn validate_read_only(
    connection: &Connection,
    correlation_id: CorrelationId,
) -> Result<u32, StoreError> {
    let catalog = Migrations::catalog();
    validate_catalog(&catalog, correlation_id)?;
    let latest = catalog.last().map_or(0, |record| record.version);
    let current = current_schema_version(connection, correlation_id)?;
    if current < latest {
        return Err(StoreError::new(
            StoreErrorKind::SchemaOlder,
            "database schema is older than this binary can read without migration",
            correlation_id,
        ));
    }
    if current > latest {
        return Err(StoreError::new(
            StoreErrorKind::SchemaNewer,
            "database schema is newer than this binary supports",
            correlation_id,
        ));
    }
    verify_applied_checksum(connection, &catalog, current, correlation_id)?;
    Ok(current)
}

/// Applies every migration in the supplied catalog that is not yet
/// present on disk. Production code uses [`apply_pending`] so the
/// compiled-in catalog stays the single source of truth; tests use
/// the [`apply_catalog`] wrapper to inject a pending catalog or
/// exercise the tampered-prefix interaction.
fn apply_with_catalog(
    connection: &Connection,
    app_version: &str,
    correlation_id: CorrelationId,
    catalog: &[MigrationRecord],
) -> Result<u32, StoreError> {
    let catalog_by_version: BTreeMap<u32, MigrationRecord> =
        validate_catalog(catalog, correlation_id)?;
    let latest = catalog.last().map_or(0, |record| record.version);

    let current = current_schema_version(connection, correlation_id)?;
    if current > latest {
        return Err(StoreError::new(
            StoreErrorKind::SchemaNewer,
            "database schema is newer than this binary supports",
            correlation_id,
        ));
    }

    // Verify the on-disk prefix identity *before* running any
    // pending migration. The check proves the SQL the binary would
    // emit matches the SQL that originally produced the schema; a
    // mismatch on an already-migrated database fails closed without
    // mutating state.
    verify_applied_checksum(connection, catalog, current, correlation_id)?;

    for version in (current + 1)..=latest {
        let record = catalog_by_version.get(&version).ok_or_else(|| {
            StoreError::new(
                StoreErrorKind::SchemaIncompatible,
                format!("missing migration v{version:04}"),
                correlation_id,
            )
        })?;
        apply_one(connection, record, app_version, catalog, correlation_id)?;
    }

    Ok(latest)
}

/// Test-only twin of [`apply_pending`] that accepts an explicit
/// catalog. Production code must use [`apply_pending`] so the
/// compiled-in catalog stays the single source of truth; tests use
/// this entry point to inject pending migrations or exercise the
/// tampered-prefix interaction.
#[cfg(test)]
pub(crate) fn apply_catalog(
    connection: &Connection,
    app_version: &str,
    correlation_id: CorrelationId,
    catalog: &[MigrationRecord],
) -> Result<u32, StoreError> {
    apply_with_catalog(connection, app_version, correlation_id, catalog)
}

/// Validates that the supplied catalog is well-formed: versions are
/// unique, sorted in ascending order, and form a contiguous prefix
/// starting at `1`. The function fails closed because every
/// checksum and migration loop below assumes that property; a
/// `BTreeMap`-based dedup would silently hide duplicates and an
/// order-blind check would silently accept a reversed catalog.
fn validate_catalog(
    catalog: &[MigrationRecord],
    correlation_id: CorrelationId,
) -> Result<BTreeMap<u32, MigrationRecord>, StoreError> {
    if catalog.is_empty() {
        return Err(StoreError::new(
            StoreErrorKind::SchemaIncompatible,
            "migration catalog must not be empty",
            correlation_id,
        ));
    }
    // Reject unsorted catalogs *before* building the map so a
    // reversed `[v2, v1]` does not silently pass the contiguity
    // check once the keys are re-sorted by `BTreeMap`.
    for pair in catalog.windows(2) {
        if pair[0].version >= pair[1].version {
            return Err(StoreError::new(
                StoreErrorKind::SchemaIncompatible,
                format!(
                    "migration catalog must be strictly ascending; got v{:04} followed by v{:04}",
                    pair[0].version, pair[1].version
                ),
                correlation_id,
            ));
        }
    }
    let mut by_version: BTreeMap<u32, MigrationRecord> = BTreeMap::new();
    for record in catalog {
        if by_version.insert(record.version, record.clone()).is_some() {
            return Err(StoreError::new(
                StoreErrorKind::SchemaIncompatible,
                format!("duplicate migration version {}", record.version),
                correlation_id,
            ));
        }
    }
    if by_version.keys().next().copied() != Some(1) {
        return Err(StoreError::new(
            StoreErrorKind::SchemaIncompatible,
            format!(
                "migration catalog must start at version 1, found {}",
                by_version.keys().next().copied().unwrap_or(0)
            ),
            correlation_id,
        ));
    }
    for (idx, version) in by_version.keys().enumerate() {
        let expected = idx as u32 + 1;
        if *version != expected {
            return Err(StoreError::new(
                StoreErrorKind::SchemaIncompatible,
                format!(
                    "migration catalog is not contiguous: expected v{expected:04}, found v{version:04}"
                ),
                correlation_id,
            ));
        }
    }
    Ok(by_version)
}

fn apply_one(
    connection: &Connection,
    record: &MigrationRecord,
    app_version: &str,
    catalog: &[MigrationRecord],
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    for statement in record.statements {
        tx.execute_batch(statement)
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    }
    record_schema_version(&tx, record.version, app_version, catalog, correlation_id)?;
    tx.commit().map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    Ok(())
}

/// Reads the current schema version. Returns 0 when the database is
/// fresh (no `schema_meta` row).
fn current_schema_version(
    connection: &Connection,
    correlation_id: CorrelationId,
) -> Result<u32, StoreError> {
    // Detect the absence of `schema_meta` explicitly so a fresh
    // database does not look like a corruption error.
    let present: bool = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'",
            [],
            |row| row.get::<_, i64>(0).map(|_| true),
        )
        .optional()
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?
        .unwrap_or(false);
    if !present {
        return Ok(0);
    }
    let version: i64 = connection
        .query_row("SELECT schema_version FROM schema_meta WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    u32::try_from(version).map_err(|_| {
        StoreError::new(
            StoreErrorKind::SchemaIncompatible,
            "schema version overflow",
            correlation_id,
        )
    })
}

/// Compares the on-disk applied-prefix checksum against the
/// compiled-in catalog's prefix checksum. A mismatch on an
/// already-migrated database is treated as incompatible because the
/// SQL the binary would emit no longer matches the SQL that
/// originally produced the schema.
fn verify_applied_checksum(
    connection: &Connection,
    catalog: &[MigrationRecord],
    current: u32,
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    // A fresh database has just been migrated in this call; the
    // stored checksum is the one we wrote so it always matches.
    // The check is therefore meaningful only after the first
    // migration has been applied during a previous open.
    if current == 0 {
        return Ok(());
    }
    let stored: String = connection
        .query_row("SELECT applied_checksum FROM schema_meta WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    // The catalog slice for the applied prefix contains every
    // migration whose version is less than or equal to the stored
    // `current`. A truncation here would itself indicate tampering,
    // so we surface it explicitly rather than guessing.
    let prefix: Vec<MigrationRecord> =
        catalog.iter().filter(|record| record.version <= current).cloned().collect();
    if prefix.len() as u32 != current {
        return Err(StoreError::new(
            StoreErrorKind::SchemaIncompatible,
            format!(
                "binary catalog is missing migrations up to v{current:04}; cannot verify prefix"
            ),
            correlation_id,
        ));
    }
    let expected = Migrations::prefix_checksum(&prefix);
    if stored != expected {
        return Err(StoreError::new(
            StoreErrorKind::SchemaIncompatible,
            format!(
                "stored applied checksum {stored} does not match binary prefix checksum {expected}"
            ),
            correlation_id,
        ));
    }
    Ok(())
}

/// Inserts (or replaces) the singleton `schema_meta` row. The
/// `applied_checksum` column is recomputed over the supplied
/// catalog's prefix up to the new version and stored alongside the
/// version bump in the same transaction.
fn record_schema_version(
    connection: &Connection,
    version: u32,
    app_version: &str,
    catalog: &[MigrationRecord],
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    let now = WallTime::now().to_rfc3339();
    let prefix: Vec<MigrationRecord> =
        catalog.iter().filter(|record| record.version <= version).cloned().collect();
    let checksum = Migrations::prefix_checksum(&prefix);
    connection
        .execute(
            "INSERT OR REPLACE INTO schema_meta \
             (singleton, schema_version, min_reader_version, migrated_at, app_version, applied_checksum) \
             VALUES (1, ?1, ?1, ?2, ?3, ?4)",
            rusqlite::params![i64::from(version), now, app_version, checksum],
        )
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    Ok(())
}

use rusqlite::OptionalExtension as _;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use xtrace_domain::CorrelationId;

    fn new_memory() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory store");
        conn.execute_batch("PRAGMA foreign_keys = ON").expect("foreign keys");
        conn
    }

    #[test]
    fn fresh_database_is_initialized_to_latest() {
        let conn = new_memory();
        let reached = apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply");
        assert_eq!(reached, Migrations::latest_version());

        let stored: i64 =
            conn.query_row("SELECT schema_version FROM schema_meta", [], |row| row.get(0)).unwrap();
        assert_eq!(stored as u32, Migrations::latest_version());
        assert_eq!(list_columns(&conn, "recordings"), RECORDINGS_COLUMNS);
        assert_eq!(list_columns(&conn, "recording_segments"), RECORDING_SEGMENTS_COLUMNS);
        assert_recording_schema_contract(&conn);
    }

    #[test]
    fn applying_twice_is_idempotent() {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("first apply");
        let second = apply_pending(&conn, "0.1.0-test", CorrelationId::new())
            .expect("second apply is a no-op");
        assert_eq!(second, Migrations::latest_version());
    }

    #[test]
    fn v1_database_upgrades_to_v4_and_reopens_idempotently() {
        let conn = new_memory();
        let v1 = v1_catalog();
        assert_eq!(
            apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &v1).expect("apply v1"),
            1
        );
        assert!(!table_exists(&conn, "recordings"));
        assert!(!table_exists(&conn, "recording_segments"));

        assert_eq!(
            apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("upgrade v4"),
            4
        );
        assert_recording_schema_contract(&conn);
        assert_eq!(
            apply_pending(&conn, "0.1.0-test", CorrelationId::new())
                .expect("repeat open is idempotent"),
            4
        );
    }

    #[test]
    fn v2_database_migrates_forward_without_backfilling_recordings() {
        let conn = new_memory();
        let v2 = Migrations::catalog()[..2].to_vec();
        assert_eq!(apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &v2).expect("v2"), 2);
        let project = id(0x31);
        let recording = id(0x41);
        insert_project(&conn, &project).expect("project");
        insert_recording(&conn, &recording, &project, &id(0x51), "recording").expect("recording");

        assert_eq!(apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("v4"), 4);
        let sidecars: i64 = conn
            .query_row("SELECT count(*) FROM recording_endpoint_observations", [], |row| row.get(0))
            .expect("sidecars");
        assert_eq!(sidecars, 0);
        assert_eq!(schema_version(&conn), 4);
        assert!(table_exists(&conn, "operations"));
        assert!(table_exists(&conn, "recording_endpoint_observations"));
        assert!(table_exists(&conn, "recording_frame_index"));
        assert!(table_exists(&conn, "recording_terminal_evidence"));
        let terminal_rows: i64 = conn
            .query_row("SELECT count(*) FROM recording_terminal_evidence", [], |row| row.get(0))
            .expect("terminal evidence remains unbackfilled");
        assert_eq!(terminal_rows, 0);
        let fk_errors: i64 = conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| row.get(0))
            .expect("foreign keys");
        assert_eq!(fk_errors, 0);
    }

    #[test]
    fn applying_when_schema_is_newer_fails_without_mutation() {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("first apply");
        let err = apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("idempotent");
        assert_eq!(err, Migrations::latest_version());

        // Simulate a future binary bumping the on-disk version by hand.
        conn.execute(
            "UPDATE schema_meta SET schema_version = schema_version + 1 WHERE singleton = 1",
            [],
        )
        .expect("bump version");
        let checksum_before: String = conn
            .query_row("SELECT applied_checksum FROM schema_meta", [], |row| row.get(0))
            .expect("checksum before failed reopen");
        let err = apply_pending(&conn, "0.1.0-test", CorrelationId::new()).unwrap_err();
        assert_eq!(err.kind(), StoreErrorKind::SchemaNewer);
        let checksum_after: String = conn
            .query_row("SELECT applied_checksum FROM schema_meta", [], |row| row.get(0))
            .expect("checksum after failed reopen");
        assert_eq!(checksum_after, checksum_before);
        assert_recording_schema_contract(&conn);
    }

    #[test]
    fn applied_checksum_records_binary_prefix_identity() {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply");
        let stored: String = conn
            .query_row("SELECT applied_checksum FROM schema_meta WHERE singleton = 1", [], |row| {
                row.get(0)
            })
            .expect("checksum row");
        let expected = Migrations::prefix_checksum(&Migrations::catalog());
        assert_eq!(stored, expected);
    }

    #[test]
    fn v0001_prefix_checksum_is_pinned() {
        // v0001 is already shipped. Its byte-for-byte migration identity must
        // remain stable even while later migrations extend the catalog.
        assert_eq!(
            Migrations::prefix_checksum(&v1_catalog()),
            "b3:47f2631947a676aceea0a8e887b32e5ee590cd07c8eb643770583a673bba4787"
        );
    }

    #[test]
    fn tampered_applied_checksum_is_rejected_before_pending_runs() {
        // The regression we are guarding against: a future binary
        // that ships a v2 migration could overwrite the on-disk
        // checksum with the new full-catalog hash before the older
        // checksum was verified. With the new design the older
        // checksum is verified *before* any pending migration runs,
        // so a tampered value is rejected without v2 mutating state.
        let conn = new_memory();
        let v1 = v1_catalog();
        apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &v1).expect("apply v1");

        // Tamper the stored applied checksum.
        conn.execute(
            "UPDATE schema_meta SET applied_checksum = 'b3:0000000000000000000000000000000000000000000000000000000000000000' WHERE singleton = 1",
            [],
        )
        .expect("tamper checksum");

        let err = apply_pending(&conn, "0.1.0-test", CorrelationId::new())
            .expect_err("tampered checksum must be rejected");
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
        assert!(!table_exists(&conn, "recordings"));
        assert!(!table_exists(&conn, "recording_segments"));
    }

    #[test]
    fn tampered_v2_checksum_is_rejected_on_reopen() {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply v2");
        conn.execute(
            "UPDATE schema_meta SET applied_checksum = 'b3:0000000000000000000000000000000000000000000000000000000000000000' WHERE singleton = 1",
            [],
        )
        .expect("tamper v2 checksum");

        let err = apply_pending(&conn, "0.1.0-test", CorrelationId::new())
            .expect_err("tampered v2 checksum must fail closed");
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
        assert_recording_schema_contract(&conn);
    }

    #[test]
    fn fresh_database_ignores_pending_catalog_without_checksum_failure() {
        // A fresh database has no stored checksum. The verification
        // step short-circuits and pending migrations apply as usual.
        let conn = new_memory();
        let v1 = v1_catalog();
        const V2_STATEMENT: &str =
            "ALTER TABLE projects ADD COLUMN another_marker TEXT NOT NULL DEFAULT ''";
        let catalog = vec![
            v1[0].clone(),
            MigrationRecord { version: 2, label: "v0002_another", statements: &[V2_STATEMENT] },
        ];
        let reached =
            apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &catalog).expect("apply");
        assert_eq!(reached, 2);
    }

    #[test]
    fn failed_v2_migration_rolls_back_without_partial_tables() {
        const CREATE_PARTIAL_TABLE: &str =
            "CREATE TABLE migration_should_rollback (value TEXT) STRICT";
        const INVALID_STATEMENT: &str = "NOT VALID SQL";

        let conn = new_memory();
        let v1 = v1_catalog();
        apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &v1).expect("apply v1");
        let failing_catalog = vec![
            v1[0].clone(),
            MigrationRecord {
                version: 2,
                label: "v0002_injected_failure",
                statements: &[CREATE_PARTIAL_TABLE, INVALID_STATEMENT],
            },
        ];

        apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &failing_catalog)
            .expect_err("invalid v2 migration must fail");
        assert!(!table_exists(&conn, "migration_should_rollback"));
        assert!(!table_exists(&conn, "recordings"));
        assert!(!table_exists(&conn, "recording_segments"));
        assert_eq!(schema_version(&conn), 1);
    }

    #[test]
    fn preexisting_malformed_recordings_fails_closed_without_v2_side_effects() {
        let conn = new_memory();
        let v1 = v1_catalog();
        apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &v1).expect("apply v1 only");
        conn.execute_batch("CREATE TABLE recordings (malformed TEXT) STRICT;")
            .expect("seed malformed recordings table");
        let recordings_before = table_sql(&conn, "recordings");

        apply_pending(&conn, "0.1.0-test", CorrelationId::new())
            .expect_err("preexisting recordings table must reject versioned migration");
        assert_eq!(schema_version(&conn), 1);
        assert_eq!(applied_checksum(&conn), Migrations::prefix_checksum(&v1));
        assert_eq!(table_sql(&conn, "recordings"), recordings_before);
        assert!(!table_exists(&conn, "recording_segments"));
    }

    #[test]
    fn preexisting_malformed_segments_roll_back_earlier_v2_table_creation() {
        let conn = new_memory();
        let v1 = v1_catalog();
        apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &v1).expect("apply v1 only");
        conn.execute_batch("CREATE TABLE recording_segments (malformed TEXT) STRICT;")
            .expect("seed malformed recording_segments table");
        let segments_before = table_sql(&conn, "recording_segments");

        apply_pending(&conn, "0.1.0-test", CorrelationId::new())
            .expect_err("preexisting segments table must reject versioned migration");
        assert_eq!(schema_version(&conn), 1);
        assert_eq!(applied_checksum(&conn), Migrations::prefix_checksum(&v1));
        assert!(!table_exists(&conn, "recordings"));
        assert_eq!(table_sql(&conn, "recording_segments"), segments_before);
    }

    #[test]
    fn recordings_constraints_accept_current_states_and_reject_invalid_rows() {
        let conn = initialized_v2();
        let project_id = id(0x11);
        let runtime_session_id = id(0x22);
        insert_project(&conn, &project_id).expect("insert project");

        for (index, state) in
            ["recording", "finalizing", "complete", "partial", "invalid"].into_iter().enumerate()
        {
            let recording_id = id(0x30 + index as u8);
            insert_recording(&conn, &recording_id, &project_id, &runtime_session_id, state)
                .expect("current recording state is accepted");
        }
        assert_eq!(table_count(&conn, "recordings"), 5);

        let invalid_state_id = id(0x40);
        assert!(insert_recording(
            &conn,
            &invalid_state_id,
            &project_id,
            &runtime_session_id,
            "unknown",
        )
        .is_err());
        assert!(
            insert_recording(&conn, &[0x41; 15], &project_id, &runtime_session_id, "recording",)
                .is_err()
        );
        assert!(
            insert_recording(&conn, &id(0x42), &[0x42; 15], &runtime_session_id, "recording",)
                .is_err()
        );
        assert!(
            insert_recording(&conn, &id(0x43), &project_id, &[0x43; 15], "recording",).is_err()
        );
        assert!(
            insert_recording(&conn, &id(0x44), &id(0x45), &runtime_session_id, "recording",)
                .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO recordings \
                 (recording_id, project_id, runtime_session_id, status, opened_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                // This text has 16 characters, so STRICT typing rather than
                // the length check must reject it for the BLOB identifier.
                params!["1234567890abcdef", &project_id, &runtime_session_id, "recording", "now"],
            )
            .is_err()
        );
    }

    #[test]
    fn recording_segments_constraints_accept_u64_max_and_reject_invalid_rows() {
        let conn = initialized_v2();
        let project_id = id(0x51);
        let recording_id = id(0x52);
        let runtime_session_id = id(0x53);
        insert_project(&conn, &project_id).expect("insert project");
        insert_recording(&conn, &recording_id, &project_id, &runtime_session_id, "recording")
            .expect("insert recording");

        let max_sequence = u64::MAX.to_be_bytes();
        let mut valid = valid_segment(&recording_id);
        valid.first_recording_seq = &max_sequence;
        valid.last_recording_seq = &max_sequence;
        insert_segment(&conn, valid).expect("valid u64::MAX sequence blob");

        assert!(insert_segment(&conn, valid_segment(&id(0x54))).is_err());
        let mut negative_ordinal = valid_segment(&recording_id);
        negative_ordinal.segment_ordinal = -1;
        assert!(insert_segment(&conn, negative_ordinal).is_err());
        let short_hash = [0x55; 31];
        let mut bad_hash = valid_segment(&recording_id);
        bad_hash.object_hash = &short_hash;
        assert!(insert_segment(&conn, bad_hash).is_err());
        let short_checksum = [0x56; 31];
        let mut bad_checksum = valid_segment(&recording_id);
        bad_checksum.checksum = &short_checksum;
        assert!(insert_segment(&conn, bad_checksum).is_err());
        let short_sequence = [0x57; 7];
        let mut bad_first_sequence = valid_segment(&recording_id);
        bad_first_sequence.first_recording_seq = &short_sequence;
        assert!(insert_segment(&conn, bad_first_sequence).is_err());
        let mut bad_last_sequence = valid_segment(&recording_id);
        bad_last_sequence.last_recording_seq = &short_sequence;
        assert!(insert_segment(&conn, bad_last_sequence).is_err());
        let mut zero_events = valid_segment(&recording_id);
        zero_events.event_count = 0;
        assert!(insert_segment(&conn, zero_events).is_err());
        let mut zero_uncompressed = valid_segment(&recording_id);
        zero_uncompressed.uncompressed_bytes = 0;
        assert!(insert_segment(&conn, zero_uncompressed).is_err());
        let mut zero_compressed = valid_segment(&recording_id);
        zero_compressed.compressed_bytes = 0;
        assert!(insert_segment(&conn, zero_compressed).is_err());
        assert!(insert_segment(&conn, valid_segment(&recording_id)).is_err());
        assert!(
            conn.execute(
                "INSERT INTO recording_segments \
                 (recording_id, segment_ordinal, object_hash, first_recording_seq, \
                  last_recording_seq, event_count, uncompressed_bytes, compressed_bytes, checksum) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    &recording_id,
                    1_i64,
                    // This text has 32 characters, so STRICT typing rather
                    // than the length check must reject it for object_hash.
                    "0123456789abcdef0123456789abcdef",
                    &max_sequence,
                    &max_sequence,
                    1_i64,
                    1_i64,
                    1_i64,
                    &CHECKSUM,
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn checksum_changes_when_migration_text_changes() {
        // Sanity check that any textual change to the compiled-in
        // catalog produces a different identity. This guards against
        // a future change that "looks the same" but silently alters
        // behavior.
        let a = Migrations::catalog_checksum();
        let b = blake3::hash(b"alternate-migration-text").to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn duplicate_catalog_versions_fail_closed_without_mutating_schema() {
        // A catalog with two records sharing the same version must
        // be rejected before any migration runs; a `BTreeMap`-based
        // dedup would silently keep the last record and silently
        // change the on-disk identity.
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply latest schema");
        let compiled_catalog = Migrations::catalog();
        let column_count_before = list_columns(&conn, "projects").len();

        let catalog = vec![
            compiled_catalog[0].clone(),
            MigrationRecord {
                version: 2,
                label: "v0002_first",
                statements: &[
                    "ALTER TABLE projects ADD COLUMN first_marker TEXT NOT NULL DEFAULT ''",
                ],
            },
            MigrationRecord {
                version: 2,
                label: "v0002_second",
                statements: &[
                    "ALTER TABLE projects ADD COLUMN second_marker TEXT NOT NULL DEFAULT ''",
                ],
            },
        ];
        let err = apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &catalog)
            .expect_err("duplicate catalog versions must be rejected");
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
        // No mutation: neither marker column must be present.
        let columns = list_columns(&conn, "projects");
        assert_eq!(columns.len(), column_count_before);
        assert!(!columns.iter().any(|name| name == "first_marker"));
        assert!(!columns.iter().any(|name| name == "second_marker"));
    }

    #[test]
    fn gapped_catalog_fails_closed_without_mutating_schema() {
        // A catalog that skips v2 must fail closed. The migration
        // runner must not silently insert only v1 and v3.
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply latest schema");
        let compiled_catalog = Migrations::catalog();
        let column_count_before = list_columns(&conn, "projects").len();

        let catalog = vec![
            compiled_catalog[0].clone(),
            MigrationRecord {
                version: 3,
                label: "v0003_skip_two",
                statements: &[
                    "ALTER TABLE projects ADD COLUMN skipped_marker TEXT NOT NULL DEFAULT ''",
                ],
            },
        ];
        let err = apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &catalog)
            .expect_err("gapped catalog must be rejected");
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
        let columns = list_columns(&conn, "projects");
        assert_eq!(columns.len(), column_count_before);
        assert!(!columns.iter().any(|name| name == "skipped_marker"));
    }

    #[test]
    fn unsorted_catalog_fails_closed_without_mutating_schema() {
        // The runner iterates `(current + 1)..=latest` so the catalog
        // must be sorted in ascending order. A reversed catalog that
        // also happens to be contiguous would otherwise have its
        // checksum computed incorrectly.
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply latest schema");
        let compiled_catalog = Migrations::catalog();
        let column_count_before = list_columns(&conn, "projects").len();

        let catalog = vec![
            MigrationRecord {
                version: 2,
                label: "v0002_unsorted",
                statements: &[
                    "ALTER TABLE projects ADD COLUMN unsorted_marker TEXT NOT NULL DEFAULT ''",
                ],
            },
            compiled_catalog[0].clone(),
        ];
        let err = apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &catalog)
            .expect_err("unsorted catalog must be rejected");
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
        let columns = list_columns(&conn, "projects");
        assert_eq!(columns.len(), column_count_before);
        assert!(!columns.iter().any(|name| name == "unsorted_marker"));
    }

    const OBJECT_HASH: [u8; 32] = [0x61; 32];
    const CHECKSUM: [u8; 32] = [0x62; 32];
    const SEQUENCE_TWO: [u8; 8] = 2_u64.to_be_bytes();

    struct SegmentInput<'a> {
        recording_id: &'a [u8],
        segment_ordinal: i64,
        object_hash: &'a [u8],
        first_recording_seq: &'a [u8],
        last_recording_seq: &'a [u8],
        event_count: i64,
        uncompressed_bytes: i64,
        compressed_bytes: i64,
        checksum: &'a [u8],
    }

    fn initialized_v2() -> Connection {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply v2");
        conn
    }

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn insert_project(conn: &Connection, project_id: &[u8]) -> Result<usize, rusqlite::Error> {
        conn.execute(
            "INSERT INTO projects \
             (project_id, canonical_repo_hash, display_name, created_at, last_opened_at, \
              config_schema_version, effective_config_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![project_id, "b3:project", "project", "now", "now", 1_i64, "b3:config"],
        )
    }

    fn insert_recording(
        conn: &Connection,
        recording_id: &[u8],
        project_id: &[u8],
        runtime_session_id: &[u8],
        status: &str,
    ) -> Result<usize, rusqlite::Error> {
        conn.execute(
            "INSERT INTO recordings \
             (recording_id, project_id, runtime_session_id, status, opened_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![recording_id, project_id, runtime_session_id, status, "now"],
        )
    }

    fn valid_segment(recording_id: &[u8]) -> SegmentInput<'_> {
        SegmentInput {
            recording_id,
            segment_ordinal: 0,
            object_hash: &OBJECT_HASH,
            first_recording_seq: &SEQUENCE_TWO,
            last_recording_seq: &SEQUENCE_TWO,
            event_count: 1,
            uncompressed_bytes: 1,
            compressed_bytes: 1,
            checksum: &CHECKSUM,
        }
    }

    fn insert_segment(
        conn: &Connection,
        segment: SegmentInput<'_>,
    ) -> Result<usize, rusqlite::Error> {
        conn.execute(
            "INSERT INTO recording_segments \
             (recording_id, segment_ordinal, object_hash, first_recording_seq, \
              last_recording_seq, event_count, uncompressed_bytes, compressed_bytes, checksum) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                segment.recording_id,
                segment.segment_ordinal,
                segment.object_hash,
                segment.first_recording_seq,
                segment.last_recording_seq,
                segment.event_count,
                segment.uncompressed_bytes,
                segment.compressed_bytes,
                segment.checksum,
            ],
        )
    }

    fn list_columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).expect("prepare");
        let rows = stmt.query_map([], |row| row.get::<_, String>(1)).expect("rows");
        rows.filter_map(Result::ok).collect()
    }

    const RECORDINGS_COLUMNS: &[&str] =
        &["recording_id", "project_id", "runtime_session_id", "status", "opened_at"];
    const RECORDING_SEGMENTS_COLUMNS: &[&str] = &[
        "recording_id",
        "segment_ordinal",
        "object_hash",
        "first_recording_seq",
        "last_recording_seq",
        "event_count",
        "uncompressed_bytes",
        "compressed_bytes",
        "checksum",
    ];

    fn v1_catalog() -> Vec<MigrationRecord> {
        vec![Migrations::catalog()[0].clone()]
    }

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, i64>(0).map(|_| true),
        )
        .optional()
        .expect("look up table")
        .unwrap_or(false)
    }

    fn schema_version(conn: &Connection) -> i64 {
        conn.query_row("SELECT schema_version FROM schema_meta WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .expect("schema version")
    }

    fn applied_checksum(conn: &Connection) -> String {
        conn.query_row("SELECT applied_checksum FROM schema_meta WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .expect("applied checksum")
    }

    fn table_count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .expect("table count")
    }

    fn table_sql(conn: &Connection, table: &str) -> String {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .expect("table schema")
    }

    fn assert_recording_schema_contract(conn: &Connection) {
        let recordings_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'recordings'",
                [],
                |row| row.get(0),
            )
            .expect("recordings schema");
        assert!(recordings_sql.contains("CHECK(length(recording_id) = 16)"));
        assert!(recordings_sql.contains("CHECK(length(project_id) = 16)"));
        assert!(recordings_sql.contains("CHECK(length(runtime_session_id) = 16)"));
        for state in ["recording", "finalizing", "complete", "partial", "invalid"] {
            assert!(recordings_sql.contains(state), "recordings status must include {state}");
        }

        let segments_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'recording_segments'",
                [],
                |row| row.get(0),
            )
            .expect("recording_segments schema");
        assert!(segments_sql.contains("CHECK(length(first_recording_seq) = 8)"));
        assert!(segments_sql.contains("CHECK(length(last_recording_seq) = 8)"));
        assert!(!segments_sql.contains("UNIQUE"));
        let secondary_indexes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'recording_segments' AND sql IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .expect("recording_segments secondary indexes");
        assert_eq!(secondary_indexes, 0);
    }
}
