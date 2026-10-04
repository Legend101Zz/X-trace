//! Root-bound recording anchor persistence.
//!
//! The XTF object and segment commit path arrives in a later pass. This module
//! establishes only the root binding, scoped error surface, and idempotent
//! recording anchor needed before object publication can be added safely.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

use rusqlite::OptionalExtension as _;
use xtrace_application::observed_endpoint_queries::{
    ObservedEndpointKey, ObservedEndpointRecord, ObservedRecordingKey, ObservedRecordingRecord,
};
use xtrace_application::recording::EndpointObservationInput;
use xtrace_application::recording_queries::{
    MAX_RECORDING_EVENT_PROJECTION_BYTES, MAX_RECORDING_VERIFIED_INPUT_BYTES, PersistedEvent,
    PersistedInteraction, PersistedSource, RecordingEventWindow, RecordingMetadata,
    RecordingStatus, ShowWindowRequest, SourceStatus,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    ContentHash, CorrelationId, ENDPOINT_FINGERPRINT_FORMAT_VERSION, EndpointIdentity, HttpMethod,
    ProjectId, RecordingId, RuntimeSessionId, SourceBinding, SourceRange, Transport, WallTime,
};
use xtrace_runtime::private_storage::{AdmittedPrivateRoot, PrivateStorageError};

use crate::connection::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};
use crate::xtf::{
    LogicalXtfSegment, XtfCodecError, XtfSegmentInput, compress_logical_bytes,
    encode_logical_segment, max_compressed_segment_bytes, verify_compressed_segment,
};

/// Input for the idempotent recording-anchor operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginRecordingRequest {
    /// Project that owns the recording.
    pub project_id: ProjectId,
    /// Stable recording identity assigned by the admitted session.
    pub recording_id: RecordingId,
    /// Runtime session that opened the recording.
    pub runtime_session_id: RuntimeSessionId,
    /// Canonical wall-clock time when the recording opened.
    pub opened_at: WallTime,
    /// Run-scoped opt-in and adapter fields for safe endpoint classification.
    pub endpoint_observation: EndpointObservationInput,
}

/// Successful outcome of [`SqliteRecordingStore::begin_recording`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeginRecordingReceipt {
    /// Recording identity that was inserted or replayed.
    pub recording_id: RecordingId,
    /// Whether this call inserted a row or proved an exact replay.
    pub disposition: BeginRecordingDisposition,
}

/// Idempotency disposition for a recording anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginRecordingDisposition {
    /// A new `recording` lifecycle row was inserted.
    Inserted,
    /// An existing row has the same immutable begin identity.
    ExactReplay,
    /// Existing legacy recording has no observation sidecar and was not changed.
    LegacyObservationAbsent,
}

/// Typed input for one immutable XTF segment commit.
#[derive(Clone, Debug)]
pub struct SegmentCommitRequest {
    /// Project that owns the recording anchor.
    pub project_id: ProjectId,
    /// Recording that owns the segment.
    pub recording_id: RecordingId,
    /// Zero-based segment ordinal.
    pub segment_ordinal: u32,
    /// Ordered typed events encoded by the canonical XTF codec.
    pub events: Vec<xtrace_protocol::xtf::XtfEventEnvelope>,
}

/// Successful result of [`SqliteRecordingStore::commit_segment`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentCommitReceipt {
    /// Recording that owns the committed segment.
    pub recording_id: RecordingId,
    /// Zero-based committed ordinal.
    pub segment_ordinal: u32,
    /// BLAKE3 address of the complete uncompressed logical XTF stream.
    pub object_hash: ContentHash,
    /// Size of the complete uncompressed logical XTF stream.
    pub uncompressed_bytes: u64,
    /// Size of the persisted checksummed zstd object.
    pub compressed_bytes: u64,
    /// Whether a row was inserted or a verified exact replay returned.
    pub disposition: SegmentCommitDisposition,
}

/// Idempotency disposition for a segment commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentCommitDisposition {
    /// A verified object and metadata row were committed.
    Inserted,
    /// A matching metadata row and fully verified object already exist.
    ExactReplay,
}

/// Fine-grained classification for recording-store failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordingStoreErrorKind {
    /// Caller input or a root binding is invalid.
    Validation,
    /// A required project or recording is absent.
    NotFound,
    /// An immutable identity or a database integrity rule conflicts.
    Conflict,
    /// Durable data or a synchronization primitive cannot be trusted.
    Corruption,
    /// The root or database does not meet owner-only permission requirements.
    Permission,
    /// The filesystem or SQLite transport failed.
    Transport,
    /// The active platform or database schema is incompatible.
    Compatibility,
    /// SQLite contention exceeded its configured wait.
    Busy,
    /// SQLite or the host exhausted a bounded resource.
    Resource,
    /// An unexpected internal failure occurred.
    Internal,
}

/// Broad, safe category for recording-store failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordingStoreErrorCategory {
    /// The caller must correct input or choose a different root.
    Validation,
    /// A prerequisite entity has not been created.
    NotFound,
    /// Immutable or integrity-protected state disagrees.
    Conflict,
    /// Stored data or synchronization state cannot be trusted.
    Integrity,
    /// Filesystem or SQLite availability prevented completion.
    Availability,
    /// The platform or schema cannot support this operation.
    Compatibility,
    /// An implementation failure requires investigation.
    Internal,
}

/// Scoped error returned by recording persistence operations.
///
/// Its messages and optional source descriptions deliberately omit SQL text,
/// paths, parameter values, and captured payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordingStoreError {
    kind: RecordingStoreErrorKind,
    code: &'static str,
    message: &'static str,
    correlation_id: CorrelationId,
    source: Option<&'static str>,
}

impl RecordingStoreError {
    fn new(
        kind: RecordingStoreErrorKind,
        code: &'static str,
        message: &'static str,
        correlation_id: CorrelationId,
    ) -> Self {
        Self { kind, code, message, correlation_id, source: None }
    }

    fn with_source(mut self, source: &'static str) -> Self {
        self.source = Some(source);
        self
    }

    /// Returns the stable machine-readable recording-store code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the detailed failure kind.
    #[must_use]
    pub const fn kind(&self) -> RecordingStoreErrorKind {
        self.kind
    }

    /// Returns the broad safe category for the failure.
    #[must_use]
    pub const fn category(&self) -> RecordingStoreErrorCategory {
        match self.kind {
            RecordingStoreErrorKind::Validation | RecordingStoreErrorKind::Permission => {
                RecordingStoreErrorCategory::Validation
            }
            RecordingStoreErrorKind::NotFound => RecordingStoreErrorCategory::NotFound,
            RecordingStoreErrorKind::Conflict => RecordingStoreErrorCategory::Conflict,
            RecordingStoreErrorKind::Corruption => RecordingStoreErrorCategory::Integrity,
            RecordingStoreErrorKind::Transport
            | RecordingStoreErrorKind::Busy
            | RecordingStoreErrorKind::Resource => RecordingStoreErrorCategory::Availability,
            RecordingStoreErrorKind::Compatibility => RecordingStoreErrorCategory::Compatibility,
            RecordingStoreErrorKind::Internal => RecordingStoreErrorCategory::Internal,
        }
    }

    /// Returns the correlation identity minted for this operation.
    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }

    /// Returns a user-safe diagnostic message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns a sanitized source category when one is useful to diagnostics.
    #[must_use]
    pub const fn source(&self) -> Option<&'static str> {
        self.source
    }
}

impl fmt::Display for RecordingStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RecordingStoreError {}

/// Borrowing, root-bound recording persistence view.
///
/// Construct it with [`SqliteStore::recording_store`]. The view does not create
/// object or staging directories; later commit work will revalidate this same
/// binding at every filesystem boundary to account for TOCTOU changes.
#[derive(Debug)]
pub struct SqliteRecordingStore<'store> {
    store: &'store SqliteStore,
    binding: ProjectRootBinding,
}

impl SqliteStore {
    /// Returns a root-bound recording persistence view for an on-disk store.
    ///
    /// The project root and the bootstrap SQLite file must be absolute,
    /// owner-only, regular, and symlink-free. In-memory stores and unsupported
    /// platforms are rejected because they cannot safely publish objects.
    ///
    /// # Errors
    ///
    /// Returns [`RecordingStoreError`] when the root/database binding is not
    /// safe for future object publication.
    pub fn recording_store(
        &self,
        project_root: &Path,
    ) -> Result<SqliteRecordingStore<'_>, RecordingStoreError> {
        let correlation_id = CorrelationId::new();
        let database_path = self.bootstrap().database_path.as_ref().ok_or_else(|| {
            RecordingStoreError::new(
                RecordingStoreErrorKind::Compatibility,
                "XTR-STORE-RECORDING-ROOT-COMPATIBILITY",
                "recording persistence requires an on-disk SQLite store",
                correlation_id,
            )
        })?;
        let binding = ProjectRootBinding::new(project_root, database_path.clone(), correlation_id)?;
        binding.revalidate(correlation_id)?;
        Ok(SqliteRecordingStore { store: self, binding })
    }
}

impl SqliteRecordingStore<'_> {
    /// Lists observed endpoints with a project-bound keyset read.
    pub(crate) fn list_observed_endpoints(
        &self,
        project_id: ProjectId,
        after: Option<&ObservedEndpointKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedEndpointRecord>, bool), RecordingStoreError> {
        let correlation_id = CorrelationId::new();
        self.binding.revalidate(correlation_id)?;
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        if !project_exists(&connection, project_id, correlation_id)? {
            return Err(read_not_found_error(correlation_id));
        }
        let query_limit = i64::from(limit)
            .checked_add(1)
            .ok_or_else(|| recording_query_corrupt_error(correlation_id))?;
        let mut statement = connection.prepare(
            "SELECT operation_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint FROM operations WHERE project_id = ?1 AND (?2 IS NULL OR method > ?2 OR (method = ?2 AND route_template > ?3) OR (method = ?2 AND route_template = ?3 AND application_component > ?4) OR (method = ?2 AND route_template = ?3 AND application_component = ?4 AND binding_key > ?5) OR (method = ?2 AND route_template = ?3 AND application_component = ?4 AND binding_key = ?5 AND operation_id > ?6)) ORDER BY method ASC, route_template ASC, application_component ASC, binding_key ASC, operation_id ASC LIMIT ?7"
        ).map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
        let mut rows = statement
            .query(rusqlite::params![
                project_id.as_uuid().as_bytes().to_vec(),
                after.map(|key| key.method.as_str()),
                after.map(|key| key.route_template.as_str()),
                after.map(|key| key.application_component.as_str()),
                after.map(|key| key.binding.as_str()),
                after.map(|key| key.operation_id.as_uuid().as_bytes().to_vec()),
                query_limit
            ])
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })? {
            let operation_bytes: Vec<u8> = row.get(0).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let operation_id = parse_stored_operation_id(&operation_bytes, correlation_id)?;
            let transport: String = row.get(1).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let method: String = row.get(2).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let route: String = row.get(3).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let component: String = row.get(4).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let binding: String = row.get(5).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let version: i64 = row.get(6).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let fingerprint: Vec<u8> = row.get(7).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let identity = EndpointIdentity {
                project_id,
                application_component: "spring-fixture".to_owned(),
                binding_key: "default".to_owned(),
                transport: Transport::Http,
                method: HttpMethod::Post,
                route_template: "/orders".to_owned(),
            };
            let expected =
                identity.fingerprint().map_err(|_| endpoint_identity_corrupt(correlation_id))?;
            if transport != "http"
                || method != "POST"
                || route != "/orders"
                || component != "spring-fixture"
                || binding != "default"
                || version != i64::from(ENDPOINT_FINGERPRINT_FORMAT_VERSION)
                || fingerprint.as_slice() != expected.as_bytes()
            {
                return Err(endpoint_identity_corrupt(correlation_id));
            }
            validate_operation_has_observation(
                &connection,
                project_id,
                &operation_bytes,
                correlation_id,
            )?;
            result.push(ObservedEndpointRecord {
                operation_id,
                project_id,
                application_component: component,
                binding,
                method,
                route_template: route,
                observation_policy: "spring-orders-v1".to_owned(),
            });
        }
        let has_more = result.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        if has_more {
            result.pop();
        }
        Ok((result, has_more))
    }

    /// Lists linked recordings for one project-owned operation.
    pub(crate) fn list_operation_recordings(
        &self,
        project_id: ProjectId,
        operation_id: xtrace_domain::OperationId,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), RecordingStoreError> {
        let uuid = operation_id.as_uuid();
        if uuid.get_version_num() != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
            return Err(recording_query_validation_error(CorrelationId::new()));
        }
        self.list_endpoint_recordings(project_id, Some(operation_id), after, limit)
    }

    /// Lists sidecar-unmatched and legacy sidecar-absent recordings.
    pub(crate) fn list_unmatched_recordings(
        &self,
        project_id: ProjectId,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), RecordingStoreError> {
        self.list_endpoint_recordings(project_id, None, after, limit)
    }

    fn list_endpoint_recordings(
        &self,
        project_id: ProjectId,
        operation_id: Option<xtrace_domain::OperationId>,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), RecordingStoreError> {
        let correlation_id = CorrelationId::new();
        self.binding.revalidate(correlation_id)?;
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        if !project_exists(&connection, project_id, correlation_id)? {
            return Err(read_not_found_error(correlation_id));
        }
        if let Some(operation_id) = operation_id {
            let exists: Option<i64> = connection
                .query_row(
                    "SELECT 1 FROM operations WHERE project_id = ?1 AND operation_id = ?2",
                    rusqlite::params![
                        project_id.as_uuid().as_bytes().to_vec(),
                        operation_id.as_uuid().as_bytes().to_vec()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    map_store_error(
                        StoreError::from_rusqlite(error, correlation_id),
                        correlation_id,
                    )
                })?;
            if exists.is_none() {
                return Err(read_not_found_error(correlation_id));
            }
            let raw = operation_id.as_uuid().as_bytes().to_vec();
            validate_operation_has_observation(&connection, project_id, &raw, correlation_id)?;
        }
        let query_limit = i64::from(limit)
            .checked_add(1)
            .ok_or_else(|| recording_query_corrupt_error(correlation_id))?;
        let sql = if operation_id.is_some() {
            "SELECT r.recording_id, r.status, r.opened_at, COUNT(s.segment_ordinal), COALESCE(SUM(s.event_count),0), MIN(s.first_recording_seq), MAX(s.last_recording_seq), o.disposition, o.observation_policy_id, o.operation_id, o.application_component, o.binding_key, o.method, o.route_template, o.reason_code, o.project_id FROM recordings r JOIN recording_endpoint_observations o ON o.recording_id=r.recording_id LEFT JOIN recording_segments s ON s.recording_id=r.recording_id WHERE r.project_id=?1 AND o.project_id=?1 AND o.operation_id=?2 AND (?3 IS NULL OR r.opened_at < ?3 OR (r.opened_at = ?3 AND r.recording_id < ?4)) GROUP BY r.recording_id ORDER BY r.opened_at DESC,r.recording_id DESC LIMIT ?5"
        } else {
            "SELECT r.recording_id, r.status, r.opened_at, COUNT(s.segment_ordinal), COALESCE(SUM(s.event_count),0), MIN(s.first_recording_seq), MAX(s.last_recording_seq), o.disposition, o.observation_policy_id, o.operation_id, o.application_component, o.binding_key, o.method, o.route_template, o.reason_code, o.project_id FROM recordings r LEFT JOIN recording_endpoint_observations o ON o.recording_id=r.recording_id LEFT JOIN recording_segments s ON s.recording_id=r.recording_id WHERE r.project_id=?1 AND (o.recording_id IS NULL OR o.disposition <> 'linked') AND (?2 IS NULL OR r.opened_at < ?2 OR (r.opened_at = ?2 AND r.recording_id < ?3)) GROUP BY r.recording_id ORDER BY r.opened_at DESC,r.recording_id DESC LIMIT ?4"
        };
        let mut statement = connection.prepare(sql).map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })?;
        let mut rows = if let Some(operation_id) = operation_id {
            statement.query(rusqlite::params![
                project_id.as_uuid().as_bytes().to_vec(),
                operation_id.as_uuid().as_bytes().to_vec(),
                after.map(|key| key.opened_at.as_str()),
                after.map(|key| key.recording_id.as_uuid().as_bytes().to_vec()),
                query_limit
            ])
        } else {
            statement.query(rusqlite::params![
                project_id.as_uuid().as_bytes().to_vec(),
                after.map(|key| key.opened_at.as_str()),
                after.map(|key| key.recording_id.as_uuid().as_bytes().to_vec()),
                query_limit
            ])
        }
        .map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })? {
            let metadata = recording_metadata_from_row(row, correlation_id)?;
            let disposition: Option<String> = row.get(7).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let policy: Option<String> = row.get(8).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let raw_operation: Option<Vec<u8>> = row.get(9).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let component: Option<String> = row.get(10).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let binding: Option<String> = row.get(11).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let method: Option<String> = row.get(12).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let route: Option<String> = row.get(13).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let reason: Option<String> = row.get(14).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let sidecar_project: Option<Vec<u8>> = row.get(15).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let operation = raw_operation
                .as_deref()
                .map(|bytes| parse_stored_operation_id(bytes, correlation_id))
                .transpose()?;
            if let Some(disposition) = disposition {
                let raw_op = raw_operation.clone();
                let project = sidecar_project.unwrap_or_default();
                validate_stored_observation(
                    &connection,
                    project_id,
                    &(
                        disposition,
                        policy.clone(),
                        raw_op,
                        component,
                        binding,
                        method,
                        route,
                        reason.clone(),
                        project,
                    ),
                    correlation_id,
                )?;
            }
            if operation_id.is_some() && operation != operation_id {
                return Err(endpoint_identity_corrupt(correlation_id));
            }
            result.push(ObservedRecordingRecord {
                metadata,
                operation_id: operation,
                observation_policy: policy,
                unmatched_reason: reason,
            });
        }
        let has_more = result.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        if has_more {
            result.pop();
        }
        Ok((result, has_more))
    }

    /// Lists a bounded project-owned page in opening-time/identity order.
    pub(crate) fn list_recording_metadata(
        &self,
        project_id: ProjectId,
        after: Option<RecordingId>,
        limit: u32,
    ) -> Result<(Vec<RecordingMetadata>, bool), RecordingStoreError> {
        let correlation_id = CorrelationId::new();
        self.binding.revalidate(correlation_id)?;
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        if !project_exists(&connection, project_id, correlation_id)? {
            return Err(read_not_found_error(correlation_id));
        }

        let cursor_opened_at = if let Some(recording_id) = after {
            let row: Option<(Vec<u8>, String)> = connection
                .query_row(
                    "SELECT project_id, opened_at FROM recordings WHERE recording_id = ?1",
                    rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    map_store_error(
                        StoreError::from_rusqlite(error, correlation_id),
                        correlation_id,
                    )
                })?;
            let Some((cursor_project_id, opened_at)) = row else {
                return Err(read_not_found_error(correlation_id));
            };
            if cursor_project_id.as_slice() != project_id.as_uuid().as_bytes() {
                return Err(read_not_found_error(correlation_id));
            }
            Some(opened_at)
        } else {
            None
        };

        let query_limit = i64::from(limit)
            .checked_add(1)
            .ok_or_else(|| recording_query_corrupt_error(correlation_id))?;
        let mut statement = connection
            .prepare(
                "SELECT r.recording_id, r.status, r.opened_at, \
                 COUNT(s.segment_ordinal), COALESCE(SUM(s.event_count), 0), \
                 MIN(s.first_recording_seq), MAX(s.last_recording_seq) \
                 FROM recordings AS r LEFT JOIN recording_segments AS s \
                 ON s.recording_id = r.recording_id \
                 WHERE r.project_id = ?1 \
                 AND (?2 IS NULL OR r.opened_at < ?2 \
                      OR (r.opened_at = ?2 AND r.recording_id < ?3)) \
                 GROUP BY r.recording_id \
                 ORDER BY r.opened_at DESC, r.recording_id DESC LIMIT ?4",
            )
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        let mut rows = statement
            .query(rusqlite::params![
                project_id.as_uuid().as_bytes().to_vec(),
                cursor_opened_at,
                after.map(|id| id.as_uuid().as_bytes().to_vec()),
                query_limit
            ])
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        let mut recordings = Vec::new();
        while let Some(row) = rows.next().map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })? {
            let raw_id: Vec<u8> = row.get(0).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let status: String = row.get(1).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let opened_at: String = row.get(2).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let segment_count: i64 = row.get(3).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let event_count: i64 = row.get(4).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let first_sequence: Option<Vec<u8>> = row.get(5).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let last_sequence: Option<Vec<u8>> = row.get(6).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let lifecycle_status = recording_status(&status, correlation_id)?;
            let incomplete_evidence = match lifecycle_status {
                RecordingStatus::Partial | RecordingStatus::Invalid => {
                    vec![format!("persisted_status:{status}")]
                }
                _ => Vec::new(),
            };
            recordings.push(RecordingMetadata {
                recording_id: recording_id_from_bytes(&raw_id, correlation_id)?,
                status: lifecycle_status,
                opened_at,
                segment_count: u64::try_from(segment_count)
                    .map_err(|_| recording_query_corrupt_error(correlation_id))?
                    .to_string(),
                event_count: u64::try_from(event_count)
                    .map_err(|_| recording_query_corrupt_error(correlation_id))?
                    .to_string(),
                first_sequence: first_sequence
                    .as_deref()
                    .map(|value| decode_stored_sequence(value, correlation_id))
                    .transpose()?
                    .map(|value| value.to_string()),
                last_sequence: last_sequence
                    .as_deref()
                    .map(|value| decode_stored_sequence(value, correlation_id))
                    .transpose()?
                    .map(|value| value.to_string()),
                incomplete_evidence,
            });
        }
        let has_more = recordings.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        if has_more {
            recordings.pop();
        }
        Ok((recordings, has_more))
    }

    /// Reads one bounded event window while fully verifying each decoded XTF object.
    ///
    /// Compressed and logical bytes are both counted toward the per-call
    /// verified-input budget. If the next segment would exceed the budget
    /// after events have been returned, it is left for the next cursor page.
    pub(crate) fn read_recording_window(
        &self,
        request: &ShowWindowRequest,
        source_root: Option<&Path>,
    ) -> Result<RecordingEventWindow, RecordingStoreError> {
        let correlation_id = CorrelationId::new();
        self.binding.revalidate(correlation_id)?;
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        let row: Option<(Vec<u8>, String)> = connection
            .query_row(
                "SELECT project_id, status FROM recordings WHERE recording_id = ?1",
                rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        let Some((raw_project_id, status)) = row else {
            return Err(read_not_found_error(correlation_id));
        };
        let stored_project_id = project_id_from_bytes(&raw_project_id, correlation_id)?;
        if stored_project_id != request.project_id {
            return Err(read_not_found_error(correlation_id));
        }
        let lifecycle_status = recording_status(&status, correlation_id)?;

        let mut statement = connection
            .prepare(
                "SELECT segment_ordinal, object_hash, first_recording_seq, last_recording_seq, \
                 event_count, uncompressed_bytes, compressed_bytes, checksum \
                 FROM recording_segments WHERE recording_id = ?1 ORDER BY segment_ordinal ASC",
            )
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        let mut rows = statement
            .query(rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()])
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        let mut expected_ordinal = 0_u32;
        let mut expected_sequence = Some(2_u64);
        let mut segment_count = 0_u64;
        let mut events = Vec::new();
        let event_limit = usize::try_from(request.limit)
            .map_err(|_| recording_query_validation_error(correlation_id))?;
        let mut has_more = false;
        let mut projection_bytes = 2_usize;
        let mut projection_byte_limit_reached = false;
        let mut verified_input_bytes = 0_usize;
        let mut verified_work_limit_reached = false;
        let mut incomplete_evidence = Vec::new();
        let mut source_cache = SourceProjectionCache::default();
        if status == "partial" || status == "invalid" {
            incomplete_evidence.push(format!("persisted_status:{status}"));
        }

        while let Some(row) = rows.next().map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })? {
            if segment_count >= MAX_RECORDING_QUERY_SEGMENTS {
                return Err(recording_query_resource_error(correlation_id));
            }
            let ordinal: i64 = row.get(0).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let object_hash: Vec<u8> = row.get(1).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let first: Vec<u8> = row.get(2).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let last: Vec<u8> = row.get(3).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let count: i64 = row.get(4).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let uncompressed_bytes: i64 = row.get(5).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let compressed_bytes: i64 = row.get(6).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let checksum: Vec<u8> = row.get(7).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| recording_query_corrupt_error(correlation_id))?;
            let first_sequence = decode_stored_sequence(&first, correlation_id)?;
            let last_sequence = decode_stored_sequence(&last, correlation_id)?;
            let count =
                u64::try_from(count).map_err(|_| recording_query_corrupt_error(correlation_id))?;
            let uncompressed_size = usize::try_from(uncompressed_bytes)
                .map_err(|_| recording_query_corrupt_error(correlation_id))?;
            if ordinal != expected_ordinal
                || Some(first_sequence) != expected_sequence
                || count == 0
                || uncompressed_size == 0
                || uncompressed_size > crate::max_logical_segment_bytes()
                || last_sequence < first_sequence
                || last_sequence - first_sequence != count - 1
            {
                return Err(recording_query_corrupt_error(correlation_id));
            }
            expected_ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| recording_query_corrupt_error(correlation_id))?;
            expected_sequence = last_sequence.checked_add(1);
            segment_count = segment_count
                .checked_add(1)
                .ok_or_else(|| recording_query_corrupt_error(correlation_id))?;

            let after_sequence = request.after_sequence.unwrap_or(0);
            if last_sequence <= after_sequence {
                continue;
            }
            if events.len() >= event_limit {
                has_more = true;
                continue;
            }
            if projection_byte_limit_reached {
                continue;
            }
            if verified_work_limit_reached {
                continue;
            }
            let segment = SegmentRow {
                object_hash,
                first_recording_seq: first,
                last_recording_seq: last,
                event_count: i64::try_from(count)
                    .map_err(|_| recording_query_corrupt_error(correlation_id))?,
                uncompressed_bytes,
                compressed_bytes,
                checksum,
            };
            segment.validate(correlation_id)?;
            let compressed_size = usize::try_from(segment.compressed_bytes)
                .map_err(|_| recording_query_corrupt_error(correlation_id))?;
            let segment_work = compressed_size
                .checked_add(uncompressed_size)
                .ok_or_else(|| recording_query_resource_error(correlation_id))?;
            let work_if_added = verified_input_bytes.checked_add(segment_work);
            if !events.is_empty()
                && work_if_added.is_none_or(|total| total > MAX_RECORDING_VERIFIED_INPUT_BYTES)
            {
                has_more = true;
                verified_work_limit_reached = true;
                continue;
            }
            let object_path =
                object_path_from_row(&self.binding.root, &segment.object_hash, correlation_id)?;
            validate_managed_tree(
                &self.binding.root,
                object_path.parent().ok_or_else(|| object_corrupt_error(correlation_id))?,
                correlation_id,
            )?;
            let bytes = read_bounded_regular_file(&object_path, correlation_id, false)?;
            if i64::try_from(bytes.len()).map_err(|_| object_corrupt_error(correlation_id))?
                != segment.compressed_bytes
            {
                return Err(object_corrupt_error(correlation_id));
            }
            let expected_hash = content_hash_from_bytes(&segment.object_hash, correlation_id)?;
            let decoded = crate::xtf::decode_compressed_segment(&bytes, expected_hash)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            let verified = decoded.verified();
            if verified.project_id() != stored_project_id
                || verified.recording_id() != request.recording_id
                || verified.segment_ordinal() != ordinal
                || verified.event_count() != count
                || verified.logical_bytes()
                    != u64::try_from(uncompressed_bytes)
                        .map_err(|_| recording_query_corrupt_error(correlation_id))?
                || verified.first_recording_seq() != first_sequence
                || verified.last_recording_seq() != last_sequence
                || verified.footer_prefix_digest().as_bytes() != segment.checksum.as_slice()
                || i64::try_from(bytes.len()).map_err(|_| object_corrupt_error(correlation_id))?
                    != segment.compressed_bytes
            {
                return Err(object_corrupt_error(correlation_id));
            }
            verified_input_bytes = work_if_added.unwrap_or(segment_work);
            for envelope in decoded.events() {
                let Some(event) = envelope.event.as_ref() else {
                    return Err(object_corrupt_error(correlation_id));
                };
                if event.recording_seq <= after_sequence {
                    continue;
                }
                if events.len() == event_limit {
                    has_more = true;
                    break;
                }
                if event.kind == 14 {
                    incomplete_evidence.push(format!("gap_event_sequence:{}", event.recording_seq));
                }
                let projected = project_persisted_event(event, source_root, &mut source_cache);
                let projected_size = projected
                    .serialized_size_with_separator()
                    .map_err(|_| recording_query_resource_error(correlation_id))?;
                if projected_size > MAX_RECORDING_EVENT_PROJECTION_BYTES {
                    return Err(recording_query_resource_error(correlation_id));
                }
                if projection_bytes
                    .checked_add(projected_size)
                    .is_none_or(|total| total > MAX_RECORDING_EVENT_PROJECTION_BYTES)
                {
                    has_more = true;
                    projection_byte_limit_reached = true;
                    break;
                }
                projection_bytes += projected_size;
                events.push(projected);
            }
        }
        Ok(RecordingEventWindow {
            recording_id: request.recording_id,
            status: lifecycle_status,
            segment_count: segment_count.to_string(),
            events,
            has_more,
            incomplete_evidence,
        })
    }

    /// Classifies one start observation and atomically inserts the recording,
    /// optional operation, and safe disposition sidecar, or proves a replay.
    ///
    /// The shared writer guard is acquired before root revalidation and all
    /// reads, so every store clone and recording view observes one local
    /// recording-write order. Endpoint fields are allowlisted before persistence;
    /// rejected input and its digest are never retained.
    ///
    /// # Errors
    ///
    /// Returns [`RecordingStoreErrorKind::NotFound`] when the project is
    /// unknown, `Conflict` when an immutable identity or retained disposition
    /// differs, and `Corruption` when operation keys disagree.
    pub fn begin_recording(
        &self,
        request: &BeginRecordingRequest,
    ) -> Result<BeginRecordingReceipt, RecordingStoreError> {
        let correlation_id = CorrelationId::new();
        let _writer = self
            .store
            .lock_recording_writer(correlation_id)
            .map_err(|error| map_store_error(error, correlation_id))?;
        self.binding.revalidate(correlation_id)?;
        let mut connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;

        let disposition = classify_observation(&request.endpoint_observation);
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
        if !project_exists(&transaction, request.project_id, correlation_id)? {
            return Err(RecordingStoreError::new(
                RecordingStoreErrorKind::NotFound,
                "XTR-STORE-RECORDING-PROJECT-NOT-FOUND",
                "recording project does not exist",
                correlation_id,
            ));
        }
        if let Some(existing) = load_recording(&transaction, request.recording_id, correlation_id)?
        {
            verify_existing_identity(&existing, request, correlation_id)?;
            let existing_observation = transaction.query_row(
                "SELECT disposition, observation_policy_id, operation_id, application_component, binding_key, method, route_template, reason_code, project_id \
                 FROM recording_endpoint_observations WHERE recording_id = ?1",
                rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<Vec<u8>>>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?, row.get::<_, Option<String>>(6)?, row.get::<_, Option<String>>(7)?, row.get::<_, Vec<u8>>(8)?)),
            ).optional().map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
            let Some(existing_observation) = existing_observation else {
                return Ok(BeginRecordingReceipt {
                    recording_id: request.recording_id,
                    disposition: BeginRecordingDisposition::LegacyObservationAbsent,
                });
            };
            validate_stored_observation(
                &transaction,
                request.project_id,
                &existing_observation,
                correlation_id,
            )?;
            if !observation_matches(&existing_observation, &disposition) {
                return Err(recording_conflict(
                    "recording observation conflicts with an existing recording",
                    correlation_id,
                ));
            }
            return Ok(BeginRecordingReceipt {
                recording_id: request.recording_id,
                disposition: BeginRecordingDisposition::ExactReplay,
            });
        }

        let operation_id = if disposition.reason_code.is_none() {
            Some(find_or_insert_operation(
                &transaction,
                request.project_id,
                &disposition,
                correlation_id,
            )?)
        } else {
            None
        };
        transaction.execute(
            "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) VALUES (?1, ?2, ?3, 'recording', ?4)",
            rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec(), request.project_id.as_uuid().as_bytes().to_vec(), request.runtime_session_id.as_uuid().as_bytes().to_vec(), request.opened_at.to_rfc3339()],
        ).map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
        transaction.execute(
            "INSERT INTO recording_endpoint_observations (recording_id, project_id, disposition, observation_policy_id, operation_id, application_component, binding_key, method, route_template, reason_code) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec(), request.project_id.as_uuid().as_bytes().to_vec(), if operation_id.is_some() { "linked" } else { "unmatched" }, disposition.policy_id, operation_id.map(|id| id.as_uuid().as_bytes().to_vec()), disposition.application_component, disposition.binding_key, disposition.method, disposition.route_template, disposition.reason_code],
        ).map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
        transaction.commit().map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })?;
        Ok(BeginRecordingReceipt {
            recording_id: request.recording_id,
            disposition: BeginRecordingDisposition::Inserted,
        })
    }

    /// Publishes one verified XTF object and its `recording_segments` metadata.
    ///
    /// This D-5 phase boundary persists only the immutable object and segment
    /// row. It does not write frame indexes, recording counters, an outbox,
    /// lifecycle transitions, or a Committed ACK.
    ///
    /// Officially tested configurations are local APFS on macOS and ext4 on
    /// Linux CI. It relies on `hard_link` no-replace publication and directory
    /// synchronization; it makes no Windows, network, or other-filesystem
    /// durability claim.
    ///
    /// # Errors
    ///
    /// Returns a scoped error without creating a segment row when validation,
    /// continuity, verification, publication, or the SQLite transaction fails.
    pub fn commit_segment(
        &self,
        request: &SegmentCommitRequest,
    ) -> Result<SegmentCommitReceipt, RecordingStoreError> {
        reset_staging_write_observer();
        let correlation_id = CorrelationId::new();
        let _writer = self
            .store
            .lock_recording_writer(correlation_id)
            .map_err(|error| map_store_error(error, correlation_id))?;
        self.binding.revalidate(correlation_id)?;
        let logical = encode_logical_segment(&XtfSegmentInput {
            project_id: request.project_id,
            recording_id: request.recording_id,
            segment_ordinal: request.segment_ordinal,
            events: request.events.clone(),
        })
        .map_err(|error| map_xtf_error(error, correlation_id))?;
        let mut candidate = SegmentMetadata::from_logical(&logical, request, correlation_id)?;

        let existing = {
            let connection =
                self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
            validate_recording_anchor(&connection, request, correlation_id)?;
            if let Some(existing) = load_segment_row(
                &connection,
                request.recording_id,
                request.segment_ordinal,
                correlation_id,
            )? {
                Some(existing)
            } else {
                validate_new_continuity(&connection, request, &candidate, correlation_id)?;
                None
            }
        };
        if let Some(existing) = existing {
            return self.exact_or_conflict(&existing, &candidate, correlation_id);
        }

        self.binding.revalidate(correlation_id)?;
        let mut staging =
            create_staging_files(&self.binding, request.recording_id, correlation_id)?;
        commit_failpoint("before-logical-write", correlation_id, false)?;
        validate_managed_tree(&self.binding.root, &staging.directory, correlation_id)?;
        validate_managed_file(&staging.logical, correlation_id, true)?;
        write_synced_file(&staging.logical, logical.logical_bytes(), correlation_id)?;
        sync_directory(&staging.directory, correlation_id, "XTR-STORE-OBJECT-IO")?;
        commit_failpoint("after-logical-sync", correlation_id, false)?;
        self.binding.revalidate(correlation_id)?;
        commit_failpoint("before-compression", correlation_id, false)?;
        let compressed = compress_logical_bytes(logical.logical_bytes())
            .map_err(|error| map_xtf_error(error, correlation_id))?;
        commit_failpoint("after-compression-before-write", correlation_id, false)?;
        candidate.compressed_bytes = i64::try_from(compressed.len())
            .map_err(|_| segment_validation_error(correlation_id))?;
        validate_managed_tree(&self.binding.root, &staging.directory, correlation_id)?;
        validate_managed_file(&staging.compressed, correlation_id, true)?;
        write_synced_file(&staging.compressed, &compressed, correlation_id)?;
        sync_directory(&staging.directory, correlation_id, "XTR-STORE-OBJECT-IO")?;
        commit_failpoint("after-compressed-sync", correlation_id, false)?;

        validate_managed_tree(&self.binding.root, &staging.directory, correlation_id)?;
        let staged = read_bounded_regular_file(&staging.compressed, correlation_id, true)?;
        verify_staged_object(&staged, &candidate, correlation_id)?;
        self.binding.revalidate(correlation_id)?;
        let destination = object_path(&self.binding.root, candidate.object_hash);
        ensure_object_parent(&self.binding, &destination, correlation_id)?;
        self.binding.revalidate(correlation_id)?;
        commit_failpoint("before-hard-link", correlation_id, true)?;
        validate_managed_tree(&self.binding.root, &staging.directory, correlation_id)?;
        validate_managed_file(&staging.compressed, correlation_id, false)?;
        validate_managed_directory(
            destination.parent().ok_or_else(|| atomic_install_error(correlation_id))?,
            correlation_id,
        )?;
        let compressed_staging = staging.compressed.clone();
        candidate.compressed_bytes = publish_no_replace(
            &compressed_staging,
            &destination,
            &candidate,
            correlation_id,
            || staging.defer_cleanup_until_authoritative(),
        )?;
        note_successful_hard_link();
        commit_failpoint("after-hard-link", correlation_id, true)?;
        commit_failpoint("before-destination-object-directory-fsync", correlation_id, true)?;
        sync_directory(
            destination.parent().ok_or_else(|| atomic_install_error(correlation_id))?,
            correlation_id,
            "XTR-STORE-ATOMIC-INSTALL",
        )?;
        commit_failpoint("after-object-directory-sync", correlation_id, true)?;

        let outcome = {
            commit_failpoint("before-transaction", correlation_id, false)?;
            let connection =
                self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
            let transaction = connection.unchecked_transaction().map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?;
            let inserted = transaction.execute(
                "INSERT INTO recording_segments \
                 (recording_id, segment_ordinal, object_hash, first_recording_seq, \
                  last_recording_seq, event_count, uncompressed_bytes, compressed_bytes, checksum) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    request.recording_id.as_uuid().as_bytes().to_vec(),
                    i64::from(request.segment_ordinal),
                    candidate.object_hash.as_bytes().to_vec(),
                    candidate.first_recording_seq.to_be_bytes().to_vec(),
                    candidate.last_recording_seq.to_be_bytes().to_vec(),
                    candidate.event_count,
                    candidate.uncompressed_bytes,
                    candidate.compressed_bytes,
                    candidate.checksum.as_bytes().to_vec(),
                ],
            );
            match inserted {
                Ok(_) => {
                    commit_failpoint("before-transaction-commit", correlation_id, false)?;
                    transaction.commit().map_err(|error| {
                        map_store_error(
                            StoreError::from_rusqlite(error, correlation_id),
                            correlation_id,
                        )
                    })?;
                    Ok(None)
                }
                Err(error) => {
                    let mapped = StoreError::from_rusqlite(error, correlation_id);
                    transaction.rollback().map_err(|rollback| {
                        map_store_error(
                            StoreError::from_rusqlite(rollback, correlation_id),
                            correlation_id,
                        )
                    })?;
                    if matches!(mapped.kind(), StoreErrorKind::AlreadyExists) {
                        let existing = load_segment_row(
                            &connection,
                            request.recording_id,
                            request.segment_ordinal,
                            correlation_id,
                        )?
                        .ok_or_else(|| segment_conflict_error(correlation_id))?;
                        Ok(Some(existing))
                    } else {
                        Err(map_store_error(mapped, correlation_id))
                    }
                }
            }
        }?;
        if let Some(existing) = outcome {
            let receipt = self.exact_or_conflict(&existing, &candidate, correlation_id)?;
            staging.enable_cleanup_after_authority();
            return Ok(receipt);
        }
        staging.enable_cleanup_after_authority();
        if commit_failpoint("after-commit-before-cleanup", correlation_id, false).is_err() {
            tracing::warn!("recording segment committed; staging cleanup left safe residue");
            staging.preserve_residue();
            return Ok(SegmentCommitReceipt {
                recording_id: request.recording_id,
                segment_ordinal: request.segment_ordinal,
                object_hash: candidate.object_hash,
                uncompressed_bytes: u64::try_from(candidate.uncompressed_bytes)
                    .map_err(|_| segment_validation_error(correlation_id))?,
                compressed_bytes: u64::try_from(candidate.compressed_bytes)
                    .map_err(|_| segment_validation_error(correlation_id))?,
                disposition: SegmentCommitDisposition::Inserted,
            });
        }
        Ok(SegmentCommitReceipt {
            recording_id: request.recording_id,
            segment_ordinal: request.segment_ordinal,
            object_hash: candidate.object_hash,
            uncompressed_bytes: u64::try_from(candidate.uncompressed_bytes)
                .map_err(|_| segment_validation_error(correlation_id))?,
            compressed_bytes: u64::try_from(candidate.compressed_bytes)
                .map_err(|_| segment_validation_error(correlation_id))?,
            disposition: SegmentCommitDisposition::Inserted,
        })
    }

    fn exact_or_conflict(
        &self,
        existing: &SegmentRow,
        candidate: &SegmentMetadata,
        correlation_id: CorrelationId,
    ) -> Result<SegmentCommitReceipt, RecordingStoreError> {
        existing.validate(correlation_id)?;
        if !existing.matches(candidate) {
            return Err(segment_conflict_error(correlation_id));
        }
        pause_replay_verification(candidate.recording_id, candidate.segment_ordinal);
        self.binding.revalidate(correlation_id)?;
        let object_path =
            object_path_from_row(&self.binding.root, &existing.object_hash, correlation_id)?;
        validate_managed_tree(
            &self.binding.root,
            object_path.parent().ok_or_else(|| object_corrupt_error(correlation_id))?,
            correlation_id,
        )?;
        let bytes = read_bounded_regular_file(&object_path, correlation_id, false)?;
        let compressed_bytes = verify_existing_object(&bytes, existing, candidate, correlation_id)?;
        Ok(SegmentCommitReceipt {
            recording_id: candidate.recording_id,
            segment_ordinal: candidate.segment_ordinal,
            object_hash: candidate.object_hash,
            uncompressed_bytes: u64::try_from(existing.uncompressed_bytes)
                .map_err(|_| segment_validation_error(correlation_id))?,
            compressed_bytes: u64::try_from(compressed_bytes)
                .map_err(|_| segment_validation_error(correlation_id))?,
            disposition: SegmentCommitDisposition::ExactReplay,
        })
    }
}

#[derive(Clone, Debug)]
struct SegmentMetadata {
    project_id: ProjectId,
    recording_id: RecordingId,
    segment_ordinal: u32,
    object_hash: ContentHash,
    checksum: ContentHash,
    first_recording_seq: u64,
    last_recording_seq: u64,
    event_count: i64,
    uncompressed_bytes: i64,
    compressed_bytes: i64,
}

impl SegmentMetadata {
    fn from_logical(
        logical: &LogicalXtfSegment,
        request: &SegmentCommitRequest,
        correlation_id: CorrelationId,
    ) -> Result<Self, RecordingStoreError> {
        let event_count = i64::try_from(logical.event_count())
            .map_err(|_| segment_validation_error(correlation_id))?;
        let uncompressed_bytes = i64::try_from(logical.logical_bytes().len())
            .map_err(|_| segment_validation_error(correlation_id))?;
        if event_count <= 0 || uncompressed_bytes <= 0 {
            return Err(segment_validation_error(correlation_id));
        }
        Ok(Self {
            project_id: request.project_id,
            recording_id: request.recording_id,
            segment_ordinal: request.segment_ordinal,
            object_hash: logical.content_hash(),
            checksum: logical.footer_prefix_digest(),
            first_recording_seq: logical.first_recording_seq(),
            last_recording_seq: logical.last_recording_seq(),
            event_count,
            uncompressed_bytes,
            compressed_bytes: 0,
        })
    }
}

#[derive(Debug)]
struct SegmentRow {
    object_hash: Vec<u8>,
    first_recording_seq: Vec<u8>,
    last_recording_seq: Vec<u8>,
    event_count: i64,
    uncompressed_bytes: i64,
    compressed_bytes: i64,
    checksum: Vec<u8>,
}

impl SegmentRow {
    fn validate(&self, correlation_id: CorrelationId) -> Result<(), RecordingStoreError> {
        if self.object_hash.len() != 32
            || self.checksum.len() != 32
            || self.event_count <= 0
            || self.uncompressed_bytes <= 0
        {
            return Err(object_corrupt_error(correlation_id));
        }
        if decode_stored_sequence(&self.first_recording_seq, correlation_id)?
            > decode_stored_sequence(&self.last_recording_seq, correlation_id)?
        {
            return Err(object_corrupt_error(correlation_id));
        }
        Ok(())
    }

    fn matches(&self, candidate: &SegmentMetadata) -> bool {
        self.object_hash == candidate.object_hash.as_bytes()
            && self.first_recording_seq == candidate.first_recording_seq.to_be_bytes()
            && self.last_recording_seq == candidate.last_recording_seq.to_be_bytes()
            && self.event_count == candidate.event_count
            && self.uncompressed_bytes == candidate.uncompressed_bytes
            && self.checksum == candidate.checksum.as_bytes()
    }
}

#[derive(Debug)]
struct StagingFiles {
    directory: PathBuf,
    logical: PathBuf,
    compressed: PathBuf,
    cleanup_on_drop: bool,
}

impl StagingFiles {
    fn defer_cleanup_until_authoritative(&mut self) {
        self.cleanup_on_drop = false;
    }

    fn enable_cleanup_after_authority(&mut self) {
        self.cleanup_on_drop = true;
    }

    fn preserve_residue(&mut self) {
        self.cleanup_on_drop = false;
    }
}

impl Drop for StagingFiles {
    fn drop(&mut self) {
        // Cleanup is allowed before publication or after SQLite establishes an
        // authoritative row. A published staging link is retained otherwise.
        if self.cleanup_on_drop {
            cleanup_owned_staging_paths(self, CorrelationId::new());
        }
    }
}

fn validate_recording_anchor(
    connection: &rusqlite::Connection,
    request: &SegmentCommitRequest,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let project_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT project_id FROM recordings WHERE recording_id = ?1",
            rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })?;
    let Some(project_id) = project_id else {
        return Err(segment_validation_error(correlation_id));
    };
    if project_id.len() != 16 || project_id != request.project_id.as_uuid().as_bytes() {
        return Err(segment_validation_error(correlation_id));
    }
    Ok(())
}

fn load_segment_row(
    connection: &rusqlite::Connection,
    recording_id: RecordingId,
    segment_ordinal: u32,
    correlation_id: CorrelationId,
) -> Result<Option<SegmentRow>, RecordingStoreError> {
    connection
        .query_row(
            "SELECT object_hash, first_recording_seq, last_recording_seq, event_count, \
             uncompressed_bytes, compressed_bytes, checksum FROM recording_segments \
             WHERE recording_id = ?1 AND segment_ordinal = ?2",
            rusqlite::params![
                recording_id.as_uuid().as_bytes().to_vec(),
                i64::from(segment_ordinal)
            ],
            |row| {
                Ok(SegmentRow {
                    object_hash: row.get(0)?,
                    first_recording_seq: row.get(1)?,
                    last_recording_seq: row.get(2)?,
                    event_count: row.get(3)?,
                    uncompressed_bytes: row.get(4)?,
                    compressed_bytes: row.get(5)?,
                    checksum: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })
}

fn validate_new_continuity(
    connection: &rusqlite::Connection,
    request: &SegmentCommitRequest,
    candidate: &SegmentMetadata,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let previous: Option<(i64, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT segment_ordinal, first_recording_seq, last_recording_seq \
             FROM recording_segments WHERE recording_id = ?1 \
             ORDER BY segment_ordinal DESC LIMIT 1",
            rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })?;
    let Some((ordinal, first, last)) = previous else {
        if request.segment_ordinal != 0 || candidate.first_recording_seq != 2 {
            return Err(segment_continuity_error(correlation_id));
        }
        return Ok(());
    };
    let previous_ordinal =
        u32::try_from(ordinal).map_err(|_| segment_continuity_error(correlation_id))?;
    let previous_first = decode_sequence(&first, correlation_id)?;
    let previous_last = decode_sequence(&last, correlation_id)?;
    if previous_first > previous_last {
        return Err(segment_continuity_error(correlation_id));
    }
    let expected_ordinal =
        previous_ordinal.checked_add(1).ok_or_else(|| segment_continuity_error(correlation_id))?;
    let expected_first =
        previous_last.checked_add(1).ok_or_else(|| segment_continuity_error(correlation_id))?;
    if request.segment_ordinal != expected_ordinal
        || candidate.first_recording_seq != expected_first
    {
        return Err(segment_continuity_error(correlation_id));
    }
    Ok(())
}

fn decode_sequence(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<u64, RecordingStoreError> {
    let raw: [u8; 8] = bytes.try_into().map_err(|_| object_corrupt_error(correlation_id))?;
    Ok(u64::from_be_bytes(raw))
}

fn decode_stored_sequence(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<u64, RecordingStoreError> {
    let raw: [u8; 8] = bytes.try_into().map_err(|_| object_corrupt_error(correlation_id))?;
    Ok(u64::from_be_bytes(raw))
}

const MAX_RECORDING_QUERY_SEGMENTS: u64 = 10_000;

fn recording_id_from_bytes(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<RecordingId, RecordingStoreError> {
    let raw: [u8; 16] =
        bytes.try_into().map_err(|_| recording_query_corrupt_error(correlation_id))?;
    Ok(RecordingId::from_uuid(uuid::Uuid::from_bytes(raw)))
}

fn observed_recording_id_from_bytes(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<RecordingId, RecordingStoreError> {
    let recording_id = recording_id_from_bytes(bytes, correlation_id)?;
    let uuid = recording_id.as_uuid();
    if !matches!(uuid.get_version_num(), 4 | 7) || uuid.get_variant() != uuid::Variant::RFC4122 {
        return Err(recording_query_corrupt_error(correlation_id));
    }
    Ok(recording_id)
}

fn project_id_from_bytes(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<ProjectId, RecordingStoreError> {
    let raw: [u8; 16] =
        bytes.try_into().map_err(|_| recording_query_corrupt_error(correlation_id))?;
    Ok(ProjectId::from_uuid(uuid::Uuid::from_bytes(raw)))
}

fn content_hash_from_bytes(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<ContentHash, RecordingStoreError> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| object_corrupt_error(correlation_id))?;
    ContentHash::from_str(&format!("b3:{}", hex::encode(raw)))
        .map_err(|_| object_corrupt_error(correlation_id))
}

fn recording_status(
    status: &str,
    correlation_id: CorrelationId,
) -> Result<RecordingStatus, RecordingStoreError> {
    match status {
        "recording" => Ok(RecordingStatus::Recording),
        "finalizing" => Ok(RecordingStatus::Finalizing),
        "complete" => Ok(RecordingStatus::Complete),
        "partial" => Ok(RecordingStatus::Partial),
        "invalid" => Ok(RecordingStatus::Invalid),
        _ => Err(recording_query_corrupt_error(correlation_id)),
    }
}

fn project_persisted_event(
    event: &xtrace_protocol::generated::agent::RecordingEvent,
    source_root: Option<&Path>,
    source_cache: &mut SourceProjectionCache,
) -> PersistedEvent {
    use xtrace_protocol::generated::agent::SourceBinding as WireSourceBinding;

    let interaction = event.interaction.as_ref().map(|interaction| PersistedInteraction {
        kind: Some(interaction_kind_label(interaction.kind)),
        driver: nonempty(&interaction.driver),
        schema: nonempty(&interaction.schema),
        table: nonempty(&interaction.table),
        host: nonempty(&interaction.host),
        method: nonempty(&interaction.method),
    });
    let source_binding = WireSourceBinding::try_from(event.source_binding).ok().map_or(
        SourceBinding::Unspecified,
        |binding| match binding {
            WireSourceBinding::Verified => SourceBinding::Verified,
            WireSourceBinding::AttestationMissing => SourceBinding::AttestationMissing,
            WireSourceBinding::ClassBytesMismatch => SourceBinding::ClassBytesMismatch,
            WireSourceBinding::DebugMetadataAbsent => SourceBinding::DebugMetadataAbsent,
            WireSourceBinding::SourceMetadataInvalid => SourceBinding::SourceMetadataInvalid,
            WireSourceBinding::Unspecified => SourceBinding::Unspecified,
        },
    );
    let source = if source_binding.is_verified() {
        event
            .source
            .as_ref()
            .and_then(source_range_from_wire)
            .and_then(|source| project_source(&source, source_root, source_cache))
    } else {
        None
    };
    let mut projected = PersistedEvent {
        sequence: event.recording_seq.to_string(),
        monotonic_ns: event.monotonic_ns.to_string(),
        event_id: nonempty(&event.event_id),
        parent_event_id: nonempty(&event.parent_event_id),
        async_parent_event_id: nonempty(&event.async_parent_event_id),
        kind: recording_event_kind_label(event.kind),
        symbol: nonempty(&event.symbol),
        interaction,
        source,
        source_binding,
        field_truncations: Vec::new(),
    };
    projected.bound_display_fields();
    projected
}

fn source_range_from_wire(
    wire: &xtrace_protocol::generated::agent::SourceRange,
) -> Option<SourceRange> {
    Some(SourceRange {
        path: wire.path.clone(),
        start_line: (wire.start_line > 0).then_some(wire.start_line),
        start_column: (wire.start_column > 0).then_some(wire.start_column),
        end_line: (wire.end_line > 0).then_some(wire.end_line),
        end_column: (wire.end_column > 0).then_some(wire.end_column),
        content_hash: ContentHash::from_digest_bytes(&wire.content_hash),
    })
}

const MAX_SOURCE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SOURCE_EXCERPT_BYTES: usize = 16 * 1024;
const MAX_SOURCE_EXCERPT_LINES: u32 = 64;

#[derive(Default)]
struct SourceProjectionCache {
    snapshots: HashMap<String, SourceSnapshot>,
    reads: usize,
}

enum SourceSnapshot {
    Unavailable,
    Loaded { hash: ContentHash, text: Option<String> },
}

fn project_source(
    source: &SourceRange,
    source_root: Option<&Path>,
    cache: &mut SourceProjectionCache,
) -> Option<PersistedSource> {
    let start_line = source.start_line?;
    let path = source.path.as_str();
    let safe = [
        "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/OrderController.java",
        "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/OrderService.java",
        "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/OrderRepository.java",
    ];
    if start_line == 0 || !safe.contains(&path) || source.content_hash.is_none() {
        return None;
    }
    let end_line = source.end_line.filter(|end| *end >= start_line);
    let Some(root) = source_root else {
        return Some(PersistedSource {
            path: path.to_owned(),
            start_line,
            end_line,
            status: SourceStatus::Unavailable,
            excerpt: None,
            truncated: false,
        });
    };
    if !cache.snapshots.contains_key(path) {
        cache.reads += 1;
        cache.snapshots.insert(path.to_owned(), load_source_snapshot(root, path));
    }
    let snapshot = cache.snapshots.get(path)?;
    let SourceSnapshot::Loaded { hash, text } = snapshot else {
        return unavailable_source(path, start_line, end_line);
    };
    let recorded_hash = source.content_hash.as_ref()?;
    if hash != recorded_hash {
        return Some(PersistedSource {
            path: path.to_owned(),
            start_line,
            end_line,
            status: SourceStatus::Mismatch,
            excerpt: None,
            truncated: false,
        });
    }
    let Some(text) = text.as_deref() else {
        return unavailable_source(path, start_line, end_line);
    };
    project_matching_source(path, start_line, end_line, text)
}

fn load_source_snapshot(root: &Path, path: &str) -> SourceSnapshot {
    let Ok(root) = root.canonicalize() else {
        return SourceSnapshot::Unavailable;
    };
    let relative = Path::new(path);
    let Ok(root_metadata) = std::fs::symlink_metadata(&root) else {
        return SourceSnapshot::Unavailable;
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return SourceSnapshot::Unavailable;
    }
    let Ok(mut directory) = std::fs::File::open(&root) else {
        return SourceSnapshot::Unavailable;
    };
    let Ok(opened_root) = directory.metadata() else {
        return SourceSnapshot::Unavailable;
    };
    #[cfg(unix)]
    if root_metadata.dev() != opened_root.dev() || root_metadata.ino() != opened_root.ino() {
        return SourceSnapshot::Unavailable;
    }
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            return SourceSnapshot::Unavailable;
        };
        let final_component = index + 1 == components.len();
        let flags = if final_component {
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC
        } else {
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
        };
        let Ok(opened) = rustix::fs::openat(&directory, *part, flags, rustix::fs::Mode::empty())
        else {
            return SourceSnapshot::Unavailable;
        };
        let file = std::fs::File::from(opened);
        if final_component {
            let Ok(metadata) = file.metadata() else {
                return SourceSnapshot::Unavailable;
            };
            if !metadata.is_file() || metadata.len() > MAX_SOURCE_FILE_BYTES {
                return SourceSnapshot::Unavailable;
            }
            let mut reader = file.take(MAX_SOURCE_FILE_BYTES + 1);
            let capacity = usize::try_from(metadata.len()).unwrap_or(0);
            let mut bytes = Vec::with_capacity(capacity);
            if reader.read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_SOURCE_FILE_BYTES
            {
                return SourceSnapshot::Unavailable;
            }
            return SourceSnapshot::Loaded {
                hash: ContentHash::of_bytes(&bytes),
                text: std::str::from_utf8(&bytes).ok().map(str::to_owned),
            };
        }
        if file.metadata().is_err() {
            return SourceSnapshot::Unavailable;
        }
        directory = file;
    }
    SourceSnapshot::Unavailable
}

fn project_matching_source(
    path: &str,
    start_line: u32,
    end_line: Option<u32>,
    text: &str,
) -> Option<PersistedSource> {
    let mut excerpt = String::new();
    let mut truncated = false;
    let mut found = false;
    let upper =
        end_line.unwrap_or(start_line).min(start_line.saturating_add(MAX_SOURCE_EXCERPT_LINES - 1));
    for (index, line) in text.lines().enumerate() {
        let Ok(number) = u32::try_from(index + 1) else {
            truncated = true;
            break;
        };
        if number < start_line {
            continue;
        }
        if number > upper {
            truncated = end_line.is_some_and(|end| end > upper);
            break;
        }
        found = true;
        let separator_bytes = usize::from(!excerpt.is_empty());
        if excerpt.len().saturating_add(separator_bytes) > MAX_SOURCE_EXCERPT_BYTES {
            truncated = true;
            break;
        }
        let remaining =
            MAX_SOURCE_EXCERPT_BYTES.saturating_sub(excerpt.len().saturating_add(separator_bytes));
        if separator_bytes != 0 {
            excerpt.push('\n');
        }
        if line.len() > remaining {
            let mut boundary = remaining.min(line.len());
            while !line.is_char_boundary(boundary) {
                boundary -= 1;
            }
            excerpt.push_str(&line[..boundary]);
            truncated = true;
            break;
        }
        excerpt.push_str(line);
    }
    if !found {
        return unavailable_source(path, start_line, end_line);
    }
    Some(PersistedSource {
        path: path.to_owned(),
        start_line,
        end_line,
        status: SourceStatus::Matched,
        excerpt: Some(excerpt),
        truncated,
    })
}

fn unavailable_source(
    path: &str,
    start_line: u32,
    end_line: Option<u32>,
) -> Option<PersistedSource> {
    Some(PersistedSource {
        path: path.to_owned(),
        start_line,
        end_line,
        status: SourceStatus::Unavailable,
        excerpt: None,
        truncated: false,
    })
}

#[cfg(test)]
mod source_projection_tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        tempfile::Builder::new()
            .prefix("xtrace-source-projection-")
            .tempdir_in(scratch)
            .expect("private source projection test directory")
    }

    const PATH: &str =
        "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/OrderService.java";

    fn range(path: &str, hash: ContentHash) -> SourceRange {
        SourceRange {
            path: path.to_owned(),
            start_line: Some(2),
            start_column: None,
            end_line: Some(3),
            end_column: None,
            content_hash: Some(hash),
        }
    }

    fn write_source(root: &Path, bytes: &[u8]) {
        let file = root.join(PATH);
        std::fs::create_dir_all(file.parent().expect("parent exists")).expect("directory created");
        std::fs::write(file, bytes).expect("source written");
    }

    fn project(source: &SourceRange, source_root: Option<&Path>) -> Option<PersistedSource> {
        project_source(source, source_root, &mut SourceProjectionCache::default())
    }

    #[test]
    fn matching_source_returns_only_the_bounded_recorded_extent() {
        let root = tempdir().expect("temporary root");
        let bytes = b"one\ntwo\nthree\nfour\n";
        write_source(root.path(), bytes);
        let projected = project(&range(PATH, ContentHash::of_bytes(bytes)), Some(root.path()))
            .expect("source projection");
        assert_eq!(projected.status, SourceStatus::Matched);
        assert_eq!(projected.excerpt.as_deref(), Some("two\nthree"));
    }

    #[test]
    fn changed_source_is_reported_without_returning_its_contents() {
        let root = tempdir().expect("temporary root");
        write_source(root.path(), b"private-source-canary\nchanged\n");
        let projected =
            project(&range(PATH, ContentHash::of_bytes(b"recorded\nsource\n")), Some(root.path()))
                .expect("source projection");
        assert_eq!(projected.status, SourceStatus::Mismatch);
        assert!(projected.excerpt.is_none());
    }

    #[test]
    fn repeated_frames_hash_near_limit_source_once_per_query() {
        let root = tempdir().expect("temporary root");
        let max_bytes = usize::try_from(MAX_SOURCE_FILE_BYTES).expect("bound fits");
        let mut bytes = b"header\nrecorded line\n".to_vec();
        bytes.resize(max_bytes - 1, b'x');
        bytes.push(b'\n');
        write_source(root.path(), &bytes);
        let mut source = range(PATH, ContentHash::of_bytes(&bytes));
        source.end_line = Some(2);
        let mut cache = SourceProjectionCache::default();

        for _ in 0..1_000 {
            let projected =
                project_source(&source, Some(root.path()), &mut cache).expect("source projection");
            assert_eq!(projected.status, SourceStatus::Matched);
            assert_eq!(projected.excerpt.as_deref(), Some("recorded line"));
        }
        assert_eq!(cache.reads, 1, "repeated frames must share one bounded file read/hash");

        let changed = b"private-source-canary\nchanged\n";
        write_source(root.path(), changed);
        let mut next_query_cache = SourceProjectionCache::default();
        let next_query = project_source(&source, Some(root.path()), &mut next_query_cache)
            .expect("safe mismatch projection");
        assert_eq!(next_query.status, SourceStatus::Mismatch);
        assert!(next_query.excerpt.is_none());
        assert_eq!(next_query_cache.reads, 1, "a new query must observe live source changes");
    }

    #[test]
    fn source_paths_outside_the_fixture_allowlist_are_never_projected() {
        let root = tempdir().expect("temporary root");
        let projected =
            project(&range("../../private.txt", ContentHash::of_bytes(b"x")), Some(root.path()));
        assert!(projected.is_none());
    }

    #[test]
    fn source_files_over_the_read_bound_are_unavailable() {
        let root = tempdir().expect("temporary root");
        write_source(
            root.path(),
            &vec![b'x'; usize::try_from(MAX_SOURCE_FILE_BYTES + 1).expect("bound fits")],
        );
        let projected = project(&range(PATH, ContentHash::of_bytes(b"unused")), Some(root.path()))
            .expect("safe unavailable projection");
        assert_eq!(projected.status, SourceStatus::Unavailable);
        assert!(projected.excerpt.is_none());
    }

    #[test]
    fn missing_source_root_and_out_of_range_method_lines_are_unavailable() {
        let root = tempdir().expect("temporary root");
        let bytes = b"one\ntwo\n";
        write_source(root.path(), bytes);
        let no_root = project(&range(PATH, ContentHash::of_bytes(bytes)), None)
            .expect("unavailable projection");
        assert_eq!(no_root.status, SourceStatus::Unavailable);
        let mut out_of_range = range(PATH, ContentHash::of_bytes(bytes));
        out_of_range.start_line = Some(20);
        out_of_range.end_line = Some(20);
        let projected =
            project(&out_of_range, Some(root.path())).expect("safe unavailable projection");
        assert_eq!(projected.status, SourceStatus::Unavailable);
        assert!(projected.excerpt.is_none());
    }

    #[test]
    fn excerpt_limit_includes_inter_line_separator_bytes() {
        let root = tempdir().expect("temporary root");
        let first = "a".repeat(MAX_SOURCE_EXCERPT_BYTES);
        let contents = format!("header\n{first}\nnext\n");
        write_source(root.path(), contents.as_bytes());
        let projected =
            project(&range(PATH, ContentHash::of_bytes(contents.as_bytes())), Some(root.path()))
                .expect("source projection");
        let excerpt = projected.excerpt.expect("matched excerpt");
        assert_eq!(excerpt.len(), MAX_SOURCE_EXCERPT_BYTES);
        assert!(projected.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_file_is_not_read() {
        use std::os::unix::fs::symlink;

        let root = tempdir().expect("temporary root");
        let file = root.path().join(PATH);
        std::fs::create_dir_all(file.parent().expect("parent exists")).expect("directory created");
        let private = root.path().join("private-source-canary.txt");
        std::fs::write(&private, b"private-source-canary").expect("private file written");
        symlink(&private, &file).expect("source symlink created");
        let projected = project(
            &range(PATH, ContentHash::of_bytes(b"private-source-canary")),
            Some(root.path()),
        )
        .expect("unavailable projection");
        assert_eq!(projected.status, SourceStatus::Unavailable);
        assert!(projected.excerpt.is_none());
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn recording_event_kind_label(value: i32) -> String {
    const NAMES: &[&str] = &[
        "unspecified",
        "request_update",
        "frame_enter",
        "frame_exit",
        "frame_throw",
        "line_cursor",
        "value_snapshot",
        "database_start",
        "database_end",
        "outbound_http_start",
        "outbound_http_end",
        "async_link",
        "exception",
        "response",
        "gap",
    ];
    enum_label("recording_event_kind", value, NAMES)
}

fn interaction_kind_label(value: i32) -> String {
    const NAMES: &[&str] =
        &["unspecified", "database", "outbound_http", "messaging", "filesystem", "framework"];
    enum_label("interaction_kind", value, NAMES)
}

fn enum_label(prefix: &str, value: i32, names: &[&str]) -> String {
    usize::try_from(value)
        .ok()
        .and_then(|index| names.get(index))
        .map_or_else(|| format!("unknown:{value}"), |name| format!("{prefix}:{name}"))
}

fn read_not_found_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::NotFound,
        "XTR-STORE-RECORDING-NOT-FOUND",
        "recording was not found in the selected project",
        correlation_id,
    )
}

fn recording_query_validation_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Validation,
        "XTR-STORE-RECORDING-QUERY-VALIDATION",
        "recording query arguments are outside supported bounds",
        correlation_id,
    )
}

fn recording_query_corrupt_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Corruption,
        "XTR-STORE-RECORDING-QUERY-CORRUPT",
        "persisted recording metadata is inconsistent",
        correlation_id,
    )
}

fn recording_query_resource_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Resource,
        "XTR-STORE-RECORDING-QUERY-RESOURCE",
        "recording read exceeds its bounded segment or projection budget",
        correlation_id,
    )
}

fn segment_validation_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Validation,
        "XTR-STORE-SEGMENT-VALIDATION",
        "segment request is invalid for the recording anchor",
        correlation_id,
    )
}

fn segment_conflict_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Conflict,
        "XTR-STORE-SEGMENT-CONFLICT",
        "segment conflicts with immutable stored metadata",
        correlation_id,
    )
}

fn segment_continuity_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Conflict,
        "XTR-STORE-SEGMENT-CONTINUITY",
        "segment does not continue the recording sequence",
        correlation_id,
    )
}

fn atomic_install_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Compatibility,
        "XTR-STORE-ATOMIC-INSTALL",
        "atomic object installation could not be completed",
        correlation_id,
    )
}

fn map_xtf_error(error: XtfCodecError, correlation_id: CorrelationId) -> RecordingStoreError {
    match error {
        XtfCodecError::EmptyEvents
        | XtfCodecError::EventLimitExceeded
        | XtfCodecError::MissingEvent
        | XtfCodecError::SequenceMismatch
        | XtfCodecError::NonContiguousSequence
        | XtfCodecError::SequenceOverflow
        | XtfCodecError::LengthLimitExceeded => segment_validation_error(correlation_id),
        _ => xtf_verify_error(correlation_id).with_source("XTF codec failure"),
    }
}

#[cfg(unix)]
fn create_staging_files(
    binding: &ProjectRootBinding,
    recording_id: RecordingId,
    correlation_id: CorrelationId,
) -> Result<StagingFiles, RecordingStoreError> {
    binding.revalidate(correlation_id)?;
    let root =
        AdmittedPrivateRoot::open(&binding.root).map_err(|_| object_io_error(correlation_id))?;
    let staging_root = root
        .open_or_create_private_child("staging")
        .map_err(|_| object_io_error(correlation_id))?;
    let recording_directory = staging_root
        .open_or_create_private_child(&recording_id.as_uuid().to_string())
        .map_err(|_| object_io_error(correlation_id))?;
    // UUIDv7 supplies entropy for collision resistance while preserving no caller
    // material in the staging path.
    let directory_name = uuid::Uuid::now_v7().to_string();
    let staging = recording_directory
        .create_private_child(&directory_name)
        .map_err(|_| object_io_error(correlation_id))?;
    recording_directory.sync().map_err(|_| object_io_error(correlation_id))?;
    let directory = staging.path().to_path_buf();
    drop(staging);
    Ok(StagingFiles {
        logical: directory.join("logical.xtf"),
        compressed: directory.join("object.xtf.zst"),
        directory,
        cleanup_on_drop: true,
    })
}

#[cfg(not(unix))]
fn create_staging_files(
    _binding: &ProjectRootBinding,
    _recording_id: RecordingId,
    correlation_id: CorrelationId,
) -> Result<StagingFiles, RecordingStoreError> {
    Err(RecordingStoreError::new(
        RecordingStoreErrorKind::Compatibility,
        "XTR-STORE-ATOMIC-INSTALL",
        "atomic object installation is unsupported on this platform",
        correlation_id,
    ))
}

#[cfg(unix)]
fn ensure_object_parent(
    binding: &ProjectRootBinding,
    destination: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    binding.revalidate(correlation_id)?;
    let objects = binding.root.join("objects");
    let b3 = objects.join("b3");
    let shard = destination.parent().ok_or_else(|| atomic_install_error(correlation_id))?;
    ensure_owner_only_directory(&binding.root, &objects, correlation_id)?;
    ensure_owner_only_directory(&binding.root, &b3, correlation_id)?;
    ensure_owner_only_directory(&binding.root, shard, correlation_id)
}

#[cfg(not(unix))]
fn ensure_object_parent(
    _binding: &ProjectRootBinding,
    _destination: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    Err(atomic_install_error(correlation_id))
}

#[cfg(unix)]
fn ensure_owner_only_directory(
    root: &Path,
    directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let relative =
        directory.strip_prefix(root).map_err(|_| atomic_install_error(correlation_id))?;
    let root_cap = AdmittedPrivateRoot::open(root).map_err(|_| object_io_error(correlation_id))?;
    let mut current = root_cap;
    let mut traversed = 0_usize;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(atomic_install_error(correlation_id));
        };
        traversed += 1;
        if traversed > 16 {
            return Err(atomic_install_error(correlation_id));
        }
        let name = name.to_str().ok_or_else(|| atomic_install_error(correlation_id))?;
        current = current
            .open_or_create_private_child(name)
            .map_err(|_| object_io_error(correlation_id))?;
    }
    current.revalidate().map_err(|_| object_io_error(correlation_id))
}

fn write_synced_file(
    path: &Path,
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    note_staging_write();
    let parent = path.parent().ok_or_else(|| object_io_error(correlation_id))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| object_io_error(correlation_id))?;
    let root = AdmittedPrivateRoot::open(parent).map_err(|_| object_io_error(correlation_id))?;
    let mut file = root.create_private_file(name).map_err(|_| object_io_error(correlation_id))?;
    file.write_all(bytes).map_err(|_| object_io_error(correlation_id))?;
    file.flush().map_err(|_| object_io_error(correlation_id))?;
    file.sync_all().map_err(|_| object_io_error(correlation_id))?;
    root.validate_file_binding(name, &file, true).map_err(|_| object_io_error(correlation_id))?;
    root.sync().map_err(|_| object_io_error(correlation_id))
}

#[cfg(unix)]
fn validate_managed_directory(
    directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    AdmittedPrivateRoot::open(directory)
        .and_then(|root| root.revalidate())
        .map_err(|_| atomic_install_error(correlation_id))
}

#[cfg(unix)]
fn validate_managed_tree(
    root: &Path,
    directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let relative =
        directory.strip_prefix(root).map_err(|_| atomic_install_error(correlation_id))?;
    let mut current =
        AdmittedPrivateRoot::open(root).map_err(|_| atomic_install_error(correlation_id))?;
    let mut traversed = 0_usize;
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(atomic_install_error(correlation_id));
        };
        traversed += 1;
        if traversed > 16 {
            return Err(atomic_install_error(correlation_id));
        }
        current = current
            .open_private_child(part.to_str().ok_or_else(|| atomic_install_error(correlation_id))?)
            .map_err(|_| atomic_install_error(correlation_id))?;
    }
    current.revalidate().map_err(|_| atomic_install_error(correlation_id))
}

#[cfg(not(unix))]
fn validate_managed_tree(
    _root: &Path,
    _directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    Err(atomic_install_error(correlation_id))
}

#[cfg(not(unix))]
fn validate_managed_directory(
    _directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    Err(atomic_install_error(correlation_id))
}

fn validate_managed_file(
    path: &Path,
    correlation_id: CorrelationId,
    absent_is_valid: bool,
) -> Result<(), RecordingStoreError> {
    let parent = path.parent().ok_or_else(|| atomic_install_error(correlation_id))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| atomic_install_error(correlation_id))?;
    let root =
        AdmittedPrivateRoot::open(parent).map_err(|_| atomic_install_error(correlation_id))?;
    match root.open_managed_file(name) {
        Ok(file) => root
            .validate_managed_file_binding(name, &file, false)
            .map_err(|_| atomic_install_error(correlation_id)),
        Err(_) if absent_is_valid => match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(atomic_install_error(correlation_id)),
        },
        Err(_) => Err(atomic_install_error(correlation_id)),
    }
}

#[cfg(unix)]
fn sync_directory(
    directory: &Path,
    correlation_id: CorrelationId,
    code: &'static str,
) -> Result<(), RecordingStoreError> {
    let failure = || {
        if code == "XTR-STORE-ATOMIC-INSTALL" {
            atomic_install_error(correlation_id)
        } else {
            object_io_error(correlation_id)
        }
    };
    let handle = AdmittedPrivateRoot::open(directory).map_err(|_| failure())?;
    handle.sync().map_err(|_| failure())
}

#[cfg(not(unix))]
fn sync_directory(
    _directory: &Path,
    correlation_id: CorrelationId,
    _code: &'static str,
) -> Result<(), RecordingStoreError> {
    Err(atomic_install_error(correlation_id))
}

fn object_path(root: &Path, object_hash: ContentHash) -> PathBuf {
    let hex = hex::encode(object_hash.as_bytes());
    root.join("objects").join("b3").join(&hex[..2]).join(format!("{}.xtf.zst", &hex[2..]))
}

fn object_path_from_row(
    root: &Path,
    raw_hash: &[u8],
    correlation_id: CorrelationId,
) -> Result<PathBuf, RecordingStoreError> {
    let raw: [u8; 32] = raw_hash.try_into().map_err(|_| object_corrupt_error(correlation_id))?;
    let hash = ContentHash::from_str(&format!("b3:{}", hex::encode(raw)))
        .map_err(|_| object_corrupt_error(correlation_id))?;
    Ok(object_path(root, hash))
}

fn read_bounded_regular_file(
    path: &Path,
    correlation_id: CorrelationId,
    staging: bool,
) -> Result<Vec<u8>, RecordingStoreError> {
    let failure = || {
        if staging {
            xtf_verify_error(correlation_id)
        } else {
            object_corrupt_error(correlation_id)
        }
    };
    let limit = max_compressed_segment_bytes();
    let parent = path.parent().ok_or_else(failure)?;
    let name = path.file_name().and_then(|name| name.to_str()).ok_or_else(failure)?;
    let root = AdmittedPrivateRoot::open(parent).map_err(|_| failure())?;
    if staging {
        root.read_bounded_file(name, limit).map_err(|_| failure())
    } else {
        root.read_bounded_managed_file(name, limit).map_err(|_| failure())
    }
}

fn verify_staged_object(
    bytes: &[u8],
    candidate: &SegmentMetadata,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let verified = verify_compressed_segment(bytes, candidate.object_hash)
        .map_err(|_| xtf_verify_error(correlation_id))?;
    if verified.project_id() != candidate.project_id
        || verified.recording_id() != candidate.recording_id
        || verified.segment_ordinal() != candidate.segment_ordinal
        || verified.event_count()
            != u64::try_from(candidate.event_count).map_err(|_| xtf_verify_error(correlation_id))?
        || verified.first_recording_seq() != candidate.first_recording_seq
        || verified.last_recording_seq() != candidate.last_recording_seq
        || verified.footer_prefix_digest() != candidate.checksum
    {
        return Err(xtf_verify_error(correlation_id));
    }
    Ok(())
}

fn verify_existing_object(
    bytes: &[u8],
    row: &SegmentRow,
    candidate: &SegmentMetadata,
    correlation_id: CorrelationId,
) -> Result<i64, RecordingStoreError> {
    if i64::try_from(bytes.len()).map_err(|_| object_corrupt_error(correlation_id))?
        != row.compressed_bytes
    {
        return Err(object_corrupt_error(correlation_id));
    }
    let verified = verify_compressed_segment(bytes, candidate.object_hash)
        .map_err(|_| object_corrupt_error(correlation_id))?;
    if verified.project_id() != candidate.project_id
        || verified.recording_id() != candidate.recording_id
        || verified.segment_ordinal() != candidate.segment_ordinal
        || verified.event_count()
            != u64::try_from(row.event_count).map_err(|_| object_corrupt_error(correlation_id))?
        || verified.first_recording_seq()
            != decode_stored_sequence(&row.first_recording_seq, correlation_id)?
        || verified.last_recording_seq()
            != decode_stored_sequence(&row.last_recording_seq, correlation_id)?
        || verified.footer_prefix_digest().as_bytes() != row.checksum.as_slice()
        || i64::try_from(bytes.len()).map_err(|_| object_corrupt_error(correlation_id))?
            != row.compressed_bytes
    {
        return Err(object_corrupt_error(correlation_id));
    }
    i64::try_from(bytes.len()).map_err(|_| object_corrupt_error(correlation_id))
}

fn publish_no_replace<F>(
    staging: &Path,
    destination: &Path,
    candidate: &SegmentMetadata,
    correlation_id: CorrelationId,
    defer_cleanup_after_new_link: F,
) -> Result<i64, RecordingStoreError>
where
    F: FnOnce(),
{
    let staging_parent = staging.parent().ok_or_else(|| atomic_install_error(correlation_id))?;
    let staging_name = staging
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| atomic_install_error(correlation_id))?;
    let destination_parent =
        destination.parent().ok_or_else(|| atomic_install_error(correlation_id))?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| atomic_install_error(correlation_id))?;
    let staging_root = AdmittedPrivateRoot::open(staging_parent)
        .map_err(|_| atomic_install_error(correlation_id))?;
    let staged_file = staging_root
        .open_regular_file(staging_name)
        .map_err(|_| atomic_install_error(correlation_id))?;
    staging_root
        .validate_file_binding(staging_name, &staged_file, false)
        .map_err(|_| atomic_install_error(correlation_id))?;
    let destination_root = AdmittedPrivateRoot::open(destination_parent)
        .map_err(|_| atomic_install_error(correlation_id))?;
    staging_root.revalidate().map_err(|_| atomic_install_error(correlation_id))?;
    destination_root.revalidate().map_err(|_| atomic_install_error(correlation_id))?;
    commit_failpoint("hard-link-syscall", correlation_id, true)?;
    match std::fs::hard_link(staging, destination) {
        Ok(()) => {
            // The new destination and staging names now address the same
            // verified source bytes. Retain that source evidence before any
            // fallible readback can observe the new destination.
            defer_cleanup_after_new_link();
            commit_failpoint("after-hard-link-before-readback", correlation_id, true)?;
            let persisted_file = destination_root
                .open_managed_file(destination_name)
                .map_err(|_| atomic_install_error(correlation_id))?;
            destination_root
                .validate_managed_file_binding(destination_name, &persisted_file, false)
                .map_err(|_| atomic_install_error(correlation_id))?;
            let persisted = read_bounded_regular_file(destination, correlation_id, false)?;
            verify_staged_object(&persisted, candidate, correlation_id)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            i64::try_from(persisted.len()).map_err(|_| object_corrupt_error(correlation_id))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing_file = destination_root
                .open_managed_file(destination_name)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            destination_root
                .validate_managed_file_binding(destination_name, &existing_file, false)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            let existing = read_bounded_regular_file(destination, correlation_id, false)?;
            verify_staged_object(&existing, candidate, correlation_id)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            i64::try_from(existing.len()).map_err(|_| object_corrupt_error(correlation_id))
        }
        Err(_) => Err(atomic_install_error(correlation_id)),
    }
}

fn cleanup_owned_staging_paths(staging: &StagingFiles, correlation_id: CorrelationId) {
    let Some(parent) = staging.directory.parent() else {
        tracing::warn!("recording segment staging cleanup could not bind its parent");
        return;
    };
    let Some(directory_name) = staging.directory.file_name().and_then(|name| name.to_str()) else {
        tracing::warn!("recording segment staging cleanup had an invalid directory name");
        return;
    };
    let cleanup = (|| {
        let parent_cap =
            AdmittedPrivateRoot::open(parent).map_err(|_| PrivateStorageError::Unavailable)?;
        let staging_cap = parent_cap.open_private_child(directory_name)?;
        for (path, managed) in [(&staging.logical, false), (&staging.compressed, true)] {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(PrivateStorageError::InvalidName)?;
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Ok(_) => {}
                Err(_) => return Err(PrivateStorageError::Unavailable),
            }
            if managed {
                staging_cap.remove_managed_file(name)?;
            } else {
                staging_cap.remove_private_file(name)?;
            }
        }
        parent_cap.remove_private_child(directory_name)?;
        Ok::<(), PrivateStorageError>(())
    })();
    if cleanup.is_err() {
        tracing::warn!("recording segment staging cleanup left safe residue");
        return;
    }
    if commit_failpoint("cleanup-staging-directory-fsync", correlation_id, false).is_err()
        || sync_directory(parent, correlation_id, "XTR-STORE-OBJECT-IO").is_err()
    {
        tracing::warn!("recording segment staging directory synchronization left safe residue");
    }
}

fn object_corrupt_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Corruption,
        "XTR-STORE-OBJECT-CORRUPT",
        "stored segment object is missing or corrupt",
        correlation_id,
    )
}

fn object_io_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Transport,
        "XTR-STORE-OBJECT-IO",
        "segment object I/O could not be completed",
        correlation_id,
    )
}

fn xtf_verify_error(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Corruption,
        "XTR-STORE-XTF-VERIFY",
        "XTF object verification failed",
        correlation_id,
    )
}

#[cfg(test)]
thread_local! {
    static COMMIT_FAILPOINT: std::cell::RefCell<Option<&'static str>> = const { std::cell::RefCell::new(None) };
    static COMMIT_FAILPOINT_FIRED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STAGING_HARD_LINKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STAGING_WRITE_AFTER_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn note_staging_write() {
    STAGING_HARD_LINKED.with(|published| {
        if published.get() {
            STAGING_WRITE_AFTER_LINK.with(|write| write.set(true));
        }
    });
}

#[cfg(not(test))]
fn note_staging_write() {}

#[cfg(test)]
fn note_successful_hard_link() {
    STAGING_HARD_LINKED.with(|published| published.set(true));
}

#[cfg(not(test))]
fn note_successful_hard_link() {}

#[cfg(test)]
fn reset_staging_write_observer() {
    STAGING_HARD_LINKED.with(|published| published.set(false));
    STAGING_WRITE_AFTER_LINK.with(|write| write.set(false));
}

#[cfg(not(test))]
fn reset_staging_write_observer() {}

#[cfg(test)]
#[derive(Debug)]
struct ReplayPause {
    recording_id: RecordingId,
    segment_ordinal: u32,
    entered: std::sync::Barrier,
    release: std::sync::Barrier,
}

#[cfg(test)]
static REPLAY_PAUSE: std::sync::Mutex<Option<std::sync::Arc<ReplayPause>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
struct ReplayPauseInstall {
    pause: std::sync::Arc<ReplayPause>,
}

#[cfg(test)]
impl Drop for ReplayPauseInstall {
    fn drop(&mut self) {
        let mut configured = REPLAY_PAUSE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if configured.as_ref().is_some_and(|current| std::sync::Arc::ptr_eq(current, &self.pause)) {
            *configured = None;
        }
    }
}

#[cfg(test)]
struct ReplayReleaseGuard {
    pause: std::sync::Arc<ReplayPause>,
    released: bool,
}

#[cfg(test)]
impl ReplayReleaseGuard {
    fn new(pause: std::sync::Arc<ReplayPause>) -> Self {
        Self { pause, released: false }
    }

    fn release(&mut self) {
        self.pause.release.wait();
        self.released = true;
    }
}

#[cfg(test)]
impl Drop for ReplayReleaseGuard {
    fn drop(&mut self) {
        if !self.released {
            self.pause.release.wait();
        }
    }
}

#[cfg(test)]
fn install_replay_pause(pause: std::sync::Arc<ReplayPause>) -> ReplayPauseInstall {
    let mut configured = REPLAY_PAUSE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    *configured = Some(pause.clone());
    ReplayPauseInstall { pause }
}

#[cfg(test)]
fn pause_replay_verification(recording_id: RecordingId, segment_ordinal: u32) {
    let pause = {
        let configured = REPLAY_PAUSE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        configured
            .as_ref()
            .filter(|pause| {
                pause.recording_id == recording_id && pause.segment_ordinal == segment_ordinal
            })
            .cloned()
    };
    if let Some(pause) = pause {
        pause.entered.wait();
        pause.release.wait();
    }
}

#[cfg(not(test))]
fn pause_replay_verification(_recording_id: RecordingId, _segment_ordinal: u32) {}

#[cfg(test)]
fn commit_failpoint(
    point: &'static str,
    correlation_id: CorrelationId,
    atomic_boundary: bool,
) -> Result<(), RecordingStoreError> {
    let injected = COMMIT_FAILPOINT.with(|configured| *configured.borrow() == Some(point));
    if injected {
        COMMIT_FAILPOINT_FIRED.with(|fired| fired.set(true));
        return Err(if atomic_boundary {
            atomic_install_error(correlation_id)
        } else {
            object_io_error(correlation_id)
        });
    }
    Ok(())
}

#[cfg(not(test))]
fn commit_failpoint(
    _point: &'static str,
    _correlation_id: CorrelationId,
    _atomic_boundary: bool,
) -> Result<(), RecordingStoreError> {
    Ok(())
}

#[derive(Debug)]
struct ProjectRootBinding {
    root: PathBuf,
    database_path: PathBuf,
    private_root: AdmittedPrivateRoot,
}

impl ProjectRootBinding {
    fn new(
        root: &Path,
        database_path: PathBuf,
        correlation_id: CorrelationId,
    ) -> Result<Self, RecordingStoreError> {
        let private_root = AdmittedPrivateRoot::open(root).map_err(|_| {
            RecordingStoreError::new(
                RecordingStoreErrorKind::Permission,
                "XTR-PRIVATE-STORAGE-UNAVAILABLE",
                "private storage is unavailable",
                correlation_id,
            )
        })?;
        if private_root.path() != root {
            return Err(RecordingStoreError::new(
                RecordingStoreErrorKind::Validation,
                "XTR-STORE-RECORDING-ROOT-INVALID",
                "project root identity does not match its requested path",
                correlation_id,
            ));
        }
        let binding = Self { root: root.to_path_buf(), database_path, private_root };
        binding.revalidate(correlation_id)?;
        Ok(binding)
    }

    /// Re-checks the durable root/database identity without canonicalizing.
    ///
    /// Construction-time checks cannot eliminate filesystem TOCTOU. Later
    /// publish code reuses this method before every filesystem boundary.
    fn revalidate(&self, correlation_id: CorrelationId) -> Result<(), RecordingStoreError> {
        #[cfg(not(unix))]
        {
            return Err(RecordingStoreError::new(
                RecordingStoreErrorKind::Compatibility,
                "XTR-STORE-RECORDING-ROOT-COMPATIBILITY",
                "recording persistence is unsupported on this platform",
                correlation_id,
            ));
        }

        #[cfg(unix)]
        {
            self.private_root.revalidate().map_err(|_| {
                RecordingStoreError::new(
                    RecordingStoreErrorKind::Permission,
                    "XTR-PRIVATE-STORAGE-UNAVAILABLE",
                    "private storage is unavailable",
                    correlation_id,
                )
            })?;
            let parent = self.database_path.parent().ok_or_else(|| {
                RecordingStoreError::new(
                    RecordingStoreErrorKind::Validation,
                    "XTR-STORE-RECORDING-ROOT-INVALID",
                    "SQLite database path has no parent directory",
                    correlation_id,
                )
            })?;
            if parent != self.root {
                return Err(RecordingStoreError::new(
                    RecordingStoreErrorKind::Validation,
                    "XTR-STORE-RECORDING-ROOT-INVALID",
                    "SQLite database parent does not match project root",
                    correlation_id,
                ));
            }
            validate_regular_owner_only_file(&self.database_path, correlation_id)?;
            let file_name =
                self.database_path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
                    RecordingStoreError::new(
                        RecordingStoreErrorKind::Validation,
                        "XTR-STORE-RECORDING-ROOT-INVALID",
                        "SQLite database file name is invalid",
                        correlation_id,
                    )
                })?;
            let file = self.private_root.open_regular_file(file_name).map_err(|_| {
                RecordingStoreError::new(
                    RecordingStoreErrorKind::Permission,
                    "XTR-PRIVATE-STORAGE-UNAVAILABLE",
                    "private storage is unavailable",
                    correlation_id,
                )
            })?;
            drop(file);
            self.private_root.revalidate().map_err(|_| {
                RecordingStoreError::new(
                    RecordingStoreErrorKind::Permission,
                    "XTR-PRIVATE-STORAGE-UNAVAILABLE",
                    "private storage is unavailable",
                    correlation_id,
                )
            })
        }
    }
}

#[cfg(unix)]
fn validate_regular_owner_only_file(
    database_path: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(database_path).map_err(|_| {
        RecordingStoreError::new(
            RecordingStoreErrorKind::Transport,
            "XTR-STORE-RECORDING-ROOT-IO",
            "SQLite database metadata could not be read",
            correlation_id,
        )
        .with_source("filesystem metadata failure")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Validation,
            "XTR-STORE-RECORDING-ROOT-INVALID",
            "SQLite database must be a regular non-symbolic-link file",
            correlation_id,
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Permission,
            "XTR-STORE-RECORDING-ROOT-PERMISSION",
            "SQLite database must be owner-only",
            correlation_id,
        ));
    }
    Ok(())
}

fn project_exists(
    connection: &rusqlite::Connection,
    project_id: ProjectId,
    correlation_id: CorrelationId,
) -> Result<bool, RecordingStoreError> {
    connection
        .query_row(
            "SELECT 1 FROM projects WHERE project_id = ?1",
            rusqlite::params![project_id.as_uuid().as_bytes().to_vec()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })
}

#[derive(Debug)]
struct ExistingRecording {
    project_id: Vec<u8>,
    runtime_session_id: Vec<u8>,
    opened_at: String,
}

fn load_recording(
    connection: &rusqlite::Connection,
    recording_id: RecordingId,
    correlation_id: CorrelationId,
) -> Result<Option<ExistingRecording>, RecordingStoreError> {
    connection
        .query_row(
            "SELECT project_id, runtime_session_id, opened_at FROM recordings WHERE recording_id = ?1",
            rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
            |row| {
                Ok(ExistingRecording {
                    project_id: row.get(0)?,
                    runtime_session_id: row.get(1)?,
                    opened_at: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))
}

fn verify_existing_identity(
    existing: &ExistingRecording,
    request: &BeginRecordingRequest,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let valid_identity_widths =
        existing.project_id.len() == 16 && existing.runtime_session_id.len() == 16;
    if !valid_identity_widths {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Corruption,
            "XTR-STORE-RECORDING-CORRUPT",
            "recording identity has invalid stored width",
            correlation_id,
        ));
    }
    if existing.project_id == request.project_id.as_uuid().as_bytes()
        && existing.runtime_session_id == request.runtime_session_id.as_uuid().as_bytes()
        && existing.opened_at == request.opened_at.to_rfc3339()
    {
        return Ok(());
    }
    Err(recording_conflict(
        "recording identity conflicts with an existing recording",
        correlation_id,
    ))
}

fn recording_conflict(message: &'static str, correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Conflict,
        "XTR-STORE-RECORDING-CONFLICT",
        message,
        correlation_id,
    )
}

#[derive(Clone, Copy)]
struct SafeObservation {
    policy_id: Option<&'static str>,
    application_component: Option<&'static str>,
    binding_key: Option<&'static str>,
    method: Option<&'static str>,
    route_template: Option<&'static str>,
    reason_code: Option<&'static str>,
}

fn classify_observation(input: &EndpointObservationInput) -> SafeObservation {
    const POLICY: &str = "spring-orders-v1";
    const COMPONENT: &str = "spring-fixture";
    const BINDING: &str = "default";
    let safe_context = if input.application_component.as_deref() == Some(COMPONENT)
        && input.binding_key.as_deref() == Some(BINDING)
    {
        (Some(COMPONENT), Some(BINDING))
    } else {
        (None, None)
    };
    let Some(policy) = input.policy_id.as_deref() else {
        return unmatched(None, safe_context.0, safe_context.1, "observation_policy_missing");
    };
    if policy != POLICY {
        return unmatched(None, safe_context.0, safe_context.1, "observation_policy_invalid");
    }
    if input.application_component.is_none() && input.binding_key.is_none() {
        return unmatched(Some(POLICY), None, None, "identity_context_missing");
    }
    let valid_pair = input.application_component.as_deref() == Some(COMPONENT)
        && input.binding_key.as_deref() == Some(BINDING);
    if !valid_pair {
        return unmatched(Some(POLICY), None, None, "identity_context_invalid");
    }
    let Some(method) = HttpMethod::parse(&input.method) else {
        return unmatched(Some(POLICY), Some(COMPONENT), Some(BINDING), "method_unsupported");
    };
    if method != HttpMethod::Post {
        return unmatched(Some(POLICY), Some(COMPONENT), Some(BINDING), "method_unsupported");
    }
    if input.route_template != "/orders" {
        return unmatched(Some(POLICY), Some(COMPONENT), Some(BINDING), "route_unapproved");
    }
    SafeObservation {
        policy_id: Some(POLICY),
        application_component: Some(COMPONENT),
        binding_key: Some(BINDING),
        method: Some("POST"),
        route_template: Some("/orders"),
        reason_code: None,
    }
}

fn unmatched(
    policy_id: Option<&'static str>,
    application_component: Option<&'static str>,
    binding_key: Option<&'static str>,
    reason_code: &'static str,
) -> SafeObservation {
    SafeObservation {
        policy_id,
        application_component,
        binding_key,
        method: None,
        route_template: None,
        reason_code: Some(reason_code),
    }
}

type StoredObservation = (
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<u8>,
);

fn observation_matches(stored: &StoredObservation, expected: &SafeObservation) -> bool {
    let linked = expected.reason_code.is_none();
    stored.0 == if linked { "linked" } else { "unmatched" }
        && stored.1.as_deref() == expected.policy_id
        && stored.3.as_deref() == expected.application_component
        && stored.4.as_deref() == expected.binding_key
        && stored.5.as_deref() == expected.method
        && stored.6.as_deref() == expected.route_template
        && stored.7.as_deref() == expected.reason_code
}

fn validate_stored_observation(
    transaction: &rusqlite::Connection,
    project_id: ProjectId,
    stored: &StoredObservation,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let stored_project: [u8; 16] =
        stored.8.as_slice().try_into().map_err(|_| endpoint_identity_corrupt(correlation_id))?;
    let stored_project = ProjectId::from_uuid(uuid::Uuid::from_bytes(stored_project));
    if stored_project != project_id {
        return Err(endpoint_identity_corrupt(correlation_id));
    }
    match stored.0.as_str() {
        "linked" => {
            let Some(operation_bytes) = stored.2.as_deref() else {
                return Err(endpoint_identity_corrupt(correlation_id));
            };
            if stored.1.as_deref() != Some("spring-orders-v1")
                || stored.3.as_deref() != Some("spring-fixture")
                || stored.4.as_deref() != Some("default")
                || stored.5.as_deref() != Some("POST")
                || stored.6.as_deref() != Some("/orders")
                || stored.7.is_some()
            {
                return Err(endpoint_identity_corrupt(correlation_id));
            }
            validate_linked_operation(transaction, project_id, operation_bytes, correlation_id)
        }
        "unmatched" => {
            if stored.2.is_some() || stored.5.is_some() || stored.6.is_some() {
                return Err(endpoint_identity_corrupt(correlation_id));
            }
            let valid_shape = match stored.7.as_deref() {
                Some("observation_policy_missing" | "observation_policy_invalid") => {
                    stored.1.is_none()
                        && valid_optional_context(stored.3.as_deref(), stored.4.as_deref())
                }
                Some("identity_context_missing" | "identity_context_invalid") => {
                    stored.1.as_deref() == Some("spring-orders-v1")
                        && stored.3.is_none()
                        && stored.4.is_none()
                }
                Some("method_unsupported" | "route_unapproved") => {
                    stored.1.as_deref() == Some("spring-orders-v1")
                        && stored.3.as_deref() == Some("spring-fixture")
                        && stored.4.as_deref() == Some("default")
                }
                _ => false,
            };
            if valid_shape { Ok(()) } else { Err(endpoint_identity_corrupt(correlation_id)) }
        }
        _ => Err(endpoint_identity_corrupt(correlation_id)),
    }
}

fn valid_optional_context(component: Option<&str>, binding: Option<&str>) -> bool {
    matches!((component, binding), (None, None) | (Some("spring-fixture"), Some("default")))
}

fn endpoint_identity_corrupt(correlation_id: CorrelationId) -> RecordingStoreError {
    RecordingStoreError::new(
        RecordingStoreErrorKind::Corruption,
        "XTR-STORE-ENDPOINT-IDENTITY-CORRUPT",
        "stored endpoint identity is inconsistent",
        correlation_id,
    )
}

fn parse_stored_operation_id(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<xtrace_domain::OperationId, RecordingStoreError> {
    let raw: [u8; 16] = bytes.try_into().map_err(|_| endpoint_identity_corrupt(correlation_id))?;
    let uuid = uuid::Uuid::from_bytes(raw);
    if uuid.get_version_num() != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
        return Err(endpoint_identity_corrupt(correlation_id));
    }
    Ok(xtrace_domain::OperationId::from_uuid(uuid))
}

fn validate_linked_operation(
    transaction: &rusqlite::Connection,
    project_id: ProjectId,
    operation_bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let operation_id = parse_stored_operation_id(operation_bytes, correlation_id)?;
    type StoredOperation = (String, String, String, String, String, i64, Vec<u8>);
    let row: Option<StoredOperation> = transaction
        .query_row(
            "SELECT transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint FROM operations WHERE project_id = ?1 AND operation_id = ?2",
            rusqlite::params![project_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )
        .optional()
        .map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
    let Some((transport, method, route, component, binding, format_version, fingerprint)) = row
    else {
        return Err(endpoint_identity_corrupt(correlation_id));
    };
    let identity = EndpointIdentity {
        project_id,
        application_component: "spring-fixture".to_owned(),
        binding_key: "default".to_owned(),
        transport: Transport::Http,
        method: HttpMethod::Post,
        route_template: "/orders".to_owned(),
    };
    let expected_fingerprint = identity.fingerprint().map_err(|_| {
        RecordingStoreError::new(
            RecordingStoreErrorKind::Internal,
            "XTR-STORE-ENDPOINT-FINGERPRINT",
            "endpoint identity encoding failed",
            correlation_id,
        )
    })?;
    if transport != "http"
        || method != "POST"
        || route != "/orders"
        || component != "spring-fixture"
        || binding != "default"
        || format_version != i64::from(ENDPOINT_FINGERPRINT_FORMAT_VERSION)
        || fingerprint.as_slice() != expected_fingerprint.as_bytes()
    {
        return Err(endpoint_identity_corrupt(correlation_id));
    }
    Ok(())
}

fn validate_operation_has_observation(
    connection: &rusqlite::Connection,
    project_id: ProjectId,
    operation_bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let operation_id = parse_stored_operation_id(operation_bytes, correlation_id)?;
    validate_linked_operation(connection, project_id, operation_bytes, correlation_id)?;
    let mut statement = connection.prepare(
        "SELECT disposition, observation_policy_id, operation_id, application_component, binding_key, method, route_template, reason_code, project_id FROM recording_endpoint_observations WHERE operation_id = ?1",
    ).map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
    let mut rows =
        statement.query([operation_id.as_uuid().as_bytes().to_vec()]).map_err(|error| {
            map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
        })?;
    let mut found_link = false;
    while let Some(row) = rows.next().map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })? {
        let stored: StoredObservation = (
            row.get(0).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(1).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(2).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(3).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(4).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(5).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(6).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(7).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
            row.get(8).map_err(|error| {
                map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
            })?,
        );
        validate_stored_observation(connection, project_id, &stored, correlation_id)?;
        found_link |= stored.0 == "linked" && stored.2.as_deref() == Some(operation_bytes);
    }
    if found_link { Ok(()) } else { Err(endpoint_identity_corrupt(correlation_id)) }
}

fn recording_metadata_from_row(
    row: &rusqlite::Row<'_>,
    correlation_id: CorrelationId,
) -> Result<RecordingMetadata, RecordingStoreError> {
    let raw_id: Vec<u8> = row.get(0).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let status: String = row.get(1).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let opened_at: String = row.get(2).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let parsed_opened_at =
        opened_at.parse::<WallTime>().map_err(|_| recording_query_corrupt_error(correlation_id))?;
    if parsed_opened_at.to_rfc3339() != opened_at {
        return Err(recording_query_corrupt_error(correlation_id));
    }
    let segment_count: i64 = row.get(3).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let event_count: i64 = row.get(4).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let first_sequence: Option<Vec<u8>> = row.get(5).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let last_sequence: Option<Vec<u8>> = row.get(6).map_err(|error| {
        map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id)
    })?;
    let lifecycle_status = recording_status(&status, correlation_id)?;
    let incomplete_evidence = match lifecycle_status {
        RecordingStatus::Partial | RecordingStatus::Invalid => {
            vec![format!("persisted_status:{status}")]
        }
        _ => Vec::new(),
    };
    Ok(RecordingMetadata {
        recording_id: observed_recording_id_from_bytes(&raw_id, correlation_id)?,
        status: lifecycle_status,
        opened_at,
        segment_count: u64::try_from(segment_count)
            .map_err(|_| recording_query_corrupt_error(correlation_id))?
            .to_string(),
        event_count: u64::try_from(event_count)
            .map_err(|_| recording_query_corrupt_error(correlation_id))?
            .to_string(),
        first_sequence: first_sequence
            .as_deref()
            .map(|value| decode_stored_sequence(value, correlation_id))
            .transpose()?
            .map(|value| value.to_string()),
        last_sequence: last_sequence
            .as_deref()
            .map(|value| decode_stored_sequence(value, correlation_id))
            .transpose()?
            .map(|value| value.to_string()),
        incomplete_evidence,
    })
}

fn find_or_insert_operation(
    transaction: &rusqlite::Transaction<'_>,
    project_id: ProjectId,
    observation: &SafeObservation,
    correlation_id: CorrelationId,
) -> Result<xtrace_domain::OperationId, RecordingStoreError> {
    let identity = EndpointIdentity {
        project_id,
        application_component: observation
            .application_component
            .unwrap_or("spring-fixture")
            .to_owned(),
        binding_key: observation.binding_key.unwrap_or("default").to_owned(),
        transport: Transport::Http,
        method: HttpMethod::Post,
        route_template: "/orders".to_owned(),
    };
    let fingerprint = identity.fingerprint().map_err(|_| {
        RecordingStoreError::new(
            RecordingStoreErrorKind::Internal,
            "XTR-STORE-ENDPOINT-FINGERPRINT",
            "endpoint identity encoding failed",
            correlation_id,
        )
    })?;
    let project_bytes = project_id.as_uuid().as_bytes().to_vec();
    let fingerprint_bytes = fingerprint.as_bytes().to_vec();
    let fingerprint_id: Option<Vec<u8>> = transaction.query_row(
        "SELECT operation_id FROM operations WHERE project_id = ?1 AND fingerprint_format_version = ?2 AND endpoint_fingerprint = ?3",
        rusqlite::params![project_bytes, i64::from(ENDPOINT_FINGERPRINT_FORMAT_VERSION), fingerprint_bytes],
        |row| row.get(0),
    ).optional().map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
    let tuple_id: Option<Vec<u8>> = transaction.query_row(
        "SELECT operation_id FROM operations WHERE project_id = ?1 AND application_component = 'spring-fixture' AND binding_key = 'default' AND transport = 'http' AND method = 'POST' AND route_template = '/orders'",
        rusqlite::params![project_id.as_uuid().as_bytes().to_vec()], |row| row.get(0),
    ).optional().map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
    if fingerprint_id.is_some() || tuple_id.is_some() {
        let fingerprint_operation_id = fingerprint_id
            .as_deref()
            .map(|id| parse_stored_operation_id(id, correlation_id))
            .transpose()?;
        let tuple_operation_id = tuple_id
            .as_deref()
            .map(|id| parse_stored_operation_id(id, correlation_id))
            .transpose()?;
        if fingerprint_operation_id != tuple_operation_id {
            return Err(endpoint_identity_corrupt(correlation_id));
        }
        return fingerprint_operation_id.ok_or_else(|| endpoint_identity_corrupt(correlation_id));
    }
    let operation_id = xtrace_domain::OperationId::new();
    transaction.execute(
        "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', 'POST', '/orders', 'spring-fixture', 'default', ?3, ?4, ?5)",
        rusqlite::params![operation_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec(), i64::from(ENDPOINT_FINGERPRINT_FORMAT_VERSION), fingerprint.as_bytes().to_vec(), WallTime::now().to_rfc3339()],
    ).map_err(|error| map_store_error(StoreError::from_rusqlite(error, correlation_id), correlation_id))?;
    Ok(operation_id)
}

fn map_store_error(error: StoreError, correlation_id: CorrelationId) -> RecordingStoreError {
    let (kind, code, message, source) = match error.kind() {
        StoreErrorKind::Validation => (
            RecordingStoreErrorKind::Validation,
            "XTR-STORE-RECORDING-SQLITE-VALIDATION",
            "SQLite rejected recording input",
            Some("SQLite validation failure"),
        ),
        StoreErrorKind::SchemaOlder
        | StoreErrorKind::SchemaNewer
        | StoreErrorKind::SchemaIncompatible => (
            RecordingStoreErrorKind::Compatibility,
            "XTR-STORE-RECORDING-SQLITE-COMPATIBILITY",
            "SQLite schema is incompatible with recording persistence",
            Some("SQLite schema compatibility failure"),
        ),
        StoreErrorKind::AlreadyExists | StoreErrorKind::Conflict => (
            RecordingStoreErrorKind::Conflict,
            "XTR-STORE-RECORDING-SQLITE-CONFLICT",
            "SQLite recording integrity conflict",
            Some("SQLite integrity failure"),
        ),
        StoreErrorKind::NotFound => (
            RecordingStoreErrorKind::NotFound,
            "XTR-STORE-RECORDING-SQLITE-NOT-FOUND",
            "SQLite recording row was not found",
            Some("SQLite row lookup failure"),
        ),
        StoreErrorKind::Corruption => (
            RecordingStoreErrorKind::Corruption,
            "XTR-STORE-RECORDING-SQLITE-CORRUPT",
            "SQLite recording data is corrupt",
            Some("SQLite corruption failure"),
        ),
        StoreErrorKind::Transport => (
            RecordingStoreErrorKind::Transport,
            "XTR-STORE-RECORDING-SQLITE-IO",
            "SQLite transport operation failed",
            Some("SQLite transport failure"),
        ),
        StoreErrorKind::Permission => (
            RecordingStoreErrorKind::Permission,
            "XTR-PRIVATE-STORAGE-UNAVAILABLE",
            "private storage is unavailable",
            Some("private storage admission failure"),
        ),
        StoreErrorKind::Busy => (
            RecordingStoreErrorKind::Busy,
            "XTR-STORE-RECORDING-SQLITE-BUSY",
            "SQLite recording operation is busy",
            Some("SQLite contention failure"),
        ),
        StoreErrorKind::Resource => (
            RecordingStoreErrorKind::Resource,
            "XTR-STORE-RECORDING-SQLITE-RESOURCE",
            "SQLite recording operation exhausted a resource",
            Some("SQLite resource failure"),
        ),
        StoreErrorKind::Internal => (
            RecordingStoreErrorKind::Internal,
            "XTR-STORE-RECORDING-SQLITE-INTERNAL",
            "SQLite recording operation failed internally",
            Some("SQLite internal failure"),
        ),
    };
    let mut mapped = RecordingStoreError::new(kind, code, message, correlation_id);
    if let Some(source) = source {
        mapped = mapped.with_source(source);
    }
    mapped
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests assert on fixture setup")]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use xtrace_protocol::generated::agent::RecordingEvent;
    use xtrace_protocol::xtf::XtfEventEnvelope;

    use super::*;
    use crate::{OpenOptions, SqliteStore};

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn in_memory_store_is_refused() {
        let store = SqliteStore::open_in_memory(OpenOptions::default()).expect("open memory");
        let error = store.recording_store(Path::new("/unused")).expect_err("in-memory refusal");
        assert_eq!(error.kind(), RecordingStoreErrorKind::Compatibility);
        assert_eq!(error.code(), "XTR-STORE-RECORDING-ROOT-COMPATIBILITY");
    }

    #[test]
    fn observation_classification_uses_stable_reason_precedence() {
        let cases = [
            (EndpointObservationInput::default(), "observation_policy_missing"),
            (
                EndpointObservationInput {
                    policy_id: Some("unknown-private-policy".to_owned()),
                    ..EndpointObservationInput::default()
                },
                "observation_policy_invalid",
            ),
            (
                EndpointObservationInput {
                    policy_id: Some("spring-orders-v1".to_owned()),
                    ..EndpointObservationInput::default()
                },
                "identity_context_missing",
            ),
            (
                EndpointObservationInput {
                    policy_id: Some("spring-orders-v1".to_owned()),
                    application_component: Some("other".to_owned()),
                    binding_key: Some("default".to_owned()),
                    method: "PRIVATE".to_owned(),
                    route_template: "/secret".to_owned(),
                },
                "identity_context_invalid",
            ),
            (
                EndpointObservationInput {
                    policy_id: Some("spring-orders-v1".to_owned()),
                    application_component: Some("spring-fixture".to_owned()),
                    binding_key: Some("default".to_owned()),
                    method: "PRIVATE".to_owned(),
                    route_template: "/secret".to_owned(),
                },
                "method_unsupported",
            ),
            (
                EndpointObservationInput {
                    policy_id: Some("spring-orders-v1".to_owned()),
                    application_component: Some("spring-fixture".to_owned()),
                    binding_key: Some("default".to_owned()),
                    method: "POST".to_owned(),
                    route_template: "/secret?canary".to_owned(),
                },
                "route_unapproved",
            ),
        ];
        for (input, expected) in cases {
            let result = classify_observation(&input);
            assert_eq!(result.reason_code, Some(expected));
            assert_eq!(result.method, None);
            assert_eq!(result.route_template, None);
        }
        let identity_only = classify_observation(&EndpointObservationInput {
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            ..EndpointObservationInput::default()
        });
        assert_eq!(identity_only.reason_code, Some("observation_policy_missing"));
        assert_eq!(identity_only.application_component, Some("spring-fixture"));
        assert_eq!(identity_only.binding_key, Some("default"));
    }

    #[cfg(unix)]
    #[test]
    fn root_binding_rejects_relative_mismatched_unsafe_and_linked_paths() {
        let fixture = on_disk_store("bindings");
        let relative =
            fixture.store.recording_store(Path::new("relative-root")).expect_err("relative root");
        assert_eq!(relative.kind(), RecordingStoreErrorKind::Validation);

        let mismatch_root = fixture.base.join("other");
        std::fs::create_dir(&mismatch_root).expect("mismatch root");
        set_mode(&mismatch_root, 0o700);
        let mismatch = fixture.store.recording_store(&mismatch_root).expect_err("mismatch root");
        assert_eq!(mismatch.kind(), RecordingStoreErrorKind::Validation);

        set_mode(&fixture.root, 0o755);
        let unsafe_root = fixture.store.recording_store(&fixture.root).expect_err("unsafe root");
        assert_eq!(unsafe_root.kind(), RecordingStoreErrorKind::Permission);
        set_mode(&fixture.root, 0o700);

        let root_link = fixture.base.join("root-link");
        symlink(&fixture.root, &root_link).expect("root link");
        let linked_root = fixture.store.recording_store(&root_link).expect_err("linked root");
        assert_eq!(linked_root.kind(), RecordingStoreErrorKind::Validation);

        let ancestor = fixture.base.join("ancestor");
        std::fs::create_dir(&ancestor).expect("ancestor");
        set_mode(&ancestor, 0o700);
        let ancestor_link = fixture.base.join("ancestor-link");
        symlink(&ancestor, &ancestor_link).expect("ancestor link");
        let descendant = ancestor_link.join("child");
        std::fs::create_dir(fixture.base.join("ancestor").join("child")).expect("child");
        set_mode(fixture.base.join("ancestor").join("child"), 0o700);
        let ancestor_failure =
            fixture.store.recording_store(&descendant).expect_err("ancestor link");
        assert_eq!(ancestor_failure.kind(), RecordingStoreErrorKind::Validation);
    }

    #[cfg(unix)]
    #[test]
    fn root_binding_rejects_symlinked_and_nonregular_database_paths() {
        let fixture = on_disk_store("database-permissions");
        set_mode(&fixture.database, 0o644);
        let unsafe_database =
            fixture.store.recording_store(&fixture.root).expect_err("unsafe database permissions");
        assert_eq!(unsafe_database.kind(), RecordingStoreErrorKind::Permission);

        let fixture = on_disk_store("database-path");
        let relocated = fixture.root.join("relocated.sqlite3");
        std::fs::rename(&fixture.database, &relocated).expect("relocate database");
        symlink(&relocated, &fixture.database).expect("database link");
        let linked = fixture.store.recording_store(&fixture.root).expect_err("linked database");
        assert_eq!(linked.kind(), RecordingStoreErrorKind::Validation);

        let fixture = on_disk_store("database-directory");
        let relocated = fixture.root.join("relocated.sqlite3");
        std::fs::rename(&fixture.database, &relocated).expect("relocate database");
        std::fs::create_dir(&fixture.database).expect("database directory");
        let nonregular =
            fixture.store.recording_store(&fixture.root).expect_err("database directory");
        assert_eq!(nonregular.kind(), RecordingStoreErrorKind::Validation);
    }

    #[cfg(unix)]
    #[test]
    fn begin_recording_inserts_replays_and_preserves_advanced_status() {
        let fixture = on_disk_store("begin");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let request = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());

        assert_eq!(
            view.begin_recording(&request).expect("insert").disposition,
            BeginRecordingDisposition::Inserted
        );
        assert_recording_row(&fixture.store, &request, "recording");
        assert_eq!(
            view.begin_recording(&request).expect("replay").disposition,
            BeginRecordingDisposition::ExactReplay
        );
        {
            let connection = fixture.store.lock().expect("connection");
            connection
                .execute(
                    "UPDATE recordings SET status = 'complete' WHERE recording_id = ?1",
                    rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
                )
                .expect("advance status");
        }
        assert_eq!(
            view.begin_recording(&request).expect("advanced replay").disposition,
            BeginRecordingDisposition::ExactReplay
        );
    }

    #[cfg(unix)]
    #[test]
    fn observed_begin_links_exact_fixture_and_replays_only_safe_disposition() {
        let fixture = on_disk_store("observed-start");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let mut linked =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        assert_eq!(
            view.begin_recording(&linked).expect("linked begin").disposition,
            BeginRecordingDisposition::Inserted
        );
        {
            let connection = fixture.store.lock().expect("connection");
            let operation_bytes: Vec<u8> = connection
                .query_row(
                    "SELECT operation_id FROM operations WHERE project_id = ?1",
                    [project_id.as_uuid().as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .expect("operation ID");
            let operation_uuid = uuid::Uuid::from_slice(&operation_bytes).expect("UUIDv7 width");
            assert_eq!(operation_uuid.get_version_num(), 7);
        }
        let counts = || {
            let conn = fixture.store.lock().expect("connection");
            let operations: i64 = conn
                .query_row(
                    "SELECT count(*) FROM operations WHERE project_id = ?1",
                    [project_id.as_uuid().as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .expect("operations");
            let sidecars: i64 = conn
                .query_row(
                    "SELECT count(*) FROM recording_endpoint_observations WHERE project_id = ?1",
                    [project_id.as_uuid().as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .expect("sidecars");
            (operations, sidecars)
        };
        assert_eq!(counts(), (1, 1));
        let mut second =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        second.endpoint_observation = linked.endpoint_observation.clone();
        view.begin_recording(&second).expect("deduplicated begin");
        assert_eq!(counts(), (1, 2));
        assert_eq!(
            view.begin_recording(&linked).expect("exact replay").disposition,
            BeginRecordingDisposition::ExactReplay
        );

        let mut rejected =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        rejected.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "BREW_PRIVATE_METHOD".to_owned(),
            route_template: "/private-canary?token=secret".to_owned(),
        };
        view.begin_recording(&rejected).expect("unmatched start is accepted");
        let mut replay = rejected.clone();
        replay.endpoint_observation.method = "UNKNOWN_OTHER_METHOD".to_owned();
        replay.endpoint_observation.route_template = "/different-canary".to_owned();
        assert_eq!(
            view.begin_recording(&replay).expect("rejected raw inputs collapse safely").disposition,
            BeginRecordingDisposition::ExactReplay
        );
        let mut rejected_route =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        rejected_route.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/route-canary?secret=value".to_owned(),
        };
        view.begin_recording(&rejected_route).expect("rejected route is unmatched");
        let conn = fixture.store.lock().expect("connection");
        let row: (String, Option<String>, Option<String>, Option<String>, Option<String>) = conn.query_row(
            "SELECT disposition, observation_policy_id, application_component, binding_key, reason_code FROM recording_endpoint_observations WHERE recording_id = ?1",
            [rejected.recording_id.as_uuid().as_bytes().to_vec()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).expect("safe unmatched row");
        assert_eq!(
            row,
            (
                "unmatched".to_owned(),
                Some("spring-orders-v1".to_owned()),
                Some("spring-fixture".to_owned()),
                Some("default".to_owned()),
                Some("method_unsupported".to_owned())
            )
        );
        let route_reason: String = conn
            .query_row(
                "SELECT reason_code FROM recording_endpoint_observations WHERE recording_id = ?1",
                [rejected_route.recording_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("safe route reason");
        assert_eq!(route_reason, "route_unapproved");
        let all_text: String = conn.query_row("SELECT group_concat(coalesce(observation_policy_id,'') || coalesce(application_component,'') || coalesce(binding_key,'') || coalesce(method,'') || coalesce(route_template,'') || coalesce(reason_code,'')) FROM recording_endpoint_observations", [], |row| row.get(0)).expect("sidecar text");
        assert!(!all_text.contains("PRIVATE"));
        assert!(!all_text.contains("secret"));
        assert!(!all_text.contains("canary"));
    }

    #[cfg(unix)]
    #[test]
    fn operation_schema_rejects_non_v7_uuid_bytes() {
        let fixture = on_disk_store("operation-schema-uuid");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let connection = fixture.store.lock().expect("connection");
        let error = connection.execute(
            "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', 'POST', '/orders', 'spring-fixture', 'default', 1, zeroblob(32), 'now')",
            rusqlite::params![vec![0_u8; 16], project_id.as_uuid().as_bytes().to_vec()],
        ).expect_err("schema rejects UUID with no v7/RFC4122 bits");
        assert!(error.to_string().contains("CHECK constraint failed"));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_non_v7_operation_fails_closed_on_reuse_and_replay() {
        let fixture = on_disk_store("operation-corrupt-uuid");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let mut linked =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        view.begin_recording(&linked).expect("linked begin");
        {
            let connection = fixture.store.lock().expect("connection");
            connection
                .execute_batch("PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON;")
                .expect("bypass integrity checks for fixture");
            connection
                .execute(
                    "UPDATE operations SET operation_id = zeroblob(16) WHERE project_id = ?1",
                    [project_id.as_uuid().as_bytes().to_vec()],
                )
                .expect("corrupt operation identifier");
            connection.execute("UPDATE recording_endpoint_observations SET operation_id = zeroblob(16) WHERE recording_id = ?1", [linked.recording_id.as_uuid().as_bytes().to_vec()]).expect("corrupt sidecar identifier");
            connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF; PRAGMA foreign_keys = ON;")
                .expect("restore integrity checks");
        }
        let replay =
            view.begin_recording(&linked).expect_err("linked replay detects corrupt operation");
        assert_eq!(replay.kind(), RecordingStoreErrorKind::Corruption);
        let mut another = linked.clone();
        another.recording_id = RecordingId::new();
        another.runtime_session_id = RuntimeSessionId::new();
        let reuse = view.begin_recording(&another).expect_err("operation reuse detects corrupt ID");
        assert_eq!(reuse.kind(), RecordingStoreErrorKind::Corruption);
        let connection = fixture.store.lock().expect("connection");
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM recordings WHERE recording_id = ?1",
                [another.recording_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("recording count");
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn linked_replay_revalidates_stored_operation_fingerprint_and_tuple() {
        for (label, statement) in [
            (
                "fingerprint",
                "UPDATE operations SET endpoint_fingerprint = zeroblob(32) WHERE project_id = ?1",
            ),
            ("method", "UPDATE operations SET method = 'PUT' WHERE project_id = ?1"),
            ("route", "UPDATE operations SET route_template = '/corrupt' WHERE project_id = ?1"),
            (
                "component",
                "UPDATE operations SET application_component = 'corrupt' WHERE project_id = ?1",
            ),
            (
                "sidecar-method",
                "UPDATE recording_endpoint_observations SET method = 'PUT' WHERE project_id = ?1",
            ),
            (
                "sidecar-route",
                "UPDATE recording_endpoint_observations SET route_template = '/corrupt' WHERE project_id = ?1",
            ),
        ] {
            let fixture = on_disk_store(&format!("replay-operation-{label}"));
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            let project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            let mut linked =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            linked.endpoint_observation = EndpointObservationInput {
                policy_id: Some("spring-orders-v1".to_owned()),
                application_component: Some("spring-fixture".to_owned()),
                binding_key: Some("default".to_owned()),
                method: "POST".to_owned(),
                route_template: "/orders".to_owned(),
            };
            view.begin_recording(&linked).expect("linked begin");
            let connection = fixture.store.lock().expect("connection");
            connection
                .execute_batch("PRAGMA ignore_check_constraints = ON;")
                .expect("bypass schema checks for fixture");
            connection
                .execute(statement, [project_id.as_uuid().as_bytes().to_vec()])
                .expect("corrupt stored operation fixture");
            connection
                .execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .expect("restore schema checks");
            drop(connection);
            let error = view
                .begin_recording(&linked)
                .expect_err("linked replay fails closed on stored operation corruption");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption, "{label}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn unmatched_replay_rejects_malformed_persisted_sidecar_shapes() {
        let cases = [
            (
                "wrong-width-operation-id",
                "UPDATE recording_endpoint_observations SET operation_id = x'01' WHERE project_id = ?1",
            ),
            (
                "valid-width-operation-id",
                "UPDATE recording_endpoint_observations SET operation_id = x'018bcfe5680070008000000000000000' WHERE project_id = ?1",
            ),
            (
                "method-present",
                "UPDATE recording_endpoint_observations SET method = 'GET' WHERE project_id = ?1",
            ),
            (
                "route-present",
                "UPDATE recording_endpoint_observations SET route_template = '/corrupt' WHERE project_id = ?1",
            ),
            (
                "invalid-reason",
                "UPDATE recording_endpoint_observations SET reason_code = 'unlisted_reason' WHERE project_id = ?1",
            ),
            (
                "invalid-policy-context",
                "UPDATE recording_endpoint_observations SET reason_code = 'identity_context_missing', observation_policy_id = 'spring-orders-v1', application_component = 'spring-fixture', binding_key = 'default' WHERE project_id = ?1",
            ),
            (
                "invalid-policy",
                "UPDATE recording_endpoint_observations SET observation_policy_id = 'unlisted-policy' WHERE project_id = ?1",
            ),
        ];
        for (label, statement) in cases {
            let fixture = on_disk_store(&format!("unmatched-sidecar-{label}"));
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            let project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            let unmatched =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            view.begin_recording(&unmatched).expect("unmatched begin");
            {
                let connection = fixture.store.lock().expect("connection");
                connection
                    .execute_batch(
                        "PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON;",
                    )
                    .expect("bypass schema checks for fixture");
                connection
                    .execute(statement, [project_id.as_uuid().as_bytes().to_vec()])
                    .expect("corrupt stored sidecar fixture");
                connection
                    .execute_batch(
                        "PRAGMA ignore_check_constraints = OFF; PRAGMA foreign_keys = ON;",
                    )
                    .expect("restore schema checks");
            }
            let error = view
                .begin_recording(&unmatched)
                .expect_err("malformed unmatched sidecar fails closed");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption, "{label}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn replay_rejects_corrupt_sidecar_project_identity_without_mutation() {
        for label in ["wrong-width", "other-project"] {
            let fixture = on_disk_store(&format!("sidecar-project-{label}"));
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            let project_id = ProjectId::new();
            let other_project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            insert_project(&fixture.store, other_project_id);
            let unmatched =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            view.begin_recording(&unmatched).expect("unmatched begin");
            let replacement = if label == "wrong-width" {
                vec![0x01]
            } else {
                other_project_id.as_uuid().as_bytes().to_vec()
            };
            {
                let connection = fixture.store.lock().expect("connection");
                connection
                    .execute_batch(
                        "PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON;",
                    )
                    .expect("bypass schema checks for fixture");
                connection
                    .execute(
                        "UPDATE recording_endpoint_observations SET project_id = ?1 WHERE recording_id = ?2",
                        rusqlite::params![replacement, unmatched.recording_id.as_uuid().as_bytes().to_vec()],
                    )
                    .expect("corrupt sidecar project identity");
                connection
                    .execute_batch(
                        "PRAGMA ignore_check_constraints = OFF; PRAGMA foreign_keys = ON;",
                    )
                    .expect("restore schema checks");
            }
            let error = view
                .begin_recording(&unmatched)
                .expect_err("corrupt sidecar project identity fails closed");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption, "{label}");
            let connection = fixture.store.lock().expect("connection");
            let (recordings, operations): (i64, i64) = connection
                .query_row(
                    "SELECT (SELECT count(*) FROM recordings WHERE recording_id = ?1), (SELECT count(*) FROM operations WHERE project_id = ?2)",
                    rusqlite::params![unmatched.recording_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("state counts");
            assert_eq!((recordings, operations), (1, 0), "{label}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn legacy_replay_stays_absent_and_failed_sidecar_insert_rolls_back_operation() {
        let fixture = on_disk_store("observed-rollback");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let mut legacy =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        view.begin_recording(&legacy).expect("legacy-style unmatched row");
        {
            let conn = fixture.store.lock().expect("connection");
            conn.execute(
                "DELETE FROM recording_endpoint_observations WHERE recording_id = ?1",
                [legacy.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("remove sidecar for legacy fixture");
        }
        legacy.endpoint_observation.policy_id = Some("spring-orders-v1".to_owned());
        legacy.endpoint_observation.application_component = Some("spring-fixture".to_owned());
        legacy.endpoint_observation.binding_key = Some("default".to_owned());
        legacy.endpoint_observation.method = "POST".to_owned();
        legacy.endpoint_observation.route_template = "/orders".to_owned();
        assert_eq!(
            view.begin_recording(&legacy).expect("legacy replay").disposition,
            BeginRecordingDisposition::LegacyObservationAbsent
        );
        let failed_id = RecordingId::new();
        let mut accepted = legacy.clone();
        accepted.recording_id = failed_id;
        accepted.runtime_session_id = RuntimeSessionId::new();
        {
            let conn = fixture.store.lock().expect("connection");
            conn.execute_batch("CREATE TRIGGER fail_sidecar BEFORE INSERT ON recording_endpoint_observations BEGIN SELECT RAISE(ABORT, 'injected'); END;").expect("install failpoint");
        }
        assert!(view.begin_recording(&accepted).is_err());
        let conn = fixture.store.lock().expect("connection");
        let count: i64 = conn.query_row("SELECT (SELECT count(*) FROM operations) + (SELECT count(*) FROM recordings WHERE recording_id = ?1) + (SELECT count(*) FROM recording_endpoint_observations WHERE recording_id = ?1)", [failed_id.as_uuid().as_bytes().to_vec()], |row| row.get(0)).expect("rollback counts");
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn identical_endpoint_tuples_are_isolated_by_project() {
        let fixture = on_disk_store("project-isolation");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let first_project = ProjectId::new();
        let second_project = ProjectId::new();
        insert_project(&fixture.store, first_project);
        insert_project(&fixture.store, second_project);
        let context = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        for project_id in [first_project, second_project] {
            let mut start =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            start.endpoint_observation = context.clone();
            view.begin_recording(&start).expect("linked observation");
        }
        let connection = fixture.store.lock().expect("connection");
        let first_id: Vec<u8> = connection
            .query_row(
                "SELECT operation_id FROM operations WHERE project_id = ?1",
                [first_project.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("first project operation");
        let second_id: Vec<u8> = connection
            .query_row(
                "SELECT operation_id FROM operations WHERE project_id = ?1",
                [second_project.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("second project operation");
        assert_ne!(first_id, second_id);
    }

    #[cfg(unix)]
    #[test]
    fn fingerprint_to_tuple_mismatch_fails_closed_before_recording_insert() {
        let fixture = on_disk_store("fingerprint-tuple-mismatch");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let context = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        let mut first =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        first.endpoint_observation = context.clone();
        view.begin_recording(&first).expect("first operation");
        {
            let connection = fixture.store.lock().expect("connection");
            connection.execute("UPDATE operations SET endpoint_fingerprint = zeroblob(32) WHERE project_id = ?1", [project_id.as_uuid().as_bytes().to_vec()]).expect("corrupt fingerprint fixture");
        }
        let mut replay =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        replay.endpoint_observation = context.clone();
        let error = view.begin_recording(&replay).expect_err("fingerprint mismatch is corruption");
        assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption);
        let connection = fixture.store.lock().expect("connection");
        let present: i64 = connection
            .query_row(
                "SELECT count(*) FROM recordings WHERE recording_id = ?1",
                [replay.recording_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("recording count");
        assert_eq!(present, 0);
    }

    #[cfg(unix)]
    #[test]
    fn begin_recording_reports_missing_project_and_each_identity_conflict() {
        let fixture = on_disk_store("conflicts");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let missing =
            request(ProjectId::new(), RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let not_found = view.begin_recording(&missing).expect_err("missing project");
        assert_eq!(not_found.kind(), RecordingStoreErrorKind::NotFound);
        assert_eq!(not_found.code(), "XTR-STORE-RECORDING-PROJECT-NOT-FOUND");
        assert_eq!(not_found.category(), RecordingStoreErrorCategory::NotFound);
        assert_eq!(recording_count(&fixture.store), 0);

        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let request = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        view.begin_recording(&request).expect("insert");
        let other_project_id = ProjectId::new();
        insert_project(&fixture.store, other_project_id);
        for changed in [
            BeginRecordingRequest { project_id: other_project_id, ..request.clone() },
            BeginRecordingRequest {
                runtime_session_id: RuntimeSessionId::new(),
                ..request.clone()
            },
            BeginRecordingRequest {
                opened_at: WallTime::from_parts(2026, 9, 29, 2, 3, 5, 6).expect("time"),
                ..request.clone()
            },
        ] {
            let error = view.begin_recording(&changed).expect_err("identity conflict");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Conflict);
            assert_eq!(error.code(), "XTR-STORE-RECORDING-CONFLICT");
            assert_eq!(error.category(), RecordingStoreErrorCategory::Conflict);
            assert!(error.source().is_none());
        }
        assert_recording_row(&fixture.store, &request, "recording");
        assert_eq!(recording_count(&fixture.store), 1);
    }

    #[cfg(unix)]
    #[test]
    fn raw_foreign_key_failure_is_a_sanitized_conflict() {
        let fixture = on_disk_store("foreign-key");
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let request = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        {
            let connection = fixture.store.lock().expect("connection");
            connection
                .execute_batch(
                    "CREATE TRIGGER delete_project_before_recording \
                     BEFORE INSERT ON recordings BEGIN \
                         DELETE FROM projects WHERE project_id = NEW.project_id; \
                     END",
                )
                .expect("trigger");
        }
        let error = view.begin_recording(&request).expect_err("foreign key conflict");
        assert_eq!(error.kind(), RecordingStoreErrorKind::Conflict);
        assert_eq!(error.code(), "XTR-STORE-RECORDING-SQLITE-CONFLICT");
        assert_eq!(error.category(), RecordingStoreErrorCategory::Conflict);
        assert_eq!(error.source(), Some("SQLite integrity failure"));
        assert!(!error.to_string().contains("DELETE"));
        assert_eq!(project_count(&fixture.store), 1);
        assert_eq!(recording_count(&fixture.store), 0);
    }

    #[test]
    fn sqlite_error_mapping_preserves_correlation_and_sanitizes_source() {
        let correlation_id = CorrelationId::new();
        let store_error =
            StoreError::new(StoreErrorKind::Transport, "untrusted sqlite detail", correlation_id)
                .with_source("untrusted SQLite path and parameter detail");
        let error = map_store_error(store_error, correlation_id);
        assert_eq!(error.correlation_id(), correlation_id);
        assert_eq!(error.code(), "XTR-STORE-RECORDING-SQLITE-IO");
        assert_eq!(error.category(), RecordingStoreErrorCategory::Availability);
        assert_eq!(error.source(), Some("SQLite transport failure"));
        assert!(!error.to_string().contains("untrusted"));
    }

    #[cfg(unix)]
    #[test]
    fn clone_and_recording_view_share_one_writer_mutex() {
        let fixture = on_disk_store("writer");
        let clone = fixture.store.clone();
        let _view = clone.recording_store(&fixture.root).expect("view");
        let guard =
            fixture.store.lock_recording_writer(CorrelationId::new()).expect("writer guard");
        assert!(clone.try_lock_recording_writer().is_none());
        drop(guard);
        assert!(clone.try_lock_recording_writer().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn commit_segment_publishes_metadata_and_a_owner_only_object() {
        let fixture = on_disk_store("commit-happy");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");

        let receipt = view
            .commit_segment(&segment_request(project_id, anchor.recording_id, 0, &[2, 3]))
            .expect("commit");
        assert_eq!(receipt.disposition, SegmentCommitDisposition::Inserted);
        assert_eq!(receipt.segment_ordinal, 0);
        assert!(receipt.uncompressed_bytes > 0);
        assert!(receipt.compressed_bytes > 0);
        assert_segment_row(&fixture.store, anchor.recording_id, 0, &receipt, 2, 3, 2);
        let path = object_path(&fixture.root, receipt.object_hash);
        let metadata = std::fs::symlink_metadata(&path).expect("object metadata");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        for directory in [
            fixture.root.join("objects"),
            fixture.root.join("objects/b3"),
            path.parent().expect("parent").to_path_buf(),
        ] {
            assert_eq!(
                std::fs::metadata(directory).expect("dir").permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(STAGING_HARD_LINKED.with(std::cell::Cell::get));
        assert!(!STAGING_WRITE_AFTER_LINK.with(std::cell::Cell::get));
    }

    #[cfg(unix)]
    #[test]
    fn commit_segment_replays_after_a_later_segment_and_rejects_changed_content() {
        let fixture = on_disk_store("commit-replay");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        let first = segment_request(project_id, anchor.recording_id, 0, &[2, 3]);
        view.commit_segment(&first).expect("first");
        view.commit_segment(&segment_request(project_id, anchor.recording_id, 1, &[4]))
            .expect("later");
        assert_eq!(
            view.commit_segment(&first).expect("exact replay").disposition,
            SegmentCommitDisposition::ExactReplay
        );
        let changed = segment_request(project_id, anchor.recording_id, 0, &[2]);
        let error = view.commit_segment(&changed).expect_err("changed object");
        assert_eq!(error.code(), "XTR-STORE-SEGMENT-CONFLICT");
        assert_eq!(segment_count(&fixture.store), 2);
    }

    #[cfg(unix)]
    #[test]
    fn commit_segment_enforces_anchor_input_and_continuity_before_publication() {
        let fixture = on_disk_store("commit-continuity");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");

        for invalid in [
            segment_request(project_id, anchor.recording_id, 1, &[2]),
            segment_request(project_id, anchor.recording_id, 0, &[3]),
        ] {
            let error = view.commit_segment(&invalid).expect_err("first continuity");
            assert_eq!(error.code(), "XTR-STORE-SEGMENT-CONTINUITY");
        }
        let empty = SegmentCommitRequest {
            project_id,
            recording_id: anchor.recording_id,
            segment_ordinal: 0,
            events: Vec::new(),
        };
        assert_eq!(
            view.commit_segment(&empty).expect_err("empty").code(),
            "XTR-STORE-SEGMENT-VALIDATION"
        );
        view.commit_segment(&segment_request(project_id, anchor.recording_id, 0, &[2]))
            .expect("first");
        for invalid in [
            segment_request(project_id, anchor.recording_id, 2, &[3]),
            segment_request(project_id, anchor.recording_id, 1, &[4]),
            segment_request(project_id, anchor.recording_id, 1, &[2]),
        ] {
            let error = view.commit_segment(&invalid).expect_err("continuity");
            assert_eq!(error.code(), "XTR-STORE-SEGMENT-CONTINUITY");
        }
        assert_eq!(segment_count(&fixture.store), 1);
    }

    #[cfg(unix)]
    #[test]
    fn exact_replay_requires_the_referenced_object_to_verify() {
        let fixture = on_disk_store("commit-corrupt");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        let commit = segment_request(project_id, anchor.recording_id, 0, &[2]);
        let receipt = view.commit_segment(&commit).expect("commit");
        std::fs::remove_file(object_path(&fixture.root, receipt.object_hash))
            .expect("remove object");
        let error = view.commit_segment(&commit).expect_err("missing replay object");
        assert_eq!(error.code(), "XTR-STORE-OBJECT-CORRUPT");
        assert_eq!(segment_count(&fixture.store), 1);
    }

    #[cfg(unix)]
    #[test]
    fn every_existing_object_read_failure_is_corruption_not_transport() {
        for kind in ["missing", "corrupt", "oversize", "symlink", "directory", "unreadable"] {
            let fixture = on_disk_store(kind);
            let project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            let anchor =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            view.begin_recording(&anchor).expect("anchor");
            let request = segment_request(project_id, anchor.recording_id, 0, &[2]);
            let receipt = view.commit_segment(&request).expect("commit");
            let path = object_path(&fixture.root, receipt.object_hash);
            match kind {
                "missing" => std::fs::remove_file(&path).expect("remove"),
                "corrupt" => std::fs::write(&path, b"bad").expect("corrupt"),
                "oversize" => {
                    let bytes = vec![0_u8; max_compressed_segment_bytes() + 1];
                    std::fs::write(&path, bytes).expect("oversize");
                }
                "symlink" => {
                    std::fs::remove_file(&path).expect("remove");
                    symlink(&fixture.database, &path).expect("symlink");
                }
                "directory" => {
                    std::fs::remove_file(&path).expect("remove");
                    std::fs::create_dir(&path).expect("directory");
                }
                "unreadable" => set_mode(&path, 0o000),
                _ => unreachable!("static fixture kind"),
            }
            let error = view.commit_segment(&request).expect_err("replay failure");
            assert_eq!(error.code(), "XTR-STORE-OBJECT-CORRUPT", "{kind}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn recording_identity_prevents_cross_recording_object_deduplication() {
        let fixture = on_disk_store("commit-no-cross-dedup");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let left = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let right = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&left).expect("left anchor");
        view.begin_recording(&right).expect("right anchor");
        let left_receipt = view
            .commit_segment(&segment_request(project_id, left.recording_id, 0, &[2]))
            .expect("left");
        let right_receipt = view
            .commit_segment(&segment_request(project_id, right.recording_id, 0, &[2]))
            .expect("right");
        assert_ne!(left_receipt.object_hash, right_receipt.object_hash);
        assert_eq!(segment_count(&fixture.store), 2);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_object_is_verified_before_new_metadata_is_inserted() {
        let fixture = on_disk_store("commit-preexisting");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        let request = segment_request(project_id, anchor.recording_id, 0, &[2]);
        let receipt = view.commit_segment(&request).expect("first");
        delete_segment_row(&fixture.store, anchor.recording_id, 0);
        assert_eq!(
            view.commit_segment(&request).expect("reuse verified object").disposition,
            SegmentCommitDisposition::Inserted
        );
        delete_segment_row(&fixture.store, anchor.recording_id, 0);
        std::fs::write(object_path(&fixture.root, receipt.object_hash), b"corrupt")
            .expect("corrupt object");
        let error = view.commit_segment(&request).expect_err("corrupt destination");
        assert_eq!(error.code(), "XTR-STORE-OBJECT-CORRUPT");
        assert_eq!(segment_count(&fixture.store), 0);
    }

    #[cfg(unix)]
    #[test]
    fn valid_preexisting_differently_compressed_object_uses_its_actual_size() {
        let fixture = on_disk_store("commit-preexisting-compression");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        let request = segment_request(project_id, anchor.recording_id, 0, &[2]);
        let mut large = request.events.clone();
        large[0].event.as_mut().expect("event").symbol = "x".repeat(500_000);
        let request = SegmentCommitRequest { events: large, ..request };
        let logical = encode_logical_segment(&XtfSegmentInput {
            project_id,
            recording_id: anchor.recording_id,
            segment_ordinal: 0,
            events: request.events.clone(),
        })
        .expect("logical");
        let default = compress_logical_bytes(logical.logical_bytes()).expect("default");
        let alternate =
            crate::xtf::compress_logical_at_level(logical.logical_bytes(), 19).expect("alternate");
        assert_ne!(default.len(), alternate.len());
        let destination = object_path(&fixture.root, logical.content_hash());
        ensure_object_parent(
            &ProjectRootBinding::new(&fixture.root, fixture.database.clone(), CorrelationId::new())
                .expect("admitted project root"),
            &destination,
            CorrelationId::new(),
        )
        .expect("object parent");
        write_synced_file(&destination, &alternate, CorrelationId::new()).expect("preplace");
        sync_directory(
            destination.parent().expect("parent"),
            CorrelationId::new(),
            "XTR-STORE-ATOMIC-INSTALL",
        )
        .expect("sync");

        let receipt = view.commit_segment(&request).expect("commit preexisting");
        assert_eq!(receipt.disposition, SegmentCommitDisposition::Inserted);
        assert_eq!(receipt.compressed_bytes, u64::try_from(alternate.len()).expect("size"));
        assert_segment_row(&fixture.store, anchor.recording_id, 0, &receipt, 2, 2, 1);
        assert_eq!(
            view.commit_segment(&request).expect("replay").compressed_bytes,
            receipt.compressed_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn commit_segment_revalidates_root_and_rejects_wrapper_mismatch() {
        let fixture = on_disk_store("commit-root-revalidate");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        let mismatch = SegmentCommitRequest {
            project_id,
            recording_id: anchor.recording_id,
            segment_ordinal: 0,
            events: vec![XtfEventEnvelope {
                recording_seq: 2,
                event: Some(RecordingEvent {
                    event_id: "mismatch".to_owned(),
                    recording_seq: 3,
                    ..RecordingEvent::default()
                }),
            }],
        };
        assert_eq!(
            view.commit_segment(&mismatch).expect_err("wrapper mismatch").code(),
            "XTR-STORE-SEGMENT-VALIDATION"
        );
        set_mode(&fixture.root, 0o755);
        let error = view
            .commit_segment(&segment_request(project_id, anchor.recording_id, 0, &[2]))
            .expect_err("unsafe root");
        assert_eq!(error.kind(), RecordingStoreErrorKind::Permission);
        assert_eq!(segment_count(&fixture.store), 0);
    }

    #[test]
    fn sequence_blobs_round_trip_the_full_unsigned_domain() {
        let correlation_id = CorrelationId::new();
        for sequence in [0, 2, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                decode_sequence(&sequence.to_be_bytes(), correlation_id).expect("continuity blob"),
                sequence
            );
            assert_eq!(
                decode_stored_sequence(&sequence.to_be_bytes(), correlation_id)
                    .expect("stored blob"),
                sequence
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn u64_max_existing_segment_replays_before_continuity_and_blocks_append() {
        let fixture = on_disk_store("max-replay");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        let request = segment_request(project_id, anchor.recording_id, 0, &[u64::MAX]);
        let encoded = crate::xtf::encode_segment(&XtfSegmentInput {
            project_id,
            recording_id: anchor.recording_id,
            segment_ordinal: 0,
            events: request.events.clone(),
        })
        .expect("max object");
        let destination = object_path(&fixture.root, encoded.content_hash());
        ensure_object_parent(
            &ProjectRootBinding::new(&fixture.root, fixture.database.clone(), CorrelationId::new())
                .expect("admitted project root"),
            &destination,
            CorrelationId::new(),
        )
        .expect("parent");
        write_synced_file(&destination, encoded.compressed_bytes(), CorrelationId::new())
            .expect("object");
        let connection = fixture.store.lock().expect("connection");
        connection
            .execute(
                "INSERT INTO recording_segments \
                 (recording_id, segment_ordinal, object_hash, first_recording_seq, \
                  last_recording_seq, event_count, uncompressed_bytes, compressed_bytes, checksum) \
                 VALUES (?1, 0, ?2, ?3, ?3, 1, ?4, ?5, ?6)",
                rusqlite::params![
                    anchor.recording_id.as_uuid().as_bytes().to_vec(),
                    encoded.content_hash().as_bytes().to_vec(),
                    u64::MAX.to_be_bytes().to_vec(),
                    i64::try_from(encoded.logical_bytes().len()).expect("size"),
                    i64::try_from(encoded.compressed_bytes().len()).expect("size"),
                    encoded.footer_prefix_digest().as_bytes().to_vec(),
                ],
            )
            .expect("segment row");
        drop(connection);
        assert_eq!(
            view.commit_segment(&request).expect("exact max replay").disposition,
            SegmentCommitDisposition::ExactReplay
        );
        let append = segment_request(project_id, anchor.recording_id, 1, &[u64::MAX]);
        assert_eq!(
            view.commit_segment(&append).expect_err("max append").code(),
            "XTR-STORE-SEGMENT-CONTINUITY"
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_same_process_exact_commits_serialize_through_the_shared_writer() {
        let fixture = on_disk_store("commit-concurrent");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        fixture
            .store
            .recording_store(&fixture.root)
            .expect("view")
            .begin_recording(&anchor)
            .expect("anchor");
        let request = segment_request(project_id, anchor.recording_id, 0, &[2]);
        let barrier = std::sync::Barrier::new(3);
        let (left, right) = std::thread::scope(|scope| {
            let left_store = fixture.store.clone();
            let right_store = fixture.store.clone();
            let root = &fixture.root;
            let left_request = request.clone();
            let right_request = request.clone();
            let left_barrier = &barrier;
            let right_barrier = &barrier;
            let left = scope.spawn(move || {
                left_barrier.wait();
                left_store
                    .recording_store(root)
                    .expect("left view")
                    .commit_segment(&left_request)
                    .expect("left commit")
            });
            let right = scope.spawn(move || {
                right_barrier.wait();
                right_store
                    .recording_store(root)
                    .expect("right view")
                    .commit_segment(&right_request)
                    .expect("right commit")
            });
            barrier.wait();
            (left.join().expect("left thread"), right.join().expect("right thread"))
        });
        assert!(
            matches!(left.disposition, SegmentCommitDisposition::Inserted)
                || matches!(right.disposition, SegmentCommitDisposition::Inserted)
        );
        assert!(
            matches!(left.disposition, SegmentCommitDisposition::ExactReplay)
                || matches!(right.disposition, SegmentCommitDisposition::ExactReplay)
        );
        assert_eq!(segment_count(&fixture.store), 1);
    }

    #[cfg(unix)]
    #[test]
    fn exact_replay_releases_connection_before_object_verification() {
        let fixture = on_disk_store("replay-connection");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let target_request = segment_request(project_id, anchor.recording_id, 0, &[2]);
        fixture
            .store
            .recording_store(&fixture.root)
            .expect("view")
            .begin_recording(&anchor)
            .expect("anchor");
        fixture
            .store
            .recording_store(&fixture.root)
            .expect("view")
            .commit_segment(&target_request)
            .expect("insert");
        let unrelated_anchor =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let unrelated_request = segment_request(project_id, unrelated_anchor.recording_id, 0, &[2]);
        let unrelated_view = fixture.store.recording_store(&fixture.root).expect("view");
        unrelated_view.begin_recording(&unrelated_anchor).expect("unrelated anchor");
        unrelated_view.commit_segment(&unrelated_request).expect("unrelated insert");
        let pause = std::sync::Arc::new(ReplayPause {
            recording_id: anchor.recording_id,
            segment_ordinal: target_request.segment_ordinal,
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        let _pause_install = install_replay_pause(pause.clone());
        assert_eq!(
            unrelated_view
                .commit_segment(&unrelated_request)
                .expect("unrelated replay")
                .disposition,
            SegmentCommitDisposition::ExactReplay,
            "a differently keyed replay must not consume the target pause"
        );
        std::thread::scope(|scope| {
            let store = fixture.store.clone();
            let root = &fixture.root;
            let request = target_request.clone();
            let replay = scope.spawn(move || {
                store.recording_store(root).expect("view").commit_segment(&request).expect("replay")
            });
            pause.entered.wait();
            let mut release = ReplayReleaseGuard::new(pause.clone());
            assert!(fixture.store.try_lock_connection().is_some());
            release.release();
            assert_eq!(
                replay.join().expect("thread").disposition,
                SegmentCommitDisposition::ExactReplay
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_publish_no_replace_handles_a_real_already_exists_race() {
        use std::os::unix::fs::MetadataExt as _;

        let fixture = on_disk_store("already-exists-race");
        let project_id = ProjectId::new();
        let recording_id = RecordingId::new();
        let request = segment_request(project_id, recording_id, 0, &[2]);
        let logical = encode_logical_segment(&XtfSegmentInput {
            project_id,
            recording_id,
            segment_ordinal: 0,
            events: request.events.clone(),
        })
        .expect("logical");
        let mut candidate = SegmentMetadata::from_logical(&logical, &request, CorrelationId::new())
            .expect("metadata");
        let compressed = compress_logical_bytes(logical.logical_bytes()).expect("compressed");
        candidate.compressed_bytes = i64::try_from(compressed.len()).expect("size");
        let left = fixture.root.join("race-left.zst");
        let right = fixture.root.join("race-right.zst");
        let destination = fixture.root.join("race-destination.zst");
        write_synced_file(&left, &compressed, CorrelationId::new()).expect("left staging");
        write_synced_file(&right, &compressed, CorrelationId::new()).expect("right staging");
        let barrier = std::sync::Barrier::new(3);
        let (left_result, right_result) = std::thread::scope(|scope| {
            let left_barrier = &barrier;
            let right_barrier = &barrier;
            let left_candidate = candidate.clone();
            let right_candidate = candidate.clone();
            let left_destination = &destination;
            let right_destination = &destination;
            let left_source = &left;
            let right_source = &right;
            let left = scope.spawn(move || {
                left_barrier.wait();
                publish_no_replace(
                    left_source,
                    left_destination,
                    &left_candidate,
                    CorrelationId::new(),
                    || {},
                )
            });
            let right = scope.spawn(move || {
                right_barrier.wait();
                publish_no_replace(
                    right_source,
                    right_destination,
                    &right_candidate,
                    CorrelationId::new(),
                    || {},
                )
            });
            barrier.wait();
            (left.join().expect("left thread"), right.join().expect("right thread"))
        });
        assert_eq!(left_result.expect("left publish"), candidate.compressed_bytes);
        assert_eq!(right_result.expect("right publish"), candidate.compressed_bytes);
        let persisted = read_bounded_regular_file(&destination, CorrelationId::new(), false)
            .expect("destination");
        verify_compressed_segment(&persisted, logical.content_hash()).expect("destination verify");
        let destination_metadata = std::fs::metadata(&destination).expect("destination metadata");
        let left_metadata = std::fs::metadata(&left).expect("left metadata");
        let right_metadata = std::fs::metadata(&right).expect("right metadata");
        assert!(
            destination_metadata.ino() == left_metadata.ino()
                || destination_metadata.ino() == right_metadata.ino()
        );
    }

    #[cfg(unix)]
    #[test]
    fn injected_commit_boundary_failures_never_create_a_dangling_segment_row() {
        let pre_commit = [
            "before-logical-write",
            "after-logical-sync",
            "before-compression",
            "after-compression-before-write",
            "after-compressed-sync",
            "before-hard-link",
            "hard-link-syscall",
            "after-hard-link-before-readback",
            "after-hard-link",
            "before-destination-object-directory-fsync",
            "after-object-directory-sync",
            "before-transaction",
            "before-transaction-commit",
        ];
        for point in pre_commit {
            let fixture = on_disk_store(point);
            let project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            let anchor =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            view.begin_recording(&anchor).expect("anchor");
            let request = segment_request(project_id, anchor.recording_id, 0, &[2]);
            let logical = encode_logical_segment(&XtfSegmentInput {
                project_id,
                recording_id: anchor.recording_id,
                segment_ordinal: 0,
                events: request.events.clone(),
            })
            .expect("logical");
            let destination = object_path(&fixture.root, logical.content_hash());
            set_commit_failpoint(Some(point));
            let result = view.commit_segment(&request);
            assert!(commit_failpoint_fired(), "{point} hook did not fire");
            set_commit_failpoint(None);
            let error = result.expect_err("{point} must fail before SQL commit");
            if point == "hard-link-syscall"
                || point == "after-hard-link-before-readback"
                || point == "before-destination-object-directory-fsync"
            {
                assert_eq!(error.code(), "XTR-STORE-ATOMIC-INSTALL");
            }
            assert_eq!(segment_count(&fixture.store), 0, "{point} left a segment row");
            if matches!(
                point,
                "after-hard-link-before-readback"
                    | "after-hard-link"
                    | "before-destination-object-directory-fsync"
                    | "after-object-directory-sync"
                    | "before-transaction"
                    | "before-transaction-commit"
            ) {
                let object = read_bounded_regular_file(&destination, CorrelationId::new(), false)
                    .expect("verified orphan");
                verify_compressed_segment(&object, logical.content_hash()).expect("orphan valid");
                let staged = staging_compressed_paths(&fixture.root, anchor.recording_id);
                assert_eq!(staged.len(), 1, "{point} must retain its published staging link");
                let staged_bytes =
                    read_bounded_regular_file(&staged[0], CorrelationId::new(), true)
                        .expect("staging link");
                verify_compressed_segment(&staged_bytes, logical.content_hash())
                    .expect("staging link valid");
                assert_eq!(
                    std::fs::metadata(&staged[0]).expect("staging metadata").ino(),
                    std::fs::metadata(&destination).expect("destination metadata").ino(),
                    "{point} staging path must remain a hard link to the orphan"
                );
                if point == "after-hard-link" {
                    let receipt = view.commit_segment(&request).expect("orphan retry");
                    assert_eq!(receipt.disposition, SegmentCommitDisposition::Inserted);
                    assert_eq!(segment_count(&fixture.store), 1);
                    let after =
                        read_bounded_regular_file(&destination, CorrelationId::new(), false)
                            .expect("orphan retained");
                    verify_compressed_segment(&after, logical.content_hash())
                        .expect("orphan still valid");
                }
            } else {
                assert!(!destination.exists(), "{point} unexpectedly published an object");
                assert!(
                    staging_compressed_paths(&fixture.root, anchor.recording_id).is_empty(),
                    "{point} left a pre-publication staging compressed file"
                );
            }
        }

        let fixture = on_disk_store("after-commit");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        set_commit_failpoint(Some("after-commit-before-cleanup"));
        let receipt = view
            .commit_segment(&segment_request(project_id, anchor.recording_id, 0, &[2]))
            .expect("committed success despite cleanup fault");
        assert!(commit_failpoint_fired());
        set_commit_failpoint(None);
        assert_eq!(receipt.disposition, SegmentCommitDisposition::Inserted);
        assert_eq!(segment_count(&fixture.store), 1);
        let committed_path = object_path(&fixture.root, receipt.object_hash);
        let object = read_bounded_regular_file(&committed_path, CorrelationId::new(), false)
            .expect("committed object");
        verify_compressed_segment(&object, receipt.object_hash).expect("committed verification");
        let staging_recording =
            fixture.root.join("staging").join(anchor.recording_id.as_uuid().to_string());
        assert!(
            std::fs::read_dir(staging_recording).expect("staging recording").next().is_some(),
            "the post-commit boundary must preserve staging residue"
        );

        let fixture = on_disk_store("cleanup-staging-fsync");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let anchor = request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        view.begin_recording(&anchor).expect("anchor");
        set_commit_failpoint(Some("cleanup-staging-directory-fsync"));
        let receipt = view
            .commit_segment(&segment_request(project_id, anchor.recording_id, 0, &[2]))
            .expect("committed despite cleanup sync failure");
        assert!(commit_failpoint_fired());
        set_commit_failpoint(None);
        assert_eq!(segment_count(&fixture.store), 1);
        let object = read_bounded_regular_file(
            &object_path(&fixture.root, receipt.object_hash),
            CorrelationId::new(),
            false,
        )
        .expect("final object");
        verify_compressed_segment(&object, receipt.object_hash).expect("final verification");
    }

    #[cfg(unix)]
    #[test]
    fn observed_catalog_reads_are_bounded_project_scoped_and_include_legacy_unmatched() {
        let fixture = on_disk_store("observed-query-pages");
        let project_a = ProjectId::new();
        let project_b = ProjectId::new();
        insert_project(&fixture.store, project_a);
        insert_project(&fixture.store, project_b);
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let mut linked_a =
            request(project_a, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked_a.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        view.begin_recording(&linked_a).expect("linked A");
        let mut linked_b =
            request(project_b, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked_b.endpoint_observation = linked_a.endpoint_observation.clone();
        view.begin_recording(&linked_b).expect("linked B");
        let unmatched =
            request(project_a, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        view.begin_recording(&unmatched).expect("unmatched");
        let legacy = request(project_a, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        view.begin_recording(&legacy).expect("legacy anchor");
        fixture
            .store
            .lock()
            .expect("connection")
            .execute(
                "DELETE FROM recording_endpoint_observations WHERE recording_id=?1",
                [legacy.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("remove legacy sidecar");

        let (endpoints_a, more_a) =
            view.list_observed_endpoints(project_a, None, 1).expect("endpoints A");
        let (endpoints_b, more_b) =
            view.list_observed_endpoints(project_b, None, 1).expect("endpoints B");
        assert_eq!(endpoints_a.len(), 1);
        assert_eq!(endpoints_b.len(), 1);
        assert!(!more_a && !more_b);
        assert_ne!(endpoints_a[0].operation_id, endpoints_b[0].operation_id);
        let guessed_cross_project = view
            .list_operation_recordings(project_a, endpoints_b[0].operation_id, None, 1)
            .expect_err("cross-project operation must be hidden");
        let unknown = view
            .list_operation_recordings(project_a, xtrace_domain::OperationId::new(), None, 1)
            .expect_err("unknown operation");
        assert_eq!(guessed_cross_project.kind(), RecordingStoreErrorKind::NotFound);
        assert_eq!(unknown.kind(), RecordingStoreErrorKind::NotFound);
        assert_eq!(guessed_cross_project.code(), unknown.code());

        let (linked_rows, linked_more) = view
            .list_operation_recordings(project_a, endpoints_a[0].operation_id, None, 1)
            .expect("linked recordings");
        assert_eq!(linked_rows.len(), 1);
        assert!(!linked_more);
        assert_eq!(linked_rows[0].metadata.recording_id, linked_a.recording_id);
        assert_eq!(linked_rows[0].operation_id, Some(endpoints_a[0].operation_id));

        let (first, has_more) =
            view.list_unmatched_recordings(project_a, None, 1).expect("first unmatched page");
        assert_eq!(first.len(), 1);
        assert!(has_more);
        let after = ObservedRecordingKey {
            opened_at: first[0].metadata.opened_at.clone(),
            recording_id: first[0].metadata.recording_id,
        };
        let (second, has_more) = view
            .list_unmatched_recordings(project_a, Some(&after), 1)
            .expect("second unmatched page");
        assert_eq!(second.len(), 1);
        assert!(!has_more);
        let rows = first.iter().chain(&second).collect::<Vec<_>>();
        assert!(rows.iter().any(|row| row.metadata.recording_id == unmatched.recording_id));
        assert!(rows.iter().any(|row| row.metadata.recording_id == legacy.recording_id
            && row.unmatched_reason.is_none()));
    }

    #[cfg(unix)]
    #[test]
    fn operation_recording_query_rejects_orphaned_operation_even_on_empty_page() {
        let fixture = on_disk_store("observed-query-orphan");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let mut linked =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        view.begin_recording(&linked).expect("linked recording");
        let (endpoints, _) = view.list_observed_endpoints(project_id, None, 1).expect("endpoint");
        let operation_id = endpoints[0].operation_id;
        fixture
            .store
            .lock()
            .expect("connection")
            .execute(
                "DELETE FROM recording_endpoint_observations WHERE operation_id=?1",
                [operation_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("delete all linked observations");

        let error = view
            .list_operation_recordings(project_id, operation_id, None, 1)
            .expect_err("orphaned operation must fail closed rather than return empty page");
        assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption);
    }

    #[cfg(unix)]
    #[test]
    fn observed_recording_queries_preserve_canonical_v4_and_v7_recording_ids() {
        let fixture = on_disk_store("observed-query-v4-recording-id");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let uuid_v4_linked =
            uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("UUIDv4");
        let uuid_v4_unmatched =
            uuid::Uuid::parse_str("d9428888-122b-4d34-9f4a-123456789abc").expect("UUIDv4");
        let uuid_v4_legacy =
            uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d47a").expect("UUIDv4");
        let mut linked = request(
            project_id,
            RecordingId::from_uuid(uuid_v4_linked),
            RuntimeSessionId::new(),
            opened_at(),
        );
        let mut linked_v7 =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        linked_v7.endpoint_observation = linked.endpoint_observation.clone();
        view.begin_recording(&linked).expect("linked recording");
        view.begin_recording(&linked_v7).expect("UUIDv7 linked recording");
        let unmatched = request(
            project_id,
            RecordingId::from_uuid(uuid_v4_unmatched),
            RuntimeSessionId::new(),
            opened_at(),
        );
        view.begin_recording(&unmatched).expect("unmatched recording");
        let unmatched_v7 =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        view.begin_recording(&unmatched_v7).expect("UUIDv7 unmatched recording");
        let legacy = request(
            project_id,
            RecordingId::from_uuid(uuid_v4_legacy),
            RuntimeSessionId::new(),
            opened_at(),
        );
        view.begin_recording(&legacy).expect("legacy recording");
        fixture
            .store
            .lock()
            .expect("connection")
            .execute(
                "DELETE FROM recording_endpoint_observations WHERE recording_id=?1",
                [legacy.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("remove sidecar to model historical recording");
        let (endpoints, _) = view.list_observed_endpoints(project_id, None, 1).expect("endpoint");
        let operation_id = endpoints[0].operation_id;

        let mut linked_ids = Vec::new();
        let mut after = None;
        loop {
            let (page, has_more) = view
                .list_operation_recordings(project_id, operation_id, after.as_ref(), 1)
                .expect("linked query accepts canonical UUIDv4 and UUIDv7 IDs");
            assert_eq!(page.len(), 1);
            linked_ids.push(page[0].metadata.recording_id);
            after = page.last().map(|row| ObservedRecordingKey {
                opened_at: row.metadata.opened_at.clone(),
                recording_id: row.metadata.recording_id,
            });
            if !has_more {
                break;
            }
        }
        assert_eq!(linked_ids.len(), 2);
        assert!(linked_ids.contains(&linked.recording_id));
        assert!(linked_ids.contains(&linked_v7.recording_id));
        assert!(linked_ids.iter().any(|id| id.as_uuid() == uuid_v4_linked));

        let mut unmatched_ids = Vec::new();
        after = None;
        loop {
            let (page, has_more) = view
                .list_unmatched_recordings(project_id, after.as_ref(), 1)
                .expect("unmatched query accepts canonical UUIDv4 and UUIDv7 IDs");
            assert_eq!(page.len(), 1);
            unmatched_ids.push(page[0].metadata.recording_id);
            after = page.last().map(|row| ObservedRecordingKey {
                opened_at: row.metadata.opened_at.clone(),
                recording_id: row.metadata.recording_id,
            });
            if !has_more {
                break;
            }
        }
        assert_eq!(unmatched_ids.len(), 3);
        assert!(unmatched_ids.contains(&unmatched.recording_id));
        assert!(unmatched_ids.contains(&unmatched_v7.recording_id));
        assert!(unmatched_ids.iter().any(|id| id.as_uuid() == uuid_v4_unmatched));
        let legacy_page =
            view.list_unmatched_recordings(project_id, None, 10).expect("legacy unmatched page").0;
        assert!(legacy_page.iter().any(|row| {
            row.metadata.recording_id.as_uuid() == uuid_v4_legacy && row.unmatched_reason.is_none()
        }));
        let connection = fixture.store.lock().expect("connection");
        for identifier in [uuid_v4_linked, uuid_v4_unmatched, uuid_v4_legacy] {
            let stored_id: Vec<u8> = connection
                .query_row(
                    "SELECT recording_id FROM recordings WHERE recording_id=?1",
                    [identifier.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .expect("historical recording ID remains unchanged");
            assert_eq!(stored_id, identifier.as_bytes());
        }
    }

    #[cfg(unix)]
    #[test]
    fn observed_recording_queries_reject_invalid_version_and_variant() {
        let invalid_ids = [
            uuid::Uuid::parse_str("f47ac10b-58cc-1372-a567-0e02b2c3d479").expect("UUIDv1"),
            uuid::Uuid::parse_str("f47ac10b-58cc-5372-a567-0e02b2c3d479").expect("UUIDv5"),
            uuid::Uuid::nil(),
            uuid::Uuid::parse_str("01890f3e-7c00-7000-0000-000000000001").expect("non-RFC UUIDv7"),
        ];
        for (index, invalid_id) in invalid_ids.into_iter().enumerate() {
            for linked in [false, true] {
                let fixture =
                    on_disk_store(&format!("observed-query-invalid-recording-id-{index}-{linked}"));
                let project_id = ProjectId::new();
                insert_project(&fixture.store, project_id);
                let view = fixture.store.recording_store(&fixture.root).expect("view");
                let mut recording = request(
                    project_id,
                    RecordingId::from_uuid(invalid_id),
                    RuntimeSessionId::new(),
                    opened_at(),
                );
                if linked {
                    recording.endpoint_observation = EndpointObservationInput {
                        policy_id: Some("spring-orders-v1".to_owned()),
                        application_component: Some("spring-fixture".to_owned()),
                        binding_key: Some("default".to_owned()),
                        method: "POST".to_owned(),
                        route_template: "/orders".to_owned(),
                    };
                }
                view.begin_recording(&recording).expect("recording");
                let error = if linked {
                    let (endpoints, _) =
                        view.list_observed_endpoints(project_id, None, 1).expect("endpoint");
                    view.list_operation_recordings(project_id, endpoints[0].operation_id, None, 10)
                        .expect_err("invalid linked UUID must fail closed")
                } else {
                    view.list_unmatched_recordings(project_id, None, 10)
                        .expect_err("invalid unmatched UUID must fail closed")
                };
                assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption);
                assert!(!error.to_string().contains(&invalid_id.to_string()));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn observed_query_validates_sidecars_and_read_only_open_has_no_write_effect() {
        let fixture = on_disk_store("observed-query-corruption");
        let project_id = ProjectId::new();
        insert_project(&fixture.store, project_id);
        let view = fixture.store.recording_store(&fixture.root).expect("view");
        let mut linked =
            request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
        linked.endpoint_observation = EndpointObservationInput {
            policy_id: Some("spring-orders-v1".to_owned()),
            application_component: Some("spring-fixture".to_owned()),
            binding_key: Some("default".to_owned()),
            method: "POST".to_owned(),
            route_template: "/orders".to_owned(),
        };
        view.begin_recording(&linked).expect("linked recording");
        let (endpoints, _) =
            view.list_observed_endpoints(project_id, None, 1).expect("endpoint read");
        let operation_id = endpoints[0].operation_id;
        fixture.store.lock().expect("connection").execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE recording_endpoint_observations SET method='GET'; PRAGMA ignore_check_constraints=OFF;").expect("corrupt sidecar");
        let error = view
            .list_operation_recordings(project_id, operation_id, None, 1)
            .expect_err("corrupt sidecar");
        assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption);

        let read_only = SqliteStore::open(
            &fixture.database,
            OpenOptions::default().with_must_exist(true).with_read_only(true),
        )
        .expect("read-only store");
        let before: (i64, i64) = fixture
            .store
            .lock()
            .expect("connection")
            .query_row(
                "SELECT (SELECT count(*) FROM recordings),(SELECT count(*) FROM operations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("before counts");
        let readonly_view = read_only.recording_store(&fixture.root).expect("read-only view");
        let query_only: i64 = read_only
            .lock()
            .expect("read-only connection")
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .expect("query only");
        assert_eq!(query_only, 1);
        let _ =
            readonly_view.list_unmatched_recordings(project_id, None, 1).expect("read-only query");
        let after: (i64, i64) = fixture
            .store
            .lock()
            .expect("connection")
            .query_row(
                "SELECT (SELECT count(*) FROM recordings),(SELECT count(*) FROM operations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("after counts");
        assert_eq!(before, after);
    }

    #[cfg(unix)]
    #[test]
    fn observed_endpoint_query_rejects_corrupt_operation_and_link_shapes() {
        for (label, mutation) in [
            (
                "bad-operation-id",
                "PRAGMA ignore_check_constraints=ON; PRAGMA foreign_keys=OFF; UPDATE operations SET operation_id=zeroblob(16); PRAGMA foreign_keys=ON;",
            ),
            (
                "bad-operation-tuple",
                "PRAGMA ignore_check_constraints=ON; UPDATE operations SET method='PUT'; PRAGMA ignore_check_constraints=OFF;",
            ),
            (
                "bad-operation-fingerprint",
                "UPDATE operations SET endpoint_fingerprint=zeroblob(32);",
            ),
            (
                "bad-sidecar-policy",
                "PRAGMA ignore_check_constraints=ON; UPDATE recording_endpoint_observations SET observation_policy_id='private-policy'; PRAGMA ignore_check_constraints=OFF;",
            ),
            (
                "bad-sidecar-project",
                "PRAGMA foreign_keys=OFF; UPDATE recording_endpoint_observations SET project_id=zeroblob(16); PRAGMA foreign_keys=ON;",
            ),
        ] {
            let fixture = on_disk_store(label);
            let project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            let mut linked =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            linked.endpoint_observation = EndpointObservationInput {
                policy_id: Some("spring-orders-v1".to_owned()),
                application_component: Some("spring-fixture".to_owned()),
                binding_key: Some("default".to_owned()),
                method: "POST".to_owned(),
                route_template: "/orders".to_owned(),
            };
            view.begin_recording(&linked).expect("linked recording");
            fixture
                .store
                .lock()
                .expect("connection")
                .execute_batch(mutation)
                .expect("corrupt database fixture");
            let error = view
                .list_observed_endpoints(project_id, None, 1)
                .expect_err("corrupt endpoint identity");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption, "{label}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn unmatched_query_rejects_unknown_reason_and_invalid_policy_context_shape() {
        for (label, mutation) in [
            (
                "bad-unmatched-reason",
                "PRAGMA ignore_check_constraints=ON; UPDATE recording_endpoint_observations SET reason_code='private-canary'; PRAGMA ignore_check_constraints=OFF;",
            ),
            (
                "bad-unmatched-policy",
                "PRAGMA ignore_check_constraints=ON; UPDATE recording_endpoint_observations SET observation_policy_id='private-policy'; PRAGMA ignore_check_constraints=OFF;",
            ),
        ] {
            let fixture = on_disk_store(label);
            let project_id = ProjectId::new();
            insert_project(&fixture.store, project_id);
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            let unmatched =
                request(project_id, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            view.begin_recording(&unmatched).expect("unmatched recording");
            fixture
                .store
                .lock()
                .expect("connection")
                .execute_batch(mutation)
                .expect("corrupt unmatched fixture");
            let error = view
                .list_unmatched_recordings(project_id, None, 1)
                .expect_err("corrupt unmatched sidecar");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption, "{label}");
        }
    }

    #[cfg(unix)]
    struct Fixture {
        base: PathBuf,
        root: PathBuf,
        database: PathBuf,
        store: SqliteStore,
    }

    #[cfg(unix)]
    fn on_disk_store(label: &str) -> Fixture {
        let base = tempdir(label);
        let root = base.join("project");
        std::fs::create_dir(&root).expect("project root");
        set_mode(&root, 0o700);
        let database = root.join("metadata.sqlite3");
        let store = SqliteStore::open(&database, OpenOptions::default()).expect("open database");
        set_mode(&database, 0o600);
        Fixture { base, root, database, store }
    }

    #[cfg(unix)]
    fn tempdir(label: &str) -> PathBuf {
        let index = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        let root = AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        root.create_private_child(&format!(
            "xtrace-recording-store-{label}-{}-{index}",
            std::process::id()
        ))
        .expect("private recording store test directory")
        .path()
        .to_path_buf()
    }

    #[cfg(unix)]
    fn set_mode(path: impl AsRef<Path>, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
    }

    #[cfg(unix)]
    fn insert_project(store: &SqliteStore, project_id: ProjectId) {
        let connection = store.lock().expect("connection");
        connection
            .execute(
                "INSERT INTO projects \
                 (project_id, canonical_repo_hash, display_name, created_at, last_opened_at, \
                  config_schema_version, effective_config_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    project_id.as_uuid().as_bytes().to_vec(),
                    format!(
                        "b3:{}{}",
                        hex::encode(project_id.as_uuid().as_bytes()),
                        "0".repeat(32)
                    ),
                    "test project",
                    opened_at().to_rfc3339(),
                    opened_at().to_rfc3339(),
                    1_i64,
                    "0".repeat(64),
                ],
            )
            .expect("insert project");
    }

    #[cfg(unix)]
    fn request(
        project_id: ProjectId,
        recording_id: RecordingId,
        runtime_session_id: RuntimeSessionId,
        opened_at: WallTime,
    ) -> BeginRecordingRequest {
        BeginRecordingRequest {
            project_id,
            recording_id,
            runtime_session_id,
            opened_at,
            endpoint_observation: EndpointObservationInput::default(),
        }
    }

    #[cfg(unix)]
    fn segment_request(
        project_id: ProjectId,
        recording_id: RecordingId,
        segment_ordinal: u32,
        sequences: &[u64],
    ) -> SegmentCommitRequest {
        SegmentCommitRequest {
            project_id,
            recording_id,
            segment_ordinal,
            events: sequences.iter().map(|sequence| event(*sequence)).collect(),
        }
    }

    #[cfg(unix)]
    fn event(sequence: u64) -> XtfEventEnvelope {
        XtfEventEnvelope {
            recording_seq: sequence,
            event: Some(RecordingEvent {
                event_id: format!("event-{sequence}"),
                recording_seq: sequence,
                ..RecordingEvent::default()
            }),
        }
    }

    #[cfg(unix)]
    fn opened_at() -> WallTime {
        WallTime::from_parts(2026, 9, 29, 2, 3, 4, 5).expect("fixed time")
    }

    #[cfg(unix)]
    fn assert_recording_row(
        store: &SqliteStore,
        request: &BeginRecordingRequest,
        expected_status: &str,
    ) {
        let connection = store.lock().expect("connection");
        let row: (Vec<u8>, Vec<u8>, String, String) = connection
            .query_row(
                "SELECT project_id, runtime_session_id, status, opened_at \
                 FROM recordings WHERE recording_id = ?1",
                rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("recording row");
        assert_eq!(row.0, request.project_id.as_uuid().as_bytes());
        assert_eq!(row.1, request.runtime_session_id.as_uuid().as_bytes());
        assert_eq!(row.2, expected_status);
        assert_eq!(row.3, request.opened_at.to_rfc3339());
    }

    #[cfg(unix)]
    fn recording_count(store: &SqliteStore) -> i64 {
        let connection = store.lock().expect("connection");
        connection
            .query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get(0))
            .expect("recording count")
    }

    #[cfg(unix)]
    fn segment_count(store: &SqliteStore) -> i64 {
        let connection = store.lock().expect("connection");
        connection
            .query_row("SELECT COUNT(*) FROM recording_segments", [], |row| row.get(0))
            .expect("segment count")
    }

    #[cfg(unix)]
    fn staging_compressed_paths(root: &Path, recording_id: RecordingId) -> Vec<PathBuf> {
        let recording_directory = root.join("staging").join(recording_id.as_uuid().to_string());
        let Ok(entries) = std::fs::read_dir(recording_directory) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("object.xtf.zst"))
            .filter(|path| path.is_file())
            .collect()
    }

    #[cfg(unix)]
    fn delete_segment_row(store: &SqliteStore, recording_id: RecordingId, ordinal: u32) {
        let connection = store.lock().expect("connection");
        connection
            .execute(
                "DELETE FROM recording_segments WHERE recording_id = ?1 AND segment_ordinal = ?2",
                rusqlite::params![recording_id.as_uuid().as_bytes().to_vec(), i64::from(ordinal)],
            )
            .expect("delete segment row");
    }

    #[cfg(unix)]
    fn set_commit_failpoint(point: Option<&'static str>) {
        COMMIT_FAILPOINT.with(|configured| {
            *configured.borrow_mut() = point;
        });
        COMMIT_FAILPOINT_FIRED.with(|fired| fired.set(false));
    }

    #[cfg(unix)]
    fn commit_failpoint_fired() -> bool {
        COMMIT_FAILPOINT_FIRED.with(std::cell::Cell::get)
    }

    #[cfg(unix)]
    fn assert_segment_row(
        store: &SqliteStore,
        recording_id: RecordingId,
        ordinal: u32,
        receipt: &SegmentCommitReceipt,
        first: u64,
        last: u64,
        count: i64,
    ) {
        let connection = store.lock().expect("connection");
        let row: (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64) = connection
            .query_row(
                "SELECT object_hash, first_recording_seq, last_recording_seq, event_count, \
                 uncompressed_bytes, compressed_bytes FROM recording_segments \
                 WHERE recording_id = ?1 AND segment_ordinal = ?2",
                rusqlite::params![recording_id.as_uuid().as_bytes().to_vec(), i64::from(ordinal)],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("segment row");
        assert_eq!(row.0, receipt.object_hash.as_bytes());
        assert_eq!(row.1, first.to_be_bytes());
        assert_eq!(row.2, last.to_be_bytes());
        assert_eq!(row.3, count);
        assert_eq!(row.4, i64::try_from(receipt.uncompressed_bytes).expect("size"));
        assert_eq!(row.5, i64::try_from(receipt.compressed_bytes).expect("size"));
    }

    #[cfg(unix)]
    fn project_count(store: &SqliteStore) -> i64 {
        let connection = store.lock().expect("connection");
        connection
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
            .expect("project count")
    }
}
