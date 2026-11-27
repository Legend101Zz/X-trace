//! SQLite persistence for parent-child runtime session links and explicit gaps (`v0012_process_linkage`).
//!
//! Persists strictly bounded identifiers, closed enums, millisecond timestamps, and optional
//! 32-byte BLAKE3 correlation token hashes. Raw command arguments, environment maps, executable
//! paths, and raw tokens are never stored.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use xtrace_application::{PortError, PortErrorKind, ProcessLinkagePort};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    ContentHash, CorrelationId, GapReason, RecordingId, RuntimeSessionId, RuntimeSessionLink,
    SessionLinkId, SessionLinkStatus, SpawnKind,
};

use crate::connection::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};

/// Maximum rows returned by a single bounded process-linkage child query.
pub const MAX_CHILD_LINKS_LIMIT: i64 = 1_000;

/// SQLite view implementing [`ProcessLinkagePort`] and direct CRUD/query helpers.
#[derive(Clone, Debug)]
pub struct SqliteProcessLinkageStore {
    store: SqliteStore,
}

impl SqliteProcessLinkageStore {
    /// Creates a process-linkage store view over the shared [`SqliteStore`].
    #[must_use]
    pub const fn new(store: SqliteStore) -> Self {
        Self { store }
    }

    /// Persists one validated [`RuntimeSessionLink`] idempotently.
    ///
    /// Exact replays of an existing `link_id` with identical metadata return `Ok(existing)`;
    /// mismatched metadata for an existing `link_id` or missing foreign-key recordings return
    /// [`PortErrorKind::Conflict`].
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with `Validation`, `Conflict`, or storage failure kinds.
    pub fn record_session_link(
        &self,
        link: &RuntimeSessionLink,
    ) -> Result<RuntimeSessionLink, PortError> {
        let correlation_id = CorrelationId::new();
        link.validate().map_err(|_| {
            PortError::new(
                PortErrorKind::Validation,
                "runtime session link violates structural invariants",
                correlation_id,
            )
        })?;
        let created_at_ms = i64::try_from(link.created_at_ms).map_err(|_| {
            PortError::new(
                PortErrorKind::Validation,
                "runtime session link timestamp is out of bounds",
                correlation_id,
            )
        })?;

        let mut connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sql_error(error, correlation_id))?;

        let link_bytes = link.link_id.as_uuid().as_bytes().to_vec();
        let existing: Option<LinkRow> = tx
            .query_row(
                "SELECT link_id, parent_recording_id, parent_session_id, child_recording_id, \
                        child_session_id, spawn_kind, status, gap_reason, correlation_token_hash, \
                        created_at_ms \
                 FROM runtime_session_links \
                 WHERE link_id = ?1",
                params![&link_bytes],
                read_link_row,
            )
            .optional()
            .map_err(|error| map_sql_error(error, correlation_id))?;

        if let Some(row) = existing {
            let decoded = decode_link_row(row, correlation_id)?;
            if decoded == *link {
                return Ok(decoded);
            }
            return Err(PortError::new(
                PortErrorKind::Conflict,
                "runtime session link identifier already exists with different metadata",
                correlation_id,
            ));
        }

        tx.execute(
            "INSERT INTO runtime_session_links \
             (link_id, parent_recording_id, parent_session_id, child_recording_id, \
              child_session_id, spawn_kind, status, gap_reason, correlation_token_hash, \
              created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                link_bytes,
                link.parent_recording_id.map(|id| id.as_uuid().as_bytes().to_vec()),
                link.parent_session_id.as_uuid().as_bytes().to_vec(),
                link.child_recording_id.map(|id| id.as_uuid().as_bytes().to_vec()),
                link.child_session_id.map(|id| id.as_uuid().as_bytes().to_vec()),
                link.spawn_kind.as_str(),
                link.status.as_str(),
                link.gap_reason.map(GapReason::as_str),
                link.correlation_token_hash.map(|hash| hash.as_bytes().to_vec()),
                created_at_ms,
            ],
        )
        .map_err(|error| map_sql_error(error, correlation_id))?;

        tx.commit().map_err(|error| map_sql_error(error, correlation_id))?;
        Ok(*link)
    }

    /// Lists child links and explicit gap records for `parent_session_id`, ordered deterministically
    /// by `(created_at_ms ASC, link_id ASC)`.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if storage cannot be queried or persisted rows fail integrity decoding.
    pub fn list_child_links(
        &self,
        parent_session_id: RuntimeSessionId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError> {
        let correlation_id = CorrelationId::new();
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        let mut stmt = connection
            .prepare(
                "SELECT link_id, parent_recording_id, parent_session_id, child_recording_id, \
                        child_session_id, spawn_kind, status, gap_reason, correlation_token_hash, \
                        created_at_ms \
                 FROM runtime_session_links \
                 WHERE parent_session_id = ?1 \
                 ORDER BY created_at_ms ASC, link_id ASC \
                 LIMIT ?2",
            )
            .map_err(|error| map_sql_error(error, correlation_id))?;
        let rows = stmt
            .query_map(
                params![parent_session_id.as_uuid().as_bytes().as_slice(), MAX_CHILD_LINKS_LIMIT],
                read_link_row,
            )
            .map_err(|error| map_sql_error(error, correlation_id))?
            .collect::<Result<Vec<LinkRow>, _>>()
            .map_err(|error| map_sql_error(error, correlation_id))?;
        rows.into_iter().map(|row| decode_link_row(row, correlation_id)).collect()
    }

    /// Lists child links and explicit gap records associated with `parent_recording_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if storage cannot be queried or persisted rows fail integrity decoding.
    pub fn list_child_links_for_recording(
        &self,
        parent_recording_id: RecordingId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError> {
        let correlation_id = CorrelationId::new();
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        let mut stmt = connection
            .prepare(
                "SELECT link_id, parent_recording_id, parent_session_id, child_recording_id, \
                        child_session_id, spawn_kind, status, gap_reason, correlation_token_hash, \
                        created_at_ms \
                 FROM runtime_session_links \
                 WHERE parent_recording_id = ?1 \
                 ORDER BY created_at_ms ASC, link_id ASC \
                 LIMIT ?2",
            )
            .map_err(|error| map_sql_error(error, correlation_id))?;
        let rows = stmt
            .query_map(
                params![parent_recording_id.as_uuid().as_bytes().as_slice(), MAX_CHILD_LINKS_LIMIT],
                read_link_row,
            )
            .map_err(|error| map_sql_error(error, correlation_id))?
            .collect::<Result<Vec<LinkRow>, _>>()
            .map_err(|error| map_sql_error(error, correlation_id))?;
        rows.into_iter().map(|row| decode_link_row(row, correlation_id)).collect()
    }

    /// Finds the earliest recorded parent link for `child_session_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if storage cannot be queried or persisted rows fail integrity decoding.
    pub fn find_parent_link(
        &self,
        child_session_id: RuntimeSessionId,
    ) -> Result<Option<RuntimeSessionLink>, PortError> {
        let correlation_id = CorrelationId::new();
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        let row: Option<LinkRow> = connection
            .query_row(
                "SELECT link_id, parent_recording_id, parent_session_id, child_recording_id, \
                        child_session_id, spawn_kind, status, gap_reason, correlation_token_hash, \
                        created_at_ms \
                 FROM runtime_session_links \
                 WHERE child_session_id = ?1 \
                 ORDER BY created_at_ms ASC, link_id ASC \
                 LIMIT 1",
                params![child_session_id.as_uuid().as_bytes().as_slice()],
                read_link_row,
            )
            .optional()
            .map_err(|error| map_sql_error(error, correlation_id))?;
        row.map(|item| decode_link_row(item, correlation_id)).transpose()
    }

    /// Finds the earliest recorded parent link for `child_recording_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] if storage cannot be queried or persisted rows fail integrity decoding.
    pub fn find_parent_link_by_recording(
        &self,
        child_recording_id: RecordingId,
    ) -> Result<Option<RuntimeSessionLink>, PortError> {
        let correlation_id = CorrelationId::new();
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;
        let row: Option<LinkRow> = connection
            .query_row(
                "SELECT link_id, parent_recording_id, parent_session_id, child_recording_id, \
                        child_session_id, spawn_kind, status, gap_reason, correlation_token_hash, \
                        created_at_ms \
                 FROM runtime_session_links \
                 WHERE child_recording_id = ?1 \
                 ORDER BY created_at_ms ASC, link_id ASC \
                 LIMIT 1",
                params![child_recording_id.as_uuid().as_bytes().as_slice()],
                read_link_row,
            )
            .optional()
            .map_err(|error| map_sql_error(error, correlation_id))?;
        row.map(|item| decode_link_row(item, correlation_id)).transpose()
    }
}

impl ProcessLinkagePort for SqliteProcessLinkageStore {
    fn record_session_link(
        &self,
        link: &RuntimeSessionLink,
    ) -> Result<RuntimeSessionLink, PortError> {
        Self::record_session_link(self, link)
    }

    fn list_child_links(
        &self,
        parent_session_id: RuntimeSessionId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError> {
        Self::list_child_links(self, parent_session_id)
    }

    fn list_child_links_for_recording(
        &self,
        parent_recording_id: RecordingId,
    ) -> Result<Vec<RuntimeSessionLink>, PortError> {
        Self::list_child_links_for_recording(self, parent_recording_id)
    }

    fn find_parent_link(
        &self,
        child_session_id: RuntimeSessionId,
    ) -> Result<Option<RuntimeSessionLink>, PortError> {
        Self::find_parent_link(self, child_session_id)
    }

    fn find_parent_link_by_recording(
        &self,
        child_recording_id: RecordingId,
    ) -> Result<Option<RuntimeSessionLink>, PortError> {
        Self::find_parent_link_by_recording(self, child_recording_id)
    }
}

type LinkRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    String,
    String,
    Option<String>,
    Option<Vec<u8>>,
    i64,
);

fn read_link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LinkRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn parse_uuid_id<T: From<uuid::Uuid>>(
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<T, PortError> {
    let parsed = uuid::Uuid::from_slice(bytes).map_err(|_| {
        PortError::new(
            PortErrorKind::Corruption,
            "stored session link UUID blob is malformed",
            correlation_id,
        )
    })?;
    Ok(T::from(parsed))
}

fn parse_gap_reason(value: &str) -> Option<GapReason> {
    match value {
        "child_process_not_instrumented" => Some(GapReason::ChildProcessNotInstrumented),
        "correlation_lost" => Some(GapReason::CorrelationLost),
        "bootstrap_consumed" => Some(GapReason::BootstrapConsumed),
        _ => None,
    }
}

fn decode_link_row(
    row: LinkRow,
    correlation_id: CorrelationId,
) -> Result<RuntimeSessionLink, PortError> {
    let link_id: SessionLinkId = parse_uuid_id(&row.0, correlation_id)?;
    let parent_recording_id: Option<RecordingId> =
        row.1.as_deref().map(|bytes| parse_uuid_id(bytes, correlation_id)).transpose()?;
    let parent_session_id: RuntimeSessionId = parse_uuid_id(&row.2, correlation_id)?;
    let child_recording_id: Option<RecordingId> =
        row.3.as_deref().map(|bytes| parse_uuid_id(bytes, correlation_id)).transpose()?;
    let child_session_id: Option<RuntimeSessionId> =
        row.4.as_deref().map(|bytes| parse_uuid_id(bytes, correlation_id)).transpose()?;
    let spawn_kind = SpawnKind::parse(&row.5).ok_or_else(|| {
        PortError::new(
            PortErrorKind::Corruption,
            "stored session link spawn_kind is invalid",
            correlation_id,
        )
    })?;
    let status = SessionLinkStatus::parse(&row.6).ok_or_else(|| {
        PortError::new(
            PortErrorKind::Corruption,
            "stored session link status is invalid",
            correlation_id,
        )
    })?;
    let gap_reason = row
        .7
        .as_deref()
        .map(|value| {
            parse_gap_reason(value).ok_or_else(|| {
                PortError::new(
                    PortErrorKind::Corruption,
                    "stored session link gap_reason is invalid",
                    correlation_id,
                )
            })
        })
        .transpose()?;
    let correlation_token_hash = row
        .8
        .as_deref()
        .map(|bytes| {
            ContentHash::from_digest_bytes(bytes).ok_or_else(|| {
                PortError::new(
                    PortErrorKind::Corruption,
                    "stored correlation_token_hash digest is malformed",
                    correlation_id,
                )
            })
        })
        .transpose()?;
    let created_at_ms = u64::try_from(row.9).map_err(|_| {
        PortError::new(
            PortErrorKind::Corruption,
            "stored created_at_ms is negative",
            correlation_id,
        )
    })?;

    let link = RuntimeSessionLink {
        link_id,
        parent_recording_id,
        parent_session_id,
        child_recording_id,
        child_session_id,
        spawn_kind,
        status,
        gap_reason,
        correlation_token_hash,
        created_at_ms,
    };
    link.validate().map_err(|_| {
        PortError::new(
            PortErrorKind::Corruption,
            "stored runtime session link violates domain invariants",
            correlation_id,
        )
    })?;
    Ok(link)
}

fn map_store_error(err: StoreError, fallback_corr: CorrelationId) -> PortError {
    let kind = match err.kind() {
        StoreErrorKind::Validation => PortErrorKind::Validation,
        StoreErrorKind::SchemaOlder
        | StoreErrorKind::SchemaNewer
        | StoreErrorKind::SchemaIncompatible => PortErrorKind::Compatibility,
        StoreErrorKind::AlreadyExists => PortErrorKind::AlreadyExists,
        StoreErrorKind::NotFound => PortErrorKind::NotFound,
        StoreErrorKind::Conflict => PortErrorKind::Conflict,
        StoreErrorKind::Corruption => PortErrorKind::Corruption,
        StoreErrorKind::Transport => PortErrorKind::Transport,
        StoreErrorKind::Permission | StoreErrorKind::Busy | StoreErrorKind::Resource => {
            PortErrorKind::Resource
        }
        StoreErrorKind::Internal => PortErrorKind::Internal,
    };
    let corr = if matches!(err.kind(), StoreErrorKind::Internal) {
        fallback_corr
    } else {
        err.correlation_id()
    };
    let mut out = PortError::new(kind, err.message(), corr);
    if let Some(source) = err.source() {
        out = out.with_source(source.to_string());
    }
    out
}

fn map_sql_error(err: rusqlite::Error, correlation_id: CorrelationId) -> PortError {
    map_store_error(StoreError::from_rusqlite(err, correlation_id), correlation_id)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "in-memory SQLite process linkage tests"
)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use xtrace_domain::{ProjectId, hash_correlation_token};

    fn seed_recordings(
        store: &SqliteStore,
        parent_session: RuntimeSessionId,
        child_session: RuntimeSessionId,
    ) -> (RecordingId, RecordingId) {
        let project = ProjectId::new();
        let parent_rec = RecordingId::new();
        let child_rec = RecordingId::new();
        let conn = store.lock().unwrap();
        conn.execute(
            "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, \
             last_opened_at, config_schema_version, effective_config_hash) \
             VALUES (?1, ?2, 'proj', 't', 't', 1, 'cfg')",
            params![project.as_uuid().as_bytes().as_slice(), format!("b3:{project}")],
        )
        .unwrap();
        for (rec, sess) in [(parent_rec, parent_session), (child_rec, child_session)] {
            conn.execute(
                "INSERT INTO recordings (recording_id, project_id, runtime_session_id, status, opened_at) \
                 VALUES (?1, ?2, ?3, 'complete', 't')",
                params![
                    rec.as_uuid().as_bytes().as_slice(),
                    project.as_uuid().as_bytes().as_slice(),
                    sess.as_uuid().as_bytes().as_slice(),
                ],
            )
            .unwrap();
        }
        (parent_rec, child_rec)
    }

    #[test]
    fn crud_idempotency_and_queries_round_trip() {
        let store = SqliteStore::open_in_memory(OpenOptions::default()).unwrap();
        let parent_session = RuntimeSessionId::new();
        let child_session = RuntimeSessionId::new();
        let (parent_rec, child_rec) = seed_recordings(&store, parent_session, child_session);
        let linkage = SqliteProcessLinkageStore::new(store);

        let token_hash = hash_correlation_token("canary-token-xyz").unwrap();
        let linked = RuntimeSessionLink::linked(
            SessionLinkId::new(),
            parent_session,
            Some(parent_rec),
            child_session,
            Some(child_rec),
            SpawnKind::NodeWorker,
            Some(token_hash),
            1_700_000_000_010,
        )
        .unwrap();
        assert_eq!(linkage.record_session_link(&linked).unwrap(), linked);
        assert_eq!(linkage.record_session_link(&linked).unwrap(), linked);

        let mut conflicting = linked;
        conflicting.created_at_ms += 1;
        assert_eq!(
            linkage.record_session_link(&conflicting).unwrap_err().kind(),
            PortErrorKind::Conflict
        );

        let gap = RuntimeSessionLink::uninstrumented_gap(
            SessionLinkId::new(),
            parent_session,
            Some(parent_rec),
            SpawnKind::NodeChildProcess,
            GapReason::ChildProcessNotInstrumented,
            1_700_000_000_020,
        )
        .unwrap();
        linkage.record_session_link(&gap).unwrap();

        let lost = RuntimeSessionLink::correlation_lost(
            SessionLinkId::new(),
            parent_session,
            None,
            None,
            SpawnKind::JvmFork,
            None,
            1_700_000_000_030,
        )
        .unwrap();
        linkage.record_session_link(&lost).unwrap();

        let children = linkage.list_child_links(parent_session).unwrap();
        assert_eq!(children, vec![linked, gap, lost]);
        assert_eq!(linkage.list_child_links_for_recording(parent_rec).unwrap(), vec![linked, gap]);
        assert_eq!(linkage.find_parent_link(child_session).unwrap(), Some(linked));
        assert_eq!(linkage.find_parent_link_by_recording(child_rec).unwrap(), Some(linked));
        assert_eq!(linkage.find_parent_link(RuntimeSessionId::new()).unwrap(), None);
    }
}
