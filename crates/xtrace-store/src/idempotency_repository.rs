//! Typed [`SqliteIdempotencyStore`] implementation.
//!
//! The store owns the SQL for the `command_receipts` table and
//! translates SQLite errors into [`PortError`] values so the
//! application layer never sees a raw [`rusqlite::Error`].
//!
//! The store keys receipts by `(project_id, command_kind,
//! idempotency_key)` so a future slice can host several projects in
//! one database without collisions. The primary key also enforces
//! the uniqueness constraint the application facade relies on to
//! detect an idempotency conflict.

use rusqlite::{OptionalExtension as _, Row};
use uuid::Uuid;
use xtrace_application::IdempotencyStore;
use xtrace_application::PortError;
use xtrace_application::PortErrorKind;
use xtrace_application::StoredReceipt;
use xtrace_domain::ids::Id as _;
use xtrace_domain::{CorrelationId, ProjectId, WallTime};

use crate::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};

/// Typed view over the `command_receipts` table.
pub struct SqliteIdempotencyStore<'store> {
    store: &'store SqliteStore,
}

impl<'store> SqliteIdempotencyStore<'store> {
    /// Constructs a new idempotency store view over the supplied
    /// SQLite store.
    #[must_use]
    pub const fn new(store: &'store SqliteStore) -> Self {
        Self { store }
    }

    fn map_error(err: StoreError) -> PortError {
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
            StoreErrorKind::Busy => PortErrorKind::Resource,
            StoreErrorKind::Resource => PortErrorKind::Resource,
            StoreErrorKind::Internal => PortErrorKind::Internal,
        };
        let mut builder = PortError::new(kind, err.message(), err.correlation_id());
        if let Some(source) = err.source() {
            builder = builder.with_source(source.to_string());
        }
        builder
    }

    /// Returns the infrastructure correlation ID used for this port
    /// call. The application boundary surfaces the request's
    /// correlation ID and attaches this value as a diagnostic detail;
    /// minting a fresh ID per call prevents the request thread from
    /// sharing the infrastructure identity with another request.
    fn correlation_id(&self) -> CorrelationId {
        CorrelationId::new()
    }
}

impl IdempotencyStore for SqliteIdempotencyStore<'_> {
    fn lookup_receipt(
        &self,
        command_kind: &str,
        idempotency_key: &str,
    ) -> Result<Option<StoredReceipt>, PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let row = conn
            .query_row(
                "SELECT project_id, command_kind, idempotency_key, input_digest, \
                 correlation_id, created_at, receipt_json \
                 FROM command_receipts \
                 WHERE command_kind = ?1 AND idempotency_key = ?2 \
                 LIMIT 1",
                rusqlite::params![command_kind, idempotency_key],
                map_receipt_row,
            )
            .optional()
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        Ok(row)
    }

    fn record_receipt(&self, receipt: &StoredReceipt) -> Result<(), PortError> {
        let correlation_id = self.correlation_id();
        let conn = self.store.lock().map_err(Self::map_error)?;
        let project_id_bytes = receipt.project_id.as_uuid().as_bytes().to_vec();
        // `INSERT OR IGNORE` makes the operation a no-op when a
        // `(project_id, command_kind, idempotency_key)` row already
        // exists. We then check the row count: a rowcount of zero
        // means the receipt already existed; we must compare its
        // `input_digest` against the one we are about to persist
        // and surface an `AlreadyExists` when they differ.
        let result = conn
            .execute(
                "INSERT OR IGNORE INTO command_receipts (\
                 project_id, command_kind, idempotency_key, input_digest, \
                 receipt_json, correlation_id, created_at\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    project_id_bytes,
                    receipt.command_kind,
                    receipt.idempotency_key,
                    receipt.input_digest,
                    receipt.receipt_json,
                    receipt.correlation_id.to_string(),
                    receipt.created_at.to_rfc3339(),
                ],
            )
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        if result == 1 {
            return Ok(());
        }
        // Row already existed. Compare the stored digest to the one
        // we are about to write so a true retry returns `Ok` while a
        // conflicting reuse surfaces as `AlreadyExists`.
        let existing: Option<String> = conn
            .query_row(
                "SELECT input_digest FROM command_receipts \
                 WHERE project_id = ?1 AND command_kind = ?2 AND idempotency_key = ?3",
                rusqlite::params![
                    receipt.project_id.as_uuid().as_bytes().to_vec(),
                    receipt.command_kind,
                    receipt.idempotency_key,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))
            .map_err(Self::map_error)?;
        match existing {
            Some(stored) if stored == receipt.input_digest => Ok(()),
            Some(_) => Err(PortError::new(
                PortErrorKind::AlreadyExists,
                "idempotency key reused with a different canonical input",
                correlation_id,
            )),
            // The row vanished between the INSERT and the SELECT.
            // The application facade treats this as a transient
            // internal failure rather than masking it as success.
            None => Err(PortError::new(
                PortErrorKind::Internal,
                "idempotency row vanished during record",
                correlation_id,
            )),
        }
    }
}

fn map_receipt_row(row: &Row<'_>) -> rusqlite::Result<StoredReceipt> {
    let project_id_bytes: Vec<u8> = row.get(0)?;
    let command_kind: String = row.get(1)?;
    let idempotency_key: String = row.get(2)?;
    let input_digest: String = row.get(3)?;
    let correlation_id_text: String = row.get(4)?;
    let created_at_text: String = row.get(5)?;
    let receipt_json: String = row.get(6)?;

    let mut project_id_arr = [0u8; 16];
    if project_id_bytes.len() != 16 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "column project_id: UUID must be 16 bytes",
            )),
        ));
    }
    project_id_arr.copy_from_slice(&project_id_bytes);
    let project_id = ProjectId::from_uuid(Uuid::from_bytes(project_id_arr));

    let correlation_id = correlation_id_text.parse::<CorrelationId>().map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("column correlation_id: {err}"),
            )),
        )
    })?;
    let created_at = created_at_text.parse::<WallTime>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "column created_at: invalid RFC 3339 timestamp",
            )),
        )
    })?;

    Ok(StoredReceipt {
        project_id,
        command_kind,
        idempotency_key,
        input_digest,
        correlation_id,
        created_at,
        receipt_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::SqliteProjectRepository;
    use xtrace_application::ProjectRepository;
    use xtrace_domain::{Project, ProjectId, RepositoryFingerprint, WallTime};

    fn fixture() -> SqliteStore {
        SqliteStore::open_in_memory(OpenOptions::default()).expect("open in-memory")
    }

    fn sample_project(name: &str) -> Project {
        let created_at = WallTime::from_parts(2026, 9, 28, 12, 0, 0, 0).expect("valid");
        Project {
            id: ProjectId::new(),
            canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/tmp/repo"),
            display_name: name.to_string(),
            created_at,
            last_opened_at: created_at,
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        }
    }

    fn sample_receipt(project_id: ProjectId, key: &str) -> StoredReceipt {
        StoredReceipt {
            project_id,
            command_kind: "initialize_project".to_string(),
            idempotency_key: key.to_string(),
            input_digest: "b3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            correlation_id: CorrelationId::new(),
            created_at: WallTime::now(),
            receipt_json: "{\"kind\":\"project_initialized\"}".to_string(),
        }
    }

    #[test]
    fn lookup_receipt_returns_none_when_missing() {
        let store = fixture();
        let idem = SqliteIdempotencyStore::new(&store);
        let found = idem.lookup_receipt("initialize_project", "absent").expect("lookup");
        assert!(found.is_none());
    }

    #[test]
    fn record_then_lookup_round_trips() {
        let store = fixture();
        let project = sample_project("Example");
        let project_id = project.id();
        SqliteProjectRepository::new(&store).insert_project(&project).expect("insert project");
        let idem = SqliteIdempotencyStore::new(&store);
        let stored = sample_receipt(project_id, "key-1");
        idem.record_receipt(&stored).expect("record");
        let loaded =
            idem.lookup_receipt("initialize_project", "key-1").expect("lookup").expect("present");
        assert_eq!(loaded.command_kind, stored.command_kind);
        assert_eq!(loaded.idempotency_key, stored.idempotency_key);
        assert_eq!(loaded.input_digest, stored.input_digest);
        assert_eq!(loaded.receipt_json, stored.receipt_json);
        assert_eq!(loaded.project_id, project_id);
    }

    #[test]
    fn duplicate_key_with_different_digest_is_rejected() {
        let store = fixture();
        let project = sample_project("Example");
        let project_id = project.id();
        SqliteProjectRepository::new(&store).insert_project(&project).expect("insert project");
        let idem = SqliteIdempotencyStore::new(&store);
        let mut stored = sample_receipt(project_id, "key-2");
        idem.record_receipt(&stored).expect("first");
        stored.input_digest =
            "b3:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let err = idem.record_receipt(&stored).unwrap_err();
        assert_eq!(err.kind(), PortErrorKind::AlreadyExists);
    }

    #[test]
    fn duplicate_key_with_same_digest_is_a_no_op() {
        let store = fixture();
        let project = sample_project("Example");
        let project_id = project.id();
        SqliteProjectRepository::new(&store).insert_project(&project).expect("insert project");
        let idem = SqliteIdempotencyStore::new(&store);
        let stored = sample_receipt(project_id, "key-3");
        idem.record_receipt(&stored).expect("first");
        idem.record_receipt(&stored).expect("second is a no-op");
    }
}
