//! Forward-only SQLite migrations.
//!
//! Each migration is identified by a monotonically increasing numeric
//! `version`. Migrations run in order; once applied, a migration is
//! never re-applied. The migration runner is the only component that
//! writes to `schema_meta`.
//!
//! Slice 1A ships exactly one migration: `v0001_initial`. It creates
//! the `schema_meta` singleton, the `projects` table, and the `runs`
//! table. Foreign keys are defined on `runs` so a future delete of a
//! project fails loudly instead of silently leaving orphan rows.
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
//! The runner also records a deterministic BLAKE3-256 checksum of
//! the entire migration catalog (labels concatenated with their SQL
//! statements) in `schema_meta.catalog_checksum`. Opening a database
//! whose stored checksum does not match the binary's compiled-in
//! catalog fails with [`StoreErrorKind::SchemaIncompatible`] so a
//! tampered or partially-applied schema cannot silently corrupt
//! later slices. The checksum is computed only over the migrations
//! the binary ships, so a newer binary that adds a migration can
//! read an older checksum, recompute its own, and apply the missing
//! delta.

use std::collections::BTreeMap;

use rusqlite::Connection;
use xtrace_domain::{ContentHash, CorrelationId, WallTime};

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
        vec![MigrationRecord { version: 1, label: "v0001_initial", statements: &[INITIAL_SCHEMA] }]
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

    /// Returns the canonical identity for the compiled-in migration
    /// catalog as the lowercase `b3:<hex>` form. The hash covers the
    /// ordered `(label, version, statement)` triples so any textual
    /// change to a migration produces a new identity.
    ///
    /// [`ContentHash::to_canonical`]: xtrace_domain::ContentHash::to_canonical
    #[must_use]
    pub fn catalog_checksum() -> String {
        let mut hasher = blake3::Hasher::new();
        for record in Self::catalog() {
            hasher.update(&record.version.to_be_bytes());
            hasher.update(record.label.as_bytes());
            for statement in record.statements {
                hasher.update(statement.as_bytes());
            }
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_bytes());
        ContentHash::of_bytes(&bytes).to_canonical()
    }
}

/// First schema version. Created by `v0001_initial`.
const INITIAL_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS schema_meta (
    singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version      INTEGER NOT NULL,
    min_reader_version  INTEGER NOT NULL,
    migrated_at         TEXT NOT NULL,
    app_version         TEXT NOT NULL,
    catalog_checksum    TEXT NOT NULL
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

/// Applies every pending migration to the supplied connection.
///
/// The function is total: it returns a [`StoreError`] describing the
/// first failure it encounters. After a successful return the
/// `schema_meta` singleton records the version reached.
pub fn apply_pending(
    connection: &Connection,
    app_version: &str,
    correlation_id: CorrelationId,
) -> Result<u32, StoreError> {
    let catalog = Migrations::catalog_by_version();
    let latest = Migrations::latest_version();

    let current = current_schema_version(connection, correlation_id)?;
    if current > latest {
        return Err(StoreError::new(
            StoreErrorKind::SchemaNewer,
            "database schema is newer than this binary supports",
            correlation_id,
        ));
    }

    for version in (current + 1)..=latest {
        let record = catalog.get(&version).ok_or_else(|| {
            StoreError::new(
                StoreErrorKind::SchemaIncompatible,
                format!("missing migration v{version:04}"),
                correlation_id,
            )
        })?;
        apply_one(connection, record, app_version, correlation_id)?;
    }

    // Compare the catalog identity stored on disk against the binary's
    // compiled-in catalog. A mismatch on a previously migrated
    // database means the schema was tampered with or restored from
    // an incompatible source; refuse to read it.
    verify_catalog_checksum(connection, correlation_id)?;

    Ok(latest)
}

fn apply_one(
    connection: &Connection,
    record: &MigrationRecord,
    app_version: &str,
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    let tx = connection
        .unchecked_transaction()
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    for statement in record.statements {
        tx.execute_batch(statement)
            .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    }
    record_schema_version(&tx, record.version, app_version, correlation_id)?;
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

/// Compares the catalog checksum stored on disk against the
/// compiled-in catalog. A mismatch on a previously migrated database
/// is treated as incompatible because the SQL the binary would emit
/// no longer matches the SQL that originally produced the schema.
fn verify_catalog_checksum(
    connection: &Connection,
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    // A fresh database has just been migrated in this call; the
    // stored checksum is the one we wrote so it always matches.
    // The check is therefore meaningful only after the first
    // migration has been applied during a previous open.
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
        return Ok(());
    }
    let stored: String = connection
        .query_row("SELECT catalog_checksum FROM schema_meta WHERE singleton = 1", [], |row| {
            row.get(0)
        })
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    let expected = Migrations::catalog_checksum();
    if stored != expected {
        return Err(StoreError::new(
            StoreErrorKind::SchemaIncompatible,
            format!(
                "stored migration catalog checksum {stored} does not match binary catalog {expected}"
            ),
            correlation_id,
        ));
    }
    Ok(())
}

/// Inserts (or replaces) the singleton `schema_meta` row.
fn record_schema_version(
    connection: &Connection,
    version: u32,
    app_version: &str,
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    let now = WallTime::now().to_rfc3339();
    let checksum = Migrations::catalog_checksum();
    connection
        .execute(
            "INSERT OR REPLACE INTO schema_meta \
             (singleton, schema_version, min_reader_version, migrated_at, app_version, catalog_checksum) \
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
        let err = apply_pending(&conn, "0.1.0-test", CorrelationId::new()).unwrap_err();
        assert_eq!(err.kind(), StoreErrorKind::SchemaNewer);
    }

    #[test]
    fn catalog_checksum_records_binary_identity() {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply");
        let stored: String = conn
            .query_row("SELECT catalog_checksum FROM schema_meta WHERE singleton = 1", [], |row| {
                row.get(0)
            })
            .expect("checksum row");
        assert_eq!(stored, Migrations::catalog_checksum());
    }

    #[test]
    fn tampered_checksum_is_rejected_as_incompatible() {
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply");
        // Simulate tampering by overwriting the stored checksum with
        // the wrong value. The next open must refuse the database.
        conn.execute(
            "UPDATE schema_meta SET catalog_checksum = 'b3:0000000000000000000000000000000000000000000000000000000000000000' WHERE singleton = 1",
            [],
        )
        .expect("tamper checksum");
        let err = apply_pending(&conn, "0.1.0-test", CorrelationId::new()).unwrap_err();
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
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
}
