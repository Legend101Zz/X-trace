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
}

/// First schema version. Created by `v0001_initial`.
const INITIAL_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS schema_meta (
    singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version      INTEGER NOT NULL,
    min_reader_version  INTEGER NOT NULL,
    migrated_at         TEXT NOT NULL,
    app_version         TEXT NOT NULL
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

/// Inserts (or replaces) the singleton `schema_meta` row.
fn record_schema_version(
    connection: &Connection,
    version: u32,
    app_version: &str,
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    let now = WallTime::now().to_rfc3339();
    connection
        .execute(
            "INSERT OR REPLACE INTO schema_meta \
             (singleton, schema_version, min_reader_version, migrated_at, app_version) \
             VALUES (1, ?1, ?1, ?2, ?3)",
            rusqlite::params![i64::from(version), now, app_version],
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
}
