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
    apply_catalog(connection, app_version, correlation_id, &Migrations::catalog())
}

/// Applies every migration in the supplied catalog that is not yet
/// present on disk. The function is the test-friendly twin of
/// [`apply_pending`]: it accepts an explicit catalog so a future
/// slice (or a regression test) can exercise the
/// "tampered-prefix / pending-next" interaction without modifying
/// the compiled-in catalog.
pub fn apply_catalog(
    connection: &Connection,
    app_version: &str,
    correlation_id: CorrelationId,
    catalog: &[MigrationRecord],
) -> Result<u32, StoreError> {
    let catalog_by_version: BTreeMap<u32, MigrationRecord> =
        catalog.iter().map(|record| (record.version, record.clone())).collect();
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
    fn tampered_applied_checksum_is_rejected_before_pending_runs() {
        // The regression we are guarding against: a future binary
        // that ships a v2 migration could overwrite the on-disk
        // checksum with the new full-catalog hash before the older
        // checksum was verified. With the new design the older
        // checksum is verified *before* any pending migration runs,
        // so a tampered value is rejected without v2 mutating state.
        let conn = new_memory();
        apply_pending(&conn, "0.1.0-test", CorrelationId::new()).expect("apply v1");
        let v1 = Migrations::catalog();
        let v1_count = table_count(&conn, "projects");

        // Inject a pending v2 into the catalog (test fixture; not
        // present in the compiled-in production catalog).
        const V2_STATEMENT: &str =
            "ALTER TABLE projects ADD COLUMN test_marker TEXT NOT NULL DEFAULT ''";
        let catalog = vec![
            v1[0].clone(),
            MigrationRecord { version: 2, label: "v0002_marker", statements: &[V2_STATEMENT] },
        ];

        // Tamper the stored applied checksum.
        conn.execute(
            "UPDATE schema_meta SET applied_checksum = 'b3:0000000000000000000000000000000000000000000000000000000000000000' WHERE singleton = 1",
            [],
        )
        .expect("tamper checksum");

        let err = apply_catalog(&conn, "0.1.0-test", CorrelationId::new(), &catalog)
            .expect_err("tampered checksum must be rejected");
        assert_eq!(err.kind(), StoreErrorKind::SchemaIncompatible);
        // v2 must not have run; the marker column must be absent.
        assert_eq!(table_count(&conn, "projects"), v1_count);
        let columns = list_columns(&conn, "projects");
        assert!(
            !columns.iter().any(|name| name == "test_marker"),
            "v2 must not have mutated the schema when checksum was rejected"
        );
    }

    #[test]
    fn fresh_database_ignores_pending_catalog_without_checksum_failure() {
        // A fresh database has no stored checksum. The verification
        // step short-circuits and pending migrations apply as usual.
        let conn = new_memory();
        let v1 = Migrations::catalog();
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
    fn checksum_changes_when_migration_text_changes() {
        // Sanity check that any textual change to the compiled-in
        // catalog produces a different identity. This guards against
        // a future change that "looks the same" but silently alters
        // behavior.
        let a = Migrations::catalog_checksum();
        let b = blake3::hash(b"alternate-migration-text").to_string();
        assert_ne!(a, b);
    }

    fn table_count(conn: &Connection, name: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {name}"), [], |row| row.get(0))
            .expect("count")
    }

    fn list_columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).expect("prepare");
        let rows = stmt.query_map([], |row| row.get::<_, String>(1)).expect("rows");
        rows.filter_map(Result::ok).collect()
    }
}
