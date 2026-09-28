//! SQLite store handle and connection management.
//!
//! [`SqliteStore`] is the public type every other crate interacts
//! with. It owns a [`rusqlite::Connection`] wrapped with a `Mutex`,
//! applies the pending migrations at construction time, and exposes
//! the [`SqliteProjectRepository`] view through
//! [`SqliteStore::project_repository`].
//!
//! The store applies the following pragmas on every open:
//!
//! - `foreign_keys = ON` so `STRICT` tables enforce referential
//!   integrity;
//! - `journal_mode = WAL` for concurrent readers and a single writer
//!   without blocking on disk;
//! - `synchronous = NORMAL` per `docs/plans/x-trace/03a-domain-and-storage.md`
//!   §7 (FULL is reserved for migration checkpoints in later
//!   slices);
//! - `busy_timeout = 5000ms` so a brief contention window returns a
//!   typed [`StoreErrorKind::Busy`] rather than failing immediately.
//!
//! [`StoreErrorKind::Busy`]: crate::error::StoreErrorKind::Busy

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;
use xtrace_domain::CorrelationId;

use crate::error::{StoreError, StoreErrorKind};
use crate::migrations;
use crate::project_repository::SqliteProjectRepository;

/// Application binary identifier stored in `schema_meta.app_version`.
pub const STORE_APP_VERSION: &str = concat!("xtrace ", env!("CARGO_PKG_VERSION"));

/// Foreign-key pragma string. Centralized so tests can assert it.
pub const FOREIGN_KEYS_PRAGMA: &str = "PRAGMA foreign_keys = ON";

/// Journal mode pragma string.
pub const JOURNAL_MODE_PRAGMA: &str = "PRAGMA journal_mode = WAL";

/// Synchronous mode pragma string.
///
/// `NORMAL` matches `03a-domain-and-storage.md` §7: it commits without
/// the additional fsync that `FULL` requires while still surviving
/// application-level crashes. `FULL` remains the documented choice
/// for migration checkpoints in later slices.
pub const SYNCHRONOUS_PRAGMA: &str = "PRAGMA synchronous = NORMAL";

/// Busy timeout applied to every connection. Five seconds matches the
/// value used by other local-first products; longer values mask real
/// contention bugs.
pub const BUSY_TIMEOUT_PRAGMA: &str = "PRAGMA busy_timeout = 5000";

/// Maximum schema version this binary can read. Bumped together with
/// new migrations.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Stable ABI version of the store crate. Bumped when the on-disk
/// representation changes in a way that requires all linked code to
/// be rebuilt in lockstep. Independent from [`CURRENT_SCHEMA_VERSION`].
pub const STORE_ABI_VERSION: u32 = 1;

/// Busy timeout configuration. The value is stored on the connection
/// so the [`SqliteStore`] can report the effective timeout to
/// diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusyTimeout {
    millis: u32,
}

impl BusyTimeout {
    /// Constructs a busy timeout. Values above one minute are clamped
    /// because long waits usually hide a real contention bug.
    #[must_use]
    pub const fn from_millis(millis: u32) -> Self {
        let millis = if millis > 60_000 { 60_000 } else { millis };
        Self { millis }
    }

    /// Returns the effective timeout in milliseconds.
    #[must_use]
    pub const fn as_millis(&self) -> u32 {
        self.millis
    }
}

impl Default for BusyTimeout {
    fn default() -> Self {
        Self::from_millis(5_000)
    }
}

/// Open-time configuration. Defaults match what every slice needs;
/// callers only override fields when a test or a maintenance command
/// demands it.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    busy_timeout: BusyTimeout,
    app_version: String,
    correlation_id: CorrelationId,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            busy_timeout: BusyTimeout::default(),
            app_version: STORE_APP_VERSION.to_string(),
            correlation_id: CorrelationId::new(),
        }
    }
}

impl OpenOptions {
    /// Sets the busy timeout applied at open time.
    #[must_use]
    pub fn with_busy_timeout(mut self, timeout: BusyTimeout) -> Self {
        self.busy_timeout = timeout;
        self
    }

    /// Sets the application version stored in `schema_meta.app_version`.
    #[must_use]
    pub fn with_app_version(mut self, version: impl Into<String>) -> Self {
        self.app_version = version.into();
        self
    }

    /// Sets the correlation ID attached to bootstrap diagnostics.
    #[must_use]
    pub fn with_correlation_id(mut self, id: CorrelationId) -> Self {
        self.correlation_id = id;
        self
    }
}

/// Result of opening a store.
#[derive(Clone, Debug)]
pub struct StoreBootstrap {
    /// Absolute path of the SQLite database file. `None` when the
    /// store was opened in-memory.
    pub database_path: Option<PathBuf>,
    /// Schema version this binary initialized the store with. Equal
    /// to [`CURRENT_SCHEMA_VERSION`] for a fresh database or for an
    /// already up-to-date database.
    pub schema_version: u32,
    /// Busy timeout applied to the connection.
    pub busy_timeout: BusyTimeout,
}

/// Bundled SQLite store. Cheap to clone (`Arc` inside).
#[derive(Clone, Debug)]
pub struct SqliteStore {
    inner: std::sync::Arc<Mutex<Connection>>,
    bootstrap: StoreBootstrap,
}

impl SqliteStore {
    /// Opens an in-memory store. Intended for tests.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLite cannot open the connection
    /// or migrations fail.
    pub fn open_in_memory(options: OpenOptions) -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()
            .map_err(|err| StoreError::from_rusqlite(err, options.correlation_id))?;
        Self::from_connection(connection, None, options)
    }

    /// Opens or creates a store at the supplied path. The parent
    /// directory must already exist; the store creates the database
    /// file itself.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLite cannot open the connection,
    /// the parent directory does not exist, or migrations fail.
    pub fn open(path: &Path, options: OpenOptions) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(StoreError::new(
                    StoreErrorKind::Validation,
                    "parent directory of database file does not exist",
                    options.correlation_id,
                ));
            }
        }
        let connection = Connection::open(path)
            .map_err(|err| StoreError::from_rusqlite(err, options.correlation_id))?;
        Self::from_connection(connection, Some(path.to_path_buf()), options)
    }

    /// Wraps a pre-built connection. Exposed for tests that want to
    /// drive migrations themselves.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the pragmas cannot be applied or
    /// migrations fail.
    pub fn from_connection(
        connection: Connection,
        database_path: Option<PathBuf>,
        options: OpenOptions,
    ) -> Result<Self, StoreError> {
        apply_pragmas(&connection, options.busy_timeout, options.correlation_id)?;
        let schema_version =
            migrations::apply_pending(&connection, &options.app_version, options.correlation_id)?;
        let bootstrap =
            StoreBootstrap { database_path, schema_version, busy_timeout: options.busy_timeout };
        Ok(Self { inner: std::sync::Arc::new(Mutex::new(connection)), bootstrap })
    }

    /// Returns the bootstrap snapshot.
    #[must_use]
    pub fn bootstrap(&self) -> &StoreBootstrap {
        &self.bootstrap
    }

    /// Returns a typed [`SqliteProjectRepository`] view over this
    /// store. The repository borrows the connection mutex; callers
    /// must keep the returned reference alive only as long as the
    /// store is.
    #[must_use]
    pub fn project_repository(&self) -> SqliteProjectRepository<'_> {
        SqliteProjectRepository::new(self)
    }

    /// Acquires the underlying connection lock. Used by sibling
    /// repositories (added in later slices) that share the same
    /// connection mutex.
    pub(crate) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        // Locking a `Mutex` only fails when poisoned. Poisoning
        // means a previous holder panicked; treat it as corruption
        // because the database may be in an inconsistent state.
        self.inner.lock().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Corruption,
                "store connection mutex was poisoned by a panic",
                CorrelationId::new(),
            )
        })
    }
}

fn apply_pragmas(
    connection: &Connection,
    busy_timeout: BusyTimeout,
    correlation_id: CorrelationId,
) -> Result<(), StoreError> {
    connection
        .execute_batch(FOREIGN_KEYS_PRAGMA)
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    // `journal_mode = WAL` must be issued outside of a transaction
    // and is silently a no-op on in-memory databases. We issue it
    // unconditionally because the pragma is safe on both kinds.
    connection
        .execute_batch(JOURNAL_MODE_PRAGMA)
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    connection
        .execute_batch(SYNCHRONOUS_PRAGMA)
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    let pragma = format!("PRAGMA busy_timeout = {}", busy_timeout.as_millis());
    connection
        .execute_batch(&pragma)
        .map_err(|err| StoreError::from_rusqlite(err, correlation_id))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_initializes_schema() {
        let store = SqliteStore::open_in_memory(OpenOptions::default()).expect("open");
        assert_eq!(store.bootstrap().schema_version, CURRENT_SCHEMA_VERSION);

        let conn = store.lock().expect("lock");
        let pragma: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("foreign_keys pragma");
        assert_eq!(pragma, 1, "foreign keys must be enforced");

        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("busy_timeout pragma");
        assert_eq!(timeout, 5_000);

        let synchronous: i64 =
            conn.query_row("PRAGMA synchronous", [], |row| row.get(0)).expect("synchronous pragma");
        assert_eq!(synchronous, 1, "synchronous must be NORMAL (value 1); FULL=2, OFF=0");
    }

    #[test]
    fn on_disk_store_initializes_schema() {
        let dir = tempdir();
        let path = dir.join("xtrace.sqlite3");
        let store = SqliteStore::open(&path, OpenOptions::default()).expect("open");
        assert_eq!(store.bootstrap().schema_version, CURRENT_SCHEMA_VERSION);

        // A second open reuses the same schema version without
        // re-applying migrations.
        let reopened = SqliteStore::open(&path, OpenOptions::default()).expect("reopen");
        assert_eq!(reopened.bootstrap().schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn missing_parent_directory_is_rejected() {
        let dir = tempdir();
        let path = dir.join("missing").join("xtrace.sqlite3");
        let err = SqliteStore::open(&path, OpenOptions::default()).unwrap_err();
        assert_eq!(err.kind(), StoreErrorKind::Validation);
    }

    fn tempdir() -> PathBuf {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("xtrace-store-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}
