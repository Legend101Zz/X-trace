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
use std::sync::{Arc, Mutex, MutexGuard};

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
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

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
    /// Correlation ID attached to bootstrap diagnostics (pragma
    /// application and migration runs). Per-request correlation IDs
    /// are not threaded through this struct on purpose: repositories
    /// mint their own infrastructure correlation IDs and the
    /// application boundary surfaces the request correlation ID.
    bootstrap_correlation_id: CorrelationId,
    /// When `true`, opening fails with
    /// [`StoreErrorKind::Validation`] when the SQLite file does not
    /// already exist. Used by callers (`open`, `status`) that must
    /// refuse an absent project rather than create one implicitly.
    must_exist: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            busy_timeout: BusyTimeout::default(),
            app_version: STORE_APP_VERSION.to_string(),
            bootstrap_correlation_id: CorrelationId::new(),
            must_exist: false,
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

    /// Sets the bootstrap correlation ID attached to pragma and
    /// migration diagnostics. The value lives only in the
    /// [`OpenOptions`] struct; the store itself does not retain
    /// shared mutable correlation state. Repositories mint their
    /// own infrastructure correlation ID per call and the
    /// application boundary surfaces the request correlation ID;
    /// this builder only controls which correlation ID is attached
    /// to errors raised while bootstrapping the connection.
    #[must_use]
    pub fn with_correlation_id(mut self, id: CorrelationId) -> Self {
        self.bootstrap_correlation_id = id;
        self
    }

    /// Requires the database file to already exist. When set,
    /// [`SqliteStore::open`] opens the file with
    /// [`rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE`] only so an
    /// absent database is rejected without being created. The caller
    /// surfaces a truthful "uninitialized" error instead of silently
    /// creating the file.
    #[must_use]
    pub fn with_must_exist(mut self, must_exist: bool) -> Self {
        self.must_exist = must_exist;
        self
    }

    /// Returns whether the open requires the file to already exist.
    #[must_use]
    pub const fn must_exist(&self) -> bool {
        self.must_exist
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
    inner: Arc<StoreInner>,
    bootstrap: StoreBootstrap,
}

#[derive(Debug)]
struct StoreInner {
    connection: Mutex<Connection>,
    // This lock owns recording-wide ordering across every clone and every
    // borrowed recording-store view. It intentionally remains separate from
    // the connection lock because later commits hold it across filesystem and
    // SQLite boundaries.
    recording_writer: Mutex<()>,
}

impl SqliteStore {
    /// Opens an in-memory store. Intended for tests.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLite cannot open the connection
    /// or migrations fail.
    pub fn open_in_memory(options: OpenOptions) -> Result<Self, StoreError> {
        let bootstrap = options.bootstrap_correlation_id;
        let connection = Connection::open_in_memory()
            .map_err(|err| StoreError::from_rusqlite(err, bootstrap))?;
        Self::from_connection(connection, None, options)
    }

    /// Opens or creates a store at the supplied path. The parent
    /// directory must already exist; the store creates the database
    /// file itself unless [`OpenOptions::with_must_exist`] is set,
    /// in which case the open flags exclude `SQLITE_OPEN_CREATE` so
    /// an absent file is rejected atomically without being created.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when SQLite cannot open the connection,
    /// the parent directory does not exist, or migrations fail.
    pub fn open(path: &Path, options: OpenOptions) -> Result<Self, StoreError> {
        let bootstrap = options.bootstrap_correlation_id;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(StoreError::new(
                    StoreErrorKind::Validation,
                    "parent directory of database file does not exist",
                    bootstrap,
                ));
            }
        }
        // When `must_exist` is set we open the file with read-write
        // flags only so SQLite refuses to create the file. This closes
        // the `path.exists()`-then-`Connection::open` race in which a
        // missing database could be implicitly created.
        let flags = if options.must_exist() {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        };
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|err| StoreError::from_rusqlite(err, bootstrap))?;
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
        let bootstrap = options.bootstrap_correlation_id;
        apply_pragmas(&connection, options.busy_timeout, bootstrap)?;
        let schema_version =
            migrations::apply_pending(&connection, &options.app_version, bootstrap)?;
        let bootstrap_snapshot =
            StoreBootstrap { database_path, schema_version, busy_timeout: options.busy_timeout };
        Ok(Self {
            inner: Arc::new(StoreInner {
                connection: Mutex::new(connection),
                recording_writer: Mutex::new(()),
            }),
            bootstrap: bootstrap_snapshot,
        })
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
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        // Locking a `Mutex` only fails when poisoned. Poisoning
        // means a previous holder panicked; treat it as corruption
        // because the database may be in an inconsistent state.
        self.inner.connection.lock().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Corruption,
                "store connection mutex was poisoned by a panic",
                CorrelationId::new(),
            )
        })
    }

    /// Acquires the shared recording writer guard.
    ///
    /// Recording persistence obtains this before any recording read and keeps
    /// it across its complete operation. The guard is shared by every clone
    /// because it lives in [`StoreInner`], not in a repository view.
    pub(crate) fn lock_recording_writer(
        &self,
        correlation_id: CorrelationId,
    ) -> Result<MutexGuard<'_, ()>, StoreError> {
        self.inner.recording_writer.lock().map_err(|_| {
            StoreError::new(
                StoreErrorKind::Corruption,
                "recording writer mutex was poisoned by a panic",
                correlation_id,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn try_lock_recording_writer(&self) -> Option<MutexGuard<'_, ()>> {
        self.inner.recording_writer.try_lock().ok()
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

    #[test]
    fn must_exist_never_creates_the_database_file() {
        // The previous `path.exists()` + `Connection::open` race
        // could implicitly create a missing database even when the
        // caller required it to already exist. With
        // `SQLITE_OPEN_CREATE` excluded from the open flags the
        // open returns a `Transport` failure (the typed mapping of
        // SQLite's `CannotOpen` code) and the file remains absent.
        let dir = tempdir();
        let path = dir.join("must-exist.sqlite3");
        let err =
            SqliteStore::open(&path, OpenOptions::default().with_must_exist(true)).unwrap_err();
        assert_eq!(err.kind(), StoreErrorKind::Transport);
        assert!(!path.exists(), "must_exist must not create the SQLite file");
    }

    fn tempdir() -> PathBuf {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("xtrace-store-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}
