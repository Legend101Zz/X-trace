//! Root-bound recording anchor persistence.
//!
//! The XTF object and segment commit path arrives in a later pass. This module
//! establishes only the root binding, scoped error surface, and idempotent
//! recording anchor needed before object publication can be added safely.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use rusqlite::OptionalExtension as _;
use xtrace_domain::ids::Id as _;
use xtrace_domain::{CorrelationId, ProjectId, RecordingId, RuntimeSessionId, WallTime};

use crate::connection::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};

/// Input for the idempotent recording-anchor operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeginRecordingRequest {
    /// Project that owns the recording.
    pub project_id: ProjectId,
    /// Stable recording identity assigned by the admitted session.
    pub recording_id: RecordingId,
    /// Runtime session that opened the recording.
    pub runtime_session_id: RuntimeSessionId,
    /// Canonical wall-clock time when the recording opened.
    pub opened_at: WallTime,
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
        let binding = ProjectRootBinding {
            root: project_root.to_path_buf(),
            database_path: database_path.clone(),
        };
        binding.revalidate(correlation_id)?;
        Ok(SqliteRecordingStore { store: self, binding })
    }
}

impl SqliteRecordingStore<'_> {
    /// Inserts a recording anchor or returns an exact immutable replay.
    ///
    /// The shared writer guard is acquired before root revalidation and all
    /// reads, so every store clone and recording view observes one local
    /// recording-write order. This pass always inserts `recording`; it never
    /// transitions lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`RecordingStoreErrorKind::NotFound`] before inserting when the
    /// project does not exist, or `XTR-STORE-RECORDING-CONFLICT` when an
    /// existing recording has different immutable begin identity.
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
        let connection =
            self.store.lock().map_err(|error| map_store_error(error, correlation_id))?;

        if !project_exists(&connection, request.project_id, correlation_id)? {
            return Err(RecordingStoreError::new(
                RecordingStoreErrorKind::NotFound,
                "XTR-STORE-RECORDING-PROJECT-NOT-FOUND",
                "recording project does not exist",
                correlation_id,
            ));
        }

        if let Some(existing) = load_recording(&connection, request.recording_id, correlation_id)? {
            return receipt_for_existing(existing, request, correlation_id);
        }

        let result = connection.execute(
            "INSERT INTO recordings \
                 (recording_id, project_id, runtime_session_id, status, opened_at) \
             VALUES (?1, ?2, ?3, 'recording', ?4)",
            rusqlite::params![
                request.recording_id.as_uuid().as_bytes().to_vec(),
                request.project_id.as_uuid().as_bytes().to_vec(),
                request.runtime_session_id.as_uuid().as_bytes().to_vec(),
                request.opened_at.to_rfc3339(),
            ],
        );
        match result {
            Ok(_) => Ok(BeginRecordingReceipt {
                recording_id: request.recording_id,
                disposition: BeginRecordingDisposition::Inserted,
            }),
            Err(error) => {
                let mapped = StoreError::from_rusqlite(error, correlation_id);
                if matches!(mapped.kind(), StoreErrorKind::AlreadyExists) {
                    if let Some(existing) =
                        load_recording(&connection, request.recording_id, correlation_id)?
                    {
                        return receipt_for_existing(existing, request, correlation_id);
                    }
                }
                Err(map_store_error(mapped, correlation_id))
            }
        }
    }
}

#[derive(Debug)]
struct ProjectRootBinding {
    root: PathBuf,
    database_path: PathBuf,
}

impl ProjectRootBinding {
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
            validate_absolute_symlink_free_directory(&self.root, correlation_id)?;
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
            validate_regular_owner_only_file(&self.database_path, correlation_id)
        }
    }
}

#[cfg(unix)]
fn validate_absolute_symlink_free_directory(
    root: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Validation,
            "XTR-STORE-RECORDING-ROOT-INVALID",
            "project root must be an absolute lexical path without dot components",
            correlation_id,
        ));
    }
    let mut component_path = PathBuf::from("/");
    let root_metadata = std::fs::symlink_metadata(&component_path).map_err(|_| {
        RecordingStoreError::new(
            RecordingStoreErrorKind::Transport,
            "XTR-STORE-RECORDING-ROOT-IO",
            "project root metadata could not be read",
            correlation_id,
        )
        .with_source("filesystem metadata failure")
    })?;
    if root_metadata.file_type().is_symlink() {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Validation,
            "XTR-STORE-RECORDING-ROOT-INVALID",
            "project root path must not contain symbolic links",
            correlation_id,
        ));
    }
    for component in root.components() {
        let Component::Normal(segment) = component else {
            continue;
        };
        component_path.push(segment);
        let metadata = std::fs::symlink_metadata(&component_path).map_err(|_| {
            RecordingStoreError::new(
                RecordingStoreErrorKind::Transport,
                "XTR-STORE-RECORDING-ROOT-IO",
                "project root metadata could not be read",
                correlation_id,
            )
            .with_source("filesystem metadata failure")
        })?;
        if metadata.file_type().is_symlink() {
            return Err(RecordingStoreError::new(
                RecordingStoreErrorKind::Validation,
                "XTR-STORE-RECORDING-ROOT-INVALID",
                "project root path must not contain symbolic links",
                correlation_id,
            ));
        }
    }
    let metadata = std::fs::symlink_metadata(root).map_err(|_| {
        RecordingStoreError::new(
            RecordingStoreErrorKind::Transport,
            "XTR-STORE-RECORDING-ROOT-IO",
            "project root metadata could not be read",
            correlation_id,
        )
        .with_source("filesystem metadata failure")
    })?;
    if !metadata.file_type().is_dir() {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Validation,
            "XTR-STORE-RECORDING-ROOT-INVALID",
            "project root must be a directory",
            correlation_id,
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(RecordingStoreError::new(
            RecordingStoreErrorKind::Permission,
            "XTR-STORE-RECORDING-ROOT-PERMISSION",
            "project root must be owner-only",
            correlation_id,
        ));
    }
    Ok(())
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

fn receipt_for_existing(
    existing: ExistingRecording,
    request: &BeginRecordingRequest,
    correlation_id: CorrelationId,
) -> Result<BeginRecordingReceipt, RecordingStoreError> {
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
        return Ok(BeginRecordingReceipt {
            recording_id: request.recording_id,
            disposition: BeginRecordingDisposition::ExactReplay,
        });
    }
    Err(RecordingStoreError::new(
        RecordingStoreErrorKind::Conflict,
        "XTR-STORE-RECORDING-CONFLICT",
        "recording identity conflicts with an existing recording",
        correlation_id,
    ))
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

    use xtrace_domain::ids::Id as _;

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
            BeginRecordingRequest { project_id: other_project_id, ..request },
            BeginRecordingRequest { runtime_session_id: RuntimeSessionId::new(), ..request },
            BeginRecordingRequest {
                opened_at: WallTime::from_parts(2026, 9, 29, 2, 3, 5, 6).expect("time"),
                ..request
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
        // Fixture setup may resolve macOS's `/var` alias. Production root
        // validation intentionally never canonicalizes, because that would
        // accept a symlinked user-supplied path.
        let symlink_free_base = std::env::temp_dir().canonicalize().expect("canonical test base");
        let path = symlink_free_base
            .join(format!("xtrace-recording-store-{label}-{}-{index}", std::process::id()));
        std::fs::create_dir(&path).expect("deterministic test directory");
        set_mode(&path, 0o700);
        path
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
        BeginRecordingRequest { project_id, recording_id, runtime_session_id, opened_at }
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
    fn project_count(store: &SqliteStore) -> i64 {
        let connection = store.lock().expect("connection");
        connection
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
            .expect("project count")
    }
}
