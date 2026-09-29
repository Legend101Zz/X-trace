//! Root-bound recording anchor persistence.
//!
//! The XTF object and segment commit path arrives in a later pass. This module
//! establishes only the root binding, scoped error surface, and idempotent
//! recording anchor needed before object publication can be added safely.

use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

use rusqlite::OptionalExtension as _;
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    ContentHash, CorrelationId, ProjectId, RecordingId, RuntimeSessionId, WallTime,
};

use crate::connection::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};
use crate::xtf::{
    LogicalXtfSegment, XtfCodecError, XtfSegmentInput, compress_logical_bytes,
    encode_logical_segment, max_compressed_segment_bytes, verify_compressed_segment,
};

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
    let staging_root = binding.root.join("staging");
    ensure_owner_only_directory(&binding.root, &staging_root, correlation_id)?;
    let recording_directory = staging_root.join(recording_id.as_uuid().to_string());
    ensure_owner_only_directory(&binding.root, &recording_directory, correlation_id)?;
    // UUIDv7 supplies entropy for collision resistance while preserving no caller
    // material in the staging path.
    let directory = recording_directory.join(uuid::Uuid::now_v7().to_string());
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&directory).map_err(|_| object_io_error(correlation_id))?;
    set_owner_mode(&directory, 0o700, correlation_id)?;
    sync_directory(&recording_directory, correlation_id, "XTR-STORE-OBJECT-IO")?;
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
    use std::os::unix::fs::MetadataExt as _;

    if !directory.starts_with(root) {
        return Err(atomic_install_error(correlation_id));
    }
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(atomic_install_error(correlation_id));
            }
            if metadata.mode() & 0o077 != 0 {
                return Err(RecordingStoreError::new(
                    RecordingStoreErrorKind::Permission,
                    "XTR-STORE-OBJECT-IO",
                    "object storage directory must be owner-only",
                    correlation_id,
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(directory).map_err(|_| object_io_error(correlation_id))?;
            set_owner_mode(directory, 0o700, correlation_id)?;
            let parent = directory.parent().ok_or_else(|| object_io_error(correlation_id))?;
            sync_directory(parent, correlation_id, "XTR-STORE-OBJECT-IO")?;
        }
        Err(_) => return Err(atomic_install_error(correlation_id)),
    }
    Ok(())
}

#[cfg(unix)]
fn set_owner_mode(
    path: &Path,
    mode: u32,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| object_io_error(correlation_id))
}

fn write_synced_file(
    path: &Path,
    bytes: &[u8],
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    use std::fs::OpenOptions;

    note_staging_write();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|_| object_io_error(correlation_id))?;
    #[cfg(unix)]
    set_owner_mode(path, 0o600, correlation_id)?;
    file.write_all(bytes).map_err(|_| object_io_error(correlation_id))?;
    file.flush().map_err(|_| object_io_error(correlation_id))?;
    file.sync_all().map_err(|_| object_io_error(correlation_id))
}

#[cfg(unix)]
fn validate_managed_directory(
    directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let metadata =
        std::fs::symlink_metadata(directory).map_err(|_| atomic_install_error(correlation_id))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.mode() & 0o077 != 0
    {
        return Err(atomic_install_error(correlation_id));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_managed_tree(
    root: &Path,
    directory: &Path,
    correlation_id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let relative =
        directory.strip_prefix(root).map_err(|_| atomic_install_error(correlation_id))?;
    validate_managed_directory(root, correlation_id)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(atomic_install_error(correlation_id));
        };
        current.push(part);
        validate_managed_directory(&current, correlation_id)?;
    }
    Ok(())
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
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_file()
                || metadata.mode() & 0o077 != 0
            {
                return Err(atomic_install_error(correlation_id));
            }
            #[cfg(not(unix))]
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(atomic_install_error(correlation_id));
            }
            Ok(())
        }
        Err(error) if absent_is_valid && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
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
    let handle = std::fs::File::open(directory).map_err(|_| failure())?;
    handle.sync_all().map_err(|_| failure())
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
    let metadata = std::fs::symlink_metadata(path).map_err(|_| failure())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(failure());
    }
    let limit = max_compressed_segment_bytes();
    if metadata.len() > u64::try_from(limit).map_err(|_| failure())? {
        return Err(failure());
    }
    let file = std::fs::File::open(path).map_err(|_| failure())?;
    #[cfg(unix)]
    {
        let opened = file.metadata().map_err(|_| failure())?;
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || !opened.file_type().is_file()
            || opened.mode() & 0o077 != 0
        {
            return Err(failure());
        }
    }
    let mut reader = file.take(u64::try_from(limit + 1).map_err(|_| failure())?);
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| failure())?);
    reader.read_to_end(&mut bytes).map_err(|_| failure())?;
    if bytes.len() > limit {
        return Err(failure());
    }
    Ok(bytes)
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
    commit_failpoint("hard-link-syscall", correlation_id, true)?;
    match std::fs::hard_link(staging, destination) {
        Ok(()) => {
            // The new destination and staging names now address the same
            // verified source bytes. Retain that source evidence before any
            // fallible readback can observe the new destination.
            defer_cleanup_after_new_link();
            commit_failpoint("after-hard-link-before-readback", correlation_id, true)?;
            let persisted = read_bounded_regular_file(destination, correlation_id, false)?;
            verify_staged_object(&persisted, candidate, correlation_id)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            i64::try_from(persisted.len()).map_err(|_| object_corrupt_error(correlation_id))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_regular_file(destination, correlation_id, false)?;
            verify_staged_object(&existing, candidate, correlation_id)
                .map_err(|_| object_corrupt_error(correlation_id))?;
            i64::try_from(existing.len()).map_err(|_| object_corrupt_error(correlation_id))
        }
        Err(_) => Err(atomic_install_error(correlation_id)),
    }
}

fn cleanup_owned_staging_paths(staging: &StagingFiles, correlation_id: CorrelationId) {
    let cleanup = std::fs::remove_file(&staging.logical)
        .and_then(|_| std::fs::remove_file(&staging.compressed))
        .and_then(|_| std::fs::remove_dir(&staging.directory));
    if cleanup.is_err() {
        tracing::warn!("recording segment staging cleanup left safe residue");
        return;
    }
    #[cfg(unix)]
    if let Some(parent) = staging.directory.parent() {
        if commit_failpoint("cleanup-staging-directory-fsync", correlation_id, false).is_err()
            || sync_directory(parent, correlation_id, "XTR-STORE-OBJECT-IO").is_err()
        {
            tracing::warn!("recording segment staging directory synchronization left safe residue");
        }
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
            &ProjectRootBinding {
                root: fixture.root.clone(),
                database_path: fixture.database.clone(),
            },
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
            &ProjectRootBinding {
                root: fixture.root.clone(),
                database_path: fixture.database.clone(),
            },
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
