//! Private, bounded append journal for the one unfinished segment of a recording.
//!
//! XTF objects remain immutable. Only the current tail is appendable: each
//! envelope has a length and digest. A separate, atomically replaced checkpoint
//! names the synced prefix; bytes beyond it never participate in recovery or live
//! reads. Acknowledgement follows a grouped data/checkpoint sync and directory sync.

use std::io::{Seek as _, SeekFrom};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use prost::Message as _;
use xtrace_application::recording::{
    DEFAULT_SEGMENT_EVENT_BYTES, DEFAULT_SEGMENT_EVENTS, PersistRecordingSegment,
};
use xtrace_protocol::xtf::XtfEventEnvelope;

use super::*;

const LEGACY_MAGIC: &[u8; 8] = b"XTRTAIL1";
const MAGIC: &[u8; 8] = b"XTRTAIL2";
const BOUNDARY_BYTES: usize = HEADER_BYTES + 8 + 32;
const HEADER_BYTES: usize = 44;
const MAX_JOURNAL_BYTES: usize =
    HEADER_BYTES + DEFAULT_SEGMENT_EVENT_BYTES + DEFAULT_SEGMENT_EVENTS * 32;

#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_SYNC: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_BOUNDARY: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_SNAPSHOT_READS: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static SNAPSHOT_CONTENDED: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_PUBLICATION: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_CLEANUP: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_DIRECTORY_LOOKUP: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
    static CHECKPOINT_SYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static JOURNAL_SYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static COUNT_ONLY_SYNCS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static DIRECTORY_SYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BOUNDARY_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SYNC_ORDER: std::cell::RefCell<Vec<SyncKind>> = const { std::cell::RefCell::new(Vec::new()) };
}

// Coordinate only journal mutation/publication, not the recording writer: a
// reader must still complete while an append is waiting for its data sync.
// Paths, rather than store instances, also cover independently opened readers.
type SnapshotLocks = HashMap<PathBuf, Weak<RwLock<()>>>;
pub(super) fn snapshot_lock(
    root: &AdmittedPrivateRoot,
    recording_id: RecordingId,
    id: CorrelationId,
) -> Result<Arc<RwLock<()>>, RecordingStoreError> {
    #[cfg(test)]
    let mut phase = work_profile::Phase::enter("snapshot_registry_mutex_wait");
    static LOCKS: OnceLock<Mutex<SnapshotLocks>> = OnceLock::new();
    let mut locks = LOCKS.get_or_init(Mutex::default).lock().map_err(|_| object_io_error(id))?;
    #[cfg(test)]
    phase.switch("snapshot_registry_scan");
    locks.retain(|_, lock| lock.strong_count() != 0);
    let entry = locks.entry(root.path().join(name(recording_id))).or_default();
    if let Some(lock) = entry.upgrade() {
        return Ok(lock);
    }
    let lock = Arc::new(RwLock::new(()));
    *entry = Arc::downgrade(&lock);
    Ok(lock)
}

// Lock admitted directory inodes: the project root coordinates first journals
// creation; the journals directory survives checkpoint replacement and cleanup.
// Read-only clients need not create a lock file, including for older journals.
// Take a per-recording lock, if needed, before the journals flock, and release
// mutation locks before syncing append data or decoding events.
// Each call opens its own descriptor; closing it releases only this flock.
#[cfg(unix)]
fn snapshot_file_lock(
    root: &AdmittedPrivateRoot,
    exclusive: bool,
    id: CorrelationId,
) -> Result<std::fs::File, RecordingStoreError> {
    use rustix::fs::{FlockOperation, flock};

    #[cfg(test)]
    let mut phase = work_profile::Phase::enter("flock_admission");
    let file = xtrace_private_storage::open_private_directory_descriptor(root.path())
        .map_err(|_| object_io_error(id))?;
    let operation =
        if exclusive { FlockOperation::LockExclusive } else { FlockOperation::LockShared };
    #[cfg(test)]
    phase.switch("flock_wait");
    #[cfg(test)]
    if exclusive {
        // Observe actual kernel contention without a sleep or a timing-based
        // assertion. The production path simply makes one blocking lock call.
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                #[cfg(test)]
                phase.switch("flock_revalidate");
                root.revalidate().map_err(|_| object_io_error(id))?;
                return Ok(file);
            }
            Err(rustix::io::Errno::WOULDBLOCK) => SNAPSHOT_CONTENDED.with(|hook| {
                if let Some(hook) = hook.borrow().as_ref() {
                    hook();
                }
            }),
            Err(_) => return Err(object_io_error(id)),
        }
    }
    flock(&file, operation).map_err(|_| object_io_error(id))?;
    #[cfg(test)]
    phase.switch("flock_revalidate");
    root.revalidate().map_err(|_| object_io_error(id))?;
    Ok(file)
}

/// Only the large cardinality tests substitute the sync syscall. All writes,
/// admission, rename, sync ordering, fault boundaries and recovery stay real.
#[cfg(test)]
pub(crate) struct CountOnlySyncs(std::marker::PhantomData<std::rc::Rc<()>>);

#[cfg(test)]
impl CountOnlySyncs {
    pub(crate) fn enter() -> Self {
        COUNT_ONLY_SYNCS.with(|enabled| assert!(!enabled.replace(true)));
        Self(std::marker::PhantomData)
    }
}

#[cfg(test)]
impl Drop for CountOnlySyncs {
    fn drop(&mut self) {
        COUNT_ONLY_SYNCS.with(|enabled| enabled.set(false));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyncKind {
    Journal,
    Checkpoint,
    Directory,
}

fn durable_sync(
    _kind: SyncKind,
    sync: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    #[cfg(test)]
    let _phase = work_profile::Phase::enter(match _kind {
        SyncKind::Journal => "journal_sync",
        SyncKind::Checkpoint => "checkpoint_sync",
        SyncKind::Directory => "directory_sync",
    });
    #[cfg(test)]
    let count_only = COUNT_ONLY_SYNCS.with(|enabled| enabled.get());
    #[cfg(not(test))]
    let count_only = false;
    if !count_only {
        sync()?;
    }
    #[cfg(test)]
    {
        SYNC_ORDER.with(|order| order.borrow_mut().push(_kind));
        let counter = match _kind {
            SyncKind::Journal => &JOURNAL_SYNCS,
            SyncKind::Checkpoint => &CHECKPOINT_SYNCS,
            SyncKind::Directory => &DIRECTORY_SYNCS,
        };
        counter.with(|count| count.set(count.get() + 1));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn take_sync_order() -> Vec<SyncKind> {
    SYNC_ORDER.with(|order| std::mem::take(&mut *order.borrow_mut()))
}

#[cfg(test)]
pub(crate) fn take_directory_sync_count() -> usize {
    DIRECTORY_SYNCS.with(|count| count.replace(0))
}

#[cfg(test)]
pub(crate) fn take_boundary_read_count() -> usize {
    BOUNDARY_READS.with(|count| count.replace(0))
}

// Use the admitted descriptor for both renameat and its durability barrier.
// Apple's fsync alone does not flush the device cache for directory changes.
#[cfg(unix)]
fn sync_directory_descriptor(file: &std::fs::File) -> std::io::Result<()> {
    durable_sync(SyncKind::Directory, || {
        #[cfg(target_vendor = "apple")]
        let result = rustix::fs::fcntl_fullfsync(file);
        #[cfg(not(target_vendor = "apple"))]
        let result = rustix::fs::fsync(file);
        result.map_err(std::io::Error::from)
    })
}

fn sync_journal_directory(root: &AdmittedPrivateRoot) -> Result<(), PrivateStorageError> {
    root.revalidate()?;
    #[cfg(unix)]
    {
        let file = xtrace_private_storage::open_private_directory_descriptor(root.path())?;
        sync_directory_descriptor(&file).map_err(|_| PrivateStorageError::Operation)?;
    }
    #[cfg(not(unix))]
    root.sync()?;
    root.revalidate()
}

#[cfg(test)]
pub(crate) fn take_sync_count() -> usize {
    JOURNAL_SYNCS.with(|count| count.replace(0))
}

/// Checkpoint file syncs are additional to the append-file sync count.
#[cfg(test)]
pub(crate) fn take_checkpoint_sync_count() -> usize {
    CHECKPOINT_SYNCS.with(|count| count.replace(0))
}

/// A checkpoint is installed only after file and creation-directory sync.
/// Digests prevent an ambiguous retry from changing an already written prefix.
#[derive(Debug)]
pub(crate) struct Checkpoint {
    header: [u8; HEADER_BYTES],
    ordinal: u32,
    length: u64,
    digests: Vec<[u8; 32]>,
    first_sequence: u64,
    identities: HashSet<String>,
}

struct Tail {
    header: [u8; HEADER_BYTES],
    project_id: ProjectId,
    ordinal: u32,
    events: Vec<XtfEventEnvelope>,
    length: u64,
}

fn directory(
    binding: &ProjectRootBinding,
    create: bool,
    id: CorrelationId,
) -> Result<Option<AdmittedPrivateRoot>, RecordingStoreError> {
    #[cfg(test)]
    let _phase = work_profile::Phase::enter("journal_directory_admission");
    binding.revalidate(id)?;
    // The binding already owns and has just revalidated this capability.
    // Child APIs still rewalk ancestors and check the named child themselves.
    let root = &binding.private_root;
    if create {
        if std::fs::symlink_metadata(binding.root.join("journals")).is_ok() {
            return root.open_private_child("journals").map(Some).map_err(|_| object_io_error(id));
        }
        // A reader that found no journals retains a shared parent lock through
        // its SQLite snapshot. Creation must wait until that read completes.
        #[cfg(unix)]
        let _creation = snapshot_file_lock(root, true, id)?;
        let child =
            root.open_or_create_private_child("journals").map_err(|_| object_io_error(id))?;
        // Each cold writer syncs this parent before acknowledging. In
        // particular it must do so again after an ambiguous creation failure.
        Ok(Some(child))
    } else {
        match std::fs::symlink_metadata(binding.root.join("journals")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(object_io_error(id)),
            Ok(_) => root.open_private_child("journals").map(Some).map_err(|_| object_io_error(id)),
        }
    }
}

fn name(recording_id: RecordingId) -> String {
    format!("{}.tail", recording_id.as_uuid())
}

fn boundary_name(recording_id: RecordingId) -> String {
    format!("{}.tail.commit", recording_id.as_uuid())
}

fn read_boundary(
    root: &AdmittedPrivateRoot,
    recording_id: RecordingId,
    id: CorrelationId,
) -> Result<Option<Vec<u8>>, RecordingStoreError> {
    #[cfg(test)]
    BOUNDARY_READS.with(|count| count.set(count.get() + 1));
    let name = boundary_name(recording_id);
    match std::fs::symlink_metadata(root.path().join(&name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(object_io_error(id)),
        Ok(metadata) if metadata.len() != BOUNDARY_BYTES as u64 => {
            return Err(object_corrupt_error(id));
        }
        Ok(_) => {}
    }
    let bytes = root.read_bounded_file(&name, BOUNDARY_BYTES).map_err(|_| object_io_error(id))?;
    if bytes.len() != BOUNDARY_BYTES
        || blake3::hash(&bytes[..HEADER_BYTES + 8]).as_bytes() != &bytes[HEADER_BYTES + 8..]
        || &bytes[24..40] != recording_id.as_uuid().as_bytes()
    {
        return Err(object_corrupt_error(id));
    }
    Ok(Some(bytes))
}

/// Flush the unpublished checkpoint to the filesystem before the journal's
/// device barrier. Both files are in this same admitted directory: on Apple,
/// the following journal F_FULLFSYNC drains their shared device cache once.
/// Linux fsync already makes each file durable. No reader uses this temporary.
fn prepare_boundary(
    root: &AdmittedPrivateRoot,
    recording_id: RecordingId,
    header: &[u8],
    length: u64,
    id: CorrelationId,
) -> Result<std::fs::File, RecordingStoreError> {
    let name = boundary_name(recording_id);
    let pending = format!("{name}-next");
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
    let mut file = root.open_or_create_private_file(&pending).map_err(|_| object_io_error(id))?;
    file.set_len(0).map_err(|_| object_io_error(id))?;
    file.write_all(&bytes).map_err(|_| object_io_error(id))?;
    commit_failpoint("journal-checkpoint-before-sync", id, false)?;
    durable_sync(SyncKind::Checkpoint, || sync_recording_file(&file, FileSync::Filesystem))
        .map_err(|_| object_io_error(id))?;
    root.validate_file_binding(&pending, &file, true).map_err(|_| object_io_error(id))?;
    Ok(file)
}

/// The caller has made both files durable with the journal's device barrier.
/// Never overwrite the old checkpoint: rename exposes an entirely durable old
/// or new prefix even if power is lost before this batch is acknowledged.
fn publish_boundary(
    root: &AdmittedPrivateRoot,
    recording_id: RecordingId,
    file: &std::fs::File,
    id: CorrelationId,
) -> Result<(), RecordingStoreError> {
    let name = boundary_name(recording_id);
    let pending = format!("{name}-next");
    commit_failpoint("journal-checkpoint-before-rename", id, false)?;
    #[cfg(test)]
    BEFORE_PUBLICATION.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook();
        }
    });
    let lock = snapshot_lock(root, recording_id, id)?;
    let _snapshot = {
        #[cfg(test)]
        let _phase = work_profile::Phase::enter("publication_rwlock_wait");
        lock.write().map_err(|_| object_io_error(id))?
    };
    #[cfg(unix)]
    let _file_snapshot = snapshot_file_lock(root, true, id)?;
    #[cfg(unix)]
    {
        // Keep the same source/target admission and post-rename binding checks
        // as rename_replace, with an explicit full directory sync on Apple.
        let directory = xtrace_private_storage::open_private_directory_descriptor(root.path())
            .map_err(|_| object_io_error(id))?;
        root.validate_file_binding(&pending, file, false).map_err(|_| object_io_error(id))?;
        // The old target is discarded, not read. Stat-only admission already
        // checks owner, mode, ACL, filesystem, link count and stable identity.
        // Opening it and validating it twice more adds no publication evidence.
        root.validate_optional_private_file(&name).map_err(|_| object_io_error(id))?;
        root.revalidate().map_err(|_| object_io_error(id))?;
        rustix::fs::renameat(&directory, pending.as_str(), &directory, name.as_str())
            .map_err(|_| object_io_error(id))?;
        root.validate_file_binding(&name, file, false).map_err(|_| object_io_error(id))?;
        sync_directory_descriptor(&directory).map_err(|_| object_io_error(id))?;
        root.revalidate().map_err(|_| object_io_error(id))
    }
    #[cfg(not(unix))]
    root.rename_replace(&pending, &name).map_err(|_| object_io_error(id))
}

fn load(
    binding: &ProjectRootBinding,
    recording_id: RecordingId,
    id: CorrelationId,
) -> Result<Option<Tail>, RecordingStoreError> {
    load_for_retry(binding, recording_id, id, false)
}

// Fully written pending envelopes constrain ambiguous retries, but are never
// visible to recovery/readers until the retry has synced and checkpointed them.
fn load_for_retry(
    binding: &ProjectRootBinding,
    recording_id: RecordingId,
    id: CorrelationId,
    include_pending: bool,
) -> Result<Option<Tail>, RecordingStoreError> {
    #[cfg(test)]
    let _phase = work_profile::Phase::enter("journal_retry_load");
    let Some(root) = directory(binding, false, id)? else { return Ok(None) };
    let lock = snapshot_lock(&root, recording_id, id)?;
    let snapshot = {
        let _snapshot = lock.read().map_err(|_| object_io_error(id))?;
        #[cfg(unix)]
        let _file_snapshot = snapshot_file_lock(&root, false, id)?;
        read_snapshot_files(&root, recording_id, id)?
    };
    decode_snapshot(snapshot, recording_id, id, include_pending)
}

/// Pins journal publication before the caller establishes its SQLite read
/// transaction. Seals may commit meanwhile, but their old tails cannot be
/// removed or replaced until every row and tail has been copied. Do not take a
/// per-recording lock inside this guard: a writer may hold it while waiting on
/// our directory flock. When journals do not exist, retain the project-root
/// flock instead so first creation cannot overtake the SQLite snapshot.
/// These flocks also cover independent processes.
pub(super) struct PublishedRead {
    root: Option<AdmittedPrivateRoot>,
    #[cfg(unix)]
    _file_snapshot: std::fs::File,
}

impl PublishedRead {
    pub(super) fn new(
        view: &SqliteRecordingStore<'_>,
        id: CorrelationId,
    ) -> Result<Self, RecordingStoreError> {
        #[cfg(unix)]
        let creation_snapshot = snapshot_file_lock(&view.binding.private_root, false, id)?;
        let root = directory(&view.binding, false, id)?;
        #[cfg(test)]
        AFTER_DIRECTORY_LOOKUP.with(|hook| {
            if let Some(hook) = hook.borrow().as_ref() {
                hook();
            }
        });
        #[cfg(unix)]
        let file_snapshot = match &root {
            Some(root) => snapshot_file_lock(root, false, id)?,
            None => creation_snapshot,
        };
        Ok(Self {
            root,
            #[cfg(unix)]
            _file_snapshot: file_snapshot,
        })
    }

    fn load(
        &self,
        recording_id: RecordingId,
        id: CorrelationId,
    ) -> Result<Option<Tail>, RecordingStoreError> {
        let Some(root) = &self.root else { return Ok(None) };
        decode_snapshot(read_snapshot_files(root, recording_id, id)?, recording_id, id, false)
    }

    pub(super) fn events(
        &self,
        project_id: ProjectId,
        recording_id: RecordingId,
    ) -> Result<Option<(u32, Vec<XtfEventEnvelope>)>, RecordingStoreError> {
        let id = CorrelationId::new();
        let Some(tail) = self.load(recording_id, id)? else { return Ok(None) };
        if tail.project_id != project_id {
            return Err(object_corrupt_error(id));
        }
        Ok(Some((tail.ordinal, tail.events)))
    }

    pub(super) fn summary(
        &self,
        recording_id: RecordingId,
        sealed_last: u64,
    ) -> Result<Option<(u64, u64, u64)>, RecordingStoreError> {
        summarize(self.load(recording_id, CorrelationId::new())?, sealed_last)
    }
}

type SnapshotFiles = Option<(Option<Vec<u8>>, Vec<u8>)>;

fn read_snapshot_files(
    root: &AdmittedPrivateRoot,
    recording_id: RecordingId,
    id: CorrelationId,
) -> Result<SnapshotFiles, RecordingStoreError> {
    let boundary = read_boundary(root, recording_id, id)?;
    #[cfg(test)]
    AFTER_BOUNDARY.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook();
        }
    });
    let name = name(recording_id);
    match std::fs::symlink_metadata(root.path().join(&name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && boundary.is_none() => {
            return Ok(None);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(object_corrupt_error(id));
        }
        Err(_) => return Err(object_io_error(id)),
        Ok(metadata) if metadata.len() > MAX_JOURNAL_BYTES as u64 => {
            return Err(object_corrupt_error(id));
        }
        Ok(_) => {}
    }
    let bytes =
        root.read_bounded_file(&name, MAX_JOURNAL_BYTES).map_err(|_| object_io_error(id))?;
    Ok(Some((boundary, bytes)))
}

fn decode_snapshot(
    snapshot: SnapshotFiles,
    recording_id: RecordingId,
    id: CorrelationId,
    include_pending: bool,
) -> Result<Option<Tail>, RecordingStoreError> {
    let Some((boundary, bytes)) = snapshot else { return Ok(None) };
    #[cfg(test)]
    AFTER_SNAPSHOT_READS.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook();
        }
    });
    // A crash during initial header creation cannot have acknowledged events.
    if bytes.len() < HEADER_BYTES {
        return if boundary.is_some() { Err(object_corrupt_error(id)) } else { Ok(None) };
    }
    let legacy = &bytes[..8] == LEGACY_MAGIC && boundary.is_none();
    let committed = if let Some(boundary) = &boundary {
        let length = u64::from_be_bytes(
            boundary[HEADER_BYTES..HEADER_BYTES + 8]
                .try_into()
                .map_err(|_| object_corrupt_error(id))?,
        );
        let length = usize::try_from(length).map_err(|_| object_corrupt_error(id))?;
        if length < HEADER_BYTES
            || length > bytes.len()
            || boundary[..HEADER_BYTES] != bytes[..HEADER_BYTES]
        {
            return Err(object_corrupt_error(id));
        }
        length
    } else if legacy {
        bytes.len()
    } else {
        0
    };
    if committed == 0 && !include_pending {
        return Ok(None);
    }
    if (&bytes[..8] != MAGIC && &bytes[..8] != LEGACY_MAGIC)
        || &bytes[24..40] != recording_id.as_uuid().as_bytes()
    {
        return Err(object_corrupt_error(id));
    }
    let project_id = project_id_from_bytes(&bytes[8..24], id)?;
    let ordinal =
        u32::from_be_bytes(bytes[40..44].try_into().map_err(|_| object_corrupt_error(id))?);
    if u64::from(ordinal) >= MAX_RECORDING_QUERY_SEGMENTS {
        return Err(object_corrupt_error(id));
    }
    let mut events = Vec::new();
    let mut offset = HEADER_BYTES;
    let limit = if include_pending || legacy { bytes.len() } else { committed };
    while offset < limit {
        let decoded = decode_envelope(&bytes[..limit], offset, events.last(), id);
        let (envelope, end) = match decoded {
            Ok(Some(decoded)) => decoded,
            Ok(None) if legacy => break,
            Ok(None) | Err(_) if offset >= committed => break,
            _ => return Err(object_corrupt_error(id)),
        };
        if offset < committed && end > committed {
            return Err(object_corrupt_error(id));
        }
        events.push(envelope);
        if events.len() > DEFAULT_SEGMENT_EVENTS {
            return Err(object_corrupt_error(id));
        }
        offset = end;
    }
    let header = bytes[..HEADER_BYTES].try_into().map_err(|_| object_corrupt_error(id))?;
    Ok(Some(Tail { header, project_id, ordinal, events, length: offset as u64 }))
}

fn decode_envelope(
    bytes: &[u8],
    offset: usize,
    previous: Option<&XtfEventEnvelope>,
    id: CorrelationId,
) -> Result<Option<(XtfEventEnvelope, usize)>, RecordingStoreError> {
    if bytes.len().saturating_sub(offset) < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(
        bytes[offset..offset + 4].try_into().map_err(|_| object_corrupt_error(id))?,
    ) as usize;
    let end = offset
        .checked_add(4)
        .and_then(|value| value.checked_add(length))
        .ok_or_else(|| object_corrupt_error(id))?;
    let digest_end = end.checked_add(32).ok_or_else(|| object_corrupt_error(id))?;
    if digest_end > bytes.len() {
        return Ok(None);
    }
    let payload = &bytes[offset + 4..end];
    if blake3::hash(payload).as_bytes() != &bytes[end..digest_end] {
        return Err(object_corrupt_error(id));
    }
    let envelope = XtfEventEnvelope::decode(payload).map_err(|_| object_corrupt_error(id))?;
    if envelope.encode_to_vec() != payload
        || envelope.event.as_ref().is_none_or(|event| event.recording_seq != envelope.recording_seq)
        || previous.is_some_and(|previous| {
            previous.recording_seq.checked_add(1) != Some(envelope.recording_seq)
        })
    {
        return Err(object_corrupt_error(id));
    }
    Ok(Some((envelope, digest_end)))
}

impl SqliteRecordingStore<'_> {
    pub(crate) fn persist_capture_cap(
        &self,
        recording_id: RecordingId,
        cap: usize,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        if !event_cap_in_bounds(cap as u64) {
            return Err(terminal_validation_error(id));
        }
        let _writer =
            self.store.lock_recording_writer(id).map_err(|error| map_store_error(error, id))?;
        {
            let connection = self.store.lock().map_err(|error| map_store_error(error, id))?;
            let status: Option<String> = connection
                .query_row(
                    "SELECT status FROM recordings WHERE recording_id = ?1",
                    rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| map_store_error(StoreError::from_rusqlite(error, id), id))?;
            match status.as_deref() {
                Some("recording") => {}
                Some(_) => return Ok(()), // Never retrofit policy onto terminal legacy evidence.
                None => return Err(read_not_found_error(id)),
            }
        }
        let root = directory(&self.binding, true, id)?.ok_or_else(|| object_io_error(id))?;
        let name = format!("{}.cap", recording_id.as_uuid());
        let expected = (cap as u64).to_be_bytes();
        let mut file = root.open_or_create_private_file(&name).map_err(|_| object_io_error(id))?;
        let stored = root.read_bounded_file(&name, 8).map_err(|_| object_io_error(id))?;
        if !expected.starts_with(&stored) {
            return Err(segment_conflict_error(id));
        }
        if stored.len() < expected.len() {
            file.write_all(&expected).map_err(|_| object_io_error(id))?;
        }
        // Also sync an exact retry: a previous sync may have failed ambiguously.
        file.sync_all().map_err(|_| object_io_error(id))?;
        root.validate_file_binding(&name, &file, true).map_err(|_| object_io_error(id))?;
        sync_journal_directory(&root).map_err(|_| object_io_error(id))?;
        AdmittedPrivateRoot::open(&self.binding.root)
            .and_then(|parent| sync_journal_directory(&parent))
            .map_err(|_| object_io_error(id))
    }

    pub(crate) fn capture_cap(
        &self,
        recording_id: RecordingId,
    ) -> Result<Option<u64>, RecordingStoreError> {
        let id = CorrelationId::new();
        let Some(root) = directory(&self.binding, false, id)? else { return Ok(None) };
        let name = format!("{}.cap", recording_id.as_uuid());
        match std::fs::symlink_metadata(root.path().join(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(object_io_error(id)),
            Ok(_) => {}
        }
        let stored = root.read_bounded_file(&name, 8).map_err(|_| object_io_error(id))?;
        // An interrupted Begin with no policy acknowledgement has no admitted events.
        if stored.len() < 8 {
            return Ok(None);
        }
        let cap = u64::from_be_bytes(stored.try_into().map_err(|_| object_corrupt_error(id))?);
        if !event_cap_in_bounds(cap) {
            return Err(object_corrupt_error(id));
        }
        Ok(Some(cap))
    }

    pub(crate) fn journal_tail(
        &self,
        request: &PersistRecordingSegment<XtfEventEnvelope>,
        prefix_events: usize,
        checkpoint: &mut Option<Checkpoint>,
    ) -> Result<(), RecordingStoreError> {
        #[cfg(test)]
        let mut phase = work_profile::Phase::enter("writer_wait");
        let id = CorrelationId::new();
        let _writer =
            self.store.lock_recording_writer(id).map_err(|error| map_store_error(error, id))?;
        #[cfg(test)]
        phase.switch("journal_validation");
        if u64::from(request.segment_ordinal) >= MAX_RECORDING_QUERY_SEGMENTS {
            return Err(recording_query_resource_error(id));
        }
        let commit = SegmentCommitRequest {
            project_id: request.project_id,
            recording_id: request.recording_id,
            segment_ordinal: request.segment_ordinal,
            events: request.events.iter().map(|event| event.payload.clone()).collect(),
        };
        let logical = encode_logical_segment(&XtfSegmentInput {
            project_id: commit.project_id,
            recording_id: commit.recording_id,
            segment_ordinal: commit.segment_ordinal,
            events: commit.events.clone(),
        })
        .map_err(|error| map_xtf_error(error, id))?;
        let root = directory(&self.binding, true, id)?.ok_or_else(|| object_io_error(id))?;
        #[cfg(test)]
        phase.switch("tail_file_admission");
        let name = name(request.recording_id);
        let mut file = root.open_or_create_private_file(&name).map_err(|_| object_io_error(id))?;
        let length = file.metadata().map_err(|_| object_io_error(id))?.len();
        #[cfg(test)]
        phase.switch("journal_validation");
        let mut known = checkpoint
            .take()
            .filter(|known| known.ordinal == request.segment_ordinal && known.length == length);
        let cached = known.is_some();
        if known.is_none() {
            let tail = load_for_retry(&self.binding, request.recording_id, id, true)?;
            if tail.as_ref().is_some_and(|tail| tail.project_id != request.project_id) {
                return Err(segment_conflict_error(id));
            }
            known = tail.map(|tail| Checkpoint {
                header: tail.header,
                ordinal: tail.ordinal,
                length: tail.length,
                first_sequence: tail.events.first().map_or(0, |event| event.recording_seq),
                digests: tail
                    .events
                    .iter()
                    .map(|event| *blake3::hash(&event.encode_to_vec()).as_bytes())
                    .collect(),
                identities: tail
                    .events
                    .iter()
                    .filter_map(|event| event.event.as_ref())
                    .map(|event| event.event_id.clone())
                    .collect(),
            });
        }
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8..24].copy_from_slice(request.project_id.as_uuid().as_bytes());
        header[24..40].copy_from_slice(request.recording_id.as_uuid().as_bytes());
        header[40..44].copy_from_slice(&request.segment_ordinal.to_be_bytes());
        let mut known = known.unwrap_or(Checkpoint {
            header,
            ordinal: request.segment_ordinal,
            length: 0,
            digests: Vec::new(),
            first_sequence: request.events.first().map_or(0, |event| event.recording_seq),
            identities: HashSet::new(),
        });
        if known.digests.is_empty() {
            known.first_sequence = request.events.first().map_or(0, |event| event.recording_seq);
        }
        let digests: Vec<_> = request
            .events
            .iter()
            .map(|event| *blake3::hash(&event.canonical_bytes).as_bytes())
            .collect();
        if known.ordinal != request.segment_ordinal
            || prefix_events > known.digests.len()
            || !digests.starts_with(&known.digests[prefix_events..])
            || known.first_sequence.checked_add(prefix_events as u64)
                != request.events.first().map(|event| event.recording_seq)
        {
            return Err(segment_conflict_error(id));
        }
        let overlap = known.digests.len() - prefix_events;
        let suffix = &request.events[overlap..];
        let new_count = known
            .digests
            .len()
            .checked_add(suffix.len())
            .ok_or_else(|| segment_validation_error(id))?;
        let new_bytes = suffix
            .iter()
            .try_fold(0_usize, |total, event| {
                total.checked_add(4 + event.canonical_bytes.len() + 32)
            })
            .ok_or_else(|| segment_validation_error(id))?;
        let base_length = known.length.max(HEADER_BYTES as u64);
        let final_length = base_length
            .checked_add(new_bytes as u64)
            .ok_or_else(|| segment_validation_error(id))?;
        // XTF's event budget excludes the per-envelope journal digests.
        if new_count > DEFAULT_SEGMENT_EVENTS
            || final_length > MAX_JOURNAL_BYTES as u64
            || final_length - HEADER_BYTES as u64 - new_count as u64 * 32
                > DEFAULT_SEGMENT_EVENT_BYTES as u64
        {
            return Err(segment_validation_error(id));
        }
        let mut candidate = SegmentMetadata::from_logical(&logical, &commit, id)?;
        candidate.first_recording_seq = known.first_sequence;
        {
            #[cfg(test)]
            phase.switch("connection_wait_and_admission");
            let connection = self.store.lock().map_err(|error| map_store_error(error, id))?;
            #[cfg(test)]
            phase.switch("journal_sql_validation");
            validate_recording_anchor(&connection, &commit, id)?;
            validate_new_continuity(&connection, &commit, &candidate, id)?;
            validate_frame_identities(
                &connection,
                &SegmentCommitRequest {
                    events: suffix.iter().map(|event| event.payload.clone()).collect(),
                    ..commit
                },
                id,
            )?;
        }
        #[cfg(test)]
        phase.switch("journal_validation");
        for envelope in suffix {
            let event =
                envelope.payload.event.as_ref().ok_or_else(|| segment_validation_error(id))?;
            if !known.identities.insert(event.event_id.clone()) {
                return Err(frame_identity_error(id));
            }
        }
        if cached && suffix.is_empty() {
            *checkpoint = Some(known);
            return Ok(());
        }
        if !cached
            && known.length >= HEADER_BYTES as u64
            && &known.header[..8] == LEGACY_MAGIC
            && read_boundary(&root, request.recording_id, id)?.is_none()
        {
            let boundary =
                prepare_boundary(&root, request.recording_id, &known.header, known.length, id)?;
            durable_sync(SyncKind::Journal, || sync_recording_file(&file, FileSync::Device))
                .map_err(|_| object_io_error(id))?;
            publish_boundary(&root, request.recording_id, &boundary, id)?;
        }
        let lock = snapshot_lock(&root, request.recording_id, id)?;
        #[cfg(test)]
        phase.switch("snapshot_write_wait");
        let mutation = lock.write().map_err(|_| object_io_error(id))?;
        #[cfg(unix)]
        let file_mutation = snapshot_file_lock(&root, true, id)?;
        #[cfg(test)]
        phase.switch("journal_append");
        // Remove only an incomplete, unacknowledged suffix before an exact retry.
        if length != known.length {
            file.set_len(known.length).map_err(|_| object_io_error(id))?;
        }
        file.seek(SeekFrom::Start(known.length)).map_err(|_| object_io_error(id))?;
        if known.length == 0 {
            file.write_all(&known.header).map_err(|_| object_io_error(id))?;
        }
        for event in suffix {
            let bytes = &event.canonical_bytes;
            let length = u32::try_from(bytes.len()).map_err(|_| segment_validation_error(id))?;
            file.write_all(&length.to_be_bytes())
                .and_then(|()| file.write_all(bytes))
                .and_then(|()| file.write_all(blake3::hash(bytes).as_bytes()))
                .map_err(|_| object_io_error(id))?;
        }
        #[cfg(unix)]
        drop(file_mutation);
        drop(mutation);
        #[cfg(test)]
        phase.switch("checkpoint_prepare");
        let boundary =
            prepare_boundary(&root, request.recording_id, &known.header, final_length, id)?;
        #[cfg(test)]
        BEFORE_SYNC.with(|hook| {
            if let Some(hook) = hook.borrow().as_ref() {
                hook();
            }
        });
        commit_failpoint("journal-before-sync", id, false)?;
        durable_sync(SyncKind::Journal, || sync_recording_file(&file, FileSync::Device))
            .map_err(|_| object_io_error(id))?;
        #[cfg(test)]
        phase.switch("tail_binding_admission");
        root.validate_file_binding(&name, &file, true).map_err(|_| object_io_error(id))?;
        if !cached {
            AdmittedPrivateRoot::open(&self.binding.root)
                .and_then(|parent| sync_journal_directory(&parent))
                .map_err(|_| object_io_error(id))?;
        }
        // The publication directory barrier covers both the tail's creation
        // and checkpoint rename; a cold writer also persisted its parent.
        #[cfg(test)]
        phase.switch("checkpoint_publish");
        publish_boundary(&root, request.recording_id, &boundary, id)?;
        commit_failpoint("journal-after-sync", id, false)?;
        known.length = final_length;
        known.digests.extend_from_slice(&digests[overlap..]);
        *checkpoint = Some(known);
        Ok(())
    }

    pub(crate) fn clear_journal(
        &self,
        recording_id: RecordingId,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        if let Some(root) = directory(&self.binding, false, id)? {
            #[cfg(test)]
            BEFORE_CLEANUP.with(|hook| {
                if let Some(hook) = hook.borrow().as_ref() {
                    hook();
                }
            });
            let lock = snapshot_lock(&root, recording_id, id)?;
            let _snapshot = lock.write().map_err(|_| object_io_error(id))?;
            #[cfg(unix)]
            let _file_snapshot = snapshot_file_lock(&root, true, id)?;
            let mut removed_boundary = false;
            for name in
                [boundary_name(recording_id), format!("{}-next", boundary_name(recording_id))]
            {
                match std::fs::symlink_metadata(root.path().join(&name)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(object_io_error(id)),
                    Ok(_) => {}
                }
                root.remove_private_file(&name).map_err(|_| object_io_error(id))?;
                removed_boundary = true;
            }
            let name = name(recording_id);
            match std::fs::symlink_metadata(root.path().join(&name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if removed_boundary {
                        sync_journal_directory(&root).map_err(|_| object_io_error(id))?;
                    }
                    return Ok(());
                }
                Err(_) => return Err(object_io_error(id)),
                Ok(_) => {}
            }
            // Repeat this barrier even if a prior attempt already unlinked the
            // checkpoint: its absence must be durable before the tail vanishes.
            sync_journal_directory(&root).map_err(|_| object_io_error(id))?;
            commit_failpoint("journal-cleanup-before-tail-removal", id, false)?;
            root.remove_private_file(&name).map_err(|_| object_io_error(id))?;
            sync_journal_directory(&root).map_err(|_| object_io_error(id))?;
        }
        Ok(())
    }

    pub(crate) fn clear_segment_journal(
        &self,
        recording_id: RecordingId,
        ordinal: u32,
    ) -> Result<bool, RecordingStoreError> {
        let id = CorrelationId::new();
        let _writer =
            self.store.lock_recording_writer(id).map_err(|error| map_store_error(error, id))?;
        // Pending bytes still identify the segment after checkpoint removal.
        // Never clear a newer tail when replaying an older immutable segment.
        let tail = load_for_retry(&self.binding, recording_id, id, true)?;
        if tail.as_ref().is_none_or(|tail| tail.ordinal == ordinal) {
            self.clear_journal(recording_id)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// A normal XTF publication may extend an acknowledged journal prefix,
    /// but must never replace or shorten it, including through a fresh port.
    pub(super) fn validate_journal_segment(
        &self,
        request: &SegmentCommitRequest,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        if let Some(tail) = load(&self.binding, request.recording_id, id)? {
            if tail.ordinal == request.segment_ordinal
                && (tail.project_id != request.project_id
                    || !request.events.starts_with(&tail.events))
            {
                return Err(segment_conflict_error(id));
            }
        }
        Ok(())
    }

    /// Publish the tail before terminal verification. A crash after publication
    /// leaves a stale journal; verify its prefix against the immutable object.
    /// The caller holds the store writer through publication, cleanup and Finish.
    pub(super) fn recover_journal_under_writer(
        &self,
        recording_id: RecordingId,
    ) -> Result<(), RecordingStoreError> {
        let id = CorrelationId::new();
        let Some(tail) = load(&self.binding, recording_id, id)? else {
            // No checkpoint means no acknowledged events, not no files. Also
            // remove an interrupted initial header and an orphan commit-next.
            return self.clear_journal(recording_id);
        };
        if tail.events.is_empty() {
            return self.clear_journal(recording_id);
        }
        let existing = {
            let connection = self.store.lock().map_err(|error| map_store_error(error, id))?;
            load_segment_row(&connection, recording_id, tail.ordinal, id)?
        };
        if let Some(existing) = existing {
            let path = object_path_from_row(&self.binding.root, &existing.object_hash, id)?;
            let bytes = read_bounded_regular_file(&path, id, false)?;
            let hash = content_hash_from_bytes(&existing.object_hash, id)?;
            let decoded = crate::xtf::decode_compressed_segment(&bytes, hash)
                .map_err(|_| object_corrupt_error(id))?;
            if decoded.verified().project_id() != tail.project_id
                || decoded.verified().recording_id() != recording_id
                || decoded.verified().segment_ordinal() != tail.ordinal
                || !decoded.events().starts_with(&tail.events)
            {
                return Err(object_corrupt_error(id));
            }
        } else {
            self.commit_segment_under_writer(&SegmentCommitRequest {
                project_id: tail.project_id,
                recording_id,
                segment_ordinal: tail.ordinal,
                events: tail.events,
            })?;
        }
        self.clear_journal(recording_id)
    }

    /// Journal events beyond the sealed prefix, for truthful lifecycle metadata.
    #[cfg(test)]
    pub(crate) fn journal_summary(
        &self,
        recording_id: RecordingId,
        sealed_last: u64,
    ) -> Result<Option<(u64, u64, u64)>, RecordingStoreError> {
        summarize(load(&self.binding, recording_id, CorrelationId::new())?, sealed_last)
    }
}

fn summarize(
    tail: Option<Tail>,
    sealed_last: u64,
) -> Result<Option<(u64, u64, u64)>, RecordingStoreError> {
    let id = CorrelationId::new();
    let Some(tail) = tail else { return Ok(None) };
    let mut sequences = tail
        .events
        .iter()
        .filter_map(|envelope| envelope.event.as_ref())
        .map(|event| event.recording_seq)
        .filter(|sequence| *sequence > sealed_last);
    let Some(first) = sequences.next() else { return Ok(None) };
    let mut last = first;
    let mut count = 1;
    for sequence in sequences {
        last = sequence;
        count += 1;
    }
    if sealed_last.checked_add(1) != Some(first) {
        return Err(object_corrupt_error(id));
    }
    Ok(Some((first, last, count)))
}
