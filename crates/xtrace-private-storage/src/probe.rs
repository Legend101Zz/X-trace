//! ACL probes and the per-operation verdict memo.
//!
//! Admission walks every component of a path, and on macOS the only available oracle for "does
//! this directory carry an ACL" is a `/bin/ls -ldeO` subprocess. A single operation (one
//! `revalidate`, one `create_private_child`, ...) used to spawn it several times per component. An
//! [`Operation`] bounds one such operation with a single deadline and remembers which directory
//! *states* it has already judged acceptable, so each distinct state is probed once.
//!
//! # Why the memo cannot admit a changed directory
//!
//! A remembered verdict is keyed by the directory's complete observable state, read from the
//! opened descriptor: device, inode, owner, mode, **and ctime** (plus the policy class that was
//! judged). Every chmod, chown, ACL edit, or extended-attribute edit bumps ctime, and creating or
//! removing a child bumps the ctime of the directory that changed. So a hit proves that the
//! descriptor still shows exactly the state that was probed, and any change misses and is probed
//! again. A hit is additionally gated by the same stat-based checks as a fresh probe: the named
//! path must still resolve to the same directory (not a symlink) with the identity the caller
//! expects, and the descriptor must match that identity. The memo lives inside one [`Operation`]
//! (one bounded 750 ms budget) and is dropped with it; it is never shared across threads or
//! processes. Outside an admission scope it is never shared across operations either.
//!
//! # Admission scope (ADR 0008 Amendment 1)
//!
//! An operation created on a thread with a live, un-expired [`crate::AdmissionScope`] shares the
//! scope's memo and batched listing instead. Its key additionally carries the filesystem
//! identity and mount flags of the held descriptor (`f_fsid`, `f_flags`) and the operation's
//! filesystem profile, so a verdict judged under one profile never serves another. The identity
//! checks, the per-operation deadline and the named-file probes are unchanged.

use std::cell::RefCell;
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::admission::FileIdentity;
use crate::policy::{DirectoryRole, FilesystemProfile};
use crate::scope;

/// Most verdicts one scope remembers; beyond it new verdicts are simply not stored.
const SCOPE_MEMO_LIMIT: usize = 1024;

/// Total time one admission operation may spend, ACL probes included.
pub(crate) const ADMISSION_BUDGET: Duration = Duration::from_millis(750);
/// How often an owned ACL probe is polled for exit. A local `ls` finishes in a few
/// milliseconds, so a coarse interval would be most of every admission's cost.
#[cfg(target_os = "macos")]
const ACL_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(target_os = "macos")]
const ACL_PROBE_CLEANUP_BUDGET: Duration = Duration::from_millis(100);

/// Complete observable state of a directory, as read from its opened descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryState {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
    /// Whether the strict (no-ACL) Linux policy was judged. macOS has one policy for all roles.
    strict: bool,
}

impl DirectoryState {
    fn of(metadata: &std::fs::Metadata, role: DirectoryRole) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
            strict: cfg!(not(target_os = "macos"))
                && matches!(role, DirectoryRole::PrivateLeaf | DirectoryRole::Sealed { .. }),
        }
    }
}

/// Key of a verdict shared through an admission scope: the directory state, the identity and
/// mount flags of the filesystem holding it, and the profile it was judged under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MemoKey {
    state: DirectoryState,
    /// The full `f_fsid` value, rendered (the libc type has no public fields).
    fsid: String,
    flags: u64,
    /// The filesystem type name (`f_fstypename`); only `apfs` is ever shared across operations.
    fstype: String,
    profile: FilesystemProfile,
}

impl MemoKey {
    fn from_parts(
        state: DirectoryState,
        fsid: String,
        flags: u64,
        fstype: String,
        profile: FilesystemProfile,
    ) -> Self {
        Self { state, fsid, flags, fstype, profile }
    }

    /// The key for `directory` in `state`, read from its held descriptor.
    fn of_descriptor(
        state: DirectoryState,
        directory: &File,
        profile: FilesystemProfile,
    ) -> Option<Self> {
        let stats = rustix::fs::fstatfs(directory).ok()?;
        let (fsid, flags, fstype) = filesystem_identity(&stats);
        // HFS+ stamps ctime with one-second granularity, so a change shortly after a probe can
        // leave the key equal. Only filesystems with nanosecond ctime share verdicts.
        scope_shares_filesystem(&fstype)
            .then(|| Self::from_parts(state, fsid, flags, fstype, profile))
    }
}

/// Whether verdicts and batched listings of this filesystem type may be reused beyond one
/// operation. macOS: APFS only (nanosecond ctime). Elsewhere the scope exists for tests alone.
#[cfg(target_os = "macos")]
fn scope_shares_filesystem(fstype: &str) -> bool {
    fstype == "apfs"
}

#[cfg(not(target_os = "macos"))]
fn scope_shares_filesystem(_fstype: &str) -> bool {
    true
}

#[cfg(target_os = "macos")]
fn filesystem_identity(stats: &rustix::fs::StatFs) -> (String, u64, String) {
    let name = stats
        .f_fstypename
        .iter()
        .map(|unit| unit.to_ne_bytes()[0])
        .take_while(|byte| *byte != 0)
        .collect::<Vec<u8>>();
    (
        format!("{:?}", stats.f_fsid),
        u64::from(stats.f_flags),
        String::from_utf8_lossy(&name).into_owned(),
    )
}

/// Only macOS memoizes in production; elsewhere the memo exists for tests alone, where the
/// device number in the state already separates filesystems.
#[cfg(not(target_os = "macos"))]
fn filesystem_identity(_stats: &rustix::fs::StatFs) -> (String, u64, String) {
    (String::new(), 0, String::new())
}

/// One bounded admission operation: a single deadline plus the verdicts earned inside it.
pub(crate) struct Operation {
    deadline: Instant,
    profile: crate::policy::FilesystemProfile,
    memoize: bool,
    judged: RefCell<Vec<DirectoryState>>,
    /// The admission scope that was live on the creating thread when this operation was made.
    scope_id: Option<u64>,
    /// Prefix operands of the most recent ancestor walk; the batch is spawned lazily from them.
    #[cfg(target_os = "macos")]
    walk: RefCell<Vec<std::path::PathBuf>>,
    /// Whether this operation's one batch has been attempted (outside a scope).
    #[cfg(target_os = "macos")]
    batch_attempted: std::cell::Cell<bool>,
    /// The batched listing taken for this operation when no scope holds it.
    #[cfg(target_os = "macos")]
    prefetched: RefCell<Option<Prefetched>>,
}

/// Listings for every component of a walk, taken by one `ls` run at `taken_at`.
#[cfg(target_os = "macos")]
pub(crate) struct Prefetched {
    taken_at: std::time::SystemTime,
    /// Monotonic stamp of the same moment, so reuse can notice the realtime clock stepping.
    taken_mono: Instant,
    entries: Vec<BatchEntry>,
}

/// One batched listing, bound to the device and inode `lstat` reported for its operand.
#[cfg(any(target_os = "macos", test))]
pub(crate) struct BatchEntry {
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only the macOS batch looks entries up by path")
    )]
    path: std::path::PathBuf,
    device: u64,
    listing: crate::policy::BatchedListing,
}

impl Operation {
    /// A fresh operation with the ordinary admission budget.
    pub(crate) fn new() -> Self {
        Self::until(Instant::now() + ADMISSION_BUDGET)
    }

    /// An operation inside a caller's larger deadline, never longer than the ordinary budget.
    pub(crate) fn capped(operation_deadline: Instant) -> Self {
        Self::until(operation_deadline.min(Instant::now() + ADMISSION_BUDGET))
    }

    fn until(deadline: Instant) -> Self {
        // The memo exists because a macOS probe is a subprocess. A Linux probe is two
        // extended-attribute reads, so Linux keeps probing every time, exactly as before, rather
        // than relying on ctime granularity of the filesystem for no gain.
        let memoize = cfg!(target_os = "macos");
        Self {
            deadline,
            profile: crate::policy::FilesystemProfile::Durable,
            memoize,
            judged: RefCell::new(Vec::new()),
            scope_id: if memoize { scope::live_scope_id() } else { None },
            #[cfg(target_os = "macos")]
            walk: RefCell::new(Vec::new()),
            #[cfg(target_os = "macos")]
            batch_attempted: std::cell::Cell::new(false),
            #[cfg(target_os = "macos")]
            prefetched: RefCell::new(None),
        }
    }

    /// An operation that memoizes on every platform, so the memo logic is testable on Linux.
    #[cfg(test)]
    pub(crate) fn memoizing() -> Self {
        Self { memoize: true, scope_id: scope::live_scope_id(), ..Self::new() }
    }

    /// The same operation judging filesystems under `profile`.
    pub(crate) fn with_profile(mut self, profile: crate::policy::FilesystemProfile) -> Self {
        self.profile = profile;
        self
    }

    pub(crate) fn profile(&self) -> crate::policy::FilesystemProfile {
        self.profile
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Registers the prefix operands of an ancestor walk. Nothing is spawned here: the batched
    /// listing is taken lazily, by [`Self::spawn_batch_for`], only when a directory on the walk
    /// misses the memo and no usable batched entry exists.
    #[cfg(target_os = "macos")]
    pub(crate) fn register_walk(&self, paths: &[std::path::PathBuf]) {
        if !self.memoize || paths.len() < 2 {
            return;
        }
        *self.walk.borrow_mut() = paths.to_vec();
    }

    /// Takes the one batched listing this operation (or its scope) may take, when `path` is on
    /// the registered walk. Returns whether a batch is now held.
    ///
    /// The listings are not verdicts. `prefetched_verdict` uses one only for a directory whose
    /// opened descriptor reports the listing's inode and a ctime that is older than the moment
    /// the listing was taken, which proves the directory has not been modified since (a chmod,
    /// ACL edit or child change all advance ctime) and is the object that was listed. Otherwise
    /// that directory is probed on its own, so a batch that is stale, misparsed or raced never
    /// admits anything.
    #[cfg(target_os = "macos")]
    fn spawn_batch_for(&self, path: &Path) -> bool {
        if !self.memoize || !self.walk.borrow().iter().any(|operand| operand == path) {
            return false;
        }
        let scope_first = self.scope_id.and_then(|id| {
            scope::with_scope(id, |state| !std::mem::replace(&mut state.batch_attempted, true))
        });
        let first = match scope_first {
            Some(first) => first,
            None => !self.batch_attempted.replace(true),
        };
        if !first {
            return false;
        }
        let paths = self.walk.borrow().clone();
        let Some(batch) = self.take_batch(&paths) else { return false };
        let mut batch = Some(batch);
        if scope_first.is_some() {
            if let Some(id) = self.scope_id {
                scope::with_scope(id, |state| state.batch = batch.take());
            }
        }
        if batch.is_some() {
            *self.prefetched.borrow_mut() = batch;
        }
        true
    }

    #[cfg(target_os = "macos")]
    fn take_batch(&self, paths: &[std::path::PathBuf]) -> Option<Prefetched> {
        #[cfg(test)]
        BATCH_ATTEMPTS.with(|count| count.set(count.get() + 1));
        let names = paths.iter().map(|path| path.to_str()).collect::<Option<Vec<_>>>()?;
        let before =
            paths.iter().map(|path| std::fs::symlink_metadata(path).ok()).collect::<Vec<_>>();
        let started = Instant::now();
        let taken_at = std::time::SystemTime::now();
        let operands = paths.iter().map(std::path::PathBuf::as_path).collect::<Vec<_>>();
        let text = run_ls("-ldeOi", &operands, self.deadline, BATCH_OUTPUT_LIMIT)?;
        // A realtime clock that stepped while `ls` ran (or went backwards) makes `taken_at`
        // meaningless for the ctime comparison: drop the whole batch.
        if !clock_is_consistent(taken_at, std::time::SystemTime::now(), started.elapsed()) {
            return None;
        }
        let parsed = crate::policy::split_batched_listing(&text, &names)?;
        let mut entries = Vec::new();
        for ((path, listing), before) in paths.iter().zip(parsed).zip(before) {
            // Bind the listing to (device, inode) as `lstat` saw them on both sides of the run;
            // an operand that moved, vanished or disagrees with the listing is simply left out.
            use std::os::unix::fs::MetadataExt as _;
            let after = std::fs::symlink_metadata(path).ok();
            let (Some(before), Some(after)) = (before, after) else { continue };
            if before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.ino() == listing.inode
            {
                entries.push(BatchEntry { path: path.clone(), device: before.dev(), listing });
            }
        }
        Some(Prefetched { taken_at, taken_mono: started, entries })
    }

    /// The scope-level key for `directory` in `state`, when this operation shares a live scope.
    fn scope_key(&self, state: DirectoryState, directory: &File) -> Option<MemoKey> {
        let id = self.scope_id?;
        scope::with_scope(id, |_| ())?;
        MemoKey::of_descriptor(state, directory, self.profile)
    }

    fn scope_has(&self, key: &MemoKey) -> bool {
        self.scope_id
            .and_then(|id| scope::with_scope(id, |state| state.memo.contains(key)))
            .unwrap_or(false)
    }

    fn scope_remember(&self, key: MemoKey) {
        if let Some(id) = self.scope_id {
            scope::with_scope(id, |state| {
                if state.memo.len() < SCOPE_MEMO_LIMIT && !state.memo.contains(&key) {
                    state.memo.push(key);
                }
            });
        }
    }

    fn already_judged(&self, state: &DirectoryState) -> bool {
        self.memoize && self.judged.borrow().contains(state)
    }

    fn remember(&self, state: DirectoryState) {
        if !self.memoize {
            return;
        }
        let mut judged = self.judged.borrow_mut();
        if !judged.contains(&state) {
            judged.push(state);
        }
    }
}

#[cfg(test)]
thread_local! {
    static DIRECTORY_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROBED_PATHS: RefCell<Vec<std::path::PathBuf>> = const { RefCell::new(Vec::new()) };
}

/// Every directory path this thread has probed, in order. Lets a test ignore a directory that
/// other tests are busy in, which would otherwise make its probe count nondeterministic.
#[cfg(test)]
pub(crate) fn probed_paths() -> Vec<std::path::PathBuf> {
    PROBED_PATHS.with(|paths| paths.borrow().clone())
}

/// Number of real directory ACL probes this thread has run (a `/bin/ls` spawn on macOS, the
/// extended-attribute reads on Linux). Test seam for the probe-count bounds.
#[cfg(test)]
pub(crate) fn directory_probe_count() -> usize {
    DIRECTORY_PROBES.with(std::cell::Cell::get)
}

fn directory_is_expected(path: &Path, expected: FileIdentity, opened: &std::fs::Metadata) -> bool {
    let Ok(named) = std::fs::symlink_metadata(path) else { return false };
    !named.file_type().is_symlink()
        && named.is_dir()
        && expected.same_directory(FileIdentity::from_metadata(&named))
        && expected.same_directory(FileIdentity::from_metadata(opened))
}

/// Judges a directory's ACL for `role`, probing at most once per directory state per operation.
///
/// The named-path and descriptor identity checks run on every call, hit or miss, and again after
/// a fresh probe; only the ACL query itself is skipped on a hit. See the module documentation for
/// why a hit cannot admit a directory whose state changed.
pub(crate) fn directory_acl_admits(
    operation: &Operation,
    role: DirectoryRole,
    path: &Path,
    directory: &File,
    expected: FileIdentity,
) -> bool {
    let Ok(before) = directory.metadata() else { return false };
    if !directory_is_expected(path, expected, &before) {
        return false;
    }
    let state = DirectoryState::of(&before, role);
    if operation.already_judged(&state) {
        return true;
    }
    let scope_key = operation.scope_key(state, directory);
    if scope_key.as_ref().is_some_and(|key| operation.scope_has(key)) {
        return true;
    }
    #[cfg(test)]
    {
        DIRECTORY_PROBES.with(|count| count.set(count.get() + 1));
        PROBED_PATHS.with(|paths| paths.borrow_mut().push(path.to_path_buf()));
    }
    if !probe_directory(operation, role, path, directory) {
        return false;
    }
    let Ok(after) = directory.metadata() else { return false };
    if !directory_is_expected(path, expected, &after) {
        return false;
    }
    // Remember the verdict only if the directory did not change while it was being probed. A
    // busy directory (siblings creating children) bumps ctime constantly; that must not turn a
    // good verdict into a refusal, it only means this verdict is too old to reuse.
    if DirectoryState::of(&after, role) == state {
        operation.remember(state);
        if let Some(key) = scope_key {
            if operation.scope_key(DirectoryState::of(&after, role), directory).as_ref()
                == Some(&key)
            {
                operation.scope_remember(key);
            }
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn read_acl_attribute(directory: &File, name: &str) -> Result<Option<Vec<u8>>, ()> {
    let mut value = vec![0_u8; 16 * 1024];
    match rustix::fs::fgetxattr(directory, name, value.as_mut_slice()) {
        Ok(length) => {
            value.truncate(length);
            Ok(Some(value))
        }
        Err(error) if error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA => {
            Ok(None)
        }
        Err(_) => Err(()),
    }
}

#[cfg(target_os = "linux")]
fn probe_directory(
    _operation: &Operation,
    role: DirectoryRole,
    _path: &Path,
    directory: &File,
) -> bool {
    let Ok(access) = read_acl_attribute(directory, "system.posix_acl_access") else {
        return false;
    };
    let Ok(default) = read_acl_attribute(directory, "system.posix_acl_default") else {
        return false;
    };
    crate::policy::linux_directory_acl_admits(role, access.as_deref(), default.as_deref())
}

#[cfg(target_os = "macos")]
fn probe_directory(
    operation: &Operation,
    _role: DirectoryRole,
    path: &Path,
    directory: &File,
) -> bool {
    if let Some(verdict) = prefetched_verdict(operation, path, directory) {
        return verdict;
    }
    // Lazy batch: taken only now that a directory on the walk missed the memo.
    if operation.spawn_batch_for(path) {
        if let Some(verdict) = prefetched_verdict(operation, path, directory) {
            return verdict;
        }
    }
    let Some(text) = run_acl_listing(path, operation.deadline()) else { return false };
    path.to_str()
        .is_some_and(|expected| crate::policy::macos_directory_listing_admits(&text, expected))
}

/// A ctime must be at least this much older than the batched listing to be trusted.
#[cfg(any(target_os = "macos", test))]
const PREFETCH_QUIET_PERIOD: Duration = Duration::from_millis(20);
/// How far the realtime clock may disagree with the monotonic clock over one `ls` run.
#[cfg(any(target_os = "macos", test))]
const CLOCK_TOLERANCE: Duration = Duration::from_millis(50);

/// Whether the realtime clock behaved over a batch: it did not go backwards, and the time it
/// measured agrees with the monotonic clock to within [`CLOCK_TOLERANCE`].
#[cfg(any(target_os = "macos", test))]
fn clock_is_consistent(
    taken_at: std::time::SystemTime,
    after: std::time::SystemTime,
    monotonic_elapsed: Duration,
) -> bool {
    after.duration_since(taken_at).is_ok_and(|realtime_elapsed| {
        realtime_elapsed.abs_diff(monotonic_elapsed) <= CLOCK_TOLERANCE
    })
}

/// Whether a batched entry provably describes the object behind a descriptor.
///
/// The listing is trusted only if device and inode both match the descriptor's, and the
/// descriptor's ctime is at least [`PREFETCH_QUIET_PERIOD`] older than the batch (so, absent root
/// controlling the clock, nothing changed the directory between the listing and the descriptor
/// read; any mode, owner, ACL, flag or xattr edit advances ctime). A ctime in the future of the
/// batch also fails this test.
#[cfg(any(target_os = "macos", test))]
fn batch_entry_describes(
    batch_taken_at: std::time::SystemTime,
    entry: &BatchEntry,
    device: u64,
    inode: u64,
    ctime: std::time::SystemTime,
) -> bool {
    entry.device == device
        && entry.listing.inode == inode
        && ctime.checked_add(PREFETCH_QUIET_PERIOD).is_some_and(|quiet| quiet <= batch_taken_at)
}

/// Judges `directory` from the batched listing (the scope's, else the operation's own) when
/// that listing provably describes it. Directories modified recently (busy ones) and
/// directories the batch does not cover return `None` and are probed on their own.
#[cfg(target_os = "macos")]
fn prefetched_verdict(operation: &Operation, path: &Path, directory: &File) -> Option<bool> {
    let from_scope = operation.scope_id.and_then(|id| {
        scope::with_scope(id, |state| {
            state.batch.as_ref().and_then(|batch| verdict_from_batch(batch, path, directory))
        })
    });
    if let Some(Some(verdict)) = from_scope {
        return Some(verdict);
    }
    let own = operation.prefetched.borrow();
    own.as_ref().and_then(|batch| verdict_from_batch(batch, path, directory))
}

/// Whether a batch taken at (`taken_at`, `taken_mono`) may still be trusted at (`now`,
/// `now_mono`): the realtime clock has neither stepped back nor drifted from the monotonic one.
#[cfg(any(target_os = "macos", test))]
fn batch_clock_trusted(
    taken_at: std::time::SystemTime,
    taken_mono: Instant,
    now: std::time::SystemTime,
    now_mono: Instant,
) -> bool {
    clock_is_consistent(taken_at, now, now_mono.saturating_duration_since(taken_mono))
}

#[cfg(target_os = "macos")]
fn verdict_from_batch(batch: &Prefetched, path: &Path, directory: &File) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;

    // A batch is reused for up to a scope (10 s): re-check the realtime clock on every reuse and
    // fall back to a single probe if it stepped.
    if !batch_clock_trusted(
        batch.taken_at,
        batch.taken_mono,
        std::time::SystemTime::now(),
        Instant::now(),
    ) {
        return None;
    }
    // Batch reuse is APFS-only for the same ctime-granularity reason as the scope memo.
    let stats = rustix::fs::fstatfs(directory).ok()?;
    if !scope_shares_filesystem(&filesystem_identity(&stats).2) {
        return None;
    }
    let entry = batch.entries.iter().find(|entry| entry.path == path)?;
    let metadata = directory.metadata().ok()?;
    let ctime = std::time::UNIX_EPOCH
        + Duration::new(
            u64::try_from(metadata.ctime()).ok()?,
            u32::try_from(metadata.ctime_nsec()).ok()?,
        );
    if !batch_entry_describes(batch.taken_at, entry, metadata.dev(), metadata.ino(), ctime) {
        return None;
    }
    Some(path.to_str().is_some_and(|expected| {
        crate::policy::macos_directory_listing_admits(&entry.listing.text, expected)
    }))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe_directory(
    _operation: &Operation,
    _role: DirectoryRole,
    _path: &Path,
    _directory: &File,
) -> bool {
    false
}

/// Descriptor-free ACL admission of a named regular file.
#[cfg(target_os = "linux")]
pub(crate) fn named_file_acl_admits(
    path: &Path,
    _identity: FileIdentity,
    _operation: &Operation,
) -> bool {
    let mut value = [0_u8; 16 * 1024];
    match rustix::fs::lgetxattr(path, "system.posix_acl_access", value.as_mut_slice()) {
        Ok(_) => false,
        Err(error) => error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn named_file_acl_admits(
    path: &Path,
    identity: FileIdentity,
    operation: &Operation,
) -> bool {
    if !file_listing_admits(path, operation) {
        return false;
    }
    // Same inode, owner and mode; size is excluded because live SQLite files grow.
    std::fs::symlink_metadata(path)
        .is_ok_and(|named| identity.same_directory(FileIdentity::from_metadata(&named)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn named_file_acl_admits(
    _path: &Path,
    _identity: FileIdentity,
    _operation: &Operation,
) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub(crate) fn acl_admits_file(
    _path: &Path,
    file: &File,
    _expected: FileIdentity,
    _operation: &Operation,
) -> bool {
    let mut value = [0_u8; 16 * 1024];
    match rustix::fs::fgetxattr(file, "system.posix_acl_access", value.as_mut_slice()) {
        Ok(_) => false,
        Err(error) => error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn acl_admits_file(
    path: &Path,
    file: &File,
    expected: FileIdentity,
    operation: &Operation,
) -> bool {
    if !file_listing_admits(path, operation) {
        return false;
    }
    let Ok(named) = std::fs::symlink_metadata(path) else { return false };
    let Ok(opened) = file.metadata() else { return false };
    expected.same_file(FileIdentity::from_metadata(&named))
        && expected.same_file(FileIdentity::from_metadata(&opened))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn acl_admits_file(
    _path: &Path,
    _file: &File,
    _expected: FileIdentity,
    _operation: &Operation,
) -> bool {
    false
}

/// Path-based macOS ACL probe for a regular file; never opens the file.
#[cfg(target_os = "macos")]
fn file_listing_admits(path: &Path, operation: &Operation) -> bool {
    let Some(text) = run_acl_listing(path, operation.deadline()) else { return false };
    path.to_str().is_some_and(|expected| crate::policy::macos_file_listing_admits(&text, expected))
}

/// Longest single-directory listing accepted.
#[cfg(target_os = "macos")]
const LISTING_OUTPUT_LIMIT: usize = 16_384;
/// Longest batched listing accepted (a walk is at most 129 directories).
#[cfg(target_os = "macos")]
const BATCH_OUTPUT_LIMIT: usize = 512 * 1024;

#[cfg(all(target_os = "macos", test))]
thread_local! {
    static LS_SPAWNS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static BATCH_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Number of batched listings this thread has attempted. Test seam for the lazy-batch rule.
#[cfg(all(target_os = "macos", test))]
pub(crate) fn batch_attempt_count() -> usize {
    BATCH_ATTEMPTS.with(std::cell::Cell::get)
}

/// Number of `/bin/ls` processes this thread has spawned. Test seam for spawn-count bounds.
#[cfg(all(target_os = "macos", test))]
pub(crate) fn ls_spawn_count() -> usize {
    LS_SPAWNS.with(std::cell::Cell::get)
}

/// Runs `/bin/ls -ldeO <path>` under the deadline and returns its bounded stdout.
#[cfg(target_os = "macos")]
fn run_acl_listing(path: &Path, deadline: Instant) -> Option<String> {
    run_ls("-ldeO", &[path], deadline, LISTING_OUTPUT_LIMIT)
}

/// Runs `/bin/ls <flags> <paths...>` under the deadline and returns its bounded stdout.
///
/// This is the only place that spawns the probe. Any failure (control characters in a path,
/// spawn failure, deadline, oversized or non-UTF-8 output, nonzero exit) is `None`, which every
/// caller treats as a refusal or a fallback to a single-directory probe.
#[cfg(target_os = "macos")]
fn run_ls(flags: &str, paths: &[&Path], deadline: Instant, limit: usize) -> Option<String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    if Instant::now() >= deadline
        || paths.iter().any(|path| path.as_os_str().to_string_lossy().chars().any(char::is_control))
    {
        return None;
    }
    #[cfg(test)]
    LS_SPAWNS.with(|count| count.set(count.get() + 1));
    #[cfg(feature = "spawn-counter")]
    crate::spawn_counter::record_ls_spawn();
    let Ok(mut child) = Command::new("/bin/ls")
        .arg(flags)
        .args(paths)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return None;
    };
    let Some(mut stdout) = child.stdout.take() else {
        report_acl_probe_cleanup(stop_acl_probe(&mut child, probe_cleanup_deadline(deadline)));
        return None;
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.by_ref().take(limit as u64 + 1).read_to_end(&mut bytes);
        // A failed send only means the receiver is gone, so there is nobody left to tell.
        let _ = sender.send((result.is_ok() && bytes.len() <= limit, bytes));
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(
                deadline.saturating_duration_since(Instant::now()).min(ACL_PROBE_POLL_INTERVAL),
            ),
            _ => break None,
        }
    };
    if status.is_none() {
        let cleanup_deadline = probe_cleanup_deadline(deadline);
        report_acl_probe_cleanup(stop_acl_probe(&mut child, cleanup_deadline));
        match receiver.recv_timeout(cleanup_deadline.saturating_duration_since(Instant::now())) {
            Ok(_) => {
                if reader.join().is_err() {
                    tracing::warn!("private storage ACL reader did not join after probe cleanup");
                }
            }
            Err(_) => tracing::warn!("private storage ACL reader drain is unconfirmed"),
        }
        return None;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let Ok((bounded, bytes)) = receiver.recv_timeout(remaining) else {
        tracing::warn!("private storage ACL reader drain is unconfirmed");
        return None;
    };
    if reader.join().is_err() || !status.is_some_and(|value| value.success()) || !bounded {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Requests termination of the owned ACL probe and confirms reaping within a
/// short bounded cleanup window. Failure remains a closed admission result.
#[cfg(target_os = "macos")]
fn stop_acl_probe(child: &mut std::process::Child, deadline: Instant) -> bool {
    use std::thread;

    if let Err(error) = child.kill() {
        if error.kind() != std::io::ErrorKind::InvalidInput {
            return false;
        }
    }
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => thread::sleep(
                deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(5)),
            ),
            _ => return false,
        }
    }
}

#[cfg(target_os = "macos")]
fn probe_cleanup_deadline(admission_deadline: Instant) -> Instant {
    admission_deadline + ACL_PROBE_CLEANUP_BUDGET
}

#[cfg(target_os = "macos")]
fn report_acl_probe_cleanup(drained: bool) {
    if !drained {
        tracing::warn!("private storage ACL probe drain is unconfirmed");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests assert on fixture setup")]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn entry(device: u64, inode: u64) -> BatchEntry {
        BatchEntry {
            path: std::path::PathBuf::from("/d"),
            device,
            listing: crate::policy::BatchedListing { inode, text: String::new() },
        }
    }

    #[test]
    fn a_batched_entry_binds_only_to_the_same_device_inode_and_a_quiet_ctime() {
        use std::time::{Duration as D, UNIX_EPOCH};
        let taken = UNIX_EPOCH + D::from_secs(1_000);
        let quiet = taken - D::from_millis(21);
        assert!(batch_entry_describes(taken, &entry(7, 42), 7, 42, quiet));
        assert!(!batch_entry_describes(taken, &entry(7, 42), 7, 43, quiet), "inode mismatch");
        assert!(!batch_entry_describes(taken, &entry(7, 42), 8, 42, quiet), "device mismatch");
        assert!(!batch_entry_describes(taken, &entry(7, 42), 7, 42, taken - D::from_millis(19)));
        assert!(!batch_entry_describes(taken, &entry(7, 42), 7, 42, taken), "ctime at the batch");
        assert!(!batch_entry_describes(taken, &entry(7, 42), 7, 42, taken + D::from_secs(5)));
    }

    #[test]
    fn a_batch_is_dropped_when_the_realtime_clock_stepped_or_disagrees() {
        use std::time::{Duration as D, UNIX_EPOCH};
        let taken = UNIX_EPOCH + D::from_secs(1_000);
        let elapsed = D::from_millis(30);
        assert!(clock_is_consistent(taken, taken + D::from_millis(30), elapsed));
        assert!(clock_is_consistent(taken, taken + D::from_millis(70), elapsed));
        // Stepped back during the run, or a forward step much larger than the monotonic time.
        assert!(!clock_is_consistent(taken, taken - D::from_secs(3_600), elapsed));
        assert!(!clock_is_consistent(taken, taken - D::from_millis(1), elapsed));
        assert!(!clock_is_consistent(taken, taken + D::from_secs(3_600), elapsed));
        assert!(!clock_is_consistent(taken, taken + D::from_millis(100), elapsed));
    }

    #[test]
    fn a_reused_batch_is_refused_when_the_realtime_clock_steps_between_reuses() {
        use std::time::{Duration as D, UNIX_EPOCH};
        let mono = Instant::now();
        let taken = UNIX_EPOCH + D::from_secs(1_000);
        let later = mono + D::from_secs(5);
        assert!(batch_clock_trusted(taken, mono, taken + D::from_secs(5), later));
        assert!(batch_clock_trusted(taken, mono, taken + D::from_millis(5_040), later));
        // Realtime stepped back, or jumped forward, while the monotonic clock moved 5 s.
        assert!(!batch_clock_trusted(taken, mono, taken - D::from_secs(1), later));
        assert!(!batch_clock_trusted(taken, mono, taken + D::from_secs(3_600), later));
        assert!(!batch_clock_trusted(taken, mono, taken + D::from_millis(5_100), later));
        assert!(!batch_clock_trusted(taken, mono, taken, later), "frozen realtime clock");
    }

    fn identity_of(directory: &File) -> FileIdentity {
        FileIdentity::from_metadata(&directory.metadata().expect("directory metadata"))
    }

    fn open(path: &Path) -> File {
        File::open(path).expect("open fixture directory")
    }

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().expect("fixture directory")
    }

    fn judge(operation: &Operation, path: &Path, directory: &File) -> bool {
        directory_acl_admits(
            operation,
            DirectoryRole::Traversed,
            path,
            directory,
            identity_of(directory),
        )
    }

    #[test]
    fn an_unchanged_directory_is_probed_once_per_operation() {
        let root = fixture();
        let directory = open(root.path());
        let operation = Operation::memoizing();
        let before = directory_probe_count();
        for _ in 0..5 {
            assert!(judge(&operation, root.path(), &directory));
        }
        assert_eq!(directory_probe_count() - before, 1);
    }

    #[test]
    fn a_new_operation_never_reuses_a_verdict() {
        let root = fixture();
        let directory = open(root.path());
        let before = directory_probe_count();
        for _ in 0..3 {
            assert!(judge(&Operation::memoizing(), root.path(), &directory));
        }
        assert_eq!(directory_probe_count() - before, 3);
    }

    #[test]
    fn a_strict_and_a_traversal_verdict_are_remembered_separately_on_linux() {
        let root = fixture();
        let directory = open(root.path());
        let operation = Operation::memoizing();
        let identity = identity_of(&directory);
        let before = directory_probe_count();
        assert!(directory_acl_admits(
            &operation,
            DirectoryRole::Traversed,
            root.path(),
            &directory,
            identity
        ));
        assert!(directory_acl_admits(
            &operation,
            DirectoryRole::PrivateLeaf,
            root.path(),
            &directory,
            identity
        ));
        let probes = directory_probe_count() - before;
        if cfg!(target_os = "macos") {
            assert_eq!(probes, 1, "one listing policy serves every role");
        } else {
            assert_eq!(probes, 2, "the strict no-ACL verdict is not the traversal verdict");
        }
    }

    #[test]
    fn a_mode_change_between_judgments_is_refused_and_then_judged_afresh() {
        let root = fixture();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let directory = open(root.path());
        let operation = Operation::memoizing();
        let stale = identity_of(&directory);
        assert!(directory_acl_admits(
            &operation,
            DirectoryRole::Traversed,
            root.path(),
            &directory,
            stale
        ));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750))
            .expect("loosen mode");
        let before = directory_probe_count();
        // The caller still holds the old identity: refused without consulting the memo.
        assert!(!directory_acl_admits(
            &operation,
            DirectoryRole::Traversed,
            root.path(),
            &directory,
            stale
        ));
        assert_eq!(directory_probe_count(), before);
        // A caller that adopts the new identity gets a fresh probe, not the remembered verdict.
        assert!(judge(&operation, root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 1);
    }

    #[test]
    fn a_change_that_only_moves_ctime_forces_a_fresh_probe() {
        let root = fixture();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let directory = open(root.path());
        let operation = Operation::memoizing();
        assert!(judge(&operation, root.path(), &directory));
        // Coarse kernel timestamps need a visible gap; then mode returns to its original value, so
        // device, inode, owner and mode are identical and only ctime tells the two states apart.
        std::thread::sleep(Duration::from_millis(50));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750))
            .expect("change mode");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore mode");
        let before = directory_probe_count();
        assert!(judge(&operation, root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 1, "ctime must invalidate the memo");
    }

    #[test]
    fn a_directory_replaced_under_the_same_name_is_refused() {
        let root = fixture();
        let named = root.path().join("d");
        std::fs::create_dir(&named).expect("original");
        let original = open(&named);
        let operation = Operation::memoizing();
        assert!(judge(&operation, &named, &original));
        std::fs::rename(&named, root.path().join("moved")).expect("move original");
        std::fs::create_dir(&named).expect("replacement");
        // The retained descriptor is the moved directory: the name no longer resolves to it.
        assert!(!judge(&operation, &named, &original));
        // The replacement has a different inode, so it never matches a remembered state.
        let replacement = open(&named);
        let before = directory_probe_count();
        assert!(judge(&operation, &named, &replacement));
        assert_eq!(directory_probe_count() - before, 1);
    }

    #[test]
    fn a_symlink_swapped_in_for_the_name_is_refused() {
        let root = fixture();
        let named = root.path().join("d");
        std::fs::create_dir(&named).expect("original");
        let original = open(&named);
        let operation = Operation::memoizing();
        assert!(judge(&operation, &named, &original));
        std::fs::rename(&named, root.path().join("moved")).expect("move original");
        std::os::unix::fs::symlink(root.path().join("moved"), &named).expect("symlink");
        assert!(!judge(&operation, &named, &original));
    }

    // ---- admission scope (ADR 0008 Amendment 1) ------------------------------------------

    use crate::scope::AdmissionScope;

    #[test]
    fn operations_in_one_scope_share_a_verdict_and_probe_once() {
        let root = fixture();
        let directory = open(root.path());
        let _scope = AdmissionScope::enter();
        let before = directory_probe_count();
        for _ in 0..4 {
            assert!(judge(&Operation::memoizing(), root.path(), &directory));
        }
        assert_eq!(directory_probe_count() - before, 1);
    }

    #[test]
    fn nothing_is_remembered_after_the_scope_is_dropped() {
        let root = fixture();
        let directory = open(root.path());
        let before = directory_probe_count();
        {
            let _scope = AdmissionScope::enter();
            assert!(judge(&Operation::memoizing(), root.path(), &directory));
            assert!(judge(&Operation::memoizing(), root.path(), &directory));
        }
        assert_eq!(directory_probe_count() - before, 1);
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 2, "no scope: a fresh operation probes");
        // A later scope starts empty too.
        let _scope = AdmissionScope::enter();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 3);
    }

    #[test]
    fn a_nested_scope_joins_the_outer_one_and_the_memo_outlives_only_the_outer_guard() {
        let root = fixture();
        let directory = open(root.path());
        let before = directory_probe_count();
        let outer = AdmissionScope::enter();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        {
            let _inner = AdmissionScope::enter();
            assert!(judge(&Operation::memoizing(), root.path(), &directory));
        }
        assert!(judge(&Operation::memoizing(), root.path(), &directory), "inner drop keeps it");
        assert_eq!(directory_probe_count() - before, 1);
        drop(outer);
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 2);
    }

    #[test]
    fn an_operation_made_before_the_scope_or_under_a_dropped_one_never_uses_it() {
        let root = fixture();
        let directory = open(root.path());
        let early = Operation::memoizing();
        let scope = AdmissionScope::enter();
        let stale = Operation::memoizing();
        let before = directory_probe_count();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert!(judge(&early, root.path(), &directory), "early op has only its own memo");
        assert_eq!(directory_probe_count() - before, 2);
        drop(scope);
        // A new scope has a new id: an operation made under the old one stays out of it.
        let _again = AdmissionScope::enter();
        let before = directory_probe_count();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert!(judge(&stale, root.path(), &directory), "stale-scope op probes for itself");
        assert_eq!(directory_probe_count() - before, 2);
    }

    #[test]
    fn a_scope_verdict_is_not_visible_on_another_thread() {
        let root = fixture();
        let directory = open(root.path());
        let _scope = AdmissionScope::enter();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        let path = root.path().to_path_buf();
        let other_thread_probes = std::thread::spawn(move || {
            let directory = open(&path);
            let before = directory_probe_count();
            assert!(judge(&Operation::memoizing(), &path, &directory));
            assert!(judge(&Operation::memoizing(), &path, &directory));
            let without_scope = directory_probe_count() - before;
            // Its own scope starts empty, whatever this thread's scope holds.
            let _own = AdmissionScope::enter();
            let before = directory_probe_count();
            assert!(judge(&Operation::memoizing(), &path, &directory));
            assert!(judge(&Operation::memoizing(), &path, &directory));
            (without_scope, directory_probe_count() - before)
        })
        .join()
        .expect("other thread");
        assert_eq!(other_thread_probes, (2, 1));
    }

    #[test]
    fn a_scope_past_its_cap_probes_afresh() {
        let root = fixture();
        let directory = open(root.path());
        let _scope = AdmissionScope::enter_with_cap(Duration::from_millis(150));
        let waiting = Operation::memoizing();
        let before = directory_probe_count();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 1);
        std::thread::sleep(Duration::from_millis(200));
        // Both an operation made before the cap and ones made after it behave as in the base ADR.
        assert!(judge(&waiting, root.path(), &directory));
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 4);
    }

    #[test]
    fn a_scope_verdict_is_not_served_after_a_mode_change_or_to_another_profile() {
        let root = fixture();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let directory = open(root.path());
        let _scope = AdmissionScope::enter();
        let before = directory_probe_count();
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        // Same state, a different profile: never served from the Durable verdict.
        let ephemeral =
            Operation::memoizing().with_profile(crate::policy::FilesystemProfile::Ephemeral);
        assert!(judge(&ephemeral, root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 2);
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 2, "same profile and state is a hit");
        // A mode change advances the state: probed again under the new identity.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750))
            .expect("loosen mode");
        assert!(judge(&Operation::memoizing(), root.path(), &directory));
        assert_eq!(directory_probe_count() - before, 3);
    }

    #[test]
    fn the_scope_key_separates_state_filesystem_flags_and_profile() {
        let root = fixture();
        let directory = open(root.path());
        let metadata = directory.metadata().expect("metadata");
        let state = DirectoryState::of(&metadata, DirectoryRole::Traversed);
        let durable = FilesystemProfile::Durable;
        let base = MemoKey::from_parts(state, "fs-a".to_owned(), 0x10, "apfs".to_owned(), durable);
        assert_eq!(
            base,
            MemoKey::from_parts(state, "fs-a".to_owned(), 0x10, "apfs".to_owned(), durable)
        );
        assert_ne!(
            base,
            MemoKey::from_parts(state, "fs-b".to_owned(), 0x10, "apfs".to_owned(), durable),
            "fsid"
        );
        assert_ne!(
            base,
            MemoKey::from_parts(state, "fs-a".to_owned(), 0x11, "apfs".to_owned(), durable),
            "flags"
        );
        assert_ne!(
            base,
            MemoKey::from_parts(
                state,
                "fs-a".to_owned(),
                0x10,
                "apfs".to_owned(),
                FilesystemProfile::Ephemeral
            ),
            "profile"
        );
        assert_ne!(
            base,
            MemoKey::from_parts(state, "fs-a".to_owned(), 0x10, "hfs".to_owned(), durable),
            "filesystem type"
        );
        let moved = DirectoryState { ctime_nanoseconds: state.ctime_nanoseconds + 1, ..state };
        assert_ne!(
            base,
            MemoKey::from_parts(moved, "fs-a".to_owned(), 0x10, "apfs".to_owned(), durable),
            "ctime"
        );
        // The real descriptor key is deterministic and carries the descriptor's filesystem.
        let key = MemoKey::of_descriptor(state, &directory, durable);
        assert_eq!(key, MemoKey::of_descriptor(state, &directory, durable));
        #[cfg(target_os = "macos")]
        {
            // A host that runs these tests on a non-APFS volume stores nothing, by design.
            let apfs = rustix::fs::fstatfs(&directory)
                .is_ok_and(|stats| filesystem_identity(&stats).2 == "apfs");
            assert_eq!(key.is_some(), apfs);
        }
        #[cfg(not(target_os = "macos"))]
        assert!(key.is_some());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn acl_probe_cleanup_reaps_a_stuck_owned_child_within_its_deadline() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn bounded cleanup fixture");
        assert!(stop_acl_probe(&mut child, std::time::Instant::now() + ACL_PROBE_CLEANUP_BUDGET,));
    }
}
