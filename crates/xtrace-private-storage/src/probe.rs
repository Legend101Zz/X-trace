//! ACL probes and the per-operation verdict memo.
//!
//! Admission walks every component of a path, and on macOS the only available oracle for "does
//! this directory carry an ACL" is a `/bin/ls -ldeO` subprocess. A single operation (one
//! `revalidate`, one `create_private_child`, ...) used to spawn it several times per component. An
//! [`Operation`] bounds one such operation with a single deadline and remembers which directory
//! *states* it has already judged acceptable, so eligible states are probed once while space
//! remains. File validation revalidates its parent before and after checking the file, so directory
//! reuse also avoids repeated subprocesses on those file-validation paths.
//!
//! # Threat model and reuse
//!
//! An owner or another process may edit an ACL between any two reads. Both operation-local and
//! scope verdicts are APFS-only: HFS+ ctime has one-second granularity and cannot distinguish
//! same-second edits. Keys bind device, inode, owner, mode, ctime, policy class, filesystem
//! identity, mount flags and profile. On APFS a chmod, chown, ACL or xattr edit advances ctime;
//! creating or removing a child also changes its directory's ctime. Every hit rereads both the
//! descriptor and named path and requires their complete states to equal the lookup state,
//! including ctime; an identity check alone cannot detect an ACL edit. A change fails admission
//! closed. Fresh probes apply the same checks across the listing, including batch fallbacks.
//! A directory content change can invalidate a fresh listing without changing its ACL. In that
//! case APFS admission requires another listing with identical ACL entries and an unchanged
//! state across that listing, under the original deadline. Other filesystems fail closed.
//! The raced verdict is never cached.
//! Only positive, unchanged verdicts are stored, and each memo is bounded to 1024 entries.
//! This does not defend against root forging filesystem metadata, or changes after the final
//! state read; the capability's later uses still revalidate it.
//! The memo lives inside one [`Operation`]
//! (one bounded 750 ms budget) and is dropped with it; it is never shared across threads or
//! processes. Outside an admission scope it is never shared across operations either.
//!
//! # Admission scope (ADR 0008 Amendment 1)
//!
//! An operation created on a thread with a live, un-expired [`crate::AdmissionScope`] shares the
//! scope's memo and batched listing as well. Every memo key carries the filesystem
//! identity and mount flags of the held descriptor (`f_fsid`, `f_flags`) and the operation's
//! filesystem profile, so a verdict judged under one profile never serves another. The identity
//! checks and the per-operation deadline are unchanged. Regular files use the same
//! state-bound policy: one listing per unchanged APFS file state in the operation/scope.

use std::cell::RefCell;
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::admission::FileIdentity;
use crate::policy::{DirectoryRole, FilesystemProfile};
use crate::scope;

/// Most verdicts one operation or scope remembers; beyond it new verdicts are not stored.
const SCOPE_MEMO_LIMIT: usize = 1024;

/// Total time one admission operation may spend, ACL probes included.
pub(crate) const ADMISSION_BUDGET: Duration = Duration::from_millis(750);
/// How often an owned ACL probe is polled for exit. A local `ls` finishes in a few
/// milliseconds, so a coarse interval would be most of every admission's cost.
#[cfg(target_os = "macos")]
const ACL_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(target_os = "macos")]
const ACL_PROBE_CLEANUP_BUDGET: Duration = Duration::from_millis(100);

/// State that invalidates an ACL verdict, for either a directory or a regular file.
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
        let state = Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
            strict: cfg!(not(target_os = "macos"))
                && matches!(role, DirectoryRole::PrivateLeaf | DirectoryRole::Sealed { .. }),
        };
        // Deterministically model two directory ACL edits within one HFS+ ctime tick.
        #[cfg(all(target_os = "macos", test))]
        if metadata.is_dir() {
            if let Some(seconds) = COARSE_FILESYSTEM.with(std::cell::Cell::get) {
                return Self { ctime_seconds: seconds, ctime_nanoseconds: 0, ..state };
            }
        }
        state
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
    /// The filesystem type name (`f_fstypename`); macOS reuses only `apfs` verdicts.
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
        // leave the key equal. This gates operation-local reuse as well as scope reuse.
        scope_shares_filesystem(&fstype)
            .then(|| Self::from_parts(state, fsid, flags, fstype, profile))
    }
}

/// Whether verdicts and batched listings of this filesystem type may be reused at all.
/// macOS: APFS only (nanosecond ctime). Elsewhere the memo exists for tests alone.
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
    let fstype = String::from_utf8_lossy(&name).into_owned();
    #[cfg(test)]
    let fstype = if COARSE_FILESYSTEM.with(|coarse| coarse.get().is_some()) {
        "hfs".to_owned()
    } else {
        fstype
    };
    (format!("{:?}", stats.f_fsid), u64::from(stats.f_flags), fstype)
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
    judged: RefCell<Vec<MemoKey>>,
    #[cfg(target_os = "macos")]
    file_judged: RefCell<Vec<MemoKey>>,
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
            #[cfg(target_os = "macos")]
            file_judged: RefCell::new(Vec::new()),
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
    /// The listings are not verdicts. `prefetched_listing` uses one only for a directory whose
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
            // Keep only unchanged states. A raced operand needs a fresh single-directory
            // listing under this operation's original deadline, even if its inode is unchanged.
            use std::os::unix::fs::MetadataExt as _;
            let after = std::fs::symlink_metadata(path).ok();
            let (Some(before), Some(after)) = (before, after) else { continue };
            if before.is_dir()
                && after.is_dir()
                && DirectoryState::of(&before, DirectoryRole::Traversed)
                    == DirectoryState::of(&after, DirectoryRole::Traversed)
                && before.ino() == listing.inode
            {
                entries.push(BatchEntry { path: path.clone(), device: before.dev(), listing });
            }
        }
        Some(Prefetched { taken_at, taken_mono: started, entries })
    }

    /// Every directory memo, even without a scope, requires an eligible filesystem key.
    fn directory_key(&self, state: DirectoryState, directory: &File) -> Option<MemoKey> {
        if !self.memoize {
            return None;
        }
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
                let remembered = state.memo.len();
                #[cfg(target_os = "macos")]
                let remembered = remembered + state.file_memo.len();
                if remembered < SCOPE_MEMO_LIMIT && !state.memo.contains(&key) {
                    state.memo.push(key);
                }
            });
        }
    }

    fn already_judged(&self, key: &MemoKey) -> bool {
        self.memoize && self.judged.borrow().contains(key)
    }

    fn remember(&self, key: MemoKey) {
        if !self.memoize {
            return;
        }
        let mut judged = self.judged.borrow_mut();
        let remembered = judged.len();
        #[cfg(target_os = "macos")]
        let remembered = remembered + self.file_judged.borrow().len();
        if remembered < SCOPE_MEMO_LIMIT && !judged.contains(&key) {
            judged.push(key);
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

#[cfg(test)]
fn record_directory_probe(path: &Path) {
    DIRECTORY_PROBES.with(|count| count.set(count.get() + 1));
    PROBED_PATHS.with(|paths| paths.borrow_mut().push(path.to_path_buf()));
}

fn directory_metadata(
    operation: &Operation,
    path: &Path,
    directory: &File,
    expected: FileIdentity,
    role: DirectoryRole,
) -> Option<std::fs::Metadata> {
    loop {
        if operation.expired() {
            return None;
        }
        let opened = directory.metadata().ok()?;
        #[cfg(all(target_os = "macos", test))]
        run_directory_read_hook(path);
        let named = std::fs::symlink_metadata(path).ok()?;
        if !named.is_dir()
            || !opened.is_dir()
            || !expected.same_directory(FileIdentity::from_metadata(&named))
            || !expected.same_directory(FileIdentity::from_metadata(&opened))
        {
            return None;
        }
        if DirectoryState::of(&named, role) == DirectoryState::of(&opened, role) {
            return Some(opened);
        }
        // No verdict has been used yet. Obtain a matching descriptor/path snapshot if child
        // activity raced these two reads; an ACL-only change still fails closed.
        if cfg!(target_os = "macos") && directory_contents_changed(&opened, &named) {
            continue;
        }
        return None;
    }
}

/// mtime is only a reason to obtain fresh evidence, never proof that an ACL stayed unchanged.
fn directory_contents_changed(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    (before.mtime(), before.mtime_nsec()) != (after.mtime(), after.mtime_nsec())
}

/// Judges a directory's ACL for `role`, with bounded APFS verdict reuse.
///
/// Both states are checked again after every hit or probe. Only an unchanged, APFS-qualified
/// positive verdict may be reused, in either the operation or its scope.
pub(crate) fn directory_acl_admits(
    operation: &Operation,
    role: DirectoryRole,
    path: &Path,
    directory: &File,
    expected: FileIdentity,
) -> bool {
    if operation.expired() {
        return false;
    }
    let Some(before) = directory_metadata(operation, path, directory, expected, role) else {
        return false;
    };
    let state = DirectoryState::of(&before, role);
    let key = operation.directory_key(state, directory);
    #[cfg(all(target_os = "macos", test))]
    run_initial_state_hook(path);
    let remembered =
        key.as_ref().is_some_and(|key| operation.already_judged(key) || operation.scope_has(key));
    #[cfg(target_os = "macos")]
    let mut listing = None;
    if !remembered {
        #[cfg(test)]
        record_directory_probe(path);
        #[cfg(target_os = "macos")]
        let admitted = {
            listing = probe_directory(operation, path, directory);
            listing.is_some()
        };
        #[cfg(not(target_os = "macos"))]
        let admitted = probe_directory(operation, role, path, directory);
        if !admitted {
            return false;
        }
    }
    let Some(after) = directory_metadata(operation, path, directory, expected, role) else {
        return false;
    };
    if operation.expired()
        || key
            .as_ref()
            .is_some_and(|key| operation.directory_key(state, directory).as_ref() != Some(key))
    {
        return false;
    }
    // A changed state invalidates this verdict: the listing may predate an ACL grant. Child
    // activity permits fresh evidence only on APFS, whose nanosecond ctime can prove stability.
    if DirectoryState::of(&after, role) != state {
        #[cfg(target_os = "macos")]
        if key.is_some() && directory_contents_changed(&before, &after) {
            if let Some(listing) = listing {
                return recheck_directory_listing(
                    operation, role, path, directory, expected, &listing,
                ) && operation.directory_key(state, directory) == key
                    && !operation.expired();
            }
        }
        return false;
    }
    if let Some(key) = key {
        if !remembered {
            operation.scope_remember(key.clone());
            operation.remember(key);
        }
    }
    true
}

/// Replace a listing raced by child activity with stable evidence. Comparing the ACL entries
/// also refuses a deny-only ACL edit accompanied by a child change. Nothing on this path earns
/// a memo; the original state was invalidated. Continuous mutation exhausts the same deadline.
#[cfg(target_os = "macos")]
fn recheck_directory_listing(
    operation: &Operation,
    role: DirectoryRole,
    path: &Path,
    directory: &File,
    expected: FileIdentity,
    original: &str,
) -> bool {
    loop {
        let Some(before) = directory_metadata(operation, path, directory, expected, role) else {
            return false;
        };
        let state = DirectoryState::of(&before, role);
        let key = operation.directory_key(state, directory);
        // A new single-operand listing is required; the batch predates the content change.
        #[cfg(test)]
        record_directory_probe(path);
        let Some(text) = run_acl_listing(path, operation.deadline()) else { return false };
        if !path
            .to_str()
            .is_some_and(|expected| crate::policy::macos_directory_listing_admits(&text, expected))
            || !original.lines().skip(1).eq(text.lines().skip(1))
        {
            return false;
        }
        let Some(after) = directory_metadata(operation, path, directory, expected, role) else {
            return false;
        };
        if operation.directory_key(state, directory) != key || operation.expired() {
            return false;
        }
        if DirectoryState::of(&after, role) == state {
            return true;
        }
        if !directory_contents_changed(&before, &after) {
            return false;
        }
    }
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
fn probe_directory(operation: &Operation, path: &Path, directory: &File) -> Option<String> {
    // Lazy batch: taken only now that a directory on the walk missed the memo.
    let text = prefetched_listing(operation, path, directory)
        .or_else(|| {
            operation
                .spawn_batch_for(path)
                .then(|| prefetched_listing(operation, path, directory))
                .flatten()
        })
        .or_else(|| run_acl_listing(path, operation.deadline()))?;
    path.to_str()
        .is_some_and(|expected| crate::policy::macos_directory_listing_admits(&text, expected))
        .then_some(text)
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
fn prefetched_listing(operation: &Operation, path: &Path, directory: &File) -> Option<String> {
    let from_scope = operation.scope_id.and_then(|id| {
        scope::with_scope(id, |state| {
            state.batch.as_ref().and_then(|batch| listing_from_batch(batch, path, directory))
        })
    });
    if let Some(Some(verdict)) = from_scope {
        return Some(verdict);
    }
    let own = operation.prefetched.borrow();
    own.as_ref().and_then(|batch| listing_from_batch(batch, path, directory))
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
fn listing_from_batch(batch: &Prefetched, path: &Path, directory: &File) -> Option<String> {
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
    Some(entry.listing.text.clone())
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
    _directory: &File,
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
    directory: &File,
    identity: FileIdentity,
    operation: &Operation,
) -> bool {
    if !file_listing_admits(path, directory, None, identity, operation) {
        return false;
    }
    // Same inode, owner and mode; size is excluded because live SQLite files grow.
    std::fs::symlink_metadata(path)
        .is_ok_and(|named| identity.same_directory(FileIdentity::from_metadata(&named)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn named_file_acl_admits(
    _path: &Path,
    _directory: &File,
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
    if !file_listing_admits(path, file, Some(file), expected, operation) {
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
///
/// Threat model: an ACL edit by the owner or another process must not make a
/// remembered deny-only verdict admit an allow entry. Reuse is APFS-only (nanosecond
/// ctime), keyed by device/inode, owner, mode, ctime, filesystem identity/mount flags
/// and profile. Path/descriptor identity checks still run before and after a query
/// or hit. Writes, replacement, chmod, chown and ACL edits invalidate the key. A
/// file changing during a fresh listing or a hit is refused, just like a directory;
/// neither changed-state listings nor failed verdicts are cached.
/// No file is opened here: closing another descriptor could release SQLite's locks.
#[cfg(target_os = "macos")]
fn file_listing_admits(
    path: &Path,
    filesystem_descriptor: &File,
    file: Option<&File>,
    expected: FileIdentity,
    operation: &Operation,
) -> bool {
    if operation.expired() {
        return false;
    }
    let state = || {
        let named = std::fs::symlink_metadata(path).ok()?;
        if !named.is_file() || !expected.same_directory(FileIdentity::from_metadata(&named)) {
            return None;
        }
        let state = DirectoryState::of(&named, DirectoryRole::PrivateLeaf);
        if let Some(file) = file {
            let opened = file.metadata().ok()?;
            if !expected.same_file(FileIdentity::from_metadata(&opened))
                || DirectoryState::of(&opened, DirectoryRole::PrivateLeaf) != state
            {
                return None;
            }
        }
        Some(state)
    };
    let Some(before) = state() else { return false };
    let key = MemoKey::of_descriptor(before, filesystem_descriptor, operation.profile());
    #[cfg(test)]
    run_initial_state_hook(path);
    let remembered = key.as_ref().is_some_and(|key| {
        operation.file_judged.borrow().contains(key)
            || operation
                .scope_id
                .and_then(|id| scope::with_scope(id, |scope| scope.file_memo.contains(key)))
                .unwrap_or(false)
    });
    if !remembered {
        let Some(text) = run_acl_listing(path, operation.deadline()) else { return false };
        if !path
            .to_str()
            .is_some_and(|expected| crate::policy::macos_file_listing_admits(&text, expected))
        {
            return false;
        }
    }
    let Some(after) = state() else { return false };
    if operation.expired() {
        return false;
    }
    if after != before {
        return false;
    }
    if let Some(key) = key {
        if MemoKey::of_descriptor(before, filesystem_descriptor, operation.profile()).as_ref()
            != Some(&key)
        {
            return false;
        }
        if !remembered {
            let mut judged = operation.file_judged.borrow_mut();
            if operation.judged.borrow().len() + judged.len() < SCOPE_MEMO_LIMIT {
                judged.push(key.clone());
            }
            if let Some(id) = operation.scope_id {
                scope::with_scope(id, |scope| {
                    if scope.memo.len() + scope.file_memo.len() < SCOPE_MEMO_LIMIT
                        && !scope.file_memo.contains(&key)
                    {
                        scope.file_memo.push(key);
                    }
                });
            }
        }
    }
    true
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
    static AFTER_LISTING: RefCell<Option<AfterListing>> = const { RefCell::new(None) };
    static AFTER_INITIAL_STATE: RefCell<Option<AfterListing>> = const { RefCell::new(None) };
    static BETWEEN_DIRECTORY_READS: RefCell<Option<AfterListing>> = const { RefCell::new(None) };
    /// Test-only HFS+ facts: a chosen ctime second and a filesystem ineligible for reuse.
    static COARSE_FILESYSTEM: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(target_os = "macos", test))]
fn run_directory_read_hook(path: &Path) {
    let hook = BETWEEN_DIRECTORY_READS.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|hook| hook.path == path) { slot.take() } else { None }
    });
    if let Some(hook) = hook {
        (hook.action)();
    }
}

#[cfg(all(target_os = "macos", test))]
fn run_initial_state_hook(path: &Path) {
    let hook = AFTER_INITIAL_STATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|hook| hook.path == path) { slot.take() } else { None }
    });
    if let Some(hook) = hook {
        (hook.action)();
    }
}

/// One-shot mutation after stdout is captured and before any post-listing state read.
#[cfg(all(target_os = "macos", test))]
struct AfterListing {
    path: std::path::PathBuf,
    action: Box<dyn FnOnce()>,
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
    let text = String::from_utf8(bytes).ok()?;
    #[cfg(test)]
    {
        let hook = AFTER_LISTING.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|hook| paths.contains(&hook.path.as_path())) {
                slot.take()
            } else {
                None
            }
        });
        if let Some(hook) = hook {
            (hook.action)();
        }
    }
    Some(text)
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

    #[cfg(target_os = "macos")]
    fn edit_acl(path: &Path, flag: &str, entry: &str) {
        assert!(
            std::process::Command::new("/bin/chmod")
                .args([flag, entry])
                .arg(path)
                .status()
                .expect("edit fixture ACL")
                .success()
        );
    }

    #[cfg(target_os = "macos")]
    fn acl_edit_hook(path: &Path, entry: &'static str) -> AfterListing {
        let path = path.to_path_buf();
        AfterListing {
            path: path.clone(),
            action: Box::new(move || {
                let before = std::fs::symlink_metadata(&path).expect("before ACL edit");
                edit_acl(&path, "+a", entry);
                let after = std::fs::symlink_metadata(&path).expect("after ACL edit");
                assert!(
                    FileIdentity::from_metadata(&before)
                        .same_directory(FileIdentity::from_metadata(&after))
                );
                let before = DirectoryState::of(&before, DirectoryRole::PrivateLeaf);
                let after = DirectoryState::of(&after, DirectoryRole::PrivateLeaf);
                assert_ne!(before, after, "the ACL edit must invalidate the state key");
            }),
        }
    }

    #[cfg(target_os = "macos")]
    fn change_acl_after_listing(path: &Path, entry: &'static str) {
        let hook = acl_edit_hook(path, entry);
        AFTER_LISTING.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone, Copy)]
    enum ContentEdit {
        Create,
        Rename,
        Remove,
    }

    #[cfg(target_os = "macos")]
    fn content_edit_hook(
        path: &Path,
        edit: ContentEdit,
        acl: Option<&'static str>,
    ) -> AfterListing {
        let path = path.to_path_buf();
        AfterListing {
            path: path.clone(),
            action: Box::new(move || {
                let before = std::fs::symlink_metadata(&path).expect("before child change");
                match edit {
                    ContentEdit::Create => {
                        std::fs::create_dir(path.join("created")).expect("create child")
                    }
                    ContentEdit::Rename => {
                        std::fs::rename(path.join("child"), path.join("renamed"))
                            .expect("rename child")
                    }
                    ContentEdit::Remove => {
                        std::fs::remove_file(path.join("child")).expect("remove child")
                    }
                }
                if let Some(entry) = acl {
                    edit_acl(&path, "+a", entry);
                }
                let after = std::fs::symlink_metadata(&path).expect("after child change");
                assert!(
                    FileIdentity::from_metadata(&before)
                        .same_directory(FileIdentity::from_metadata(&after))
                );
                assert!(
                    directory_contents_changed(&before, &after),
                    "child activity changes mtime"
                );
                assert_ne!(
                    DirectoryState::of(&before, DirectoryRole::PrivateLeaf),
                    DirectoryState::of(&after, DirectoryRole::PrivateLeaf),
                    "APFS child activity also invalidates the ctime key"
                );
            }),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_activity_between_descriptor_and_path_reads_requires_a_matching_snapshot() {
        for acl in [None, Some("group:everyone allow read")] {
            let root = fixture();
            let path = root.path();
            let directory = open(path);
            let hook = content_edit_hook(path, ContentEdit::Create, acl);
            BETWEEN_DIRECTORY_READS.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
            let operation = Operation::new();
            assert_eq!(judge(&operation, path, &directory), acl.is_none());
            BETWEEN_DIRECTORY_READS.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
            assert_eq!(operation.judged.borrow().len(), usize::from(acl.is_none()));
            if let Some(entry) = acl {
                edit_acl(path, "-a", entry);
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_activity_during_directory_admission_requires_a_fresh_unchanged_listing() {
        for scoped in [false, true] {
            for batched in [false, true] {
                for edit in [ContentEdit::Create, ContentEdit::Rename, ContentEdit::Remove] {
                    for acl in [None, Some("group:everyone allow read")] {
                        let root = fixture();
                        let path = root.path().join("directory");
                        std::fs::create_dir(&path).expect("directory");
                        std::fs::write(path.join("child"), b"").expect("child");
                        let directory = open(&path);
                        let _scope = scoped.then(AdmissionScope::enter);
                        let operation = Operation::new();
                        if batched {
                            operation.register_walk(&[root.path().to_path_buf(), path.clone()]);
                        }
                        let hook = content_edit_hook(&path, edit, acl);
                        AFTER_LISTING
                            .with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
                        let before = ls_spawn_count();
                        assert_eq!(judge(&operation, &path, &directory), acl.is_none());
                        AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
                        assert!(ls_spawn_count() - before >= 2, "fresh evidence is required");
                        assert!(operation.judged.borrow().is_empty(), "no raced verdict is cached");
                        if let Some(id) = operation.scope_id {
                            assert_eq!(
                                scope::with_scope(id, |state| state.memo.is_empty()),
                                Some(true)
                            );
                        }
                        if let Some(entry) = acl {
                            edit_acl(&path, "-a", entry);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_child_change_does_not_hide_a_deny_only_acl_edit_during_a_single_listing() {
        let root = fixture();
        let path = root.path();
        let directory = open(path);
        let hook = content_edit_hook(path, ContentEdit::Create, Some("group:everyone deny delete"));
        AFTER_LISTING.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
        let operation = Operation::new();
        assert!(!judge(&operation, path, &directory));
        AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
        assert!(operation.judged.borrow().is_empty());
        edit_acl(path, "-a", "group:everyone deny delete");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_content_recheck_still_refuses_an_acl_edit_after_its_listing() {
        for entry in ["group:everyone allow read", "group:everyone deny delete"] {
            let root = fixture();
            let path = root.path();
            let directory = open(path);
            let content = content_edit_hook(path, ContentEdit::Create, None);
            let changed_path = path.to_path_buf();
            let hook = AfterListing {
                path: path.to_path_buf(),
                action: Box::new(move || {
                    (content.action)();
                    change_acl_after_listing(&changed_path, entry);
                }),
            };
            AFTER_LISTING.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
            let operation = Operation::new();
            let before = ls_spawn_count();
            assert!(!judge(&operation, path, &directory));
            AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "both hooks ran"));
            assert_eq!(
                ls_spawn_count() - before,
                2,
                "the second listing also needs a stable state"
            );
            assert!(operation.judged.borrow().is_empty());
            edit_acl(path, "-a", entry);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn directory_cache_hits_refuse_acl_edits_after_the_initial_state_read() {
        for scoped in [false, true] {
            for entry in ["group:everyone allow read", "group:everyone deny write"] {
                let root = fixture();
                let path = root.path();
                let directory = open(path);
                edit_acl(path, "+a", "group:everyone deny delete");
                let _scope = scoped.then(AdmissionScope::enter);
                let priming = Operation::new();
                assert!(judge(&priming, path, &directory));
                assert_eq!(priming.judged.borrow().len(), 1, "prime an APFS verdict");
                let operation = if scoped { Operation::new() } else { priming };
                if scoped {
                    assert!(operation.judged.borrow().is_empty(), "exercise only the scope hit");
                    let id = operation.scope_id.expect("live scope");
                    assert_eq!(scope::with_scope(id, |state| state.memo.len()), Some(1));
                }
                let hook = acl_edit_hook(path, entry);
                AFTER_INITIAL_STATE.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
                let before = ls_spawn_count();
                assert!(!judge(&operation, path, &directory), "a changed cache hit fails closed");
                AFTER_INITIAL_STATE.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
                assert_eq!(ls_spawn_count(), before, "the stale lookup reached the hit path");
                assert_eq!(judge(&operation, path, &directory), entry.contains(" deny "));
                assert_eq!(ls_spawn_count() - before, 1, "the changed state needs a fresh probe");
                if entry.contains(" allow ") {
                    assert!(!judge(&operation, path, &directory));
                    assert_eq!(ls_spawn_count() - before, 2, "negative verdicts are never cached");
                }
                edit_acl(path, "-a", entry);
                edit_acl(path, "-a", "group:everyone deny delete");
            }
        }
    }

    /// Restore the thread-local filesystem seam even if an assertion unwinds.
    #[cfg(target_os = "macos")]
    struct CoarseFilesystem;

    #[cfg(target_os = "macos")]
    impl CoarseFilesystem {
        fn enter() -> Self {
            COARSE_FILESYSTEM.with(|coarse| assert!(coarse.replace(Some(1)).is_none()));
            Self
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for CoarseFilesystem {
        fn drop(&mut self) {
            COARSE_FILESYSTEM.with(|coarse| coarse.set(None));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn coarse_ctime_child_races_cannot_recover_with_a_listing_that_hides_an_acl_grant() {
        for scoped in [false, true] {
            let root = fixture();
            let path = root.path();
            let directory = open(path);
            let _coarse = CoarseFilesystem::enter();
            let _scope = scoped.then(AdmissionScope::enter);
            let changed_path = path.to_path_buf();
            let hook = AfterListing {
                path: changed_path.clone(),
                action: Box::new(move || {
                    let before = std::fs::symlink_metadata(&changed_path).expect("before child");
                    let state = DirectoryState::of(&before, DirectoryRole::PrivateLeaf);
                    std::fs::create_dir(changed_path.join("child")).expect("create child");
                    // Cross one coarse ctime tick after the original listing, then freeze it.
                    COARSE_FILESYSTEM.with(|coarse| coarse.set(Some(2)));
                    let after = std::fs::symlink_metadata(&changed_path).expect("after child");
                    assert!(directory_contents_changed(&before, &after));
                    assert_ne!(
                        state,
                        DirectoryState::of(&after, DirectoryRole::PrivateLeaf),
                        "the child change crosses a coarse ctime tick"
                    );
                    let grant_path = changed_path.clone();
                    let grant = AfterListing {
                        path: grant_path.clone(),
                        action: Box::new(move || {
                            let before = DirectoryState::of(
                                &std::fs::symlink_metadata(&grant_path).expect("before grant"),
                                DirectoryRole::PrivateLeaf,
                            );
                            edit_acl(&grant_path, "+a", "group:everyone allow read");
                            assert_eq!(
                                before,
                                DirectoryState::of(
                                    &std::fs::symlink_metadata(&grant_path).expect("after grant"),
                                    DirectoryRole::PrivateLeaf,
                                ),
                                "a grant after the fresh listing is invisible within this tick"
                            );
                        }),
                    };
                    AFTER_LISTING.with(|slot| assert!(slot.borrow_mut().replace(grant).is_none()));
                }),
            };
            AFTER_LISTING.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
            let operation = Operation::new();
            let before = ls_spawn_count();
            assert!(!judge(&operation, path, &directory), "coarse ctime cannot prove recovery");
            assert_eq!(ls_spawn_count() - before, 1, "non-APFS races fail before a fresh listing");
            AFTER_LISTING.with(|slot| assert!(slot.borrow().is_some(), "grant prevented"));
            // Exercise the blocked interleaving: this fresh snapshot hides the subsequent grant,
            // and the hook proves that coarse ctime cannot distinguish the two ACL states.
            let text = run_acl_listing(path, operation.deadline()).expect("fresh listing");
            assert!(crate::policy::macos_directory_listing_admits(&text, path.to_str().unwrap()));
            AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "grant injected"));
            assert!(!judge(&operation, path, &directory), "a new probe sees the grant");
            assert!(operation.judged.borrow().is_empty());
            if let Some(id) = operation.scope_id {
                assert_eq!(scope::with_scope(id, |scope| scope.memo.is_empty()), Some(true));
            }
            edit_acl(path, "-a", "group:everyone allow read");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn coarse_ctime_non_apfs_directories_never_reuse_positive_verdicts() {
        for scoped in [false, true] {
            let root = fixture();
            let path = root.path();
            let directory = open(path);
            edit_acl(path, "+a", "group:everyone deny delete");
            let _coarse = CoarseFilesystem::enter();
            let _scope = scoped.then(AdmissionScope::enter);
            let priming = Operation::new();
            let state = DirectoryState::of(
                &directory.metadata().expect("metadata"),
                DirectoryRole::Traversed,
            );
            assert!(MemoKey::of_descriptor(state, &directory, priming.profile()).is_none());
            let before = ls_spawn_count();
            assert!(judge(&priming, path, &directory));
            assert!(judge(&priming, path, &directory));
            assert_eq!(ls_spawn_count() - before, 2, "even unchanged non-APFS states are listed");
            assert!(priming.judged.borrow().is_empty(), "no operation-local insertion");
            let operation = if scoped { Operation::new() } else { priming };
            if let Some(id) = operation.scope_id {
                assert_eq!(scope::with_scope(id, |scope| scope.memo.is_empty()), Some(true));
            }
            let changed_path = path.to_path_buf();
            let hook = AfterListing {
                path: changed_path.clone(),
                action: Box::new(move || {
                    edit_acl(&changed_path, "+a", "group:everyone allow read")
                }),
            };
            AFTER_INITIAL_STATE.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
            assert!(!judge(&operation, path, &directory), "a fresh listing must see the grant");
            AFTER_INITIAL_STATE.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
            assert_eq!(
                state,
                DirectoryState::of(
                    &directory.metadata().expect("metadata after ACL edit"),
                    DirectoryRole::Traversed
                ),
                "the simulated coarse ctime hides the edit"
            );
            assert_eq!(ls_spawn_count() - before, 3);
            assert!(!judge(&operation, path, &directory));
            assert_eq!(ls_spawn_count() - before, 4, "negative verdicts are not cached either");
            assert!(operation.judged.borrow().is_empty());
            if let Some(id) = operation.scope_id {
                assert_eq!(scope::with_scope(id, |scope| scope.memo.is_empty()), Some(true));
            }
            edit_acl(path, "-a", "group:everyone allow read");
            edit_acl(path, "-a", "group:everyone deny delete");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn file_cache_hits_refuse_acl_edits_after_the_initial_state_read() {
        for scoped in [false, true] {
            for descriptor_backed in [false, true] {
                for entry in ["group:everyone allow read", "group:everyone deny write"] {
                    let root = fixture();
                    let directory = open(root.path());
                    let path = root.path().join("private-file");
                    let file = File::create(&path).expect("fixture file");
                    edit_acl(&path, "+a", "group:everyone deny delete");
                    let _scope = scoped.then(AdmissionScope::enter);
                    let identity = identity_of(&file);
                    let admits = |operation: &Operation| {
                        if descriptor_backed {
                            acl_admits_file(&path, &file, identity, operation)
                        } else {
                            named_file_acl_admits(&path, &directory, identity, operation)
                        }
                    };
                    let priming = Operation::new();
                    assert!(admits(&priming));
                    assert_eq!(priming.file_judged.borrow().len(), 1);
                    let operation = if scoped { Operation::new() } else { priming };
                    if scoped {
                        assert!(operation.file_judged.borrow().is_empty());
                        let id = operation.scope_id.expect("live scope");
                        assert_eq!(scope::with_scope(id, |scope| scope.file_memo.len()), Some(1));
                    }
                    let hook = acl_edit_hook(&path, entry);
                    AFTER_INITIAL_STATE
                        .with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
                    let before = ls_spawn_count();
                    assert!(!admits(&operation), "a file cache hit must recheck its state");
                    AFTER_INITIAL_STATE.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
                    assert_eq!(ls_spawn_count(), before);
                    assert_eq!(admits(&operation), entry.contains(" deny "));
                    assert_eq!(ls_spawn_count() - before, 1);
                    edit_acl(&path, "-a", entry);
                    edit_acl(&path, "-a", "group:everyone deny delete");
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn non_apfs_files_never_cache_positive_or_negative_verdicts() {
        for scoped in [false, true] {
            for descriptor_backed in [false, true] {
                let root = fixture();
                let directory = open(root.path());
                let path = root.path().join("private-file");
                let file = File::create(&path).expect("fixture file");
                edit_acl(&path, "+a", "group:everyone deny delete");
                let _coarse = CoarseFilesystem::enter();
                let _scope = scoped.then(AdmissionScope::enter);
                let operation = Operation::new();
                let identity = identity_of(&file);
                let admits = |operation: &Operation| {
                    if descriptor_backed {
                        acl_admits_file(&path, &file, identity, operation)
                    } else {
                        named_file_acl_admits(&path, &directory, identity, operation)
                    }
                };
                let before = ls_spawn_count();
                assert!(admits(&operation));
                assert!(admits(&operation));
                assert!(admits(&Operation::new()));
                assert_eq!(ls_spawn_count() - before, 3, "no operation or scope reuse");
                assert_no_file_verdicts(&operation);
                edit_acl(&path, "+a", "group:everyone allow read");
                assert!(!admits(&operation));
                assert!(!admits(&operation));
                assert_eq!(ls_spawn_count() - before, 5);
                assert_no_file_verdicts(&operation);
                edit_acl(&path, "-a", "group:everyone allow read");
                edit_acl(&path, "-a", "group:everyone deny delete");
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn operation_and_scope_memos_are_bounded_across_directory_and_file_verdicts() {
        for file_entries in [0, SCOPE_MEMO_LIMIT] {
            let root = fixture();
            let directory = open(root.path());
            let path = root.path().join("private-file");
            let file = File::create(&path).expect("fixture file");
            let _scope = AdmissionScope::enter();
            let operation = Operation::new();
            let id = operation.scope_id.expect("live scope");
            let state = DirectoryState::of(
                &directory.metadata().expect("metadata"),
                DirectoryRole::Traversed,
            );
            let base = operation.directory_key(state, &directory).expect("APFS fixture");
            for index in 0..=SCOPE_MEMO_LIMIT {
                let mut key = base.clone();
                key.state.device = state.device.wrapping_add(1);
                key.state.inode = index as u64;
                if index < file_entries {
                    operation.file_judged.borrow_mut().push(key.clone());
                    scope::with_scope(id, |scope| scope.file_memo.push(key.clone()));
                } else {
                    operation.remember(key.clone());
                    operation.scope_remember(key);
                }
            }
            let directory_entries = SCOPE_MEMO_LIMIT - file_entries;
            assert_eq!(operation.judged.borrow().len(), directory_entries);
            assert_eq!(scope::with_scope(id, |scope| scope.memo.len()), Some(directory_entries));
            let before = ls_spawn_count();
            assert!(judge(&operation, root.path(), &directory));
            assert!(judge(&operation, root.path(), &directory));
            assert!(judge(&Operation::new(), root.path(), &directory));
            assert_eq!(ls_spawn_count() - before, 3, "a full memo still probes directories");
            let identity = identity_of(&file);
            assert!(acl_admits_file(&path, &file, identity, &operation));
            assert!(acl_admits_file(&path, &file, identity, &operation));
            assert!(acl_admits_file(&path, &file, identity, &Operation::new()));
            assert_eq!(ls_spawn_count() - before, 6, "a full memo still probes files");
            assert_eq!(operation.judged.borrow().len(), directory_entries);
            assert_eq!(operation.file_judged.borrow().len(), file_entries);
            assert_eq!(
                scope::with_scope(id, |scope| scope.memo.len() + scope.file_memo.len()),
                Some(SCOPE_MEMO_LIMIT)
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn assert_no_file_verdicts(operation: &Operation) {
        assert!(operation.file_judged.borrow().is_empty());
        if let Some(id) = operation.scope_id {
            assert_eq!(scope::with_scope(id, |scope| scope.file_memo.is_empty()), Some(true));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_file_acl_grant_during_listing_is_refused_without_caching() {
        use std::os::unix::fs::OpenOptionsExt as _;

        for scoped in [false, true] {
            for descriptor_backed in [false, true] {
                let root = fixture();
                let directory = open(root.path());
                let path = root.path().join("private-file");
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .expect("private file");
                edit_acl(&path, "+a", "group:everyone deny delete");
                let _scope = scoped.then(crate::AdmissionScope::enter);
                let operation = Operation::new();
                let identity = identity_of(&file);
                let admits = || {
                    if descriptor_backed {
                        acl_admits_file(&path, &file, identity, &operation)
                    } else {
                        named_file_acl_admits(&path, &directory, identity, &operation)
                    }
                };
                change_acl_after_listing(&path, "group:everyone allow read");
                let before = ls_spawn_count();
                assert!(!admits(), "a deny-only listing cannot admit the subsequent ACL grant");
                AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
                assert_eq!(ls_spawn_count() - before, 1);
                assert_no_file_verdicts(&operation);

                assert!(!admits(), "the allow entry is still refused by a fresh listing");
                assert_eq!(ls_spawn_count() - before, 2, "the raced verdict was not cached");
                assert_no_file_verdicts(&operation);
                assert!(!admits());
                assert_eq!(ls_spawn_count() - before, 3, "negative verdicts are not cached");
                assert_no_file_verdicts(&operation);
                edit_acl(&path, "-a", "group:everyone allow read");
                assert!(admits(), "an unchanged deny-only listing still admits");
                edit_acl(&path, "-a", "group:everyone deny delete");
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn file_admission_entry_points_refuse_a_changed_listing_state() {
        for descriptor_backed in [false, true] {
            let fixture = fixture();
            let root = crate::AdmittedPrivateRoot::open(fixture.path()).expect("private root");
            let file = root.create_private_file("private-file").expect("private file");
            let path = root.path().join("private-file");
            edit_acl(&path, "+a", "group:everyone deny delete");
            let _scope = crate::AdmissionScope::enter();
            // Descriptor admission queries the file twice. A benign edit ensures a later good
            // listing cannot conceal the fact that the first listing raced a state change.
            change_acl_after_listing(
                &path,
                if descriptor_backed {
                    "group:everyone deny write"
                } else {
                    "group:everyone allow read"
                },
            );
            let result = if descriptor_backed {
                root.validate_file_binding("private-file", &file, false)
            } else {
                root.validate_regular_file("private-file")
            };
            assert_eq!(result, Err(crate::PrivateStorageError::Unavailable));
            AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
            let id = scope::live_scope_id().expect("live scope");
            assert_eq!(scope::with_scope(id, |scope| scope.file_memo.is_empty()), Some(true));
            edit_acl(
                &path,
                "-a",
                if descriptor_backed {
                    "group:everyone deny write"
                } else {
                    "group:everyone allow read"
                },
            );
            edit_acl(&path, "-a", "group:everyone deny delete");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_changed_during_a_single_or_batched_listing_is_not_admitted_or_cached() {
        for batched in [false, true] {
            let root = fixture();
            let path = root.path().join("directory");
            std::fs::create_dir(&path).expect("fixture child");
            let directory = open(&path);
            let _scope = crate::AdmissionScope::enter();
            let operation = Operation::new();
            if batched {
                operation.register_walk(&[root.path().to_path_buf(), path.clone()]);
            }
            // A benign edit keeps the listing policy acceptable. Even then, its changed state
            // cannot be admitted using the listing captured before the edit.
            change_acl_after_listing(&path, "group:everyone deny delete");
            let before = ls_spawn_count();
            assert!(!judge(&operation, &path, &directory));
            AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
            assert_eq!(ls_spawn_count() - before, if batched { 2 } else { 1 });
            assert!(operation.judged.borrow().is_empty());
            let id = operation.scope_id.expect("live scope");
            assert_eq!(scope::with_scope(id, |scope| scope.memo.is_empty()), Some(true));
            assert!(judge(&operation, &path, &directory), "a new unchanged listing admits");
            edit_acl(&path, "-a", "group:everyone deny delete");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_batch_discards_an_operand_whose_acl_changes_without_changing_its_inode() {
        let root = fixture();
        let path = root.path().join("directory");
        std::fs::create_dir(&path).expect("fixture child");
        let directory = open(&path);
        edit_acl(&path, "+a", "group:everyone deny delete");
        change_acl_after_listing(&path, "group:everyone allow read");
        let operation = Operation::new();
        let batch = operation
            .take_batch(&[root.path().to_path_buf(), path.clone()])
            .expect("bounded batch");
        AFTER_LISTING.with(|slot| assert!(slot.borrow().is_none(), "hook ran"));
        assert!(!batch.entries.iter().any(|entry| entry.path == path), "discard changed state");
        *operation.prefetched.borrow_mut() = Some(batch);
        let before = ls_spawn_count();
        assert!(!judge(&operation, &path, &directory), "fallback must see the ACL grant");
        assert_eq!(ls_spawn_count() - before, 1, "one fresh listing under the same deadline");
        assert!(operation.judged.borrow().is_empty());
        edit_acl(&path, "-a", "group:everyone allow read");
        edit_acl(&path, "-a", "group:everyone deny delete");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn regular_file_listings_are_bounded_by_file_states_and_acl_edits_invalidate_them() {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let root = fixture();
        let directory = open(root.path());
        let path = root.path().join("private-file");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("private file");
        let _scope = crate::AdmissionScope::enter();
        let admits = |file: &File| {
            let op = Operation::new();
            let identity = identity_of(file);
            assert!(named_file_acl_admits(&path, &directory, identity, &op));
            assert!(acl_admits_file(&path, file, identity, &op));
        };
        let before = ls_spawn_count();
        admits(&file);
        assert_eq!(ls_spawn_count() - before, 1, "one listing serves path and descriptor checks");
        for _ in 0..8 {
            admits(&file);
        }
        assert_eq!(
            ls_spawn_count() - before,
            1,
            "unchanged files spawn nothing across scoped operations"
        );

        let old =
            DirectoryState::of(&file.metadata().expect("before write"), DirectoryRole::PrivateLeaf);
        file.write_all(b"observed prefix").expect("write changes ctime");
        let new =
            DirectoryState::of(&file.metadata().expect("after write"), DirectoryRole::PrivateLeaf);
        assert_ne!(old, new);
        admits(&file);
        assert_eq!(ls_spawn_count() - before, 2, "data writes also invalidate the verdict");

        let acl = |flag: &str, entry: &str| {
            assert!(
                std::process::Command::new("/bin/chmod")
                    .args([flag, entry])
                    .arg(&path)
                    .status()
                    .expect("edit fixture ACL")
                    .success()
            );
        };
        acl("+a", "group:everyone allow read");
        let op = Operation::new();
        let identity = identity_of(&file);
        assert!(
            !named_file_acl_admits(&path, &directory, identity, &op),
            "allow cannot reuse a deny-only verdict"
        );
        assert!(!acl_admits_file(&path, &file, identity, &op));
        acl("-a", "group:everyone allow read");
        acl("+a", "group:everyone deny delete");
        let before = ls_spawn_count();
        admits(&file);
        admits(&file);
        assert_eq!(ls_spawn_count() - before, 1, "a fresh deny-only state is cached again");
        acl("-a", "group:everyone deny delete");

        drop(_scope);
        let before = ls_spawn_count();
        admits(&file);
        admits(&file);
        assert_eq!(ls_spawn_count() - before, 2, "verdicts never escape their scope or operation");
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
