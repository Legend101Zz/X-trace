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
//! (one bounded 750 ms budget) and is dropped with it; it is never shared across operations,
//! threads, or processes, so no verdict outlives the operation that produced it.

use std::cell::RefCell;
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::admission::FileIdentity;
use crate::policy::DirectoryRole;

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

/// One bounded admission operation: a single deadline plus the verdicts earned inside it.
pub(crate) struct Operation {
    deadline: Instant,
    profile: crate::policy::FilesystemProfile,
    memoize: bool,
    judged: RefCell<Vec<DirectoryState>>,
    /// Batched macOS listings taken at the start of an ancestor walk (see `prefetch`).
    #[cfg(target_os = "macos")]
    prefetched: RefCell<Option<Prefetched>>,
    trace: Option<crate::trace::OpTrace>,
}

impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(trace) = self.trace.take() {
            crate::trace::operation_ended(&trace);
        }
    }
}

/// Listings for every component of a walk, taken by one `ls` run at `taken_at`.
#[cfg(target_os = "macos")]
struct Prefetched {
    taken_at: std::time::SystemTime,
    entries: Vec<BatchEntry>,
}

/// One batched listing, bound to the device and inode `lstat` reported for its operand.
#[cfg(any(target_os = "macos", test))]
struct BatchEntry {
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
        Self {
            deadline,
            profile: crate::policy::FilesystemProfile::Durable,
            memoize: cfg!(target_os = "macos"),
            judged: RefCell::new(Vec::new()),
            #[cfg(target_os = "macos")]
            prefetched: RefCell::new(None),
            trace: crate::trace::operation_started(),
        }
    }

    /// An operation that memoizes on every platform, so the memo logic is testable on Linux.
    #[cfg(test)]
    pub(crate) fn memoizing() -> Self {
        let mut operation = Self::new();
        operation.memoize = true;
        operation
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

    /// Lists every directory on a walk with a single `ls` run instead of one run per component.
    ///
    /// The listings are not verdicts. `probe_directory` uses one only for a directory whose
    /// opened descriptor reports the listing's inode and a ctime that is older than the moment
    /// the listing was taken, which proves the directory has not been modified since (a chmod,
    /// ACL edit or child change all advance ctime) and is the object that was listed. Otherwise
    /// it probes that directory on its own, so a batch that is stale, misparsed or raced never
    /// admits anything.
    #[cfg(target_os = "macos")]
    pub(crate) fn prefetch_directory_listings(&self, paths: &[std::path::PathBuf]) {
        if !self.memoize || paths.len() < 2 {
            return;
        }
        let Some(names) = paths.iter().map(|path| path.to_str()).collect::<Option<Vec<_>>>() else {
            return;
        };
        let before =
            paths.iter().map(|path| std::fs::symlink_metadata(path).ok()).collect::<Vec<_>>();
        let started = Instant::now();
        let taken_at = std::time::SystemTime::now();
        let operands = paths.iter().map(std::path::PathBuf::as_path).collect::<Vec<_>>();
        let Some(text) = run_ls("batch", "-ldeOi", &operands, self.deadline, BATCH_OUTPUT_LIMIT) else {
            crate::trace::discard("spawn_failed_or_deadline");
            return;
        };
        // A realtime clock that stepped while `ls` ran (or went backwards) makes `taken_at`
        // meaningless for the ctime comparison below: drop the whole batch.
        if !clock_is_consistent(taken_at, std::time::SystemTime::now(), started.elapsed()) {
            crate::trace::discard("clock_skew");
            return;
        }
        let Some(parsed) = crate::policy::split_batched_listing(&text, &names) else {
            crate::trace::discard("parse_ambiguity");
            return;
        };
        let mut entries = Vec::new();
        for ((path, listing), before) in paths.iter().zip(parsed).zip(before) {
            // Bind the listing to (device, inode) as `lstat` saw them on both sides of the run;
            // an operand that moved, vanished or disagrees with the listing is simply left out.
            use std::os::unix::fs::MetadataExt as _;
            let after = std::fs::symlink_metadata(path).ok();
            let (Some(before), Some(after)) = (before, after) else {
                crate::trace::discard("entry_lstat_missing");
                continue;
            };
            if before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.ino() == listing.inode
            {
                entries.push(BatchEntry { path: path.clone(), device: before.dev(), listing });
            } else {
                crate::trace::discard("entry_device_inode_mismatch");
            }
        }
        *self.prefetched.borrow_mut() = Some(Prefetched { taken_at, entries });
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
    let Some(text) = run_acl_listing("single", path, operation.deadline()) else { return false };
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

/// Judges `directory` from the walk's batched listing when that listing provably describes it.
/// Directories modified recently (busy ones) return `None` and are probed on their own.
#[cfg(target_os = "macos")]
fn prefetched_verdict(operation: &Operation, path: &Path, directory: &File) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;

    crate::trace::set_fallback("no_batch");
    let prefetched = operation.prefetched.borrow();
    let batch = prefetched.as_ref()?;
    crate::trace::set_fallback("not_in_batch");
    let entry = batch.entries.iter().find(|entry| entry.path == path)?;
    let metadata = directory.metadata().ok()?;
    let ctime = std::time::UNIX_EPOCH
        + Duration::new(
            u64::try_from(metadata.ctime()).ok()?,
            u32::try_from(metadata.ctime_nsec()).ok()?,
        );
    if !batch_entry_describes(batch.taken_at, entry, metadata.dev(), metadata.ino(), ctime) {
        let reason = if entry.device != metadata.dev() || entry.listing.inode != metadata.ino() {
            "devino_mismatch"
        } else {
            "ctime_younger_than_20ms"
        };
        crate::trace::set_fallback(reason);
        crate::trace::discard(reason);
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
    let Some(text) = run_acl_listing("file", path, operation.deadline()) else { return false };
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
}

/// Number of `/bin/ls` processes this thread has spawned. Test seam for spawn-count bounds.
#[cfg(all(target_os = "macos", test))]
pub(crate) fn ls_spawn_count() -> usize {
    LS_SPAWNS.with(std::cell::Cell::get)
}

/// Runs `/bin/ls -ldeO <path>` under the deadline and returns its bounded stdout.
#[cfg(target_os = "macos")]
fn run_acl_listing(kind: &'static str, path: &Path, deadline: Instant) -> Option<String> {
    run_ls(kind, "-ldeO", &[path], deadline, LISTING_OUTPUT_LIMIT)
}

/// Runs `/bin/ls <flags> <paths...>` under the deadline and returns its bounded stdout.
///
/// This is the only place that spawns the probe. Any failure (control characters in a path,
/// spawn failure, deadline, oversized or non-UTF-8 output, nonzero exit) is `None`, which every
/// caller treats as a refusal or a fallback to a single-directory probe.
#[cfg(target_os = "macos")]
fn run_ls(
    kind: &'static str,
    flags: &str,
    paths: &[&Path],
    deadline: Instant,
    limit: usize,
) -> Option<String> {
    if Instant::now() >= deadline
        || paths.iter().any(|path| path.as_os_str().to_string_lossy().chars().any(char::is_control))
    {
        return None;
    }
    #[cfg(test)]
    LS_SPAWNS.with(|count| count.set(count.get() + 1));
    crate::trace::spawn_started(kind);
    let spawn_began = Instant::now();
    let result = run_ls_inner(flags, paths, deadline, limit);
    crate::trace::spawn_finished(kind, paths, spawn_began.elapsed(), result.is_some());
    result
}

#[cfg(target_os = "macos")]
fn run_ls_inner(flags: &str, paths: &[&Path], deadline: Instant, limit: usize) -> Option<String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
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
