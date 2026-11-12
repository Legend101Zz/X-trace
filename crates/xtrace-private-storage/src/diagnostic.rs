//! Admission diagnostics contain fixed vocabulary and numeric OS facts only.

use std::{fmt, io};

/// Check sites, rather than paths, distinguish otherwise identical ACL-state refusals.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AdmissionSite {
    Snapshot,
    #[cfg(target_os = "linux")]
    ProbeSnapshot,
    ProbeState,
    MemoState,
    Filesystem,
    #[cfg(target_os = "macos")]
    Listing,
    #[cfg(target_os = "macos")]
    RecheckListing,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    RecheckAcl,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    RecheckState,
    #[cfg(target_os = "linux")]
    RecheckSnapshot,
    #[cfg(target_os = "linux")]
    RecheckProbe,
    #[cfg(target_os = "macos")]
    RecheckFilesystem,
}

/// Parser outcomes contain no listing text, principal, right, or pathname.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ListingRefusal {
    NotChecked,
    #[cfg(any(target_os = "macos", test))]
    Text,
    #[cfg(any(target_os = "macos", test))]
    Header,
    #[cfg(any(target_os = "macos", test))]
    Mode,
    #[cfg(any(target_os = "macos", test))]
    Index,
    #[cfg(any(target_os = "macos", test))]
    Principal,
    #[cfg(any(target_os = "macos", test))]
    Effect,
    #[cfg(any(target_os = "macos", test))]
    Allow,
    #[cfg(any(target_os = "macos", test))]
    InheritedAllow,
    #[cfg(any(target_os = "macos", test))]
    InheritanceFlags,
    #[cfg(any(target_os = "macos", test))]
    Rights,
    #[cfg(any(target_os = "macos", test))]
    Marker,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AdmissionObject {
    File,
    Directory,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AdmissionContext {
    pub site: AdmissionSite,
    /// Difference mask: ctime=1, mtime=2, mode=4, owner=8, device/inode=16.
    /// This records equality only; timestamps, IDs and modes never leave the process.
    /// Listing-only sites use zero because they do not compare metadata.
    pub changes: u8,
    pub listing: ListingRefusal,
    pub object: Option<AdmissionObject>,
    /// Zero is the requested admission root, negative values are ancestors, +1 is a child.
    pub component_depth: Option<i64>,
    pub nlink_changed: Option<bool>,
}

impl AdmissionContext {
    pub(crate) fn state(
        site: AdmissionSite,
        before: &std::fs::Metadata,
        after: &std::fs::Metadata,
    ) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        let changes =
            u8::from((before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec()))
                | (u8::from(
                    (before.mtime(), before.mtime_nsec()) != (after.mtime(), after.mtime_nsec()),
                ) << 1)
                | (u8::from(before.mode() != after.mode()) << 2)
                | (u8::from(before.uid() != after.uid()) << 3)
                | (u8::from((before.dev(), before.ino()) != (after.dev(), after.ino())) << 4);
        let object = if before.is_dir() {
            AdmissionObject::Directory
        } else if before.is_file() {
            AdmissionObject::File
        } else {
            AdmissionObject::Other
        };
        Self {
            site,
            changes,
            listing: ListingRefusal::NotChecked,
            object: Some(object),
            component_depth: None,
            nlink_changed: Some(before.nlink() != after.nlink()),
        }
    }

    pub(crate) fn at_depth(mut self, depth: Option<i64>) -> Self {
        self.component_depth = depth;
        self
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn listing(site: AdmissionSite, listing: ListingRefusal) -> Self {
        Self { site, changes: 0, listing, object: None, component_depth: None, nlink_changed: None }
    }
}

// A second layer: build.rs rejects release profiles even with debug assertions enabled.
#[cfg(all(feature = "ci-diagnostics", not(debug_assertions)))]
compile_error!("ci-diagnostics requires debug_assertions; release/package builds must exclude it");

/// The operation or invariant that refused private-storage admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOperation {
    /// Opening a directory without following a symlink.
    OpenDirectory,
    /// Reading metadata through a held descriptor.
    DescriptorMetadata,
    /// Reading metadata of the named object without following links.
    NamedMetadata,
    /// Binding the named object to the descriptor and expected state.
    Identity,
    /// Checking ownership and permission bits.
    OwnershipAndMode,
    /// Reading filesystem identity and mount flags.
    FilesystemMetadata,
    /// Checking the filesystem allowlist and ownership enforcement.
    FilesystemPolicy,
    /// Reading the Linux access ACL attribute.
    AccessAcl,
    /// Reading the Linux default ACL attribute.
    DefaultAcl,
    /// Checking ACL contents against the fixed policy.
    AclPolicy,
    /// Requiring unchanged state across an ACL check.
    AclState,
    /// Spawning the macOS ACL oracle.
    SpawnAclProbe,
    /// Waiting for the owned ACL oracle.
    WaitAclProbe,
    /// Reading the bounded output of the ACL oracle.
    ReadAclProbe,
    /// Joining the ACL output reader.
    JoinAclReader,
    /// Requiring a successful ACL oracle exit.
    AclProbeExit,
    /// Parsing bounded UTF-8 output from the ACL oracle.
    AclProbeOutput,
    /// Rejecting an operand the oracle cannot safely represent.
    AclProbeOperand,
    /// Enforcing the original admission deadline.
    Deadline,
}

/// Privacy-safe facts about a failed admission. No error text or pathname is retained.
#[derive(Clone, Copy, thiserror::Error)]
#[error("operation={operation:?} kind={kind:?} raw_os_error={raw_os_error:?}")]
pub struct AdmissionFailure {
    /// Failed operation, drawn from a fixed vocabulary.
    pub operation: AdmissionOperation,
    /// OS error classification, or `None` for a policy/state refusal.
    pub kind: Option<io::ErrorKind>,
    /// OS error number, when the OS supplied one.
    pub raw_os_error: Option<i32>,
    #[cfg(all(target_os = "linux", debug_assertions))]
    context: Option<AdmissionContext>,
}

impl PartialEq for AdmissionFailure {
    fn eq(&self, other: &Self) -> bool {
        self.operation == other.operation
            && self.kind == other.kind
            && self.raw_os_error == other.raw_os_error
    }
}

impl Eq for AdmissionFailure {}

impl fmt::Debug for AdmissionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut failure = formatter.debug_struct("AdmissionFailure");
        failure
            .field("operation", &self.operation)
            .field("kind", &self.kind)
            .field("raw_os_error", &self.raw_os_error);
        // The default Linux test job captures Debug output without the artifact feature.
        #[cfg(all(target_os = "linux", debug_assertions))]
        if let Some(context) = self.context {
            failure.field("context", &context);
        }
        failure.finish()
    }
}

impl AdmissionFailure {
    const fn facts(
        operation: AdmissionOperation,
        kind: Option<io::ErrorKind>,
        raw_os_error: Option<i32>,
    ) -> Self {
        Self {
            operation,
            kind,
            raw_os_error,
            #[cfg(all(target_os = "linux", debug_assertions))]
            context: None,
        }
    }

    pub(crate) fn check(operation: AdmissionOperation) -> Self {
        let failure = Self::facts(operation, None, None);
        #[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
        ci::record(failure, None);
        failure
    }

    pub(crate) fn check_context(operation: AdmissionOperation, context: AdmissionContext) -> Self {
        let failure = Self::facts(operation, None, None);
        #[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
        ci::record(failure, Some(context));
        // The context is not part of the returned error or the release diagnostic channel.
        let _ = (
            context.site,
            context.changes,
            context.listing,
            context.object,
            context.component_depth,
            context.nlink_changed,
        );
        failure
    }

    /// Build an I/O refusal from the error kind and errno, discarding the error text.
    pub fn io(operation: AdmissionOperation, error: impl Into<io::Error>) -> Self {
        let error = error.into();
        let failure = Self::facts(operation, Some(error.kind()), error.raw_os_error());
        #[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
        ci::record(failure, None);
        failure
    }

    #[cfg(all(target_os = "linux", debug_assertions))]
    pub(crate) fn with_context(mut self, context: Option<AdmissionContext>) -> Self {
        self.context = context;
        self
    }

    /// Render only the context attached to the returned refusal for a store test.
    #[cfg(all(feature = "spawn-counter", debug_assertions))]
    pub fn diagnostic_context(failure: Option<Self>) -> impl fmt::Display {
        #[cfg(all(target_os = "linux", debug_assertions))]
        let context = failure.and_then(|failure| failure.context);
        #[cfg(not(target_os = "linux"))]
        let context = {
            let _ = failure;
            None
        };
        ContextFacts(context)
    }
}

#[cfg(all(feature = "spawn-counter", debug_assertions))]
struct ContextFacts(Option<AdmissionContext>);

#[cfg(all(feature = "spawn-counter", debug_assertions))]
impl fmt::Display for ContextFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(context) = self.0 else { return formatter.write_str("unavailable") };
        write!(
            formatter,
            "{:?},{},{:?},{:?},{:?},{:?}",
            context.site,
            context.changes,
            context.listing,
            context.object,
            context.component_depth,
            context.nlink_changed
        )
    }
}

// The store enables spawn-counter through its existing dev dependency only.
// This scope is independent of the best-effort CI file sink and never retains
// the error object. The outer store test scope owns the first failing site.
#[cfg(all(feature = "spawn-counter", debug_assertions))]
type IoFacts = (io::ErrorKind, Option<i32>);

#[cfg(all(feature = "spawn-counter", debug_assertions))]
thread_local! {
    static DISCARDED_IO: std::cell::Cell<Option<Option<IoFacts>>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(feature = "spawn-counter", debug_assertions))]
pub(crate) fn observe_discarded_io(error: impl Into<io::Error>) {
    DISCARDED_IO.with(|slot| {
        if slot.get() == Some(None) {
            let error = error.into();
            slot.set(Some(Some((error.kind(), error.raw_os_error()))));
        }
    });
}

#[cfg(all(feature = "spawn-counter", debug_assertions))]
impl crate::PrivateStorageError {
    /// Run one private-storage call and observe I/O facts its error mapping discards.
    pub fn with_io_diagnostic<T>(
        call: impl FnOnce() -> Result<T, Self>,
    ) -> (Result<T, Self>, Option<IoFacts>) {
        struct Restore(Option<Option<IoFacts>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                DISCARDED_IO.with(|slot| slot.set(self.0));
            }
        }

        let _restore = Restore(DISCARDED_IO.with(|slot| slot.replace(Some(None))));
        let result = call();
        let facts =
            if result.is_err() { DISCARDED_IO.with(|slot| slot.get().flatten()) } else { None };
        (result, facts)
    }
}

/// Observe a refusal without changing the caller's fallback or deadline precedence.
pub(crate) fn observe_context(operation: AdmissionOperation, context: AdmissionContext) {
    // Only check_context's feature-gated CI channel consumes this observation.
    // The returned failure must never enter the operation's failure accumulator.
    let _ = AdmissionFailure::check_context(operation, context);
}

#[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
mod ci {
    use super::{AdmissionContext, AdmissionFailure};
    use std::fmt::Write as _;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MAX_RECORDS: usize = 256;
    const MAX_BYTES: u64 = 64 * 1024;
    // POSIX's minimum PIPE_BUF; one bounded syscall per record on every host.
    const MAX_LINE: usize = 512;
    static RECORDS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(test)]
    struct TestSink {
        directory: tempfile::TempDir,
        records: AtomicUsize,
    }

    #[cfg(test)]
    thread_local! {
        static TEST_SINK: std::cell::RefCell<Option<TestSink>> = const { std::cell::RefCell::new(None) };
    }

    /// Redirect synthetic observations without changing the environment or shared budget.
    #[cfg(test)]
    pub(super) struct TestSinkGuard {
        previous: Option<TestSink>,
        // A thread-local override must be restored on the thread that installed it.
        _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    #[cfg(test)]
    impl TestSinkGuard {
        pub(super) fn enter() -> std::io::Result<Self> {
            use std::os::unix::fs::PermissionsExt as _;
            let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let sink = TestSink { directory, records: AtomicUsize::new(0) };
            let previous = TEST_SINK.with(|slot| slot.replace(Some(sink)));
            Ok(Self { previous, _thread: std::marker::PhantomData })
        }
    }

    #[cfg(test)]
    impl Drop for TestSinkGuard {
        fn drop(&mut self) {
            TEST_SINK.with(|slot| slot.replace(self.previous.take()));
        }
    }

    struct Record {
        bytes: [u8; MAX_LINE],
        len: usize,
    }

    impl Record {
        fn new() -> Self {
            Self { bytes: [0; MAX_LINE], len: 0 }
        }

        fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
            std::str::from_utf8(&self.bytes[..self.len])
        }
    }

    impl std::fmt::Write for Record {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            let end = self.len.checked_add(value.len()).ok_or(std::fmt::Error)?;
            let target = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
            target.copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    fn quoted(json: &mut Record, value: &str) -> std::fmt::Result {
        json.write_char('"')?;
        for c in value.chars() {
            match c {
                '"' => json.write_str("\\\"")?,
                '\\' => json.write_str("\\\\")?,
                c if c < ' ' => write!(json, "\\u{:04x}", c as u32)?,
                c => json.write_char(c)?,
            }
        }
        json.write_char('"')
    }

    fn line(
        failure: AdmissionFailure,
        thread: Option<&str>,
        context: Option<AdmissionContext>,
    ) -> Result<Record, std::fmt::Error> {
        let mut json = Record::new();
        json.write_str("{\"thread\":")?;
        if let Some(thread) = thread.filter(|name| name.len() <= 512) {
            quoted(&mut json, thread)?;
        } else {
            json.write_str("null")?;
        }
        write!(
            json,
            ",\"error\":\"Admission\",\"operation\":\"{:?}\",\"kind\":",
            failure.operation
        )?;
        if let Some(kind) = failure.kind {
            write!(json, "\"{kind:?}\"")?;
        } else {
            json.write_str("null")?;
        }
        json.write_str(",\"errno\":")?;
        if let Some(errno) = failure.raw_os_error {
            write!(json, "{errno}")?;
        } else {
            json.write_str("null")?;
        }
        if let Some(context) = context {
            write!(
                json,
                ",\"site\":\"{:?}\",\"changes\":{},\"listing\":\"{:?}\"",
                context.site, context.changes, context.listing
            )?;
            if let Some(object) = context.object {
                write!(json, ",\"object\":\"{object:?}\"")?;
            }
            if let Some(depth) = context.component_depth {
                write!(json, ",\"component_depth\":{depth}")?;
            }
            if let Some(changed) = context.nlink_changed {
                write!(json, ",\"nlink_changed\":{changed}")?;
            }
        }
        let (phase, site) = crate::caller::current();
        if let Some(phase) = phase {
            write!(json, ",\"store_phase\":\"{phase:?}\"")?;
        }
        if let Some(site) = site {
            write!(json, ",\"store_site\":\"{site:?}\"")?;
        }
        json.write_str("}\n")?;
        Ok(json)
    }

    fn open_directory(directory: &Path) -> std::io::Result<File> {
        use rustix::fs::{Mode, OFlags, open, openat};
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        // Inspect raw components: Path::components would normalize trailing
        // slashes and '.' before we could reject them. Hold every parent fd.
        let bytes = directory.as_os_str().as_bytes();
        if !bytes.starts_with(b"/") || bytes.ends_with(b"/") {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let mut parent = File::from(open("/", flags, Mode::empty())?);
        for component in bytes[1..].split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." || component == b".." {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            parent = File::from(openat(
                &parent,
                std::ffi::OsStr::from_bytes(component),
                flags,
                Mode::empty(),
            )?);
        }
        Ok(parent)
    }

    // Never use admission here: recording must not recurse or change its result.
    fn append(directory: &Path, record: &str) -> std::io::Result<()> {
        use rustix::fs::{Mode, OFlags, openat};
        if record.len() > MAX_LINE {
            return Ok(());
        }
        let root = open_directory(directory)?;
        let metadata = root.metadata()?;
        let uid = rustix::process::getuid().as_raw();
        if metadata.uid() != uid || metadata.mode() & 0o777 != 0o700 {
            return Ok(());
        }
        let file = File::from(openat(
            &root,
            "private-storage.jsonl",
            OFlags::RDWR
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )?);
        append_file(file, record)
    }

    struct AppendLock<'a>(&'a File);

    impl Drop for AppendLock<'_> {
        fn drop(&mut self) {
            // Closing alone releases flock only at the last reference. A concurrent spawn
            // can retain a duplicate until exec even with CLOEXEC, dropping later records.
            let _ = rustix::fs::flock(self.0, rustix::fs::FlockOperation::Unlock);
        }
    }

    fn append_file(file: File, record: &str) -> std::io::Result<()> {
        use rustix::fs::{FlockOperation, flock};
        use rustix::process::{Resource, getrlimit};
        // Independent open descriptions plus flock serialize threads AND
        // processes. Contention drops the observation instead of waiting.
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        let _lock = AppendLock(&file);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Ok(());
        }
        let limit = getrlimit(Resource::Fsize).current.unwrap_or(u64::MAX).min(MAX_BYTES);
        let end = metadata.len().checked_add(record.len() as u64);
        if end.is_none_or(|end| end > limit) {
            return Ok(());
        }
        if metadata.len() > 0 {
            let mut tail = [0];
            if rustix::io::pread(&file, &mut tail, metadata.len() - 1)? != 1 || tail[0] != b'\n' {
                return Ok(());
            }
        }
        // Refuse a pre-existing torn tail instead of joining a new record to it.
        // A short write is rolled back under the lock; no suffix is ever retried.
        // The size check also prevents SIGXFSZ with the current soft file limit.
        match (&file).write(record.as_bytes()) {
            Ok(written) if written != record.len() => {
                let _ = file.set_len(metadata.len());
            }
            _ => {}
        }
        Ok(())
    }

    #[cfg(test)]
    fn record_at(directory: &Path, record: &str, budget: &AtomicUsize) {
        if reserve(budget) {
            let _ = append(directory, record);
        }
    }

    fn reserve(budget: &AtomicUsize) -> bool {
        let mut count = budget.load(Ordering::Relaxed);
        while count < MAX_RECORDS {
            match budget.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => count = current,
            }
        }
        false
    }

    pub(super) fn record(failure: AdmissionFailure, context: Option<AdmissionContext>) {
        let _ = std::panic::catch_unwind(|| {
            #[cfg(test)]
            if TEST_SINK.with(|slot| {
                let slot = slot.borrow();
                let Some(sink) = slot.as_ref() else { return false };
                if reserve(&sink.records) {
                    let thread = std::thread::current();
                    if let Ok(record) = line(failure, thread.name(), context) {
                        if let Ok(record) = record.as_str() {
                            let _ = append(sink.directory.path(), record);
                        }
                    }
                }
                // Exhaustion still consumes the observation; never fall back to CI.
                true
            }) {
                return;
            }
            if let Some(directory) = std::env::var_os("XTRACE_CI_DIAG_DIR") {
                if reserve(&RECORDS) {
                    let thread = std::thread::current();
                    if let Ok(record) = line(failure, thread.name(), context) {
                        if let Ok(record) = record.as_str() {
                            let _ = append(Path::new(&directory), record);
                        }
                    }
                }
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::AdmissionOperation;
        use std::os::unix::fs::PermissionsExt as _;

        #[test]
        fn record_shape_and_libtest_thread_name() -> Result<(), Box<dyn std::error::Error>> {
            // This runs under the lane's actual libtest concurrency setting.
            let expected = concat!(module_path!(), "::record_shape_and_libtest_thread_name");
            let expected = expected.split_once("::").map_or(expected, |(_, name)| name);
            assert_eq!(std::thread::current().name(), Some(expected));
            let failure = AdmissionFailure::facts(
                AdmissionOperation::NamedMetadata,
                Some(std::io::ErrorKind::PermissionDenied),
                Some(13),
            );
            let record = line(failure, Some(expected), None)?;
            let record = record.as_str()?;
            assert_eq!(
                record,
                format!(
                    "{{\"thread\":\"{expected}\",\"error\":\"Admission\",\"operation\":\"NamedMetadata\",\"kind\":\"PermissionDenied\",\"errno\":13}}\n"
                )
            );
            let mut escaped = Record::new();
            quoted(&mut escaped, "a\"\\\n\t")?;
            assert_eq!(escaped.as_str()?, "\"a\\\"\\\\\\u000a\\u0009\"");
            assert!(line(failure, Some(&"\0".repeat(MAX_LINE)), None).is_err());
            let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            append(directory.path(), record)?;
            append(directory.path(), record)?;
            assert_eq!(
                std::fs::read_to_string(directory.path().join("private-storage.jsonl"))?,
                record.repeat(2)
            );
            let absent = AdmissionFailure::facts(AdmissionOperation::Deadline, None, None);
            assert_eq!(
                line(absent, None, None)?.as_str()?,
                "{\"thread\":null,\"error\":\"Admission\",\"operation\":\"Deadline\",\"kind\":null,\"errno\":null}\n"
            );
            Ok(())
        }

        #[test]
        fn contextual_record_contains_only_fixed_categories_and_a_difference_mask()
        -> Result<(), Box<dyn std::error::Error>> {
            let _sink = TestSinkGuard::enter()?;
            use crate::diagnostic::{AdmissionContext, AdmissionSite, ListingRefusal};
            let failure = AdmissionFailure::facts(AdmissionOperation::AclState, None, None);
            let context = AdmissionContext {
                site: AdmissionSite::Snapshot,
                changes: 3,
                listing: ListingRefusal::NotChecked,
                object: Some(super::super::AdmissionObject::Directory),
                component_depth: Some(-2),
                nlink_changed: Some(true),
            };
            assert_eq!(
                line(failure, None, Some(context))?.as_str()?,
                concat!(
                    "{\"thread\":null,\"error\":\"Admission\",\"operation\":\"AclState\",",
                    "\"kind\":null,\"errno\":null,\"site\":\"Snapshot\",",
                    "\"changes\":3,\"listing\":\"NotChecked\",\"object\":\"Directory\",",
                    "\"component_depth\":-2,\"nlink_changed\":true}\n"
                )
            );
            let context = AdmissionContext { listing: ListingRefusal::InheritedAllow, ..context };
            let record = line(failure, None, Some(context))?;
            assert!(record.as_str()?.contains("\"listing\":\"InheritedAllow\""));
            assert!(record.len <= MAX_LINE);
            assert_eq!(AdmissionFailure::check_context(failure.operation, context), failure);
            let _phase = crate::AdmissionCallerGuard::enter(crate::AdmissionCaller::Append);
            let _site = crate::AdmissionCallerGuard::enter(crate::AdmissionCaller::JournalPublish);
            let record = line(failure, None, Some(context))?;
            let record = record.as_str()?;
            assert!(record.contains("\"store_phase\":\"Append\""));
            assert!(record.contains("\"store_site\":\"JournalPublish\""));
            assert!(record.len() <= MAX_LINE);
            Ok(())
        }

        #[test]
        fn synthetic_record_tests_leave_shared_sink_untouched()
        -> Result<(), Box<dyn std::error::Error>> {
            use crate::diagnostic::tests::rendering_keeps_only_fixed_operations_and_os_error_facts;
            const CHILD: &str = "XTRACE_CI_DIAG_ISOLATION_CHILD";
            if std::env::var_os(CHILD).is_some() {
                contextual_record_contains_only_fixed_categories_and_a_difference_mask()?;
                rendering_keeps_only_fixed_operations_and_os_error_facts()?;
                test_sink_restores_nested_overrides_and_keeps_separate_budgets()?;
                assert_eq!(RECORDS.load(Ordering::Relaxed), 0);
                return Ok(());
            }
            let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let path = directory.path().join("private-storage.jsonl");
            let original = "{\"shared-sink-canary\":true}\n";
            std::fs::write(&path, original)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let output = crate::test_process::output(
                std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "diagnostic::ci::tests::synthetic_record_tests_leave_shared_sink_untouched",
                    ])
                    .env(CHILD, "1")
                    .env("XTRACE_CI_DIAG_DIR", directory.path()),
            )?;
            assert!(output.status.success(), "isolation child failed: {}", output.status);
            assert!(output.stderr.is_empty(), "isolation child must remain silent on stderr");
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            assert_eq!(std::fs::read_to_string(&path)?, original);
            assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
            Ok(())
        }

        #[test]
        fn test_sink_restores_nested_overrides_and_keeps_separate_budgets() -> std::io::Result<()> {
            let outer = TestSinkGuard::enter()?;
            let failure = AdmissionFailure::facts(AdmissionOperation::AclState, None, None);
            record(failure, None);
            {
                let _inner = TestSinkGuard::enter()?;
                for _ in 0..MAX_RECORDS + 1 {
                    record(failure, None);
                }
                TEST_SINK.with(|slot| {
                    assert_eq!(
                        slot.borrow().as_ref().map(|sink| sink.records.load(Ordering::Relaxed)),
                        Some(MAX_RECORDS)
                    );
                });
            }
            record(failure, None);
            TEST_SINK.with(|slot| {
                let slot = slot.borrow();
                let sink =
                    slot.as_ref().ok_or_else(|| std::io::Error::other("outer sink missing"))?;
                assert_eq!(sink.records.load(Ordering::Relaxed), 2);
                assert_eq!(
                    std::fs::read_to_string(sink.directory.path().join("private-storage.jsonl"))?
                        .lines()
                        .count(),
                    2
                );
                Ok::<_, std::io::Error>(())
            })?;
            drop(outer);
            TEST_SINK.with(|slot| assert!(slot.borrow().is_none()));
            Ok(())
        }

        #[test]
        fn refuses_public_directories_and_symlink_destinations() -> std::io::Result<()> {
            let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
            append(directory.path(), "{}\n")?;
            assert!(!directory.path().join("private-storage.jsonl").exists());
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let target = directory.path().join("target");
            std::fs::write(&target, "unchanged")?;
            std::os::unix::fs::symlink(&target, directory.path().join("private-storage.jsonl"))?;
            assert!(append(directory.path(), "{}\n").is_err());
            assert_eq!(std::fs::read_to_string(target)?, "unchanged");
            Ok(())
        }

        #[test]
        fn refuses_ancestor_symlinks_and_trailing_slashes() -> std::io::Result<()> {
            let fixture = tempfile::tempdir()?;
            let fixture = fixture.path().canonicalize()?;
            let outside = tempfile::tempdir()?;
            let target = outside.path().join("diag");
            std::fs::create_dir(&target)?;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
            std::os::unix::fs::symlink(outside.path(), fixture.join("link"))?;
            for path in [
                fixture.join("link/diag"),
                fixture.join("link/diag/"),
                target.join(""),
                fixture.join("./link/diag"),
                fixture.join("link/../link/diag"),
            ] {
                assert!(append(&path, "{}\n").is_err());
                assert!(!target.join("private-storage.jsonl").exists());
            }
            Ok(())
        }

        #[test]
        fn record_and_byte_caps_stop_silently() -> std::io::Result<()> {
            let directory = tempfile::tempdir()?;
            let directory = directory.path().canonicalize()?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let path = directory.join("private-storage.jsonl");
            let budget = AtomicUsize::new(0);
            for _ in 0..MAX_RECORDS + 10 {
                record_at(&directory, "{}\n", &budget);
            }
            assert_eq!(budget.load(Ordering::Relaxed), MAX_RECORDS);
            assert_eq!(std::fs::read_to_string(&path)?, "{}\n".repeat(MAX_RECORDS));
            for size in [MAX_BYTES - 1, MAX_BYTES, MAX_BYTES + 1] {
                let contents = vec![b'\n'; size as usize];
                std::fs::write(&path, &contents)?;
                append(&directory, "{}\n")?;
                assert_eq!(std::fs::read(&path)?, contents);
            }
            std::fs::write(&path, "torn")?;
            append(&directory, "{}\n")?;
            assert_eq!(std::fs::read_to_string(&path)?, "torn");
            std::fs::write(&path, "")?;
            append(&directory, &"x".repeat(MAX_LINE + 1))?;
            assert_eq!(std::fs::metadata(path)?.len(), 0);
            Ok(())
        }

        #[test]
        fn append_unlocks_even_while_a_spawn_retains_the_file_description() -> std::io::Result<()> {
            use std::os::unix::fs::OpenOptionsExt as _;

            let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let path = directory.path().join("private-storage.jsonl");
            // Model the descriptor reference held between fork and exec, without a timing
            // race. Both a successful write and the early refusal paths must unlock it.
            for prefix in [Vec::new(), b"torn".to_vec(), vec![b'\n'; MAX_BYTES as usize]] {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .open(&path)?;
                std::fs::write(&path, &prefix)?;
                let inherited = file.try_clone()?;
                append_file(file, "{}\n")?;
                // This independent open must acquire the lock, even though the duplicated
                // description is still live. Without explicit unlock this returns WouldBlock.
                append(directory.path(), "{}\n")?;
                drop(inherited);
                assert_eq!(
                    std::fs::read(&path)?,
                    if prefix.is_empty() { b"{}\n{}\n".to_vec() } else { prefix }
                );
            }
            Ok(())
        }

        #[test]
        fn concurrent_writers_keep_complete_lines_within_both_caps() -> std::io::Result<()> {
            let directory = tempfile::tempdir()?;
            let directory = directory.path().canonicalize()?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let path = directory.join("private-storage.jsonl");
            let record = "{\"error\":\"Admission\"}\n";
            for prefix in [0, MAX_BYTES as usize - 2 * record.len()] {
                std::fs::write(&path, vec![b'\n'; prefix])?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                let budget = AtomicUsize::new(0);
                let barrier = std::sync::Barrier::new(8);
                std::thread::scope(|scope| {
                    for _ in 0..8 {
                        let (directory, budget, barrier) = (&directory, &budget, &barrier);
                        scope.spawn(move || {
                            barrier.wait();
                            for _ in 0..MAX_RECORDS {
                                record_at(directory, record, budget);
                            }
                        });
                    }
                });
                let contents = std::fs::read_to_string(&path)?;
                let appended = &contents[prefix..];
                assert!(!appended.is_empty());
                assert!(appended.ends_with('\n'));
                assert!(contents.len() as u64 <= MAX_BYTES);
                assert!(appended.lines().count() <= MAX_RECORDS);
                assert_eq!(budget.load(Ordering::Relaxed), MAX_RECORDS);
                for complete in appended.lines() {
                    assert_eq!(complete, record.trim_end());
                }
            }
            Ok(())
        }

        #[test]
        fn saturated_file_and_fsize_limit_preserve_original_admission() -> std::io::Result<()> {
            const CHILD: &str = "XTRACE_CI_DIAG_LIMIT_CHILD";
            if std::env::var_os(CHILD).is_some() {
                use rustix::process::{Resource, Rlimit, setrlimit};
                setrlimit(Resource::Fsize, Rlimit { current: Some(4096), maximum: Some(4096) })?;
                let original = AdmissionFailure::facts(
                    AdmissionOperation::NamedMetadata,
                    Some(std::io::ErrorKind::PermissionDenied),
                    Some(13),
                );
                for _ in 0..MAX_RECORDS + 1 {
                    assert_eq!(
                        AdmissionFailure::io(
                            original.operation,
                            std::io::Error::from_raw_os_error(13)
                        ),
                        original
                    );
                }
                return Ok(());
            }
            let directory = tempfile::tempdir()?;
            let directory = directory.path().canonicalize()?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let path = directory.join("private-storage.jsonl");
            for size in [0, 4095, 4096, MAX_BYTES as usize, MAX_BYTES as usize + 1] {
                std::fs::write(&path, vec![b'\n'; size])?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                // Rust's test binary retains the default SIGXFSZ disposition.
                // A write at the limit would kill this child before its asserts.
                let output = crate::test_process::output(
                    std::process::Command::new(std::env::current_exe()?)
                        .args([
                            "--exact",
                            concat!(
                                "diagnostic::ci::tests::",
                                "saturated_file_and_fsize_limit_preserve_original_admission"
                            ),
                        ])
                        .env(CHILD, "1")
                        .env("XTRACE_CI_DIAG_DIR", &directory),
                )?;
                assert!(
                    output.status.success(),
                    "diagnostic writer changed admission: {}",
                    output.status
                );
                assert!(output.stderr.is_empty(), "diagnostic child must remain silent on stderr");
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
                if size == 0 {
                    // Prove the child reached the writer under the same file limit.
                    let contents = std::fs::read_to_string(&path)?;
                    assert!(!contents.is_empty());
                    assert!(contents.len() <= 4096);
                    let expected = line(
                        AdmissionFailure::facts(
                            AdmissionOperation::NamedMetadata,
                            Some(std::io::ErrorKind::PermissionDenied),
                            Some(13),
                        ),
                        Some(concat!(
                            "diagnostic::ci::tests::",
                            "saturated_file_and_fsize_limit_preserve_original_admission"
                        )),
                        None,
                    )
                    .map_err(std::io::Error::other)?;
                    assert_eq!(
                        contents,
                        expected
                            .as_str()
                            .map_err(std::io::Error::other)?
                            .repeat(contents.lines().count())
                    );
                } else {
                    assert_eq!(std::fs::read(&path)?, vec![b'\n'; size]);
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_evidence_reports_differences_without_retaining_metadata() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir()?;
        let before = root.path().symlink_metadata()?;
        let unchanged = AdmissionContext::state(AdmissionSite::Snapshot, &before, &before);
        assert_eq!(unchanged.changes, 0);
        assert_eq!(unchanged.listing, ListingRefusal::NotChecked);
        let mode = before.permissions().mode() ^ 0o100;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(mode))?;
        let after = root.path().symlink_metadata()?;
        let changed = AdmissionContext::state(AdmissionSite::Snapshot, &before, &after);
        assert_eq!(changed.changes & 4, 4, "mode difference");
        assert_eq!(changed.changes & (2 | 8 | 16), 0, "mtime, owner and identity stayed equal");
        assert_eq!(changed.nlink_changed, Some(false));
        std::fs::set_permissions(root.path(), before.permissions())?;
        let other = tempfile::tempdir_in(root.path())?;
        let replaced = AdmissionContext::state(
            AdmissionSite::Snapshot,
            &before,
            &other.path().symlink_metadata()?,
        );
        assert_eq!(replaced.changes & 16, 16, "different inode");
        let file = root.path().join("file");
        std::fs::write(&file, b"link-count-canary")?;
        let before = file.symlink_metadata()?;
        std::fs::hard_link(&file, root.path().join("link"))?;
        let linked =
            AdmissionContext::state(AdmissionSite::Snapshot, &before, &file.symlink_metadata()?);
        assert!(matches!(linked.object, Some(AdmissionObject::File)));
        assert_eq!(linked.nlink_changed, Some(true));
        assert_eq!(linked.changes & (2 | 4 | 8 | 16), 0);
        Ok(())
    }

    #[test]
    pub(super) fn rendering_keeps_only_fixed_operations_and_os_error_facts() -> io::Result<()> {
        #[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
        let _sink = ci::TestSinkGuard::enter()?;
        let error = AdmissionFailure::io(
            AdmissionOperation::NamedMetadata,
            io::Error::new(io::ErrorKind::PermissionDenied, "private-path/value-canary"),
        );
        let error = crate::PrivateStorageError::Admission(error);
        assert_eq!(
            error.to_string(),
            "private storage is unavailable: operation=NamedMetadata kind=Some(PermissionDenied) raw_os_error=None"
        );
        assert_eq!(
            format!("{error:?}"),
            "Admission(AdmissionFailure { operation: NamedMetadata, kind: Some(PermissionDenied), raw_os_error: None })"
        );
        assert!(!error.to_string().contains("canary"));
        assert!(!format!("{error:?}").contains("canary"));

        let os_error = io::Error::from_raw_os_error(13);
        let failure = AdmissionFailure::io(AdmissionOperation::AccessAcl, os_error);
        assert_eq!(failure.kind, Some(io::ErrorKind::PermissionDenied));
        assert_eq!(failure.raw_os_error, Some(13));
        assert_eq!(
            failure.to_string(),
            "operation=AccessAcl kind=Some(PermissionDenied) raw_os_error=Some(13)"
        );
        assert_eq!(
            AdmissionFailure::check(AdmissionOperation::AclState).to_string(),
            "operation=AclState kind=None raw_os_error=None"
        );
        Ok(())
    }

    #[cfg(all(feature = "spawn-counter", debug_assertions))]
    #[test]
    fn discarded_io_is_scoped_and_preserves_the_generic_operation_error() {
        use crate::PrivateStorageError;

        let (result, facts) = PrivateStorageError::with_io_diagnostic(|| {
            Err::<(), _>(PrivateStorageError::Operation.discard_io(rustix::io::Errno::NOSPC))
        });
        assert_eq!(result, Err(PrivateStorageError::Operation));
        assert_eq!(
            facts,
            Some((io::ErrorKind::StorageFull, Some(rustix::io::Errno::NOSPC.raw_os_error())))
        );

        let (result, facts) = PrivateStorageError::with_io_diagnostic(|| {
            Err::<(), _>(
                PrivateStorageError::Operation
                    .discard_io(io::Error::other("/private/path fixture-canary")),
            )
        });
        assert_eq!(result, Err(PrivateStorageError::Operation));
        assert_eq!(facts, Some((io::ErrorKind::Other, None)));

        let (_, facts) = PrivateStorageError::with_io_diagnostic(|| {
            let (_, inner) = PrivateStorageError::with_io_diagnostic(|| {
                Err::<(), _>(PrivateStorageError::Operation.discard_io(rustix::io::Errno::NOSPC))
            });
            assert!(inner.is_some());
            Err::<(), _>(PrivateStorageError::Operation)
        });
        assert_eq!(facts, None);
    }

    #[cfg(all(target_os = "linux", feature = "spawn-counter", debug_assertions))]
    #[test]
    fn acknowledgement_context_comes_from_the_returned_admission_refusal() {
        let context = AdmissionContext {
            site: AdmissionSite::ProbeState,
            changes: 1,
            listing: ListingRefusal::NotChecked,
            object: Some(AdmissionObject::Directory),
            component_depth: Some(-1),
            nlink_changed: Some(false),
        };
        let failure = AdmissionFailure::facts(AdmissionOperation::AclState, None, None)
            .with_context(Some(context));
        assert_eq!(
            AdmissionFailure::diagnostic_context(Some(failure)).to_string(),
            "ProbeState,1,NotChecked,Some(Directory),Some(-1),Some(false)"
        );
        assert_eq!(AdmissionFailure::diagnostic_context(None).to_string(), "unavailable");
    }
}
