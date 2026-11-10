//! Admission diagnostics contain fixed vocabulary and numeric OS facts only.

use std::io;

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
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("operation={operation:?} kind={kind:?} raw_os_error={raw_os_error:?}")]
pub struct AdmissionFailure {
    /// Failed operation, drawn from a fixed vocabulary.
    pub operation: AdmissionOperation,
    /// OS error classification, or `None` for a policy/state refusal.
    pub kind: Option<io::ErrorKind>,
    /// OS error number, when the OS supplied one.
    pub raw_os_error: Option<i32>,
}

impl AdmissionFailure {
    pub(crate) fn check(operation: AdmissionOperation) -> Self {
        let failure = Self { operation, kind: None, raw_os_error: None };
        #[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
        ci::record(failure);
        failure
    }

    pub(crate) fn io(operation: AdmissionOperation, error: impl Into<io::Error>) -> Self {
        let error = error.into();
        let failure =
            Self { operation, kind: Some(error.kind()), raw_os_error: error.raw_os_error() };
        #[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
        ci::record(failure);
        failure
    }
}

#[cfg(all(feature = "ci-diagnostics", debug_assertions, unix))]
mod ci {
    use super::AdmissionFailure;
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

    fn line(failure: AdmissionFailure, thread: Option<&str>) -> Result<Record, std::fmt::Error> {
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
        use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
        use rustix::process::{Resource, getrlimit};
        if record.len() > MAX_LINE {
            return Ok(());
        }
        let root = open_directory(directory)?;
        let metadata = root.metadata()?;
        let uid = rustix::process::getuid().as_raw();
        if metadata.uid() != uid || metadata.mode() & 0o777 != 0o700 {
            return Ok(());
        }
        let mut file = File::from(openat(
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
        // Independent open descriptions plus flock serialize threads AND
        // processes. Contention drops the observation instead of waiting.
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
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
        match file.write(record.as_bytes()) {
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
        budget
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_RECORDS).then_some(count + 1)
            })
            .is_ok()
    }

    pub(super) fn record(failure: AdmissionFailure) {
        let _ = std::panic::catch_unwind(|| {
            if let Some(directory) = std::env::var_os("XTRACE_CI_DIAG_DIR") {
                if reserve(&RECORDS) {
                    let thread = std::thread::current();
                    if let Ok(record) = line(failure, thread.name()) {
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
            let failure = AdmissionFailure {
                operation: AdmissionOperation::NamedMetadata,
                kind: Some(std::io::ErrorKind::PermissionDenied),
                raw_os_error: Some(13),
            };
            let record = line(failure, Some(expected))?;
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
            assert!(line(failure, Some(&"\0".repeat(MAX_LINE))).is_err());
            let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            append(directory.path(), record)?;
            append(directory.path(), record)?;
            assert_eq!(
                std::fs::read_to_string(directory.path().join("private-storage.jsonl"))?,
                record.repeat(2)
            );
            let absent = AdmissionFailure {
                operation: AdmissionOperation::Deadline,
                kind: None,
                raw_os_error: None,
            };
            assert_eq!(
                line(absent, None)?.as_str()?,
                "{\"thread\":null,\"error\":\"Admission\",\"operation\":\"Deadline\",\"kind\":null,\"errno\":null}\n"
            );
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
        fn concurrent_writers_keep_complete_lines_within_both_caps() -> std::io::Result<()> {
            let directory = tempfile::tempdir()?;
            let directory = directory.path().canonicalize()?;
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
                let original = AdmissionFailure {
                    operation: AdmissionOperation::NamedMetadata,
                    kind: Some(std::io::ErrorKind::PermissionDenied),
                    raw_os_error: Some(13),
                };
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
            let path = directory.join("private-storage.jsonl");
            for size in [4095, 4096, MAX_BYTES as usize, MAX_BYTES as usize + 1] {
                std::fs::write(&path, vec![b'\n'; size])?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                // Rust's test binary retains the default SIGXFSZ disposition.
                // A write at the limit would kill this child before its asserts.
                let output = std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        concat!(
                            "diagnostic::ci::tests::",
                            "saturated_file_and_fsize_limit_preserve_original_admission"
                        ),
                    ])
                    .env(CHILD, "1")
                    .env("XTRACE_CI_DIAG_DIR", &directory)
                    .output()?;
                assert!(
                    output.status.success(),
                    "diagnostic writer changed admission: {}",
                    output.status
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
                assert_eq!(std::fs::read(&path)?, vec![b'\n'; size]);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_keeps_only_fixed_operations_and_os_error_facts() {
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
    }
}
