//! Admission diagnostics contain fixed vocabulary and numeric OS facts only.

use std::io;

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
        #[cfg(all(feature = "ci-diagnostics", unix))]
        ci::record(failure);
        failure
    }

    pub(crate) fn io(operation: AdmissionOperation, error: impl Into<io::Error>) -> Self {
        let error = error.into();
        let failure =
            Self { operation, kind: Some(error.kind()), raw_os_error: error.raw_os_error() };
        #[cfg(all(feature = "ci-diagnostics", unix))]
        ci::record(failure);
        failure
    }
}

#[cfg(all(feature = "ci-diagnostics", unix))]
mod ci {
    use super::AdmissionFailure;
    use std::fmt::Write as _;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    fn quoted(value: &str) -> String {
        let mut json = String::from("\"");
        for c in value.chars() {
            match c {
                '"' => json.push_str("\\\""),
                '\\' => json.push_str("\\\\"),
                c if c < ' ' => {
                    let _ = write!(json, "\\u{:04x}", c as u32);
                }
                c => json.push(c),
            }
        }
        json.push('"');
        json
    }

    fn line(failure: AdmissionFailure, thread: Option<&str>) -> String {
        let thread = thread.filter(|name| name.len() <= 512).map(quoted);
        let kind = failure.kind.map(|kind| quoted(&format!("{kind:?}")));
        let errno = failure.raw_os_error.map(|errno| errno.to_string());
        format!(
            "{{\"thread\":{},\"error\":\"Admission\",\"operation\":\"{:?}\",\"kind\":{},\"errno\":{}}}\n",
            thread.as_deref().unwrap_or("null"),
            failure.operation,
            kind.as_deref().unwrap_or("null"),
            errno.as_deref().unwrap_or("null"),
        )
    }

    // Do not use private-storage admission here: diagnostics must never recurse
    // into admission, alter its result, or interpret any OS error message.
    fn append(directory: &Path, record: &str) -> std::io::Result<()> {
        use rustix::fs::{Mode, OFlags, open, openat};
        let root = File::from(open(
            directory,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = root.metadata()?;
        let uid = rustix::process::getuid().as_raw();
        if metadata.uid() != uid || metadata.mode() & 0o777 != 0o700 {
            return Ok(());
        }
        let mut file = File::from(openat(
            &root,
            "private-storage.jsonl",
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Ok(());
        }
        // One append syscall keeps concurrent records together. A partial write
        // is discarded by the reader; retrying could interleave JSON fragments.
        let _ = file.write(record.as_bytes());
        Ok(())
    }

    pub(super) fn record(failure: AdmissionFailure) {
        if let Some(directory) = std::env::var_os("XTRACE_CI_DIAG_DIR") {
            let thread = std::thread::current();
            let _ = append(Path::new(&directory), &line(failure, thread.name()));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::AdmissionOperation;
        use std::os::unix::fs::PermissionsExt as _;

        #[test]
        fn record_shape_and_libtest_thread_name() -> std::io::Result<()> {
            // This runs under the lane's actual libtest concurrency setting.
            let expected = concat!(module_path!(), "::record_shape_and_libtest_thread_name");
            let expected = expected.split_once("::").map_or(expected, |(_, name)| name);
            assert_eq!(std::thread::current().name(), Some(expected));
            let failure = AdmissionFailure {
                operation: AdmissionOperation::NamedMetadata,
                kind: Some(std::io::ErrorKind::PermissionDenied),
                raw_os_error: Some(13),
            };
            let record = line(failure, Some(expected));
            assert_eq!(
                record,
                format!(
                    "{{\"thread\":\"{expected}\",\"error\":\"Admission\",\"operation\":\"NamedMetadata\",\"kind\":\"PermissionDenied\",\"errno\":13}}\n"
                )
            );
            assert_eq!(quoted("a\"\\\n\t"), "\"a\\\"\\\\\\u000a\\u0009\"");
            let directory = tempfile::tempdir()?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            append(directory.path(), &record)?;
            append(directory.path(), &record)?;
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
                line(absent, None),
                "{\"thread\":null,\"error\":\"Admission\",\"operation\":\"Deadline\",\"kind\":null,\"errno\":null}\n"
            );
            Ok(())
        }

        #[test]
        fn refuses_public_directories_and_symlink_destinations() -> std::io::Result<()> {
            let directory = tempfile::tempdir()?;
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
