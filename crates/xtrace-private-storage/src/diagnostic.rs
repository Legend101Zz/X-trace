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
    pub(crate) const fn check(operation: AdmissionOperation) -> Self {
        Self { operation, kind: None, raw_os_error: None }
    }

    pub(crate) fn io(operation: AdmissionOperation, error: impl Into<io::Error>) -> Self {
        let error = error.into();
        Self { operation, kind: Some(error.kind()), raw_os_error: error.raw_os_error() }
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
