//! Fail-closed private-storage capability for platforms without the Unix proof.

use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
#[error("private storage is unavailable")]
pub enum PrivateStorageError {
    /// The platform cannot establish the required private-storage proof.
    Unavailable,
    /// The requested child name is invalid.
    InvalidName,
    /// An exclusive child creation collided with an existing name.
    AlreadyExists,
    /// A bounded operation failed.
    Operation,
}

/// No-op admission scope: this platform admits nothing, so there is nothing to share.
///
/// Guards are pinned to their thread:
///
/// ```compile_fail
/// fn needs_send<T: Send>(_: T) {}
/// needs_send(xtrace_private_storage::AdmissionScope::enter());
/// ```
///
/// ```compile_fail
/// fn needs_sync<T: Sync>(_: &T) {}
/// needs_sync(&xtrace_private_storage::AdmissionScope::enter());
/// ```
#[must_use = "an admission scope ends as soon as its guard is dropped"]
pub struct AdmissionScope {
    _single_thread: std::marker::PhantomData<*const ()>,
}

impl AdmissionScope {
    /// Opens a scope (a no-op on this platform).
    pub fn enter() -> Self {
        Self { _single_thread: std::marker::PhantomData }
    }
}

/// Platform placeholder that deliberately cannot admit a private root.
pub struct AdmittedPrivateRoot;

impl std::fmt::Debug for AdmittedPrivateRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AdmittedPrivateRoot(unavailable)")
    }
}

impl AdmittedPrivateRoot {
    /// Fails closed on unsupported platforms.
    pub fn validate_open_directory(
        _path: &Path,
        _directory: &File,
        _private_leaf: bool,
    ) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on platforms without an implemented owner/ACL/filesystem proof.
    pub fn open(_path: &Path) -> Result<Self, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_container(_path: &Path) -> Result<Self, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_or_create(_path: &Path) -> Result<Self, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn revalidate(&self) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// This path is never available without a capability.
    #[must_use]
    pub fn path(&self) -> &Path {
        Path::new("")
    }

    /// Fails closed on unsupported platforms.
    pub fn create_private_child(&self, _name: &str) -> Result<Self, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_or_create_private_child(&self, _name: &str) -> Result<Self, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_private_child(&self, _name: &str) -> Result<Self, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn bounded_child_names(
        &self,
        _maximum_entries: usize,
    ) -> Result<Vec<String>, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn remove_private_file(&self, _name: &str) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn remove_private_file_if_matches(
        &self,
        _name: &str,
        _expected: &File,
    ) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn remove_managed_file(&self, _name: &str) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn remove_private_child(&self, _name: &str) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_regular_file(&self, _name: &str) -> Result<File, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn validate_optional_private_file(&self, _name: &str) -> Result<bool, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_managed_file(&self, _name: &str) -> Result<File, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn create_private_file(&self, _name: &str) -> Result<File, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn open_or_create_private_file(&self, _name: &str) -> Result<File, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn read_bounded_file(
        &self,
        _name: &str,
        _maximum_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn read_bounded_managed_file(
        &self,
        _name: &str,
        _maximum_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn validate_file_binding(
        &self,
        _name: &str,
        _file: &File,
        _newly_created: bool,
    ) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn validate_managed_file_binding(
        &self,
        _name: &str,
        _file: &File,
        _newly_created: bool,
    ) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn rename_replace(&self, _source: &str, _target: &str) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }

    /// Fails closed on unsupported platforms.
    pub fn sync(&self) -> Result<(), PrivateStorageError> {
        Err(PrivateStorageError::Unavailable)
    }
}

/// Validates a bounded single-component name independently of platform support.
pub fn validate_child_name(name: &str) -> Result<(), PrivateStorageError> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.bytes().any(|byte| byte == b'/' || byte == 0 || byte.is_ascii_control())
    {
        return Err(PrivateStorageError::InvalidName);
    }
    Ok(())
}
