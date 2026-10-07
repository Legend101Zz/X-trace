//! Owner-enforced private directory capabilities for local X-trace state.
//!
//! Paths are used only to locate a directory. Callers retain this non-cloneable
//! descriptor-backed capability and revalidate it before each independent
//! operation that may read or write private state.

use std::fs::File;
use std::path::{Path, PathBuf};

use thiserror::Error;

const MAX_PATH_COMPONENTS: usize = 128;
const ADMISSION_BUDGET: std::time::Duration = std::time::Duration::from_millis(750);
/// How often an owned ACL probe is polled for exit. A local `ls` finishes in a few
/// milliseconds, so a coarse interval would be most of every admission's cost.
#[cfg(target_os = "macos")]
const ACL_PROBE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(1);
#[cfg(target_os = "macos")]
const ACL_PROBE_CLEANUP_BUDGET: std::time::Duration = std::time::Duration::from_millis(100);

fn new_admission_deadline() -> std::time::Instant {
    std::time::Instant::now() + ADMISSION_BUDGET
}

/// Sanitized failure to prove that private storage is safe to use.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrivateStorageError {
    /// The path, descriptor, owner, permissions, ACL, or filesystem failed closed validation.
    #[error("private storage is unavailable")]
    Unavailable,
    /// A child name was not a single safe path component.
    #[error("private storage child name is invalid")]
    InvalidName,
    /// An exclusive child creation collided with an existing name.
    #[error("private storage child already exists")]
    AlreadyExists,
    /// The requested bounded operation failed.
    #[error("private storage operation failed")]
    Operation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    owner: u32,
    mode: u32,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
        }
    }

    fn same_directory(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.owner == other.owner
            && self.mode == other.mode
    }

    fn same_file(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.size == other.size
            && self.owner == other.owner
            && self.mode == other.mode
    }
}

/// An admitted private directory bound to its opened descriptor and named identity.
///
/// This type is intentionally neither `Clone` nor constructible from a path or
/// Boolean. It is a point-in-time capability; privileged remounts and hostile
/// processes running as the same user remain outside its guarantee.
pub struct AdmittedPrivateRoot {
    path: PathBuf,
    directory: File,
    identity: FileIdentity,
    private_leaf: bool,
}

impl std::fmt::Debug for AdmittedPrivateRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedPrivateRoot")
            .field("admitted", &true)
            .finish_non_exhaustive()
    }
}

impl AdmittedPrivateRoot {
    /// Validates an already-open directory using the shared storage policy.
    ///
    /// This is for tightly scoped adapters that must retain their descriptor
    /// shape; ordinary callers should retain an `AdmittedPrivateRoot` instead.
    pub fn validate_open_directory(
        path: &Path,
        directory: &File,
        private_leaf: bool,
    ) -> Result<(), PrivateStorageError> {
        let deadline = new_admission_deadline();
        let walked = open_directory_without_symlinks_until(path, deadline)?;
        let supplied = directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let walked_metadata = walked.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let supplied_identity = FileIdentity::from_metadata(&supplied);
        if !supplied_identity.same_directory(FileIdentity::from_metadata(&walked_metadata)) {
            return Err(PrivateStorageError::Unavailable);
        }
        admit_directory_descriptor_until(path, directory, private_leaf, deadline)
    }

    /// Opens and admits an existing exact-owner `0700` directory.
    pub fn open(path: &Path) -> Result<Self, PrivateStorageError> {
        Self::open_with_mode(path, true)
    }

    /// Opens an existing container that is safe for traversal but not necessarily private.
    ///
    /// This is for an already-existing ancestor only; it must not be used as
    /// authorization to create private files directly inside that ancestor.
    pub fn open_container(path: &Path) -> Result<Self, PrivateStorageError> {
        Self::open_with_mode(path, false)
    }

    /// Creates missing path components with owner-only permissions and admits the final leaf.
    ///
    /// Existing ancestors are opened without following links and checked before
    /// a missing child is created. No existing directory is chmod-repaired.
    pub fn open_or_create(path: &Path) -> Result<Self, PrivateStorageError> {
        use std::path::Component;

        let deadline = new_admission_deadline();
        if !path.is_absolute() {
            return Err(PrivateStorageError::InvalidName);
        }
        if path.as_os_str().len() > 4096 {
            return Err(PrivateStorageError::InvalidName);
        }
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name.to_str().ok_or(PrivateStorageError::InvalidName)?;
                    validate_child_name(name)?;
                    names.push(name.to_owned());
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(PrivateStorageError::InvalidName);
                }
            }
        }
        if names.is_empty() {
            return Err(PrivateStorageError::InvalidName);
        }
        if names.len() > MAX_PATH_COMPONENTS {
            return Err(PrivateStorageError::InvalidName);
        }
        let descriptor = open_directory_descriptor("/")?;
        let mut current =
            Self::from_admitted_descriptor_until(PathBuf::from("/"), descriptor, false, deadline)?;
        for (index, name) in names.iter().enumerate() {
            let is_leaf = index + 1 == names.len();
            match rustix::fs::openat(
                &current.directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            ) {
                Ok(opened) => {
                    let next_path = current.path.join(name);
                    current = Self::from_admitted_descriptor_until(
                        next_path,
                        File::from(opened),
                        is_leaf,
                        deadline,
                    )?;
                }
                Err(error) if error == rustix::io::Errno::NOENT => {
                    current = current.create_private_child_until(name, deadline)?;
                }
                Err(_) => return Err(PrivateStorageError::Unavailable),
            }
        }
        current.revalidate_until(deadline)?;
        Ok(current)
    }

    fn from_admitted_descriptor_until(
        path: PathBuf,
        directory: File,
        private_leaf: bool,
        deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        admit_directory_descriptor_until(&path, &directory, private_leaf, deadline)?;
        let metadata = directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        Ok(Self { path, directory, identity: FileIdentity::from_metadata(&metadata), private_leaf })
    }

    fn open_with_mode(path: &Path, private_leaf: bool) -> Result<Self, PrivateStorageError> {
        let deadline = new_admission_deadline();
        let directory = open_directory_without_symlinks_until(path, deadline)?;
        admit_directory_descriptor_until(path, &directory, private_leaf, deadline)?;
        let metadata = directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let identity = FileIdentity::from_metadata(&metadata);
        Ok(Self { path: path.to_path_buf(), directory, identity, private_leaf })
    }

    /// Revalidates the opened descriptor, its current name, ACL, owner, mode, and filesystem.
    pub fn revalidate(&self) -> Result<(), PrivateStorageError> {
        self.revalidate_until(new_admission_deadline())
    }

    /// Revalidates within a caller-owned bounded multi-step operation.
    ///
    /// The caller's absolute deadline is capped by the ordinary admission
    /// budget for this individual operation.
    pub(crate) fn revalidate_for_operation(
        &self,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        self.revalidate_until(operation_deadline.min(new_admission_deadline()))
    }

    fn revalidate_until(&self, deadline: std::time::Instant) -> Result<(), PrivateStorageError> {
        // Re-open every component from `/` without following links. Checking
        // only the retained leaf descriptor would miss replacement of an
        // intermediate ancestor after this capability was created.
        let walked = open_directory_without_symlinks_until(&self.path, deadline)?;
        let metadata = self.directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let walked_metadata = walked.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        if !self.identity.same_directory(FileIdentity::from_metadata(&metadata))
            || !self.identity.same_directory(FileIdentity::from_metadata(&walked_metadata))
        {
            return Err(PrivateStorageError::Unavailable);
        }
        admit_directory_descriptor_until(&self.path, &self.directory, self.private_leaf, deadline)
    }

    /// Returns the canonical path associated with this capability for path-based APIs.
    ///
    /// The path is informational and is not an admission token; callers must
    /// retain and revalidate this object around path-based operations.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates and admits a new owner-only child directory relative to this descriptor.
    pub fn create_private_child(&self, name: &str) -> Result<Self, PrivateStorageError> {
        self.create_private_child_until(name, new_admission_deadline())
    }

    /// Creates a private child while preserving the caller's absolute deadline.
    pub(crate) fn create_private_child_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        self.create_private_child_until(name, operation_deadline.min(new_admission_deadline()))
    }

    fn create_private_child_until(
        &self,
        name: &str,
        deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        validate_child_name(name)?;
        self.revalidate_until(deadline)?;
        rustix::fs::mkdirat(&self.directory, name, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)?;
        self.sync_until(deadline)?;
        let child = rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| PrivateStorageError::Unavailable)?;
        self.revalidate_until(deadline)?;
        let path = self.path.join(name);
        admit_directory_descriptor_until(&path, &child, true, deadline)?;
        self.revalidate_until(deadline)?;
        let metadata = child.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        Ok(Self {
            path,
            directory: child,
            identity: FileIdentity::from_metadata(&metadata),
            private_leaf: true,
        })
    }

    /// Opens a private child, creating it only when it is absent.
    pub fn open_or_create_private_child(&self, name: &str) -> Result<Self, PrivateStorageError> {
        self.open_or_create_private_child_until(name, new_admission_deadline())
    }

    fn open_or_create_private_child_until(
        &self,
        name: &str,
        deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        validate_child_name(name)?;
        self.revalidate_until(deadline)?;
        match rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ) {
            Ok(opened) => {
                let child = Self::from_admitted_descriptor_until(
                    self.path.join(name),
                    File::from(opened),
                    true,
                    deadline,
                )?;
                self.revalidate_until(deadline)?;
                Ok(child)
            }
            Err(error) if error == rustix::io::Errno::NOENT => {
                self.create_private_child_until(name, deadline)
            }
            Err(_) => Err(PrivateStorageError::Unavailable),
        }
    }

    /// Opens an already-existing private child directory relative to this descriptor.
    pub fn open_private_child(&self, name: &str) -> Result<Self, PrivateStorageError> {
        self.open_private_child_until(name, new_admission_deadline())
    }

    /// Opens an admitted private child within a caller-owned bounded operation.
    pub(crate) fn open_private_child_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        self.open_private_child_until(name, operation_deadline.min(new_admission_deadline()))
    }

    fn open_private_child_until(
        &self,
        name: &str,
        deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        validate_child_name(name)?;
        self.revalidate_until(deadline)?;
        let child = rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)?;
        let path = self.path.join(name);
        admit_directory_descriptor_until(&path, &child, true, deadline)?;
        self.revalidate_until(deadline)?;
        let metadata = child.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        Ok(Self {
            path,
            directory: child,
            identity: FileIdentity::from_metadata(&metadata),
            private_leaf: true,
        })
    }

    /// Lists at most `maximum_entries` immediate child names and revalidates this root.
    pub fn bounded_child_names(
        &self,
        maximum_entries: usize,
    ) -> Result<Vec<String>, PrivateStorageError> {
        self.bounded_child_names_until(maximum_entries, new_admission_deadline())
    }

    /// Lists bounded child names under the same absolute deadline as a larger operation.
    pub(crate) fn bounded_child_names_for_operation(
        &self,
        maximum_entries: usize,
        operation_deadline: std::time::Instant,
    ) -> Result<Vec<String>, PrivateStorageError> {
        self.bounded_child_names_until(
            maximum_entries,
            operation_deadline.min(new_admission_deadline()),
        )
    }

    fn bounded_child_names_until(
        &self,
        maximum_entries: usize,
        deadline: std::time::Instant,
    ) -> Result<Vec<String>, PrivateStorageError> {
        self.revalidate_until(deadline)?;
        let entries = std::fs::read_dir(&self.path).map_err(|_| PrivateStorageError::Operation)?;
        let mut names = Vec::new();
        for entry in entries {
            if names.len() >= maximum_entries {
                return Err(PrivateStorageError::Unavailable);
            }
            let entry = entry.map_err(|_| PrivateStorageError::Operation)?;
            let name =
                entry.file_name().into_string().map_err(|_| PrivateStorageError::Unavailable)?;
            validate_child_name(&name)?;
            names.push(name);
        }
        self.revalidate_until(deadline)?;
        names.sort_unstable();
        Ok(names)
    }

    /// Removes a validated private regular file by its bounded child name.
    pub fn remove_private_file(&self, name: &str) -> Result<(), PrivateStorageError> {
        let deadline = new_admission_deadline();
        let file = self.open_file_with_link_policy_until(name, false, deadline)?;
        self.validate_file_binding_with_link_policy_until(name, &file, false, false, deadline)?;
        drop(file);
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)
    }

    /// Removes a private file only when its name still identifies the caller's open file.
    pub fn remove_private_file_if_matches(
        &self,
        name: &str,
        expected: &File,
    ) -> Result<(), PrivateStorageError> {
        let deadline = new_admission_deadline();
        let actual = self.open_file_with_link_policy_until(name, false, deadline)?;
        self.validate_file_binding_with_link_policy_until(name, &actual, false, false, deadline)?;
        use std::os::unix::fs::MetadataExt as _;
        let expected_metadata = expected.metadata().map_err(|_| PrivateStorageError::Operation)?;
        let actual_metadata = actual.metadata().map_err(|_| PrivateStorageError::Operation)?;
        if !FileIdentity::from_metadata(&expected_metadata)
            .same_file(FileIdentity::from_metadata(&actual_metadata))
            || expected_metadata.nlink() != actual_metadata.nlink()
        {
            return Err(PrivateStorageError::Unavailable);
        }
        drop(actual);
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)
    }

    /// Removes a file only if its name still identifies the expected descriptor, under one deadline.
    pub(crate) fn remove_private_file_if_matches_for_operation(
        &self,
        name: &str,
        expected: &File,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        use std::os::unix::fs::MetadataExt as _;
        let deadline = operation_deadline.min(new_admission_deadline());
        let actual = self.open_file_with_link_policy_until(name, false, deadline)?;
        self.validate_file_binding_with_link_policy_until(name, &actual, false, false, deadline)?;
        let expected_metadata = expected.metadata().map_err(|_| PrivateStorageError::Operation)?;
        let actual_metadata = actual.metadata().map_err(|_| PrivateStorageError::Operation)?;
        if !FileIdentity::from_metadata(&expected_metadata)
            .same_file(FileIdentity::from_metadata(&actual_metadata))
            || expected_metadata.nlink() != actual_metadata.nlink()
        {
            return Err(PrivateStorageError::Unavailable);
        }
        drop(actual);
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)?;
        self.sync_until(deadline)
    }

    /// Removes a validated private immutable object file that may have hard links.
    pub fn remove_managed_file(&self, name: &str) -> Result<(), PrivateStorageError> {
        let deadline = new_admission_deadline();
        let file = self.open_file_with_link_policy_until(name, true, deadline)?;
        self.validate_file_binding_with_link_policy_until(name, &file, false, true, deadline)?;
        drop(file);
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)
    }

    /// Removes an admitted empty private child directory.
    pub fn remove_private_child(&self, name: &str) -> Result<(), PrivateStorageError> {
        let deadline = new_admission_deadline();
        validate_child_name(name)?;
        let child = self.open_private_child_until(name, deadline)?;
        if !child.bounded_child_names_until(1, deadline)?.is_empty() {
            return Err(PrivateStorageError::Unavailable);
        }
        child.revalidate_until(deadline)?;
        self.revalidate_until(deadline)?;
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)?;
        self.sync_until(deadline)
    }

    /// Removes an empty admitted child using the caller's absolute deadline.
    pub(crate) fn remove_private_child_for_operation(
        &self,
        name: &str,
        expected: &AdmittedPrivateRoot,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        let deadline = operation_deadline.min(new_admission_deadline());
        validate_child_name(name)?;
        let child = self.open_private_child_until(name, deadline)?;
        let expected_metadata =
            expected.directory.metadata().map_err(|_| PrivateStorageError::Operation)?;
        let actual_metadata =
            child.directory.metadata().map_err(|_| PrivateStorageError::Operation)?;
        if !FileIdentity::from_metadata(&expected_metadata)
            .same_directory(FileIdentity::from_metadata(&actual_metadata))
        {
            return Err(PrivateStorageError::Unavailable);
        }
        if !child.bounded_child_names_until(1, deadline)?.is_empty() {
            return Err(PrivateStorageError::Unavailable);
        }
        child.revalidate_until(deadline)?;
        expected.revalidate_until(deadline)?;
        self.revalidate_until(deadline)?;
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(deadline)?;
        self.sync_until(deadline)
    }

    /// Opens a regular no-follow child file after revalidating this directory.
    pub fn open_regular_file(&self, name: &str) -> Result<File, PrivateStorageError> {
        self.open_file_with_link_policy(name, false)
    }

    /// Opens a regular private file within a caller-owned bounded operation.
    pub(crate) fn open_regular_file_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<File, PrivateStorageError> {
        self.open_file_with_link_policy_until(
            name,
            false,
            operation_deadline.min(new_admission_deadline()),
        )
    }

    /// Admits an existing private regular file without keeping or opening a descriptor.
    ///
    /// SQLite takes POSIX advisory locks on its database, `-wal`, and `-shm` files. POSIX
    /// releases *every* lock a process holds on a file when that process closes *any*
    /// descriptor for it, so validating a live database by opening and dropping a second
    /// descriptor silently drops SQLite's locks and lets another process delete the WAL out
    /// from under this one. On Linux this check therefore uses only `statat`; elsewhere it
    /// keeps the descriptor-bound check.
    pub fn validate_regular_file(&self, name: &str) -> Result<(), PrivateStorageError> {
        #[cfg(target_os = "linux")]
        {
            if self.validate_named_file_without_open(name)? {
                Ok(())
            } else {
                Err(PrivateStorageError::Operation)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            if self.validate_named_file_without_open(name)? {
                Ok(())
            } else {
                Err(PrivateStorageError::Operation)
            }
        }
    }

    /// Stat-only admission of an optional private regular file: returns whether it exists.
    /// No descriptor for the file is ever opened (Linux uses `lgetxattr`, macOS `/bin/ls`).
    fn validate_named_file_without_open(&self, name: &str) -> Result<bool, PrivateStorageError> {
        use std::os::unix::fs::MetadataExt as _;

        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        let deadline = new_admission_deadline();
        self.revalidate_until(deadline)?;
        let stat = |directory: &File| {
            rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        };
        let first = match stat(&self.directory) {
            Ok(first) => first,
            Err(error) if error == rustix::io::Errno::NOENT => {
                self.revalidate_until(deadline)?;
                return Ok(false);
            }
            Err(_) => return Err(PrivateStorageError::Unavailable),
        };
        let directory_metadata =
            self.directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let group_other = rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO;
        if rustix::fs::FileType::from_raw_mode(first.st_mode) != rustix::fs::FileType::RegularFile
            || first.st_uid != rustix::process::getuid().as_raw()
            || first.st_nlink != 1
            || rustix::fs::Mode::from_raw_mode(first.st_mode).intersects(group_other)
            || stat_device(&first) != directory_metadata.dev()
        {
            return Err(PrivateStorageError::Unavailable);
        }
        // The identity deliberately omits size: a live database or WAL grows between probes.
        let identity = FileIdentity {
            device: stat_device(&first),
            inode: stat_inode(&first),
            size: 0,
            owner: first.st_uid,
            mode: stat_mode(&first) & 0o7777,
        };
        if !named_file_acl_admits(&self.path.join(name), identity, deadline) {
            return Err(PrivateStorageError::Unavailable);
        }
        self.revalidate_until(deadline)?;
        let second = stat(&self.directory).map_err(|_| PrivateStorageError::Unavailable)?;
        if second.st_dev != first.st_dev
            || second.st_ino != first.st_ino
            || second.st_mode != first.st_mode
            || second.st_uid != first.st_uid
            || second.st_nlink != first.st_nlink
        {
            return Err(PrivateStorageError::Unavailable);
        }
        Ok(true)
    }

    /// Admits an optional private regular file without treating absence as an error.
    pub fn validate_optional_private_file(&self, name: &str) -> Result<bool, PrivateStorageError> {
        // Stat-only: see `validate_regular_file` for why no descriptor may be opened.
        self.validate_named_file_without_open(name)
    }

    /// Opens a private regular file that may intentionally have additional hard links.
    ///
    /// This is reserved for immutable content-addressed objects whose publication
    /// contract uses hard links to deduplicate bytes. The opened descriptor and
    /// named entry are still bound and checked for owner, mode, ACL, and mount.
    pub fn open_managed_file(&self, name: &str) -> Result<File, PrivateStorageError> {
        self.open_file_with_link_policy(name, true)
    }

    fn open_file_with_link_policy(
        &self,
        name: &str,
        allow_hardlinks: bool,
    ) -> Result<File, PrivateStorageError> {
        self.open_file_with_link_policy_until(name, allow_hardlinks, new_admission_deadline())
    }

    fn open_file_with_link_policy_until(
        &self,
        name: &str,
        allow_hardlinks: bool,
        deadline: std::time::Instant,
    ) -> Result<File, PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        if !self.named_regular_file_exists_until(name, deadline)? {
            return Err(PrivateStorageError::Operation);
        }
        let file = self
            .open_nonblocking_read_descriptor(name)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.validate_file_binding_with_link_policy_until(
            name,
            &file,
            false,
            allow_hardlinks,
            deadline,
        )?;
        self.revalidate_until(deadline)?;
        Ok(file)
    }

    fn open_nonblocking_read_descriptor(&self, name: &str) -> Result<File, rustix::io::Errno> {
        rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
    }

    fn named_regular_file_exists_until(
        &self,
        name: &str,
        deadline: std::time::Instant,
    ) -> Result<bool, PrivateStorageError> {
        self.revalidate_until(deadline)?;
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(PrivateStorageError::Unavailable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.revalidate_until(deadline)?;
                Ok(false)
            }
            Err(_) => Err(PrivateStorageError::Unavailable),
        }
    }

    /// Exclusively creates a no-follow owner-only regular file relative to this directory.
    pub fn create_private_file(&self, name: &str) -> Result<File, PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        let deadline = new_admission_deadline();
        self.revalidate_until(deadline)?;
        let file = rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                PrivateStorageError::AlreadyExists
            } else {
                PrivateStorageError::Operation
            }
        })?;
        self.validate_file_binding_with_link_policy_until(name, &file, true, false, deadline)?;
        self.revalidate_until(deadline)?;
        Ok(file)
    }

    /// Exclusively creates a private regular file under a caller-owned deadline.
    pub(crate) fn create_private_file_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<File, PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        let deadline = operation_deadline.min(new_admission_deadline());
        self.revalidate_until(deadline)?;
        let file = rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                PrivateStorageError::AlreadyExists
            } else {
                PrivateStorageError::Operation
            }
        })?;
        self.validate_file_binding_with_link_policy_until(name, &file, true, false, deadline)?;
        self.revalidate_until(deadline)?;
        Ok(file)
    }

    /// Rechecks that a retained descriptor is still the named private file within a larger operation.
    pub(crate) fn validate_file_binding_for_operation(
        &self,
        name: &str,
        file: &File,
        newly_created: bool,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        self.validate_file_binding_with_link_policy_until(
            name,
            file,
            newly_created,
            false,
            operation_deadline.min(new_admission_deadline()),
        )
    }

    /// Syncs the admitted directory within a caller-owned bounded operation.
    pub(crate) fn sync_for_operation(
        &self,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        self.sync_until(operation_deadline.min(new_admission_deadline()))
    }

    /// Opens an existing private regular file or creates it exclusively as `0600`.
    ///
    /// The opened descriptor and current directory entry are validated before
    /// returning. This is intended for the SQLite database bootstrap path;
    /// existing files are never chmod-repaired.
    pub fn open_or_create_private_file(&self, name: &str) -> Result<File, PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        let deadline = new_admission_deadline();
        self.named_regular_file_exists_until(name, deadline)?;
        let opened = rustix::fs::openat(
            &self.directory,
            name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        );
        let (file, created) = match opened {
            Ok(opened) => (File::from(opened), false),
            Err(error) if error == rustix::io::Errno::NOENT => {
                let created = rustix::fs::openat(
                    &self.directory,
                    name,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::EXCL
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::from_raw_mode(0o600),
                )
                .map(File::from)
                .map_err(|_| PrivateStorageError::Unavailable)?;
                (created, true)
            }
            Err(_) => return Err(PrivateStorageError::Unavailable),
        };
        self.validate_file_binding_with_link_policy_until(name, &file, created, false, deadline)?;
        self.revalidate_until(deadline)?;
        Ok(file)
    }

    /// Reads a bounded private file through its validated no-follow descriptor.
    pub fn read_bounded_file(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStorageError> {
        use std::io::Read as _;

        let deadline = new_admission_deadline();
        let file = self.open_file_with_link_policy_until(name, false, deadline)?;
        let metadata = file.metadata().map_err(|_| PrivateStorageError::Operation)?;
        if metadata.len() > maximum_bytes as u64 {
            return Err(PrivateStorageError::Unavailable);
        }
        let mut limited = file
            .try_clone()
            .map_err(|_| PrivateStorageError::Operation)?
            .take(maximum_bytes.saturating_add(1) as u64);
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        limited.read_to_end(&mut bytes).map_err(|_| PrivateStorageError::Operation)?;
        if bytes.len() > maximum_bytes {
            return Err(PrivateStorageError::Unavailable);
        }
        self.validate_file_binding_with_link_policy_until(name, &file, false, false, deadline)?;
        self.revalidate_until(deadline)?;
        Ok(bytes)
    }

    /// Reads a bounded immutable object that may be intentionally hard-linked.
    pub fn read_bounded_managed_file(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStorageError> {
        use std::io::Read as _;

        let deadline = new_admission_deadline();
        let file = self.open_file_with_link_policy_until(name, true, deadline)?;
        let metadata = file.metadata().map_err(|_| PrivateStorageError::Operation)?;
        if metadata.len() > maximum_bytes as u64 {
            return Err(PrivateStorageError::Unavailable);
        }
        let mut limited = file
            .try_clone()
            .map_err(|_| PrivateStorageError::Operation)?
            .take(maximum_bytes.saturating_add(1) as u64);
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        limited.read_to_end(&mut bytes).map_err(|_| PrivateStorageError::Operation)?;
        if bytes.len() > maximum_bytes {
            return Err(PrivateStorageError::Unavailable);
        }
        self.validate_file_binding_with_link_policy_until(name, &file, false, true, deadline)?;
        self.revalidate_until(deadline)?;
        Ok(bytes)
    }

    /// Confirms that an opened file is still the exact private regular file named by this root.
    pub fn validate_file_binding(
        &self,
        name: &str,
        file: &File,
        newly_created: bool,
    ) -> Result<(), PrivateStorageError> {
        self.validate_file_binding_with_link_policy(name, file, newly_created, false)
    }

    /// Validates a private immutable object file that may have intentional hard links.
    pub fn validate_managed_file_binding(
        &self,
        name: &str,
        file: &File,
        newly_created: bool,
    ) -> Result<(), PrivateStorageError> {
        self.validate_file_binding_with_link_policy(name, file, newly_created, true)
    }

    fn validate_file_binding_with_link_policy(
        &self,
        name: &str,
        file: &File,
        newly_created: bool,
        allow_hardlinks: bool,
    ) -> Result<(), PrivateStorageError> {
        self.validate_file_binding_with_link_policy_until(
            name,
            file,
            newly_created,
            allow_hardlinks,
            new_admission_deadline(),
        )
    }

    fn validate_file_binding_with_link_policy_until(
        &self,
        name: &str,
        file: &File,
        newly_created: bool,
        allow_hardlinks: bool,
        deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        self.revalidate_until(deadline)?;
        let descriptor = file.metadata().map_err(|_| PrivateStorageError::Operation)?;
        let named = std::fs::symlink_metadata(self.path.join(name))
            .map_err(|_| PrivateStorageError::Unavailable)?;
        use std::os::unix::fs::MetadataExt as _;
        let descriptor_identity = FileIdentity::from_metadata(&descriptor);
        let named_identity = FileIdentity::from_metadata(&named);
        if named.file_type().is_symlink()
            || !descriptor.is_file()
            || !named.is_file()
            || !descriptor_identity.same_file(named_identity)
            || descriptor.uid() != rustix::process::getuid().as_raw()
            || (!allow_hardlinks && descriptor.nlink() != 1)
            || (allow_hardlinks && descriptor.nlink() == 0)
            || if newly_created {
                descriptor.mode() & 0o777 != 0o600
            } else {
                descriptor.mode() & 0o077 != 0
            }
        {
            return Err(PrivateStorageError::Unavailable);
        }
        if !acl_admits_file(&self.path.join(name), file, descriptor_identity, deadline) {
            return Err(PrivateStorageError::Unavailable);
        }
        let directory_metadata =
            self.directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        if descriptor.dev() != directory_metadata.dev() {
            return Err(PrivateStorageError::Unavailable);
        }
        let filesystem = rustix::fs::fstatfs(file).map_err(|_| PrivateStorageError::Unavailable)?;
        if !owner_enforcing_local_filesystem(&filesystem) {
            return Err(PrivateStorageError::Unavailable);
        }
        self.revalidate_until(deadline)?;
        let named_after = std::fs::symlink_metadata(self.path.join(name))
            .map_err(|_| PrivateStorageError::Unavailable)?;
        let opened_after = file.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        if FileIdentity::from_metadata(&named_after) != descriptor_identity
            || FileIdentity::from_metadata(&opened_after) != descriptor_identity
            || named_after.nlink() != descriptor.nlink()
            || opened_after.nlink() != descriptor.nlink()
            || !acl_admits_file(&self.path.join(name), file, descriptor_identity, deadline)
        {
            return Err(PrivateStorageError::Unavailable);
        }
        Ok(())
    }

    /// Atomically renames two validated names within this private directory and syncs it.
    pub fn rename_replace(&self, source: &str, target: &str) -> Result<(), PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        let deadline = new_admission_deadline();
        validate_child_name(source)?;
        validate_child_name(target)?;
        self.revalidate_until(deadline)?;
        let source_file = self.open_file_with_link_policy_until(source, false, deadline)?;
        self.validate_file_binding_with_link_policy_until(
            source,
            &source_file,
            false,
            false,
            deadline,
        )?;
        match std::fs::symlink_metadata(self.path.join(target)) {
            Ok(_) => {
                let target_file = self.open_file_with_link_policy_until(target, false, deadline)?;
                self.validate_file_binding_with_link_policy_until(
                    target,
                    &target_file,
                    false,
                    false,
                    deadline,
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PrivateStorageError::Unavailable),
        }
        rustix::fs::renameat(&self.directory, source, &self.directory, target)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.validate_file_binding_with_link_policy_until(
            target,
            &source_file,
            false,
            false,
            deadline,
        )?;
        self.revalidate_until(deadline)?;
        self.sync_until(deadline)
    }

    /// Syncs this admitted directory descriptor after a descriptor-relative rename.
    pub fn sync(&self) -> Result<(), PrivateStorageError> {
        self.sync_until(new_admission_deadline())
    }

    fn sync_until(&self, deadline: std::time::Instant) -> Result<(), PrivateStorageError> {
        self.revalidate_until(deadline)?;
        rustix::fs::fsync(&self.directory).map_err(|_| PrivateStorageError::Operation)
    }
}

/// Returns whether `name` is one bounded non-special path component.
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

fn open_directory_descriptor(path: &str) -> Result<File, PrivateStorageError> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| PrivateStorageError::Unavailable)
}

fn open_directory_without_symlinks_until(
    path: &Path,
    deadline: std::time::Instant,
) -> Result<File, PrivateStorageError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(PrivateStorageError::InvalidName);
    }
    let components = path.components().count();
    if components > MAX_PATH_COMPONENTS + 1 || path.as_os_str().len() > 4096 {
        return Err(PrivateStorageError::InvalidName);
    }
    let mut descriptor = open_directory_descriptor("/")?;
    let mut traversed = PathBuf::from("/");
    verify_ancestor_metadata(&traversed, &descriptor, deadline)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name = name.to_str().ok_or(PrivateStorageError::InvalidName)?;
                validate_child_name(name)?;
                let opened = rustix::fs::openat(
                    &descriptor,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(|_| PrivateStorageError::Unavailable)?;
                traversed.push(name);
                descriptor = opened;
                verify_ancestor_metadata(&traversed, &descriptor, deadline)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(PrivateStorageError::InvalidName);
            }
        }
    }
    Ok(descriptor)
}

fn verify_ancestor_metadata(
    path: &Path,
    descriptor: &File,
    deadline: std::time::Instant,
) -> Result<(), PrivateStorageError> {
    use std::os::unix::fs::MetadataExt as _;

    if std::time::Instant::now() >= deadline {
        return Err(PrivateStorageError::Unavailable);
    }
    let named = std::fs::symlink_metadata(path).map_err(|_| PrivateStorageError::Unavailable)?;
    let opened = descriptor.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
    let identity = FileIdentity::from_metadata(&opened);
    if named.file_type().is_symlink()
        || !named.is_dir()
        || !identity.same_directory(FileIdentity::from_metadata(&named))
    {
        return Err(PrivateStorageError::Unavailable);
    }
    let owner = rustix::process::getuid().as_raw();
    if !(opened.uid() == owner || opened.uid() == 0)
        || opened.mode() & 0o022 != 0
        || !rustix::fs::fstatfs(descriptor)
            .is_ok_and(|filesystem| owner_enforcing_local_filesystem(&filesystem))
        || !acl_admits_traversal_directory(path, descriptor, identity, deadline)
    {
        return Err(PrivateStorageError::Unavailable);
    }
    let named_after =
        std::fs::symlink_metadata(path).map_err(|_| PrivateStorageError::Unavailable)?;
    let opened_after = descriptor.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
    if !identity.same_directory(FileIdentity::from_metadata(&named_after))
        || !identity.same_directory(FileIdentity::from_metadata(&opened_after))
    {
        return Err(PrivateStorageError::Unavailable);
    }
    Ok(())
}

fn admit_directory_descriptor_until(
    path: &Path,
    descriptor: &File,
    private_leaf: bool,
    deadline: std::time::Instant,
) -> Result<(), PrivateStorageError> {
    use std::os::unix::fs::MetadataExt as _;

    verify_ancestor_metadata(path, descriptor, deadline)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| PrivateStorageError::Unavailable)?;
    let opened = descriptor.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
    let identity = FileIdentity::from_metadata(&opened);
    if named.file_type().is_symlink()
        || !named.is_dir()
        || !identity.same_directory(FileIdentity::from_metadata(&named))
    {
        return Err(PrivateStorageError::Unavailable);
    }
    let owner = rustix::process::getuid().as_raw();
    if private_leaf {
        if opened.uid() != owner || opened.mode() & 0o7777 != 0o700 {
            return Err(PrivateStorageError::Unavailable);
        }
    } else if !(opened.uid() == owner || opened.uid() == 0) || opened.mode() & 0o022 != 0 {
        return Err(PrivateStorageError::Unavailable);
    }
    let filesystem =
        rustix::fs::fstatfs(descriptor).map_err(|_| PrivateStorageError::Unavailable)?;
    if !owner_enforcing_local_filesystem(&filesystem)
        || !acl_admits_directory(path, descriptor, identity, deadline)
    {
        return Err(PrivateStorageError::Unavailable);
    }
    verify_ancestor_metadata(path, descriptor, deadline)?;
    let named_after =
        std::fs::symlink_metadata(path).map_err(|_| PrivateStorageError::Unavailable)?;
    let opened_after = descriptor.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
    if !identity.same_directory(FileIdentity::from_metadata(&named_after))
        || !identity.same_directory(FileIdentity::from_metadata(&opened_after))
    {
        return Err(PrivateStorageError::Unavailable);
    }
    Ok(())
}

/// ACL policy for a directory that is only traversed on the way to a private root.
///
/// On Linux a traversed directory is admitted when it carries no ACL, or when its access ACL is
/// well formed and grants no write permission to anyone but the owning user; its default ACL only
/// shapes children created later and cannot change who may write into the directory itself.
/// (Stock CI images give `/home` a default ACL.) The private leaf and every managed container
/// still go through the strict `acl_admits_directory` check, which refuses any ACL.
#[cfg(target_os = "linux")]
fn acl_admits_traversal_directory(
    _path: &Path,
    directory: &File,
    _expected: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    linux_directory_admits_traversal(directory)
}

/// Linux traversal ACL policy, shared with the Java attach ancestor walk.
#[cfg(target_os = "linux")]
pub(crate) fn linux_directory_admits_traversal(directory: &File) -> bool {
    let mut value = vec![0_u8; 16 * 1024];
    match rustix::fs::fgetxattr(directory, "system.posix_acl_access", value.as_mut_slice()) {
        Ok(length) => {
            if !linux_access_acl_grants_no_foreign_write(value.get(..length).unwrap_or(&[])) {
                return false;
            }
        }
        Err(error) if error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA => {}
        Err(_) => return false,
    }
    match rustix::fs::fgetxattr(directory, "system.posix_acl_default", value.as_mut_slice()) {
        Ok(length) => linux_default_acl_is_well_formed(value.get(..length).unwrap_or(&[])),
        Err(error) => error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA,
    }
}

#[cfg(not(target_os = "linux"))]
fn acl_admits_traversal_directory(
    path: &Path,
    directory: &File,
    expected: FileIdentity,
    deadline: std::time::Instant,
) -> bool {
    acl_admits_directory(path, directory, expected, deadline)
}

/// Parses a Linux `system.posix_acl_*` xattr (version 2, 8-byte entries) into `(tag, perm)`
/// pairs; `None` for anything malformed, so unknown shapes stay refused.
#[cfg(any(target_os = "linux", test))]
fn parse_linux_acl(bytes: &[u8]) -> Option<Vec<(u16, u16)>> {
    const VERSION: u32 = 2;
    const UNDEFINED_ID: u32 = u32::MAX;
    const MAX_ENTRIES: usize = 64;
    let (header, body) = bytes.split_at_checked(4)?;
    if u32::from_le_bytes(header.try_into().ok()?) != VERSION
        || body.len() % 8 != 0
        || body.len() / 8 > MAX_ENTRIES
    {
        return None;
    }
    let mut entries = Vec::new();
    for entry in body.chunks_exact(8) {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let perm = u16::from_le_bytes([entry[2], entry[3]]);
        let id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let named = matches!(tag, 0x02 | 0x08);
        let unnamed = matches!(tag, 0x01 | 0x04 | 0x10 | 0x20);
        if perm > 7 || !(named || unnamed) || (unnamed && id != UNDEFINED_ID) {
            return None;
        }
        entries.push((tag, perm));
    }
    Some(entries)
}

#[cfg(any(target_os = "linux", test))]
fn linux_access_acl_grants_no_foreign_write(bytes: &[u8]) -> bool {
    const USER_OBJ: u16 = 0x01;
    const WRITE: u16 = 0x02;
    parse_linux_acl(bytes).is_some_and(|entries| {
        entries.iter().any(|(tag, _)| *tag == USER_OBJ)
            && entries.iter().all(|(tag, perm)| *tag == USER_OBJ || perm & WRITE == 0)
    })
}

#[cfg(any(target_os = "linux", test))]
fn linux_default_acl_is_well_formed(bytes: &[u8]) -> bool {
    parse_linux_acl(bytes).is_some()
}

/// Device number of a `statat` result, widened exactly as `Metadata::dev` widens it
/// (macOS reports a signed 32-bit device).
#[allow(clippy::unnecessary_cast, clippy::cast_sign_loss, reason = "st_dev width differs by OS")]
fn stat_device(stat: &rustix::fs::Stat) -> u64 {
    stat.st_dev as u64
}

#[allow(clippy::unnecessary_cast, reason = "st_ino width differs by OS")]
fn stat_inode(stat: &rustix::fs::Stat) -> u64 {
    stat.st_ino as u64
}

#[allow(clippy::unnecessary_cast, reason = "st_mode is u16 on macOS and u32 on Linux")]
fn stat_mode(stat: &rustix::fs::Stat) -> u32 {
    stat.st_mode as u32
}

/// Descriptor-free ACL admission of a named regular file.
#[cfg(target_os = "linux")]
fn named_file_acl_admits(
    path: &Path,
    _identity: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    let mut value = [0_u8; 16 * 1024];
    match rustix::fs::lgetxattr(path, "system.posix_acl_access", value.as_mut_slice()) {
        Ok(_) => false,
        Err(error) => error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA,
    }
}

#[cfg(target_os = "macos")]
fn named_file_acl_admits(
    path: &Path,
    identity: FileIdentity,
    deadline: std::time::Instant,
) -> bool {
    if !macos_file_acl_listing_admits(path, deadline) {
        return false;
    }
    // Same inode, owner and mode; size is excluded because live SQLite files grow.
    std::fs::symlink_metadata(path)
        .is_ok_and(|named| identity.same_directory(FileIdentity::from_metadata(&named)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn named_file_acl_admits(
    _path: &Path,
    _identity: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn acl_admits_directory(
    _path: &Path,
    directory: &File,
    _expected: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    fn absent(error: rustix::io::Errno) -> bool {
        error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA
    }
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = [0_u8; 16 * 1024];
        match rustix::fs::fgetxattr(directory, name, value.as_mut_slice()) {
            Ok(_) => return false,
            Err(error) if absent(error) => {}
            Err(_) => return false,
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn acl_admits_file(
    _path: &Path,
    file: &File,
    _expected: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    let mut value = [0_u8; 16 * 1024];
    match rustix::fs::fgetxattr(file, "system.posix_acl_access", value.as_mut_slice()) {
        Ok(_) => false,
        Err(error) => error == rustix::io::Errno::NOENT || error == rustix::io::Errno::NODATA,
    }
}

#[cfg(target_os = "macos")]
fn acl_admits_directory(
    path: &Path,
    directory: &File,
    expected: FileIdentity,
    deadline: std::time::Instant,
) -> bool {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    if Instant::now() >= deadline
        || path.as_os_str().to_string_lossy().chars().any(char::is_control)
    {
        return false;
    }
    let Ok(mut child) = Command::new("/bin/ls")
        .args(["-ldeO"])
        .arg(path)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let Some(mut stdout) = child.stdout.take() else {
        report_acl_probe_cleanup(stop_acl_probe(&mut child, probe_cleanup_deadline(deadline)));
        return false;
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.by_ref().take(16_385).read_to_end(&mut bytes);
        if sender.send((result.is_ok() && bytes.len() <= 16_384, bytes)).is_err() {
            return;
        }
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
        return false;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let Ok((bounded, bytes)) = receiver.recv_timeout(remaining) else {
        tracing::warn!("private storage ACL reader drain is unconfirmed");
        return false;
    };
    if reader.join().is_err() || !status.is_some_and(|value| value.success()) || !bounded {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else { return false };
    let Some(expected_path) = path.to_str() else { return false };
    if !parse_macos_acl_listing(text, expected_path) {
        return false;
    }
    let Ok(named) = std::fs::symlink_metadata(path) else { return false };
    let Ok(opened) = directory.metadata() else { return false };
    expected.same_directory(FileIdentity::from_metadata(&named))
        && expected.same_directory(FileIdentity::from_metadata(&opened))
}

#[cfg(target_os = "macos")]
fn acl_admits_file(
    path: &Path,
    file: &File,
    expected: FileIdentity,
    deadline: std::time::Instant,
) -> bool {
    if !macos_file_acl_listing_admits(path, deadline) {
        return false;
    }
    let Ok(named) = std::fs::symlink_metadata(path) else { return false };
    let Ok(opened) = file.metadata() else { return false };
    expected.same_file(FileIdentity::from_metadata(&named))
        && expected.same_file(FileIdentity::from_metadata(&opened))
}

/// Path-based macOS ACL probe for a regular file (`/bin/ls -ldeO`); never opens the file.
#[cfg(target_os = "macos")]
fn macos_file_acl_listing_admits(path: &Path, deadline: std::time::Instant) -> bool {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    if Instant::now() >= deadline
        || path.as_os_str().to_string_lossy().chars().any(char::is_control)
    {
        return false;
    }
    let Ok(mut child) = Command::new("/bin/ls")
        .args(["-ldeO"])
        .arg(path)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let Some(mut stdout) = child.stdout.take() else {
        report_acl_probe_cleanup(stop_acl_probe(&mut child, probe_cleanup_deadline(deadline)));
        return false;
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.by_ref().take(16_385).read_to_end(&mut bytes);
        if sender.send((result.is_ok() && bytes.len() <= 16_384, bytes)).is_err() {
            return;
        }
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
        return false;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let Ok((bounded, bytes)) = receiver.recv_timeout(remaining) else {
        tracing::warn!("private storage ACL reader drain is unconfirmed");
        return false;
    };
    if reader.join().is_err() || !status.is_some_and(|value| value.success()) || !bounded {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else { return false };
    let Some(expected_path) = path.to_str() else { return false };
    parse_macos_acl_listing_kind(text, expected_path, b'-')
}

/// Requests termination of the owned ACL probe and confirms reaping within a
/// short bounded cleanup window. Failure remains a closed admission result.
#[cfg(target_os = "macos")]
fn stop_acl_probe(child: &mut std::process::Child, deadline: std::time::Instant) -> bool {
    use std::thread;
    use std::time::Instant;

    if let Err(error) = child.kill() {
        if error.kind() != std::io::ErrorKind::InvalidInput {
            return false;
        }
    }
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(std::time::Duration::from_millis(5)),
            ),
            _ => return false,
        }
    }
}

#[cfg(target_os = "macos")]
fn probe_cleanup_deadline(admission_deadline: std::time::Instant) -> std::time::Instant {
    admission_deadline + ACL_PROBE_CLEANUP_BUDGET
}

#[cfg(target_os = "macos")]
fn report_acl_probe_cleanup(drained: bool) {
    if !drained {
        tracing::warn!("private storage ACL probe drain is unconfirmed");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn acl_admits_directory(
    _path: &Path,
    _directory: &File,
    _expected: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn acl_admits_file(
    _path: &Path,
    _file: &File,
    _expected: FileIdentity,
    _deadline: std::time::Instant,
) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn owner_enforcing_local_filesystem(stats: &rustix::fs::StatFs) -> bool {
    const MNT_IGNORE_OWNERSHIP: u32 = 0x0020_0000;
    if stats.f_flags & MNT_IGNORE_OWNERSHIP != 0 {
        return false;
    }
    let name = stats
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    matches!(name.as_slice(), b"apfs" | b"hfs")
}

#[cfg(target_os = "linux")]
fn owner_enforcing_local_filesystem(stats: &rustix::fs::StatFs) -> bool {
    matches!(stats.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn owner_enforcing_local_filesystem(_stats: &rustix::fs::StatFs) -> bool {
    false
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_acl_listing(text: &str, expected_path: &str) -> bool {
    parse_macos_acl_listing_kind(text, expected_path, b'd')
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_acl_listing_kind(text: &str, expected_path: &str, kind: u8) -> bool {
    if text.contains('\r') || !text.is_ascii() || !text.ends_with('\n') {
        return false;
    }
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return false };
    let Some(prefix) = header.strip_suffix(expected_path) else { return false };
    let Some(prefix) = prefix.strip_suffix(' ') else { return false };
    let fields = prefix.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 9
        || fields[1].parse::<u64>().is_err()
        || !valid_owner_name(fields[2])
        || !valid_owner_name(fields[3])
        || !valid_macos_flags(fields[4])
        || fields[5].parse::<u64>().is_err()
        || !matches!(
            fields[6],
            "Jan"
                | "Feb"
                | "Mar"
                | "Apr"
                | "May"
                | "Jun"
                | "Jul"
                | "Aug"
                | "Sep"
                | "Oct"
                | "Nov"
                | "Dec"
        )
        || fields[7].is_empty()
        || fields[7].len() > 2
        || !fields[7].bytes().all(|byte| byte.is_ascii_digit())
        || !(fields[8].contains(':') || fields[8].bytes().all(|byte| byte.is_ascii_digit()))
        || (fields[8].contains(':') && fields[8].len() != 5)
        || (!fields[8].contains(':') && fields[8].len() != 4)
    {
        return false;
    }
    let mode = fields[0].as_bytes();
    if mode.len() < 10 || mode[0] != kind || !valid_posix_mode(&mode[1..10]) {
        return false;
    }
    let suffix = &mode[10..];
    if !(suffix.is_empty() || suffix == b"+" || suffix == b"@" || suffix == b"+@") {
        return false;
    }
    let acl_required = suffix.contains(&b'+');
    let mut saw_acl = false;
    let mut expected_index = 0_u32;
    for line in lines {
        let Some((index, body)) = line.trim().split_once(':') else { return false };
        let Ok(index) = index.parse::<u32>() else { return false };
        if index != expected_index {
            return false;
        }
        let Some(next) = expected_index.checked_add(1) else { return false };
        expected_index = next;
        let words = body.split_ascii_whitespace().collect::<Vec<_>>();
        if words.len() < 3 || !valid_acl_principal(words[0]) {
            return false;
        }
        let effects = words
            .iter()
            .enumerate()
            .filter(|(_, word)| matches!(**word, "allow" | "deny"))
            .collect::<Vec<_>>();
        if effects.len() != 1 {
            return false;
        }
        let (effect_index, effect) = effects[0];
        if *effect != "deny" || effect_index == 0 || effect_index + 1 >= words.len() {
            return false;
        }
        if words[1..effect_index].iter().any(|word| {
            !matches!(
                *word,
                "inherited"
                    | "file_inherit"
                    | "directory_inherit"
                    | "limit_inherit"
                    | "only_inherit"
                    | "no_propagate"
            )
        }) {
            return false;
        }
        let rights = words[effect_index + 1..].join("");
        let parsed = rights.split(',').collect::<Vec<_>>();
        const RIGHTS: &[&str] = &[
            "read",
            "write",
            "append",
            "delete",
            "execute",
            "readattr",
            "writeattr",
            "readextattr",
            "writeextattr",
            "readsecurity",
            "writesecurity",
            "chown",
        ];
        if parsed.is_empty()
            || parsed.iter().any(|right| right.is_empty() || !RIGHTS.contains(right))
        {
            return false;
        }
        saw_acl = true;
    }
    (!acl_required || saw_acl) && (!saw_acl || suffix.contains(&b'@') || acl_required)
}

#[cfg(any(target_os = "macos", test))]
fn valid_owner_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

#[cfg(any(target_os = "macos", test))]
fn valid_acl_principal(value: &str) -> bool {
    let Some((kind, name)) = value.split_once(':') else { return false };
    matches!(kind, "user" | "group")
        && !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'$'))
}

#[cfg(any(target_os = "macos", test))]
/// `ls -O` file flags admitted on a directory: `sunlnk` (sticky-like unlink restriction) and
/// `restricted` (SIP) only narrow what can be changed, and `hidden` (UF_HIDDEN) is a Finder
/// visibility bit (e.g. `/Volumes`) that changes neither ownership nor access. Anything else
/// (`opaque`, `uchg`, `dataless`, ...) stays refused so unknown semantics fail closed.
fn valid_macos_flags(flags: &str) -> bool {
    if flags == "-" {
        return true;
    }
    let mut seen = std::collections::BTreeSet::new();
    flags
        .split(',')
        .all(|flag| matches!(flag, "sunlnk" | "restricted" | "hidden") && seen.insert(flag))
}

#[cfg(any(target_os = "macos", test))]
fn valid_posix_mode(mode: &[u8]) -> bool {
    const PERMISSIONS: [&[u8]; 9] =
        [b"r-", b"w-", b"xSs-", b"r-", b"w-", b"xSs-", b"r-", b"w-", b"xTt-"];
    mode.len() == PERMISSIONS.len()
        && mode.iter().zip(PERMISSIONS).all(|(actual, allowed)| allowed.contains(actual))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests assert on fixture setup")]
mod tests {
    use super::*;

    fn private_scratch() -> AdmittedPrivateRoot {
        let path = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        AdmittedPrivateRoot::open(&path).expect("admitted private test scratch")
    }

    fn unique_name(stem: &str) -> String {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        format!("{stem}-{}-{time}", std::process::id())
    }

    /// True while `/proc/locks` lists a POSIX lock held by this process on `inode`.
    #[cfg(target_os = "linux")]
    fn posix_lock_held(inode: u64) -> bool {
        let pid = std::process::id().to_string();
        let suffix = format!(":{inode} ");
        std::fs::read_to_string("/proc/locks").expect("read /proc/locks").lines().any(|line| {
            line.contains("POSIX")
                && line.contains(&suffix)
                && line.split_whitespace().any(|w| w == pid)
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_validation_opens_no_descriptor_and_keeps_posix_locks() {
        use std::os::unix::fs::MetadataExt as _;

        let scratch = private_scratch();
        let name = unique_name("lock");
        let child = scratch.create_private_child(&name).expect("create child");
        let file = child.create_private_file("live.db").expect("create file");
        rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("take POSIX lock");
        let inode = file.metadata().expect("metadata").ino();
        assert!(posix_lock_held(inode));
        // Control: POSIX semantics drop the lock when ANY descriptor for the file is closed, so the
        // probe above can see an open-and-drop validation.
        drop(std::fs::File::open(child.path().join("live.db")).expect("control open"));
        assert!(!posix_lock_held(inode), "control: closing a second descriptor releases the lock");
        rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("retake POSIX lock");
        assert!(posix_lock_held(inode));
        child.validate_regular_file("live.db").expect("validate regular file");
        assert_eq!(child.validate_optional_private_file("live.db"), Ok(true));
        assert_eq!(child.validate_optional_private_file("absent.db"), Ok(false));
        assert!(posix_lock_held(inode), "validation must not open or close a descriptor");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_validation_still_refuses_unsafe_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch = private_scratch();
        let name = unique_name("unsafe");
        let child = scratch.create_private_child(&name).expect("create child");
        child.create_private_file("ok").expect("create");
        let make = |file: &str, mode: u32| {
            let path = child.path().join(file);
            std::fs::write(&path, b"x").expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        };
        make("group-readable", 0o640);
        make("world-writable", 0o606);
        std::fs::hard_link(child.path().join("ok"), child.path().join("linked")).expect("link");
        std::os::unix::fs::symlink("ok", child.path().join("symlink")).expect("symlink");
        std::fs::create_dir(child.path().join("dir")).expect("dir");
        for bad in ["group-readable", "world-writable", "linked", "symlink", "dir"] {
            assert!(child.validate_regular_file(bad).is_err(), "{bad}");
            assert!(child.validate_optional_private_file(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn traversal_acl_parser_admits_read_only_acls_and_refuses_foreign_write() {
        fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
            let mut out = 2_u32.to_le_bytes().to_vec();
            for (tag, perm, id) in entries {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&perm.to_le_bytes());
                out.extend_from_slice(&id.to_le_bytes());
            }
            out
        }
        const NONE: u32 = u32::MAX;
        let base = [(1, 7, NONE), (4, 5, NONE), (32, 5, NONE)];
        assert!(linux_access_acl_grants_no_foreign_write(&acl(&base)));
        let read_only_named =
            [(1, 7, NONE), (2, 5, 1000), (4, 5, NONE), (16, 5, NONE), (32, 5, NONE)];
        assert!(linux_access_acl_grants_no_foreign_write(&acl(&read_only_named)));
        let writable_named_user =
            [(1, 7, NONE), (2, 7, 1000), (4, 5, NONE), (16, 7, NONE), (32, 5, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_named_user)));
        let writable_named_group =
            [(1, 7, NONE), (4, 5, NONE), (8, 2, 7), (16, 7, NONE), (32, 5, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_named_group)));
        let writable_other = [(1, 7, NONE), (4, 5, NONE), (32, 2, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_other)));
        let writable_group_owner = [(1, 7, NONE), (4, 7, NONE), (32, 5, NONE)];
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&writable_group_owner)));
        assert!(!linux_access_acl_grants_no_foreign_write(&[]));
        assert!(!linux_access_acl_grants_no_foreign_write(&[2, 0, 0, 0, 1, 0]));
        let mut wrong_version = acl(&base);
        wrong_version[0] = 3;
        assert!(!linux_access_acl_grants_no_foreign_write(&wrong_version));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(0x40, 5, NONE)])));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(1, 8, NONE)])));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(1, 7, 5)])));
        assert!(!linux_access_acl_grants_no_foreign_write(&acl(&[(2, 4, 5)])));
        assert!(linux_default_acl_is_well_formed(&acl(&base)));
        assert!(linux_default_acl_is_well_formed(&acl(&[])));
        assert!(!linux_default_acl_is_well_formed(&[1, 2, 3]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_directory_acls_are_judged_by_traversal_and_strict_policy() {
        fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
            let mut out = 2_u32.to_le_bytes().to_vec();
            for (tag, perm, id) in entries {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&perm.to_le_bytes());
                out.extend_from_slice(&id.to_le_bytes());
            }
            out
        }
        const NONE: u32 = u32::MAX;
        let scratch = private_scratch();
        let name = unique_name("acl");
        let child = scratch.create_private_child(&name).expect("create child");
        let directory = open_directory_descriptor(child.path().to_str().expect("utf-8 path"))
            .expect("open child");
        let identity = FileIdentity::from_metadata(&directory.metadata().expect("metadata"));
        let deadline = new_admission_deadline();
        let admits_traversal =
            || acl_admits_traversal_directory(child.path(), &directory, identity, deadline);
        let admits_strict = || acl_admits_directory(child.path(), &directory, identity, deadline);
        assert!(admits_traversal() && admits_strict());
        let set = |attr: &str, value: &[u8]| {
            rustix::fs::fsetxattr(&directory, attr, value, rustix::fs::XattrFlags::empty())
        };
        // Default ACL (what stock CI images put on /home): traversal admits, strict refuses.
        let default_result =
            set("system.posix_acl_default", &acl(&[(1, 7, NONE), (4, 5, NONE), (32, 5, NONE)]));
        if default_result == Err(rustix::io::Errno::OPNOTSUPP) {
            return;
        }
        default_result.expect("set default acl");
        assert!(admits_traversal());
        assert!(!admits_strict());
        // A named user with write is refused by both.
        set(
            "system.posix_acl_access",
            &acl(&[(1, 7, NONE), (2, 7, 12345), (4, 5, NONE), (16, 7, NONE), (32, 0, NONE)]),
        )
        .expect("set writable access acl");
        assert!(!admits_traversal());
        assert!(!admits_strict());
        // A named user with read only: traversal admits, strict refuses.
        set(
            "system.posix_acl_access",
            &acl(&[(1, 7, NONE), (2, 5, 12345), (4, 5, NONE), (16, 5, NONE), (32, 0, NONE)]),
        )
        .expect("set read-only access acl");
        assert!(admits_traversal());
        assert!(!admits_strict());
    }

    #[test]
    fn rejects_path_syntax_as_a_child_name() {
        for name in ["", ".", "..", "a/b", "a\0b", "a\nb"] {
            assert_eq!(validate_child_name(name), Err(PrivateStorageError::InvalidName));
        }
        assert_eq!(validate_child_name("metadata.sqlite3"), Ok(()));
    }

    #[test]
    fn parses_real_macos_directory_headers_and_deny_only_acl() {
        let root = "drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n";
        assert!(parse_macos_acl_listing(root, "/"));

        let home = concat!(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "0: group:everyone deny delete\n",
        );
        assert!(parse_macos_acl_listing(home, "/Users/alice/Documents"));

        let restricted = "drwxr-xr-x 6 root wheel restricted 192 Feb 25 2026 /System\n";
        assert!(parse_macos_acl_listing(restricted, "/System"));
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x 6 root wheel unknown 192 Feb 25 2026 /System\n",
            "/System",
        ));
        assert!(parse_macos_acl_listing(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "/Users/alice/Documents",
        ));
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x+ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "/Users/alice/Documents",
        ));
    }

    #[test]
    fn macos_flags_admit_hidden_volumes_and_refuse_unknown_flags() {
        let listing =
            |flags: &str| format!("drwxr-xr-x 7 root wheel {flags} 224 Oct 8 01:32 /Volumes\n");
        for ok in ["hidden", "hidden,sunlnk", "sunlnk,hidden", "hidden,restricted", "-"] {
            assert!(parse_macos_acl_listing(&listing(ok), "/Volumes"), "{ok}");
        }
        for bad in [
            "uchg",
            "opaque",
            "hidden,uchg",
            "hidden,hidden",
            "hidden,",
            ",hidden",
            "Hidden",
            "dataless",
            "schg",
            "nodump",
        ] {
            assert!(!parse_macos_acl_listing(&listing(bad), "/Volumes"), "{bad}");
        }
        // hidden never excuses an ACL entry (write bits are enforced from st_mode, not this parser).
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x+ 7 root wheel hidden 224 Oct 8 01:32 /Volumes\n0: user:evil allow write\n",
            "/Volumes",
        ));
    }

    #[test]
    fn parser_rejects_acl_allow_and_malformed_headers() {
        let allow = concat!(
            "drwxr-xr-x@ 4 alice staff - 128 Oct 4 00:23 /Users/alice/Documents\n",
            "0: group:everyone allow delete\n",
        );
        assert!(!parse_macos_acl_listing(allow, "/Users/alice/Documents"));
        assert!(!parse_macos_acl_listing(
            "extra drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n",
            "/",
        ));
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

    #[test]
    fn unsupported_container_capability_cannot_create_private_files() {
        let path = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        let container =
            AdmittedPrivateRoot::open_container(&path).expect("admitted traversable container");
        let name = unique_name("private-storage-denied");
        let target = path.join(&name);
        assert!(!target.exists(), "test canary must start absent");
        let error = container
            .create_private_file(&name)
            .expect_err("container is not a file-creation capability");
        assert_eq!(error, PrivateStorageError::Unavailable);
        assert!(!target.exists(), "denied capability must not create a file");
    }

    #[test]
    fn controlled_child_creation_does_not_invalidate_parent_identity() {
        let root = private_scratch();
        let name = unique_name("private-storage-child");
        let child = root.create_private_child(&name).expect("private child");
        root.revalidate().expect("directory link-count growth is controlled");
        child.revalidate().expect("child remains bound");
        drop(child);
        root.remove_private_child(&name).expect("remove empty private child");
        root.revalidate().expect("parent remains admitted after removal");
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_replacement_with_symlink_invalidates_existing_capability() {
        use std::os::unix::fs::symlink;

        let scratch = private_scratch();
        let name = unique_name("private-storage-ancestor");
        let moved_name = unique_name("private-storage-moved");
        let ancestor = scratch.create_private_child(&name).expect("private ancestor");
        let child = ancestor.create_private_child("leaf").expect("private leaf");
        let moved_path = scratch.path().join(&moved_name);
        std::fs::rename(ancestor.path(), &moved_path).expect("move admitted ancestor");
        symlink(&moved_path, ancestor.path()).expect("replace ancestor with symlink");

        assert_eq!(child.revalidate(), Err(PrivateStorageError::Unavailable));

        std::fs::remove_file(ancestor.path()).expect("remove symlink canary");
        let moved = scratch.open_private_child(&moved_name).expect("reopen moved ancestor");
        moved.remove_private_child("leaf").expect("remove private leaf");
        scratch.remove_private_child(&moved_name).expect("remove moved ancestor");
    }

    #[test]
    fn unsafe_existing_file_is_rejected_without_permission_repair() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = private_scratch();
        let name = unique_name("private-storage-mode-canary");
        let path = root.path().join(&name);
        std::fs::write(&path, b"unchanged-canary").expect("private fixture file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("unsafe fixture mode");
        let error = root
            .open_or_create_private_file(&name)
            .expect_err("existing loose file must fail closed");
        assert_eq!(error, PrivateStorageError::Unavailable);
        assert_eq!(std::fs::read(&path).expect("canary remains"), b"unchanged-canary");
        assert_eq!(
            std::fs::metadata(&path).expect("mode metadata").permissions().mode() & 0o777,
            0o644,
            "unsafe metadata must not be chmod-repaired"
        );
        std::fs::remove_file(&path).expect("remove deliberately unsafe canary");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn file_openers_reject_fifo_without_waiting_for_a_peer() {
        use std::os::unix::fs::FileTypeExt as _;
        use std::sync::mpsc;
        use std::time::Duration;

        let root = private_scratch();
        let name = unique_name("private-storage-fifo");
        #[cfg(target_os = "linux")]
        rustix::fs::mkfifoat(&root.directory, &name, rustix::fs::Mode::from_raw_mode(0o600))
            .expect("create FIFO fixture in admitted scratch");
        #[cfg(target_os = "macos")]
        {
            let fifo_path = root.path().join(&name);
            let status = std::process::Command::new("/usr/bin/mkfifo")
                .arg(&fifo_path)
                .status()
                .expect("create FIFO fixture with the macOS system utility");
            assert!(status.success(), "create FIFO fixture in admitted scratch");
        }

        let worker_root_path = root.path().to_path_buf();
        let worker_name = name.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let root = AdmittedPrivateRoot::open(&worker_root_path)
                .expect("reopen admitted scratch in fixture worker");
            let raced_descriptor = root
                .open_nonblocking_read_descriptor(&worker_name)
                .expect("opening a raced FIFO must return without a peer");
            let descriptor_is_fifo = raced_descriptor
                .metadata()
                .expect("FIFO descriptor metadata")
                .file_type()
                .is_fifo();
            drop(raced_descriptor);
            let outcomes = [
                root.open_regular_file(&worker_name).is_err(),
                root.open_managed_file(&worker_name).is_err(),
                root.read_bounded_file(&worker_name, 8).is_err(),
                root.read_bounded_managed_file(&worker_name, 8).is_err(),
                root.validate_optional_private_file(&worker_name).is_err(),
                root.open_or_create_private_file(&worker_name).is_err(),
            ];
            sender.send((descriptor_is_fifo, outcomes)).expect("deliver FIFO fixture outcomes");
        });
        let (descriptor_is_fifo, outcomes) = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("FIFO validation must not block waiting for a reader or writer");
        worker.join().expect("FIFO fixture worker must finish before cleanup");
        assert!(descriptor_is_fifo, "the race fixture must reach the descriptor-level opener");
        assert!(outcomes.into_iter().all(|opened| opened));
        #[cfg(target_os = "linux")]
        rustix::fs::unlinkat(&root.directory, &name, rustix::fs::AtFlags::empty())
            .expect("remove FIFO fixture");
        #[cfg(target_os = "macos")]
        std::fs::remove_file(root.path().join(&name)).expect("remove FIFO fixture");
    }
}
