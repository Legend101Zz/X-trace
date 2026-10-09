//! Owner-enforced private directory capabilities for local X-trace state.
//!
//! Paths are used only to locate a directory. Callers retain this non-cloneable
//! descriptor-backed capability and revalidate it before each independent
//! operation that may read or write private state.

use std::fs::File;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::policy::{self, DirectoryRole, FilesystemProfile};
use crate::probe::{self, Operation};

const MAX_PATH_COMPONENTS: usize = 128;

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
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    owner: u32,
    mode: u32,
}

impl FileIdentity {
    pub(crate) fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
        }
    }

    pub(crate) fn same_directory(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.owner == other.owner
            && self.mode == other.mode
    }

    pub(crate) fn same_file(self, other: Self) -> bool {
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
    profile: FilesystemProfile,
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
        Self::validate_open_directory_with_profile(
            path,
            directory,
            private_leaf,
            FilesystemProfile::Durable,
        )
    }

    /// [`Self::validate_open_directory`] under an explicit filesystem profile.
    pub fn validate_open_directory_with_profile(
        path: &Path,
        directory: &File,
        private_leaf: bool,
        profile: FilesystemProfile,
    ) -> Result<(), PrivateStorageError> {
        let op = &Operation::new().with_profile(profile);
        let walked = open_directory_without_symlinks_until(path, op)?;
        let supplied = directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let walked_metadata = walked.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let supplied_identity = FileIdentity::from_metadata(&supplied);
        if !supplied_identity.same_directory(FileIdentity::from_metadata(&walked_metadata)) {
            return Err(PrivateStorageError::Unavailable);
        }
        admit_directory_descriptor_until(path, directory, role_of(private_leaf), op)
    }

    /// Opens and admits an existing exact-owner `0700` directory.
    pub fn open(path: &Path) -> Result<Self, PrivateStorageError> {
        Self::open_with_mode(path, true, FilesystemProfile::Durable)
    }

    /// [`Self::open`] under an explicit filesystem profile; children inherit the profile.
    pub fn open_with_profile(
        path: &Path,
        profile: FilesystemProfile,
    ) -> Result<Self, PrivateStorageError> {
        Self::open_with_mode(path, true, profile)
    }

    /// Opens an existing container that is safe for traversal but not necessarily private.
    ///
    /// This is for an already-existing ancestor only; it must not be used as
    /// authorization to create private files directly inside that ancestor.
    pub fn open_container(path: &Path) -> Result<Self, PrivateStorageError> {
        Self::open_with_mode(path, false, FilesystemProfile::Durable)
    }

    /// [`Self::open_container`] under an explicit filesystem profile; children inherit it.
    pub fn open_container_with_profile(
        path: &Path,
        profile: FilesystemProfile,
    ) -> Result<Self, PrivateStorageError> {
        Self::open_with_mode(path, false, profile)
    }

    /// Creates missing path components with owner-only permissions and admits the final leaf.
    ///
    /// Existing ancestors are opened without following links and checked before
    /// a missing child is created. No existing directory is chmod-repaired.
    pub fn open_or_create(path: &Path) -> Result<Self, PrivateStorageError> {
        use std::path::Component;

        let profile = FilesystemProfile::Durable;
        let op = &Operation::new().with_profile(profile);
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
        let mut current = Self::from_admitted_descriptor_until(
            PathBuf::from("/"),
            descriptor,
            false,
            profile,
            op,
        )?;
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
                        profile,
                        op,
                    )?;
                }
                Err(error) if error == rustix::io::Errno::NOENT => {
                    current = current.create_private_child_until(name, op)?;
                }
                Err(_) => return Err(PrivateStorageError::Unavailable),
            }
        }
        current.revalidate_until(op)?;
        Ok(current)
    }

    fn from_admitted_descriptor_until(
        path: PathBuf,
        directory: File,
        private_leaf: bool,
        profile: FilesystemProfile,
        op: &Operation,
    ) -> Result<Self, PrivateStorageError> {
        admit_directory_descriptor_until(&path, &directory, role_of(private_leaf), op)?;
        let metadata = directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        Ok(Self {
            path,
            directory,
            identity: FileIdentity::from_metadata(&metadata),
            private_leaf,
            profile,
        })
    }

    /// A fresh admission operation judging filesystems under this capability's profile.
    fn operation(&self) -> Operation {
        Operation::new().with_profile(self.profile)
    }

    /// [`Self::operation`] inside a caller's larger deadline.
    fn operation_capped(&self, operation_deadline: std::time::Instant) -> Operation {
        Operation::capped(operation_deadline).with_profile(self.profile)
    }

    fn open_with_mode(
        path: &Path,
        private_leaf: bool,
        profile: FilesystemProfile,
    ) -> Result<Self, PrivateStorageError> {
        let op = &Operation::new().with_profile(profile);
        let directory = open_directory_without_symlinks_until(path, op)?;
        admit_directory_descriptor_until(path, &directory, role_of(private_leaf), op)?;
        let metadata = directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let identity = FileIdentity::from_metadata(&metadata);
        Ok(Self { path: path.to_path_buf(), directory, identity, private_leaf, profile })
    }

    /// Revalidates the opened descriptor, its current name, ACL, owner, mode, and filesystem.
    pub fn revalidate(&self) -> Result<(), PrivateStorageError> {
        self.revalidate_until(&self.operation())
    }

    // The ten `*_for_operation` methods below are public because `xtrace-runtime`'s pack
    // snapshot code (`pack_inventory`) calls every one of them: it runs a long multi-step
    // operation (copy a pack tree, then verify and clean it) under ONE caller-owned deadline
    // instead of a fresh 750 ms budget per step. Each is capped by the ordinary admission budget.
    /// Revalidates within a caller-owned bounded multi-step operation.
    ///
    /// The caller's absolute deadline is capped by the ordinary admission
    /// budget for this individual operation.
    pub fn revalidate_for_operation(
        &self,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        self.revalidate_until(&self.operation_capped(operation_deadline))
    }

    fn revalidate_until(&self, op: &Operation) -> Result<(), PrivateStorageError> {
        // Re-open every component from `/` without following links. Checking
        // only the retained leaf descriptor would miss replacement of an
        // intermediate ancestor after this capability was created.
        let walked = open_directory_without_symlinks_until(&self.path, op)?;
        let metadata = self.directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        let walked_metadata = walked.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        if !self.identity.same_directory(FileIdentity::from_metadata(&metadata))
            || !self.identity.same_directory(FileIdentity::from_metadata(&walked_metadata))
        {
            return Err(PrivateStorageError::Unavailable);
        }
        admit_directory_descriptor_until(
            &self.path,
            &self.directory,
            role_of(self.private_leaf),
            op,
        )
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
        self.create_private_child_until(name, &self.operation())
    }

    /// Creates a private child while preserving the caller's absolute deadline.
    pub fn create_private_child_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        self.create_private_child_until(name, &self.operation_capped(operation_deadline))
    }

    fn create_private_child_until(
        &self,
        name: &str,
        op: &Operation,
    ) -> Result<Self, PrivateStorageError> {
        validate_child_name(name)?;
        self.revalidate_until(op)?;
        rustix::fs::mkdirat(&self.directory, name, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(op)?;
        self.sync_until(op)?;
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
        self.revalidate_until(op)?;
        let path = self.path.join(name);
        admit_directory_descriptor_until(&path, &child, DirectoryRole::PrivateLeaf, op)?;
        self.revalidate_until(op)?;
        let metadata = child.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        Ok(Self {
            path,
            directory: child,
            identity: FileIdentity::from_metadata(&metadata),
            private_leaf: true,
            profile: self.profile,
        })
    }

    /// Opens a private child, creating it only when it is absent.
    pub fn open_or_create_private_child(&self, name: &str) -> Result<Self, PrivateStorageError> {
        self.open_or_create_private_child_until(name, &self.operation())
    }

    fn open_or_create_private_child_until(
        &self,
        name: &str,
        op: &Operation,
    ) -> Result<Self, PrivateStorageError> {
        validate_child_name(name)?;
        self.revalidate_until(op)?;
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
                    self.profile,
                    op,
                )?;
                self.revalidate_until(op)?;
                Ok(child)
            }
            Err(error) if error == rustix::io::Errno::NOENT => {
                self.create_private_child_until(name, op)
            }
            Err(_) => Err(PrivateStorageError::Unavailable),
        }
    }

    /// Opens an already-existing private child directory relative to this descriptor.
    pub fn open_private_child(&self, name: &str) -> Result<Self, PrivateStorageError> {
        self.open_private_child_until(name, &self.operation())
    }

    /// Opens an admitted private child within a caller-owned bounded operation.
    pub fn open_private_child_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<Self, PrivateStorageError> {
        self.open_private_child_until(name, &self.operation_capped(operation_deadline))
    }

    fn open_private_child_until(
        &self,
        name: &str,
        op: &Operation,
    ) -> Result<Self, PrivateStorageError> {
        validate_child_name(name)?;
        self.revalidate_until(op)?;
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
        self.revalidate_until(op)?;
        let path = self.path.join(name);
        admit_directory_descriptor_until(&path, &child, DirectoryRole::PrivateLeaf, op)?;
        self.revalidate_until(op)?;
        let metadata = child.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        Ok(Self {
            path,
            directory: child,
            identity: FileIdentity::from_metadata(&metadata),
            private_leaf: true,
            profile: self.profile,
        })
    }

    /// Lists at most `maximum_entries` immediate child names and revalidates this root.
    pub fn bounded_child_names(
        &self,
        maximum_entries: usize,
    ) -> Result<Vec<String>, PrivateStorageError> {
        self.bounded_child_names_until(maximum_entries, &self.operation())
    }

    /// Lists bounded child names under the same absolute deadline as a larger operation.
    pub fn bounded_child_names_for_operation(
        &self,
        maximum_entries: usize,
        operation_deadline: std::time::Instant,
    ) -> Result<Vec<String>, PrivateStorageError> {
        self.bounded_child_names_until(maximum_entries, &self.operation_capped(operation_deadline))
    }

    fn bounded_child_names_until(
        &self,
        maximum_entries: usize,
        op: &Operation,
    ) -> Result<Vec<String>, PrivateStorageError> {
        self.revalidate_until(op)?;
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
        self.revalidate_until(op)?;
        names.sort_unstable();
        Ok(names)
    }

    /// Removes a validated private regular file by its bounded child name.
    pub fn remove_private_file(&self, name: &str) -> Result<(), PrivateStorageError> {
        let op = &self.operation();
        let file = self.open_file_with_link_policy_until(name, false, op)?;
        self.validate_file_binding_with_link_policy_until(name, &file, false, false, op)?;
        drop(file);
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(op)
    }

    /// Removes a private file only when its name still identifies the caller's open file.
    pub fn remove_private_file_if_matches(
        &self,
        name: &str,
        expected: &File,
    ) -> Result<(), PrivateStorageError> {
        let op = &self.operation();
        let actual = self.open_file_with_link_policy_until(name, false, op)?;
        self.validate_file_binding_with_link_policy_until(name, &actual, false, false, op)?;
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
        self.revalidate_until(op)
    }

    /// Removes a file only if its name still identifies the expected descriptor, under one deadline.
    pub fn remove_private_file_if_matches_for_operation(
        &self,
        name: &str,
        expected: &File,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        use std::os::unix::fs::MetadataExt as _;
        let op = &self.operation_capped(operation_deadline);
        let actual = self.open_file_with_link_policy_until(name, false, op)?;
        self.validate_file_binding_with_link_policy_until(name, &actual, false, false, op)?;
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
        self.revalidate_until(op)?;
        self.sync_until(op)
    }

    /// Removes a validated private immutable object file that may have hard links.
    pub fn remove_managed_file(&self, name: &str) -> Result<(), PrivateStorageError> {
        let op = &self.operation();
        let file = self.open_file_with_link_policy_until(name, true, op)?;
        self.validate_file_binding_with_link_policy_until(name, &file, false, true, op)?;
        drop(file);
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(op)
    }

    /// Removes an admitted empty private child directory.
    pub fn remove_private_child(&self, name: &str) -> Result<(), PrivateStorageError> {
        let op = &self.operation();
        validate_child_name(name)?;
        let child = self.open_private_child_until(name, op)?;
        if !child.bounded_child_names_until(1, op)?.is_empty() {
            return Err(PrivateStorageError::Unavailable);
        }
        child.revalidate_until(op)?;
        self.revalidate_until(op)?;
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(op)?;
        self.sync_until(op)
    }

    /// Removes an empty admitted child using the caller's absolute deadline.
    pub fn remove_private_child_for_operation(
        &self,
        name: &str,
        expected: &AdmittedPrivateRoot,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        let op = &self.operation_capped(operation_deadline);
        validate_child_name(name)?;
        let child = self.open_private_child_until(name, op)?;
        let expected_metadata =
            expected.directory.metadata().map_err(|_| PrivateStorageError::Operation)?;
        let actual_metadata =
            child.directory.metadata().map_err(|_| PrivateStorageError::Operation)?;
        if !FileIdentity::from_metadata(&expected_metadata)
            .same_directory(FileIdentity::from_metadata(&actual_metadata))
        {
            return Err(PrivateStorageError::Unavailable);
        }
        if !child.bounded_child_names_until(1, op)?.is_empty() {
            return Err(PrivateStorageError::Unavailable);
        }
        child.revalidate_until(op)?;
        expected.revalidate_until(op)?;
        self.revalidate_until(op)?;
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.revalidate_until(op)?;
        self.sync_until(op)
    }

    /// Opens a regular no-follow child file after revalidating this directory.
    pub fn open_regular_file(&self, name: &str) -> Result<File, PrivateStorageError> {
        self.open_file_with_link_policy(name, false)
    }

    /// Opens a regular private file within a caller-owned bounded operation.
    pub fn open_regular_file_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<File, PrivateStorageError> {
        self.open_file_with_link_policy_until(
            name,
            false,
            &self.operation_capped(operation_deadline),
        )
    }

    /// Admits an existing private regular file without keeping or opening a descriptor.
    ///
    /// SQLite takes POSIX advisory locks on its database, `-wal`, and `-shm` files. POSIX
    /// releases *every* lock a process holds on a file when that process closes *any*
    /// descriptor for it, so validating a live database by opening and dropping a second
    /// descriptor silently drops SQLite's locks and lets another process delete the WAL out
    /// from under this one. On every supported Unix this check is therefore descriptor-free:
    /// it uses `statat` plus a path-based ACL query (`lgetxattr` on Linux, `/bin/ls -ldeO` on
    /// macOS) and never opens the file.
    pub fn validate_regular_file(&self, name: &str) -> Result<(), PrivateStorageError> {
        if self.validate_named_file_without_open(name)? {
            Ok(())
        } else {
            Err(PrivateStorageError::Operation)
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
        let op = &self.operation();
        self.revalidate_until(op)?;
        let stat = |directory: &File| {
            rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        };
        let first = match stat(&self.directory) {
            Ok(first) => first,
            Err(error) if error == rustix::io::Errno::NOENT => {
                self.revalidate_until(op)?;
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
        if !probe::named_file_acl_admits(&self.path.join(name), identity, op) {
            return Err(PrivateStorageError::Unavailable);
        }
        self.revalidate_until(op)?;
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
        self.open_file_with_link_policy_until(name, allow_hardlinks, &self.operation())
    }

    fn open_file_with_link_policy_until(
        &self,
        name: &str,
        allow_hardlinks: bool,
        op: &Operation,
    ) -> Result<File, PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        if !self.named_regular_file_exists_until(name, op)? {
            return Err(PrivateStorageError::Operation);
        }
        let file = self
            .open_nonblocking_read_descriptor(name)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.validate_file_binding_with_link_policy_until(name, &file, false, allow_hardlinks, op)?;
        self.revalidate_until(op)?;
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
        op: &Operation,
    ) -> Result<bool, PrivateStorageError> {
        self.revalidate_until(op)?;
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(PrivateStorageError::Unavailable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.revalidate_until(op)?;
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
        let op = &self.operation();
        self.revalidate_until(op)?;
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
        self.validate_file_binding_with_link_policy_until(name, &file, true, false, op)?;
        self.revalidate_until(op)?;
        Ok(file)
    }

    /// Exclusively creates a private regular file under a caller-owned deadline.
    pub fn create_private_file_for_operation(
        &self,
        name: &str,
        operation_deadline: std::time::Instant,
    ) -> Result<File, PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        let op = &self.operation_capped(operation_deadline);
        self.revalidate_until(op)?;
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
        self.validate_file_binding_with_link_policy_until(name, &file, true, false, op)?;
        self.revalidate_until(op)?;
        Ok(file)
    }

    /// Rechecks that a retained descriptor is still the named private file within a larger operation.
    pub fn validate_file_binding_for_operation(
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
            &self.operation_capped(operation_deadline),
        )
    }

    /// Syncs the admitted directory within a caller-owned bounded operation.
    pub fn sync_for_operation(
        &self,
        operation_deadline: std::time::Instant,
    ) -> Result<(), PrivateStorageError> {
        self.sync_until(&self.operation_capped(operation_deadline))
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
        let op = &self.operation();
        self.named_regular_file_exists_until(name, op)?;
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
        self.validate_file_binding_with_link_policy_until(name, &file, created, false, op)?;
        self.revalidate_until(op)?;
        Ok(file)
    }

    /// Reads a bounded private file through its validated no-follow descriptor.
    pub fn read_bounded_file(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStorageError> {
        use std::io::Read as _;

        let op = &self.operation();
        let file = self.open_file_with_link_policy_until(name, false, op)?;
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
        self.validate_file_binding_with_link_policy_until(name, &file, false, false, op)?;
        self.revalidate_until(op)?;
        Ok(bytes)
    }

    /// Reads a bounded immutable object that may be intentionally hard-linked.
    pub fn read_bounded_managed_file(
        &self,
        name: &str,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PrivateStorageError> {
        use std::io::Read as _;

        let op = &self.operation();
        let file = self.open_file_with_link_policy_until(name, true, op)?;
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
        self.validate_file_binding_with_link_policy_until(name, &file, false, true, op)?;
        self.revalidate_until(op)?;
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
            &self.operation(),
        )
    }

    fn validate_file_binding_with_link_policy_until(
        &self,
        name: &str,
        file: &File,
        newly_created: bool,
        allow_hardlinks: bool,
        op: &Operation,
    ) -> Result<(), PrivateStorageError> {
        if !self.private_leaf {
            return Err(PrivateStorageError::Unavailable);
        }
        validate_child_name(name)?;
        self.revalidate_until(op)?;
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
        if !probe::acl_admits_file(&self.path.join(name), file, descriptor_identity, op) {
            return Err(PrivateStorageError::Unavailable);
        }
        let directory_metadata =
            self.directory.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        if descriptor.dev() != directory_metadata.dev() {
            return Err(PrivateStorageError::Unavailable);
        }
        let filesystem = rustix::fs::fstatfs(file).map_err(|_| PrivateStorageError::Unavailable)?;
        if !owner_enforcing_local_filesystem(&filesystem, self.profile) {
            return Err(PrivateStorageError::Unavailable);
        }
        self.revalidate_until(op)?;
        let named_after = std::fs::symlink_metadata(self.path.join(name))
            .map_err(|_| PrivateStorageError::Unavailable)?;
        let opened_after = file.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
        if FileIdentity::from_metadata(&named_after) != descriptor_identity
            || FileIdentity::from_metadata(&opened_after) != descriptor_identity
            || named_after.nlink() != descriptor.nlink()
            || opened_after.nlink() != descriptor.nlink()
            || !probe::acl_admits_file(&self.path.join(name), file, descriptor_identity, op)
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
        let op = &self.operation();
        validate_child_name(source)?;
        validate_child_name(target)?;
        self.revalidate_until(op)?;
        let source_file = self.open_file_with_link_policy_until(source, false, op)?;
        self.validate_file_binding_with_link_policy_until(source, &source_file, false, false, op)?;
        match std::fs::symlink_metadata(self.path.join(target)) {
            Ok(_) => {
                let target_file = self.open_file_with_link_policy_until(target, false, op)?;
                self.validate_file_binding_with_link_policy_until(
                    target,
                    &target_file,
                    false,
                    false,
                    op,
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PrivateStorageError::Unavailable),
        }
        rustix::fs::renameat(&self.directory, source, &self.directory, target)
            .map_err(|_| PrivateStorageError::Operation)?;
        self.validate_file_binding_with_link_policy_until(target, &source_file, false, false, op)?;
        self.revalidate_until(op)?;
        self.sync_until(op)
    }

    /// Syncs this admitted directory descriptor after a descriptor-relative rename.
    pub fn sync(&self) -> Result<(), PrivateStorageError> {
        self.sync_until(&self.operation())
    }

    fn sync_until(&self, op: &Operation) -> Result<(), PrivateStorageError> {
        self.revalidate_until(op)?;
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
    op: &Operation,
) -> Result<File, PrivateStorageError> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(PrivateStorageError::InvalidName);
    }
    let components = path.components().count();
    if components > MAX_PATH_COMPONENTS + 1 || path.as_os_str().len() > 4096 {
        return Err(PrivateStorageError::InvalidName);
    }
    // Register the walk's prefixes; the one batched ACL listing is taken lazily on the first
    // memo miss (macOS only; see `Operation::spawn_batch_for` for why it cannot admit anything
    // by itself).
    #[cfg(target_os = "macos")]
    {
        let mut prefix = PathBuf::from("/");
        let mut prefixes = vec![prefix.clone()];
        for component in path.components() {
            if let Component::Normal(name) = component {
                prefix.push(name);
                prefixes.push(prefix.clone());
            }
        }
        op.register_walk(&prefixes);
    }
    let mut descriptor = open_directory_descriptor("/")?;
    let mut traversed = PathBuf::from("/");
    verify_ancestor_metadata(&traversed, &descriptor, op)?;
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
                verify_ancestor_metadata(&traversed, &descriptor, op)?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(PrivateStorageError::InvalidName);
            }
        }
    }
    Ok(descriptor)
}

/// Applies the [`DirectoryRole::Traversed`] policy to one component of an ancestor walk.
fn verify_ancestor_metadata(
    path: &Path,
    descriptor: &File,
    op: &Operation,
) -> Result<(), PrivateStorageError> {
    if op.expired() {
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
    {
        use std::os::unix::fs::MetadataExt as _;
        if !policy::directory_metadata_admits(
            DirectoryRole::Traversed,
            opened.uid(),
            opened.mode(),
            rustix::process::getuid().as_raw(),
        ) || !rustix::fs::fstatfs(descriptor)
            .is_ok_and(|filesystem| owner_enforcing_local_filesystem(&filesystem, op.profile()))
            || !probe::directory_acl_admits(
                op,
                DirectoryRole::Traversed,
                path,
                descriptor,
                identity,
            )
        {
            return Err(PrivateStorageError::Unavailable);
        }
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

/// The role a retained capability is judged under.
fn role_of(private_leaf: bool) -> DirectoryRole {
    if private_leaf { DirectoryRole::PrivateLeaf } else { DirectoryRole::Container }
}

/// Admits `descriptor` for `role`: the traversal policy for the walk, then the role's own rules.
///
/// Every step re-checks the named path against the descriptor. Only the ACL query is memoized
/// (see `probe`), so a directory that is both walked through and admitted costs one probe.
fn admit_directory_descriptor_until(
    path: &Path,
    descriptor: &File,
    role: DirectoryRole,
    op: &Operation,
) -> Result<(), PrivateStorageError> {
    use std::os::unix::fs::MetadataExt as _;

    verify_ancestor_metadata(path, descriptor, op)?;
    let named = std::fs::symlink_metadata(path).map_err(|_| PrivateStorageError::Unavailable)?;
    let opened = descriptor.metadata().map_err(|_| PrivateStorageError::Unavailable)?;
    let identity = FileIdentity::from_metadata(&opened);
    if named.file_type().is_symlink()
        || !named.is_dir()
        || !identity.same_directory(FileIdentity::from_metadata(&named))
    {
        return Err(PrivateStorageError::Unavailable);
    }
    if !policy::directory_metadata_admits(
        role,
        opened.uid(),
        opened.mode(),
        rustix::process::getuid().as_raw(),
    ) {
        return Err(PrivateStorageError::Unavailable);
    }
    let filesystem =
        rustix::fs::fstatfs(descriptor).map_err(|_| PrivateStorageError::Unavailable)?;
    // Only a private (or sealed) leaf must carry no ACL at all. Every other component is merely
    // walked through (or is a container whose created children are re-admitted as private
    // leaves, which refuses an inherited ACL), so it gets the traversal policy.
    if !owner_enforcing_local_filesystem(&filesystem, op.profile())
        || !probe::directory_acl_admits(op, role, path, descriptor, identity)
    {
        return Err(PrivateStorageError::Unavailable);
    }
    verify_ancestor_metadata(path, descriptor, op)?;
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

/// Walks `path` and admits the final directory as an exact-owner `0700` private leaf, returning
/// its descriptor. The walk and the leaf admission share one deadline and one probe memo.
pub fn open_private_directory_descriptor(path: &Path) -> Result<File, PrivateStorageError> {
    open_private_directory_descriptor_with_profile(path, FilesystemProfile::Durable)
}

/// [`open_private_directory_descriptor`] under an explicit filesystem profile.
pub fn open_private_directory_descriptor_with_profile(
    path: &Path,
    profile: FilesystemProfile,
) -> Result<File, PrivateStorageError> {
    let op = &Operation::new().with_profile(profile);
    let directory = open_directory_without_symlinks_until(path, op)?;
    admit_directory_descriptor_until(path, &directory, DirectoryRole::PrivateLeaf, op)?;
    Ok(directory)
}

/// Admits each path as a private directory sealed to exactly `mode` (for example a read-only
/// retained snapshot), under one shared admission deadline and one probe memo, so ancestors that
/// the paths have in common are probed once.
pub fn admit_sealed_directories(paths: &[PathBuf], mode: u32) -> Result<(), PrivateStorageError> {
    admit_sealed_directories_with_profile(paths, mode, FilesystemProfile::Durable)
}

/// [`admit_sealed_directories`] under an explicit filesystem profile.
pub fn admit_sealed_directories_with_profile(
    paths: &[PathBuf],
    mode: u32,
    profile: FilesystemProfile,
) -> Result<(), PrivateStorageError> {
    let op = &Operation::new().with_profile(profile);
    for path in paths {
        let directory = open_directory_without_symlinks_until(path, op)?;
        admit_directory_descriptor_until(path, &directory, DirectoryRole::Sealed { mode }, op)?;
    }
    Ok(())
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

#[cfg(target_os = "macos")]
fn owner_enforcing_local_filesystem(
    stats: &rustix::fs::StatFs,
    _profile: FilesystemProfile,
) -> bool {
    let name = stats
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    policy::macos_filesystem_admitted(&name, stats.f_flags)
}

#[cfg(target_os = "linux")]
fn owner_enforcing_local_filesystem(
    stats: &rustix::fs::StatFs,
    profile: FilesystemProfile,
) -> bool {
    policy::linux_filesystem_admitted(stats.f_type as u64, profile)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn owner_enforcing_local_filesystem(
    _stats: &rustix::fs::StatFs,
    _profile: FilesystemProfile,
) -> bool {
    false
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
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("{stem}-{}-{time}-{sequence}", std::process::id())
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
        // A fresh operation and a fresh identity per judgment: setting a POSIX ACL rewrites the
        // group permission bits, and the verdict memo is exercised on its own in `probe`.
        let admits = |role| {
            let identity = FileIdentity::from_metadata(&directory.metadata().expect("metadata"));
            probe::directory_acl_admits(&Operation::new(), role, child.path(), &directory, identity)
        };
        let admits_traversal = || admits(DirectoryRole::Traversed);
        let admits_strict = || admits(DirectoryRole::PrivateLeaf);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn default_acl_on_a_walked_directory_does_not_block_a_clean_private_leaf() {
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
        let walked = scratch.create_private_child(&unique_name("walked")).expect("walked dir");
        let clean = walked.create_private_child("clean").expect("clean leaf");
        let set = |attr: &str, value: &[u8]| {
            rustix::fs::fsetxattr(&walked.directory, attr, value, rustix::fs::XattrFlags::empty())
        };
        // The shape stock CI images give /home: default ACL naming the runner user with rwx.
        let stock_home_default =
            acl(&[(1, 7, NONE), (2, 7, 1000), (4, 5, NONE), (16, 7, NONE), (32, 5, NONE)]);
        let result = set("system.posix_acl_default", &stock_home_default);
        if result == Err(rustix::io::Errno::OPNOTSUPP) {
            return;
        }
        result.expect("set default acl on walked directory");
        let clean_path = clean.path().to_path_buf();
        // Creating, opening, and re-admitting a clean leaf below the walked directory still works.
        AdmittedPrivateRoot::open(&clean_path).expect("leaf below default-ACL ancestor");
        AdmittedPrivateRoot::open_or_create(&clean_path).expect("open_or_create below ancestor");
        AdmittedPrivateRoot::open_container(walked.path()).expect("container with default ACL");
        // A directory created below it inherits the ACL and is refused as a private leaf.
        let inherited = walked.path().join("inherited");
        assert!(AdmittedPrivateRoot::open_or_create(&inherited).is_err());
        // The walked directory itself, as a private leaf, is still refused for carrying an ACL.
        assert!(AdmittedPrivateRoot::open(walked.path()).is_err());
        // An ancestor whose access ACL grants a foreign write is refused for every use.
        set(
            "system.posix_acl_access",
            &acl(&[(1, 7, NONE), (2, 7, 12345), (4, 5, NONE), (16, 7, NONE), (32, 0, NONE)]),
        )
        .expect("set writable access acl");
        assert!(AdmittedPrivateRoot::open(&clean_path).is_err());
        assert!(AdmittedPrivateRoot::open_or_create(&clean_path).is_err());
    }

    #[test]
    fn rejects_path_syntax_as_a_child_name() {
        for name in ["", ".", "..", "a/b", "a\0b", "a\nb"] {
            assert_eq!(validate_child_name(name), Err(PrivateStorageError::InvalidName));
        }
        assert_eq!(validate_child_name("metadata.sqlite3"), Ok(()));
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

    // ---- probe-count bounds -------------------------------------------------------------
    //
    // On macOS every directory ACL probe is a `/bin/ls` subprocess, so the number of probes an
    // operation runs is its latency. These tests count real probes (the cfg(test) counter in
    // `probe`) and pin an upper bound per operation for a path of D directories (the root plus
    // each component). With the per-operation memo each distinct directory state is probed once:
    // `revalidate` costs D, and `create_private_child` costs D plus re-probes of the parent (whose
    // ctime the mkdir bumped) plus the new child (measured on macOS: D+3). Before the memo they
    // cost D+3 and about 5*(D+3)+3.
    //
    // Linux does not memoize (its probes are two xattr reads), so its bounds are the old ones.

    /// Directories on a path, not counting the scratch root: every test in this module creates
    /// children there at the same time, so its ctime (and thus its probe count) is noise.
    fn directory_count(path: &Path) -> usize {
        path.components().count() - 1
    }

    /// Probes of directories other than the busy scratch root.
    fn probes_during(action: impl FnOnce()) -> usize {
        let busy = private_scratch().path().to_path_buf();
        let before = probe::probed_paths().len();
        action();
        probe::probed_paths().iter().skip(before).filter(|path| **path != busy).count()
    }

    /// A private leaf several components below the scratch root.
    fn nested_leaf() -> AdmittedPrivateRoot {
        let mut current = private_scratch().create_private_child(&unique_name("depth")).expect("a");
        for name in ["b", "c", "d"] {
            current = current.create_private_child(name).expect("nested private child");
        }
        current
    }

    #[test]
    fn revalidate_probes_each_directory_at_most_once() {
        let leaf = nested_leaf();
        let directories = directory_count(leaf.path());
        let probes = probes_during(|| leaf.revalidate().expect("revalidate"));
        if cfg!(target_os = "macos") {
            assert_eq!(probes, directories, "one probe per distinct directory");
        } else {
            // No memo: every walked directory once, then the leaf's own admission (traversal
            // check, strict check, traversal check again).
            assert_eq!(probes, directories + 3);
        }
    }

    #[test]
    fn create_private_child_probe_count_is_bounded() {
        let leaf = nested_leaf();
        let directories = directory_count(leaf.path());
        let mut created = None;
        let probes = probes_during(|| {
            created = Some(leaf.create_private_child("bounded").expect("create child"));
        });
        assert!(created.is_some());
        if cfg!(target_os = "macos") {
            // D for the first walk; the parent once more because the mkdir advanced its ctime
            // (every later revalidate then hits the memo); the new child once. A first leased
            // run measured one more, but that was the shared scratch root, which other tests
            // were busy in and which these counts now exclude.
            assert!(probes <= directories + 2, "{probes} probes for {directories} directories");
        } else {
            // Five revalidations of the parent (each directories + 3) and the child's admission
            // (3 probes), with no memo.
            assert_eq!(probes, 5 * (directories + 3) + 3);
        }
    }

    #[test]
    fn open_private_child_and_open_probe_counts_are_bounded() {
        let leaf = nested_leaf();
        leaf.create_private_child("child").expect("create child");
        let directories = directory_count(leaf.path());
        let opened = probes_during(|| {
            leaf.open_private_child("child").expect("open child");
        });
        let reopened = probes_during(|| {
            AdmittedPrivateRoot::open(leaf.path()).expect("reopen leaf");
        });
        let open_or_create = probes_during(|| {
            AdmittedPrivateRoot::open_or_create(leaf.path()).expect("open or create existing");
        });
        if cfg!(target_os = "macos") {
            assert!(opened <= directories + 1, "{opened} probes for {directories} directories");
            assert!(reopened <= directories, "{reopened} probes for {directories} directories");
            assert!(
                open_or_create <= directories,
                "{open_or_create} probes for {directories} directories"
            );
        } else {
            // Three revalidations of the parent plus the child's admission.
            assert_eq!(opened, 3 * (directories + 3) + 3);
            assert_eq!(reopened, directories + 3);
            // Each existing component is admitted (3 probes), then one final revalidation.
            assert_eq!(open_or_create, 3 * directories + (directories + 3));
        }
    }

    #[test]
    fn sealed_directories_share_their_ancestors_probes() {
        let leaf = nested_leaf();
        let sealed = ["one", "two", "three"]
            .map(|name| leaf.create_private_child(name).expect("sealed candidate"));
        for child in &sealed {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(child.path(), std::fs::Permissions::from_mode(0o500))
                .expect("seal");
        }
        let paths = sealed.iter().map(|child| child.path().to_path_buf()).collect::<Vec<_>>();
        let directories = directory_count(leaf.path());
        let probes = probes_during(|| {
            admit_sealed_directories(&paths, 0o500).expect("sealed directories admitted");
        });
        if cfg!(target_os = "macos") {
            // Shared ancestors once, then one probe per sealed directory.
            assert!(probes <= directories + paths.len(), "{probes} probes");
        }
        assert!(admit_sealed_directories(&paths, 0o700).is_err(), "wrong sealed mode is refused");
        for child in &sealed {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(child.path(), std::fs::Permissions::from_mode(0o700))
                .expect("unseal");
        }
    }

    /// On macOS one walk lists all of its directories with a single `ls`; only directories that
    /// changed within the last 20 ms (the scratch root other tests are busy in) are probed alone.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_quiet_walk_spawns_one_ls_not_one_per_component() {
        let leaf = nested_leaf();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let directories = directory_count(leaf.path());
        let before = probe::ls_spawn_count();
        leaf.revalidate().expect("revalidate");
        let spawns = probe::ls_spawn_count() - before;
        assert!((1..=4).contains(&spawns), "{spawns} ls runs for {directories} directories");
        let before = probe::ls_spawn_count();
        let created = leaf.create_private_child("spawns").expect("create child");
        let spawns = probe::ls_spawn_count() - before;
        // Unbatched this costs 5 * (D + 3) + 3 runs (68 for ten directories). The batch keeps it to a
        // handful: one per walk plus a single-directory run for each directory that changed in the
        // last 20 ms, which includes the shared scratch root other tests are busy in.
        assert!(
            spawns <= 3 * directories,
            "{spawns} ls runs to create a child below {directories} directories"
        );
        drop(created);
    }

    // ---- real-filesystem admission through the public entry points -----------------------
    //
    // The pure policy table pins each rule; these drive the real entry points on real
    // directories so that reordering or dropping a step in the orchestration is caught.

    fn fresh_child() -> (AdmittedPrivateRoot, String) {
        let parent = private_scratch().create_private_child(&unique_name("real")).expect("parent");
        let name = "subject".to_owned();
        parent.create_private_child(&name).expect("subject");
        (parent, name)
    }

    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn entry_points_enforce_owner_and_mode_on_real_directories() {
        let (parent, name) = fresh_child();
        let subject = parent.path().join(&name);
        // Private leaf: exactly 0700, so anything looser is refused by `open`.
        assert!(AdmittedPrivateRoot::open(&subject).is_ok());
        chmod(&subject, 0o750);
        assert!(AdmittedPrivateRoot::open(&subject).is_err());
        assert!(AdmittedPrivateRoot::open_or_create(&subject).is_err());
        // A container tolerates group read/execute but never group or other write.
        assert!(AdmittedPrivateRoot::open_container(&subject).is_ok());
        chmod(&subject, 0o770);
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
        chmod(&subject, 0o707);
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
        // A writable ancestor poisons everything below it, even a clean 0700 leaf.
        chmod(&subject, 0o700);
        let leaf = subject.join("leaf");
        std::fs::create_dir(&leaf).expect("leaf");
        chmod(&leaf, 0o700);
        assert!(AdmittedPrivateRoot::open(&leaf).is_ok());
        chmod(&subject, 0o770);
        assert!(AdmittedPrivateRoot::open(&leaf).is_err());
        chmod(&subject, 0o700);
        // Root-owned system directories are never a private leaf, and a sticky world-writable
        // directory is never even a container.
        assert!(AdmittedPrivateRoot::open(Path::new("/")).is_err());
        assert!(AdmittedPrivateRoot::open_container(Path::new("/tmp")).is_err());
        assert!(AdmittedPrivateRoot::open_container(Path::new("/var/tmp")).is_err());
    }

    #[test]
    fn entry_points_refuse_symlinks_at_the_leaf_and_in_an_ancestor() {
        let (parent, name) = fresh_child();
        let subject = parent.path().join(&name);
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&subject, &link).expect("symlink");
        assert!(AdmittedPrivateRoot::open(&link).is_err());
        assert!(AdmittedPrivateRoot::open_container(&link).is_err());
        assert!(AdmittedPrivateRoot::open_or_create(&link).is_err());
        let through = link.join("child");
        std::fs::create_dir(subject.join("child")).expect("child");
        chmod(&subject.join("child"), 0o700);
        assert!(AdmittedPrivateRoot::open(&through).is_err());
        assert!(AdmittedPrivateRoot::open(&subject.join("child")).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn entry_points_judge_a_real_linux_acl_by_role() {
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
        let (parent, name) = fresh_child();
        let subject = parent.path().join(&name);
        let directory = File::open(&subject).expect("open subject");
        let set = |attr: &str, value: &[u8]| {
            rustix::fs::fsetxattr(&directory, attr, value, rustix::fs::XattrFlags::empty())
        };
        let read_only_user =
            acl(&[(1, 7, NONE), (2, 5, 12345), (4, 5, NONE), (16, 5, NONE), (32, 0, NONE)]);
        let result = set("system.posix_acl_access", &read_only_user);
        if result == Err(rustix::io::Errno::OPNOTSUPP) {
            return;
        }
        result.expect("set access ACL");
        // A read-only named user: fine for a container, never for a private leaf.
        assert!(AdmittedPrivateRoot::open(&subject).is_err());
        assert!(AdmittedPrivateRoot::open_container(&subject).is_ok());
        let writable_user =
            acl(&[(1, 7, NONE), (2, 7, 12345), (4, 5, NONE), (16, 7, NONE), (32, 0, NONE)]);
        set("system.posix_acl_access", &writable_user).expect("set writable ACL");
        assert!(AdmittedPrivateRoot::open(&subject).is_err());
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn entry_points_judge_a_real_macos_acl_by_entry_effect() {
        let (parent, name) = fresh_child();
        let subject = parent.path().join(&name);
        let acl = |flag: &str, entry: &str| {
            std::process::Command::new("/bin/chmod")
                .args([flag, entry])
                .arg(&subject)
                .status()
                .expect("run chmod")
                .success()
        };
        // A deny-only entry is admitted (macOS has one policy for every role).
        assert!(acl("+a", "group:everyone deny delete"));
        assert!(AdmittedPrivateRoot::open(&subject).is_ok());
        assert!(AdmittedPrivateRoot::open_container(&subject).is_ok());
        // An allow entry is refused for every role, and removing it restores admission.
        assert!(acl("+a", "group:everyone allow write"));
        assert!(AdmittedPrivateRoot::open(&subject).is_err());
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
        assert!(acl("-a", "group:everyone allow write"));
        assert!(AdmittedPrivateRoot::open(&subject).is_ok());
    }

    #[test]
    fn an_expired_deadline_refuses_before_any_probe() {
        let leaf = nested_leaf();
        let expired = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let before = probe::probed_paths().len();
        assert_eq!(leaf.revalidate_for_operation(expired), Err(PrivateStorageError::Unavailable));
        assert_eq!(
            leaf.create_private_child_for_operation("late", expired).map(|_| ()),
            Err(PrivateStorageError::Unavailable)
        );
        assert!(!leaf.path().join("late").exists(), "no directory created after expiry");
        assert_eq!(probe::probed_paths().len(), before, "no ACL probe after expiry");
    }

    // ---- admission scope through the public entry points (ADR 0008 Amendment 1) -----------

    use crate::scope::AdmissionScope;

    /// The leaf a scope test works on, with its parent holding it, after the clock has moved past
    /// the batch quiet period so the batch can describe it.
    fn scoped_subject() -> (AdmittedPrivateRoot, std::path::PathBuf) {
        let (parent, name) = fresh_child();
        let subject = parent.path().join(&name);
        std::thread::sleep(std::time::Duration::from_millis(60));
        (parent, subject)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_scope_spawns_far_fewer_listings_than_the_same_calls_without_one() {
        const CALLS: usize = 10;
        let busy = private_scratch().path().to_path_buf();
        let leaf = nested_leaf();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let directories = directory_count(leaf.path());
        let (probed, spawned) = (probe::probed_paths().len(), probe::ls_spawn_count());
        for _ in 0..CALLS {
            leaf.revalidate().expect("revalidate without a scope");
        }
        let unscoped = probe::ls_spawn_count() - spawned;
        let unscoped_probes = probe::probed_paths().len() - probed;
        let (probed, spawned) = (probe::probed_paths().len(), probe::ls_spawn_count());
        let counter_before = scope_counter();
        {
            let _scope = AdmissionScope::enter();
            for _ in 0..CALLS {
                leaf.revalidate().expect("revalidate inside a scope");
            }
        }
        let scoped = probe::ls_spawn_count() - spawned;
        let scoped_paths: Vec<_> = probe::probed_paths().into_iter().skip(probed).collect();
        // The shared scratch root is busy (other tests create children in it), so its state moves
        // between calls and it is legitimately probed again; everything else is quiet.
        let busy_probes = scoped_paths.iter().filter(|path| **path == busy).count();
        let quiet_probes = scoped_paths.len() - busy_probes;
        assert!(unscoped >= CALLS, "every operation lists at least once: {unscoped}");
        assert!(unscoped_probes >= CALLS * directories / 2, "unscoped re-judges every call");
        assert!(quiet_probes <= directories, "{quiet_probes} judgments of quiet directories");
        // One batch for the whole scope, plus a single listing per busy-root judgment and per
        // quiet directory the batch could not describe.
        assert!(
            scoped <= 1 + busy_probes + directories,
            "{scoped} ls runs ({busy_probes} busy-root judgments) for {CALLS} scoped calls"
        );
        assert!(
            scoped < unscoped || busy_probes >= CALLS,
            "scoped {scoped} vs unscoped {unscoped}"
        );
        assert_eq!(scope_counter() - counter_before, scoped as u64);
    }

    #[cfg(all(target_os = "macos", feature = "spawn-counter"))]
    fn scope_counter() -> u64 {
        crate::spawn_counter::ls_spawns_on_this_thread()
    }

    #[cfg(all(target_os = "macos", not(feature = "spawn-counter")))]
    fn scope_counter() -> u64 {
        probe::ls_spawn_count() as u64
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_walk_registers_its_operands_and_spawns_only_when_a_directory_misses() {
        let leaf = nested_leaf();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let spawns = probe::ls_spawn_count();
        let batches = probe::batch_attempt_count();
        let op = Operation::new();
        let mut prefixes = vec![PathBuf::from("/")];
        let mut prefix = PathBuf::from("/");
        for component in leaf.path().components().skip(1) {
            prefix.push(component);
            prefixes.push(prefix.clone());
        }
        op.register_walk(&prefixes);
        assert_eq!(probe::ls_spawn_count(), spawns, "registering a walk spawns nothing");
        for _ in 0..5 {
            open_directory_without_symlinks_until(leaf.path(), &op).expect("walk");
        }
        assert_eq!(probe::batch_attempt_count() - batches, 1, "at most one batch per operation");
        // A second operation with a warm scope: still at most one batch for the whole scope.
        let batches = probe::batch_attempt_count();
        {
            let _scope = AdmissionScope::enter();
            for _ in 0..5 {
                leaf.revalidate().expect("revalidate in scope");
            }
        }
        assert_eq!(probe::batch_attempt_count() - batches, 1, "at most one batch per scope");
    }

    #[test]
    fn a_mode_change_inside_a_scope_is_seen_by_the_next_call() {
        // Key invalidation itself (ctime in the memo key) is shown by the probe.rs test
        // `the_scope_key_separates_state_filesystem_flags_and_profile` and the ctime tests there;
        // this test shows the end-to-end refusal on whatever platform runs it.
        let (parent, subject) = scoped_subject();
        let _scope = AdmissionScope::enter();
        let held = AdmittedPrivateRoot::open(&subject).expect("admitted first");
        held.revalidate().expect("revalidates");
        chmod(&subject, 0o750);
        assert!(held.revalidate().is_err(), "the held capability sees the new mode");
        assert!(AdmittedPrivateRoot::open(&subject).is_err(), "private leaf must be 0700");
        assert!(AdmittedPrivateRoot::open_container(&subject).is_ok(), "container tolerates 0750");
        chmod(&subject, 0o770);
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
        chmod(&subject, 0o700);
        assert!(AdmittedPrivateRoot::open(&subject).is_ok(), "restored mode is admitted again");
        // An ancestor loosened mid-scope poisons the walk below it.
        let leaf = subject.join("leaf");
        std::fs::create_dir(&leaf).expect("leaf");
        chmod(&leaf, 0o700);
        assert!(AdmittedPrivateRoot::open(&leaf).is_ok());
        chmod(&subject, 0o770);
        assert!(AdmittedPrivateRoot::open(&leaf).is_err());
        chmod(&subject, 0o700);
        drop(parent);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_acl_added_inside_a_scope_is_seen_and_refused() {
        let (_parent, subject) = scoped_subject();
        let leaf = subject.join("leaf");
        std::fs::create_dir(&leaf).expect("leaf");
        chmod(&leaf, 0o700);
        std::thread::sleep(std::time::Duration::from_millis(60));
        let acl = |flag: &str, path: &Path| {
            std::process::Command::new("/bin/chmod")
                .args([flag, "group:everyone allow write"])
                .arg(path)
                .status()
                .expect("run chmod")
                .success()
        };
        let _scope = AdmissionScope::enter();
        assert!(AdmittedPrivateRoot::open(&subject).is_ok());
        assert!(AdmittedPrivateRoot::open(&leaf).is_ok());
        // On the private leaf itself ...
        assert!(acl("+a", &leaf));
        assert!(AdmittedPrivateRoot::open(&leaf).is_err(), "leaf ACL must be probed afresh");
        assert!(acl("-a", &leaf));
        assert!(AdmittedPrivateRoot::open(&leaf).is_ok());
        // ... and on an ancestor that was already walked and remembered.
        assert!(acl("+a", &subject));
        assert!(AdmittedPrivateRoot::open(&leaf).is_err(), "ancestor ACL must be probed afresh");
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
        assert!(acl("-a", &subject));
        assert!(AdmittedPrivateRoot::open(&leaf).is_ok());
    }

    #[test]
    fn a_directory_replaced_under_the_same_name_inside_a_scope_is_refused() {
        let (parent, subject) = scoped_subject();
        let _scope = AdmissionScope::enter();
        let held = AdmittedPrivateRoot::open(&subject).expect("admitted first");
        held.revalidate().expect("revalidates");
        std::fs::rename(&subject, parent.path().join("moved-away")).expect("move original");
        std::fs::create_dir(&subject).expect("replacement");
        chmod(&subject, 0o700);
        assert!(held.revalidate().is_err(), "the capability is bound to the original directory");
        assert!(held.create_private_child("late").is_err());
        assert!(held.open_or_create_private_child("late").is_err());
        // A loose replacement is refused by a fresh open as well.
        chmod(&subject, 0o770);
        assert!(AdmittedPrivateRoot::open(&subject).is_err());
        assert!(AdmittedPrivateRoot::open_container(&subject).is_err());
    }

    #[test]
    fn a_symlink_swapped_in_inside_a_scope_is_refused_at_the_leaf_and_at_an_ancestor() {
        let (parent, subject) = scoped_subject();
        let child = subject.join("child");
        std::fs::create_dir(&child).expect("child");
        chmod(&child, 0o700);
        let _scope = AdmissionScope::enter();
        let held_child = AdmittedPrivateRoot::open(&child).expect("child admitted first");
        let held_subject = AdmittedPrivateRoot::open(&subject).expect("subject admitted first");
        // Leaf swapped for a symlink.
        let moved_child = subject.join("child-moved");
        std::fs::rename(&child, &moved_child).expect("move child");
        std::os::unix::fs::symlink(&moved_child, &child).expect("leaf symlink");
        assert!(held_child.revalidate().is_err());
        assert!(AdmittedPrivateRoot::open(&child).is_err());
        assert!(AdmittedPrivateRoot::open_container(&child).is_err());
        std::fs::remove_file(&child).expect("remove leaf symlink");
        std::fs::rename(&moved_child, &child).expect("restore child");
        assert!(AdmittedPrivateRoot::open(&child).is_ok());
        // Ancestor swapped for a symlink.
        let moved_subject = parent.path().join("subject-moved");
        std::fs::rename(&subject, &moved_subject).expect("move subject");
        std::os::unix::fs::symlink(&moved_subject, &subject).expect("ancestor symlink");
        assert!(held_child.revalidate().is_err());
        assert!(held_subject.revalidate().is_err());
        assert!(AdmittedPrivateRoot::open(&child).is_err());
        assert!(AdmittedPrivateRoot::open(&subject).is_err());
    }

    #[test]
    fn hardlinked_and_fifo_files_are_still_refused_inside_a_scope() {
        let (parent, name) = fresh_child();
        let dir = parent.open_private_child(&name).expect("subject");
        let linked = "linked";
        drop(dir.open_or_create_private_file(linked).expect("private file"));
        let _scope = AdmissionScope::enter();
        assert!(dir.validate_regular_file(linked).is_ok(), "a single-link file is fine");
        std::fs::hard_link(dir.path().join(linked), dir.path().join("second-name"))
            .expect("hard link");
        assert!(dir.validate_regular_file(linked).is_err(), "link count 2 is refused");
        assert!(dir.open_regular_file(linked).is_err());
        assert!(dir.open_or_create_private_file(linked).is_err());
        std::fs::remove_file(dir.path().join("second-name")).expect("unlink second name");
        assert!(dir.validate_regular_file(linked).is_ok(), "named-file checks run on every call");

        let fifo = "fifo";
        #[cfg(target_os = "linux")]
        rustix::fs::mkfifoat(&dir.directory, fifo, rustix::fs::Mode::from_raw_mode(0o600))
            .expect("create FIFO fixture");
        #[cfg(target_os = "macos")]
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(dir.path().join(fifo))
                .status()
                .expect("mkfifo")
                .success()
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_dir = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let _scope = AdmissionScope::enter();
            let root = AdmittedPrivateRoot::open(&worker_dir).expect("reopen in worker");
            let outcomes = [
                root.open_regular_file(fifo).is_err(),
                root.validate_regular_file(fifo).is_err(),
                root.validate_optional_private_file(fifo).is_err(),
                root.open_or_create_private_file(fifo).is_err(),
            ];
            let _ = sender.send(outcomes);
        });
        let outcomes = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("FIFO validation must not block inside a scope");
        assert!(outcomes.into_iter().all(|refused| refused));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_scope_past_its_cap_lists_afresh() {
        let leaf = nested_leaf();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let _scope = AdmissionScope::enter_with_cap(std::time::Duration::from_millis(1_500));
        leaf.revalidate().expect("warm the scope");
        let before = probe::batch_attempt_count();
        let spawns = probe::ls_spawn_count();
        leaf.revalidate().expect("inside the cap");
        let within = probe::ls_spawn_count() - spawns;
        assert_eq!(probe::batch_attempt_count(), before, "no new batch inside the cap");
        assert!(within <= 4, "{within} ls runs inside the cap: only busy directories relist");
        std::thread::sleep(std::time::Duration::from_millis(1_600));
        let spawns = probe::ls_spawn_count();
        leaf.revalidate().expect("past the cap");
        let after = probe::ls_spawn_count() - spawns;
        assert!(after >= 1, "past the cap the scope remembers nothing, so it lists again");
        assert_eq!(probe::batch_attempt_count() - before, 1, "one fresh batch for the operation");
    }

    #[test]
    fn an_expired_deadline_inside_a_live_scope_refuses_before_any_probe() {
        let leaf = nested_leaf();
        let _scope = AdmissionScope::enter();
        leaf.revalidate().expect("warm the scope");
        let expired = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let before = probe::probed_paths().len();
        assert_eq!(leaf.revalidate_for_operation(expired), Err(PrivateStorageError::Unavailable));
        assert_eq!(
            leaf.create_private_child_for_operation("late", expired).map(|_| ()),
            Err(PrivateStorageError::Unavailable)
        );
        assert!(!leaf.path().join("late").exists(), "no directory created after expiry");
        assert_eq!(probe::probed_paths().len(), before, "no ACL probe after expiry");
    }

    /// Directory names that try to confuse listing parsing: spaces, a trailing space, a name that
    /// looks like an ACL entry index, an arrow, and non-ASCII. Whatever the batch does, the
    /// verdicts must be right: ASCII names are admitted, an ACL on one component refuses exactly
    /// the paths through it, and non-ASCII (which the ASCII-only parser has always refused)
    /// stays refused rather than being misread.
    #[cfg(target_os = "macos")]
    #[test]
    fn tricky_directory_names_get_the_right_verdict_from_the_batched_listing() {
        let mut current =
            private_scratch().create_private_child(&unique_name("tricky")).expect("base");
        let mut chain = Vec::new();
        for name in ["a b", "trail ", "0: x", "b -> c"] {
            current = current.create_private_child(name).expect("tricky child");
            chain.push(current.path().to_path_buf());
        }
        let deepest = chain[3].clone();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let before = probe::ls_spawn_count();
        AdmittedPrivateRoot::open(&deepest).expect("tricky ASCII names are admitted");
        let spawns = probe::ls_spawn_count() - before;
        assert!(spawns <= 6, "{spawns} ls runs: the batch must have been used");
        // An allow entry on exactly one component refuses every path through it ...
        let acl = |flag: &str| {
            std::process::Command::new("/bin/chmod")
                .args([flag, "group:everyone allow write"])
                .arg(&chain[1])
                .status()
                .expect("run chmod")
                .success()
        };
        assert!(acl("+a"));
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(AdmittedPrivateRoot::open(&deepest).is_err(), "ACL on 'trail ' must be seen");
        assert!(AdmittedPrivateRoot::open(&chain[0]).is_ok(), "but not blamed on its parent");
        // ... and removing it restores admission.
        assert!(acl("-a"));
        std::thread::sleep(std::time::Duration::from_millis(60));
        AdmittedPrivateRoot::open(&deepest).expect("admitted again");
        // Non-ASCII listings have always been refused by the ASCII-only parser.
        assert!(current.create_private_child("\u{fc}n\u{ef}").is_err());
        let unicode = current.path().join("\u{fc}n\u{ef}");
        assert!(unicode.is_dir(), "the refused child was still created, as before");
        chmod(&unicode, 0o700);
        assert!(AdmittedPrivateRoot::open(&unicode).is_err());
    }
}
