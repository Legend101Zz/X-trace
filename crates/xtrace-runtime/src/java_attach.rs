//! Validated Java attach-pack access and owner-enforced private storage admission.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_PACK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACK_ENTRIES: usize = 96;
const MAX_RETAINED_PACK_SNAPSHOTS: usize = 4;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Sanitized error from Java attach-pack validation or helper process control.
#[derive(Debug, Error)]
pub enum AttachError {
    /// The selected pack or private root failed closed validation.
    #[error("{0}")]
    Validation(&'static str),
    /// Owner, mount, ACL, or identity checks rejected a private root.
    #[error("{0}")]
    PrivateStorage(&'static str),
    /// The current operating system does not provide the required attach support.
    #[error("Java attach is unsupported on this platform")]
    Unsupported,
    /// A helper could not be started, bounded, or reaped safely.
    #[error("the bounded Java attach helper failed")]
    Process,
}

impl AttachError {
    /// Returns a stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "XTR-ATTACH-PACK-INVALID",
            Self::PrivateStorage(_) => "XTR-ATTACH-PRIVATE-STORAGE",
            Self::Unsupported => "XTR-ATTACH-UNSUPPORTED-HOST",
            Self::Process => "XTR-ATTACH-HELPER-FAILED",
        }
    }
}

/// An immutable, completely verified Java attach pack.
#[derive(Clone, Debug)]
pub struct JavaAttachPack {
    root: PathBuf,
    helper_jar: PathBuf,
    agent_dir: PathBuf,
}

impl JavaAttachPack {
    /// Resolves an explicitly selected unsigned development pack.
    pub fn resolve(explicit: &Path) -> Result<Self, AttachError> {
        Self::validate(explicit)
    }

    /// Verifies exact pack membership, ownership, file kinds, bounds, and SHA-256 contents.
    pub fn validate(candidate: &Path) -> Result<Self, AttachError> {
        let candidate_metadata = std::fs::symlink_metadata(candidate)
            .map_err(|_| AttachError::Validation("the Java attach pack is unavailable"))?;
        if candidate_metadata.file_type().is_symlink() || !candidate_metadata.is_dir() {
            return Err(AttachError::Validation(
                "the Java attach pack root must be a real directory",
            ));
        }
        let root = candidate
            .canonicalize()
            .map_err(|_| AttachError::Validation("the Java attach pack is unavailable"))?;
        if root.to_str().is_none() {
            return Err(AttachError::Validation("the Java attach pack path must be valid UTF-8"));
        }
        let owner = rustix::process::getuid().as_raw();
        let root_identity = check_directory(&root, owner)?;
        let inventory = walk_pack(&root, owner)?;
        let actual = &inventory.files;
        let manifest_path = root.join("pack.manifest");
        let manifest_identity = actual
            .get("pack.manifest")
            .copied()
            .ok_or(AttachError::Validation("the Java attach pack manifest is missing"))?;
        if manifest_identity.size > MAX_MANIFEST_BYTES {
            return Err(AttachError::Validation("the Java attach pack manifest exceeds its limit"));
        }
        let manifest = read_bounded_file(&manifest_path, manifest_identity, MAX_MANIFEST_BYTES)?;
        let declared = parse_manifest(&manifest)?;
        if declared.len() + 1 != actual.len()
            || actual.keys().any(|path| path != "pack.manifest" && !declared.contains_key(path))
            || inventory.directories
                != ["agent", "agent/runtime", "attach"].into_iter().map(str::to_string).collect()
        {
            return Err(AttachError::Validation("the Java attach pack membership does not match"));
        }
        for (path, expected) in &declared {
            let identity = actual
                .get(path)
                .copied()
                .ok_or(AttachError::Validation("the Java attach pack is incomplete"))?;
            let bytes = read_bounded_file(&root.join(path), identity, MAX_FILE_BYTES)?;
            if sha256(&bytes) != *expected {
                return Err(AttachError::Validation("the Java attach pack digest does not match"));
            }
        }
        let helper_jar = root.join("attach/xtrace-attach.jar");
        let agent_dir = root.join("agent");
        for required in
            ["attach/xtrace-attach.jar", "agent/manifest.sha256", "agent/xtrace-java-agent.jar"]
        {
            if !declared.contains_key(required) {
                return Err(AttachError::Validation("the Java attach pack is incomplete"));
            }
        }
        if !declared.keys().any(|path| path.starts_with("agent/runtime/") && path.ends_with(".jar"))
        {
            return Err(AttachError::Validation("the Java attach pack has no agent runtime JARs"));
        }
        let manifest_after = std::fs::symlink_metadata(&manifest_path).map_err(|_| {
            AttachError::Validation("the Java attach pack changed during validation")
        })?;
        if FileIdentity::from_metadata(&manifest_after) != manifest_identity
            || check_directory(&root, owner)? != root_identity
        {
            return Err(AttachError::Validation("the Java attach pack changed during validation"));
        }
        Ok(Self { root, helper_jar, agent_dir })
    }

    /// Returns the canonical verified pack root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the verified standalone helper JAR.
    #[must_use]
    pub fn helper_jar(&self) -> &Path {
        &self.helper_jar
    }

    /// Returns the verified Java agent distribution root.
    #[must_use]
    pub fn agent_dir(&self) -> &Path {
        &self.agent_dir
    }

    /// Copies the verified distribution into an owner-only cache snapshot.
    ///
    /// Digests protect integrity, not publisher authenticity. The private copy
    /// ensures the paths later passed to the JVM are the bytes validated here.
    pub fn snapshot_into(&self, cache: &Path) -> Result<Self, AttachError> {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let current = Self::validate(&self.root)?;
        let manifest_identity = std::fs::symlink_metadata(current.root.join("pack.manifest"))
            .map_err(|_| {
                AttachError::Validation("the Java attach pack changed during validation")
            })?;
        let manifest_identity = FileIdentity::from_metadata(&manifest_identity);
        let manifest = read_bounded_file(
            &current.root.join("pack.manifest"),
            manifest_identity,
            MAX_MANIFEST_BYTES,
        )?;
        let declared = parse_manifest(&manifest)?;
        let snapshot_name = sha256(&manifest);
        let parent = open_directory_without_symlinks(cache)
            .map_err(|_| AttachError::PrivateStorage("the Java helper cache changed"))?;
        admit_directory_descriptor(cache, &parent, true)?;
        let packs_name = "java-packs";
        let packs = open_or_create_private_child(&parent, packs_name)?;
        admit_directory_descriptor(&cache.join(packs_name), &packs, true)?;
        let snapshot_path = cache.join(packs_name).join(&snapshot_name);
        match std::fs::symlink_metadata(&snapshot_path) {
            Ok(_) => {
                // An existing snapshot must be complete and identical. Never repair
                // or overwrite a partially created destination in place.
                let snapshot = Self::validate(&snapshot_path)?;
                verify_retained_snapshot_directories(&snapshot_path)?;
                return Ok(snapshot);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(AttachError::PrivateStorage(
                    "the private Java pack snapshot is unavailable",
                ));
            }
        }
        ensure_snapshot_capacity(&cache.join(packs_name), &packs)?;
        rustix::fs::mkdirat(&packs, &snapshot_name, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot could not be created")
            })?;
        let snapshot = open_child_directory(&packs, &snapshot_name).map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot could not be opened")
        })?;
        verify_metadata_owner_mode(
            &snapshot.metadata().map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
            })?,
            true,
        )?;
        admit_directory_descriptor(&snapshot_path, &snapshot, true)?;
        for directory in ["attach", "agent", "agent/runtime"] {
            create_private_directory(&snapshot, directory)?;
            let descriptor = open_directory_without_symlinks(&snapshot_path.join(directory))
                .map_err(|_| {
                    AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
                })?;
            admit_directory_descriptor(&snapshot_path.join(directory), &descriptor, true)?;
        }
        let mut total = 0_u64;
        for (relative, expected_digest) in &declared {
            let identity =
                std::fs::symlink_metadata(current.root.join(relative)).map_err(|_| {
                    AttachError::Validation("the Java attach pack changed during snapshot")
                })?;
            let identity = FileIdentity::from_metadata(&identity);
            let bytes = read_bounded_file(&current.root.join(relative), identity, MAX_FILE_BYTES)?;
            if sha256(&bytes) != *expected_digest {
                return Err(AttachError::Validation(
                    "the Java attach pack changed during snapshot",
                ));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or(AttachError::Validation("the Java attach pack exceeds its size limit"))?;
            if total > MAX_PACK_BYTES {
                return Err(AttachError::Validation("the Java attach pack exceeds its size limit"));
            }
            write_snapshot_file(&snapshot, relative, &bytes)?;
        }
        total = total
            .checked_add(manifest.len() as u64)
            .ok_or(AttachError::Validation("the Java attach pack exceeds its size limit"))?;
        if total > MAX_PACK_BYTES {
            return Err(AttachError::Validation("the Java attach pack exceeds its size limit"));
        }
        let mut manifest_file = rustix::fs::openat(
            &snapshot,
            "pack.manifest",
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_raw_mode(0o400),
        )
        .map(std::fs::File::from)
        .map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot could not be written")
        })?;
        (&mut manifest_file).write_all(&manifest).map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot could not be written")
        })?;
        drop(manifest_file);
        let verified = Self::validate(&snapshot_path)?;
        for directory in ["attach", "agent/runtime", "agent"] {
            let path = snapshot_path.join(directory);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).map_err(
                |_| {
                    AttachError::PrivateStorage(
                        "the private Java pack snapshot could not be sealed",
                    )
                },
            )?;
        }
        std::fs::set_permissions(&snapshot_path, std::fs::Permissions::from_mode(0o500)).map_err(
            |_| AttachError::PrivateStorage("the private Java pack snapshot could not be sealed"),
        )?;
        Self::validate(&snapshot_path)?;
        verify_retained_snapshot_directories(&snapshot_path)?;
        Ok(verified)
    }
}

fn verify_retained_snapshot_directories(root: &Path) -> Result<(), AttachError> {
    for relative in ["", "attach", "agent", "agent/runtime"] {
        let path = if relative.is_empty() { root.to_path_buf() } else { root.join(relative) };
        let descriptor = open_directory_without_symlinks(&path).map_err(|_| {
            AttachError::PrivateStorage("the retained Java pack snapshot is unsafe")
        })?;
        let metadata = descriptor.metadata().map_err(|_| {
            AttachError::PrivateStorage("the retained Java pack snapshot is unsafe")
        })?;
        let filesystem = rustix::fs::fstatfs(&descriptor).map_err(|_| {
            AttachError::PrivateStorage("the retained Java pack snapshot filesystem is unavailable")
        })?;
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.mode() & 0o7777 != 0o500
            || !owner_enforcing_local_filesystem(&filesystem)
            || !acl_admits_directory(&path, &descriptor, FileIdentity::from_metadata(&metadata))
        {
            return Err(AttachError::PrivateStorage("the retained Java pack snapshot is unsafe"));
        }
    }
    Ok(())
}

fn ensure_snapshot_capacity(path: &Path, packs: &std::fs::File) -> Result<(), AttachError> {
    use std::os::unix::fs::MetadataExt as _;
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| AttachError::PrivateStorage("the Java pack cache is unavailable"))?;
    let descriptor_before = packs
        .metadata()
        .map_err(|_| AttachError::PrivateStorage("the Java pack cache is unavailable"))?;
    let expected = FileIdentity::from_metadata(&descriptor_before);
    if before.file_type().is_symlink()
        || !before.is_dir()
        || FileIdentity::from_metadata(&before) != expected
        || expected.owner != rustix::process::getuid().as_raw()
        || expected.mode & 0o077 != 0
    {
        return Err(AttachError::PrivateStorage("the Java pack cache identity changed"));
    }
    let iterator = std::fs::read_dir(path)
        .map_err(|_| AttachError::PrivateStorage("the Java pack cache cannot be read"))?;
    let mut count = 0_usize;
    for result in iterator {
        count += 1;
        if count > MAX_RETAINED_PACK_SNAPSHOTS {
            return Err(AttachError::PrivateStorage(
                "the bounded Java pack snapshot cache is full",
            ));
        }
        let entry = result
            .map_err(|_| AttachError::PrivateStorage("the Java pack cache cannot be read"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(AttachError::PrivateStorage("the Java pack cache has an unexpected entry"));
        };
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            AttachError::PrivateStorage("the Java pack cache has an unexpected entry")
        })?;
        let child = open_child_directory(packs, name).map_err(|_| {
            AttachError::PrivateStorage("the Java pack cache has an unexpected entry")
        })?;
        let child_metadata = child.metadata().map_err(|_| {
            AttachError::PrivateStorage("the Java pack cache has an unexpected entry")
        })?;
        if name.len() != 64
            || !name.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || FileIdentity::from_metadata(&metadata)
                != FileIdentity::from_metadata(&child_metadata)
            || child_metadata.uid() != expected.owner
            || child_metadata.mode() & 0o077 != 0
        {
            return Err(AttachError::PrivateStorage("the Java pack cache has an unexpected entry"));
        }
    }
    let after = std::fs::symlink_metadata(path)
        .map_err(|_| AttachError::PrivateStorage("the Java pack cache identity changed"))?;
    let descriptor_after = packs
        .metadata()
        .map_err(|_| AttachError::PrivateStorage("the Java pack cache identity changed"))?;
    if FileIdentity::from_metadata(&after) != expected
        || FileIdentity::from_metadata(&descriptor_after) != expected
    {
        return Err(AttachError::PrivateStorage("the Java pack cache identity changed"));
    }
    if count >= MAX_RETAINED_PACK_SNAPSHOTS {
        return Err(AttachError::PrivateStorage("the bounded Java pack snapshot cache is full"));
    }
    Ok(())
}

fn open_or_create_private_child(
    parent: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, AttachError> {
    match open_child_directory(parent, name) {
        Ok(child) => {
            verify_metadata_owner_mode(
                &child.metadata().map_err(|_| {
                    AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
                })?,
                true,
            )?;
            Ok(child)
        }
        Err(error) if error == rustix::io::Errno::NOENT => {
            rustix::fs::mkdirat(parent, name, rustix::fs::Mode::from_raw_mode(0o700)).map_err(
                |_| {
                    AttachError::PrivateStorage(
                        "the private Java pack snapshot could not be created",
                    )
                },
            )?;
            let child = open_child_directory(parent, name).map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot could not be opened")
            })?;
            verify_metadata_owner_mode(
                &child.metadata().map_err(|_| {
                    AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
                })?,
                true,
            )?;
            Ok(child)
        }
        Err(_) => Err(AttachError::PrivateStorage("the private Java pack snapshot is unavailable")),
    }
}

fn create_private_directory(root: &std::fs::File, relative: &str) -> Result<(), AttachError> {
    use rustix::fs::{Mode, OFlags, openat};
    let (parent, name) = relative.rsplit_once('/').map_or(("", relative), |pair| pair);
    let directory = if parent.is_empty() {
        root.try_clone().map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
        })?
    } else {
        openat(
            root,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(|_| AttachError::PrivateStorage("the private Java pack snapshot is unavailable"))?
    };
    rustix::fs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)).map_err(|_| {
        AttachError::PrivateStorage("the private Java pack snapshot could not be created")
    })?;
    let child = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(|_| {
        AttachError::PrivateStorage("the private Java pack snapshot could not be opened")
    })?;
    verify_metadata_owner_mode(
        &child.metadata().map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
        })?,
        true,
    )
}

fn write_snapshot_file(
    root: &std::fs::File,
    relative: &str,
    bytes: &[u8],
) -> Result<(), AttachError> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::io::Write as _;
    let (parent, name) = relative
        .rsplit_once('/')
        .ok_or(AttachError::Validation("the Java attach pack manifest is malformed"))?;
    let directory = openat(
        root,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(|_| AttachError::PrivateStorage("the private Java pack snapshot is unavailable"))?;
    let mut file = openat(
        &directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o400),
    )
    .map(std::fs::File::from)
    .map_err(|_| {
        AttachError::PrivateStorage("the private Java pack snapshot could not be written")
    })?;
    file.write_all(bytes).map_err(|_| {
        AttachError::PrivateStorage("the private Java pack snapshot could not be written")
    })
}

/// Verifies that an existing directory is on an owner-enforcing local filesystem.
///
/// The check uses an opened directory descriptor so a path-only mount check cannot
/// be swapped between inspection and use. Unknown filesystems and failed probes
/// are rejected. This remains a point-in-time admission check, not a defense from
/// privileged remounts or hostile same-user processes.
pub fn admit_private_directory(path: &Path) -> Result<(), AttachError> {
    super::private_storage::AdmittedPrivateRoot::open(path)
        .map(|_| ())
        .map_err(|_| AttachError::PrivateStorage("private storage cannot be admitted"))
}

/// Admits a user-data container that may be traversable but is not writable by other users.
pub fn admit_private_container_directory(path: &Path) -> Result<(), AttachError> {
    super::private_storage::AdmittedPrivateRoot::open_container(path)
        .map(|_| ())
        .map_err(|_| AttachError::PrivateStorage("private storage cannot be admitted"))
}

pub(super) fn admit_directory_descriptor(
    path: &Path,
    directory: &std::fs::File,
    owner_only: bool,
) -> Result<(), AttachError> {
    super::private_storage::AdmittedPrivateRoot::validate_open_directory(
        path, directory, owner_only,
    )
    .map_err(|_| AttachError::PrivateStorage("private storage cannot be admitted"))
}

/// Creates a private, durable helper cache below an already-admitted user data home.
pub fn prepare_helper_cache(data_home: &Path) -> Result<PathBuf, AttachError> {
    let parent = super::private_storage::AdmittedPrivateRoot::open_container(data_home)
        .map_err(|_| AttachError::PrivateStorage("the user data home cannot be admitted"))?;
    let cache = parent
        .open_or_create_private_child(".xtrace-java-attach-cache")
        .map_err(|_| AttachError::PrivateStorage("the Java helper cache is unavailable"))?;
    Ok(cache.path().to_path_buf())
}

fn parse_manifest(bytes: &[u8]) -> Result<std::collections::BTreeMap<String, String>, AttachError> {
    use std::collections::BTreeMap;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AttachError::Validation("the Java attach pack manifest is malformed"))?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(AttachError::Validation("the Java attach pack manifest is malformed"));
    }
    let mut declared = BTreeMap::new();
    let mut previous = None;
    for line in text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or(AttachError::Validation("the Java attach pack manifest is malformed"))?;
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !safe_relative_path(path)
            || previous.is_some_and(|value: &str| value >= path)
            || declared.insert(path.to_string(), digest.to_string()).is_some()
        {
            return Err(AttachError::Validation("the Java attach pack manifest is malformed"));
        }
        previous = Some(path);
    }
    if declared.is_empty() {
        return Err(AttachError::Validation("the Java attach pack manifest is empty"));
    }
    Ok(declared)
}

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl FileIdentity {
    pub(super) fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            links: metadata.nlink(),
        }
    }
}

struct PackInventory {
    files: std::collections::BTreeMap<String, FileIdentity>,
    directories: std::collections::BTreeSet<String>,
}

fn walk_pack(root: &Path, owner: u32) -> Result<PackInventory, AttachError> {
    fn visit(
        root: &Path,
        directory: &Path,
        owner: u32,
        depth: usize,
        total: &mut u64,
        count: &mut usize,
        files: &mut std::collections::BTreeMap<String, FileIdentity>,
        directories: &mut std::collections::BTreeSet<String>,
    ) -> Result<(), AttachError> {
        use std::os::unix::fs::MetadataExt as _;
        if depth > 5 {
            return Err(AttachError::Validation(
                "the Java attach pack directory depth exceeds its limit",
            ));
        }
        let directory_identity = check_directory(directory, owner)?;
        let iterator = std::fs::read_dir(directory)
            .map_err(|_| AttachError::Validation("the Java attach pack cannot be read"))?;
        let mut entries = Vec::new();
        for entry in iterator {
            if entries.len() >= MAX_PACK_ENTRIES {
                return Err(AttachError::Validation("the Java attach pack has too many files"));
            }
            entries.push(
                entry.map_err(|_| AttachError::Validation("the Java attach pack is invalid"))?,
            );
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            *count += 1;
            if *count > MAX_PACK_ENTRIES {
                return Err(AttachError::Validation("the Java attach pack has too many files"));
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
                AttachError::Validation("the Java attach pack changed during validation")
            })?;
            if metadata.file_type().is_symlink() {
                return Err(AttachError::Validation("the Java attach pack cannot contain links"));
            }
            if metadata.is_dir() {
                if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
                    return Err(AttachError::Validation(
                        "Java pack directories must be owned and not group/other writable",
                    ));
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| AttachError::Validation("the Java attach pack path is invalid"))?;
                let relative = relative
                    .to_str()
                    .ok_or(AttachError::Validation("the Java attach pack has a non-UTF-8 path"))?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                if !safe_relative_path(&relative) || !directories.insert(relative) {
                    return Err(AttachError::Validation(
                        "the Java attach pack contains an invalid directory",
                    ));
                }
                visit(root, &path, owner, depth + 1, total, count, files, directories)?;
            } else if metadata.is_file() {
                let identity = FileIdentity::from_metadata(&metadata);
                if identity.owner != owner
                    || identity.links != 1
                    || identity.mode & 0o022 != 0
                    || identity.size > MAX_FILE_BYTES
                {
                    return Err(AttachError::Validation(
                        "Java pack files must be bounded owned unlinked regular files",
                    ));
                }
                *total = (*total).checked_add(identity.size).ok_or(AttachError::Validation(
                    "the Java attach pack exceeds its size limit",
                ))?;
                if *total > MAX_PACK_BYTES {
                    return Err(AttachError::Validation(
                        "the Java attach pack exceeds its size limit",
                    ));
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| AttachError::Validation("the Java attach pack path is invalid"))?;
                let relative = relative
                    .to_str()
                    .ok_or(AttachError::Validation("the Java attach pack has a non-UTF-8 path"))?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                if !safe_relative_path(&relative) || files.insert(relative, identity).is_some() {
                    return Err(AttachError::Validation(
                        "the Java attach pack contains an invalid path",
                    ));
                }
            } else {
                return Err(AttachError::Validation(
                    "the Java attach pack contains a special file",
                ));
            }
        }
        if check_directory(directory, owner)? != directory_identity {
            return Err(AttachError::Validation("the Java attach pack changed during validation"));
        }
        Ok(())
    }

    let mut files = std::collections::BTreeMap::new();
    let mut directories = std::collections::BTreeSet::new();
    let mut total = 0;
    let mut count = 0;
    visit(root, root, owner, 0, &mut total, &mut count, &mut files, &mut directories)?;
    Ok(PackInventory { files, directories })
}

fn check_directory(path: &Path, owner: u32) -> Result<FileIdentity, AttachError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AttachError::Validation("a Java pack directory is unavailable"))?;
    let identity = FileIdentity::from_metadata(&metadata);
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || identity.owner != owner
        || identity.mode & 0o022 != 0
    {
        return Err(AttachError::Validation(
            "Java pack directories must be owned and not group/other writable",
        ));
    }
    Ok(identity)
}

fn verify_metadata_owner_mode(
    metadata: &std::fs::Metadata,
    owner_only: bool,
) -> Result<(), AttachError> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != rustix::process::getuid().as_raw()
        || !directory_mode_allowed(metadata.mode(), owner_only)
    {
        return Err(AttachError::Validation("private storage ownership or permissions are unsafe"));
    }
    Ok(())
}

fn directory_mode_allowed(mode: u32, owner_only: bool) -> bool {
    if owner_only { mode & 0o7777 == 0o700 } else { mode & 0o022 == 0 }
}

fn read_bounded_file(
    path: &Path,
    expected: FileIdentity,
    bound: u64,
) -> Result<Vec<u8>, AttachError> {
    use std::io::Read as _;
    if expected.size > bound {
        return Err(AttachError::Validation("a Java attach pack file exceeds its size limit"));
    }
    let file = std::fs::File::open(path)
        .map_err(|_| AttachError::Validation("a Java attach pack file cannot be read"))?;
    let before = file
        .metadata()
        .map_err(|_| AttachError::Validation("a Java attach pack file cannot be read"))?;
    if FileIdentity::from_metadata(&before) != expected {
        return Err(AttachError::Validation("the Java attach pack changed during validation"));
    }
    let capacity = usize::try_from(expected.size)
        .map_err(|_| AttachError::Validation("a Java attach pack file exceeds its size limit"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = file.take(bound.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| AttachError::Validation("a Java attach pack file cannot be read"))?;
    if bytes.len() as u64 != expected.size || bytes.len() as u64 > bound {
        return Err(AttachError::Validation("the Java attach pack changed during validation"));
    }
    let after = std::fs::symlink_metadata(path)
        .map_err(|_| AttachError::Validation("the Java attach pack changed during validation"))?;
    if FileIdentity::from_metadata(&after) != expected {
        return Err(AttachError::Validation("the Java attach pack changed during validation"));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn open_directory_without_symlinks(path: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "directory path is not absolute",
        ));
    }
    let mut descriptor = std::fs::File::from(open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    let mut traversed = PathBuf::from("/");
    verify_ancestor_metadata(&traversed, &descriptor)?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let opened = openat(
                    &descriptor,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?;
                traversed.push(name);
                descriptor = std::fs::File::from(opened);
                verify_ancestor_metadata(&traversed, &descriptor)?;
            }
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "directory path is not canonical",
                ));
            }
        }
    }
    Ok(descriptor)
}

pub(super) fn verify_ancestor_metadata(
    path: &Path,
    descriptor: &std::fs::File,
) -> std::io::Result<()> {
    let metadata = descriptor.metadata()?;
    let uid = rustix::process::getuid().as_raw();
    let identity = FileIdentity::from_metadata(&metadata);
    if !ancestor_metadata_allowed(
        identity.owner,
        identity.mode,
        uid,
        acl_admits_directory(path, descriptor, identity),
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory ancestor has unsafe ownership, permissions, or ACL",
        ));
    }
    Ok(())
}

fn ancestor_metadata_allowed(owner: u32, mode: u32, current_uid: u32, acl_admitted: bool) -> bool {
    (owner == current_uid || owner == 0) && mode & 0o022 == 0 && acl_admitted
}

fn open_child_directory(
    parent: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, rustix::io::Errno> {
    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    Ok(std::fs::File::from(descriptor))
}

#[cfg(unix)]
#[cfg(target_os = "macos")]
fn acl_admits_directory(path: &Path, directory: &std::fs::File, expected: FileIdentity) -> bool {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    if path.as_os_str().to_string_lossy().chars().any(char::is_control) {
        return false;
    }
    let before = match std::fs::symlink_metadata(path) {
        Ok(value)
            if value.is_dir()
                && !value.file_type().is_symlink()
                && FileIdentity::from_metadata(&value) == expected =>
        {
            value
        }
        _ => return false,
    };
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
        let kill_result = child.kill();
        let cleanup_deadline = Instant::now() + Duration::from_millis(250);
        let mut reaped = false;
        while Instant::now() < cleanup_deadline {
            match child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        if kill_result.is_err() || !reaped {
            tracing::warn!(
                code = "XTR-ATTACH-ACL-PROBE-UNCONFIRMED",
                "bounded ACL probe could not be confirmed stopped"
            );
        }
        return false;
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let _reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout.by_ref().take(16_385).read_to_end(&mut output);
        let bounded = result.is_ok() && output.len() <= 16_384;
        if sender.send((bounded, output)).is_err() {
            tracing::debug!(
                code = "XTR-ATTACH-ACL-READER-CLOSED",
                "bounded ACL probe reader result was no longer needed"
            );
        }
    });
    let deadline = Instant::now() + Duration::from_millis(750);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => break None,
        }
    };
    if status.is_none() {
        let killed = child.kill();
        let cleanup_deadline = Instant::now() + Duration::from_millis(250);
        let mut reaped = false;
        while Instant::now() < cleanup_deadline {
            match child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        if killed.is_err() || !reaped {
            tracing::warn!(
                code = "XTR-ATTACH-ACL-PROBE-UNCONFIRMED",
                "bounded ACL probe could not be confirmed stopped"
            );
            return false;
        }
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let Ok((bounded, output)) = receiver.recv_timeout(remaining) else {
        tracing::warn!(
            code = "XTR-ATTACH-ACL-READER-UNCONFIRMED",
            "bounded ACL probe exited without closing its result pipe"
        );
        return false;
    };
    let Some(status) = status else { return false };
    if !status.success() || !bounded {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&output) else { return false };
    let Some(expected_path) = path.to_str() else {
        return false;
    };
    if !parse_macos_acl_listing(text, expected_path) {
        return false;
    }
    let after = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let descriptor_after = match directory.metadata() {
        Ok(value) => value,
        Err(_) => return false,
    };
    FileIdentity::from_metadata(&before) == expected
        && FileIdentity::from_metadata(&after) == expected
        && FileIdentity::from_metadata(&descriptor_after) == expected
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_acl_listing(text: &str, expected_path: &str) -> bool {
    if text.contains('\r') || !text.is_ascii() || !text.ends_with('\n') {
        return false;
    }
    let mut lines = text.lines();
    let Some(header) = lines.next() else { return false };
    let Some(header_prefix) = header.strip_suffix(expected_path) else { return false };
    if !header_prefix.ends_with(' ') {
        return false;
    }
    let Some(mode) = header.split_ascii_whitespace().next() else { return false };
    let mode_bytes = mode.as_bytes();
    if mode_bytes.len() < 10 {
        return false;
    }
    let mode_suffix = &mode_bytes[10..];
    if mode_bytes[0] != b'd'
        || !valid_posix_mode(&mode_bytes[1..10])
        || !(mode_suffix.is_empty()
            || mode_suffix == b"+"
            || mode_suffix == b"@"
            || mode_suffix == b"+@")
    {
        return false;
    }
    let Some(header_prefix) = header.strip_suffix(expected_path) else { return false };
    let Some(header_prefix) = header_prefix.strip_suffix(' ') else { return false };
    let fields = header_prefix.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 9
        || fields[1].parse::<u64>().is_err()
        || !(fields[2]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
        || !(fields[3]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
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
    let acl_required = mode_suffix.contains(&b'+');
    let mut expected_index = 0_u32;
    let mut saw_acl = false;
    for raw in lines {
        let Some((index, body)) = raw.trim().split_once(':') else { return false };
        let Ok(index) = index.parse::<u32>() else { return false };
        if index != expected_index {
            return false;
        }
        expected_index = match expected_index.checked_add(1) {
            Some(value) => value,
            None => return false,
        };
        let words = body.split_ascii_whitespace().collect::<Vec<_>>();
        if words.len() < 3 {
            return false;
        }
        let principal = words[0];
        let (principal_kind, principal_name) = match principal.split_once(':') {
            Some((kind, name)) => (kind, name),
            None => return false,
        };
        if !matches!(principal_kind, "user" | "group")
            || principal_name.is_empty()
            || principal_name.len() > 128
            || !principal_name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'$')
            })
        {
            return false;
        }
        let effect_positions = words
            .iter()
            .enumerate()
            .filter(|(_, word)| matches!(**word, "allow" | "deny"))
            .collect::<Vec<_>>();
        if effect_positions.len() != 1 {
            return false;
        }
        let (effect_index, effect) = effect_positions[0];
        if *effect == "allow" || effect_index == 0 || effect_index + 1 >= words.len() {
            return false;
        }
        if words[1..effect_index].iter().any(|word| {
            !matches!(
                **word,
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
        let rights = words[effect_index + 1..].join("");
        let parsed_rights = rights.split(',').collect::<Vec<_>>();
        if parsed_rights.is_empty()
            || parsed_rights.iter().any(|right| !RIGHTS.contains(right))
            || parsed_rights.iter().any(|right| right.is_empty())
        {
            return false;
        }
        saw_acl = true;
    }
    (!acl_required || saw_acl) && (!saw_acl || mode_suffix.contains(&b'@') || acl_required)
}

#[cfg(any(target_os = "macos", test))]
fn valid_macos_flags(flags: &str) -> bool {
    if flags == "-" {
        return true;
    }
    let mut seen = std::collections::BTreeSet::new();
    flags.split(',').all(|flag| matches!(flag, "sunlnk" | "restricted") && seen.insert(flag))
}

#[cfg(any(target_os = "macos", test))]
fn valid_posix_mode(mode: &[u8]) -> bool {
    const PERMISSIONS: [&[u8]; 9] =
        [b"r-", b"w-", b"xSs-", b"r-", b"w-", b"xSs-", b"r-", b"w-", b"xTt-"];
    mode.len() == PERMISSIONS.len()
        && mode.iter().zip(PERMISSIONS).all(|(actual, allowed)| allowed.contains(actual))
}

#[cfg(target_os = "linux")]
fn acl_admits_directory(_path: &Path, directory: &std::fs::File, _expected: FileIdentity) -> bool {
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn acl_admits_directory(_path: &Path, _directory: &std::fs::File, _expected: FileIdentity) -> bool {
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
    // Local Linux filesystem type magic values. Network, FUSE, overlay, and
    // unknown filesystems fail closed until their ownership semantics are reviewed.
    matches!(stats.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e | 0x01021994)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn owner_enforcing_local_filesystem(_stats: &rustix::fs::StatFs) -> bool {
    false
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests construct fixed bounded pack fixtures")]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    fn make_pack(root: &Path) {
        std::fs::create_dir_all(root.join("attach")).expect("attach directory");
        std::fs::create_dir_all(root.join("agent/runtime")).expect("runtime directory");
        std::fs::write(root.join("attach/xtrace-attach.jar"), b"helper jar").expect("helper bytes");
        std::fs::write(root.join("agent/xtrace-java-agent.jar"), b"agent jar")
            .expect("agent bytes");
        std::fs::write(root.join("agent/manifest.sha256"), b"fixture manifest\n")
            .expect("agent manifest");
        std::fs::write(root.join("agent/runtime/runtime.jar"), b"runtime jar")
            .expect("runtime bytes");
        let mut entries = Vec::new();
        for relative in [
            "agent/manifest.sha256",
            "agent/runtime/runtime.jar",
            "agent/xtrace-java-agent.jar",
            "attach/xtrace-attach.jar",
        ] {
            let bytes = std::fs::read(root.join(relative)).expect("file bytes");
            entries.push(format!("{}  {relative}", sha256(&bytes)));
        }
        std::fs::write(root.join("pack.manifest"), format!("{}\n", entries.join("\n")))
            .expect("pack manifest");
    }

    #[test]
    fn verifies_exact_sorted_pack_membership_and_hashes() {
        let root = tempfile::tempdir().expect("temporary pack");
        make_pack(root.path());

        let pack = JavaAttachPack::validate(root.path()).expect("valid pack");

        assert_eq!(pack.helper_jar(), root.path().join("attach/xtrace-attach.jar"));
        assert_eq!(pack.agent_dir(), root.path().join("agent"));
    }

    #[test]
    fn snapshots_verified_pack_and_keeps_executed_bytes_after_source_changes() {
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("the gate must provide an owner-enforced private scratch root");
        admit_private_directory(&scratch).expect("gate-provided scratch admission");
        let source = tempfile::tempdir_in(&scratch).expect("temporary source pack under scratch");
        make_pack(source.path());
        let cache = tempfile::tempdir_in(&scratch).expect("temporary private cache under scratch");
        let cache_path = cache.path().join("cache");
        std::fs::create_dir(&cache_path).expect("cache directory");
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o700))
            .expect("private cache mode");

        let source_pack = JavaAttachPack::validate(source.path()).expect("verified source pack");
        let snapshot = source_pack.snapshot_into(&cache_path).expect("private pack snapshot");
        let snapshot_bytes = std::fs::read(snapshot.helper_jar()).expect("snapshot helper bytes");
        std::fs::write(source.path().join("attach/xtrace-attach.jar"), b"replaced source")
            .expect("replace source helper");
        assert_eq!(
            std::fs::read(snapshot.helper_jar()).expect("stable helper snapshot"),
            snapshot_bytes
        );
        assert!(JavaAttachPack::validate(source.path()).is_err());
        assert!(JavaAttachPack::validate(snapshot.root()).is_ok());
    }

    #[test]
    fn rejects_pack_digest_mismatch_and_unlisted_files() {
        let root = tempfile::tempdir().expect("temporary pack");
        make_pack(root.path());
        std::fs::write(root.path().join("agent/runtime/runtime.jar"), b"changed")
            .expect("mutate runtime jar");
        assert!(JavaAttachPack::validate(root.path()).is_err());

        make_pack(root.path());
        std::fs::write(root.path().join("agent/runtime/extra.jar"), b"extra")
            .expect("extra runtime jar");
        assert!(JavaAttachPack::validate(root.path()).is_err());
    }

    #[test]
    fn retained_pack_snapshot_inventory_is_bounded() {
        let root = tempfile::tempdir().expect("temporary pack cache");
        for index in 0..MAX_RETAINED_PACK_SNAPSHOTS {
            let name = format!("{index:064x}");
            let path = root.path().join(name);
            std::fs::create_dir(&path).expect("snapshot directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("snapshot permissions");
        }
        let directory = open_directory_without_symlinks(root.path()).expect("pack cache fd");
        assert!(ensure_snapshot_capacity(root.path(), &directory).is_err());
    }

    #[test]
    fn manifest_parser_rejects_traversal_unsorted_duplicates_and_uppercase_hashes() {
        let digest = "a".repeat(64);
        for text in [
            format!("{digest}  ../outside\n"),
            format!("{digest}  z.jar\n{digest}  a.jar\n"),
            format!("{digest}  a.jar\n{digest}  a.jar\n"),
            format!("{}  a.jar\n", "A".repeat(64)),
        ] {
            assert!(parse_manifest(text.as_bytes()).is_err());
        }
    }

    #[test]
    fn macos_acl_parser_accepts_deny_only_and_rejects_allows_or_ambiguous_output() {
        let header = "drwx------+ 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n";
        assert!(parse_macos_acl_listing(
            &format!("{header} 0: group:everyone deny delete\n"),
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(
            &format!("{header} 0: user:other allow read,write\n"),
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(
            &format!("{header} 0: user:other inherited allow read\n"),
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(
            &format!("{header} 0: group:everyone deny read,,write\n"),
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(
            "lrwx------+ 1 xtrace-test staff - 12 Oct 4 12:00 /private/root\n 0: group:everyone deny delete\n",
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(
            &format!("{header} 1: group:everyone deny delete\n"),
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing("not a stat line\n", "/private/root"));
        assert!(!parse_macos_acl_listing(
            "drwx------+@+ 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n",
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(&format!("{header}\r\n"), "/private/root"));
        assert!(parse_macos_acl_listing(
            "drwx------ 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n",
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(&format!("{header}"), "/private/root"));
        assert!(!parse_macos_acl_listing(
            "dssssssss 3 xtrace-test staff - 96 Oct 4 12:00 /private/root\n",
            "/private/root"
        ));
        assert!(parse_macos_acl_listing(
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Volumes/Example SSD/project\n",
            "/Volumes/Example SSD/project"
        ));
        assert!(parse_macos_acl_listing(
            "drwxr-xr-x 4 example staff - 128 Oct 3 2026 /Users/example\n",
            "/Users/example"
        ));
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x@ 4 example staff 128 Oct 4 00:23 /private/root\n",
            "/private/root"
        ));
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /private/root extra\n",
            "/private/root"
        ));
        for (listing, path) in [
            ("drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n", "/"),
            ("drwxr-xr-x 5 root wheel restricted 160 Oct 4 00:23 /System\n", "/System"),
            ("drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users\n", "/Users"),
            (
                "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users/example/Documents\n 0: group:everyone deny delete\n",
                "/Users/example/Documents",
            ),
        ] {
            assert!(parse_macos_acl_listing(listing, path), "{listing}");
        }
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x 5 root wheel unknown 160 Oct 4 00:23 /System\n",
            "/System"
        ));
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x+ 5 root wheel - 160 Oct 4 00:23 /System\n",
            "/System"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pack_files_must_not_be_symlinks_or_hardlinked() {
        let root = tempfile::tempdir().expect("temporary pack");
        make_pack(root.path());
        let link = root.path().join("agent/runtime/linked.jar");
        std::os::unix::fs::symlink(root.path().join("agent/runtime/runtime.jar"), &link)
            .expect("symlink");
        assert!(JavaAttachPack::validate(root.path()).is_err());

        std::fs::remove_file(link).expect("remove symlink");
        std::fs::hard_link(
            root.path().join("agent/runtime/runtime.jar"),
            root.path().join("agent/runtime/second.jar"),
        )
        .expect("hard link");
        assert!(JavaAttachPack::validate(root.path()).is_err());
    }

    #[test]
    fn pack_tree_entry_count_is_bounded_during_enumeration() {
        let root = tempfile::tempdir().expect("temporary pack");
        make_pack(root.path());
        for index in 0..MAX_PACK_ENTRIES {
            std::fs::write(root.path().join(format!("extra-{index:03}.txt")), b"entry")
                .expect("bounded fixture entry");
        }
        assert!(JavaAttachPack::validate(root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_root_admission_rejects_symlink_paths_before_mount_probe() {
        let root = tempfile::tempdir().expect("temporary root");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path(), &link).expect("directory symlink");
        assert!(admit_private_directory(&link).is_err());
    }

    #[test]
    fn private_leaf_and_ancestor_policy_rejects_loose_modes_and_acl_grants() {
        assert!(directory_mode_allowed(0o700, true));
        assert!(!directory_mode_allowed(0o755, true));
        assert!(!directory_mode_allowed(0o2700, true));
        assert!(directory_mode_allowed(0o755, false));
        assert!(!directory_mode_allowed(0o757, false));

        assert!(ancestor_metadata_allowed(0, 0o755, 501, true));
        assert!(ancestor_metadata_allowed(501, 0o755, 501, true));
        assert!(!ancestor_metadata_allowed(501, 0o755, 501, false));
        assert!(!ancestor_metadata_allowed(501, 0o777, 501, true));
        assert!(!ancestor_metadata_allowed(502, 0o755, 501, true));

        let root = tempfile::tempdir().expect("policy fixture directory");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))
            .expect("loosen policy fixture mode");
        let metadata = std::fs::metadata(root.path()).expect("fixture metadata");
        assert!(verify_metadata_owner_mode(&metadata, true).is_err());
        assert!(verify_metadata_owner_mode(&metadata, false).is_ok());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore private fixture mode");
        let metadata = std::fs::metadata(root.path()).expect("private fixture metadata");
        assert!(verify_metadata_owner_mode(&metadata, true).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_parser_accepts_known_system_flags_and_deny_only_extended_acl() {
        for header in [
            "drwxr-xr-x 22 root wheel sunlnk 704 Feb 25 2026 /\n",
            "drwxr-xr-x 5 root wheel restricted 160 Oct 4 00:23 /System\n",
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users\n",
            "drwxr-xr-x@ 4 example staff - 128 Oct 4 00:23 /Users/example/Documents\n 0: group:everyone deny delete\n",
        ] {
            let path = header
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().last())
                .expect("fixture path");
            assert!(parse_macos_acl_listing(header, path), "{header}");
        }
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x 5 root wheel unexpected 160 Oct 4 00:23 /System\n",
            "/System"
        ));
        assert!(!parse_macos_acl_listing(
            "drwxr-xr-x+ 5 root wheel - 160 Oct 4 00:23 /System\n",
            "/System"
        ));
    }
}
