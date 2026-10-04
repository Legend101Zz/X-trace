//! Descriptor-relative inspection of an untrusted public language-pack tree.
//!
//! This proves byte integrity against the pack's own signed inventory only.
//! It does not prove publisher authority, owner-private storage, or permission
//! to execute the inspected files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::private_storage::AdmittedPrivateRoot;
use crate::signed_pack::{
    PackManifest, SignedPackError, build_hash, parse_canonical_manifest,
    verify_with_installed_trust,
};

const OUTER_MANIFEST: &str = "xtrace-pack.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_INNER_MANIFEST_ENTRIES: usize = 96;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 128;
const MAX_INSPECTION_TIME: std::time::Duration = std::time::Duration::from_secs(30);
const CORE_RELEASE_VERSION: &str = "0.0.1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    mode: u32,
}

impl Identity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            links: metadata.nlink(),
            mode: metadata.mode(),
        }
    }

    fn same_object(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }

    fn stable_file(self, other: Self) -> bool {
        self.same_object(other)
            && self.size == other.size
            && self.links == other.links
            && self.mode == other.mode
    }
}

#[derive(Debug)]
struct ScannedFile {
    digest: [u8; 32],
    sha256: [u8; 32],
    small_contents: Option<Vec<u8>>,
    source: Option<(File, Identity)>,
}

/// Untrusted pack bytes inspected through no-follow opened descriptors.
///
/// This object is deliberately not executable and does not implement a
/// verified-pack trait. A later core-owned verifier must authenticate and
/// privately snapshot these exact bytes before any runtime consumes them.
pub struct InspectedPack {
    root_path: PathBuf,
    root: File,
    manifest_bytes: Vec<u8>,
    manifest: PackManifest,
    outer_digest: [u8; 32],
    source_files: BTreeMap<String, (File, Identity, [u8; 32])>,
}

impl std::fmt::Debug for InspectedPack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InspectedPack")
            .field("inspected", &true)
            .field("publisher_authenticated", &false)
            .finish_non_exhaustive()
    }
}

impl InspectedPack {
    /// Parsed signed declarations; they are not runtime authority.
    #[must_use]
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }

    /// BLAKE3 digest of the exact canonical outer manifest bytes.
    #[must_use]
    pub const fn outer_manifest_digest(&self) -> &[u8; 32] {
        &self.outer_digest
    }

    /// Returns the source path as an informational value only.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.root_path
    }

    /// Rechecks the source tree identity and all signed file hashes.
    pub fn revalidate(&self) -> Result<(), SignedPackError> {
        self.revalidate_until(std::time::Instant::now() + MAX_INSPECTION_TIME)
    }

    fn revalidate_until(&self, deadline: std::time::Instant) -> Result<(), SignedPackError> {
        let path_metadata = std::fs::symlink_metadata(&self.root_path)
            .map_err(|_| SignedPackError::InventoryMismatch)?;
        let descriptor_metadata =
            self.root.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || !Identity::from_metadata(&path_metadata)
                .same_object(Identity::from_metadata(&descriptor_metadata))
        {
            return Err(SignedPackError::InventoryMismatch);
        }
        let actual = scan_tree(&self.root, deadline)?;
        compare_inventory(&self.manifest, &actual, *blake3::hash(&self.manifest_bytes).as_bytes())?;
        verify_inner_manifests(&self.manifest, &actual)?;
        let current_manifest =
            read_named_file(&self.root, OUTER_MANIFEST, MAX_MANIFEST_BYTES, deadline)?;
        if current_manifest != self.manifest_bytes {
            return Err(SignedPackError::InventoryMismatch);
        }
        let path_after = std::fs::symlink_metadata(&self.root_path)
            .map_err(|_| SignedPackError::InventoryMismatch)?;
        let descriptor_after =
            self.root.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
        if !Identity::from_metadata(&path_after)
            .same_object(Identity::from_metadata(&descriptor_after))
            || std::time::Instant::now() >= deadline
        {
            return Err(SignedPackError::InventoryMismatch);
        }
        Ok(())
    }

    /// Authenticates the outer release manifest and copies its exact opened
    /// artifact descriptors into an owner-enforced private snapshot.
    ///
    /// The installed trust table is intentionally empty in this checkpoint,
    /// so this method returns `TrustUnavailable` before the first private write.
    pub fn authenticate_artifacts_and_snapshot(
        &self,
        cache: &AdmittedPrivateRoot,
    ) -> Result<AuthenticatedArtifactSnapshot, SignedPackError> {
        let deadline = std::time::Instant::now() + MAX_INSPECTION_TIME;
        verify_with_installed_trust(&self.manifest_bytes)?;
        self.revalidate_until(deadline)?;
        cache
            .revalidate_for_operation(deadline)
            .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
        let snapshot_name = format!("b3-{}", encode_hex(&self.outer_digest));
        let cached_names = cache
            .bounded_child_names_for_operation(MAX_TREE_ENTRIES, deadline)
            .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
        if cached_names.iter().any(|name| name == &snapshot_name) {
            let snapshot = cache
                .open_private_child_for_operation(&snapshot_name, deadline)
                .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
            verify_private_snapshot(&snapshot, &self.manifest, &self.outer_digest, deadline)?;
            return Ok(AuthenticatedArtifactSnapshot {
                manifest: self.manifest.clone(),
                outer_digest: self.outer_digest,
                root: snapshot,
            });
        }
        let snapshot = cache
            .create_private_child_for_operation(&snapshot_name, deadline)
            .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;

        let mut directories: BTreeMap<String, AdmittedPrivateRoot> = BTreeMap::new();
        let mut created_files = Vec::new();
        for path in expected_directories(&self.manifest) {
            let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let name = path.rsplit('/').next().ok_or(SignedPackError::InventoryMismatch)?;
            let parent = if parent_path.is_empty() {
                &snapshot
            } else {
                directories.get(parent_path).ok_or(SignedPackError::InventoryMismatch)?
            };
            let child = match parent.create_private_child_for_operation(name, deadline) {
                Ok(child) => child,
                Err(_) => {
                    let cleanup = cleanup_private_snapshot(
                        cache,
                        &snapshot_name,
                        &snapshot,
                        &directories,
                        &created_files,
                        deadline,
                    );
                    return Err(if cleanup.is_ok() {
                        SignedPackError::PrivateSnapshotUnavailable
                    } else {
                        SignedPackError::SnapshotCleanupUncertain
                    });
                }
            };
            directories.insert(path, child);
        }

        let mut hooks = NoopSnapshotHooks;
        let result = populate_private_snapshot(SnapshotPopulation {
            manifest: &self.manifest,
            outer_bytes: &self.manifest_bytes,
            outer_digest: &self.outer_digest,
            sources: &self.source_files,
            snapshot: &snapshot,
            directories: &directories,
            created_files: &mut created_files,
            deadline,
            hooks: &mut hooks,
        });
        if let Err(primary) = result {
            let clean = cleanup_private_snapshot(
                cache,
                &snapshot_name,
                &snapshot,
                &directories,
                &created_files,
                deadline,
            );
            return Err(if clean.is_ok() {
                primary
            } else {
                SignedPackError::SnapshotCleanupUncertain
            });
        }
        if let Err(primary) =
            verify_private_snapshot(&snapshot, &self.manifest, &self.outer_digest, deadline)
        {
            let clean = cleanup_private_snapshot(
                cache,
                &snapshot_name,
                &snapshot,
                &directories,
                &created_files,
                deadline,
            );
            return Err(if clean.is_ok() {
                primary
            } else {
                SignedPackError::SnapshotCleanupUncertain
            });
        }
        Ok(AuthenticatedArtifactSnapshot {
            manifest: self.manifest.clone(),
            outer_digest: self.outer_digest,
            root: snapshot,
        })
    }
}

/// Publisher-authenticated artifact inventory stored under a retained,
/// owner-enforced private directory capability.
///
/// This proves outer-manifest authenticity and the copied artifact bytes. It
/// does not establish runtime/platform compatibility, the Java/Node producer
/// manifest binding, or capture readiness, and it is not an executable-pack
/// admission type.
pub struct AuthenticatedArtifactSnapshot {
    manifest: PackManifest,
    outer_digest: [u8; 32],
    root: AdmittedPrivateRoot,
}

/// A runtime major selected by X-trace's compatibility policy after runtime detection.
///
/// The closed variants prevent a producer manifest from introducing a new runtime
/// version. The selected variant must still match the pack's signed declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMajor {
    /// Java 17.
    Java17,
    /// Java 21.
    Java21,
    /// Node.js 22.
    Node22,
    /// Node.js 24.
    Node24,
}

impl RuntimeMajor {
    const fn language(self) -> &'static str {
        match self {
            Self::Java17 | Self::Java21 => "java",
            Self::Node22 | Self::Node24 => "node",
        }
    }

    const fn number(self) -> u32 {
        match self {
            Self::Java17 => 17,
            Self::Java21 => 21,
            Self::Node22 => 22,
            Self::Node24 => 24,
        }
    }
}

/// Publisher-authenticated pack bytes admitted for one core-selected runtime target.
///
/// This type is nonconstructible outside this module and retains the private
/// artifact snapshot whose full signed inventory was revalidated during admission.
/// It records compatibility facts only; it does not imply daemon readiness or
/// authorize process launch by itself.
pub struct VerifiedSignedPack {
    snapshot: AuthenticatedArtifactSnapshot,
    runtime_major: RuntimeMajor,
    inner_manifest_digest: [u8; 32],
}

impl std::fmt::Debug for VerifiedSignedPack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedSignedPack")
            .field("compatibility_verified", &true)
            .field("runtime_major", &self.runtime_major)
            .field("inner_manifest_bound", &true)
            .finish_non_exhaustive()
    }
}

impl VerifiedSignedPack {
    /// Signed pack declarations whose complete private inventory remains retained.
    #[must_use]
    pub fn manifest(&self) -> &PackManifest {
        self.snapshot.manifest()
    }

    /// Selected runtime major checked against core policy and signed pack bounds.
    #[must_use]
    pub const fn runtime_major(&self) -> RuntimeMajor {
        self.runtime_major
    }

    /// BLAKE3 digest of the core-selected inner producer manifest artifact.
    #[must_use]
    pub const fn inner_manifest_digest(&self) -> &[u8; 32] {
        &self.inner_manifest_digest
    }

    /// Revalidates all retained signed artifact bytes before a later consumer uses them.
    pub fn revalidate(&self) -> Result<(), SignedPackError> {
        self.snapshot.revalidate()?;
        let expected = known_inner_manifest_digest(self.snapshot.manifest())?;
        if expected != self.inner_manifest_digest {
            return Err(SignedPackError::SnapshotIncomplete);
        }
        Ok(())
    }
}

impl std::fmt::Debug for AuthenticatedArtifactSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedArtifactSnapshot")
            .field("pack", &self.manifest.pack_name())
            .field("publisher_authenticated", &true)
            .field("private_snapshot", &true)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedArtifactSnapshot {
    /// Signed declarations whose inventory bytes are present in the private snapshot.
    /// Compatibility and inner producer-manifest bindings remain separate checks.
    #[must_use]
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }

    /// Digest of the authenticated outer manifest, distinct from XTP producer manifests.
    #[must_use]
    pub const fn outer_manifest_digest(&self) -> &[u8; 32] {
        &self.outer_digest
    }

    /// Informational launch root; consumers must retain this snapshot object.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        self.root.path()
    }

    /// Revalidates the retained private snapshot and its complete closed inventory.
    pub fn revalidate(&self) -> Result<(), SignedPackError> {
        verify_private_snapshot(
            &self.root,
            &self.manifest,
            &self.outer_digest,
            std::time::Instant::now() + MAX_INSPECTION_TIME,
        )
    }

    /// Revalidates this authenticated snapshot and admits its declarations for one
    /// core-selected runtime major and the current supported host platform.
    ///
    /// The caller must select `runtime_major` from X-trace's runtime detection and
    /// compatibility policy. Producer declarations can only accept or reject that
    /// selection; they cannot choose a runtime or add a supported major. The
    /// installed trust table remains the only publisher-authentication authority.
    pub fn verify_for_runtime(
        self,
        runtime_major: RuntimeMajor,
    ) -> Result<VerifiedSignedPack, SignedPackError> {
        self.revalidate()?;
        let (os, arch) = current_platform().ok_or(SignedPackError::UnsupportedManifest)?;
        verify_compatibility_declarations(&self.manifest, runtime_major, os, arch)?;
        let inner_manifest_digest = known_inner_manifest_digest(&self.manifest)?;
        Ok(VerifiedSignedPack { snapshot: self, runtime_major, inner_manifest_digest })
    }
}

fn current_platform() -> Option<(&'static str, &'static str)> {
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        _ => return None,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        _ => return None,
    };
    Some((os, arch))
}

fn verify_compatibility_declarations(
    manifest: &PackManifest,
    runtime_major: RuntimeMajor,
    os: &str,
    arch: &str,
) -> Result<(), SignedPackError> {
    if manifest.pack_version() != CORE_RELEASE_VERSION
        || manifest.release_range() != (CORE_RELEASE_VERSION, CORE_RELEASE_VERSION)
        || manifest.pack_name() != runtime_major.language()
        || manifest.runtime_language() != runtime_major.language()
        || !manifest.supports_platform(os, arch)
    {
        return Err(SignedPackError::UnsupportedManifest);
    }

    let protocol = (xtrace_protocol::envelope::PROTOCOL_MAJOR, xtrace_protocol::envelope::PROTOCOL_MINOR);
    let (protocol_minimum, protocol_maximum) = manifest.protocol_range();
    if protocol < protocol_minimum || protocol > protocol_maximum {
        return Err(SignedPackError::UnsupportedManifest);
    }

    let major = runtime_major.number();
    let (minimum, maximum) = manifest.runtime_range();
    if major < minimum || major >= maximum
        || !manifest.tested_runtime_majors().contains(&major)
    {
        return Err(SignedPackError::UnsupportedManifest);
    }
    Ok(())
}

fn known_inner_manifest_digest(manifest: &PackManifest) -> Result<[u8; 32], SignedPackError> {
    // Java's nested manifest is verified against the exact runtime JAR inventory
    // during public inspection, then carried by the outer signed artifact list.
    // Node's installed-pack producer manifest contract has not been defined yet.
    let path = match manifest.pack_name() {
        "java" => "agent/manifest.sha256",
        _ => return Err(SignedPackError::UnsupportedManifest),
    };
    manifest
        .artifact_digests()
        .iter()
        .find(|artifact| artifact.path == path)
        .map(|artifact| artifact.digest)
        .ok_or(SignedPackError::UnsupportedManifest)
}

/// Opens a pack root without following its final path component and verifies
/// the closed file/directory inventory against the canonical outer manifest.
pub fn inspect_pack(path: &Path) -> Result<InspectedPack, SignedPackError> {
    let deadline = std::time::Instant::now() + MAX_INSPECTION_TIME;
    let opened = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| SignedPackError::InventoryMismatch)?;
    let root_metadata = opened.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    if !root_metadata.is_dir() {
        return Err(SignedPackError::InventoryMismatch);
    }
    let root_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| SignedPackError::InventoryMismatch)?.join(path)
    };
    let named_metadata =
        std::fs::symlink_metadata(&root_path).map_err(|_| SignedPackError::InventoryMismatch)?;
    if named_metadata.file_type().is_symlink()
        || !named_metadata.is_dir()
        || !Identity::from_metadata(&root_metadata)
            .same_object(Identity::from_metadata(&named_metadata))
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    let manifest_bytes = read_named_file(&opened, OUTER_MANIFEST, MAX_MANIFEST_BYTES, deadline)?;
    let manifest = parse_canonical_manifest(&manifest_bytes)?;
    if build_hash(manifest.artifact_digests())? != *manifest.build_hash() {
        return Err(SignedPackError::BuildHashMismatch);
    }
    let actual = scan_tree(&opened, deadline)?;
    compare_inventory(&manifest, &actual, *blake3::hash(&manifest_bytes).as_bytes())?;
    verify_inner_manifests(&manifest, &actual)?;
    let mut source_files = BTreeMap::new();
    for (path, mut scanned) in actual.files {
        let (file, identity) = scanned.source.take().ok_or(SignedPackError::InventoryMismatch)?;
        source_files.insert(path, (file, identity, scanned.digest));
    }
    let named_after =
        std::fs::symlink_metadata(&root_path).map_err(|_| SignedPackError::InventoryMismatch)?;
    let opened_after = opened.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    if named_after.file_type().is_symlink()
        || !named_after.is_dir()
        || !Identity::from_metadata(&named_after)
            .same_object(Identity::from_metadata(&opened_after))
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    if std::time::Instant::now() >= deadline {
        return Err(SignedPackError::ResourceLimit);
    }
    let outer_digest = *blake3::hash(&manifest_bytes).as_bytes();
    Ok(InspectedPack {
        root_path,
        root: opened,
        manifest_bytes,
        manifest,
        outer_digest,
        source_files,
    })
}

fn compare_inventory(
    manifest: &PackManifest,
    actual: &ScannedTree,
    outer_manifest_digest: [u8; 32],
) -> Result<(), SignedPackError> {
    let expected_files = manifest
        .artifact_digests()
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.digest))
        .collect::<BTreeMap<_, _>>();
    if actual.files.len() != expected_files.len() + 1
        || actual.files.get(OUTER_MANIFEST).is_none_or(|file| file.digest != outer_manifest_digest)
        || actual
            .files
            .keys()
            .any(|path| !expected_files.contains_key(path.as_str()) && path != OUTER_MANIFEST)
        || expected_files.iter().any(|(path, digest)| {
            actual.files.get(*path).is_none_or(|entry| entry.digest != *digest)
        })
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    let expected_directories = expected_directories(manifest);
    if actual.directories != expected_directories {
        return Err(SignedPackError::InventoryMismatch);
    }
    Ok(())
}

fn expected_directories(manifest: &PackManifest) -> BTreeSet<String> {
    manifest
        .artifact_digests()
        .iter()
        .flat_map(|artifact| {
            let components = artifact.path.split('/').collect::<Vec<_>>();
            let mut parents = Vec::new();
            let mut prefix = String::new();
            for component in components.iter().take(components.len().saturating_sub(1)) {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                parents.push(prefix.clone());
            }
            parents
        })
        .collect()
}

trait SnapshotHooks {
    fn after_copy_chunk(
        &mut self,
        _parent: &AdmittedPrivateRoot,
        _name: &str,
        _destination: &File,
        _copied: u64,
    ) -> Result<(), SignedPackError> {
        Ok(())
    }

    fn before_destination_rehash(
        &mut self,
        _parent: &AdmittedPrivateRoot,
        _name: &str,
        _destination: &File,
    ) -> Result<(), SignedPackError> {
        Ok(())
    }
}

struct NoopSnapshotHooks;

impl SnapshotHooks for NoopSnapshotHooks {}

struct SnapshotPopulation<'a> {
    manifest: &'a PackManifest,
    outer_bytes: &'a [u8],
    outer_digest: &'a [u8; 32],
    sources: &'a BTreeMap<String, (File, Identity, [u8; 32])>,
    snapshot: &'a AdmittedPrivateRoot,
    directories: &'a BTreeMap<String, AdmittedPrivateRoot>,
    created_files: &'a mut Vec<(String, File)>,
    deadline: std::time::Instant,
    hooks: &'a mut dyn SnapshotHooks,
}

fn populate_private_snapshot(context: SnapshotPopulation<'_>) -> Result<(), SignedPackError> {
    let SnapshotPopulation {
        manifest,
        outer_bytes,
        outer_digest,
        sources,
        snapshot,
        directories,
        created_files,
        deadline,
        hooks,
    } = context;
    let mut expected = manifest
        .artifact_digests()
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact.digest))
        .collect::<BTreeMap<_, _>>();
    expected.insert(OUTER_MANIFEST.to_owned(), *outer_digest);
    let mut total_bytes = 0_u64;
    for (relative, expected_digest) in expected {
        if std::time::Instant::now() >= deadline {
            return Err(SignedPackError::ResourceLimit);
        }
        let (source, source_identity, source_digest) =
            sources.get(&relative).ok_or(SignedPackError::InventoryMismatch)?;
        if source_digest != &expected_digest {
            return Err(SignedPackError::InventoryMismatch);
        }
        let parent_path = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
        let name = relative.rsplit('/').next().ok_or(SignedPackError::InventoryMismatch)?;
        let parent = if parent_path.is_empty() {
            snapshot
        } else {
            directories.get(parent_path).ok_or(SignedPackError::InventoryMismatch)?
        };
        let destination = parent
            .create_private_file_for_operation(name, deadline)
            .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
        created_files.push((relative.clone(), destination));
        let destination =
            &created_files.last().ok_or(SignedPackError::PrivateSnapshotUnavailable)?.1;
        copy_and_verify_source(SnapshotCopy {
            source,
            source_identity: *source_identity,
            expected_digest,
            outer_bytes,
            outer_manifest: relative == OUTER_MANIFEST,
            parent,
            name,
            destination,
            total_bytes: &mut total_bytes,
            deadline,
            hooks: &mut *hooks,
        })?;
    }
    Ok(())
}

struct SnapshotCopy<'a> {
    source: &'a File,
    source_identity: Identity,
    expected_digest: [u8; 32],
    outer_bytes: &'a [u8],
    outer_manifest: bool,
    parent: &'a AdmittedPrivateRoot,
    name: &'a str,
    destination: &'a File,
    total_bytes: &'a mut u64,
    deadline: std::time::Instant,
    hooks: &'a mut dyn SnapshotHooks,
}

fn copy_and_verify_source(context: SnapshotCopy<'_>) -> Result<(), SignedPackError> {
    let SnapshotCopy {
        source,
        source_identity,
        expected_digest,
        outer_bytes,
        outer_manifest,
        parent,
        name,
        destination,
        total_bytes,
        deadline,
        hooks,
    } = context;
    let source_before = source.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    if Identity::from_metadata(&source_before) != source_identity
        || !source_before.is_file()
        || source_identity.links != 1
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    let limit = if outer_manifest { MAX_MANIFEST_BYTES } else { MAX_ARTIFACT_BYTES };
    let remaining =
        MAX_TOTAL_BYTES.checked_sub(*total_bytes).ok_or(SignedPackError::ResourceLimit)?;
    if source_identity.size > limit || source_identity.size > remaining {
        return Err(SignedPackError::ResourceLimit);
    }
    let mut source_reader = source;
    source_reader.seek(SeekFrom::Start(0)).map_err(|_| SignedPackError::InventoryMismatch)?;
    let mut destination_writer =
        destination.try_clone().map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(SignedPackError::ResourceLimit);
        }
        let count =
            source_reader.read(&mut buffer).map_err(|_| SignedPackError::InventoryMismatch)?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).ok_or(SignedPackError::ResourceLimit)?;
        if copied > limit || copied > remaining {
            return Err(SignedPackError::ResourceLimit);
        }
        destination_writer
            .write_all(&buffer[..count])
            .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
        hasher.update(&buffer[..count]);
        hooks.after_copy_chunk(parent, name, destination, copied)?;
    }
    *total_bytes = total_bytes.checked_add(copied).ok_or(SignedPackError::ResourceLimit)?;
    let source_after = source.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    if Identity::from_metadata(&source_after) != source_identity
        || copied != source_identity.size
        || *hasher.finalize().as_bytes() != expected_digest
        || (outer_manifest && source_digest_mismatch(outer_bytes, expected_digest))
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    destination_writer.sync_all().map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    parent
        .validate_file_binding_for_operation(name, destination, true, deadline)
        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    hooks.before_destination_rehash(parent, name, destination)?;
    let expected_identity =
        destination.metadata().map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    verify_private_file(
        parent,
        name,
        expected_digest,
        limit,
        MAX_TOTAL_BYTES,
        Some(Identity::from_metadata(&expected_identity)),
        deadline,
    )?;
    parent.sync_for_operation(deadline).map_err(|_| SignedPackError::PrivateSnapshotUnavailable)
}

fn source_digest_mismatch(outer_bytes: &[u8], expected_digest: [u8; 32]) -> bool {
    *blake3::hash(outer_bytes).as_bytes() != expected_digest
}

fn verify_private_file(
    parent: &AdmittedPrivateRoot,
    name: &str,
    expected_digest: [u8; 32],
    maximum_bytes: u64,
    maximum_total_remaining: u64,
    expected_identity: Option<Identity>,
    deadline: std::time::Instant,
) -> Result<u64, SignedPackError> {
    let file = parent
        .open_regular_file_for_operation(name, deadline)
        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    let before = file.metadata().map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    let before_identity = Identity::from_metadata(&before);
    if before.len() > maximum_total_remaining {
        return Err(SignedPackError::ResourceLimit);
    }
    if !before.is_file()
        || before.len() > maximum_bytes
        || before.nlink() != 1
        || expected_identity.is_some_and(|expected| expected != before_identity)
    {
        return Err(SignedPackError::SnapshotIncomplete);
    }
    let mut reader = &file;
    let mut consumed = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(SignedPackError::ResourceLimit);
        }
        let count = reader.read(&mut buffer).map_err(|_| SignedPackError::SnapshotIncomplete)?;
        if count == 0 {
            break;
        }
        consumed = consumed.checked_add(count as u64).ok_or(SignedPackError::ResourceLimit)?;
        if consumed > maximum_bytes || consumed > maximum_total_remaining {
            return Err(SignedPackError::ResourceLimit);
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    if before_identity != Identity::from_metadata(&after)
        || expected_identity.is_some_and(|expected| expected != Identity::from_metadata(&after))
        || consumed != after.len()
        || *hasher.finalize().as_bytes() != expected_digest
    {
        return Err(SignedPackError::SnapshotIncomplete);
    }
    parent
        .validate_file_binding_for_operation(name, &file, false, deadline)
        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    Ok(consumed)
}

fn verify_private_snapshot(
    snapshot: &AdmittedPrivateRoot,
    manifest: &PackManifest,
    outer_digest: &[u8; 32],
    deadline: std::time::Instant,
) -> Result<(), SignedPackError> {
    verify_private_snapshot_with_total_limit(
        snapshot,
        manifest,
        outer_digest,
        MAX_TOTAL_BYTES,
        deadline,
    )
}

fn verify_private_snapshot_with_total_limit(
    snapshot: &AdmittedPrivateRoot,
    manifest: &PackManifest,
    outer_digest: &[u8; 32],
    maximum_total_bytes: u64,
    deadline: std::time::Instant,
) -> Result<(), SignedPackError> {
    snapshot
        .revalidate_for_operation(deadline)
        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
    let directories = expected_directories(manifest);
    let mut directory_caps = BTreeMap::new();
    for path in &directories {
        let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        let name = path.rsplit('/').next().ok_or(SignedPackError::SnapshotIncomplete)?;
        let parent = if parent_path.is_empty() {
            snapshot
        } else {
            directory_caps.get(parent_path).ok_or(SignedPackError::SnapshotIncomplete)?
        };
        let cap = parent
            .open_private_child_for_operation(name, deadline)
            .map_err(|_| SignedPackError::SnapshotIncomplete)?;
        directory_caps.insert(path.clone(), cap);
    }
    let mut expected_files = manifest
        .artifact_digests()
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact.digest))
        .collect::<BTreeMap<_, _>>();
    expected_files.insert(OUTER_MANIFEST.to_owned(), *outer_digest);
    let mut expected_children = BTreeMap::<String, BTreeSet<String>>::new();
    expected_children.insert(String::new(), BTreeSet::new());
    for path in &directories {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        expected_children
            .entry(parent.to_owned())
            .or_default()
            .insert(path.rsplit('/').next().ok_or(SignedPackError::SnapshotIncomplete)?.to_owned());
        expected_children.entry(path.clone()).or_default();
    }
    for path in expected_files.keys() {
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        expected_children
            .entry(parent.to_owned())
            .or_default()
            .insert(path.rsplit('/').next().ok_or(SignedPackError::SnapshotIncomplete)?.to_owned());
    }
    for (path, expected_names) in &expected_children {
        let cap = if path.is_empty() {
            snapshot
        } else {
            directory_caps.get(path).ok_or(SignedPackError::SnapshotIncomplete)?
        };
        let names = cap
            .bounded_child_names_for_operation(MAX_TREE_ENTRIES, deadline)
            .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
        if names.len() != expected_names.len()
            || names.iter().any(|name| !expected_names.contains(name))
        {
            return Err(SignedPackError::SnapshotIncomplete);
        }
    }
    let mut total_bytes = 0_u64;
    for (path, digest) in expected_files {
        let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        let name = path.rsplit('/').next().ok_or(SignedPackError::SnapshotIncomplete)?;
        let parent = if parent_path.is_empty() {
            snapshot
        } else {
            directory_caps.get(parent_path).ok_or(SignedPackError::SnapshotIncomplete)?
        };
        let maximum = if path == OUTER_MANIFEST { MAX_MANIFEST_BYTES } else { MAX_ARTIFACT_BYTES };
        let remaining =
            maximum_total_bytes.checked_sub(total_bytes).ok_or(SignedPackError::ResourceLimit)?;
        let read = verify_private_file(parent, name, digest, maximum, remaining, None, deadline)?;
        total_bytes = total_bytes.checked_add(read).ok_or(SignedPackError::ResourceLimit)?;
    }
    snapshot
        .revalidate_for_operation(deadline)
        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)
}

fn cleanup_private_snapshot(
    cache: &AdmittedPrivateRoot,
    snapshot_name: &str,
    snapshot: &AdmittedPrivateRoot,
    directories: &BTreeMap<String, AdmittedPrivateRoot>,
    created_files: &[(String, File)],
    deadline: std::time::Instant,
) -> Result<(), SignedPackError> {
    let mut cleaned = true;
    for (relative, file) in created_files.iter().rev() {
        let parent_path = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
        let name = relative.rsplit('/').next().ok_or(SignedPackError::SnapshotCleanupUncertain)?;
        let parent = if parent_path.is_empty() {
            snapshot
        } else {
            directories.get(parent_path).ok_or(SignedPackError::SnapshotCleanupUncertain)?
        };
        if parent.remove_private_file_if_matches_for_operation(name, file, deadline).is_err() {
            cleaned = false;
        }
    }
    let mut paths = directories.keys().cloned().collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
    for path in paths {
        let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        let name = path.rsplit('/').next().ok_or(SignedPackError::SnapshotCleanupUncertain)?;
        let parent = if parent_path.is_empty() {
            snapshot
        } else {
            directories.get(parent_path).ok_or(SignedPackError::SnapshotCleanupUncertain)?
        };
        let expected = directories.get(&path).ok_or(SignedPackError::SnapshotCleanupUncertain)?;
        if parent.remove_private_child_for_operation(name, expected, deadline).is_err() {
            cleaned = false;
        }
    }
    if cache.remove_private_child_for_operation(snapshot_name, snapshot, deadline).is_err() {
        cleaned = false;
    }
    if cleaned { Ok(()) } else { Err(SignedPackError::SnapshotCleanupUncertain) }
}

fn verify_inner_manifests(
    manifest: &PackManifest,
    actual: &ScannedTree,
) -> Result<(), SignedPackError> {
    if manifest.pack_name() != "java" {
        return Ok(());
    }
    let required = [
        "pack.manifest",
        "attach/xtrace-attach.jar",
        "agent/manifest.sha256",
        "agent/xtrace-java-agent.jar",
    ];
    if required.iter().any(|path| !actual.files.contains_key(*path))
        || !actual
            .files
            .keys()
            .any(|path| path.starts_with("agent/runtime/") && path.ends_with(".jar"))
        || actual.directories
            != ["agent", "agent/runtime", "attach"].into_iter().map(str::to_owned).collect()
    {
        return Err(SignedPackError::InventoryMismatch);
    }

    let outer_bytes = actual
        .files
        .get("pack.manifest")
        .and_then(|file| file.small_contents.as_deref())
        .ok_or(SignedPackError::InventoryMismatch)?;
    let outer_rows = parse_sha256_manifest(outer_bytes)?;
    if outer_rows.len() + 2 != actual.files.len()
        || outer_rows.keys().any(|path| {
            path == "pack.manifest" || path == OUTER_MANIFEST || !actual.files.contains_key(path)
        })
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    for (path, digest) in &outer_rows {
        if actual.files.get(path).is_none_or(|file| file.sha256 != *digest) {
            return Err(SignedPackError::InventoryMismatch);
        }
    }

    let agent_bytes = actual
        .files
        .get("agent/manifest.sha256")
        .and_then(|file| file.small_contents.as_deref())
        .ok_or(SignedPackError::InventoryMismatch)?;
    let agent_rows = parse_sha256_manifest(agent_bytes)?;
    let agent_files = actual
        .files
        .keys()
        .filter_map(|path| {
            path.strip_prefix("agent/")
                .filter(|relative| relative.ends_with(".jar"))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    if agent_rows.keys().cloned().collect::<BTreeSet<_>>() != agent_files {
        return Err(SignedPackError::InventoryMismatch);
    }
    for (relative, digest) in &agent_rows {
        let path = format!("agent/{relative}");
        if actual.files.get(&path).is_none_or(|file| file.sha256 != *digest) {
            return Err(SignedPackError::InventoryMismatch);
        }
    }
    Ok(())
}

fn parse_sha256_manifest(bytes: &[u8]) -> Result<BTreeMap<String, [u8; 32]>, SignedPackError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES || !bytes.ends_with(b"\n") {
        return Err(SignedPackError::InventoryMismatch);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SignedPackError::InventoryMismatch)?;
    let body = text.strip_suffix('\n').ok_or(SignedPackError::InventoryMismatch)?;
    let mut rows = BTreeMap::new();
    let mut previous: Option<String> = None;
    for (index, line) in body.split('\n').enumerate() {
        if index >= MAX_INNER_MANIFEST_ENTRIES {
            return Err(SignedPackError::ResourceLimit);
        }
        if line.is_empty() || line.contains('\r') {
            return Err(SignedPackError::InventoryMismatch);
        }
        let (hex, path) = line.split_once("  ").ok_or(SignedPackError::InventoryMismatch)?;
        if hex.len() != 64
            || !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !valid_relative_path(path)
            || previous.as_deref().is_some_and(|prior| prior >= path)
        {
            return Err(SignedPackError::InventoryMismatch);
        }
        let mut digest = [0_u8; 32];
        for (offset, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let high = sha256_nibble(pair[0])?;
            let low = sha256_nibble(pair[1])?;
            digest[offset] = (high << 4) | low;
        }
        previous = Some(path.to_owned());
        rows.insert(path.to_owned(), digest);
    }
    if rows.is_empty() {
        return Err(SignedPackError::InventoryMismatch);
    }
    Ok(rows)
}

fn sha256_nibble(byte: u8) -> Result<u8, SignedPackError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SignedPackError::InventoryMismatch),
    }
}

struct ScannedTree {
    files: BTreeMap<String, ScannedFile>,
    directories: BTreeSet<String>,
}

fn scan_tree(root: &File, deadline: std::time::Instant) -> Result<ScannedTree, SignedPackError> {
    let mut tree = ScannedTree { files: BTreeMap::new(), directories: BTreeSet::new() };
    let mut entries = 0_usize;
    let mut total_bytes = 0_u64;
    let mut folded_paths = BTreeSet::new();
    scan_directory(
        root,
        "",
        &mut tree,
        &mut entries,
        &mut total_bytes,
        &mut folded_paths,
        deadline,
    )?;
    Ok(tree)
}

fn scan_directory(
    directory: &File,
    prefix: &str,
    tree: &mut ScannedTree,
    entries: &mut usize,
    total_bytes: &mut u64,
    folded_paths: &mut BTreeSet<String>,
    deadline: std::time::Instant,
) -> Result<(), SignedPackError> {
    let stream_fd = rustix::fs::openat(
        directory,
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| SignedPackError::InventoryMismatch)?;
    let stream = rustix::fs::Dir::new(stream_fd).map_err(|_| SignedPackError::InventoryMismatch)?;
    for entry in stream {
        if std::time::Instant::now() >= deadline {
            return Err(SignedPackError::ResourceLimit);
        }
        let entry = entry.map_err(|_| SignedPackError::InventoryMismatch)?;
        let name = entry.file_name().to_str().map_err(|_| SignedPackError::InventoryMismatch)?;
        if name == "." || name == ".." {
            continue;
        }
        *entries = entries.checked_add(1).ok_or(SignedPackError::ResourceLimit)?;
        if *entries > MAX_TREE_ENTRIES {
            return Err(SignedPackError::ResourceLimit);
        }
        let relative = if prefix.is_empty() { name.to_owned() } else { format!("{prefix}/{name}") };
        if relative.split('/').count() > MAX_PATH_COMPONENTS
            || (!relative.eq_ignore_ascii_case(OUTER_MANIFEST) && !valid_relative_path(&relative))
            || (relative.eq_ignore_ascii_case(OUTER_MANIFEST) && relative != OUTER_MANIFEST)
        {
            return Err(SignedPackError::InventoryMismatch);
        }
        if !folded_paths.insert(relative.to_ascii_lowercase()) {
            return Err(SignedPackError::InventoryMismatch);
        }
        let name_c = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| SignedPackError::InventoryMismatch)?;
        let named =
            rustix::fs::statat(directory, name_c.as_c_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| SignedPackError::InventoryMismatch)?;
        match rustix::fs::FileType::from_raw_mode(named.st_mode) {
            rustix::fs::FileType::Directory => {
                if relative == OUTER_MANIFEST {
                    return Err(SignedPackError::InventoryMismatch);
                }
                let child = rustix::fs::openat(
                    directory,
                    name_c.as_c_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(|_| SignedPackError::InventoryMismatch)?;
                let opened = child.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
                if !opened.is_dir() || opened.dev() != named.st_dev || opened.ino() != named.st_ino
                {
                    return Err(SignedPackError::InventoryMismatch);
                }
                tree.directories.insert(relative.clone());
                scan_directory(
                    &child,
                    &relative,
                    tree,
                    entries,
                    total_bytes,
                    folded_paths,
                    deadline,
                )?;
                let named_after = rustix::fs::statat(
                    directory,
                    name_c.as_c_str(),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_| SignedPackError::InventoryMismatch)?;
                if named_after.st_dev != opened.dev()
                    || named_after.st_ino != opened.ino()
                    || rustix::fs::FileType::from_raw_mode(named_after.st_mode)
                        != rustix::fs::FileType::Directory
                {
                    return Err(SignedPackError::InventoryMismatch);
                }
            }
            rustix::fs::FileType::RegularFile => {
                let file = rustix::fs::openat(
                    directory,
                    name_c.as_c_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(|_| SignedPackError::InventoryMismatch)?;
                let remaining_total = MAX_TOTAL_BYTES
                    .checked_sub(*total_bytes)
                    .ok_or(SignedPackError::ResourceLimit)?;
                let scanned = scan_regular_file(
                    &file,
                    ScanFileContext {
                        parent: directory,
                        name: name_c.as_c_str(),
                        named_device: named.st_dev,
                        named_inode: named.st_ino,
                        outer_manifest: relative == OUTER_MANIFEST,
                        capture_small: matches!(
                            relative.as_str(),
                            "pack.manifest" | "agent/manifest.sha256"
                        ),
                        maximum_total_remaining: remaining_total,
                        deadline,
                    },
                    total_bytes,
                )?;
                if tree.files.insert(relative, scanned).is_some() {
                    return Err(SignedPackError::InventoryMismatch);
                }
            }
            _ => return Err(SignedPackError::InventoryMismatch),
        }
    }
    Ok(())
}

struct ScanFileContext<'a> {
    parent: &'a File,
    name: &'a std::ffi::CStr,
    named_device: u64,
    named_inode: u64,
    outer_manifest: bool,
    capture_small: bool,
    maximum_total_remaining: u64,
    deadline: std::time::Instant,
}

fn scan_regular_file(
    file: &File,
    context: ScanFileContext<'_>,
    total_bytes: &mut u64,
) -> Result<ScannedFile, SignedPackError> {
    let before = file.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    let identity = Identity::from_metadata(&before);
    let limit = if context.outer_manifest { MAX_MANIFEST_BYTES } else { MAX_ARTIFACT_BYTES };
    if context.capture_small && identity.size > MAX_MANIFEST_BYTES {
        return Err(SignedPackError::ResourceLimit);
    }
    if !before.is_file()
        || identity.device != context.named_device
        || identity.inode != context.named_inode
        || identity.links != 1
        || identity.size > limit
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    *total_bytes = total_bytes.checked_add(identity.size).ok_or(SignedPackError::ResourceLimit)?;
    if *total_bytes > MAX_TOTAL_BYTES {
        return Err(SignedPackError::ResourceLimit);
    }
    let mut reader = file;
    let mut hasher = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let capture_capacity = if context.capture_small {
        Some(usize::try_from(identity.size).map_err(|_| SignedPackError::ResourceLimit)?)
    } else {
        None
    };
    let mut small_contents = capture_capacity.map(Vec::with_capacity);
    let mut consumed = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        if std::time::Instant::now() >= context.deadline {
            return Err(SignedPackError::ResourceLimit);
        }
        let count = reader.read(&mut buffer).map_err(|_| SignedPackError::InventoryMismatch)?;
        if count == 0 {
            break;
        }
        consumed = consumed.checked_add(count as u64).ok_or(SignedPackError::ResourceLimit)?;
        if consumed > limit || consumed > context.maximum_total_remaining {
            return Err(SignedPackError::ResourceLimit);
        }
        hasher.update(&buffer[..count]);
        sha256.update(&buffer[..count]);
        if let Some(contents) = &mut small_contents {
            if contents.len().saturating_add(count) as u64 > MAX_MANIFEST_BYTES {
                return Err(SignedPackError::ResourceLimit);
            }
            contents.extend_from_slice(&buffer[..count]);
        }
    }
    let after = file.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    let after_identity = Identity::from_metadata(&after);
    let named_after =
        rustix::fs::statat(context.parent, context.name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| SignedPackError::InventoryMismatch)?;
    reader.seek(SeekFrom::Start(0)).map_err(|_| SignedPackError::InventoryMismatch)?;
    if !after_identity.stable_file(identity)
        || after_identity.size != consumed
        || named_after.st_dev != identity.device
        || named_after.st_ino != identity.inode
        || named_after.st_nlink != identity.links
        || rustix::fs::FileType::from_raw_mode(named_after.st_mode)
            != rustix::fs::FileType::RegularFile
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    Ok(ScannedFile {
        digest: *hasher.finalize().as_bytes(),
        sha256: sha256.finalize().into(),
        small_contents,
        source: Some((file.try_clone().map_err(|_| SignedPackError::InventoryMismatch)?, identity)),
    })
}

fn read_named_file(
    root: &File,
    name: &str,
    maximum: u64,
    deadline: std::time::Instant,
) -> Result<Vec<u8>, SignedPackError> {
    let file = rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| SignedPackError::InventoryMismatch)?;
    let before = file.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > maximum {
        return Err(SignedPackError::InventoryMismatch);
    }
    let named = rustix::fs::statat(root, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| SignedPackError::InventoryMismatch)?;
    if named.st_dev != before.dev() || named.st_ino != before.ino() || named.st_nlink != 1 {
        return Err(SignedPackError::InventoryMismatch);
    }
    let mut output = Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| SignedPackError::ResourceLimit)?,
    );
    let mut reader = (&file).take(maximum.saturating_add(1));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(SignedPackError::ResourceLimit);
        }
        let count = reader.read(&mut buffer).map_err(|_| SignedPackError::InventoryMismatch)?;
        if count == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..count]);
        if output.len() as u64 > maximum {
            return Err(SignedPackError::ResourceLimit);
        }
    }
    let after = file.metadata().map_err(|_| SignedPackError::InventoryMismatch)?;
    let named_after = rustix::fs::statat(root, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| SignedPackError::InventoryMismatch)?;
    if output.len() as u64 > maximum
        || Identity::from_metadata(&before) != Identity::from_metadata(&after)
        || output.len() as u64 != after.len()
        || named.st_dev != after.dev()
        || named.st_ino != after.ino()
        || named_after.st_dev != after.dev()
        || named_after.st_ino != after.ino()
        || named_after.st_nlink != after.nlink()
        || rustix::fs::FileType::from_raw_mode(named_after.st_mode)
            != rustix::fs::FileType::RegularFile
        || std::time::Instant::now() >= deadline
    {
        return Err(SignedPackError::InventoryMismatch);
    }
    Ok(output)
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.is_ascii()
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_pack::{ArtifactDigest, build_hash};
    use std::os::unix::fs::PermissionsExt as _;

    fn private_scratch() -> AdmittedPrivateRoot {
        let path = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required");
        AdmittedPrivateRoot::open(Path::new(&path)).expect("admitted private test scratch")
    }

    fn unique_name(stem: &str) -> String {
        let ticks = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        format!("{stem}-{}-{ticks}", std::process::id())
    }

    fn public_fixture(payload: &[u8]) -> (tempfile::TempDir, InspectedPack) {
        let source = tempfile::tempdir().expect("public pack fixture directory");
        let payload_path = source.path().join("payload.bin");
        std::fs::write(&payload_path, payload).expect("public artifact fixture");
        let artifacts = [ArtifactDigest {
            path: "payload.bin".to_owned(),
            digest: *blake3::hash(payload).as_bytes(),
        }];
        std::fs::write(source.path().join(OUTER_MANIFEST), make_manifest(&artifacts))
            .expect("public manifest fixture");
        let inspected = inspect_pack(source.path()).expect("closed public pack fixture");
        (source, inspected)
    }

    fn private_snapshot(
        cache: &AdmittedPrivateRoot,
        manifest: &PackManifest,
    ) -> (String, AdmittedPrivateRoot, BTreeMap<String, AdmittedPrivateRoot>) {
        let name = unique_name("pack-snapshot-test");
        let snapshot = cache.create_private_child(&name).expect("private snapshot fixture");
        let mut directories: BTreeMap<String, AdmittedPrivateRoot> = BTreeMap::new();
        for path in expected_directories(manifest) {
            let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            let basename = path.rsplit('/').next().expect("directory basename");
            let parent = if parent_path.is_empty() {
                &snapshot
            } else {
                directories.get(parent_path).expect("previous parent capability")
            };
            let child = parent.create_private_child(basename).expect("nested directory fixture");
            directories.insert(path, child);
        }
        (name, snapshot, directories)
    }

    fn populate_fixture(
        inspected: &InspectedPack,
        snapshot: &AdmittedPrivateRoot,
        directories: &BTreeMap<String, AdmittedPrivateRoot>,
        created_files: &mut Vec<(String, File)>,
        hooks: &mut dyn SnapshotHooks,
    ) -> Result<(), SignedPackError> {
        populate_private_snapshot(SnapshotPopulation {
            manifest: &inspected.manifest,
            outer_bytes: &inspected.manifest_bytes,
            outer_digest: &inspected.outer_digest,
            sources: &inspected.source_files,
            snapshot,
            directories,
            created_files,
            deadline: std::time::Instant::now() + MAX_INSPECTION_TIME,
            hooks,
        })
    }

    type ChunkFault =
        Box<dyn FnMut(&AdmittedPrivateRoot, &str, &File, u64) -> Result<(), SignedPackError>>;
    type RehashFault =
        Box<dyn FnMut(&AdmittedPrivateRoot, &str, &File) -> Result<(), SignedPackError>>;

    struct TestSnapshotHooks {
        after_chunk: Option<ChunkFault>,
        before_rehash: Option<RehashFault>,
    }

    impl SnapshotHooks for TestSnapshotHooks {
        fn after_copy_chunk(
            &mut self,
            parent: &AdmittedPrivateRoot,
            name: &str,
            destination: &File,
            copied: u64,
        ) -> Result<(), SignedPackError> {
            if let Some(fault) = &mut self.after_chunk {
                fault(parent, name, destination, copied)?;
            }
            Ok(())
        }

        fn before_destination_rehash(
            &mut self,
            parent: &AdmittedPrivateRoot,
            name: &str,
            destination: &File,
        ) -> Result<(), SignedPackError> {
            if let Some(fault) = &mut self.before_rehash {
                fault(parent, name, destination)?;
            }
            Ok(())
        }
    }

    #[test]
    fn public_input_tree_rejects_links_special_files_and_unlisted_entries() {
        // Integration fixtures supply a disposable public pack directory. The
        // verifier itself does not create or mutate that source directory.
        assert!(!valid_relative_path("../escape"));
        assert!(!valid_relative_path("a//b"));
        assert!(!valid_relative_path("a\\b"));
        assert!(valid_relative_path("agent/runtime/adapter.jar"));
    }

    #[test]
    fn opened_public_pack_is_hash_checked_closed_and_revalidated() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let payload = b"public fixture payload";
        std::fs::write(directory.path().join("payload.bin"), payload).expect("payload");
        let rows = [ArtifactDigest {
            path: "payload.bin".to_owned(),
            digest: *blake3::hash(payload).as_bytes(),
        }];
        std::fs::write(directory.path().join(OUTER_MANIFEST), make_manifest(&rows))
            .expect("outer manifest");

        let inspected = inspect_pack(directory.path()).expect("closed fixture inventory");
        assert_eq!(inspected.manifest().pack_name(), "node");
        inspected.revalidate().expect("unchanged fixture inventory");

        std::fs::write(directory.path().join("unlisted.bin"), b"unlisted").expect("unlisted file");
        assert_eq!(inspected.revalidate(), Err(SignedPackError::InventoryMismatch));
    }

    #[test]
    fn opened_public_pack_rejects_symlink_and_hardlink_entries() {
        let symlink_directory = tempfile::tempdir().expect("symlink fixture directory");
        let external = symlink_directory.path().join("outside.bin");
        std::fs::write(&external, b"outside").expect("external fixture");
        std::os::unix::fs::symlink(&external, symlink_directory.path().join("payload.bin"))
            .expect("symlink fixture");
        let symlink_rows = [ArtifactDigest {
            path: "payload.bin".to_owned(),
            digest: *blake3::hash(b"outside").as_bytes(),
        }];
        std::fs::write(symlink_directory.path().join(OUTER_MANIFEST), make_manifest(&symlink_rows))
            .expect("outer manifest");
        assert_eq!(
            inspect_pack(symlink_directory.path()).err(),
            Some(SignedPackError::InventoryMismatch)
        );

        let hardlink_directory = tempfile::tempdir().expect("hardlink fixture directory");
        std::fs::write(hardlink_directory.path().join("payload.bin"), b"linked bytes")
            .expect("payload");
        std::fs::hard_link(
            hardlink_directory.path().join("payload.bin"),
            hardlink_directory.path().join("payload-copy.bin"),
        )
        .expect("hardlink fixture");
        let linked_digest = *blake3::hash(b"linked bytes").as_bytes();
        let hardlink_rows = [
            ArtifactDigest { path: "payload-copy.bin".to_owned(), digest: linked_digest },
            ArtifactDigest { path: "payload.bin".to_owned(), digest: linked_digest },
        ];
        let mut sorted = hardlink_rows.to_vec();
        sorted.sort_by(|left, right| left.path.cmp(&right.path));
        std::fs::write(hardlink_directory.path().join(OUTER_MANIFEST), make_manifest(&sorted))
            .expect("outer manifest");
        assert_eq!(
            inspect_pack(hardlink_directory.path()).err(),
            Some(SignedPackError::InventoryMismatch)
        );
    }

    #[test]
    fn source_file_size_is_rejected_before_unbounded_read() {
        let directory = tempfile::tempdir().expect("size fixture directory");
        let file = std::fs::File::create(directory.path().join("large.bin")).expect("sparse file");
        file.set_len(MAX_ARTIFACT_BYTES + 1).expect("sparse size");
        let rows = [ArtifactDigest { path: "large.bin".to_owned(), digest: [0; 32] }];
        std::fs::write(directory.path().join(OUTER_MANIFEST), make_manifest(&rows))
            .expect("outer manifest");
        assert_eq!(inspect_pack(directory.path()).err(), Some(SignedPackError::InventoryMismatch));
    }

    #[test]
    fn small_manifest_limit_is_checked_before_capture_allocation() {
        let directory = tempfile::tempdir().expect("public manifest fixture directory");
        let path = directory.path().join("manifest.bin");
        let contents = vec![b'x'; MAX_MANIFEST_BYTES as usize + 1];
        std::fs::write(&path, &contents).expect("oversized bounded fixture");
        let file = File::open(&path).expect("open public fixture");
        let metadata = file.metadata().expect("fixture metadata");
        let parent = File::open(directory.path()).expect("fixture parent directory");
        let name = std::ffi::CString::new("manifest.bin").expect("fixed fixture name");
        let mut total = 0;
        assert!(matches!(
            scan_regular_file(
                &file,
                ScanFileContext {
                    parent: &parent,
                    name: name.as_c_str(),
                    named_device: metadata.dev(),
                    named_inode: metadata.ino(),
                    outer_manifest: false,
                    capture_small: true,
                    maximum_total_remaining: MAX_TOTAL_BYTES,
                    deadline: std::time::Instant::now() + MAX_INSPECTION_TIME,
                },
                &mut total,
            ),
            Err(SignedPackError::ResourceLimit)
        ));
    }

    #[test]
    fn java_distribution_manifest_rows_are_bounded_sorted_and_path_closed() {
        let valid = format!("{}  agent/a.jar\n", "ab".repeat(32));
        assert_eq!(parse_sha256_manifest(valid.as_bytes()).map(|rows| rows.len()), Ok(1));
        for invalid in [
            format!("{} agent/a.jar\n", "ab".repeat(32)),
            format!("{}  ../escape.jar\n", "ab".repeat(32)),
            format!("{}  agent/z.jar\n{}  agent/a.jar\n", "ab".repeat(32), "cd".repeat(32)),
            format!("{}  agent/a.jar\r\n", "ab".repeat(32)),
        ] {
            assert_eq!(
                parse_sha256_manifest(invalid.as_bytes()),
                Err(SignedPackError::InventoryMismatch)
            );
        }
        let too_many = (0..=MAX_INNER_MANIFEST_ENTRIES)
            .map(|index| format!("{}  agent/{index:03}.jar\n", "ab".repeat(32)))
            .collect::<String>();
        assert_eq!(parse_sha256_manifest(too_many.as_bytes()), Err(SignedPackError::ResourceLimit));
    }

    #[test]
    fn sha256_distribution_rows_require_literal_lf_and_no_empty_records() {
        let row = format!("{}  agent/a.jar", "ab".repeat(32));
        assert!(parse_sha256_manifest(format!("{row}\n").as_bytes()).is_ok());
        for malformed in [format!("{row}\r\n"), format!("{row}\n\n"), format!("{row}\r\n{row}\r\n")]
        {
            assert_eq!(
                parse_sha256_manifest(malformed.as_bytes()),
                Err(SignedPackError::InventoryMismatch)
            );
        }
    }

    #[test]
    fn copied_snapshot_reopens_same_descriptor_and_enforces_aggregate_budget_and_deadline() {
        let cache = private_scratch();
        let payload = b"authenticated snapshot fixture";
        let (_source, inspected) = public_fixture(payload);
        let (snapshot_name, snapshot, directories) = private_snapshot(&cache, &inspected.manifest);
        let mut created_files = Vec::new();
        let mut hooks = NoopSnapshotHooks;
        assert_eq!(
            populate_fixture(&inspected, &snapshot, &directories, &mut created_files, &mut hooks),
            Ok(())
        );
        let deadline = std::time::Instant::now() + MAX_INSPECTION_TIME;
        assert_eq!(
            verify_private_snapshot(
                &snapshot,
                &inspected.manifest,
                &inspected.outer_digest,
                deadline
            ),
            Ok(())
        );
        let exact_total = payload.len() as u64 + inspected.manifest_bytes.len() as u64;
        assert_eq!(
            verify_private_snapshot_with_total_limit(
                &snapshot,
                &inspected.manifest,
                &inspected.outer_digest,
                exact_total - 1,
                deadline,
            ),
            Err(SignedPackError::ResourceLimit)
        );
        assert!(
            verify_private_snapshot(
                &snapshot,
                &inspected.manifest,
                &inspected.outer_digest,
                std::time::Instant::now() - std::time::Duration::from_secs(1),
            )
            .is_err()
        );
        cleanup_private_snapshot(
            &cache,
            &snapshot_name,
            &snapshot,
            &directories,
            &created_files,
            deadline,
        )
        .expect("exact snapshot fixture cleanup");
    }

    #[test]
    fn partial_snapshot_copy_uses_production_cleanup_and_reports_uncertain_replacement() {
        let cache = private_scratch();
        let payload = vec![0x5a; 70 * 1024];
        let (_source, inspected) = public_fixture(&payload);

        let (snapshot_name, snapshot, directories) = private_snapshot(&cache, &inspected.manifest);
        let mut created_files = Vec::new();
        let mut fail_after_chunk = TestSnapshotHooks {
            after_chunk: Some(Box::new(
                |_: &AdmittedPrivateRoot, _: &str, _: &File, copied: u64| {
                    if copied > 0 { Err(SignedPackError::SnapshotIncomplete) } else { Ok(()) }
                },
            )),
            before_rehash: None,
        };
        assert_eq!(
            populate_fixture(
                &inspected,
                &snapshot,
                &directories,
                &mut created_files,
                &mut fail_after_chunk,
            ),
            Err(SignedPackError::SnapshotIncomplete)
        );
        let deadline = std::time::Instant::now() + MAX_INSPECTION_TIME;
        cleanup_private_snapshot(
            &cache,
            &snapshot_name,
            &snapshot,
            &directories,
            &created_files,
            deadline,
        )
        .expect("partial copy cleanup");
        assert!(
            !cache
                .bounded_child_names_for_operation(MAX_TREE_ENTRIES, deadline)
                .expect("private cache listing")
                .contains(&snapshot_name)
        );

        let (snapshot_name, snapshot, directories) = private_snapshot(&cache, &inspected.manifest);
        let mut created_files = Vec::new();
        let replacement = vec![0x5a; payload.len()];
        let mut hooks = TestSnapshotHooks {
            after_chunk: None,
            before_rehash: Some(Box::new(
                move |parent: &AdmittedPrivateRoot, name: &str, _destination: &File| {
                    let path = parent.path().join(name);
                    let parked = parent.path().join("fixture-original-held");
                    std::fs::rename(&path, &parked)
                        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
                    std::fs::write(&path, &replacement)
                        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
                    let replacement_file = File::open(&path)
                        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
                    replacement_file
                        .set_permissions(std::fs::Permissions::from_mode(0o600))
                        .map_err(|_| SignedPackError::PrivateSnapshotUnavailable)?;
                    Ok(())
                },
            )),
        };
        assert_eq!(
            populate_fixture(&inspected, &snapshot, &directories, &mut created_files, &mut hooks),
            Err(SignedPackError::SnapshotIncomplete)
        );
        assert_eq!(
            cleanup_private_snapshot(
                &cache,
                &snapshot_name,
                &snapshot,
                &directories,
                &created_files,
                std::time::Instant::now() + MAX_INSPECTION_TIME,
            ),
            Err(SignedPackError::SnapshotCleanupUncertain)
        );
        let parked = snapshot.path().join("fixture-original-held");
        assert_eq!(
            std::fs::read(snapshot.path().join("payload.bin"))
                .expect("replacement remains visible after refused cleanup"),
            payload
        );
        std::fs::remove_file(snapshot.path().join("payload.bin"))
            .expect("remove replacement fixture");
        std::fs::remove_file(&parked).expect("remove displaced fixture");
        cache
            .remove_private_child_for_operation(
                &snapshot_name,
                &snapshot,
                std::time::Instant::now() + MAX_INSPECTION_TIME,
            )
            .expect("remove manually emptied uncertain fixture");
    }

    #[test]
    fn java_inner_manifests_bind_the_complete_fixture_artifact_bytes() {
        let mut payloads = BTreeMap::from([
            ("attach/xtrace-attach.jar".to_owned(), b"helper".to_vec()),
            ("agent/xtrace-java-agent.jar".to_owned(), b"agent".to_vec()),
            ("agent/runtime/runtime.jar".to_owned(), b"runtime".to_vec()),
        ]);
        let agent_rows = ["runtime/runtime.jar", "xtrace-java-agent.jar"]
            .into_iter()
            .map(|path| {
                let bytes = payloads.get(&format!("agent/{path}")).expect("agent artifact");
                format!("{}  {path}\n", hex(&sha256_bytes(bytes)))
            })
            .collect::<String>();
        payloads.insert("agent/manifest.sha256".to_owned(), agent_rows.into_bytes());
        let outer_rows = payloads
            .iter()
            .map(|(path, bytes)| format!("{}  {path}\n", hex(&sha256_bytes(bytes))))
            .collect::<String>();
        payloads.insert("pack.manifest".to_owned(), outer_rows.into_bytes());

        let artifacts = payloads
            .iter()
            .map(|(path, bytes)| ArtifactDigest {
                path: path.clone(),
                digest: *blake3::hash(bytes).as_bytes(),
            })
            .collect::<Vec<_>>();
        let manifest = crate::signed_pack::parse_canonical_manifest(&make_manifest_for_pack(
            &artifacts, "java",
        ))
        .expect("Java outer manifest");
        let mut files = payloads
            .into_iter()
            .map(|(path, bytes)| (path, scanned_file(&bytes)))
            .collect::<BTreeMap<_, _>>();
        files.insert(OUTER_MANIFEST.to_owned(), scanned_file(b"outer"));
        let mut tree = ScannedTree {
            files,
            directories: ["agent", "agent/runtime", "attach"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        };
        assert_eq!(verify_inner_manifests(&manifest, &tree), Ok(()));

        if let Some(runtime) = tree.files.get_mut("agent/runtime/runtime.jar") {
            runtime.sha256 = [0; 32];
        }
        assert_eq!(
            verify_inner_manifests(&manifest, &tree),
            Err(SignedPackError::InventoryMismatch)
        );
    }

    #[test]
    fn executable_admission_facts_require_core_selected_release_protocol_runtime_and_host() {
        let artifact = ArtifactDigest {
            path: "agent/manifest.sha256".to_owned(),
            digest: [7; 32],
        };
        let manifest = crate::signed_pack::parse_canonical_manifest(&make_manifest_for_pack(
            std::slice::from_ref(&artifact),
            "java",
        ))
        .expect("supported Java admission fixture");

        assert_eq!(
            verify_compatibility_declarations(&manifest, RuntimeMajor::Java17, "macos", "aarch64"),
            Ok(())
        );
        assert_eq!(
            verify_compatibility_declarations(&manifest, RuntimeMajor::Java21, "macos", "aarch64"),
            Ok(())
        );
        assert_eq!(
            verify_compatibility_declarations(&manifest, RuntimeMajor::Node22, "macos", "aarch64"),
            Err(SignedPackError::UnsupportedManifest)
        );
        assert_eq!(
            verify_compatibility_declarations(&manifest, RuntimeMajor::Java17, "linux", "aarch64"),
            Err(SignedPackError::UnsupportedManifest)
        );
        assert_eq!(
            verify_compatibility_declarations(&manifest, RuntimeMajor::Java17, "macos", "x86_64"),
            Err(SignedPackError::UnsupportedManifest)
        );

        let mut incompatible_protocol =
            make_manifest_for_pack(std::slice::from_ref(&artifact), "java");
        let old = b"\"protocol\":{\"max\":\"1.2\",\"min\":\"1.0\"}";
        let position = incompatible_protocol
            .windows(old.len())
            .position(|window| window == old)
            .expect("protocol fixture field");
        incompatible_protocol.splice(
            position..position + old.len(),
            b"\"protocol\":{\"max\":\"2.0\",\"min\":\"2.0\"}".iter().copied(),
        );
        let incompatible_protocol =
            crate::signed_pack::parse_canonical_manifest(&incompatible_protocol)
                .expect("closed but incompatible protocol fixture");
        assert_eq!(
            verify_compatibility_declarations(
                &incompatible_protocol,
                RuntimeMajor::Java17,
                "macos",
                "aarch64",
            ),
            Err(SignedPackError::UnsupportedManifest)
        );
    }

    #[test]
    fn executable_admission_binds_only_the_known_inner_manifest_inventory_entry() {
        let expected_digest = [9; 32];
        let known = ArtifactDigest {
            path: "agent/manifest.sha256".to_owned(),
            digest: expected_digest,
        };
        let manifest = crate::signed_pack::parse_canonical_manifest(&make_manifest_for_pack(
            std::slice::from_ref(&known),
            "java",
        ))
        .expect("known producer manifest fixture");
        assert_eq!(known_inner_manifest_digest(&manifest), Ok(expected_digest));

        let swapped = ArtifactDigest {
            path: "agent/other-manifest.sha256".to_owned(),
            digest: expected_digest,
        };
        let swapped_manifest = crate::signed_pack::parse_canonical_manifest(
            &make_manifest_for_pack(std::slice::from_ref(&swapped), "java"),
        )
        .expect("swapped producer manifest fixture");
        assert_eq!(
            known_inner_manifest_digest(&swapped_manifest),
            Err(SignedPackError::UnsupportedManifest)
        );

        let node_manifest = crate::signed_pack::parse_canonical_manifest(&make_manifest_for_pack(
            &[ArtifactDigest { path: "index.js".to_owned(), digest: expected_digest }],
            "node",
        ))
        .expect("Node compatibility fixture");
        assert_eq!(
            known_inner_manifest_digest(&node_manifest),
            Err(SignedPackError::UnsupportedManifest)
        );
    }

    fn make_manifest(artifacts: &[ArtifactDigest]) -> Vec<u8> {
        make_manifest_for_pack(artifacts, "node")
    }

    fn make_manifest_for_pack(artifacts: &[ArtifactDigest], language: &str) -> Vec<u8> {
        let build_hash = build_hash(artifacts).expect("fixture build hash");
        let entrypoint = artifacts.first().expect("fixture artifact").path.as_str();
        let artifact_rows = artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "{{\"hash\":\"b3:{}\",\"path\":\"{}\"}}",
                    hex(&artifact.digest),
                    artifact.path
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let entrypoints = if language == "java" {
            format!(
                "\"attach\":\"{entrypoint}\",\"launch\":\"{entrypoint}\",\"staticDiscovery\":null"
            )
        } else {
            format!(
                "\"attach\":null,\"launch\":{{\"commonJs\":\"{entrypoint}\",\"esModule\":\"{entrypoint}\"}},\"staticDiscovery\":null"
            )
        };
        let (tested_majors, runtime_range) =
            if language == "java" { ("[17,21]", ">=17 <22") } else { ("[22,24]", ">=22 <25") };
        format!(
            concat!(
                "{{\"artifacts\":[{artifact_rows}],\"capabilities\":{{}},",
                "\"entrypoints\":{{{entrypoints}}},",
                "\"frameworkModules\":[],\"knownLimitations\":[],",
                "\"pack\":{{\"buildHash\":\"b3:{build_hash}\",\"name\":\"{language}\",\"version\":\"0.0.1\"}},",
                "\"platforms\":[{{\"arch\":\"aarch64\",\"os\":\"macos\"}}],",
                "\"protocol\":{{\"max\":\"1.2\",\"min\":\"1.0\"}},",
                "\"release\":{{\"max\":\"0.0.1\",\"min\":\"0.0.1\"}},",
                "\"runtime\":{{\"language\":\"{language}\",\"testedMajors\":{tested_majors},\"versionRange\":\"{runtime_range}\"}},",
                "\"schemaVersion\":1,\"signature\":{{\"algorithm\":\"Ed25519\",\"keyId\":\"release-2026\",",
                "\"value\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}}}"
            ),
            artifact_rows = artifact_rows,
            entrypoints = entrypoints,
            build_hash = hex(&build_hash),
            language = language,
            tested_majors = tested_majors,
            runtime_range = runtime_range,
        )
        .into_bytes()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn scanned_file(bytes: &[u8]) -> ScannedFile {
        ScannedFile {
            digest: *blake3::hash(bytes).as_bytes(),
            sha256: sha256_bytes(bytes),
            small_contents: (bytes.len() as u64 <= MAX_MANIFEST_BYTES).then(|| bytes.to_vec()),
            source: None,
        }
    }

    fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
}
