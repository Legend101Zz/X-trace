//! Validated Java attach-pack access and owner-enforced private storage admission.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_PACK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACK_ENTRIES: usize = 96;
const MAX_RETAINED_PACK_SNAPSHOTS: usize = 4;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Size of the single buffer used to hash and copy pack files.
const STREAM_CHUNK_BYTES: usize = 64 * 1024;
const PACKS_DIR: &str = "java-packs";
const STATE_DIR: &str = ".state";
const CACHE_LOCK: &str = "cache.lock";
const INCOMING_PREFIX: &str = ".incoming-";
/// Upper bound on entries read from the cache root, so a polluted cache fails closed.
const MAX_CACHE_ENTRIES: usize = 64;
const MAX_SNAPSHOT_DEPTH: usize = 8;
/// Bounded wait for a contended cache lock before failing closed.
const CACHE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
const CACHE_LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(10);
/// An incoming directory with no builder lock file at all is residue only after this age.
const STALE_UNLOCKED_INCOMING: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

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
///
/// A pack returned by [`JavaAttachPack::snapshot_into`] holds a shared lease on its cache
/// snapshot until the pack and every clone are dropped; the snapshot cannot be evicted while
/// the lease is held. Keep the pack alive for as long as its paths are in use.
#[derive(Clone, Debug)]
pub struct JavaAttachPack {
    root: PathBuf,
    helper_jar: PathBuf,
    agent_dir: PathBuf,
    lease: Option<std::sync::Arc<std::fs::File>>,
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
            let digest = stream_file(&root.join(path), identity, MAX_FILE_BYTES, None)?;
            if digest != *expected {
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
        Ok(Self { root, helper_jar, agent_dir, lease: None })
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
    ///
    /// The snapshot is built under a unique private `.incoming-*` name, fully
    /// verified and sealed, and only then renamed atomically to its
    /// content-addressed name, so a crash can never leave a half-built directory
    /// under a final name or count toward the retention cap. When the cap is
    /// reached the least-recently-used snapshot that no live attach holds a lease
    /// on is evicted. The returned pack holds a shared lease on its snapshot for
    /// as long as the pack (or any clone) lives.
    pub fn snapshot_into(&self, cache: &Path) -> Result<Self, AttachError> {
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
        let packs = PackCache::open(cache)?;
        let snapshot_path = packs.path.join(&snapshot_name);

        let mut lease = packs.lease(&snapshot_name)?;
        match packs.existing(&snapshot_path) {
            Ok(Some(snapshot)) => return Ok(snapshot.with_lease(lease, &packs)),
            Ok(None) => {}
            Err(error) => {
                // A final-named directory that fails verification can only be legacy
                // residue (new snapshots are renamed in complete). It is never repaired
                // in place; it is replaced only when no live attach holds a lease on it.
                drop(lease);
                if !packs.evict(&snapshot_name)? {
                    return Err(error);
                }
                lease = packs.lease(&snapshot_name)?;
            }
        }

        packs.reap_stale();
        let incoming = packs.begin_incoming()?;
        let incoming_path = packs.path.join(&incoming.name);
        packs.fill_incoming(&incoming, &incoming_path, &current, &declared, &manifest)?;

        let published = {
            let _publish = packs.lock_cache()?;
            if std::fs::symlink_metadata(&snapshot_path).is_ok() {
                // A concurrent attach published the same content first; keep its copy.
                false
            } else {
                packs.make_room()?;
                rustix::fs::renameat(&packs.packs, &incoming.name, &packs.packs, &snapshot_name)
                    .map_err(|_| {
                        AttachError::PrivateStorage(
                            "the private Java pack snapshot could not be published",
                        )
                    })?;
                true
            }
        };
        if published {
            incoming.published();
            rustix::fs::fsync(&packs.packs).map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot could not be published")
            })?;
        }
        match packs.existing(&snapshot_path)? {
            Some(snapshot) => Ok(snapshot.with_lease(lease, &packs)),
            None => {
                Err(AttachError::PrivateStorage("the private Java pack snapshot is unavailable"))
            }
        }
    }

    fn with_lease(mut self, lease: std::fs::File, packs: &PackCache) -> Self {
        packs.touch(&lease);
        self.lease = Some(std::sync::Arc::new(lease));
        self
    }
}

/// Re-admits the sealed snapshot directories through the shared admission: one deadline, one
/// ancestor walk per path, owner-only read-only mode, owner-enforcing filesystem, and no ACL.
fn verify_retained_snapshot_directories(root: &Path) -> Result<(), AttachError> {
    let paths = ["", "attach", "agent", "agent/runtime"]
        .into_iter()
        .map(|relative| if relative.is_empty() { root.to_path_buf() } else { root.join(relative) })
        .collect::<Vec<_>>();
    xtrace_private_storage::admit_sealed_directories(&paths, 0o500)
        .map_err(|_| AttachError::PrivateStorage("the retained Java pack snapshot is unsafe"))
}

/// The private `java-packs` cache: sealed content-addressed snapshots plus sidecar state.
///
/// Layout below the admitted `java-packs` directory (owner-only `0700`):
/// - `<64 hex>`: a complete sealed (`0500`) snapshot. Only these count toward the cap.
/// - `.incoming-<pid>-<nonce>`: a snapshot under construction. Never counted.
/// - `.state/<hex>.use`: lease and recency file for one snapshot. A shared `flock` is held
///   for as long as a `JavaAttachPack` uses the snapshot; the file's mtime is the LRU recency.
///   Sealed snapshot directories are never written, so recency lives here instead.
/// - `.state/<incoming>.build`: the builder's exclusive `flock`. The kernel drops it when the
///   builder exits or crashes, which is how abandoned residue is proven stale.
/// - `.state/cache.lock`: serializes only the short count-evict-publish step.
///
/// The target JVM never opens these paths: the helper copies the agent into its own per-target
/// snapshot before `loadAgent`. A snapshot is therefore in use exactly while an X-trace process
/// holds a `JavaAttachPack` for it (the helper JVM reads `attach/xtrace-attach.jar` lazily and
/// the helper reads `agent/`), which is what the lease records.
struct PackCache {
    path: PathBuf,
    packs: std::fs::File,
    state: std::fs::File,
    owner: u32,
    device: u64,
}

/// Directory names found in the cache root.
struct CacheListing {
    sealed: Vec<String>,
    incoming: Vec<String>,
}

/// A snapshot under construction; removes itself unless it was published.
struct Incoming<'a> {
    cache: &'a PackCache,
    name: String,
    _build_lock: std::fs::File,
    published: std::cell::Cell<bool>,
}

impl Incoming<'_> {
    fn published(&self) {
        self.published.set(true);
        let _ = rustix::fs::unlinkat(
            &self.cache.state,
            format!("{}.build", self.name),
            rustix::fs::AtFlags::empty(),
        );
    }
}

impl Drop for Incoming<'_> {
    fn drop(&mut self) {
        if self.published.get() {
            return;
        }
        // Best effort only; anything left behind is provably abandoned once this
        // process exits and is reaped by a later attach.
        if remove_tree(&self.cache.packs, &self.name, self.cache.owner, self.cache.device, 0)
            .is_ok()
        {
            let _ = rustix::fs::unlinkat(
                &self.cache.state,
                format!("{}.build", self.name),
                rustix::fs::AtFlags::empty(),
            );
        }
    }
}

fn is_snapshot_name(name: &str) -> bool {
    name.len() == 64
        && name.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_incoming_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(INCOMING_PREFIX) else { return false };
    let Some((pid, nonce)) = rest.split_once('-') else { return false };
    !pid.is_empty()
        && pid.len() <= 10
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && nonce.len() == 32
        && nonce.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lock_error() -> AttachError {
    AttachError::PrivateStorage("the Java pack cache lock failed")
}

/// Takes a non-blocking `flock`; `Ok(false)` means another holder has a conflicting lock.
fn try_lock(file: &std::fs::File, exclusive: bool) -> Result<bool, AttachError> {
    let operation = if exclusive {
        rustix::fs::FlockOperation::NonBlockingLockExclusive
    } else {
        rustix::fs::FlockOperation::NonBlockingLockShared
    };
    match rustix::fs::flock(file, operation) {
        Ok(()) => Ok(true),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Ok(false),
        Err(_) => Err(lock_error()),
    }
}

/// Polls a lock for a short bounded time, then fails closed.
fn lock_within_bound(file: &std::fs::File, exclusive: bool) -> Result<(), AttachError> {
    let deadline = std::time::Instant::now() + CACHE_LOCK_WAIT;
    loop {
        if try_lock(file, exclusive)? {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(AttachError::PrivateStorage("the Java pack cache is busy"));
        }
        std::thread::sleep(CACHE_LOCK_POLL);
    }
}

impl PackCache {
    fn open(cache: &Path) -> Result<Self, AttachError> {
        use std::os::unix::fs::MetadataExt as _;
        let parent = xtrace_private_storage::open_private_directory_descriptor(cache)
            .map_err(|_| AttachError::PrivateStorage("the Java helper cache changed"))?;
        let path = cache.join(PACKS_DIR);
        let packs = open_or_create_private_child(&parent, PACKS_DIR)?;
        admit_directory_descriptor(&path, &packs, true)?;
        let state = open_or_create_private_child(&packs, STATE_DIR)?;
        admit_directory_descriptor(&path.join(STATE_DIR), &state, true)?;
        let metadata = packs
            .metadata()
            .map_err(|_| AttachError::PrivateStorage("the Java pack cache is unavailable"))?;
        Ok(Self {
            path,
            packs,
            state,
            owner: rustix::process::getuid().as_raw(),
            device: metadata.dev(),
        })
    }

    /// Re-checks that the retained descriptors still name the admitted cache.
    fn revalidate(&self) -> Result<(), AttachError> {
        admit_directory_descriptor(&self.path, &self.packs, true)?;
        admit_directory_descriptor(&self.path.join(STATE_DIR), &self.state, true)
    }

    /// Lists the cache root through the admitted descriptor, failing closed on any surprise.
    fn list(&self) -> Result<CacheListing, AttachError> {
        use std::os::unix::fs::MetadataExt as _;
        let mut listing = CacheListing { sealed: Vec::new(), incoming: Vec::new() };
        for name in read_names(&self.packs, MAX_CACHE_ENTRIES)? {
            let unexpected =
                || AttachError::PrivateStorage("the Java pack cache has an unexpected entry");
            let snapshot = is_snapshot_name(&name);
            let incoming = is_incoming_name(&name);
            if name != STATE_DIR && !snapshot && !incoming {
                return Err(unexpected());
            }
            let child = open_child_directory(&self.packs, &name).map_err(|_| unexpected())?;
            let metadata = child.metadata().map_err(|_| unexpected())?;
            if metadata.uid() != self.owner
                || metadata.dev() != self.device
                || metadata.mode() & 0o077 != 0
            {
                return Err(unexpected());
            }
            if snapshot {
                listing.sealed.push(name);
            } else if incoming {
                listing.incoming.push(name);
            }
        }
        self.revalidate()?;
        Ok(listing)
    }

    fn state_file(&self, name: &str, create: bool) -> Result<Option<std::fs::File>, AttachError> {
        use std::os::unix::fs::MetadataExt as _;
        let mut flags = rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK;
        if create {
            flags |= rustix::fs::OFlags::CREATE;
        }
        let file = match rustix::fs::openat(
            &self.state,
            name,
            flags,
            rustix::fs::Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => std::fs::File::from(file),
            Err(error) if error == rustix::io::Errno::NOENT && !create => return Ok(None),
            Err(_) => return Err(lock_error()),
        };
        let metadata = file.metadata().map_err(|_| lock_error())?;
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(AttachError::PrivateStorage("the Java pack cache state is unsafe"));
        }
        Ok(Some(file))
    }

    /// Whether `name` in the state directory is still the file behind `held`.
    fn state_entry_is(&self, name: &str, held: &std::fs::File) -> Result<bool, AttachError> {
        use std::os::unix::fs::MetadataExt as _;
        let Some(current) = self.state_file(name, false)? else { return Ok(false) };
        let (current, held) = (
            current.metadata().map_err(|_| lock_error())?,
            held.metadata().map_err(|_| lock_error())?,
        );
        Ok(current.dev() == held.dev() && current.ino() == held.ino())
    }

    /// Takes a shared lease: the snapshot named `name` may not be evicted while it is held.
    fn lease(&self, name: &str) -> Result<std::fs::File, AttachError> {
        let file_name = format!("{name}.use");
        for _ in 0..8 {
            let file = self.state_file(&file_name, true)?.ok_or_else(lock_error)?;
            lock_within_bound(&file, false)?;
            // A concurrent evictor may have unlinked the file after we opened it.
            if self.state_entry_is(&file_name, &file)? {
                return Ok(file);
            }
        }
        Err(AttachError::PrivateStorage("the Java pack cache is busy"))
    }

    /// Records use now. The mtime of the lease file is the LRU recency.
    fn touch(&self, lease: &std::fs::File) {
        let _ = lease.set_modified(std::time::SystemTime::now());
    }

    fn recency(&self, name: &str) -> std::time::SystemTime {
        self.state_file(&format!("{name}.use"), false)
            .ok()
            .flatten()
            .and_then(|file| file.metadata().ok())
            .and_then(|metadata| metadata.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH)
    }

    fn lock_cache(&self) -> Result<std::fs::File, AttachError> {
        let file = self.state_file(CACHE_LOCK, true)?.ok_or_else(lock_error)?;
        lock_within_bound(&file, true)?;
        Ok(file)
    }

    /// Returns a complete verified snapshot, `None` when absent, or the verification error.
    fn existing(&self, path: &Path) -> Result<Option<JavaAttachPack>, AttachError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let snapshot = JavaAttachPack::validate(path)?;
                verify_retained_snapshot_directories(path)?;
                Ok(Some(snapshot))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => {
                Err(AttachError::PrivateStorage("the private Java pack snapshot is unavailable"))
            }
        }
    }

    /// Removes snapshot `name` if, and only if, no live attach holds a lease on it.
    ///
    /// Returns `false` (nothing removed) when the snapshot is in use.
    fn evict(&self, name: &str) -> Result<bool, AttachError> {
        let file_name = format!("{name}.use");
        let file = self.state_file(&file_name, true)?.ok_or_else(lock_error)?;
        if !try_lock(&file, true)? {
            return Ok(false);
        }
        self.revalidate()?;
        remove_tree(&self.packs, name, self.owner, self.device, 0)?;
        let _ = rustix::fs::unlinkat(&self.state, &file_name, rustix::fs::AtFlags::empty());
        rustix::fs::fsync(&self.packs)
            .map_err(|_| AttachError::PrivateStorage("the Java pack cache cannot be synced"))?;
        Ok(true)
    }

    /// Evicts least-recently-used unleased snapshots until one more fits under the cap.
    fn make_room(&self) -> Result<(), AttachError> {
        loop {
            let listing = self.list()?;
            if listing.sealed.len() < MAX_RETAINED_PACK_SNAPSHOTS {
                return Ok(());
            }
            let mut candidates = listing
                .sealed
                .into_iter()
                .map(|name| (self.recency(&name), name))
                .collect::<Vec<_>>();
            candidates.sort();
            let mut evicted = false;
            for (_, name) in candidates {
                if self.evict(&name)? {
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                return Err(AttachError::PrivateStorage(
                    "the bounded Java pack snapshot cache is full: every retained snapshot is in use by a running attach",
                ));
            }
        }
    }

    /// Creates a unique private `.incoming-*` directory guarded by an exclusive builder lock.
    fn begin_incoming(&self) -> Result<Incoming<'_>, AttachError> {
        use ring::rand::SecureRandom as _;
        let mut nonce = [0_u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AttachError::PrivateStorage("the Java pack cache nonce is unavailable"))?;
        let nonce = nonce.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let name = format!("{INCOMING_PREFIX}{}-{nonce}", std::process::id());
        let build_lock = self.state_file(&format!("{name}.build"), true)?.ok_or_else(lock_error)?;
        if !try_lock(&build_lock, true)? {
            return Err(lock_error());
        }
        let incoming = Incoming {
            cache: self,
            name,
            _build_lock: build_lock,
            published: std::cell::Cell::new(false),
        };
        rustix::fs::mkdirat(&self.packs, &incoming.name, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot could not be created")
            })?;
        Ok(incoming)
    }

    /// Writes, verifies and seals the snapshot inside the incoming directory.
    fn fill_incoming(
        &self,
        incoming: &Incoming<'_>,
        incoming_path: &Path,
        source: &JavaAttachPack,
        declared: &std::collections::BTreeMap<String, String>,
        manifest: &[u8],
    ) -> Result<(), AttachError> {
        use std::io::Write as _;
        let snapshot = open_child_directory(&self.packs, &incoming.name).map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot could not be opened")
        })?;
        verify_metadata_owner_mode(
            &snapshot.metadata().map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
            })?,
            true,
        )?;
        admit_directory_descriptor(incoming_path, &snapshot, true)?;
        for directory in ["attach", "agent", "agent/runtime"] {
            create_private_directory(&snapshot, directory)?;
            xtrace_private_storage::open_private_directory_descriptor(
                &incoming_path.join(directory),
            )
            .map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot is unavailable")
            })?;
        }
        let mut total = 0_u64;
        for (relative, expected_digest) in declared {
            let identity = std::fs::symlink_metadata(source.root.join(relative)).map_err(|_| {
                AttachError::Validation("the Java attach pack changed during snapshot")
            })?;
            let identity = FileIdentity::from_metadata(&identity);
            total = total
                .checked_add(identity.size)
                .ok_or(AttachError::Validation("the Java attach pack exceeds its size limit"))?;
            if total > MAX_PACK_BYTES {
                return Err(AttachError::Validation("the Java attach pack exceeds its size limit"));
            }
            let mut destination = create_snapshot_file(&snapshot, relative)?;
            let digest = stream_file(
                &source.root.join(relative),
                identity,
                MAX_FILE_BYTES,
                Some(&mut destination),
            )?;
            if digest != *expected_digest {
                return Err(AttachError::Validation(
                    "the Java attach pack changed during snapshot",
                ));
            }
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
        manifest_file.write_all(manifest).map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot could not be written")
        })?;
        drop(manifest_file);
        JavaAttachPack::validate(incoming_path)?;
        for directory in ["attach", "agent/runtime", "agent"] {
            let directory = open_relative_directory(&snapshot, directory)?;
            seal_directory(&directory)?;
        }
        seal_directory(&snapshot)?;
        JavaAttachPack::validate(incoming_path)?;
        verify_retained_snapshot_directories(incoming_path)?;
        rustix::fs::fsync(&snapshot).map_err(|_| {
            AttachError::PrivateStorage("the private Java pack snapshot could not be sealed")
        })
    }

    /// Removes incoming residue and orphaned state files that are provably abandoned.
    ///
    /// Anything uncertain is left alone: an incoming directory is stale only when its builder
    /// lock can be taken (the kernel releases it when the builder exits), or when it has no
    /// builder lock file at all and is older than `STALE_UNLOCKED_INCOMING`.
    fn reap_stale(&self) {
        let Ok(listing) = self.list() else { return };
        for name in &listing.incoming {
            let lock_name = format!("{name}.build");
            match self.state_file(&lock_name, false) {
                Ok(Some(lock)) => {
                    if matches!(try_lock(&lock, true), Ok(true))
                        && remove_tree(&self.packs, name, self.owner, self.device, 0).is_ok()
                    {
                        let _ = rustix::fs::unlinkat(
                            &self.state,
                            &lock_name,
                            rustix::fs::AtFlags::empty(),
                        );
                    }
                }
                Ok(None) => {
                    let old = open_child_directory(&self.packs, name)
                        .ok()
                        .and_then(|directory| directory.metadata().ok())
                        .and_then(|metadata| metadata.modified().ok())
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age > STALE_UNLOCKED_INCOMING);
                    if old {
                        let _ = remove_tree(&self.packs, name, self.owner, self.device, 0);
                    }
                }
                Err(_) => {}
            }
        }
        let Ok(state_names) = read_names(&self.state, MAX_CACHE_ENTRIES * 4) else { return };
        for name in state_names {
            let orphan = if let Some(stem) = name.strip_suffix(".use") {
                is_snapshot_name(stem) && !listing.sealed.iter().any(|sealed| sealed == stem)
            } else if let Some(stem) = name.strip_suffix(".build") {
                is_incoming_name(stem) && !listing.incoming.iter().any(|item| item == stem)
            } else {
                false
            };
            if !orphan {
                continue;
            }
            if let Ok(Some(file)) = self.state_file(&name, false) {
                if matches!(try_lock(&file, true), Ok(true)) {
                    let _ = rustix::fs::unlinkat(&self.state, &name, rustix::fs::AtFlags::empty());
                }
            }
        }
    }
}

/// Lists at most `limit` entry names of an open directory, failing closed above it.
fn read_names(directory: &std::fs::File, limit: usize) -> Result<Vec<String>, AttachError> {
    let unreadable = || AttachError::PrivateStorage("the Java pack cache cannot be read");
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory).map_err(|_| unreadable())? {
        let entry = entry.map_err(|_| unreadable())?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= limit {
            return Err(AttachError::PrivateStorage("the Java pack cache has too many entries"));
        }
        names.push(
            std::str::from_utf8(bytes)
                .map_err(|_| {
                    AttachError::PrivateStorage("the Java pack cache has an unexpected entry")
                })?
                .to_string(),
        );
    }
    Ok(names)
}

/// Recursively removes `name` below `parent` through no-follow descriptors.
///
/// Every directory is opened with `O_NOFOLLOW | O_DIRECTORY`, must be owned by this user on the
/// cache's device, and is re-checked against its directory entry before it is unlinked. Sealed
/// read-only directories are made writable by descriptor first. Non-directories are unlinked
/// without being opened or followed. A missing entry is already removed.
fn remove_tree(
    parent: &std::fs::File,
    name: &str,
    owner: u32,
    device: u64,
    depth: usize,
) -> Result<(), AttachError> {
    use std::os::unix::fs::MetadataExt as _;
    let unsafe_entry =
        || AttachError::PrivateStorage("the Java pack cache entry cannot be removed");
    if depth > MAX_SNAPSHOT_DEPTH {
        return Err(unsafe_entry());
    }
    let directory = match open_child_directory(parent, name) {
        Ok(directory) => directory,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
        Err(_) => return Err(unsafe_entry()),
    };
    let metadata = directory.metadata().map_err(|_| unsafe_entry())?;
    if metadata.uid() != owner || metadata.dev() != device {
        return Err(unsafe_entry());
    }
    if metadata.mode() & 0o700 != 0o700 {
        rustix::fs::fchmod(&directory, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(|_| unsafe_entry())?;
    }
    for child in read_names(&directory, MAX_PACK_ENTRIES * 2)? {
        match open_child_directory(&directory, &child) {
            Ok(_) => remove_tree(&directory, &child, owner, device, depth + 1)?,
            Err(error)
                if error == rustix::io::Errno::NOTDIR || error == rustix::io::Errno::LOOP =>
            {
                rustix::fs::unlinkat(&directory, &child, rustix::fs::AtFlags::empty())
                    .map_err(|_| unsafe_entry())?;
            }
            Err(_) => return Err(unsafe_entry()),
        }
    }
    let entry = open_child_directory(parent, name).map_err(|_| unsafe_entry())?;
    let entry = entry.metadata().map_err(|_| unsafe_entry())?;
    if entry.dev() != metadata.dev() || entry.ino() != metadata.ino() {
        return Err(unsafe_entry());
    }
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR).map_err(|_| unsafe_entry())
}

fn open_relative_directory(
    root: &std::fs::File,
    relative: &str,
) -> Result<std::fs::File, AttachError> {
    rustix::fs::openat(
        root,
        relative,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(|_| AttachError::PrivateStorage("the private Java pack snapshot is unavailable"))
}

fn seal_directory(directory: &std::fs::File) -> Result<(), AttachError> {
    rustix::fs::fchmod(directory, rustix::fs::Mode::from_raw_mode(0o500)).map_err(|_| {
        AttachError::PrivateStorage("the private Java pack snapshot could not be sealed")
    })
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
    let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
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

fn create_snapshot_file(
    root: &std::fs::File,
    relative: &str,
) -> Result<std::fs::File, AttachError> {
    use rustix::fs::{Mode, OFlags, openat};
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
    openat(
        &directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o400),
    )
    .map(std::fs::File::from)
    .map_err(|_| AttachError::PrivateStorage("the private Java pack snapshot could not be written"))
}

/// Verifies that an existing directory is on an owner-enforcing local filesystem.
///
/// The check uses an opened directory descriptor so a path-only mount check cannot
/// be swapped between inspection and use. Unknown filesystems and failed probes
/// are rejected. This remains a point-in-time admission check, not a defense from
/// privileged remounts or hostile same-user processes.
pub fn admit_private_directory(path: &Path) -> Result<(), AttachError> {
    xtrace_private_storage::AdmittedPrivateRoot::open(path)
        .map(|_| ())
        .map_err(|_| AttachError::PrivateStorage("private storage cannot be admitted"))
}

/// Admits a user-data container that may be traversable but is not writable by other users.
pub fn admit_private_container_directory(path: &Path) -> Result<(), AttachError> {
    xtrace_private_storage::AdmittedPrivateRoot::open_container(path)
        .map(|_| ())
        .map_err(|_| AttachError::PrivateStorage("private storage cannot be admitted"))
}

pub(super) fn admit_directory_descriptor(
    path: &Path,
    directory: &std::fs::File,
    owner_only: bool,
) -> Result<(), AttachError> {
    xtrace_private_storage::AdmittedPrivateRoot::validate_open_directory(
        path, directory, owner_only,
    )
    .map_err(|_| AttachError::PrivateStorage("private storage cannot be admitted"))
}

/// Creates a private, durable helper cache below an already-admitted user data home.
pub fn prepare_helper_cache(data_home: &Path) -> Result<PathBuf, AttachError> {
    let parent = xtrace_private_storage::AdmittedPrivateRoot::open_container(data_home)
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
    /// Running totals and collected entries for one bounded pack walk.
    struct WalkState {
        total: u64,
        count: usize,
        inventory: PackInventory,
    }

    fn visit(
        root: &Path,
        directory: &Path,
        owner: u32,
        depth: usize,
        state: &mut WalkState,
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
            state.count += 1;
            if state.count > MAX_PACK_ENTRIES {
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
                if !safe_relative_path(&relative) || !state.inventory.directories.insert(relative) {
                    return Err(AttachError::Validation(
                        "the Java attach pack contains an invalid directory",
                    ));
                }
                visit(root, &path, owner, depth + 1, state)?;
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
                state.total = state.total.checked_add(identity.size).ok_or(
                    AttachError::Validation("the Java attach pack exceeds its size limit"),
                )?;
                if state.total > MAX_PACK_BYTES {
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
                if !safe_relative_path(&relative)
                    || state.inventory.files.insert(relative, identity).is_some()
                {
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

    let mut state = WalkState {
        total: 0,
        count: 0,
        inventory: PackInventory {
            files: std::collections::BTreeMap::new(),
            directories: std::collections::BTreeSet::new(),
        },
    };
    visit(root, root, owner, 0, &mut state)?;
    Ok(state.inventory)
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

/// Streams one pack file through SHA-256 with a bounded buffer, optionally copying it to `sink`.
///
/// Memory use is one `STREAM_CHUNK_BYTES` buffer regardless of file size. The same identity
/// checks as `read_bounded_file` apply: the opened descriptor and the path must both still match
/// `expected`, and exactly `expected.size` bytes must be read.
fn stream_file(
    path: &Path,
    expected: FileIdentity,
    bound: u64,
    mut sink: Option<&mut std::fs::File>,
) -> Result<String, AttachError> {
    use std::io::{Read as _, Write as _};
    if expected.size > bound {
        return Err(AttachError::Validation("a Java attach pack file exceeds its size limit"));
    }
    let unreadable = || AttachError::Validation("a Java attach pack file cannot be read");
    let changed = || AttachError::Validation("the Java attach pack changed during validation");
    let mut file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(|_| unreadable())?;
    let before = file.metadata().map_err(|_| unreadable())?;
    if FileIdentity::from_metadata(&before) != expected {
        return Err(changed());
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; STREAM_CHUNK_BYTES];
    let mut total = 0_u64;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(unreadable()),
        };
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(changed)?;
        if total > expected.size {
            return Err(changed());
        }
        hasher.update(&buffer[..read]);
        if let Some(sink) = sink.as_deref_mut() {
            sink.write_all(&buffer[..read]).map_err(|_| {
                AttachError::PrivateStorage("the private Java pack snapshot could not be written")
            })?;
        }
    }
    if total != expected.size {
        return Err(changed());
    }
    let after = std::fs::symlink_metadata(path).map_err(|_| changed())?;
    if FileIdentity::from_metadata(&after) != expected {
        return Err(changed());
    }
    Ok(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
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

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests construct fixed bounded pack fixtures")]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    /// Creates an owner-only temporary directory regardless of the process umask.
    fn private_tempdir_in(parent: &Path) -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
    }

    fn make_pack(root: &Path) {
        make_pack_tagged(root, "runtime jar");
    }

    /// Builds a pack whose runtime jar (and therefore manifest and snapshot name) depends on `tag`.
    fn make_pack_tagged(root: &Path, tag: &str) {
        std::fs::create_dir_all(root.join("attach")).expect("attach directory");
        std::fs::create_dir_all(root.join("agent/runtime")).expect("runtime directory");
        std::fs::write(root.join("attach/xtrace-attach.jar"), b"helper jar").expect("helper bytes");
        std::fs::write(root.join("agent/xtrace-java-agent.jar"), b"agent jar")
            .expect("agent bytes");
        std::fs::write(root.join("agent/manifest.sha256"), b"fixture manifest\n")
            .expect("agent manifest");
        std::fs::write(root.join("agent/runtime/runtime.jar"), tag.as_bytes())
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
        let source = private_tempdir_in(&scratch).expect("temporary source pack under scratch");
        make_pack(source.path());
        let cache = private_tempdir_in(&scratch).expect("temporary private cache under scratch");
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

    /// A private cache directory under the gate-provided owner-enforcing scratch root.
    struct CacheFixture {
        _scratch: tempfile::TempDir,
        cache: PathBuf,
    }

    fn cache_fixture() -> CacheFixture {
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("the gate must provide an owner-enforced private scratch root");
        admit_private_directory(&scratch).expect("gate-provided scratch admission");
        let holder = private_tempdir_in(&scratch).expect("temporary private cache under scratch");
        let cache = holder.path().join("cache");
        std::fs::create_dir(&cache).expect("cache directory");
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700))
            .expect("private cache mode");
        CacheFixture { _scratch: holder, cache }
    }

    /// Creates a tagged source pack and returns its validated handle plus the owning directory.
    fn tagged_source(tag: &str) -> (tempfile::TempDir, JavaAttachPack) {
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("the gate must provide an owner-enforced private scratch root");
        let source = private_tempdir_in(&scratch).expect("temporary source pack under scratch");
        make_pack_tagged(source.path(), tag);
        let pack = JavaAttachPack::validate(source.path()).expect("verified source pack");
        (source, pack)
    }

    fn snapshot_name_of(pack: &JavaAttachPack) -> String {
        let manifest = std::fs::read(pack.root().join("pack.manifest")).expect("manifest");
        sha256(&manifest)
    }

    fn sealed_names(cache: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(cache.join(PACKS_DIR))
            .expect("packs")
            .map(|entry| entry.expect("entry").file_name().into_string().expect("utf8"))
            .filter(|name| is_snapshot_name(name))
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn incoming_names(cache: &Path) -> Vec<String> {
        std::fs::read_dir(cache.join(PACKS_DIR))
            .expect("packs")
            .map(|entry| entry.expect("entry").file_name().into_string().expect("utf8"))
            .filter(|name| name.starts_with(INCOMING_PREFIX))
            .collect()
    }

    /// Snapshots a tagged pack, drops its lease at once, and pins its recency to `age_secs` ago.
    fn snapshot_aged(fixture: &CacheFixture, tag: &str, age_secs: u64) -> String {
        let (_source, pack) = tagged_source(tag);
        let name = snapshot_name_of(&pack);
        drop(pack.snapshot_into(&fixture.cache).expect("snapshot"));
        set_recency(&fixture.cache, &name, age_secs);
        name
    }

    fn set_recency(cache: &Path, name: &str, age_secs: u64) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(cache.join(PACKS_DIR).join(STATE_DIR).join(format!("{name}.use")))
            .expect("use file");
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs))
            .expect("recency");
    }

    #[test]
    fn fifth_distinct_build_evicts_the_least_recently_used_snapshot() {
        let fixture = cache_fixture();
        let names = ["a", "b", "c", "d"]
            .iter()
            .zip([400, 300, 200, 100])
            .map(|(tag, age)| snapshot_aged(&fixture, tag, age))
            .collect::<Vec<_>>();
        // Re-attaching the oldest snapshot refreshes its recency, so "b" becomes the LRU.
        let (_source, again) = tagged_source("a");
        drop(again.snapshot_into(&fixture.cache).expect("refresh a"));
        assert_eq!(sealed_names(&fixture.cache).len(), MAX_RETAINED_PACK_SNAPSHOTS);

        let (_source, fifth) = tagged_source("e");
        let fifth_snapshot = fifth.snapshot_into(&fixture.cache).expect("fifth build evicts");
        assert!(JavaAttachPack::validate(fifth_snapshot.root()).is_ok());

        let remaining = sealed_names(&fixture.cache);
        assert_eq!(remaining.len(), MAX_RETAINED_PACK_SNAPSHOTS);
        assert!(!remaining.contains(&names[1]), "the least recently used snapshot is evicted");
        for kept in [&names[0], &names[2], &names[3]] {
            assert!(remaining.contains(kept));
        }
        assert!(incoming_names(&fixture.cache).is_empty());
    }

    #[test]
    fn in_use_snapshot_is_never_evicted_and_a_full_cache_of_leases_fails_closed() {
        let fixture = cache_fixture();
        let held = ["a", "b", "c", "d"]
            .iter()
            .map(|tag| {
                let (source, pack) = tagged_source(tag);
                let snapshot = pack.snapshot_into(&fixture.cache).expect("snapshot");
                (source, snapshot)
            })
            .collect::<Vec<_>>();
        let before = sealed_names(&fixture.cache);

        let (_source, fifth) = tagged_source("e");
        let error = fifth.snapshot_into(&fixture.cache).expect_err("every snapshot is in use");
        assert!(error.to_string().contains("in use"), "clear error: {error}");
        assert_eq!(sealed_names(&fixture.cache), before, "nothing was evicted");
        assert!(incoming_names(&fixture.cache).is_empty(), "failed build leaves no residue");
        for (_, snapshot) in &held {
            assert!(JavaAttachPack::validate(snapshot.root()).is_ok());
        }

        // Releasing only one lease frees exactly that snapshot, even though it is the newest.
        let mut held = held;
        let (_, released) = held.pop().expect("last held snapshot");
        let released_root = released.root().to_path_buf();
        drop(released);
        let (_source, fifth) = tagged_source("e");
        let fifth = fifth.snapshot_into(&fixture.cache).expect("evicts the only unleased snapshot");
        assert!(!released_root.exists());
        for (_, snapshot) in &held {
            assert!(snapshot.root().exists(), "leased snapshots survive");
        }
        assert!(fifth.root().exists());
    }

    #[test]
    fn a_clone_keeps_the_lease_after_the_original_is_dropped() {
        let fixture = cache_fixture();
        let (_source, pack) = tagged_source("a");
        let first = pack.snapshot_into(&fixture.cache).expect("snapshot");
        let clone = first.clone();
        drop(first);
        let others = ["b", "c", "d"]
            .iter()
            .map(|tag| {
                let (source, pack) = tagged_source(tag);
                (source, pack.snapshot_into(&fixture.cache).expect("snapshot"))
            })
            .collect::<Vec<_>>();
        let (_source, fifth) = tagged_source("e");
        assert!(fifth.snapshot_into(&fixture.cache).is_err());
        drop(others);
        let (_source, fifth) = tagged_source("e");
        fifth.snapshot_into(&fixture.cache).expect("others were evictable");
        assert!(clone.root().exists());
    }

    #[test]
    fn crash_residue_does_not_count_and_only_provably_abandoned_residue_is_removed() {
        let fixture = cache_fixture();
        for (tag, age) in [("a", 400), ("b", 300), ("c", 200), ("d", 100)] {
            snapshot_aged(&fixture, tag, age);
        }
        let packs = fixture.cache.join(PACKS_DIR);
        let state = packs.join(STATE_DIR);
        // A crashed builder: sealed directories inside, builder lock file present but unlocked.
        let abandoned = format!("{INCOMING_PREFIX}1-{}", "a".repeat(32));
        std::fs::create_dir_all(packs.join(&abandoned).join("agent")).expect("abandoned build");
        std::fs::write(packs.join(&abandoned).join("agent/file"), b"x").expect("residue file");
        std::fs::set_permissions(
            packs.join(&abandoned).join("agent"),
            std::fs::Permissions::from_mode(0o500),
        )
        .expect("seal residue");
        std::fs::set_permissions(packs.join(&abandoned), std::fs::Permissions::from_mode(0o500))
            .expect("seal residue root");
        std::fs::write(state.join(format!("{abandoned}.build")), b"").expect("abandoned lock");
        std::fs::set_permissions(
            state.join(format!("{abandoned}.build")),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("lock mode");
        // A live builder: its lock is held, so it must be left strictly alone.
        let live = format!("{INCOMING_PREFIX}2-{}", "b".repeat(32));
        std::fs::create_dir(packs.join(&live)).expect("live build");
        std::fs::set_permissions(packs.join(&live), std::fs::Permissions::from_mode(0o700))
            .expect("live mode");
        let live_lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(state.join(format!("{live}.build")))
            .expect("live lock file");
        assert!(try_lock(&live_lock, true).expect("lock"));
        // Unlocked, lockless and young: uncertain, so it is left alone.
        let uncertain = format!("{INCOMING_PREFIX}3-{}", "c".repeat(32));
        std::fs::create_dir(packs.join(&uncertain)).expect("uncertain build");
        std::fs::set_permissions(packs.join(&uncertain), std::fs::Permissions::from_mode(0o700))
            .expect("uncertain mode");

        // Residue never counts toward the cap: a fifth build still succeeds by evicting one.
        let (_source, fifth) = tagged_source("e");
        fifth.snapshot_into(&fixture.cache).expect("fifth build with residue present");

        assert_eq!(sealed_names(&fixture.cache).len(), MAX_RETAINED_PACK_SNAPSHOTS);
        let incoming = incoming_names(&fixture.cache);
        assert!(!incoming.contains(&abandoned), "abandoned residue is removed");
        assert!(!state.join(format!("{abandoned}.build")).exists());
        assert!(incoming.contains(&live), "a live builder is never touched");
        assert!(incoming.contains(&uncertain), "uncertain residue fails closed");
    }

    #[test]
    fn legacy_unverifiable_final_named_directory_is_replaced_only_when_unleased() {
        let fixture = cache_fixture();
        let (_source, pack) = tagged_source("a");
        let name = snapshot_name_of(&pack);
        let packs = fixture.cache.join(PACKS_DIR);
        // Pre-atomic residue: a final-named directory that never validates.
        let (_hold, state_pack) = tagged_source("bootstrap");
        drop(state_pack.snapshot_into(&fixture.cache).expect("creates the cache layout"));
        std::fs::create_dir(packs.join(&name)).expect("legacy residue");
        std::fs::set_permissions(packs.join(&name), std::fs::Permissions::from_mode(0o700))
            .expect("legacy mode");

        let cache = PackCache::open(&fixture.cache).expect("cache");
        let lease = cache.lease(&name).expect("lease");
        let error = pack.snapshot_into(&fixture.cache).expect_err("leased residue is not touched");
        assert!(matches!(error, AttachError::Validation(_)), "the verification error: {error}");
        assert!(packs.join(&name).exists());
        drop(lease);

        let rebuilt = pack.snapshot_into(&fixture.cache).expect("unleased residue is replaced");
        assert!(JavaAttachPack::validate(rebuilt.root()).is_ok());
    }

    #[test]
    fn concurrent_attaches_do_not_corrupt_the_cache() {
        let fixture = cache_fixture();
        let sources = (0..MAX_RETAINED_PACK_SNAPSHOTS)
            .map(|index| tagged_source(&format!("shared-{index}")))
            .collect::<Vec<_>>();
        let results = std::thread::scope(|scope| {
            let handles =
                (0..8)
                    .map(|worker| {
                        let cache = &fixture.cache;
                        let sources = &sources;
                        scope.spawn(move || {
                            let mut outcomes = Vec::new();
                            for round in 0..3 {
                                let (_, pack) = &sources[(worker + round) % sources.len()];
                                outcomes.push(pack.snapshot_into(cache).map(|snapshot| {
                                    JavaAttachPack::validate(snapshot.root()).is_ok()
                                }));
                            }
                            outcomes
                        })
                    })
                    .collect::<Vec<_>>();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().expect("worker"))
                .collect::<Vec<_>>()
        });
        for outcome in results {
            assert!(outcome.expect("attach within the cap succeeds"));
        }
        assert_eq!(sealed_names(&fixture.cache).len(), MAX_RETAINED_PACK_SNAPSHOTS);
        assert!(incoming_names(&fixture.cache).is_empty());
        for name in sealed_names(&fixture.cache) {
            let path = fixture.cache.join(PACKS_DIR).join(name);
            JavaAttachPack::validate(&path).expect("intact snapshot");
            verify_retained_snapshot_directories(&path).expect("sealed snapshot");
        }
    }

    #[test]
    fn concurrent_builds_beyond_the_cap_either_succeed_or_fail_closed_without_corruption() {
        let fixture = cache_fixture();
        let sources =
            (0..6).map(|index| tagged_source(&format!("wide-{index}"))).collect::<Vec<_>>();
        let results = std::thread::scope(|scope| {
            let handles = (0..6)
                .map(|worker| {
                    let cache = &fixture.cache;
                    let (_, pack) = &sources[worker];
                    scope.spawn(move || {
                        pack.snapshot_into(cache).map(|snapshot| snapshot.root().to_path_buf())
                    })
                })
                .collect::<Vec<_>>();
            handles.into_iter().map(|handle| handle.join().expect("worker")).collect::<Vec<_>>()
        });
        for outcome in &results {
            if let Err(error) = outcome {
                assert!(error.to_string().contains("in use"), "clean failure: {error}");
            }
        }
        assert!(sealed_names(&fixture.cache).len() <= MAX_RETAINED_PACK_SNAPSHOTS);
        assert!(incoming_names(&fixture.cache).is_empty());
        for name in sealed_names(&fixture.cache) {
            JavaAttachPack::validate(&fixture.cache.join(PACKS_DIR).join(name)).expect("intact");
        }
    }

    #[test]
    fn unexpected_cache_entries_fail_closed() {
        let fixture = cache_fixture();
        let (_source, pack) = tagged_source("a");
        drop(pack.snapshot_into(&fixture.cache).expect("snapshot"));
        let stray = fixture.cache.join(PACKS_DIR).join("not-a-snapshot");
        std::fs::create_dir(&stray).expect("stray");
        std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let (_source, other) = tagged_source("b");
        assert!(other.snapshot_into(&fixture.cache).is_err());
        assert!(stray.exists(), "unknown entries are never deleted");
    }

    #[test]
    fn streaming_digest_matches_whole_file_digest_across_chunk_boundaries() {
        let root = tempfile::tempdir().expect("temporary files");
        for size in [
            0,
            1,
            STREAM_CHUNK_BYTES - 1,
            STREAM_CHUNK_BYTES,
            STREAM_CHUNK_BYTES + 1,
            3 * STREAM_CHUNK_BYTES + 17,
        ] {
            let bytes = (0..size).map(|index| (index * 31 % 251) as u8).collect::<Vec<_>>();
            let path = root.path().join(format!("file-{size}"));
            std::fs::write(&path, &bytes).expect("fixture");
            let identity =
                FileIdentity::from_metadata(&std::fs::symlink_metadata(&path).expect("metadata"));
            let mut copy = tempfile::tempfile().expect("copy sink");
            let streamed =
                stream_file(&path, identity, MAX_FILE_BYTES, Some(&mut copy)).expect("stream");
            assert_eq!(streamed, sha256(&bytes), "size {size}");
            let mut copied = Vec::new();
            std::io::Read::read_to_end(
                &mut {
                    std::io::Seek::rewind(&mut copy).expect("rewind");
                    copy
                },
                &mut copied,
            )
            .expect("read copy");
            assert_eq!(copied, bytes, "copy of size {size}");
        }
    }

    #[test]
    fn streaming_digest_rejects_size_changes_and_oversize_files() {
        let root = tempfile::tempdir().expect("temporary files");
        let path = root.path().join("file");
        std::fs::write(&path, vec![7_u8; 1000]).expect("fixture");
        let identity =
            FileIdentity::from_metadata(&std::fs::symlink_metadata(&path).expect("metadata"));
        std::fs::write(&path, vec![7_u8; 1001]).expect("grow");
        assert!(stream_file(&path, identity, MAX_FILE_BYTES, None).is_err());
        let identity =
            FileIdentity::from_metadata(&std::fs::symlink_metadata(&path).expect("metadata"));
        assert!(stream_file(&path, identity, 1000, None).is_err());
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
}
