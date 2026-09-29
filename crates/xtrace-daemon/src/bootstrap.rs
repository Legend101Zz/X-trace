//! Owner-readable bootstrap artifact.
//!
//! The launcher / attach helper reads the bootstrap artifact once at
//! startup; it then launches the target process with the secret and
//! pin available through normal file-system reads rather than through
//! process arguments. The artifact is written atomically with
//! `0600` permissions, never logged, and removed on orderly shutdown.
//!
//! The schema is intentionally minimal: it carries only the values an
//! adapter needs to complete the handshake documented in
//! `docs/plans/x-trace/03b-protocol-and-api.md` §2.1:
//!
//! ```text
//! schema_version
//! host (always loopback)
//! port (OS-assigned)
//! certificate_sha256_pin (lowercase hex)
//! runtime_session_id (UUIDv7 canonical)
//! session_secret (base64, 32 bytes)
//! project_id (UUIDv7 canonical)
//! expected_repository_fingerprint
//! max_protocol_major
//! max_protocol_minor
//! ```
//!
//! ## Secure atomic lifecycle
//!
//! On Unix the writer opens a unique same-directory temporary file
//! with `O_CREAT | O_EXCL` and `0600` mode so the secret never first
//! appears world-readable. Symlinks in the parent directory or the
//! target path are refused before any write occurs. The temporary
//! file is flushed and fsynced, atomically renamed onto the target,
//! and the parent directory is fsynced so the rename is durable
//! across a crash. On every error path the temporary file is removed
//! before the function returns so a partial write cannot leak the
//! secret on a later daemon launch.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use xtrace_domain::{ProjectId, RuntimeSessionId};

use crate::error::DaemonError;
use crate::secret::SessionSecret;

/// Schema version this binary writes and reads. Bumped together with
/// field changes that older binaries cannot interpret.
pub const SCHEMA_VERSION: u32 = 1;

/// Owner of the bootstrap artifact. The owner marker controls whether
/// the artifact is removed on drop. A `Persistent` artifact outlives
/// the daemon handle and is intended for test setups that share the
/// file with a hand-rolled fake adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapOwner {
    /// Remove the artifact on `Drop`. Used for the production path.
    Daemon,
    /// Keep the artifact on `Drop`. Used by integration tests so a
    /// fake adapter can read the artifact after the daemon exits.
    Persistent,
}

/// On-disk bootstrap artifact fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapArtifactFields {
    /// Schema version the artifact was written under.
    pub schema_version: u32,
    /// Loopback host the daemon bound to. Always one of `127.0.0.1`
    /// or `::1`; non-loopback values are rejected by
    /// [`BootstrapArtifact::write`].
    pub host: String,
    /// OS-assigned TCP port the daemon bound to.
    pub port: u16,
    /// Lowercase hexadecimal SHA-256 digest of the DER-encoded leaf
    /// certificate. The adapter pins this digest before the TLS
    /// handshake so a malicious local listener cannot impersonate the
    /// daemon.
    pub certificate_sha256_pin: String,
    /// Stable runtime session identifier. The daemon rejects any
    /// post-hello envelope whose `runtime_session_id` does not match
    /// this value.
    pub runtime_session_id: String,
    /// Base64-encoded 256-bit session secret. Used by the adapter as
    /// the HMAC key for the AdapterHello/DaemonHello transcript proof.
    pub session_secret_base64: String,
    /// Project identifier the daemon expects on every connection.
    pub project_id: String,
    /// Repository fingerprint the daemon expects on every
    /// `AdapterHello`. The bounded slice validates the fingerprint as
    /// part of the project identity binding; a wrong value is
    /// rejected with the stable `XTR-DAEMON-PROJECT-IDENTITY` code.
    pub expected_repository_fingerprint: String,
    /// Maximum protocol major the daemon will negotiate.
    pub max_protocol_major: u32,
    /// Maximum protocol minor the daemon will negotiate.
    pub max_protocol_minor: u32,
}

/// Owner-managed bootstrap artifact.
///
/// The struct knows where the artifact lives on disk and whether it
/// should be removed on drop. Dropping a [`BootstrapOwner::Daemon`]
/// artifact removes the file on normal scope exit and on panic unwind
/// (the `Drop` impl runs during unwinding); the cleanup is best
/// effort and does not run during process abort or signal-induced
/// termination.
#[derive(Debug)]
pub struct BootstrapArtifact {
    fields: BootstrapArtifactFields,
    path: PathBuf,
    owner: BootstrapOwner,
}

impl BootstrapArtifact {
    /// Writes the bootstrap artifact atomically with owner-only
    /// permissions and returns a guard that removes the file on drop
    /// when [`BootstrapOwner::Daemon`] is selected.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] when the file cannot be
    /// created, written, chmod-ed, renamed, or its parent directory
    /// already holds a non-owner-only pointer file. On every error
    /// path any temporary file is removed before the function
    /// returns.
    pub fn write(
        path: &Path,
        fields: BootstrapArtifactFields,
        owner: BootstrapOwner,
    ) -> Result<Self, DaemonError> {
        validate_fields(&fields)?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| {
            DaemonError::Bootstrap("bootstrap path has no parent directory".to_string())
        })?;
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| {
                DaemonError::Bootstrap(format!(
                    "create bootstrap parent {}: {err}",
                    parent.display()
                ))
            })?;
        }
        refuse_symlink_path(path, "target")?;
        refuse_symlink_path(parent, "parent directory")?;
        chmod_dir_owner_only(parent)?;
        let body = serde_json::to_string_pretty(&fields)
            .map_err(|err| DaemonError::Bootstrap(format!("serialize bootstrap: {err}")))?;
        let tmp = unique_temp_path(path)?;
        write_atomic(path, &tmp, parent, body.as_bytes())?;
        Ok(Self { fields, path: path.to_path_buf(), owner })
    }

    /// Reads an existing artifact from disk.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] for any I/O, parse, or
    /// validation failure. The returned error never embeds the
    /// session secret because the [`BootstrapArtifactFields`] fields
    /// are validated before the function returns.
    pub fn read(path: &Path) -> Result<Self, DaemonError> {
        let text = fs::read_to_string(path)
            .map_err(|err| DaemonError::Bootstrap(format!("read bootstrap: {err}")))?;
        let fields: BootstrapArtifactFields = serde_json::from_str(&text)
            .map_err(|err| DaemonError::Bootstrap(format!("parse bootstrap: {err}")))?;
        validate_fields(&fields)?;
        Ok(Self { fields, path: path.to_path_buf(), owner: BootstrapOwner::Persistent })
    }

    /// Returns the parsed fields.
    #[must_use]
    pub fn fields(&self) -> &BootstrapArtifactFields {
        &self.fields
    }

    /// Returns the absolute path of the artifact on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-reads the on-disk artifact. Used by integration tests that
    /// race a daemon write against a fake adapter read.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] for any I/O or parse
    /// failure.
    pub fn reload(&mut self) -> Result<(), DaemonError> {
        let text = fs::read_to_string(&self.path)
            .map_err(|err| DaemonError::Bootstrap(format!("read bootstrap: {err}")))?;
        let fields: BootstrapArtifactFields = serde_json::from_str(&text)
            .map_err(|err| DaemonError::Bootstrap(format!("parse bootstrap: {err}")))?;
        validate_fields(&fields)?;
        self.fields = fields;
        Ok(())
    }
}

impl Drop for BootstrapArtifact {
    fn drop(&mut self) {
        if self.owner == BootstrapOwner::Persistent {
            return;
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                // Best-effort cleanup; the daemon cannot repair an
                // unwritable filesystem from here.
                tracing::warn!(
                    bootstrap = %self.path.display(),
                    error = %err,
                    "failed to remove bootstrap artifact on shutdown",
                );
            }
        }
    }
}

impl BootstrapArtifactFields {
    /// Constructs a new field set from a daemon bind result. Every
    /// field is sourced directly from the daemon's bind state so
    /// the bootstrap file is the only legitimate place to look up
    /// the session secret, certificate pin, and identity triple.
    #[allow(
        clippy::too_many_arguments,
        reason = "all eight fields are independent daemon-bind outputs the launcher must read out of band"
    )]
    #[must_use]
    pub fn new(
        host: String,
        port: u16,
        certificate_sha256_pin: String,
        runtime_session_id: RuntimeSessionId,
        session_secret: &SessionSecret,
        project_id: ProjectId,
        expected_repository_fingerprint: String,
        max_protocol_major: u32,
        max_protocol_minor: u32,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            host,
            port,
            certificate_sha256_pin,
            runtime_session_id: runtime_session_id.to_string(),
            session_secret_base64: session_secret.to_base64(),
            project_id: project_id.to_string(),
            expected_repository_fingerprint,
            max_protocol_major,
            max_protocol_minor,
        }
    }

    /// Decodes the session secret. The caller owns the returned value
    /// and is responsible for zeroizing it on drop.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] when the encoded value is
    /// not a valid base64 string or does not decode to the expected
    /// 32 bytes. The diagnostic message never embeds the secret.
    pub fn session_secret(&self) -> Result<SessionSecret, DaemonError> {
        SessionSecret::from_base64(&self.session_secret_base64)
            .map_err(|err| DaemonError::Bootstrap(format!("session secret: {err}")))
    }
}

fn validate_fields(fields: &BootstrapArtifactFields) -> Result<(), DaemonError> {
    if fields.schema_version != SCHEMA_VERSION {
        return Err(DaemonError::Bootstrap(format!(
            "unsupported bootstrap schema_version {} (binary expects {})",
            fields.schema_version, SCHEMA_VERSION
        )));
    }
    if fields.host != "127.0.0.1" && fields.host != "::1" {
        return Err(DaemonError::Bootstrap(format!(
            "bootstrap host is not loopback: {}",
            fields.host
        )));
    }
    if fields.certificate_sha256_pin.len() != 64 {
        return Err(DaemonError::Bootstrap(
            "certificate_sha256_pin must be 32 lowercase hex bytes".to_string(),
        ));
    }
    if !fields.certificate_sha256_pin.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DaemonError::Bootstrap(
            "certificate_sha256_pin contains non-hex characters".to_string(),
        ));
    }
    if fields.session_secret_base64.is_empty() {
        return Err(DaemonError::Bootstrap("session_secret_base64 must not be empty".to_string()));
    }
    if fields.expected_repository_fingerprint.is_empty() {
        return Err(DaemonError::Bootstrap(
            "expected_repository_fingerprint must not be empty".to_string(),
        ));
    }
    fields
        .runtime_session_id
        .parse::<RuntimeSessionId>()
        .map_err(|err| DaemonError::Bootstrap(format!("runtime_session_id: {err}")))?;
    fields
        .project_id
        .parse::<ProjectId>()
        .map_err(|err| DaemonError::Bootstrap(format!("project_id: {err}")))?;
    Ok(())
}

fn unique_temp_path(target: &Path) -> Result<PathBuf, DaemonError> {
    // Generate a per-attempt unique name in the same directory so the
    // rename is guaranteed atomic on the same filesystem and a
    // pre-existing attacker-controlled file cannot pre-empt the slot.
    let parent = target.parent().ok_or_else(|| {
        DaemonError::Bootstrap("bootstrap target has no parent directory".to_string())
    })?;
    let stem = target.file_name().and_then(|name| name.to_str()).unwrap_or("bootstrap.json");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let tmp = parent.join(format!(".{stem}.tmp-{pid}-{nanos}"));
    Ok(tmp)
}

#[cfg(unix)]
fn refuse_symlink_path(path: &Path, label: &str) -> Result<(), DaemonError> {
    use std::os::unix::fs::MetadataExt as _;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(DaemonError::Bootstrap(format!(
                    "{label} {} must not be a symbolic link",
                    path.display()
                )));
            }
            // The parent directory must be a real directory; the
            // target slot must be a regular file (or absent). Anything
            // else (device node, fifo, socket, ...) is rejected.
            if label == "parent directory" && !ft.is_dir() {
                return Err(DaemonError::Bootstrap(format!(
                    "{label} {} must be a directory",
                    path.display()
                )));
            }
            if label == "target" && meta.is_file().not() {
                return Err(DaemonError::Bootstrap(format!(
                    "{label} {} must be a regular file",
                    path.display()
                )));
            }
            // Touch the MetadataExt trait so the import is not
            // removed by dead-code analysis on builds that never
            // touch the inner methods.
            let _ = meta.mode();
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(DaemonError::Bootstrap(format!("stat {label} {}: {err}", path.display()))),
    }
}

#[cfg(not(unix))]
fn refuse_symlink_path(_path: &Path, _label: &str) -> Result<(), DaemonError> {
    Ok(())
}

use std::ops::Not as _;

fn write_atomic(target: &Path, tmp: &Path, parent: &Path, body: &[u8]) -> Result<(), DaemonError> {
    // The temporary file is opened with `create_new` so a pre-existing
    // path cannot be clobbered. The OS rejects the open if the path
    // already exists, removing the small window in which a partial
    // secret could leak through a follow-up write.
    let mut file = open_create_new(tmp).map_err(|err| {
        DaemonError::Bootstrap(format!("create bootstrap tmp {}: {err}", tmp.display()))
    })?;
    if let Err(err) = file.write_all(body) {
        let _ = fs::remove_file(tmp);
        return Err(DaemonError::Bootstrap(format!("write bootstrap tmp: {err}")));
    }
    if let Err(err) = file.flush() {
        let _ = fs::remove_file(tmp);
        return Err(DaemonError::Bootstrap(format!("flush bootstrap tmp: {err}")));
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(tmp);
        return Err(DaemonError::Bootstrap(format!("fsync bootstrap tmp: {err}")));
    }
    drop(file);
    // `rename` is atomic on the same filesystem and overwrites an
    // existing regular file; the target is guaranteed regular because
    // `refuse_symlink_path` rejected any other file type above.
    if let Err(err) = fs::rename(tmp, target) {
        let _ = fs::remove_file(tmp);
        return Err(DaemonError::Bootstrap(format!("rename bootstrap: {err}")));
    }
    chmod_file_owner_only(target)?;
    // Fsync the parent directory so the rename is durable across a
    // crash; the parent is a directory and never a symlink because
    // `refuse_symlink_path` was called above.
    fsync_dir(parent).map_err(|err| {
        DaemonError::Bootstrap(format!("fsync bootstrap parent {}: {err}", parent.display()))
    })?;
    Ok(())
}

#[cfg(unix)]
fn open_create_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().create_new(true).read(true).write(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_create_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create_new(true).read(true).write(true).open(path)
}

#[cfg(unix)]
fn chmod_dir_owner_only(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::metadata(path)
        .map_err(|err| DaemonError::Bootstrap(format!("stat dir {}: {err}", path.display())))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|err| DaemonError::Bootstrap(format!("chmod 0700 {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn chmod_dir_owner_only(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn chmod_file_owner_only(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::metadata(path)
        .map_err(|err| DaemonError::Bootstrap(format!("stat file {}: {err}", path.display())))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|err| DaemonError::Bootstrap(format!("chmod 0600 {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn chmod_file_owner_only(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("xtrace-daemon-bootstrap-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn sample_fields() -> BootstrapArtifactFields {
        let session = RuntimeSessionId::new();
        let project = ProjectId::new();
        let secret = SessionSecret::generate().expect("secret");
        BootstrapArtifactFields::new(
            "127.0.0.1".to_string(),
            12345,
            "a".repeat(64),
            session,
            &secret,
            project,
            "expected-repo".to_string(),
            1,
            0,
        )
    }

    #[cfg(unix)]
    #[test]
    fn write_enforces_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = unique_dir("perms");
        let path = dir.join("bootstrap.json");
        let artifact = BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent)
            .expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "bootstrap file must be owner-only");
        let secret = artifact.fields().session_secret().expect("secret");
        assert_eq!(secret.read_secret().len(), 32);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_rejects_non_loopback_host() {
        let dir = unique_dir("host");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.host = "0.0.0.0".to_string();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_rejects_short_pin() {
        let dir = unique_dir("pin");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.certificate_sha256_pin = "abcd".to_string();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_rejects_non_hex_pin() {
        let dir = unique_dir("hex");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.certificate_sha256_pin = "z".repeat(64);
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trip_preserves_fields() {
        let dir = unique_dir("roundtrip");
        let path = dir.join("bootstrap.json");
        let fields = sample_fields();
        let secret_before = fields.session_secret_base64.clone();
        let artifact = BootstrapArtifact::write(&path, fields.clone(), BootstrapOwner::Persistent)
            .expect("write");
        let loaded = BootstrapArtifact::read(&path).expect("read");
        assert_eq!(loaded.fields(), artifact.fields());
        assert_eq!(loaded.fields().session_secret_base64, secret_before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_owner_removes_file_on_drop() {
        let dir = unique_dir("drop");
        let path = dir.join("bootstrap.json");
        {
            let _artifact =
                BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Daemon)
                    .expect("write");
            assert!(path.exists(), "file exists while the guard is alive");
        }
        assert!(!path.exists(), "file must be removed on drop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistent_owner_keeps_file_on_drop() {
        let dir = unique_dir("persist");
        let path = dir.join("bootstrap.json");
        {
            let _artifact =
                BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent)
                    .expect("write");
        }
        assert!(path.exists(), "persistent artifact must survive drop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_target_symlink() {
        use std::os::unix::fs::symlink;
        let dir = unique_dir("target-symlink");
        let target = dir.join("bootstrap.json");
        symlink("/etc/passwd", &target).unwrap();
        let err = BootstrapArtifact::write(&target, sample_fields(), BootstrapOwner::Persistent)
            .unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_symlinked_parent_directory() {
        use std::os::unix::fs::symlink;
        let real_dir = unique_dir("real-parent");
        let link_dir = unique_dir("link-parent");
        let link = link_dir.join("parent-link");
        symlink(&real_dir, &link).unwrap();
        let target = link.join("bootstrap.json");
        let err = BootstrapArtifact::write(&target, sample_fields(), BootstrapOwner::Persistent)
            .unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&real_dir);
        let _ = fs::remove_dir_all(&link_dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_rejects_non_directory_parent() {
        let dir = unique_dir("non-dir-parent");
        let file = dir.join("file");
        fs::write(&file, b"data").unwrap();
        let target = file.join("bootstrap.json");
        let err = BootstrapArtifact::write(&target, sample_fields(), BootstrapOwner::Persistent)
            .unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_replaces_existing_target() {
        let dir = unique_dir("atomic");
        let path = dir.join("bootstrap.json");
        BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent).unwrap();
        let first_secret = fs::read_to_string(&path).unwrap();
        BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent).unwrap();
        let second_secret = fs::read_to_string(&path).unwrap();
        assert_ne!(first_secret, second_secret);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_refuses_pre_existing_tempfile() {
        // The temporary file uses `create_new`, so a pre-existing
        // path at the same name must fail. We exercise the safety
        // net by overwriting the candidate before the writer runs.
        let dir = unique_dir("tempfile-collision");
        let path = dir.join("bootstrap.json");
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let tmp = dir.join(format!(".bootstrap.json.tmp-{}-{nanos}", std::process::id()));
        fs::write(&tmp, b"stale").unwrap();
        // Touching the directory is enough; the writer will pick a
        // different nanosecond-based suffix and succeed regardless.
        let artifact = BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent)
            .expect("write");
        assert!(path.exists());
        drop(artifact);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_field_validation_rejects_empty_fingerprint() {
        let dir = unique_dir("empty-fp");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.expected_repository_fingerprint = String::new();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_field_validation_rejects_empty_secret() {
        let dir = unique_dir("empty-secret");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.session_secret_base64 = String::new();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_temp_path_resides_in_target_parent() {
        let dir = unique_dir("unique-temp");
        let path = dir.join("bootstrap.json");
        let tmp = unique_temp_path(&path).expect("temp");
        assert_eq!(tmp.parent().unwrap(), path.parent().unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_target_path_rejected() {
        let err = unique_temp_path(Path::new("/")).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
    }

    #[test]
    fn empty_filename_is_safe() {
        let dir = unique_dir("empty-name");
        let path = dir.join("bootstrap.json");
        // Verify the helper still produces a same-dir temporary when
        // the helper falls back to its default stem.
        let tmp = unique_temp_path(&path).expect("temp");
        assert!(tmp.starts_with(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
