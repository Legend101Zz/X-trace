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
//! max_protocol_major
//! max_protocol_minor
//! ```
//!
//! Future slices add fields (capture policy digest, source revision,
//! ...) without bumping the schema version unless the existing fields
//! change meaning.

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
    /// Maximum protocol major the daemon will negotiate.
    pub max_protocol_major: u32,
    /// Maximum protocol minor the daemon will negotiate.
    pub max_protocol_minor: u32,
}

/// Owner-managed bootstrap artifact.
///
/// The struct knows where the artifact lives on disk and whether it
/// should be removed on drop. Dropping a [`BootstrapOwner::Daemon`]
/// artifact removes the file even on panic (the `Drop` impl runs
/// during unwind).
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
    /// already holds a non-owner-only pointer file.
    pub fn write(
        path: &Path,
        fields: BootstrapArtifactFields,
        owner: BootstrapOwner,
    ) -> Result<Self, DaemonError> {
        validate_fields(&fields)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).map_err(|err| {
                    DaemonError::Bootstrap(format!(
                        "create bootstrap parent {}: {err}",
                        parent.display()
                    ))
                })?;
            }
            chmod_dir_owner_only(parent)?;
        }
        let body = serde_json::to_string_pretty(&fields).map_err(|err| {
            DaemonError::Bootstrap(format!("serialize bootstrap: {err}"))
        })?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut file = fs::File::create(&tmp).map_err(|err| {
                DaemonError::Bootstrap(format!(
                    "create bootstrap tmp {}: {err}",
                    tmp.display()
                ))
            })?;
            file.write_all(body.as_bytes()).map_err(|err| {
                DaemonError::Bootstrap(format!("write bootstrap tmp: {err}"))
            })?;
            file.sync_all().map_err(|err| {
                DaemonError::Bootstrap(format!("fsync bootstrap tmp: {err}"))
            })?;
        }
        chmod_file_owner_only(&tmp)?;
        fs::rename(&tmp, path).map_err(|err| {
            DaemonError::Bootstrap(format!("rename bootstrap: {err}"))
        })?;
        chmod_file_owner_only(path)?;
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
        let text = fs::read_to_string(path).map_err(|err| {
            DaemonError::Bootstrap(format!("read bootstrap: {err}"))
        })?;
        let fields: BootstrapArtifactFields = serde_json::from_str(&text).map_err(|err| {
            DaemonError::Bootstrap(format!("parse bootstrap: {err}"))
        })?;
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
        let text = fs::read_to_string(&self.path).map_err(|err| {
            DaemonError::Bootstrap(format!("read bootstrap: {err}"))
        })?;
        let fields: BootstrapArtifactFields = serde_json::from_str(&text).map_err(|err| {
            DaemonError::Bootstrap(format!("parse bootstrap: {err}"))
        })?;
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
    /// Constructs a new field set from a daemon bind result.
    #[must_use]
    pub fn new(
        host: String,
        port: u16,
        certificate_sha256_pin: String,
        runtime_session_id: RuntimeSessionId,
        session_secret: &SessionSecret,
        project_id: ProjectId,
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
        return Err(DaemonError::Bootstrap(
            "session_secret_base64 must not be empty".to_string(),
        ));
    }
    // Project and session identifiers are validated as canonical
    // UUIDv7 strings through their `FromStr` implementations.
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

#[cfg(unix)]
fn chmod_dir_owner_only(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::metadata(path).map_err(|err| {
        DaemonError::Bootstrap(format!("stat dir {}: {err}", path.display()))
    })?;
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
    let metadata = fs::metadata(path).map_err(|err| {
        DaemonError::Bootstrap(format!("stat file {}: {err}", path.display()))
    })?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|err| DaemonError::Bootstrap(format!("chmod 0600 {}: {err}", path.display())))
}

#[cfg(not(unix))]
fn chmod_file_owner_only(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(label: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
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
            1,
            0,
        )
    }

    #[cfg(unix)]
    #[test]
    fn write_enforces_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir("perms");
        let path = dir.join("bootstrap.json");
        let artifact = BootstrapArtifact::write(
            &path,
            sample_fields(),
            BootstrapOwner::Persistent,
        )
        .expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "bootstrap file must be owner-only");
        // Round-trip the session secret so we do not lose the test
        // value.
        let secret = artifact.fields().session_secret().expect("secret");
        assert_eq!(secret.read_secret().len(), 32);
    }

    #[test]
    fn write_rejects_non_loopback_host() {
        let dir = tempdir("host");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.host = "0.0.0.0".to_string();
        let err = BootstrapArtifact::write(
            &path,
            fields,
            BootstrapOwner::Persistent,
        )
        .unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
    }

    #[test]
    fn write_rejects_short_pin() {
        let dir = tempdir("pin");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.certificate_sha256_pin = "abcd".to_string();
        let err = BootstrapArtifact::write(
            &path,
            fields,
            BootstrapOwner::Persistent,
        )
        .unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
    }

    #[test]
    fn write_rejects_non_hex_pin() {
        let dir = tempdir("hex");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.certificate_sha256_pin = "z".repeat(64);
        let err = BootstrapArtifact::write(
            &path,
            fields,
            BootstrapOwner::Persistent,
        )
        .unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
    }

    #[test]
    fn round_trip_preserves_fields() {
        let dir = tempdir("roundtrip");
        let path = dir.join("bootstrap.json");
        let fields = sample_fields();
        let secret_before = fields.session_secret_base64.clone();
        let artifact = BootstrapArtifact::write(
            &path,
            fields.clone(),
            BootstrapOwner::Persistent,
        )
        .expect("write");
        let loaded = BootstrapArtifact::read(&path).expect("read");
        assert_eq!(loaded.fields(), artifact.fields());
        assert_eq!(loaded.fields().session_secret_base64, secret_before);
    }

    #[test]
    fn daemon_owner_removes_file_on_drop() {
        let dir = tempdir("drop");
        let path = dir.join("bootstrap.json");
        {
            let _artifact = BootstrapArtifact::write(
                &path,
                sample_fields(),
                BootstrapOwner::Daemon,
            )
            .expect("write");
            assert!(path.exists(), "file exists while the guard is alive");
        }
        assert!(!path.exists(), "file must be removed on drop");
    }

    #[test]
    fn persistent_owner_keeps_file_on_drop() {
        let dir = tempdir("persist");
        let path = dir.join("bootstrap.json");
        {
            let _artifact = BootstrapArtifact::write(
                &path,
                sample_fields(),
                BootstrapOwner::Persistent,
            )
            .expect("write");
        }
        assert!(path.exists(), "persistent artifact must survive drop");
        let _ = fs::remove_file(&path);
    }
}