//! Owner-readable bootstrap artifact.
//!
//! The launcher / attach helper reads the bootstrap artifact once at
//! startup; it then launches the target process with the secret and
//! pin available through normal file-system reads rather than through
//! process arguments. The artifact is written atomically with
//! `0600` permissions, never logged, and removed after the
//! negotiated session is established (`docs/plans/x-trace/03b-protocol-and-api.md`
//! §2.1: "Bootstrap files expire, are deleted after negotiation, and
//! are never copied to diagnostics.").
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
//! expected_repository_fingerprint (canonical ContentHash form)
//! max_protocol_major
//! max_protocol_minor
//! ```
//!
//! ## Secure atomic lifecycle
//!
//! On Unix the writer opens a unique same-directory temporary file
//! with `O_CREAT | O_EXCL` and `0600` mode so the secret never first
//! appears world-readable. The candidate path uses a CSPRNG-derived
//! suffix; on `AlreadyExists` the writer retries with a fresh suffix
//! up to a bounded budget. On failure, cleanup removes a temporary or
//! published name only when it still identifies the exact open file
//! created by this writer. If ownership cannot be proved, cleanup
//! preserves the name rather than deleting a replacement.
//!
//! Symlinks in the parent directory or the target path are refused
//! before any write occurs, both during the initial write and on
//! every subsequent read. The reader also enforces `0600` permission
//! bits on Unix so a deployment where another user can write to the
//! target slot cannot impersonate the daemon.
//!
//! ## Deletion after negotiation
//!
//! Once the daemon finishes writing `DaemonHello` to the wire, the
//! shared `Arc<BootstrapArtifact>` value is passed through the
//! crate-private `try_release` helper. The release path is
//! serialised through a small [`std::sync::Mutex`] that protects
//! both the released flag and the [`std::fs::remove_file`] syscall;
//! the lock is uncontended in the common case and only wraps a
//! single local syscall, so it does not introduce meaningful
//! contention. On success or [`std::io::ErrorKind::NotFound`] the
//! released flag is set so concurrent callers racing on the same
//! `Arc<...>` see the `AlreadyReleased` outcome; on any other
//! failure the flag is left unset so the supervisor's caller-visible
//! error path and the [`Drop`] fallback can both retry. Failed proof
//! exchanges never call the release path so a legitimate retry
//! against the same daemon launch can re-read the artifact.
//!
//! The [`Drop`] impl calls `try_release` as a fallback so an
//! orderly shutdown still removes the file when no connection ever
//! reached the post-hello milestone. The fallback is best-effort:
//! a non-`NotFound` I/O error is logged at error level and the
//! original `Drop` continues without panicking. Once `Drop` has
//! begun on a value, no later caller can retry through that same
//! instance; a subsequent launch writes a fresh artifact.

#[cfg(test)]
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use xtrace_domain::{ProjectId, RepositoryFingerprint, RuntimeSessionId};
use xtrace_private_storage::{AdmittedPrivateRoot, PrivateStorageError};
use zeroize::Zeroize;

use crate::error::DaemonError;
use crate::secret::SessionSecret;

/// Schema version this binary writes and reads. Bumped together with
/// field changes that older binaries cannot interpret.
pub const SCHEMA_VERSION: u32 = 1;

/// Marker written by the redacted `Debug` implementation so tests and
/// log scrapers can assert the session secret is never serialized.
/// Prefix of in-flight bootstrap temp files; must equal the identical literal
/// in `xtrace-cli` `daemon_lock.rs` (asserted by a test there).
pub const TEMP_BOOTSTRAP_PREFIX: &str = ".bootstrap.json.tmp-";
const SESSION_SECRET_REDACTED: &str = "<redacted>";

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
///
/// `Debug` is implemented manually so the session secret is never
/// serialized through formatter machinery. `Clone`, `Serialize`,
/// `Deserialize`, `PartialEq`, and `Eq` are derived because the
/// wire/file contract and the equality probes documented in the module
/// header depend on them; the secret value still travels through
/// `serialize` / `deserialize` on the bootstrap file itself, but never
/// through `format!`, `{:?}`, log macros, or the redacted accessor.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    ///
    /// The string is zeroized best-effort when this struct is dropped
    /// so the heap-allocated buffer the value still owns at drop time
    /// is cleared. The guarantee is intentionally limited: zeroize
    /// only covers the bytes this value still owns; any clone dropped
    /// earlier only zeroes its own copy, any clone dropped later only
    /// zeroes its own copy, and any compiler-introduced transient
    /// copy or read access through [`serde`] before drop is outside
    /// this type's reach. Process abort, signal-induced termination,
    /// and optimizer-elided writes are not covered either.
    pub session_secret_base64: String,
    /// Project identifier the daemon writes into the bootstrap
    /// artifact and retains as daemon-side context for the lifetime
    /// of the runtime session. The identifier is **not** carried on
    /// the wire (the `AgentEnvelope` schema has no `project_id`
    /// field) and does **not** participate in the
    /// `expected_repository_fingerprint` comparison performed on
    /// every inbound `AdapterHello`.
    pub project_id: String,
    /// Repository fingerprint the daemon expects on every
    /// `AdapterHello`. Stored in the canonical `b3:<64 lowercase hex>`
    /// form so any deployment that copies the artifact cannot smuggle
    /// in a fingerprint that the domain fingerprint parser would
    /// reject.
    pub expected_repository_fingerprint: String,
    /// Maximum protocol major the daemon will negotiate.
    pub max_protocol_major: u32,
    /// Maximum protocol minor the daemon will negotiate.
    pub max_protocol_minor: u32,
}

impl std::fmt::Debug for BootstrapArtifactFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapArtifactFields")
            .field("schema_version", &self.schema_version)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("certificate_sha256_pin", &self.certificate_sha256_pin)
            .field("runtime_session_id", &self.runtime_session_id)
            .field("session_secret_base64", &SESSION_SECRET_REDACTED)
            .field("project_id", &self.project_id)
            .field("expected_repository_fingerprint", &self.expected_repository_fingerprint)
            .field("max_protocol_major", &self.max_protocol_major)
            .field("max_protocol_minor", &self.max_protocol_minor)
            .finish()
    }
}

impl Drop for BootstrapArtifactFields {
    fn drop(&mut self) {
        // Best-effort zeroize of the secret's heap buffer. The
        // documented limited guarantee is reproduced in the field's
        // rustdoc; the goal is to clear the bytes this struct still
        // owns at drop time, nothing more.
        let bytes = std::mem::take(&mut self.session_secret_base64).into_bytes();
        let mut bytes = bytes;
        bytes.zeroize();
    }
}

/// Outcome reported by the crate-private `try_release` helper.
///
/// The variant tells the caller whether this invocation actually
/// performed the on-disk deletion or merely observed an earlier
/// successful release. Security-sensitive callers must surface an
/// `Err` from the helper rather than treat any non-`Released`
/// outcome as success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReleaseOutcome {
    /// This call performed the on-disk deletion.
    Released,
    /// The artifact had already been released by an earlier caller;
    /// no filesystem work happened on this call.
    AlreadyReleased,
}

/// Internal release state guarded by [`BootstrapArtifact::release_lock`].
#[derive(Debug)]
enum ReleaseState {
    /// The artifact has not yet been released; a fresh `remove_file`
    /// attempt is allowed.
    Pending,
    /// The artifact has been released (or never existed); subsequent
    /// callers see [`ReleaseOutcome::AlreadyReleased`].
    Released,
}

/// Owner-managed bootstrap artifact.
///
/// The struct knows where the artifact lives on disk and whether it
/// should be removed on drop. The release path is split into three
/// layers so the `docs/plans/x-trace/03b-protocol-and-api.md` §2.1
/// contract is satisfied: a successful `DaemonHello` write calls the
/// crate-private `try_release` helper on the shared `Arc<...>`
/// value so the artifact is removed exactly once during normal
/// operation; the `Drop` impl calls the same helper as a fallback
/// so an orderly daemon shutdown still cleans up if no connection
/// ever succeeded; the [`BootstrapOwner::Persistent`] variant skips
/// both paths so integration tests can inspect the artifact after
/// the daemon exits.
///
/// The release helper is race-free under concurrent connection tasks:
/// a small [`Mutex`] serialises the released flag and the
/// [`std::fs::remove_file`] syscall so the flag is set only after a
/// successful unlink (or a `NotFound`). A failed non-`NotFound`
/// unlink leaves the flag unset so a subsequent caller, the
/// `Drop` impl, or a second connection's post-hello milestone can
/// retry without re-issuing the work that already succeeded.
///
/// `Debug` is implemented manually so the redacted
/// [`BootstrapArtifactFields`] marker is the only secret-bearing
/// string that can reach a log line or a diagnostic dump.
pub struct BootstrapArtifact {
    fields: BootstrapArtifactFields,
    path: PathBuf,
    private_parent: AdmittedPrivateRoot,
    owner: BootstrapOwner,
    /// Serialises the released flag and the unlink syscall so the
    /// flag is observed exactly when the file has actually been
    /// removed (or was already absent). The lock is uncontended in
    /// the common case and only wraps a single local syscall, so it
    /// does not introduce meaningful contention.
    release_lock: Mutex<ReleaseState>,
}

impl std::fmt::Debug for BootstrapArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let released = matches!(
            *self.release_lock.lock().unwrap_or_else(|err| err.into_inner()),
            ReleaseState::Released,
        );
        f.debug_struct("BootstrapArtifact")
            .field("fields", &self.fields)
            .field("path", &self.path)
            .field("owner", &self.owner)
            .field("released", &released)
            .finish()
    }
}

impl BootstrapArtifact {
    /// Writes the bootstrap artifact atomically with owner-only
    /// permissions and returns a guard that removes the file on drop
    /// when [`BootstrapOwner::Daemon`] is selected.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] when the file cannot be
    /// created, written, renamed, or its parent directory fails the
    /// admitted private-storage policy. Any temporary file is removed
    /// only when its descriptor still proves ownership.
    pub fn write(
        path: &Path,
        fields: BootstrapArtifactFields,
        owner: BootstrapOwner,
    ) -> Result<Self, DaemonError> {
        validate_fields(&fields)?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| {
            DaemonError::Bootstrap("bootstrap path has no parent directory".to_string())
        })?;
        let private_parent = AdmittedPrivateRoot::open(parent)
            .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
        private_parent
            .revalidate()
            .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
        let target_name = path.file_name().and_then(|value| value.to_str()).ok_or_else(|| {
            DaemonError::Bootstrap("bootstrap target name is invalid".to_string())
        })?;
        if private_parent
            .bounded_child_names(64)
            .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?
            .iter()
            .any(|name| name == target_name)
        {
            let existing = private_parent.open_regular_file(target_name).map_err(|_| {
                DaemonError::Bootstrap("private storage is unavailable".to_string())
            })?;
            drop(existing);
        }
        let body = serde_json::to_string_pretty(&fields)
            .map_err(|err| DaemonError::Bootstrap(format!("serialize bootstrap: {err}")))?;
        write_atomic_admitted(&private_parent, target_name, body.as_bytes())?;
        Ok(Self {
            fields,
            path: path.to_path_buf(),
            private_parent,
            owner,
            release_lock: Mutex::new(ReleaseState::Pending),
        })
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
        let (private_parent, basename) = admit_bootstrap_path(path)?;
        let name = basename.to_str().ok_or_else(|| {
            DaemonError::Bootstrap("bootstrap target name is invalid".to_string())
        })?;
        const MAX_BOOTSTRAP_BYTES: usize = 16 * 1024;
        let bytes = private_parent
            .read_bounded_file(name, MAX_BOOTSTRAP_BYTES)
            .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
        let fields: BootstrapArtifactFields = serde_json::from_slice(&bytes)
            .map_err(|err| DaemonError::Bootstrap(format!("parse bootstrap: {err}")))?;
        validate_fields(&fields)?;
        Ok(Self {
            fields,
            path: path.to_path_buf(),
            private_parent,
            owner: BootstrapOwner::Persistent,
            release_lock: Mutex::new(ReleaseState::Pending),
        })
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

    /// Attempts to remove the on-disk artifact exactly once. The
    /// method is the shared call site the supervisor and the
    /// [`Drop`] fallback go through to honour the
    /// `docs/plans/x-trace/03b-protocol-and-api.md` §2.1 contract
    /// that the bootstrap file is deleted after the negotiated
    /// session is established.
    ///
    /// The returned [`ReleaseOutcome`] tells the caller whether this
    /// invocation performed the deletion ([`ReleaseOutcome::Released`])
    /// or merely observed an earlier successful release
    /// ([`ReleaseOutcome::AlreadyReleased`]). A
    /// [`BootstrapOwner::Persistent`] artifact never touches the
    /// filesystem and always reports [`ReleaseOutcome::AlreadyReleased`].
    ///
    /// A non-`NotFound` I/O failure is returned as
    /// [`DaemonError::Bootstrap`] without logging so the supervisor
    /// caller surfaces a typed cleanup error instead of a swallowed
    /// boolean. The released flag is **not** set on such a failure
    /// so a later caller (a retry in the supervisor path or the
    /// `Drop` fallback after the supervisor returned) can attempt
    /// the removal again. The helper does not log on failure; the
    /// [`Drop`] impl logs once when its fallback attempt also
    /// fails, which keeps a single attempt path observable.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] when the underlying
    /// [`std::fs::remove_file`] fails with an error other than
    /// [`std::io::ErrorKind::NotFound`]. The diagnostic message
    /// never embeds the session secret or any other captured value.
    pub(crate) fn try_release(&self) -> Result<ReleaseOutcome, DaemonError> {
        if self.owner == BootstrapOwner::Persistent {
            return Ok(ReleaseOutcome::AlreadyReleased);
        }
        let mut state = self.release_lock.lock().unwrap_or_else(|err| err.into_inner());
        if matches!(*state, ReleaseState::Released) {
            return Ok(ReleaseOutcome::AlreadyReleased);
        }
        let target_name =
            self.path.file_name().and_then(|value| value.to_str()).ok_or_else(|| {
                DaemonError::Bootstrap("bootstrap target name is invalid".to_string())
            })?;
        match self.private_parent.remove_private_file(target_name) {
            Ok(()) => {
                *state = ReleaseState::Released;
                Ok(ReleaseOutcome::Released)
            }
            Err(_)
                if self
                    .private_parent
                    .bounded_child_names(64)
                    .is_ok_and(|names| !names.iter().any(|name| name == target_name)) =>
            {
                // The file is already gone; mark the artifact as
                // released so subsequent callers see a stable view.
                *state = ReleaseState::Released;
                Ok(ReleaseOutcome::Released)
            }
            Err(_) => {
                Err(DaemonError::Bootstrap("private bootstrap cleanup is unavailable".to_string()))
            }
        }
    }

    /// Re-reads the on-disk artifact. Used by integration tests that
    /// race a daemon write against a fake adapter read.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] for any I/O or parse
    /// failure.
    pub fn reload(&mut self) -> Result<(), DaemonError> {
        let name = self.path.file_name().and_then(|value| value.to_str()).ok_or_else(|| {
            DaemonError::Bootstrap("bootstrap target name is invalid".to_string())
        })?;
        const MAX_BOOTSTRAP_BYTES: usize = 16 * 1024;
        let bytes = self
            .private_parent
            .read_bounded_file(name, MAX_BOOTSTRAP_BYTES)
            .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
        let fields: BootstrapArtifactFields = serde_json::from_slice(&bytes)
            .map_err(|err| DaemonError::Bootstrap(format!("parse bootstrap: {err}")))?;
        validate_fields(&fields)?;
        self.fields = fields;
        Ok(())
    }
}

impl Drop for BootstrapArtifact {
    fn drop(&mut self) {
        // Fallback cleanup path: when no connection ever completes a
        // successful `DaemonHello`, the orderly shutdown still has to
        // honour the §2.1 deletion contract. The mutex-guarded flag
        // prevents a double-deletion when a connection task already
        // called [`BootstrapArtifact::try_release`] on this instance,
        // and the helper returns an `Err` rather than silently
        // masking a real cleanup failure. A persistent artifact is
        // a no-op here, matching the explicit-release contract.
        //
        // The drop path is best-effort: a non-`NotFound` failure is
        // logged at error level so the diagnostic is visible in the
        // owner-only log, and the original `Drop` continues without
        // panicking. This is the single observable log site for the
        // release path; the helper itself never logs so a retry in
        // the supervisor caller cannot multiply the diagnostic. Once
        // `Drop` has begun on this instance, no further retry is
        // possible through the same handle; the next daemon launch
        // writes a fresh artifact.
        match self.try_release() {
            Ok(_) => {}
            Err(err) => {
                tracing::error!(
                    bootstrap = %self.path.display(),
                    error = %err,
                    "bootstrap artifact drop fallback failed; the file remains on disk",
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
        expected_repository_fingerprint: RepositoryFingerprint,
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
            expected_repository_fingerprint: expected_repository_fingerprint.as_str().to_string(),
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

    /// Returns the expected repository fingerprint as a domain type.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Bootstrap`] when the stored value is
    /// not in canonical `b3:<64 lowercase hex>` form.
    pub fn expected_repository_fingerprint(&self) -> Result<RepositoryFingerprint, DaemonError> {
        RepositoryFingerprint::try_from_canonical(&self.expected_repository_fingerprint)
            .map_err(|err| DaemonError::Bootstrap(format!("repository fingerprint: {err}")))
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
    if !is_canonical_lowercase_hex_pin(&fields.certificate_sha256_pin) {
        return Err(DaemonError::Bootstrap(
            "certificate_sha256_pin must be 64 lowercase hex bytes".to_string(),
        ));
    }
    // Reject any non-empty but malformed or wrong-length base64
    // value at the storage boundary. The schema promises that
    // `session_secret_base64` decodes to exactly 32 bytes; a value
    // that fails that contract must never reach the daemon because
    // the HMAC verification would reject it after a wasted round
    // trip, and a malformed value silently accepted here would let
    // a hostile launcher supply a secret of an unexpected shape.
    //
    // The diagnostic message intentionally omits the supplied secret
    // so the error string is safe to log or surface through a
    // `ProtocolError`.
    SessionSecret::from_base64(&fields.session_secret_base64)
        .map_err(|err| DaemonError::Bootstrap(format!("session_secret_base64: {err}")))?;
    // Re-parse the fingerprint through the canonical type so any
    // uppercase, malformed, or missing-prefix value is refused at
    // the storage boundary.
    RepositoryFingerprint::try_from_canonical(&fields.expected_repository_fingerprint)
        .map_err(|err| DaemonError::Bootstrap(format!("expected_repository_fingerprint: {err}")))?;
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

fn is_canonical_lowercase_hex_pin(value: &str) -> bool {
    if value.len() != 64 {
        return false;
    }
    value.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

use ring::rand::{SecureRandom, SystemRandom};

fn admit_bootstrap_path(
    path: &Path,
) -> Result<(AdmittedPrivateRoot, std::ffi::OsString), DaemonError> {
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty()).ok_or_else(|| {
        DaemonError::Bootstrap("bootstrap path has no parent directory".to_string())
    })?;
    let basename = path
        .file_name()
        .ok_or_else(|| DaemonError::Bootstrap("bootstrap target name is invalid".to_string()))?
        .to_os_string();
    let root = AdmittedPrivateRoot::open(parent)
        .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
    Ok((root, basename))
}

fn write_atomic_admitted(
    root: &AdmittedPrivateRoot,
    target: &str,
    body: &[u8],
) -> Result<(), DaemonError> {
    let rng = SystemRandom::new();
    write_atomic_admitted_with_hooks(
        root,
        target,
        body,
        |destination| rng.fill(destination),
        |_, _, _| Ok(()),
        |root| root.sync(),
    )
}

#[cfg(test)]
fn write_atomic_admitted_with_suffix<F>(
    root: &AdmittedPrivateRoot,
    target: &str,
    body: &[u8],
    fill_suffix: F,
) -> Result<(), DaemonError>
where
    F: FnMut(&mut [u8]) -> Result<(), ring::error::Unspecified>,
{
    write_atomic_admitted_with_hooks(
        root,
        target,
        body,
        fill_suffix,
        |_, _, _| Ok(()),
        |root| root.sync(),
    )
}

fn write_atomic_admitted_with_hooks<F, H, S>(
    root: &AdmittedPrivateRoot,
    target: &str,
    body: &[u8],
    mut fill_suffix: F,
    mut after_publish: H,
    mut sync_directory: S,
) -> Result<(), DaemonError>
where
    F: FnMut(&mut [u8]) -> Result<(), ring::error::Unspecified>,
    H: FnMut(&AdmittedPrivateRoot, &str, &std::fs::File) -> Result<(), PrivateStorageError>,
    S: FnMut(&AdmittedPrivateRoot) -> Result<(), PrivateStorageError>,
{
    const ATTEMPTS: usize = 8;
    root.revalidate()
        .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
    let mut selected: Option<(String, std::fs::File)> = None;
    for _ in 0..ATTEMPTS {
        let mut suffix = [0_u8; 16];
        fill_suffix(&mut suffix).map_err(|_| {
            DaemonError::Bootstrap("bootstrap randomness is unavailable".to_string())
        })?;
        let name = format!("{TEMP_BOOTSTRAP_PREFIX}{}", hex::encode(suffix));
        match root.create_private_file(&name) {
            Ok(file) => {
                selected = Some((name, file));
                break;
            }
            Err(PrivateStorageError::AlreadyExists) => continue,
            Err(_) => {
                return Err(DaemonError::Bootstrap(
                    "bootstrap temporary file is unavailable".to_string(),
                ));
            }
        }
    }
    let (temporary, mut file) = selected.ok_or_else(|| {
        DaemonError::Bootstrap("bootstrap temporary-file collision budget exhausted".to_string())
    })?;
    let write_result = (|| {
        file.write_all(body)
            .map_err(|_| DaemonError::Bootstrap("bootstrap write failed".to_string()))?;
        file.flush().map_err(|_| DaemonError::Bootstrap("bootstrap flush failed".to_string()))?;
        file.sync_all().map_err(|_| DaemonError::Bootstrap("bootstrap sync failed".to_string()))?;
        root.validate_file_binding(&temporary, &file, true)
            .map_err(|_| DaemonError::Bootstrap("private storage is unavailable".to_string()))?;
        root.rename_replace(&temporary, target)
            .map_err(|_| DaemonError::Bootstrap("bootstrap publish failed".to_string()))?;
        after_publish(root, target, &file)
            .map_err(|_| DaemonError::Bootstrap("bootstrap publish failed".to_string()))?;
        root.validate_file_binding(target, &file, true)
            .map_err(|_| DaemonError::Bootstrap("bootstrap publish failed".to_string()))?;
        sync_directory(root)
            .map_err(|_| DaemonError::Bootstrap("private storage sync failed".to_string()))
    })();
    if write_result.is_err() {
        let temporary_cleanup = root.remove_private_file_if_matches(&temporary, &file);
        let cleanup = match temporary_cleanup {
            Ok(()) => Ok(()),
            Err(PrivateStorageError::Operation) => {
                root.remove_private_file_if_matches(target, &file)
            }
            Err(error) => Err(error),
        };
        if cleanup.is_err() {
            tracing::warn!(
                "bootstrap cleanup could not prove temporary or published file ownership"
            );
        }
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use xtrace_domain::ContentHash;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(label: &str) -> PathBuf {
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required");
        AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        let name =
            format!("xtrace-daemon-bootstrap-{label}-{}-{counter}-{nanos}", std::process::id(),);
        let root = AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        root.create_private_child(&name)
            .expect("private bootstrap test directory")
            .path()
            .to_path_buf()
    }

    fn sample_fingerprint() -> RepositoryFingerprint {
        RepositoryFingerprint::from_canonical_path("/tmp/repo")
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
            sample_fingerprint(),
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
    fn write_rejects_uppercase_pin() {
        let dir = unique_dir("upper-pin");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.certificate_sha256_pin = "A".repeat(64);
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_rejects_non_canonical_fingerprint() {
        let dir = unique_dir("fp");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.expected_repository_fingerprint = "expected-repo".to_string();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_rejects_uppercase_fingerprint() {
        let dir = unique_dir("upper-fp");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.expected_repository_fingerprint = sample_fingerprint().as_str().replace('1', "I");
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
    fn read_rejects_target_symlink() {
        use std::os::unix::fs::symlink;
        let dir = unique_dir("read-symlink");
        let real = dir.join("real.json");
        BootstrapArtifact::write(&real, sample_fields(), BootstrapOwner::Persistent).unwrap();
        let link = dir.join("link.json");
        symlink(&real, &link).unwrap();
        let err = BootstrapArtifact::read(&link).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_group_or_other_permission_bits() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = unique_dir("read-perms");
        let path = dir.join("bootstrap.json");
        BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).unwrap();
        let err = BootstrapArtifact::read(&path).unwrap_err();
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
    fn write_retries_after_forced_temp_collision() {
        let dir = unique_dir("retry-collision");
        let root = AdmittedPrivateRoot::open(&dir).expect("admitted parent");
        let path = dir.join("bootstrap.json");
        let first = [0x21; 16];
        let second = [0x22; 16];
        let blocked = format!("{TEMP_BOOTSTRAP_PREFIX}{}", hex::encode(first));
        let mut stale = root.create_private_file(&blocked).expect("blocked candidate");
        stale.write_all(b"stale").expect("write blocker");
        stale.sync_all().expect("sync blocker");
        write_atomic_admitted_with_suffix(
            &root,
            "bootstrap.json",
            b"body",
            two_step_suffix(&first, &second),
        )
        .expect("production admitted writer retries collision");
        assert_eq!(fs::read(&path).expect("published bytes"), b"body");
        assert_eq!(root.read_bounded_file(&blocked, 16).expect("stale bytes"), b"stale");
        root.remove_private_file(&blocked).expect("remove blocker");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Deterministic suffix source that returns a fixed byte sequence
    /// on every call. Used to force a specific candidate path on the
    /// first `write_atomic_with_suffixed_rng` attempt so the retry
    /// path is exercised deterministically. The CSPRNG trait is
    /// sealed, so the test passes the deterministic source through
    /// the suffix-fill closure that the production path also uses.
    fn deterministic_suffix<'a>(
        pinned: &'a [u8; 16],
    ) -> impl FnMut(&mut [u8]) -> Result<(), ring::error::Unspecified> + 'a {
        move |dest: &mut [u8]| {
            if dest.len() != pinned.len() {
                return Err(ring::error::Unspecified);
            }
            dest.copy_from_slice(pinned);
            Ok(())
        }
    }

    /// Two-element deterministic suffix source. The first call
    /// returns `first`, the second returns `second`. Used to
    /// exercise the retry path: the writer collides on the first
    /// pinned suffix and succeeds on the second.
    fn two_step_suffix<'a>(
        first: &'a [u8; 16],
        second: &'a [u8; 16],
    ) -> impl FnMut(&mut [u8]) -> Result<(), ring::error::Unspecified> + 'a {
        let mut step: u8 = 0;
        move |dest: &mut [u8]| {
            if dest.len() != first.len() {
                return Err(ring::error::Unspecified);
            }
            let chosen = if step == 0 { first } else { second };
            dest.copy_from_slice(chosen);
            step += 1;
            Ok(())
        }
    }

    #[test]
    fn write_atomic_retry_path_succeeds_when_first_suffix_is_blocked() {
        // Force the writer to collide on its very first attempt by
        // pinning the first RNG suffix and pre-creating that
        // candidate; the second attempt uses a different pinned
        // suffix so `create_new` succeeds and the rename publishes
        // the bootstrap body rather than the stale candidate.
        let dir = unique_dir("retry-deterministic");
        let path = dir.join("bootstrap.json");
        let first: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let second: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let root = AdmittedPrivateRoot::open(&dir).expect("admitted parent");
        let first_name = format!("{TEMP_BOOTSTRAP_PREFIX}{}", hex::encode(first));
        let mut stale_file = root.create_private_file(&first_name).expect("block first candidate");
        stale_file.write_all(b"stale-attacker").expect("write blocker");
        stale_file.sync_all().expect("sync blocker");
        let first_candidate = dir.join(&first_name);
        write_atomic_admitted_with_suffix(
            &root,
            "bootstrap.json",
            b"body",
            two_step_suffix(&first, &second),
        )
        .expect("write via production admitted path");
        let published = fs::read(&path).expect("read published");
        assert_eq!(published, b"body", "published target must carry the bootstrap body");
        // The writer never touches the attacker-preplaced file; the
        // rename only moves the writer's own candidate to the
        // published path. The stale file therefore stays put, but
        // the daemon has not been tricked into publishing it as the
        // authoritative bootstrap artifact.
        assert!(first_candidate.exists(), "attacker-preplaced candidate must remain untouched");
        let stale_contents = root.read_bounded_file(&first_name, 64).expect("read stale");
        assert_eq!(stale_contents, b"stale-attacker");
        assert_ne!(first_candidate, path, "published path must differ from the stale candidate");
        root.remove_private_file(&first_name).expect("remove blocker");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_retry_budget_exhausted_returns_error() {
        // Pin the suffix so every retry draws the same candidate
        // path; the bounded retry budget must surface as a typed
        // error rather than an infinite loop.
        let dir = unique_dir("retry-budget");
        let pinned: [u8; 16] = [0xff; 16];
        let root = AdmittedPrivateRoot::open(&dir).expect("admitted parent");
        let candidate_name = format!("{TEMP_BOOTSTRAP_PREFIX}{}", hex::encode(pinned));
        let mut blocker = root.create_private_file(&candidate_name).expect("block candidate");
        blocker.write_all(b"blocker").expect("write blocker");
        blocker.sync_all().expect("sync blocker");
        let err = write_atomic_admitted_with_suffix(
            &root,
            "bootstrap.json",
            b"body",
            deterministic_suffix(&pinned),
        )
        .unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("collision budget exhausted"), "got {rendered}");
        assert_eq!(
            root.read_bounded_file(&candidate_name, 16).expect("blocker remains"),
            b"blocker"
        );
        root.remove_private_file(&candidate_name).expect("remove blocker");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn failed_publish_cleans_only_the_writer_owned_temporary_file() {
        use std::os::unix::fs::symlink;

        let dir = unique_dir("publish-failure");
        let root = AdmittedPrivateRoot::open(&dir).expect("admitted parent");
        let mut canary = root.create_private_file("canary").expect("private canary");
        canary.write_all(b"unchanged").expect("write canary");
        canary.sync_all().expect("sync canary");
        let target = dir.join("bootstrap.json");
        symlink("canary", &target).expect("preplace unsafe target symlink");
        let suffix = [0x44; 16];

        let result = write_atomic_admitted_with_suffix(
            &root,
            "bootstrap.json",
            b"secret",
            deterministic_suffix(&suffix),
        );
        assert!(result.is_err(), "writer must reject a symlink target");
        assert!(
            std::fs::symlink_metadata(&target)
                .expect("target symlink remains")
                .file_type()
                .is_symlink()
        );
        assert_eq!(root.read_bounded_file("canary", 32).expect("canary remains"), b"unchanged");
        assert!(
            root.bounded_child_names(64)
                .expect("bounded directory listing")
                .iter()
                .all(|name| !name.starts_with(TEMP_BOOTSTRAP_PREFIX))
        );
        fs::remove_file(target).expect("remove test symlink");
        root.remove_private_file("canary").expect("remove canary");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_publish_sync_failure_removes_only_the_writer_owned_target() {
        let dir = unique_dir("sync-failure");
        let root = AdmittedPrivateRoot::open(&dir).expect("admitted parent");
        let suffix = [0x55; 16];

        let result = write_atomic_admitted_with_hooks(
            &root,
            "bootstrap.json",
            b"candidate-secret",
            deterministic_suffix(&suffix),
            |_, _, _| Ok(()),
            |_| Err(PrivateStorageError::Operation),
        );
        assert!(result.is_err(), "injected directory sync failure must be surfaced");
        assert!(
            !dir.join("bootstrap.json").exists(),
            "failed publication is removed only while its original descriptor still owns it"
        );
        assert!(
            root.bounded_child_names(64)
                .expect("bounded fixture listing")
                .iter()
                .all(|name| !name.starts_with(TEMP_BOOTSTRAP_PREFIX))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_publish_replacement_is_preserved_during_failure_cleanup() {
        let dir = unique_dir("publish-replacement");
        let root = AdmittedPrivateRoot::open(&dir).expect("admitted parent");
        let suffix = [0x56; 16];
        let sync_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sync_observation = Arc::clone(&sync_called);

        let result = write_atomic_admitted_with_hooks(
            &root,
            "bootstrap.json",
            b"candidate-secret",
            deterministic_suffix(&suffix),
            |root, target, _| {
                root.remove_private_file(target)?;
                let mut replacement = root.create_private_file(target)?;
                replacement
                    .write_all(b"replacement-canary")
                    .map_err(|_| PrivateStorageError::Operation)?;
                replacement.sync_all().map_err(|_| PrivateStorageError::Operation)?;
                Ok(())
            },
            |_| {
                sync_observation.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(result.is_err(), "post-publish replacement fault must be surfaced");
        assert!(
            !sync_called.load(Ordering::SeqCst),
            "replaced target must fail identity check first"
        );
        assert_eq!(
            root.read_bounded_file("bootstrap.json", 64).expect("replacement remains"),
            b"replacement-canary",
        );
        assert!(
            root.bounded_child_names(64)
                .expect("bounded fixture listing")
                .iter()
                .all(|name| !name.starts_with(TEMP_BOOTSTRAP_PREFIX))
        );
        root.remove_private_file("bootstrap.json").expect("remove replacement fixture");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_succeeds_when_already_exists_target_is_preplaced() {
        // Re-running the writer on a path that already holds a valid
        // bootstrap artifact must overwrite it; the published file
        // carries the new secret, not the old one.
        let dir = unique_dir("overwrite");
        let path = dir.join("bootstrap.json");
        BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent).unwrap();
        let first_secret = fs::read_to_string(&path).unwrap();
        BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent).unwrap();
        let second_secret = fs::read_to_string(&path).unwrap();
        assert_ne!(first_secret, second_secret);
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
    fn read_rejects_unparseable_payload() {
        let dir = unique_dir("bad-json");
        let path = dir.join("bootstrap.json");
        fs::write(&path, b"{ not-json").unwrap();
        let err = BootstrapArtifact::read(&path).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn canonical_pin_helper_rejects_uppercase_and_short_inputs() {
        assert!(!is_canonical_lowercase_hex_pin(""));
        assert!(!is_canonical_lowercase_hex_pin("abc"));
        assert!(!is_canonical_lowercase_hex_pin(&"Z".repeat(64)));
        assert!(!is_canonical_lowercase_hex_pin(&"a".repeat(63)));
        assert!(is_canonical_lowercase_hex_pin(&"a".repeat(64)));
        assert!(is_canonical_lowercase_hex_pin(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn fields_round_trip_through_canonical_fingerprint_helper() {
        // The fields helper exposes the stored fingerprint as a
        // domain value; downstream code uses this to verify the
        // artifact without duplicating the parse path.
        let fields = sample_fields();
        let parsed = fields.expected_repository_fingerprint().expect("fp");
        assert_eq!(parsed, sample_fingerprint());
    }

    #[test]
    fn content_hash_round_trips_through_canonical_form() {
        let hash = ContentHash::of_bytes(b"hello world");
        let canonical = hash.to_canonical();
        assert_eq!(canonical.len(), 67);
        let parsed = ContentHash::from_str(&canonical).expect("parse");
        assert_eq!(parsed, hash);
    }

    /// Seeded canary: the session secret is the only field that must
    /// never appear under `Debug`. The test plants a recognisable
    /// base64-shaped string into `session_secret_base64` and asserts
    /// that `{:?}` does not contain the canary while it does contain
    /// the redacted marker. The field name itself is allowed to
    /// appear in the rendered struct so an operator can still tell
    /// which field was redacted.
    #[test]
    fn debug_redacts_session_secret_in_bootstrap_artifact_fields() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        // A 32-byte recognisable pattern that encodes to a base64
        // string the validation accepts; the test plants the
        // encoded form into `session_secret_base64` so the value
        // would appear under `{:?}` if the manual `Debug` impl
        // forgot to redact.
        let canary_bytes: [u8; 32] = std::array::from_fn(|i| {
            // 0xCA / 0xFE / 0xBA / 0xBE repeating produces a
            // base64 string with distinct characters per position
            // and a recognisable substring when not redacted.
            [0xCA, 0xFE, 0xBA, 0xBE][i % 4]
        });
        let canary_secret = STANDARD.encode(canary_bytes);
        let mut fields = sample_fields();
        fields.session_secret_base64 = canary_secret.clone();
        let rendered = format!("{fields:?}");
        assert!(
            !rendered.contains(&canary_secret),
            "Debug output must not contain the canary secret, got: {rendered}",
        );
        assert!(
            rendered.contains(SESSION_SECRET_REDACTED),
            "Debug output must surface a redacted marker, got: {rendered}",
        );
    }

    /// Seeded canary: the wrapping `BootstrapArtifact` Debug output
    /// must inherit the same redaction because the manual impl calls
    /// through to the redacted field Debug.
    #[test]
    fn debug_redacts_session_secret_in_bootstrap_artifact() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let canary_bytes: [u8; 32] = std::array::from_fn(|i| {
            // Different pattern from the field-level canary so a
            // regression in the wrapping struct cannot accidentally
            // satisfy both tests.
            [0xDE, 0xAD, 0xBE, 0xEF][i % 4]
        });
        let canary_secret = STANDARD.encode(canary_bytes);
        let dir = unique_dir("debug-redact");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.session_secret_base64 = canary_secret.clone();
        let artifact =
            BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).expect("write");
        let rendered = format!("{artifact:?}");
        assert!(
            !rendered.contains(&canary_secret),
            "Debug output must not contain the canary secret, got: {rendered}",
        );
        assert!(
            rendered.contains(SESSION_SECRET_REDACTED),
            "Debug output must surface a redacted marker, got: {rendered}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `try_release` returns [`ReleaseOutcome::Released`] exactly
    /// once on a `Daemon`-owned artifact even when called from
    /// concurrent callers on the same handle. Every other caller
    /// sees [`ReleaseOutcome::AlreadyReleased`] without touching
    /// the filesystem.
    #[test]
    fn try_release_is_idempotent_under_concurrent_calls() {
        let dir = unique_dir("release-race");
        let path = dir.join("bootstrap.json");
        let artifact = Arc::new(
            BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Daemon)
                .expect("write"),
        );
        let mut handles = Vec::new();
        for _ in 0..16 {
            let artifact = Arc::clone(&artifact);
            handles.push(std::thread::spawn(move || artifact.try_release()));
        }
        let outcomes: Vec<ReleaseOutcome> = handles
            .into_iter()
            .map(|handle| handle.join().expect("join").expect("release ok"))
            .collect();
        let released_count = outcomes.iter().filter(|&&o| o == ReleaseOutcome::Released).count();
        let already_count =
            outcomes.iter().filter(|&&o| o == ReleaseOutcome::AlreadyReleased).count();
        assert_eq!(
            released_count, 1,
            "exactly one caller must perform the deletion; got {released_count} winners"
        );
        assert_eq!(
            already_count,
            outcomes.len() - 1,
            "every other caller must observe AlreadyReleased"
        );
        assert!(!path.exists(), "bootstrap file must be gone after release");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `try_release` is a no-op on a `Persistent` artifact so
    /// integration tests can keep the file around for inspection.
    /// The helper reports [`ReleaseOutcome::AlreadyReleased`]
    /// without touching the filesystem.
    #[test]
    fn try_release_is_a_noop_on_persistent_artifact() {
        let dir = unique_dir("release-persistent");
        let path = dir.join("bootstrap.json");
        let artifact = BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Persistent)
            .expect("write");
        assert_eq!(
            artifact.try_release().expect("persistent release"),
            ReleaseOutcome::AlreadyReleased,
            "persistent artifact must report AlreadyReleased",
        );
        assert!(path.exists(), "persistent artifact must remain on disk");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `Drop` on a `Daemon`-owned artifact that was never released
    /// still removes the file; this is the fallback cleanup path the
    /// §2.1 deletion contract depends on.
    #[test]
    fn drop_removes_unreleased_daemon_artifact_as_fallback() {
        let dir = unique_dir("drop-fallback");
        let path = dir.join("bootstrap.json");
        {
            let _artifact =
                BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Daemon)
                    .expect("write");
            assert!(path.exists());
        }
        assert!(!path.exists(), "Drop must remove the artifact when no caller released it");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `Drop` after `try_release` is a no-op: the mutex-guarded flag
    /// stops the fallback cleanup from racing the explicit release.
    #[test]
    fn drop_after_try_release_is_a_noop() {
        let dir = unique_dir("drop-after-release");
        let path = dir.join("bootstrap.json");
        let artifact = BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Daemon)
            .expect("write");
        assert_eq!(
            artifact.try_release().expect("release"),
            ReleaseOutcome::Released,
            "explicit release wins",
        );
        assert!(!path.exists());
        // Re-create a sentinel file under the same path; if Drop
        // accidentally deletes it the assertion fails. The check
        // pins the release-state contract: once released, Drop is a
        // no-op regardless of what is on disk afterwards.
        fs::write(&path, b"sentinel").expect("sentinel");
        drop(artifact);
        assert!(
            path.exists(),
            "Drop must not delete a file released earlier; the sentinel must remain"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// RAII guard that restores the directory mode to `0o700` on
    /// drop so an assertion failure inside a permission-twiddling
    /// test cannot strand a read-only directory that the next
    /// `remove_dir_all` would refuse to clean up.
    #[cfg(unix)]
    struct ReadOnlyDirGuard {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl ReadOnlyDirGuard {
        fn new(path: PathBuf) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = fs::metadata(&path).expect("dir meta").permissions();
            perms.set_mode(0o500);
            fs::set_permissions(&path, perms).expect("chmod ro dir");
            Self { path }
        }
    }

    #[cfg(unix)]
    impl Drop for ReadOnlyDirGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(meta) = fs::metadata(&self.path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                let _ = fs::set_permissions(&self.path, perms);
            }
        }
    }

    /// Probe whether directory write bits gate `unlink` for the
    /// current uid. Returns `true` when the kernel bypasses DAC for
    /// the running process (typically root), which means the
    /// permission-twiddling retry tests cannot exercise the path
    /// they are designed to cover.
    #[cfg(unix)]
    fn directory_permissions_gate_unlink() -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        let probe_dir = unique_dir("release-retry-probe");
        let probe_path = probe_dir.join("probe.json");
        fs::write(&probe_path, b"probe").expect("probe file");
        let mut perms = fs::metadata(&probe_dir).expect("probe meta").permissions();
        perms.set_mode(0o500);
        fs::set_permissions(&probe_dir, perms).expect("probe chmod");
        let gated = fs::remove_file(&probe_path).is_err();
        let mut perms = fs::metadata(&probe_dir).expect("probe meta").permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&probe_dir, perms).expect("probe chmod restore");
        let _ = fs::remove_dir_all(&probe_dir);
        gated
    }

    /// A non-`NotFound` `unlink` failure leaves the released flag
    /// unset so a subsequent explicit `try_release` call retries
    /// the removal. The test removes the directory write bit to
    /// force `EACCES`, asserts the helper reports the typed error
    /// without logging, restores the permission through a guard so
    /// assertion failures cannot strand a read-only directory, and
    /// asserts the second attempt succeeds and removes the file.
    /// The test runs on Unix only because the retry mechanism
    /// relies on POSIX permission semantics.
    #[cfg(unix)]
    #[test]
    fn try_release_succeeds_on_retry_after_forced_unlink_failure() {
        if !directory_permissions_gate_unlink() {
            eprintln!(
                "skipping try_release retry test: directory write bits do not gate unlink for this uid",
            );
            return;
        }
        let dir = unique_dir("release-retry-explicit");
        let path = dir.join("bootstrap.json");
        let artifact = Arc::new(
            BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Daemon)
                .expect("write"),
        );
        let _ro = ReadOnlyDirGuard::new(dir.clone());

        let first = artifact.try_release().expect_err("unlink must fail under read-only parent");
        let rendered = format!("{first}");
        assert!(
            rendered.contains("private bootstrap cleanup is unavailable"),
            "error must report the sanitized cleanup failure, got: {rendered}",
        );
        assert!(path.exists(), "file must still exist after a failed release");
        let debug = format!("{artifact:?}");
        assert!(
            debug.contains("released: false"),
            "released flag must remain unset after a failed release; got: {debug}",
        );

        // Restore permissions through the guard's drop below; the
        // explicit second attempt asserts the retry succeeds.
        drop(_ro);
        let second = artifact.try_release().expect("retry must succeed");
        assert_eq!(second, ReleaseOutcome::Released, "retry must report Released");
        assert!(!path.exists(), "file must be removed after a successful retry");
        let debug = format!("{artifact:?}");
        assert!(
            debug.contains("released: true"),
            "released flag must be set after a successful release; got: {debug}",
        );

        drop(artifact);
        let _ = fs::remove_dir_all(&dir);
    }

    /// When `try_release` fails non-`NotFound` and the supervisor
    /// hands the artifact to `Drop` without a follow-up retry, the
    /// fallback path inside `Drop` performs a final attempt. The
    /// test forces the explicit attempt to fail by installing a
    /// read-only parent directory, then restores the directory
    /// permissions before dropping the artifact so the `Drop`
    /// fallback succeeds and removes the file. The unrelated happy
    /// path is covered by
    /// [`Self::drop_removes_unreleased_daemon_artifact_as_fallback`].
    #[cfg(unix)]
    #[test]
    fn drop_fallback_releases_when_try_release_already_failed() {
        if !directory_permissions_gate_unlink() {
            eprintln!(
                "skipping drop_fallback release test: directory write bits do not gate unlink for this uid",
            );
            return;
        }
        let dir = unique_dir("release-retry-drop");
        let path = dir.join("bootstrap.json");
        let artifact = Arc::new(
            BootstrapArtifact::write(&path, sample_fields(), BootstrapOwner::Daemon)
                .expect("write"),
        );

        // Force the explicit attempt to fail under a read-only
        // parent so the `Drop` fallback is the only path that
        // can recover the cleanup.
        let _ro = ReadOnlyDirGuard::new(dir.clone());
        let first_err =
            artifact.try_release().expect_err("unlink must fail under read-only parent");
        let rendered = format!("{first_err}");
        assert!(
            matches!(first_err, DaemonError::Bootstrap(_)),
            "explicit attempt must surface a Bootstrap error so the Drop fallback is reached, got {first_err:?}",
        );
        assert!(
            rendered.contains("private bootstrap cleanup is unavailable"),
            "error must report the sanitized cleanup failure, got: {rendered}",
        );
        assert!(path.exists(), "file must still exist after a failed explicit release");

        // Drop the read-only guard first so the directory is
        // writable when `Drop::drop` runs the fallback attempt.
        drop(_ro);
        // The explicit attempt already left the released flag
        // unset; the `Drop` fallback must perform the deletion.
        drop(artifact);
        assert!(
            !path.exists(),
            "Drop fallback must remove the file when the prior try_release left the state retryable",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `validate_fields` rejects a `session_secret_base64` value that
    /// is non-empty but not valid base64. The error message must not
    /// embed the offending input so the diagnostic is safe to log.
    #[test]
    fn validate_fields_rejects_malformed_session_secret_base64() {
        let dir = unique_dir("malformed-secret");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.session_secret_base64 = "@@@not-base64@@@".to_string();
        let err = BootstrapArtifact::write(&path, fields.clone(), BootstrapOwner::Persistent)
            .unwrap_err();
        let rendered = format!("{err}");
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        assert!(
            rendered.contains("session_secret_base64"),
            "error must name the field, got: {rendered}",
        );
        assert!(
            !rendered.contains(&fields.session_secret_base64),
            "error must not embed the supplied secret, got: {rendered}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `validate_fields` rejects a base64 value that decodes to a
    /// length other than 32 bytes. The schema promises exactly
    /// 32 bytes; a shorter or longer payload is refused at the
    /// storage boundary.
    #[test]
    fn validate_fields_rejects_wrong_length_session_secret_base64() {
        let dir = unique_dir("wrong-length-secret");
        let path = dir.join("bootstrap.json");
        // `AAAA` decodes to 3 bytes, well below the required 32.
        let mut fields = sample_fields();
        fields.session_secret_base64 = "AAAA".to_string();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        let rendered = format!("{err}");
        assert!(
            rendered.contains("session_secret_base64"),
            "error must name the field, got: {rendered}",
        );
        assert!(
            !rendered.contains("AAAA"),
            "error must not embed the supplied secret, got: {rendered}",
        );

        // A base64 value that decodes to more than 32 bytes is also
        // refused; construct one from 33 random bytes.
        let long = {
            use base64::Engine as _;
            use base64::engine::general_purpose::STANDARD;
            STANDARD.encode([0x33u8; 33])
        };
        let mut fields = sample_fields();
        fields.session_secret_base64 = long.clone();
        let err = BootstrapArtifact::write(&path, fields, BootstrapOwner::Persistent).unwrap_err();
        let rendered = format!("{err}");
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        assert!(
            !rendered.contains(&long),
            "error must not embed the supplied secret, got: {rendered}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `read` applies the same base64 contract on the load path so
    /// a tampered bootstrap file is rejected even when the writer
    /// was honest. The error must not embed the supplied secret.
    /// The test seeds the file with owner-only permissions so the
    /// owner-only check passes and the validation step is the one
    /// that fires.
    #[cfg(unix)]
    #[test]
    fn read_rejects_malformed_session_secret_base64() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = unique_dir("read-malformed-secret");
        let path = dir.join("bootstrap.json");
        let mut fields = sample_fields();
        fields.session_secret_base64 = "@@@not-base64@@@".to_string();
        let raw = serde_json::to_string(&fields).expect("serialise");
        fs::write(&path, raw).expect("write");
        // Restore owner-only permissions so the validation step is
        // reached rather than the owner-only check on the load
        // path.
        let mut perms = fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).expect("chmod");
        let err = BootstrapArtifact::read(&path).unwrap_err();
        let rendered = format!("{err}");
        assert!(matches!(err, DaemonError::Bootstrap(_)));
        assert!(
            rendered.contains("session_secret_base64"),
            "error must name the field, got: {rendered}",
        );
        assert!(
            !rendered.contains("@@@not-base64@@@"),
            "error must not embed the supplied secret, got: {rendered}",
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
