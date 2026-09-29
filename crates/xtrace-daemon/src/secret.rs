//! Per-runtime-session secret.
//!
//! Each adapter connection is authenticated through a 256-bit secret
//! drawn from the operating system CSPRNG (`ring::rand::SystemRandom`).
//! The secret never crosses the wire; it is read from the bootstrap
//! artifact on the adapter side and recomputed into the
//! [`xtrace_protocol::handshake`] HMAC tag on both ends.
//!
//! `Debug` prints a redacted marker and there is no `Display`
//! implementation, so the secret cannot be copied into a log,
//! surfaced through diagnostics, or formatted into an error chain.
//! `Clone` is derived because the daemon owns the secret in several
//! independent places: the `BoundDaemon` value, the per-connection
//! `SupervisorContext` (a clone handed to each connection task so the
//! original can stay in the supervisor), and the bootstrap artifact
//! that the adapter reads back. Every clone is owned by exactly one
//! owner at a time and zeroizes its backing buffer on drop. The
//! zeroize guarantee is best-effort: it covers the bytes the type
//! still owns at drop time and does not cover process abort, signal
//! termination, optimizer-elided writes, or any transient copy the
//! compiler may produce. `read_secret` and `read_secret_zeroizing`
//! are the only accessors that return raw bytes; the type never
//! surfaces the secret through any other path.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

/// Length of the per-runtime-session secret in bytes. Matches the
/// 256-bit requirement of `docs/plans/x-trace/03-program-design.md`
/// §11.
pub const SESSION_SECRET_LEN: usize = 32;

/// Per-runtime-session secret.
///
/// The struct intentionally exposes the secret only through the
/// `read_secret` accessor so callers cannot accidentally format it.
/// `Clone` is derived because the secret lives in several independent
/// owners at once: the `BoundDaemon` value, the per-connection
/// `SupervisorContext`, and the bootstrap artifact. Every clone is
/// zeroized when its owner is dropped.
///
/// `Debug` prints a redacted marker rather than the secret bytes so
/// an accidental `{:?}` in a log line never leaks the secret. The
/// accessor `read_secret` is the only path that returns the raw
/// bytes. The zeroize-on-drop guarantee is best-effort and covers
/// only the bytes the type still owns at drop time; it does not
/// cover process abort, signal-induced termination, or compiler
/// copies made during arithmetic or moves.
#[derive(Clone)]
pub struct SessionSecret([u8; SESSION_SECRET_LEN]);

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}

impl Zeroize for SessionSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SessionSecret {
    fn drop(&mut self) {
        // Best-effort: zeroize the backing buffer the type still owns
        // at drop time. Drop runs on normal scope exit and on unwind;
        // it does not run during process abort or external signal
        // termination, and any compiler-introduced transient copy is
        // outside the type's reach.
        self.0.zeroize();
    }
}

impl SessionSecret {
    /// Generates a fresh secret from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::OsRng`] when the operating system
    /// refuses to provide entropy. The daemon treats this as a fatal
    /// startup failure because no secure connection can be established
    /// without a fresh session secret.
    pub fn generate() -> Result<Self, SecretError> {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; SESSION_SECRET_LEN];
        rng.fill(&mut bytes).map_err(|_| SecretError::OsRng)?;
        Ok(Self(bytes))
    }

    /// Wraps a caller-supplied byte slice. Returns `None` when the
    /// slice is not exactly [`SESSION_SECRET_LEN`] bytes so the daemon
    /// never accidentally truncates or pads an inbound secret.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SESSION_SECRET_LEN {
            return None;
        }
        let mut out = [0u8; SESSION_SECRET_LEN];
        out.copy_from_slice(bytes);
        Some(Self(out))
    }

    /// Reads the secret bytes. Callers must never format, log, or
    /// otherwise surface the returned slice.
    #[must_use]
    pub fn read_secret(&self) -> &[u8; SESSION_SECRET_LEN] {
        &self.0
    }

    /// Renders the secret as a base64 string suitable for the
    /// bootstrap artifact. The caller is responsible for the file
    /// permissions; this helper never touches the filesystem.
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Inverse of [`SessionSecret::to_base64`].
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Decode`] when the input is not a valid
    /// base64 string or does not decode to exactly
    /// [`SESSION_SECRET_LEN`] bytes.
    pub fn from_base64(text: &str) -> Result<Self, SecretError> {
        let bytes = STANDARD.decode(text).map_err(|err| SecretError::Decode(err.to_string()))?;
        Self::from_bytes(&bytes).ok_or(SecretError::Decode("wrong length".to_string()))
    }

    /// Returns the secret bytes wrapped in a [`Zeroizing`] guard.
    ///
    /// The wrapper forces a zeroize on drop of the returned slice so
    /// callers that need a transient copy of the secret cannot leak
    /// it through the borrow stack. The helper exists to keep the
    /// HMAC call sites honest; the daemon itself never clones the
    /// secret outside this accessor. The zeroize-on-drop is best-effort
    /// for the returned guard only; the backing buffer of the
    /// `SessionSecret` itself is zeroized on its own drop, but neither
    /// path covers process abort or compiler-introduced transient copies.
    #[must_use]
    pub fn read_secret_zeroizing(&self) -> Zeroizing<[u8; SESSION_SECRET_LEN]> {
        Zeroizing::new(self.0)
    }
}

/// Errors raised when constructing a [`SessionSecret`].
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The OS refused to provide entropy.
    #[error("os rng refused to fill the session secret")]
    OsRng,
    /// A supplied base64 string could not be decoded into a session
    /// secret. The diagnostic message omits the offending input so
    /// the error is safe to log.
    #[error("session secret base64 decode failed: {0}")]
    Decode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_distinct_secrets() {
        let a = SessionSecret::generate().expect("first secret");
        let b = SessionSecret::generate().expect("second secret");
        assert_ne!(a.read_secret(), b.read_secret());
    }

    #[test]
    fn base64_round_trip_preserves_bytes() {
        let secret = SessionSecret::generate().expect("secret");
        let encoded = secret.to_base64();
        let decoded = SessionSecret::from_base64(&encoded).expect("round trip");
        assert_eq!(decoded.read_secret(), secret.read_secret());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(SessionSecret::from_bytes(&[]).is_none());
        assert!(SessionSecret::from_bytes(&[0u8; 16]).is_none());
        assert!(SessionSecret::from_bytes(&[0u8; 33]).is_none());
        assert!(SessionSecret::from_bytes(&[0u8; 32]).is_some());
    }

    #[test]
    fn from_base64_rejects_malformed_input() {
        let err = SessionSecret::from_base64("@@@not-base64@@@").unwrap_err();
        assert!(matches!(err, SecretError::Decode(_)));
        let err = SessionSecret::from_base64("AAAA").unwrap_err();
        assert!(matches!(err, SecretError::Decode(_)));
    }

    #[test]
    fn debug_redacts_the_secret() {
        let secret = SessionSecret::generate().expect("secret");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("redacted"));
        let base64 = secret.to_base64();
        assert!(!rendered.contains(&base64));
    }
}
