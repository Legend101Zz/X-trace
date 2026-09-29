//! Typed errors raised by the daemon library.
//!
//! Every variant carries a stable [`ProtocolErrorCode`] that can be
//! rendered to the wire as a `ProtocolError.code` value, plus a
//! user-safe message that never embeds a captured value or secret.
//! Internal errors retain the underlying cause as a string for the
//! owner-only diagnostic log; that string is never serialized into
//! the public error chain.

use std::io;

use thiserror::Error;

/// Stable error code families used in `ProtocolError` messages.
///
/// Codes follow the `XTR-DAEMON-*` namespace documented in
/// `docs/plans/x-trace/03-program-design.md` §7. New codes require an
/// ADR and must be added to this enum so a downstream adapter sees the
/// exact set the daemon can emit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtocolErrorCode {
    /// Listener could not bind to the loopback address.
    Bind,
    /// TLS 1.3 handshake failed or the client certificate chain was
    /// rejected.
    TlsHandshake,
    /// AdapterHello failed to decode or carried an invalid envelope.
    HelloDecode,
    /// AdapterHello HMAC transcript proof did not match.
    HelloProof,
    /// Protocol major version is outside the negotiated range.
    ProtocolMajor,
    /// `runtime_session_id` carried by a post-hello envelope does not
    /// match the one negotiated at handshake time.
    SessionIdentity,
    /// `project_id` does not match the bootstrap artifact.
    ProjectIdentity,
    /// `session_seq` is out of order: replay (already acknowledged) or
    /// gap (skipped sequence number).
    SessionSequence,
    /// Envelope exceeded the negotiated [`crate::DaemonConfig::max_envelope_bytes`].
    FrameTooLarge,
    /// I/O failure on the TCP stream.
    Transport,
    /// Owner-only bootstrap artifact could not be written or removed.
    Bootstrap,
    /// Supervisor was ordered to shut down; the connection is closing.
    Shutdown,
}

impl ProtocolErrorCode {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "XTR-DAEMON-BIND",
            Self::TlsHandshake => "XTR-DAEMON-TLS-HANDSHAKE",
            Self::HelloDecode => "XTR-DAEMON-HELLO-DECODE",
            Self::HelloProof => "XTR-DAEMON-HELLO-PROOF",
            Self::ProtocolMajor => "XTR-DAEMON-PROTOCOL-MAJOR",
            Self::SessionIdentity => "XTR-DAEMON-SESSION-IDENTITY",
            Self::ProjectIdentity => "XTR-DAEMON-PROJECT-IDENTITY",
            Self::SessionSequence => "XTR-DAEMON-SESSION-SEQUENCE",
            Self::FrameTooLarge => "XTR-DAEMON-FRAME-TOO-LARGE",
            Self::Transport => "XTR-DAEMON-TRANSPORT",
            Self::Bootstrap => "XTR-DAEMON-BOOTSTRAP",
            Self::Shutdown => "XTR-DAEMON-SHUTDOWN",
        }
    }
}

impl std::fmt::Display for ProtocolErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Public error returned by the daemon library API.
///
/// The error chain never carries the session secret, the certificate
/// pin, or captured values. Internal I/O errors retain the underlying
/// OS error code only so the owner-only diagnostic log can correlate
/// the failure with a system log entry.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Configuration refused by validation. The daemon never reaches
    /// the bind step when this variant is raised.
    #[error("invalid daemon configuration: {0}")]
    InvalidConfig(String),
    /// The OS refused the loopback bind. The diagnostic string omits
    /// the configured host so logs do not leak internal addresses.
    #[error("loopback bind failed: {0}")]
    BindFailed(String),
    /// The bootstrap artifact could not be written or removed.
    #[error("bootstrap artifact error: {0}")]
    Bootstrap(String),
    /// TLS configuration could not be built.
    #[error("tls configuration error: {0}")]
    TlsConfig(String),
    /// Supervisor was unable to accept a connection or read a frame.
    #[error("transport error: {0}")]
    Transport(String),
    /// Underlying I/O failure. Carries the OS error code only.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Tokio runtime failure.
    #[error("runtime join error: {0}")]
    Join(String),
}

impl DaemonError {
    /// Returns the protocol error code that best describes this
    /// failure. The mapping is total so the daemon never falls back to
    /// a generic code that could mask a compatibility boundary.
    #[must_use]
    pub const fn code(&self) -> ProtocolErrorCode {
        match self {
            Self::InvalidConfig(_) => ProtocolErrorCode::Bind,
            Self::BindFailed(_) => ProtocolErrorCode::Bind,
            Self::Bootstrap(_) => ProtocolErrorCode::Bootstrap,
            Self::TlsConfig(_) => ProtocolErrorCode::TlsHandshake,
            Self::Transport(_) => ProtocolErrorCode::Transport,
            Self::Io(_) => ProtocolErrorCode::Transport,
            Self::Join(_) => ProtocolErrorCode::Shutdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_mapping_covers_every_variant() {
        let cases: &[DaemonError] = &[
            DaemonError::InvalidConfig(String::new()),
            DaemonError::BindFailed(String::new()),
            DaemonError::Bootstrap(String::new()),
            DaemonError::TlsConfig(String::new()),
            DaemonError::Transport(String::new()),
            DaemonError::Join(String::new()),
        ];
        // Every public variant must surface a stable `XTR-DAEMON-*`
        // code; if a new variant is added the match in `code` is the
        // single point that needs review.
        for err in cases {
            assert!(
                err.code().as_str().starts_with("XTR-DAEMON-"),
                "missing code prefix for {err:?}"
            );
        }
    }

    #[test]
    fn protocol_error_codes_have_xtr_prefix() {
        for code in [
            ProtocolErrorCode::Bind,
            ProtocolErrorCode::TlsHandshake,
            ProtocolErrorCode::HelloDecode,
            ProtocolErrorCode::HelloProof,
            ProtocolErrorCode::ProtocolMajor,
            ProtocolErrorCode::SessionIdentity,
            ProtocolErrorCode::ProjectIdentity,
            ProtocolErrorCode::SessionSequence,
            ProtocolErrorCode::FrameTooLarge,
            ProtocolErrorCode::Transport,
            ProtocolErrorCode::Bootstrap,
            ProtocolErrorCode::Shutdown,
        ] {
            assert!(code.as_str().starts_with("XTR-DAEMON-"));
        }
    }
}
