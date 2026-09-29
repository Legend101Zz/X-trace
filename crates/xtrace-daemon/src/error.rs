//! Typed errors raised by the daemon library.
//!
//! Every variant carries a stable [`ProtocolErrorCode`] that the
//! session/connection layer renders to the wire as a
//! `ProtocolError.code` value, plus an owner-only diagnostic
//! payload rendered into the operator's log via the variant's
//! `Display` implementation. Most variants carry a `String`; the
//! [`DaemonError::Io`] variant carries the underlying
//! [`std::io::Error`] instead. `DaemonError` payloads are intended
//! for the daemon operator's log and may include file paths,
//! loopback bind addresses, and OS error text so the operator can
//! correlate the failure with a system log entry. `DaemonError`
//! values are not automatically serialized as wire `ProtocolError`
//! envelopes: those are constructed separately by the session and
//! connection paths and may include bounded validation or framing
//! detail. Code that builds the wire envelope must never insert
//! session secret or private-key material.
//!
//! Every code lives in the `XTR-DAEMON-*` namespace except
//! [`ProtocolErrorCode::CaptureIngest`], which is the one
//! capture-ingress exception that lives in the `XTR-CAPTURE-INGEST`
//! family. The session renders every [`xtrace_ingest::IngestError`]
//! produced by the session-bound validator as that single safe
//! variant label; the full typed error and every payload-bearing
//! field remain local to the daemon, and the wire `ProtocolError`
//! envelope contains only the stable safe variant label.

use std::io;

use thiserror::Error;

/// Stable error code families used in `ProtocolError` messages.
///
/// Codes follow the `XTR-DAEMON-*` namespace; new codes require an
/// ADR and must be added to this enum so a downstream adapter sees
/// the exact set the daemon can emit.
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
    /// Repository fingerprint in `AdapterHello` does not match the
    /// value the daemon expected from the bootstrap artifact. The
    /// enforcement uses the bootstrap-anchored repository
    /// fingerprint rather than the wire `project_id`; the
    /// `AgentEnvelope` schema has no `project_id` field and the
    /// identifier is used only to bind the bootstrap context.
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
    /// Wire code `XTR-CAPTURE-INGEST`: the single capture-ingress code
    /// emitted for every rejection returned by the session-bound
    /// [`xtrace_ingest::IngestValidator`]. It keeps the protocol
    /// surface narrow even though the underlying [`xtrace_ingest::IngestError`]
    /// carries many variants; the full typed error and every
    /// payload-bearing field remain local to the daemon, and the
    /// wire `ProtocolError` envelope contains only the stable safe
    /// variant label. The typed reason is exposed through
    /// [`crate::session::SessionError::ingest_error`] together with
    /// [`xtrace_ingest::IngestError::is_session_fatal`] so the
    /// supervisor can distinguish recoverable from session-fatal
    /// ingest rejections without ever round-tripping a payload
    /// across the wire.
    CaptureIngest,
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
            Self::CaptureIngest => "XTR-CAPTURE-INGEST",
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
/// `DaemonError` payloads are owner-only diagnostics: they are not
/// automatically serialized as wire `ProtocolError` envelopes. The
/// wire envelope is constructed separately by the session and
/// connection paths and may include bounded validation or framing
/// detail. The code that builds those envelopes must never insert
/// session secret or private-key material.
///
/// Callers that build a `DaemonError` from a context carrying the
/// certificate pin, the session secret, or peer-supplied data must
/// avoid embedding that material in the payload: each variant's
/// diagnostic text — the `String` for most variants and the
/// underlying `io::Error` for [`DaemonError::Io`] — is rendered as
/// part of the operator-visible diagnostic log via the variant's
/// `Display` implementation, and [`DaemonError::TlsConfig`] in
/// particular is reachable from paths that already hold the
/// bootstrap pin.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Configuration refused by validation. The daemon never reaches
    /// the bind step when this variant is raised.
    #[error("invalid daemon configuration: {0}")]
    InvalidConfig(String),
    /// The OS refused the loopback bind. The diagnostic string is an
    /// owner-only entry: it preserves the resolved loopback socket
    /// address (which carries the OS-assigned port) and the
    /// underlying OS error text so the operator can correlate the
    /// failure with a system log entry. The string is not part of
    /// the wire `ProtocolError` envelope sent to the adapter.
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
    fn protocol_error_codes_have_xtr_daemon_prefix() {
        // Every legacy variant must keep the `XTR-DAEMON-*` family so
        // a downstream adapter's stable prefix filter still matches;
        // adding a new code requires an ADR and updating this list.
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
            assert!(
                code.as_str().starts_with("XTR-DAEMON-"),
                "legacy protocol error code must carry the XTR-DAEMON- prefix, got {}",
                code.as_str()
            );
        }
        // The capture-ingest code lives in its own family; the
        // session uses it for every `IngestError` so the wire surface
        // stays narrow even though the underlying typed error carries
        // many variants.
        assert_eq!(
            ProtocolErrorCode::CaptureIngest.as_str(),
            "XTR-CAPTURE-INGEST",
            "CaptureIngest must equal the capture-ingest wire code exactly",
        );
    }
}
