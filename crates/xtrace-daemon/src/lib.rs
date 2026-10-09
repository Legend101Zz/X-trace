//! `xtrace-daemon`: loopback XTP-Agent ingress.
//!
//! This crate ships the smallest coherent slice of the X-trace daemon
//! that proves the architecture documented in
//! `docs/plans/x-trace/02-architecture.md` and
//! `docs/plans/x-trace/03b-protocol-and-api.md` for the adapter
//! transport:
//!
//! - one real OS-assigned loopback TCP listener;
//! - one ephemeral daemon certificate rotated per launch and pinned
//!   by its SHA-256 digest;
//! - one TLS 1.3 server configuration built from that certificate;
//! - one per-runtime-session 256-bit secret that authenticates the
//!   adapter through the [`xtrace_protocol::handshake`] transcript
//!   proof;
//! - one bootstrap artifact written atomically with `0600` permissions
//!   so the launcher / attach helper can hand the secret, pin,
//!   session, and project identifiers to the adapter without exposing
//!   them in process arguments;
//! - one bounded ingress channel per connection;
//! - one supervised per-connection task that performs the
//!   AdapterHello/DaemonHello exchange, validates session sequencing,
//!   emits ACK + Health, and shuts down on the cancellation token.
//!
//! Recording assembly and persistence are owned by an optional
//! [`xtrace_application::recording::RecordingCapture`] injected through
//! [`DaemonBuilder::with_recording_capture`]. The daemon translates admitted
//! wire events and runs that use case on a bounded blocking lane; it has no
//! production dependency on a concrete store. The crate still stops short of
//! the HTTP/WebSocket client API, Java/Node adapters, and TUI.
//!
//! ## Library API
//!
//! The crate exposes a foreground library API rather than a CLI
//! binary. The supported flow is:
//!
//! ```no_run
//! # async fn demo() -> Result<(), xtrace_daemon::DaemonError> {
//! use std::path::PathBuf;
//! use xtrace_daemon::{DaemonBuilder, DaemonConfig};
//! use xtrace_domain::{ProjectId, RepositoryFingerprint, RuntimeSessionId};
//!
//! let config = DaemonConfig::default();
//! let project_id = ProjectId::new();
//! let session_id = RuntimeSessionId::new();
//! let bootstrap_path = PathBuf::from("/tmp/xtrace-bootstrap.json");
//! let expected_repository_fingerprint =
//!     RepositoryFingerprint::from_canonical_path("/tmp/xtrace-demo-repo");
//!
//! let bound = DaemonBuilder::new(config)
//!     .with_project_id(project_id)
//!     .with_runtime_session_id(session_id)
//!     .with_expected_repository_fingerprint(expected_repository_fingerprint)
//!     .with_bootstrap_artifact(bootstrap_path)
//!     .bind()
//!     .await?;
//!
//! // `tokio::signal::ctrl_c()` requires the `signal` feature, which the
//! // daemon does not enable by default. The example below uses a
//! // one-shot future resolved after a short delay; production callers
//! // are expected to wire the shutdown future to their own signal
//! // source (for example `tokio::signal::ctrl_c()` from an enabled
//! // feature, or a `CancellationToken` from the application layer).
//! let shutdown = async {
//!     tokio::time::sleep(std::time::Duration::from_millis(50)).await;
//! };
//! bound.serve(shutdown).await?;
//! # Ok(()) }
//! ```
//!
//! [`DaemonBuilder::bind`] materializes a [`BoundDaemon`] that owns
//! the bound listener and the TLS configuration. Calling
//! [`BoundDaemon::serve`] runs the connection supervisor and blocks
//! until the supplied shutdown future resolves or every connection
//! closes.

#![allow(clippy::module_name_repetitions, reason = "daemon modules are named after their entities")]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data and exercise supervisor paths"
    )
)]

pub mod bootstrap;
pub mod capture_config;
pub mod config;
pub mod daemon;
pub mod error;
pub mod framing;
pub mod listener;
mod recording_pipeline;
pub mod runtime;
pub mod secret;
pub mod session;
pub mod tls;
pub mod viewer;

pub use bootstrap::{BootstrapArtifact, BootstrapArtifactFields, BootstrapOwner};
pub use config::{DaemonConfig, LOOPBACK_HOST, LoopbackPolicy, OutboundCapacity};
pub use daemon::{
    BoundDaemon, DaemonBuilder, MonotonicClock, ShutdownSignal, TLS_EXPORTER_LABEL,
    TLS_EXPORTER_LEN,
};
pub use error::{DaemonError, ProtocolErrorCode};
pub use framing::{EnvelopeAsyncDecoder, EnvelopeAsyncEncoder, EnvelopeDecoder, EnvelopeEncoder};
pub use listener::LoopbackListener;
pub use runtime::{AdapterHelloAck, IncomingEnvelope, OutgoingCommand, PostHelloAdmission};
pub use secret::SessionSecret;
pub use session::{HandshakeInputs, HandshakeRole, Session, StagedReleaseError};
pub use tls::{TlsServerMaterials, build_pinned_client_config};
pub use viewer::{BoundViewer, ViewerError, ViewerReadiness};

/// Re-export of the XTP-Agent protocol handshake helpers so callers
/// (the fake adapter in particular) can compute and verify the
/// transcript proof through the same reviewed module the daemon uses.
pub use xtrace_protocol::handshake::{
    TranscriptProofError, compute_transcript_proof, verify_transcript_proof,
};
