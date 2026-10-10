//! Per-connection runtime types.
//!
//! The runtime module owns the per-connection types that flow between
//! the [`crate::session::Session`] and the supervisor: incoming
//! envelopes that the supervisor decoded from the TLS stream,
//! outgoing commands the supervisor sends, and the adapter-side
//! [`AdapterHelloAck`] that the supervisor returns once the
//! adapter `AdapterHello` transcript proof has been verified.

use std::time::Duration;

use xtrace_ingest::Acceptance;
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    CapabilitySet, DaemonHello, EventBatch, Health, ProtocolError, RecordingFinished,
    RecordingStarted,
};
use xtrace_protocol::handshake::{ZERO_NONCE, verify_transcript_proof};

#[cfg(test)]
use prost::bytes::Bytes;

/// Default `Health` interval sent back to the adapter while idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthInterval(pub Duration);

impl Default for HealthInterval {
    fn default() -> Self {
        Self(Duration::from_secs(10))
    }
}

/// Result of a successful adapter `AdapterHello` exchange.
///
/// The supervisor forwards this receipt to the [`crate::session`]
/// layer so the adapter may immediately begin sending
/// [`CapabilitySet`] and [`Health`] traffic.
#[derive(Clone, Debug)]
pub struct AdapterHelloAck {
    /// Negotiated protocol major version.
    pub protocol_major: u32,
    /// Negotiated protocol minor version.
    pub protocol_minor: u32,
    /// Selected maximum envelope size in bytes.
    pub max_envelope_bytes: u32,
    /// Selected maximum batch size in events.
    pub max_batch_events: u32,
    /// Negotiated capabilities (initially empty; populated after the
    /// adapter sends its [`CapabilitySet`]).
    pub capabilities: Vec<String>,
}

/// Envelope received from the adapter after the handshake completes.
///
/// Recording wire payloads (`RecordingStarted`, `EventBatch`,
/// `RecordingFinished`) are validated through the session-bound
/// `xtrace-ingest` validator before staging and acknowledged with
/// `AckDurability::Staged`. When a capture use case is configured, the
/// supervisor dispatches each admitted message to it before releasing the
/// staged queue front and emitting that same `Staged` ACK. This type remains
/// independent of persistence, `Committed` durability, and terminal recording
/// lifecycle transitions.
#[derive(Clone, Debug)]
pub enum IncomingEnvelope {
    /// Adapter supplied its initial [`CapabilitySet`].
    CapabilitySet(CapabilitySet),
    /// Adapter sent a [`Health`] update.
    Health(Health),
    /// Adapter signalled the start of a recording session.
    RecordingStarted(RecordingStarted),
    /// Adapter forwarded a batch of recording events.
    EventBatch(EventBatch),
    /// Adapter signalled the end of a recording session.
    RecordingFinished(RecordingFinished),
}

/// Successful outcome of a single post-hello admission. `acceptance`
/// is `None` for `CapabilitySet` and `Health` because the validator
/// does not examine those variants.
#[derive(Clone, Debug)]
pub struct PostHelloAdmission {
    /// Typed accepted envelope.
    pub incoming: IncomingEnvelope,
    /// Validator verdict for the accepted envelope.
    pub acceptance: Option<Acceptance>,
    /// Outbound command the supervisor must serialize next.
    pub command: OutgoingCommand,
    /// Effective capture mode of the admitted recording (the session's armed mode for
    /// non-start envelopes). The recording pipeline applies exactly this mode.
    pub capture_mode: xtrace_domain::CaptureMode,
    /// Stable limitation codes raised by this admission (for example
    /// `capture_policy_not_armed` when a focused claim was downgraded).
    pub limitations: Vec<&'static str>,
}

/// Outbound command the supervisor wants to emit to the adapter.
///
/// The enum is the supervisor-side mirror of the wire
/// `CaptureCommand` family; the session task translates each variant
/// into the matching wire message.
#[derive(Clone, Debug)]
pub enum OutgoingCommand {
    /// Periodic [`Health`] message.
    Health(Health),
    /// Final [`ProtocolError`] sent before closing the connection.
    ProtocolError(ProtocolError),
    /// [`Ack`] acknowledging one or more envelopes.
    ///
    /// [`Ack`]: xtrace_protocol::generated::agent::Ack
    Ack(xtrace_protocol::generated::agent::Ack),
}

impl OutgoingCommand {
    /// Builds the wire `AgentEnvelope` payload that carries this
    /// command. The caller fills `runtime_session_id`, `session_seq`,
    /// `sent_monotonic_ns`, and `message_id` after the call.
    #[must_use]
    pub fn into_envelope_payload(self) -> PayloadOneof {
        match self {
            Self::Health(health) => PayloadOneof::Health(health),
            Self::ProtocolError(error) => PayloadOneof::ProtocolError(error),
            Self::Ack(ack) => PayloadOneof::Ack(ack),
        }
    }
}

/// Verifies an adapter `AdapterHello` HMAC against the supplied
/// session secret and TLS exporter. The function is a thin wrapper
/// around the protocol-level [`verify_transcript_proof`] that takes
/// typed wire inputs so the session layer does not need to know
/// about the byte layout.
///
/// The transcript proof is bound to the TLS exporter, the runtime
/// session identifier, the client nonce, the server nonce (zero
/// placeholder on the inbound direction), and the manifest digest
/// carried in the inbound `AdapterHello`. Protocol major/minor
/// negotiation is validated separately against `AdapterHello`'s
/// `protocol_major_max` and `protocol_minor_max` fields; the
/// negotiated range is not part of the HMAC transcript. Project
/// identity is enforced separately by the session layer against
/// `AdapterHello.repository_fingerprint` and the bootstrap-anchored
/// `xtrace_domain::RepositoryFingerprint`; the bootstrap artifact
/// carries the expected fingerprint out of band, and the manifest
/// digest arrives in the wire envelope.
///
/// # Errors
///
/// Returns the same error as [`verify_transcript_proof`] when the
/// supplied HMAC does not match the recomputed transcript.
pub fn verify_adapter_hello(
    session_secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &[u8],
    hello: &xtrace_protocol::generated::agent::AdapterHello,
) -> Result<(), xtrace_protocol::handshake::TranscriptProofError> {
    // The adapter does not know the daemon's server nonce when it
    // emits `AdapterHello`, so the inbound direction uses the
    // documented zero placeholder for that field. Both sides agree
    // on the placeholder length so the HMAC layout stays canonical.
    verify_transcript_proof(
        session_secret,
        tls_exporter,
        runtime_session_id,
        &hello.client_nonce,
        &ZERO_NONCE,
        hello.manifest_digest.as_bytes(),
        &hello.hmac,
    )
}

/// Inverse helper: the daemon computes the [`DaemonHello`] HMAC using
/// the real client nonce (recovered from the validated `AdapterHello`)
/// and the daemon's own server nonce. The transcript proof no longer
/// carries any zero-nonce placeholder.
///
/// # Errors
///
/// Returns the same [`xtrace_protocol::handshake::TranscriptProofError`]
/// variant as `compute_transcript_proof` when the underlying HMAC
/// primitive refuses the supplied key. The 256-bit session secret is
/// accepted by HMAC-SHA256 so the error path is unreachable for the
/// documented production key; the result is reported rather than
/// panicked because library code must not call `expect`.
#[must_use = "compute_daemon_hello_proof returns a Result that the supervisor must propagate"]
pub fn compute_daemon_hello_proof(
    session_secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    manifest_digest: &[u8],
) -> Result<[u8; 32], xtrace_protocol::handshake::TranscriptProofError> {
    xtrace_protocol::handshake::compute_transcript_proof(
        session_secret,
        tls_exporter,
        runtime_session_id,
        client_nonce,
        server_nonce,
        manifest_digest,
    )
}

/// Builds a wire [`DaemonHello`] from the daemon-side negotiated
/// parameters and the canonical transcript proof.
///
/// # Errors
///
/// Returns no error today; the helper exists so the signature stays
/// stable if a future field demands validation.
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "every field is a wire-shaped output documented in `03b-protocol-and-api.md` §2.4"
)]
pub fn build_daemon_hello(
    server_nonce: &[u8],
    proof: [u8; 32],
    manifest_digest: &str,
    protocol_major: u32,
    protocol_minor: u32,
    max_envelope_bytes: u32,
    max_batch_events: u32,
    server_monotonic_ns: u64,
) -> DaemonHello {
    use prost::bytes::Bytes;
    DaemonHello {
        protocol_major,
        protocol_minor,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        manifest_digest: manifest_digest.to_string(),
        server_nonce: Bytes::copy_from_slice(server_nonce),
        hmac: Bytes::copy_from_slice(&proof),
        max_envelope_bytes,
        max_batch_events,
        initial_capture_policy_id: String::new(),
        redaction_policy_digest: String::new(),
        server_monotonic_ns,
    }
}

/// Builds a wire [`ProtocolError`] with the supplied code and
/// message. The function is the single owner of the wire shape so
/// callers cannot accidentally omit fields or embed sensitive values.
#[must_use]
pub fn build_protocol_error(code: impl Into<String>, message: impl Into<String>) -> ProtocolError {
    ProtocolError { code: code.into(), message: message.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_and_compute_round_trip() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        // Inbound direction: AdapterHello uses the placeholder
        // server nonce because the server nonce is unknown yet.
        let client_nonce = [0xaa_u8; 32];
        let adapter_proof = xtrace_protocol::handshake::compute_transcript_proof(
            secret,
            exporter,
            session,
            &client_nonce,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest,
        )
        .expect("HMAC accepts the test secret");
        let hello = xtrace_protocol::generated::agent::AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: String::from_utf8(manifest.to_vec()).unwrap(),
            language: "rust".to_string(),
            runtime_name: "test".to_string(),
            runtime_version: "0.0.0".to_string(),
            pid: 0,
            process_start_monotonic_ns: 0,
            parent_launch_id: String::new(),
            repository_fingerprint: String::new(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&client_nonce),
            hmac: Bytes::copy_from_slice(&adapter_proof),
            ..Default::default()
        };
        verify_adapter_hello(secret, exporter, session, &hello).expect("verify");

        // Outbound direction: DaemonHello uses the real client nonce
        // (recovered from the validated AdapterHello) plus the real
        // server nonce. No placeholder nonce remains in the bytes the
        // daemon emits.
        let server_nonce = [0xbb_u8; 32];
        let daemon_proof = compute_daemon_hello_proof(
            secret,
            exporter,
            session,
            &client_nonce,
            &server_nonce,
            manifest,
        )
        .expect("HMAC accepts the test secret");
        let hello = build_daemon_hello(
            &server_nonce,
            daemon_proof,
            std::str::from_utf8(manifest).unwrap(),
            1,
            0,
            1024 * 1024,
            256,
            42,
        );
        assert_eq!(hello.server_nonce, server_nonce.to_vec());
        assert_eq!(hello.hmac, daemon_proof.to_vec());
    }

    #[test]
    fn verify_rejects_wrong_proof() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let client_nonce = [0xaa_u8; 32];
        let hello = xtrace_protocol::generated::agent::AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: String::from_utf8(manifest.to_vec()).unwrap(),
            language: "rust".to_string(),
            runtime_name: "test".to_string(),
            runtime_version: "0.0.0".to_string(),
            pid: 0,
            process_start_monotonic_ns: 0,
            parent_launch_id: String::new(),
            repository_fingerprint: String::new(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&client_nonce),
            // Tampered proof: every byte is one off the correct tag.
            hmac: Bytes::copy_from_slice(&[0u8; 32]),
            ..Default::default()
        };
        let err = verify_adapter_hello(secret, exporter, session, &hello).unwrap_err();
        assert!(matches!(err, xtrace_protocol::handshake::TranscriptProofError::Mismatch));
    }

    #[test]
    fn protocol_error_builder_does_not_panic_on_empty_inputs() {
        let err = build_protocol_error("", "");
        assert_eq!(err.code, "");
        assert_eq!(err.message, "");
    }

    #[test]
    fn outgoing_command_payload_mapping_round_trips() {
        let health = Health {
            monotonic_ns: 1,
            queue_depth_batches: 0,
            resident_bytes: 0,
            status: "ok".to_string(),
        };
        let payload = OutgoingCommand::Health(health.clone()).into_envelope_payload();
        match payload {
            PayloadOneof::Health(out) => assert_eq!(out.status, "ok"),
            other => unreachable!("`Health` payload mapped to wrong variant: {other:?}"),
        }
    }
}
