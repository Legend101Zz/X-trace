//! Per-connection runtime types.
//!
//! The runtime module owns the per-connection types that flow between
//! the [`crate::session::Session`] and the supervisor: incoming
//! envelopes that the supervisor decoded from the TLS stream,
//! outgoing commands the supervisor sends, and the adapter-side
//! [`AdapterHelloAck`] that the supervisor returns once the
//! [`AdapterHello`] transcript proof has been verified.

use std::time::Duration;

use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    AgentEnvelope, CapabilitySet, DaemonHello, Health, ProtocolError,
};
use xtrace_protocol::handshake::verify_transcript_proof;

/// Default `Health` interval sent back to the adapter while idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthInterval(pub Duration);

impl Default for HealthInterval {
    fn default() -> Self {
        Self(Duration::from_secs(10))
    }
}

/// Result of a successful [`AdapterHello`] exchange.
///
/// The supervisor forwards this receipt to the [`crate::session`]
/// layer so the adapter may immediately begin sending
/// [`CapabilitySet`] and [`Health`] traffic.
#[derive(Clone, Debug)]
pub struct AdapterHelloAck {
    /// Negotiated protocol major version. Always equal to the
    /// daemon's `max_envelope_bytes` value but mirrored here so the
    /// supervisor can log the negotiated envelope without re-reading
    /// the bootstrap artifact.
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
/// The supervisor decodes incoming bytes into this enum so the
/// session task can pattern-match without touching protobuf types.
#[derive(Clone, Debug)]
pub enum IncomingEnvelope {
    /// Adapter supplied its initial [`CapabilitySet`].
    CapabilitySet(CapabilitySet),
    /// Adapter sent a [`Health`] update.
    Health(Health),
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
    /// Builds the [`AgentEnvelope`] that carries this command. The
    /// caller fills `runtime_session_id`, `session_seq`,
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

/// Verifies an [`AdapterHello`] HMAC against the supplied session
/// secret and TLS exporter. The function is a thin wrapper around the
/// protocol-level [`verify_transcript_proof`] that takes typed wire
/// inputs so the session layer does not need to know about the byte
/// layout.
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
    verify_transcript_proof(
        session_secret,
        tls_exporter,
        runtime_session_id,
        &hello.client_nonce,
        // `server_nonce` is not yet established when the adapter sends
        // AdapterHello; the daemon supplies its own non-zero nonce in
        // `DaemonHello` and verifies the client proof using that
        // nonce during the inbound `AdapterHello` exchange. For the
        // inbound verification we substitute a fixed zero nonce so
        // the byte layout matches the wire helper exactly; the same
        // canonical layout is reused on the outbound direction.
        &[0u8; 32],
        hello.manifest_digest.as_bytes(),
        &hello.hmac,
    )
}

/// Inverse helper: the daemon computes the [`DaemonHello`] HMAC using
/// the server nonce and the same canonical layout. Returns the
/// 32-byte tag.
#[must_use]
pub fn compute_daemon_hello_proof(
    session_secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &[u8],
    server_nonce: &[u8],
    manifest_digest: &[u8],
) -> [u8; 32] {
    xtrace_protocol::handshake::compute_transcript_proof(
        session_secret,
        tls_exporter,
        runtime_session_id,
        // The client nonce is unknown to the daemon when computing
        // its own outbound HMAC, but the canonical layout requires a
        // fixed-length chunk. We substitute the documented zero
        // nonce so the byte layout is identical to the inbound
        // direction; the adapter verifies using its own nonce.
        &[0u8; 32],
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
        // Inbound direction (AdapterHello uses the placeholder
        // server nonce because the server nonce is unknown yet).
        let client_nonce = [0xaa_u8; 16];
        let adapter_proof = xtrace_protocol::handshake::compute_transcript_proof(
            secret,
            exporter,
            session,
            &client_nonce,
            &[0u8; 32],
            manifest,
        );
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
            client_nonce: client_nonce.to_vec(),
            hmac: adapter_proof.to_vec(),
        };
        verify_adapter_hello(secret, exporter, session, &hello).expect("verify");

        // Outbound direction (DaemonHello uses the real server
        // nonce and the placeholder client nonce).
        let server_nonce = [0xbb_u8; 16];
        let daemon_proof = compute_daemon_hello_proof(
            secret,
            exporter,
            session,
            &server_nonce,
            manifest,
        );
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
        let client_nonce = [0xaa_u8; 16];
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
            client_nonce: client_nonce.to_vec(),
            // Tampered proof: every byte is one off the correct tag.
            hmac: vec![0u8; 32],
        };
        let err = verify_adapter_hello(secret, exporter, session, &hello).unwrap_err();
        assert!(matches!(
            err,
            xtrace_protocol::handshake::TranscriptProofError::Mismatch
        ));
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
            _ => panic!("expected health payload"),
        }
    }
}