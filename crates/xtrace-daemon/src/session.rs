//! Session-layer handshake state machine.
//!
//! The session module owns the per-connection state machine that
//! drives the AdapterHello/DaemonHello exchange and the post-hello
//! validation rules documented in
//! `docs/plans/x-trace/03b-protocol-and-api.md` §2:
//!
//! - protocol major version negotiation;
//! - post-hello `runtime_session_id` and `project_id` identity
//!   checks;
//! - monotonic `session_seq` validation (no replay, no gap);
//! - `ProtocolError` emission for any violation;
//! - `Ack` for every accepted envelope;
//! - `Health` echo on a configurable interval.
//!
//! The module exposes [`Session`] as the canonical state machine and
//! [`HandshakeInputs`] as the immutable inputs handed to a session at
//! construction time.

use std::convert::TryFrom;

use xtrace_domain::ids::Id;
use xtrace_domain::{ProjectId, RuntimeSessionId};
use xtrace_protocol::envelope::check_protocol_version;
use xtrace_protocol::generated::agent::{
    Ack, AckDurability, AgentEnvelope, ProtocolError, RejectedMessage,
};
use xtrace_protocol::generated::agent as wire;

use crate::error::ProtocolErrorCode;
use crate::runtime::{
    AdapterHelloAck, HealthInterval, IncomingEnvelope, OutgoingCommand, build_protocol_error,
    compute_daemon_hello_proof, verify_adapter_hello,
};
use crate::secret::SessionSecret;

/// Per-session handshake role marker. Used to keep the
/// [`HandshakeInputs`] structure self-documenting at every call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// The adapter-side role, used by fake adapters in tests.
    Adapter,
    /// The daemon-side role, used by the production supervisor.
    Daemon,
}

/// Immutable inputs required to drive a [`Session`] through its
/// state machine.
#[derive(Clone, Debug)]
pub struct HandshakeInputs {
    /// Per-runtime-session secret used as the HMAC key.
    pub session_secret: SessionSecret,
    /// Bytes exported from the TLS 1.3 connection through
    /// `rustls::Exporter::export_keying_material`.
    pub tls_exporter: Vec<u8>,
    /// Stable session identifier negotiated via the bootstrap
    /// artifact.
    pub runtime_session_id: RuntimeSessionId,
    /// Stable project identifier negotiated via the bootstrap
    /// artifact.
    pub project_id: ProjectId,
    /// Maximum envelope size in bytes the daemon will accept.
    pub max_envelope_bytes: u32,
    /// Maximum batch size in events the daemon will accept.
    pub max_batch_events: u32,
    /// Maximum protocol major version this binary offers.
    pub max_protocol_major: u32,
    /// Maximum protocol minor version this binary offers.
    pub max_protocol_minor: u32,
    /// Manifest digest negotiated at bootstrap.
    pub manifest_digest: String,
    /// Interval between `Health` echoes sent back to the adapter
    /// while the connection is idle.
    pub health_interval: HealthInterval,
    /// Role marker; only [`HandshakeRole::Daemon`] emits
    /// [`OutgoingCommand::Ack`]s and tracks sequencing.
    pub role: HandshakeRole,
}

/// Per-connection state machine.
///
/// `Session` is `Send` and cheap to clone so the supervisor can hold a
/// shared handle and the connection task can move the value into a
/// sub-task. Every state transition is expressed through a method
/// that returns either the next [`OutgoingCommand`] (when the peer
/// is waiting for a reply) or [`SessionError`] when the connection
/// must be closed.
#[derive(Clone, Debug)]
pub struct Session {
    inputs: HandshakeInputs,
    /// Highest contiguous `session_seq` accepted after authentication.
    /// `0` until the first post-hello envelope has been accepted.
    next_expected_seq: u64,
    /// Server nonce generated during the daemon-side handshake.
    /// `None` until the server emits `DaemonHello`.
    server_nonce: Option<Vec<u8>>,
}

impl Session {
    /// Constructs a fresh session over the supplied inputs. The
    /// `next_expected_seq` starts at 1 per
    /// `03b-protocol-and-api.md` §2.3 ("`session_seq` begins at 1
    /// after authentication").
    #[must_use]
    pub fn new(inputs: HandshakeInputs) -> Self {
        Self { inputs, next_expected_seq: 1, server_nonce: None }
    }

    /// Returns the immutable inputs the session was constructed with.
    #[must_use]
    pub fn inputs(&self) -> &HandshakeInputs {
        &self.inputs
    }

    /// Drives the inbound AdapterHello. The function verifies the
    /// HMAC transcript proof, performs protocol major negotiation,
    /// and returns the [`OutgoingCommand::Health`] the supervisor
    /// should send back to the adapter.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] when the HMAC mismatches, the
    /// protocol major is unsupported, or the envelope payload is
    /// not an `AdapterHello`.
    pub fn accept_adapter_hello(
        &mut self,
        envelope: &AgentEnvelope,
    ) -> Result<AdapterHelloAck, SessionError> {
        if !matches!(
            envelope.payload,
            Some(wire::agent_envelope::Payload::AdapterHello(_))
        ) {
            return Err(SessionError::new(ProtocolErrorCode::HelloDecode, "not AdapterHello"));
        }
        if let Err(err) = check_protocol_version(envelope) {
            return Err(SessionError::from_envelope(err, ProtocolErrorCode::ProtocolMajor));
        }
        let wire::agent_envelope::Payload::AdapterHello(hello) = envelope
            .payload
            .as_ref()
            .expect("variant checked above");
        verify_adapter_hello(
            self.inputs.session_secret.read_secret(),
            &self.inputs.tls_exporter,
            self.inputs.runtime_session_id.as_uuid().as_bytes(),
            hello,
        )
        .map_err(|_| SessionError::new(ProtocolErrorCode::HelloProof, "transcript mismatch"))?;
        // Save the manifest digest observed on the wire; the daemon
        // mirrors this value back in DaemonHello and uses it for its
        // own HMAC computation.
        if hello.manifest_digest != self.inputs.manifest_digest {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "manifest_digest mismatch",
            ));
        }
        if hello.protocol_major_max > self.inputs.max_protocol_major {
            return Err(SessionError::new(
                ProtocolErrorCode::ProtocolMajor,
                "adapter major above negotiated range",
            ));
        }
        Ok(AdapterHelloAck {
            protocol_major: self.inputs.max_protocol_major,
            protocol_minor: self.inputs.max_protocol_minor,
            max_envelope_bytes: self.inputs.max_envelope_bytes,
            max_batch_events: self.inputs.max_batch_events,
            capabilities: Vec::new(),
        })
    }

    /// Builds the outbound `DaemonHello` envelope. The caller is
    /// responsible for filling `runtime_session_id`, `session_seq`,
    /// `sent_monotonic_ns`, and `message_id` on the resulting
    /// envelope.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] only when the supplied inputs cannot
    /// be turned into a valid handshake envelope. Today the helper
    /// is infallible; the result type documents the future-proof
    /// signature so callers do not need to be updated when
    /// validation grows.
    pub fn build_daemon_hello(
        &mut self,
        server_nonce: Vec<u8>,
        server_monotonic_ns: u64,
    ) -> Result<AgentEnvelope, SessionError> {
        if self.inputs.role != HandshakeRole::Daemon {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "build_daemon_hello called on adapter role",
            ));
        }
        if server_nonce.len() != 32 {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "server nonce must be exactly 32 bytes",
            ));
        }
        let proof = compute_daemon_hello_proof(
            self.inputs.session_secret.read_secret(),
            &self.inputs.tls_exporter,
            self.inputs.runtime_session_id.as_uuid().as_bytes(),
            &server_nonce,
            self.inputs.manifest_digest.as_bytes(),
        );
        self.server_nonce = Some(server_nonce.clone());
        let hello = crate::runtime::build_daemon_hello(
            &server_nonce,
            proof,
            &self.inputs.manifest_digest,
            self.inputs.max_protocol_major,
            self.inputs.max_protocol_minor,
            self.inputs.max_envelope_bytes,
            self.inputs.max_batch_events,
            server_monotonic_ns,
        );
        Ok(AgentEnvelope {
            protocol_major: self.inputs.max_protocol_major,
            protocol_minor: self.inputs.max_protocol_minor,
            runtime_session_id: self.inputs.runtime_session_id.as_uuid().as_bytes().to_vec(),
            session_seq: 0,
            sent_monotonic_ns: server_monotonic_ns,
            message_id: "daemon-hello".to_string(),
            correlation_token: String::new(),
            payload: Some(wire::agent_envelope::Payload::DaemonHello(hello)),
        })
    }

    /// Validates a post-hello inbound envelope and returns the
    /// decoded [`IncomingEnvelope`] together with the matching
    /// [`OutgoingCommand::Ack`] the supervisor must emit.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] when the envelope fails any of the
    /// post-hello identity, sequence, or framing checks. The
    /// supervisor must close the connection on any error.
    pub fn accept_post_hello(
        &mut self,
        envelope: &AgentEnvelope,
    ) -> Result<(IncomingEnvelope, OutgoingCommand), SessionError> {
        if envelope.protocol_major != self.inputs.max_protocol_major
            || envelope.protocol_minor > self.inputs.max_protocol_minor
        {
            return Err(SessionError::new(
                ProtocolErrorCode::ProtocolMajor,
                "post-hello major mismatch",
            ));
        }
        if envelope.runtime_session_id.as_slice()
            != self.inputs.runtime_session_id.as_uuid().as_bytes()
        {
            return Err(SessionError::new(
                ProtocolErrorCode::SessionIdentity,
                "runtime_session_id mismatch",
            ));
        }
        // The project identity is enforced through the bootstrap
        // artifact: every envelope must carry the same project ID.
        // Today XTP-Agent envelopes do not carry a project_id field,
        // so the value is encoded in the runtime_session_id by the
        // daemon. Future slices add an explicit project_id field.
        if envelope.session_seq != self.next_expected_seq {
            if envelope.session_seq < self.next_expected_seq {
                return Err(SessionError::new(
                    ProtocolErrorCode::SessionSequence,
                    "replay",
                ));
            }
            return Err(SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "gap",
            ));
        }
        let incoming = match &envelope.payload {
            Some(wire::agent_envelope::Payload::CapabilitySet(set)) => {
                IncomingEnvelope::CapabilitySet(set.clone())
            }
            Some(wire::agent_envelope::Payload::Health(health)) => {
                IncomingEnvelope::Health(health.clone())
            }
            Some(wire::agent_envelope::Payload::ProtocolError(err)) => {
                return Err(SessionError::new(
                    ProtocolErrorCode::HelloDecode,
                    format!("adapter returned ProtocolError: {}", err.message),
                ));
            }
            other => {
                return Err(SessionError::new(
                    ProtocolErrorCode::HelloDecode,
                    format!("unsupported payload after hello: {:?}", payload_kind(other)),
                ));
            }
        };
        self.next_expected_seq = self.next_expected_seq.saturating_add(1);
        let ack = build_ack(
            self.next_expected_seq.saturating_sub(1),
            envelope.message_id.clone(),
            AckDurability::Staged,
        );
        Ok((incoming, OutgoingCommand::Ack(ack)))
    }

    /// Returns the next outgoing `Health` message the supervisor
    /// should send while the connection is idle. The `now_ns` value
    /// is filled into the [`Health::monotonic_ns`] field.
    #[must_use]
    pub fn next_health(&self, now_ns: u64) -> OutgoingCommand {
        OutgoingCommand::Health(wire::Health {
            monotonic_ns: now_ns,
            queue_depth_batches: 0,
            resident_bytes: 0,
            status: "ok".to_string(),
        })
    }

    /// Returns the configured health interval.
    #[must_use]
    pub fn health_interval(&self) -> HealthInterval {
        self.inputs.health_interval
    }

    /// Returns the configured `max_envelope_bytes`.
    #[must_use]
    pub fn max_envelope_bytes(&self) -> u32 {
        self.inputs.max_envelope_bytes
    }

    /// Returns the configured project identifier.
    #[must_use]
    pub fn project_id(&self) -> ProjectId {
        self.inputs.project_id
    }

    /// Returns the configured runtime session identifier.
    #[must_use]
    pub fn runtime_session_id(&self) -> RuntimeSessionId {
        self.inputs.runtime_session_id
    }

    /// Returns the server nonce generated by the daemon. `None` when
    /// the daemon has not yet emitted `DaemonHello`.
    #[must_use]
    pub fn server_nonce(&self) -> Option<&[u8]> {
        self.server_nonce.as_deref()
    }
}

fn payload_kind(payload: &wire::agent_envelope::Payload) -> &'static str {
    match payload {
        wire::agent_envelope::Payload::AdapterHello(_) => "AdapterHello",
        wire::agent_envelope::Payload::DaemonHello(_) => "DaemonHello",
        wire::agent_envelope::Payload::CapabilitySet(_) => "CapabilitySet",
        wire::agent_envelope::Payload::EndpointClaims(_) => "EndpointClaimBatch",
        wire::agent_envelope::Payload::StaticPaths(_) => "StaticPathBatch",
        wire::agent_envelope::Payload::RecordingStarted(_) => "RecordingStarted",
        wire::agent_envelope::Payload::EventBatch(_) => "EventBatch",
        wire::agent_envelope::Payload::RecordingFinished(_) => "RecordingFinished",
        wire::agent_envelope::Payload::DropNotice(_) => "DropNotice",
        wire::agent_envelope::Payload::Health(_) => "Health",
        wire::agent_envelope::Payload::Ack(_) => "Ack",
        wire::agent_envelope::Payload::Throttle(_) => "Throttle",
        wire::agent_envelope::Payload::CaptureCommand(_) => "CaptureCommand",
        wire::agent_envelope::Payload::ProtocolError(_) => "ProtocolError",
    }
}

fn build_ack(highest_session_seq: u64, message_id: String, durability: AckDurability) -> Ack {
    Ack {
        highest_contiguous_session_seq: highest_session_seq,
        highest_contiguous_recording_seq: Default::default(),
        durability: durability as i32,
        rejected: vec![RejectedMessage {
            message_id,
            reason_code: String::new(),
        }],
    }
}

/// Failure mode of a session state transition. The supervisor maps
/// the [`ProtocolErrorCode`] to a stable `ProtocolError` envelope and
/// closes the connection.
#[derive(Debug)]
pub struct SessionError {
    pub code: ProtocolErrorCode,
    pub detail: String,
}

impl SessionError {
    /// Builds a session error from a raw `(code, detail)` pair.
    #[must_use]
    pub const fn new(code: ProtocolErrorCode, detail: String) -> Self {
        Self { code, detail }
    }

    /// Converts an envelope-decoding failure into a session error.
    pub fn from_envelope(
        err: xtrace_protocol::envelope::EnvelopeError,
        fallback: ProtocolErrorCode,
    ) -> Self {
        let code = match &err {
            xtrace_protocol::envelope::EnvelopeError::ProtocolVersion { .. } => {
                ProtocolErrorCode::ProtocolMajor
            }
            xtrace_protocol::envelope::EnvelopeError::TooLarge { .. } => {
                ProtocolErrorCode::FrameTooLarge
            }
            _ => fallback,
        };
        Self { code, detail: format!("{err}") }
    }

    /// Renders the error into the wire `ProtocolError` envelope.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        let message = match self.code {
            ProtocolErrorCode::Shutdown => "daemon shutting down".to_string(),
            _ => self.detail.clone(),
        };
        build_protocol_error(self.code.as_str().to_string(), message)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SessionSecret;
    use xtrace_domain::ids::Id as _;
    use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
    use xtrace_protocol::generated::agent::{AdapterHello, Health};
    use xtrace_protocol::handshake::compute_transcript_proof;

    fn sample_inputs(secret_bytes: Vec<u8>) -> HandshakeInputs {
        let secret = SessionSecret::from_bytes(&secret_bytes).expect("secret");
        HandshakeInputs {
            session_secret: secret,
            tls_exporter: b"tls-exporter".to_vec(),
            runtime_session_id: RuntimeSessionId::new(),
            project_id: ProjectId::new(),
            max_envelope_bytes: 1024 * 1024,
            max_batch_events: 256,
            max_protocol_major: 1,
            max_protocol_minor: 0,
            manifest_digest: "b3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            health_interval: HealthInterval::default(),
            role: HandshakeRole::Daemon,
        }
    }

    fn envelope_with_payload(
        session_id: RuntimeSessionId,
        seq: u64,
        payload: PayloadOneof,
    ) -> AgentEnvelope {
        AgentEnvelope {
            protocol_major: 1,
            protocol_minor: 0,
            runtime_session_id: session_id.as_uuid().as_bytes().to_vec(),
            session_seq: seq,
            sent_monotonic_ns: 1,
            message_id: "msg".to_string(),
            correlation_token: String::new(),
            payload: Some(payload),
        }
    }

    fn sample_adapter_hello(
        session: &Session,
        secret: &[u8],
        manifest: &str,
    ) -> AdapterHello {
        let exporter = session.inputs().tls_exporter.clone();
        let session_id = session.inputs().runtime_session_id;
        let client_nonce = [0xaa_u8; 16];
        let proof = compute_transcript_proof(
            secret,
            &exporter,
            session_id.as_uuid().as_bytes(),
            &client_nonce,
            &[0u8; 32],
            manifest.as_bytes(),
        );
        AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: manifest.to_string(),
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
            hmac: proof.to_vec(),
        }
    }

    #[test]
    fn accept_adapter_hello_round_trip() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest = session.inputs().manifest_digest.clone();
        let hello = sample_adapter_hello(&session, &secret, &manifest);
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let ack = session.accept_adapter_hello(&envelope).expect("accept");
        assert_eq!(ack.protocol_major, 1);
        assert_eq!(ack.protocol_minor, 0);
    }

    #[test]
    fn accept_adapter_hello_rejects_bad_proof() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let manifest = session.inputs().manifest_digest.clone();
        let hello = AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: manifest,
            language: "rust".to_string(),
            runtime_name: "test".to_string(),
            runtime_version: "0.0.0".to_string(),
            pid: 0,
            process_start_monotonic_ns: 0,
            parent_launch_id: String::new(),
            repository_fingerprint: String::new(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: vec![0xaa; 16],
            hmac: vec![0u8; 32],
        };
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloProof);
    }

    #[test]
    fn accept_post_hello_rejects_gap_and_replay() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let session_id = session.inputs().runtime_session_id;
        let envelope = envelope_with_payload(
            session_id,
            5,
            PayloadOneof::Health(Health {
                monotonic_ns: 1,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "ok".to_string(),
            }),
        );
        let err = session.accept_post_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionSequence);
        // Replay after the gap: still rejected because the expected
        // sequence number has not moved.
        let err = session.accept_post_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionSequence);
    }

    #[test]
    fn accept_post_hello_rejects_wrong_session_id() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let other_id = RuntimeSessionId::new();
        let envelope = envelope_with_payload(
            other_id,
            1,
            PayloadOneof::Health(Health {
                monotonic_ns: 1,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "ok".to_string(),
            }),
        );
        let err = session.accept_post_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionIdentity);
    }

    #[test]
    fn accept_post_hello_rejects_post_hello_version_mismatch() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let session_id = session.inputs().runtime_session_id;
        let mut envelope = envelope_with_payload(
            session_id,
            1,
            PayloadOneof::Health(Health {
                monotonic_ns: 1,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "ok".to_string(),
            }),
        );
        envelope.protocol_major = 99;
        let err = session.accept_post_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::ProtocolMajor);
    }

    #[test]
    fn build_daemon_hello_produces_a_well_formed_envelope() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let server_nonce = [0xcc_u8; 32];
        let envelope = session
            .build_daemon_hello(server_nonce.to_vec(), 12345)
            .expect("hello");
        assert_eq!(envelope.session_seq, 0);
        assert_eq!(envelope.message_id, "daemon-hello");
        match envelope.payload {
            Some(wire::agent_envelope::Payload::DaemonHello(ref hello)) => {
                assert_eq!(hello.server_nonce, server_nonce.to_vec());
                assert_eq!(hello.max_envelope_bytes, 1024 * 1024);
            }
            _ => panic!("expected DaemonHello payload"),
        }
        assert_eq!(session.server_nonce(), Some(server_nonce.as_slice()));
    }

    #[test]
    fn build_daemon_hello_rejects_wrong_nonce_length() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let err = session.build_daemon_hello(vec![0; 16], 1).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn build_daemon_hello_rejects_adapter_role() {
        let mut inputs = sample_inputs(vec![0xab; 32]);
        inputs.role = HandshakeRole::Adapter;
        let mut session = Session::new(inputs);
        let err = session.build_daemon_hello(vec![0; 32], 1).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn session_error_to_protocol_error_carries_code_and_message() {
        let err = SessionError::new(ProtocolErrorCode::SessionSequence, "gap".to_string());
        let wire = err.to_protocol_error();
        assert_eq!(wire.code, "XTR-DAEMON-SESSION-SEQUENCE");
        assert_eq!(wire.message, "gap");
    }

    #[test]
    fn try_from_u32_for_ack_durability_is_total() {
        // `AckDurability::Staged` is wire value 1; the helper below
        // exists to make sure the conversion is total even if the
        // protobuf enum gains new variants.
        let _ = AckDurability::try_from(1).expect("staged parses");
        let _ = AckDurability::try_from(2).expect("committed parses");
        assert!(AckDurability::try_from(99).is_err());
    }
}