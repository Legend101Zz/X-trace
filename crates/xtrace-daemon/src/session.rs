//! Session-layer handshake state machine.
//!
//! The session module owns the per-connection state machine that
//! drives the AdapterHello/DaemonHello exchange and the post-hello
//! validation rules documented in
//! `docs/plans/x-trace/03b-protocol-and-api.md` §2:
//!
//! - protocol major version negotiation;
//! - post-hello `runtime_session_id` identity checks;
//! - monotonic `session_seq` validation (no replay, no gap);
//! - `ProtocolError` emission for any violation;
//! - `Ack` for every accepted envelope;
//! - `Health` echo on a configurable interval.
//!
//! ## Inbound `AdapterHello` invariants
//!
//! The adapter's first envelope carries the bootstrap-anchored
//! identity and a transcript proof. The session enforces the
//! following invariants before the transcript proof is even
//! verified:
//!
//! - the envelope payload is `AdapterHello`;
//! - `session_seq == 0` because `AgentEnvelope.session_seq` begins
//!   at 1 only after authentication;
//! - `message_id` is non-empty;
//! - `client_nonce` is exactly 32 bytes;
//! - `protocol_major_max` is at least the daemon's major (the
//!   adapter's range must include a supported version);
//! - `manifest_digest` is a canonical non-empty digest string;
//! - `repository_fingerprint` matches the bootstrap expected value;
//! - the transcript proof verifies against the recovered client
//!   nonce, the canonical zero server-nonce placeholder, the
//!   bootstrap manifest digest, and the canonical project context.
//!
//! The validated `client_nonce` is persisted in session state so the
//! outbound `DaemonHello` transcript proof can use the real client
//! nonce rather than the documented inbound-only zero placeholder.
//!
//! The module exposes [`Session`] as the canonical state machine and
//! [`HandshakeInputs`] as the immutable inputs handed to a session at
//! construction time.

use prost::bytes::Bytes;
use xtrace_domain::ids::Id;
use xtrace_domain::{ProjectId, RuntimeSessionId};
use xtrace_protocol::envelope::check_protocol_version;
use xtrace_protocol::generated::agent as wire;
use xtrace_protocol::generated::agent::{Ack, AckDurability, AgentEnvelope, ProtocolError};

use crate::error::ProtocolErrorCode;
use crate::runtime::{
    AdapterHelloAck, HealthInterval, IncomingEnvelope, OutgoingCommand, build_protocol_error,
    compute_daemon_hello_proof, verify_adapter_hello,
};
use crate::secret::SessionSecret;

/// Length, in bytes, of the client nonce exchanged during the handshake.
/// The adapter supplies the nonce; the daemon verifies the length
/// before computing the transcript proof.
const CLIENT_NONCE_LEN: usize = 32;

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
    /// Canonical repository fingerprint negotiated at bootstrap. The
    /// daemon validates the `AdapterHello.repository_fingerprint`
    /// against this value and rejects mismatches deterministically.
    pub expected_repository_fingerprint: String,
    /// Health interval sent back to the adapter while the
    /// connection is idle.
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
    /// Client nonce validated during the inbound `AdapterHello`.
    /// `None` until the daemon has accepted `AdapterHello`.
    client_nonce: Option<Vec<u8>>,
    /// Adapter manifest digest validated during the inbound
    /// `AdapterHello`. The daemon echoes this value back in
    /// `DaemonHello` and folds it into the outbound transcript proof
    /// so the adapter can recompute the proof with the same input.
    /// `None` until the daemon has accepted `AdapterHello`.
    adapter_manifest_digest: Option<String>,
}

impl Session {
    /// Constructs a fresh session over the supplied inputs. The
    /// `next_expected_seq` starts at 1 per
    /// `03b-protocol-and-api.md` §2.3 ("`session_seq` begins at 1
    /// after authentication").
    #[must_use]
    pub fn new(inputs: HandshakeInputs) -> Self {
        Self {
            inputs,
            next_expected_seq: 1,
            server_nonce: None,
            client_nonce: None,
            adapter_manifest_digest: None,
        }
    }

    /// Returns the immutable inputs the session was constructed with.
    #[must_use]
    pub fn inputs(&self) -> &HandshakeInputs {
        &self.inputs
    }

    /// Drives the inbound `AdapterHello`. The function validates the
    /// documented hello invariants, verifies the HMAC transcript
    /// proof against the recovered client nonce, and persists the
    /// nonce for the outbound `DaemonHello` proof.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] when the hello violates any
    /// documented invariant or the transcript proof mismatches.
    pub fn accept_adapter_hello(
        &mut self,
        envelope: &AgentEnvelope,
    ) -> Result<AdapterHelloAck, SessionError> {
        if !matches!(envelope.payload, Some(wire::agent_envelope::Payload::AdapterHello(_))) {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "not AdapterHello".to_string(),
            ));
        }
        if let Err(err) = check_protocol_version(envelope) {
            return Err(SessionError::from_envelope(err, ProtocolErrorCode::ProtocolMajor));
        }
        let hello = match envelope.payload.as_ref() {
            Some(wire::agent_envelope::Payload::AdapterHello(hello)) => hello,
            Some(_) | None => {
                return Err(SessionError::new(
                    ProtocolErrorCode::HelloDecode,
                    "not AdapterHello".to_string(),
                ));
            }
        };
        if envelope.runtime_session_id.as_ref()
            != self.inputs.runtime_session_id.as_uuid().as_bytes()
        {
            return Err(SessionError::new(
                ProtocolErrorCode::SessionIdentity,
                "runtime_session_id mismatch".to_string(),
            ));
        }
        if envelope.session_seq != 0 {
            return Err(SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "hello must carry session_seq == 0".to_string(),
            ));
        }
        if envelope.message_id.is_empty() {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "message_id must not be empty".to_string(),
            ));
        }
        if hello.client_nonce.len() != CLIENT_NONCE_LEN {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                format!("client_nonce must be exactly {CLIENT_NONCE_LEN} bytes"),
            ));
        }
        // Protocol offer must include the daemon's supported major.
        // A peer offering only an older major has nothing in common
        // with this binary; a peer offering a newer maximum is
        // negotiated down to the daemon's supported version rather
        // than rejected outright.
        if hello.protocol_major_max < self.inputs.max_protocol_major {
            return Err(SessionError::new(
                ProtocolErrorCode::ProtocolMajor,
                "adapter protocol offer does not include the daemon major".to_string(),
            ));
        }
        if hello.manifest_digest.is_empty() {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "manifest_digest must not be empty".to_string(),
            ));
        }
        if !is_canonical_manifest_digest(&hello.manifest_digest) {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "manifest_digest is not a canonical lowercase hex digest".to_string(),
            ));
        }
        if hello.repository_fingerprint != self.inputs.expected_repository_fingerprint {
            return Err(SessionError::new(
                ProtocolErrorCode::ProjectIdentity,
                "repository_fingerprint mismatch".to_string(),
            ));
        }
        verify_adapter_hello(
            self.inputs.session_secret.read_secret(),
            &self.inputs.tls_exporter,
            self.inputs.runtime_session_id.as_uuid().as_bytes(),
            self.inputs.project_id.as_uuid().as_bytes(),
            hello,
        )
        .map_err(|_| {
            SessionError::new(ProtocolErrorCode::HelloProof, "transcript mismatch".to_string())
        })?;
        self.client_nonce = Some(hello.client_nonce.to_vec());
        self.adapter_manifest_digest = Some(hello.manifest_digest.clone());
        let negotiated_minor = hello.protocol_minor_max.min(self.inputs.max_protocol_minor);
        Ok(AdapterHelloAck {
            protocol_major: self.inputs.max_protocol_major,
            protocol_minor: negotiated_minor,
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
    /// Returns [`SessionError`] when the supplied inputs cannot be
    /// turned into a valid handshake envelope. The function refuses
    /// to emit `DaemonHello` until the inbound `AdapterHello` has
    /// been validated; this prevents the daemon from constructing a
    /// transcript proof against a missing or replaced client nonce.
    pub fn build_daemon_hello(
        &mut self,
        server_nonce: Vec<u8>,
        server_monotonic_ns: u64,
    ) -> Result<AgentEnvelope, SessionError> {
        if self.inputs.role != HandshakeRole::Daemon {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "build_daemon_hello called on adapter role".to_string(),
            ));
        }
        if server_nonce.len() != CLIENT_NONCE_LEN {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "server nonce must be exactly 32 bytes".to_string(),
            ));
        }
        let client_nonce = self.client_nonce.as_deref().ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "daemon hello requested before AdapterHello was validated".to_string(),
            )
        })?;
        let manifest_digest = self.adapter_manifest_digest.as_deref().ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "daemon hello requested before AdapterHello was validated".to_string(),
            )
        })?;
        let proof = compute_daemon_hello_proof(
            self.inputs.session_secret.read_secret(),
            &self.inputs.tls_exporter,
            self.inputs.runtime_session_id.as_uuid().as_bytes(),
            self.inputs.project_id.as_uuid().as_bytes(),
            client_nonce,
            &server_nonce,
            manifest_digest.as_bytes(),
        )
        .map_err(|_| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "hmac primitive refused the session secret".to_string(),
            )
        })?;
        self.server_nonce = Some(server_nonce.clone());
        let hello = crate::runtime::build_daemon_hello(
            &server_nonce,
            proof,
            manifest_digest,
            self.inputs.max_protocol_major,
            self.inputs.max_protocol_minor,
            self.inputs.max_envelope_bytes,
            self.inputs.max_batch_events,
            server_monotonic_ns,
        );
        Ok(AgentEnvelope {
            protocol_major: self.inputs.max_protocol_major,
            protocol_minor: self.inputs.max_protocol_minor,
            runtime_session_id: Bytes::copy_from_slice(
                self.inputs.runtime_session_id.as_uuid().as_bytes(),
            ),
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
                "post-hello major mismatch".to_string(),
            ));
        }
        if envelope.runtime_session_id.as_ref()
            != self.inputs.runtime_session_id.as_uuid().as_bytes()
        {
            return Err(SessionError::new(
                ProtocolErrorCode::SessionIdentity,
                "runtime_session_id mismatch".to_string(),
            ));
        }
        if envelope.message_id.is_empty() {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "post-hello message_id must not be empty".to_string(),
            ));
        }
        if envelope.session_seq != self.next_expected_seq {
            if envelope.session_seq < self.next_expected_seq {
                return Err(SessionError::new(
                    ProtocolErrorCode::SessionSequence,
                    "replay".to_string(),
                ));
            }
            return Err(SessionError::new(ProtocolErrorCode::SessionSequence, "gap".to_string()));
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
            Some(other) => {
                return Err(SessionError::new(
                    ProtocolErrorCode::HelloDecode,
                    format!("unsupported payload after hello: {}", payload_kind(other)),
                ));
            }
            None => {
                return Err(SessionError::new(
                    ProtocolErrorCode::HelloDecode,
                    "envelope carried no payload after hello".to_string(),
                ));
            }
        };
        // `checked_add` is preferred over `saturating_add` because a
        // sequence counter that silently stops advancing would mask a
        // bug as success. The exhaustion is unreachable in practice
        // because the session lifetime is bounded by the configured
        // queue capacity and the admission control.
        self.next_expected_seq = self.next_expected_seq.checked_add(1).ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "session_seq overflow".to_string(),
            )
        })?;
        let ack = build_ack(self.next_expected_seq - 1);
        Ok((incoming, OutgoingCommand::Ack(ack)))
    }

    /// Returns the next outgoing `Health` message the supervisor
    /// should send while the connection is idle. The `now_ns` value
    /// is filled into the `Health::monotonic_ns` field.
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

fn is_canonical_manifest_digest(value: &str) -> bool {
    // The bounded slice accepts any canonical lowercase hex digest of
    // 64 characters, optionally prefixed with a `b3:` BLAKE3 tag.
    // We refuse both the empty string and any non-hex character.
    // The certificate pin uses the same `b3:<64 hex>` form; the
    // adapter manifest is a separate identity and is not required
    // to match the pin, but it must be syntactically valid.
    let hex = value.strip_prefix("b3:").unwrap_or(value);
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
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

fn build_ack(highest_session_seq: u64) -> Ack {
    // Successful acknowledgement carries an empty `rejected` list.
    // A message is rejected when it explicitly violates a stable rule;
    // honest acknowledgement does not stamp the message id with a
    // empty reason code because that is semantically a rejection.
    Ack {
        highest_contiguous_session_seq: highest_session_seq,
        highest_contiguous_recording_seq: Default::default(),
        durability: AckDurability::Staged as i32,
        rejected: Vec::new(),
    }
}

/// Failure mode of a session state transition. The supervisor maps
/// the [`ProtocolErrorCode`] to a stable `ProtocolError` envelope and
/// closes the connection.
#[derive(Debug)]
pub struct SessionError {
    /// Stable `XTR-DAEMON-*` code that maps directly onto the wire
    /// `ProtocolError.code` field. Carrying it on the error struct
    /// avoids avoids string parsing on the supervisor side.
    pub code: ProtocolErrorCode,
    /// Human-readable diagnostic that never embeds a captured value,
    /// secret, or peer-supplied identifier.
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
    use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
    use xtrace_protocol::generated::agent::{AdapterHello, Health};

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
            expected_repository_fingerprint: "expected-repo".to_string(),
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
            runtime_session_id: Bytes::copy_from_slice(session_id.as_uuid().as_bytes()),
            session_seq: seq,
            sent_monotonic_ns: 1,
            message_id: "msg".to_string(),
            correlation_token: String::new(),
            payload: Some(payload),
        }
    }

    fn sample_adapter_hello(session: &Session, secret: &[u8], manifest: &str) -> AdapterHello {
        let exporter = session.inputs().tls_exporter.clone();
        let session_id = session.inputs().runtime_session_id;
        let project_id = session.inputs().project_id;
        let client_nonce = [0xaa_u8; 32];
        let ctx = xtrace_protocol::handshake::project_context(project_id.as_uuid().as_bytes());
        let proof = xtrace_protocol::handshake::compute_transcript_proof(
            secret,
            &exporter,
            session_id.as_uuid().as_bytes(),
            &client_nonce,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest.as_bytes(),
            &ctx,
        )
        .expect("HMAC accepts the test secret");
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
            repository_fingerprint: "expected-repo".to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&client_nonce),
            hmac: Bytes::copy_from_slice(&proof),
        }
    }

    #[test]
    fn accept_adapter_hello_round_trip() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
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
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut hello = AdapterHello {
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
            repository_fingerprint: "expected-repo".to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&[0xaa_u8; 32]),
            hmac: Bytes::copy_from_slice(&[0u8; 32]),
        };
        hello.repository_fingerprint = "expected-repo".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloProof);
    }

    #[test]
    fn accept_adapter_hello_rejects_wrong_client_nonce_length() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut hello = AdapterHello {
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
            repository_fingerprint: "expected-repo".to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&[0xaa_u8; 16]),
            hmac: Bytes::copy_from_slice(&[0u8; 32]),
        };
        hello.repository_fingerprint = "expected-repo".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn accept_adapter_hello_rejects_wrong_repository_fingerprint() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut hello = sample_adapter_hello(&session, &secret, &manifest);
        hello.repository_fingerprint = "wrong-repo".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::ProjectIdentity);
    }

    #[test]
    fn accept_adapter_hello_rejects_wrong_runtime_session_id() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let hello = sample_adapter_hello(&session, &secret, &manifest);
        let envelope =
            envelope_with_payload(RuntimeSessionId::new(), 0, PayloadOneof::AdapterHello(hello));
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionIdentity);
    }

    #[test]
    fn accept_adapter_hello_rejects_nonzero_session_seq() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let hello = sample_adapter_hello(&session, &secret, &manifest);
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            1,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionSequence);
    }

    #[test]
    fn accept_adapter_hello_rejects_protocol_offer_below_daemon_major() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut hello = sample_adapter_hello(&session, &secret, &manifest);
        hello.protocol_major_max = 0;
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::ProtocolMajor);
    }

    #[test]
    fn accept_adapter_hello_negotiates_down_to_supported_major() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut hello = sample_adapter_hello(&session, &secret, &manifest);
        hello.protocol_major_max = 2;
        hello.protocol_minor_max = 3;
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
    fn accept_post_hello_rejects_empty_message_id() {
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
        envelope.message_id.clear();
        let err = session.accept_post_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn ack_carries_no_rejected_messages_for_successful_acceptance() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let session_id = session.inputs().runtime_session_id;
        let envelope = envelope_with_payload(
            session_id,
            1,
            PayloadOneof::Health(Health {
                monotonic_ns: 1,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "ok".to_string(),
            }),
        );
        let (_incoming, cmd) = session.accept_post_hello(&envelope).expect("accept");
        let ack = match cmd {
            OutgoingCommand::Ack(ack) => ack,
            other => unreachable!("expected Ack, got {other:?}"),
        };
        assert!(ack.rejected.is_empty());
        assert_eq!(ack.highest_contiguous_session_seq, 1);
    }

    #[test]
    fn build_daemon_hello_produces_a_well_formed_envelope() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let manifest =
            "b3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let hello = sample_adapter_hello(&session, &secret, &manifest);
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        session.accept_adapter_hello(&envelope).expect("hello");
        let server_nonce = [0xcc_u8; 32];
        let envelope = session.build_daemon_hello(server_nonce.to_vec(), 12345).expect("hello");
        assert_eq!(envelope.session_seq, 0);
        assert_eq!(envelope.message_id, "daemon-hello");
        match envelope.payload {
            Some(wire::agent_envelope::Payload::DaemonHello(ref hello)) => {
                assert_eq!(hello.server_nonce, server_nonce.to_vec());
                assert_eq!(hello.max_envelope_bytes, 1024 * 1024);
            }
            other => unreachable!("expected DaemonHello payload, got {other:?}"),
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
    fn build_daemon_hello_requires_prior_adapter_hello() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
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
    fn try_from_u32_for_ack_dack_is_total() {
        // `AckDurability::Staged` is wire value 1; the helper below
        // exists to make sure the conversion is total even if the
        // protobuf enum gains new variants.
        let _ = AckDurability::try_from(1).expect("staged parses");
        let _ = AckDurability::try_from(2).expect("committed parses");
        assert!(AckDurability::try_from(99).is_err());
    }

    #[test]
    fn canonical_manifest_digest_accepts_lowercase_b3_hex() {
        assert!(is_canonical_manifest_digest(
            "b3:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_canonical_manifest_digest(""));
        assert!(!is_canonical_manifest_digest("not-a-digest"));
        assert!(!is_canonical_manifest_digest(
            "B3:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_canonical_manifest_digest(
            "b3:000000000000000000000000000000000000000000000000000000000000000"
        ));
    }
}
