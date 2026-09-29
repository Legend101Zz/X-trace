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
//! After the authenticated handshake, [`Session::accept_post_hello`]
//! admits the wire `CapabilitySet`, `Health`, and recording payloads
//! (`RecordingStarted`, `EventBatch`, `RecordingFinished`) as typed
//! [`IncomingEnvelope`] variants, retains each in the bounded
//! `staged_incoming` queue, and returns [`AckDurability::Staged`].
//! Recording-level validation, lifecycle, persistence, and `Committed`
//! belong to the downstream ingester.
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
//! - `manifest_digest` is a canonical `xtrace_domain::ContentHash`
//!   (`b3:` + 64 lowercase hex); the daemon validates byte equality
//!   against [`ContentHash::to_canonical`] rather than relying on
//!   `ContentHash::from_str` alone, because the parser accepts
//!   uppercase hex digits case-insensitively. The manifest digest
//!   arrives in the wire envelope itself; it is authenticated by the
//!   transcript proof but never sourced from the bootstrap file;
//! - `repository_fingerprint` is a canonical
//!   `xtrace_domain::RepositoryFingerprint` and matches the bootstrap
//!   expected value;
//! - the transcript proof verifies against the recovered client
//!   nonce, the canonical zero server-nonce placeholder, and the
//!   wire `manifest_digest`.
//!
//! The validated `client_nonce` is persisted in session state so the
//! outbound `DaemonHello` transcript proof can use the real client
//! nonce rather than the documented inbound-only zero placeholder.
//!
//! The module exposes [`Session`] as the canonical state machine and
//! [`HandshakeInputs`] as the immutable inputs handed to a session at
// construction time.

use std::str::FromStr;

use prost::bytes::Bytes;
use xtrace_domain::ids::Id;
use xtrace_domain::{ContentHash, ProjectId, RepositoryFingerprint, RuntimeSessionId};
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
    /// Bytes exported from the TLS 1.3 connection through rustls's
    /// `ServerConnection::export_keying_material` method.
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
    /// against this value and rejects mismatches deterministically;
    /// the fingerprint arrives out of band through the bootstrap
    /// artifact and is enforced on every inbound `AdapterHello`. The
    /// fingerprint has no relation to the wire `manifest_digest`,
    /// which is supplied by the adapter and authenticated by the
    /// transcript proof.
    pub expected_repository_fingerprint: RepositoryFingerprint,
    /// Health interval sent back to the adapter while the
    /// connection is idle.
    pub health_interval: HealthInterval,
    /// Role marker; only [`HandshakeRole::Daemon`] emits
    /// [`OutgoingCommand::Ack`]s and tracks sequencing.
    pub role: HandshakeRole,
}

/// Negotiation outcome published through the [`AdapterHelloAck`].
/// The minor version is negotiated down to the lesser of the daemon
/// and adapter offers; the major version is taken from the daemon
/// maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedProtocol {
    /// Negotiated major version (always the daemon's offer).
    pub major: u32,
    /// Negotiated minor version (min of daemon and adapter offers).
    pub minor: u32,
}

/// Per-connection state machine.
///
/// `Session` is `Send` but not `Clone`: the supervisor hands the
/// session value to the reader task, which is the only owner. Health,
/// capability staging, and post-hello validation run against the same
/// task; cloning would duplicate the secret-bearing inputs and the
/// negotiated protocol minor.
#[derive(Debug)]
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
    /// `DaemonHello` (rendered via [`ContentHash::to_canonical`]) and
    /// folds the same canonical bytes into the outbound transcript
    /// proof so the adapter can recompute the proof with the same
    /// input. The canonical bytes are derived from the typed value
    /// on demand rather than stored alongside it so the session has
    /// exactly one authoritative manifest representation.
    /// `None` until the daemon has accepted `AdapterHello`.
    adapter_manifest_digest: Option<ContentHash>,
    /// Negotiated protocol version derived from the validated
    /// `AdapterHello`. `None` until the daemon accepts the hello.
    negotiated: Option<NegotiatedProtocol>,
    /// Volatile staging buffer for accepted post-hello envelopes.
    /// Every [`IncomingEnvelope`] the session accepts is appended to
    /// this buffer before the matching [`Ack`] is released so the
    /// [`AckDurability::Staged`] value is honest: the daemon has
    /// actually retained the accepted data, even though it is
    /// process-local and lost on connection close.
    /// Bounded by `STAGED_INCOMING_LIMIT` so a runaway adapter
    /// cannot grow the buffer without bound.
    staged_incoming: std::collections::VecDeque<(u64, IncomingEnvelope)>,
}

/// Maximum number of accepted envelopes retained in the volatile
/// staging buffer. Beyond this bound the session refuses new
/// envelopes with [`ProtocolErrorCode::SessionSequence`] and the
/// supervisor closes the connection, matching the bounded-queue
/// discipline enforced by the architecture-level budgets. Kept
/// private so production callers cannot grow the staging buffer
/// through a public constant; tests inside this module inspect the
/// typed state directly.
const STAGED_INCOMING_LIMIT: usize = 256;

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
            negotiated: None,
            staged_incoming: std::collections::VecDeque::with_capacity(STAGED_INCOMING_LIMIT),
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
        let manifest_digest = ContentHash::from_str(&hello.manifest_digest).map_err(|err| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                format!("manifest_digest is not a canonical ContentHash: {err}"),
            )
        })?;
        // Reject non-canonical wire encodings even when the underlying
        // hex digits parse successfully. `ContentHash::from_str`
        // accepts uppercase A-F because the `hex` crate decodes
        // case-insensitively; without this guard a peer could send
        // `b3:...AAA...` and have the transcript proof computed over
        // the canonical form without ever declaring the encoding it
        // actually used. Canonical validation happens before proof
        // verification so the proof is always computed over exactly
        // the wire string the adapter emitted.
        if hello.manifest_digest != manifest_digest.to_canonical() {
            return Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "manifest_digest must be canonical lowercase b3:<hex>".to_string(),
            ));
        }
        let repository_fingerprint = RepositoryFingerprint::try_from_canonical(
            &hello.repository_fingerprint,
        )
        .map_err(|err| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                format!("repository_fingerprint is not canonical: {err}"),
            )
        })?;
        if repository_fingerprint != self.inputs.expected_repository_fingerprint {
            return Err(SessionError::new(
                ProtocolErrorCode::ProjectIdentity,
                "repository_fingerprint mismatch".to_string(),
            ));
        }
        verify_adapter_hello(
            self.inputs.session_secret.read_secret(),
            &self.inputs.tls_exporter,
            self.inputs.runtime_session_id.as_uuid().as_bytes(),
            hello,
        )
        .map_err(|_| {
            SessionError::new(ProtocolErrorCode::HelloProof, "transcript mismatch".to_string())
        })?;
        self.client_nonce = Some(hello.client_nonce.to_vec());
        let negotiated_minor = hello.protocol_minor_max.min(self.inputs.max_protocol_minor);
        self.adapter_manifest_digest = Some(manifest_digest);
        self.negotiated = Some(NegotiatedProtocol {
            major: self.inputs.max_protocol_major,
            minor: negotiated_minor,
        });
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
        let manifest_digest = self.adapter_manifest_digest.ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "daemon hello requested before AdapterHello was validated".to_string(),
            )
        })?;
        let negotiated = self.negotiated.ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "daemon hello requested before AdapterHello was validated".to_string(),
            )
        })?;
        // The canonical `b3:<hex>` byte sequence is derived from the
        // typed manifest digest so the session holds exactly one
        // authoritative manifest representation; the rendered form
        // here matches the inbound `manifest_digest` field that
        // already passed `ContentHash::from_str` validation.
        let manifest_canonical = manifest_digest.to_canonical();
        let proof = compute_daemon_hello_proof(
            self.inputs.session_secret.read_secret(),
            &self.inputs.tls_exporter,
            self.inputs.runtime_session_id.as_uuid().as_bytes(),
            client_nonce,
            &server_nonce,
            manifest_canonical.as_bytes(),
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
            &manifest_canonical,
            negotiated.major,
            negotiated.minor,
            self.inputs.max_envelope_bytes,
            self.inputs.max_batch_events,
            server_monotonic_ns,
        );
        Ok(AgentEnvelope {
            protocol_major: negotiated.major,
            protocol_minor: negotiated.minor,
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
        let negotiated = self.negotiated.ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::SessionIdentity,
                "post-hello envelope received before AdapterHello".to_string(),
            )
        })?;
        if envelope.protocol_major != negotiated.major || envelope.protocol_minor > negotiated.minor
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
            Some(wire::agent_envelope::Payload::RecordingStarted(started)) => {
                IncomingEnvelope::RecordingStarted(started.clone())
            }
            Some(wire::agent_envelope::Payload::EventBatch(batch)) => {
                IncomingEnvelope::EventBatch(batch.clone())
            }
            Some(wire::agent_envelope::Payload::RecordingFinished(finished)) => {
                IncomingEnvelope::RecordingFinished(finished.clone())
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
        // Volatile staging: the bounded buffer retains every accepted
        // `IncomingEnvelope` so the matching `Ack` honestly reports
        // `AckDurability::Staged`. The limit mirrors the architecture
        // ingest capacity so an adapter that outpaces the daemon
        // surfaces a sequence error instead of growing the buffer.
        if self.staged_incoming.len() >= STAGED_INCOMING_LIMIT {
            return Err(SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "staged ingress capacity exhausted".to_string(),
            ));
        }
        // Compute the next sequence value before mutating either
        // field. An overflow leaves every session field unchanged so
        // the connection cannot accidentally retain a staged envelope
        // that the session then refuses to acknowledge: either the
        // envelope is staged together with the advanced sequence, or
        // neither field moves. `checked_add` is preferred over
        // `saturating_add` because a sequence counter that silently
        // stops advancing would mask a bug as success. The exhaustion
        // is unreachable in practice because the session lifetime is
        // bounded by the configured queue capacity and the admission
        // control.
        let staged_seq = self.next_expected_seq;
        let next_seq = self.next_expected_seq.checked_add(1).ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "session_seq overflow".to_string(),
            )
        })?;
        self.staged_incoming.push_back((staged_seq, incoming.clone()));
        self.next_expected_seq = next_seq;
        let ack = build_ack(next_seq - 1);
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

    /// Returns the negotiated protocol version. `None` until the
    /// daemon accepts the inbound `AdapterHello`.
    #[must_use]
    pub fn negotiated(&self) -> Option<NegotiatedProtocol> {
        self.negotiated
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

fn build_ack(highest_session_seq: u64) -> Ack {
    // Successful acknowledgement carries an empty `rejected` list.
    // A message is rejected when it explicitly violates a stable rule;
    // honest acknowledgement does not stamp the message id with a
    // empty reason code because that is semantically a rejection.
    //
    // `AckDurability::Staged` documents that the acknowledged data is
    // held in connection/session memory (not on durable storage) and
    // is therefore volatile; nothing in this crate ever reports it as
    // committed until a future slice wires the real ingester.
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
    /// avoids string parsing on the supervisor side.
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
    use xtrace_domain::{ProjectId, RuntimeSessionId};
    use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
    use xtrace_protocol::generated::agent::{AdapterHello, Health};

    const CANONICAL_FINGERPRINT: &str =
        "b3:1111111111111111111111111111111111111111111111111111111111111111";
    const CANONICAL_MANIFEST: &str =
        "b3:0000000000000000000000000000000000000000000000000000000000000000";

    fn sample_inputs(secret_bytes: Vec<u8>) -> HandshakeInputs {
        let secret = SessionSecret::from_bytes(&secret_bytes).expect("secret");
        let fingerprint =
            RepositoryFingerprint::try_from_canonical(CANONICAL_FINGERPRINT).expect("fp");
        HandshakeInputs {
            session_secret: secret,
            tls_exporter: b"tls-exporter".to_vec(),
            runtime_session_id: RuntimeSessionId::new(),
            project_id: ProjectId::new(),
            max_envelope_bytes: 1024 * 1024,
            max_batch_events: 256,
            max_protocol_major: 1,
            max_protocol_minor: 0,
            expected_repository_fingerprint: fingerprint,
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
        let client_nonce = [0xaa_u8; 32];
        let proof = xtrace_protocol::handshake::compute_transcript_proof(
            secret,
            &exporter,
            session_id.as_uuid().as_bytes(),
            &client_nonce,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest.as_bytes(),
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
            repository_fingerprint: CANONICAL_FINGERPRINT.to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&client_nonce),
            hmac: Bytes::copy_from_slice(&proof),
        }
    }

    /// Builds a session whose state has accepted the canonical
    /// `AdapterHello`, so post-hello tests exercise the negotiated
    /// protocol version instead of the "received before hello"
    /// branch.
    fn session_after_hello() -> (Session, RuntimeSessionId, Vec<u8>) {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let session_id = session.inputs().runtime_session_id;
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        let envelope = envelope_with_payload(session_id, 0, PayloadOneof::AdapterHello(hello));
        session.accept_adapter_hello(&envelope).expect("hello");
        (session, session_id, secret)
    }

    #[test]
    fn accept_adapter_hello_round_trip() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let ack = session.accept_adapter_hello(&envelope).expect("accept");
        assert_eq!(ack.protocol_major, 1);
        assert_eq!(ack.protocol_minor, 0);
        assert_eq!(ack.max_envelope_bytes, 1024 * 1024);
    }

    #[test]
    fn accept_adapter_hello_rejects_bad_proof() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let hello = AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: CANONICAL_MANIFEST.to_string(),
            language: "rust".to_string(),
            runtime_name: "test".to_string(),
            runtime_version: "0.0.0".to_string(),
            pid: 0,
            process_start_monotonic_ns: 0,
            parent_launch_id: String::new(),
            repository_fingerprint: CANONICAL_FINGERPRINT.to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&[0xaa_u8; 32]),
            hmac: Bytes::copy_from_slice(&[0u8; 32]),
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
    fn accept_adapter_hello_rejects_wrong_client_nonce_length() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let hello = AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: CANONICAL_MANIFEST.to_string(),
            language: "rust".to_string(),
            runtime_name: "test".to_string(),
            runtime_version: "0.0.0".to_string(),
            pid: 0,
            process_start_monotonic_ns: 0,
            parent_launch_id: String::new(),
            repository_fingerprint: CANONICAL_FINGERPRINT.to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&[0xaa_u8; 16]),
            hmac: Bytes::copy_from_slice(&[0u8; 32]),
        };
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn accept_adapter_hello_rejects_non_canonical_fingerprint() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        hello.repository_fingerprint = "wrong-repo".to_string();
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
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        // Build a different canonical fingerprint through
        // `from_canonical_path`; the value still round-trips
        // through `try_from_canonical` so the rejection path is
        // exercised as a project-identity mismatch rather than a
        // parsing failure.
        let alt = RepositoryFingerprint::from_canonical_path("/tmp/other-repo");
        hello.repository_fingerprint = alt.as_str().to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::ProjectIdentity);
    }

    #[test]
    fn accept_adapter_hello_rejects_non_canonical_manifest() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        hello.manifest_digest = "deadbeef".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn accept_adapter_hello_rejects_uppercase_manifest() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        hello.manifest_digest =
            "B3:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn accept_adapter_hello_rejects_non_canonical_lowercase_prefix_uppercase_hex() {
        // Regression: `ContentHash::from_str` accepts uppercase hex
        // digits because the `hex` crate decodes case-insensitively,
        // so a peer sending `b3:<uppercase>` slips past the prefix
        // check and parses to the same digest. The session must
        // refuse the wire encoding before computing the transcript
        // proof so the adapter cannot mint a proof over the canonical
        // bytes and present a non-canonical wire string. The HMAC in
        // this test is computed over the exact non-canonical string
        // so a passing test would actually demonstrate the proof
        // reaching `verify_adapter_hello`; a rejection at the
        // canonical-validation guard proves the new behavior.
        let non_canonical_manifest =
            "b3:00000000000000000000000000000000000000000000000000000000ABCDEF01";
        assert!(
            ContentHash::from_str(non_canonical_manifest).is_ok(),
            "the test premise requires the underlying parser to accept the non-canonical form"
        );

        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let client_nonce = [0xaa_u8; 32];
        let exporter = session.inputs().tls_exporter.clone();
        let session_id_uuid = session.inputs().runtime_session_id.as_uuid();
        let session_id_bytes = session_id_uuid.as_bytes();
        let proof = xtrace_protocol::handshake::compute_transcript_proof(
            &secret,
            &exporter,
            session_id_bytes,
            &client_nonce,
            &xtrace_protocol::handshake::ZERO_NONCE,
            non_canonical_manifest.as_bytes(),
        )
        .expect("HMAC accepts the test secret");
        let hello = AdapterHello {
            adapter_name: "fake".to_string(),
            adapter_version: "0.0.0".to_string(),
            adapter_build_hash: String::new(),
            signing_identity: String::new(),
            manifest_digest: non_canonical_manifest.to_string(),
            language: "rust".to_string(),
            runtime_name: "test".to_string(),
            runtime_version: "0.0.0".to_string(),
            pid: 0,
            process_start_monotonic_ns: 0,
            parent_launch_id: String::new(),
            repository_fingerprint: CANONICAL_FINGERPRINT.to_string(),
            protocol_major_max: 1,
            protocol_minor_max: 0,
            client_nonce: Bytes::copy_from_slice(&client_nonce),
            hmac: Bytes::copy_from_slice(&proof),
        };
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
        assert!(
            err.detail.contains("canonical"),
            "rejection must surface the canonical-form requirement, got: {}",
            err.detail
        );
    }

    #[test]
    fn accept_adapter_hello_rejects_uppercase_fingerprint() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        hello.repository_fingerprint =
            "B3:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }

    #[test]
    fn accept_adapter_hello_rejects_wrong_runtime_session_id() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        let envelope =
            envelope_with_payload(RuntimeSessionId::new(), 0, PayloadOneof::AdapterHello(hello));
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionIdentity);
    }

    #[test]
    fn accept_adapter_hello_rejects_nonzero_session_seq() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
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
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
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
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
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
        assert_eq!(session.negotiated(), Some(NegotiatedProtocol { major: 1, minor: 0 }));
    }

    #[test]
    fn accept_post_hello_rejects_gap_and_replay() {
        let (mut session, session_id, _) = session_after_hello();
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
        let (mut session, _, _) = session_after_hello();
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
        let (mut session, session_id, _) = session_after_hello();
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
        let (mut session, session_id, _) = session_after_hello();
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
        let (mut session, session_id, _) = session_after_hello();
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
        assert_eq!(ack.durability, AckDurability::Staged as i32);
    }

    /// [`AckDurability::Staged`] is only honest when the session has
    /// actually retained the accepted `IncomingEnvelope` in the
    /// volatile staging buffer before the matching `Ack` is released.
    /// The test drives three accepted envelopes and inspects the
    /// private staging buffer directly to prove the data is
    /// process-local and bounded. The pattern match on the
    /// `IncomingEnvelope` variant replaces the removed
    /// `IncomingEnvelope::status` helper so production surface
    /// stays minimal.
    #[test]
    fn staged_incoming_buffer_retains_every_accepted_envelope() {
        let (mut session, session_id, _) = session_after_hello();
        assert!(session.staged_incoming.is_empty());
        for seq in 1..=3u64 {
            let envelope = envelope_with_payload(
                session_id,
                seq,
                PayloadOneof::Health(Health {
                    monotonic_ns: seq,
                    queue_depth_batches: 0,
                    resident_bytes: 0,
                    status: format!("seq-{seq}"),
                }),
            );
            let (_incoming, cmd) = session.accept_post_hello(&envelope).expect("accept");
            match cmd {
                OutgoingCommand::Ack(_) => {}
                other => unreachable!("expected Ack, got {other:?}"),
            }
        }
        assert_eq!(session.staged_incoming.len(), 3, "every accepted envelope must be staged");
        let staged = &session.staged_incoming;
        assert_eq!(staged[0].0, 1);
        assert_eq!(staged[1].0, 2);
        assert_eq!(staged[2].0, 3);
        // The volatile buffer retains the raw payloads so an operator
        // inspecting the process can see what was acknowledged without
        // touching durable storage. A future slice will replace the
        // buffer with a real ingester; today the data is explicitly
        // documented as volatile.
        match &staged.front().unwrap().1 {
            IncomingEnvelope::Health(health) => assert_eq!(health.status, "seq-1"),
            other => unreachable!("expected Health envelope, got {other:?}"),
        }
        match &staged.back().unwrap().1 {
            IncomingEnvelope::Health(health) => assert_eq!(health.status, "seq-3"),
            other => unreachable!("expected Health envelope, got {other:?}"),
        }
    }

    /// `accept_post_hello` must leave every session field unchanged
    /// when the post-validation sequence advancement overflows. A
    /// regression that mutated `staged_incoming` before discovering
    /// the overflow would leave the session holding data it just
    /// refused to acknowledge; this test forces `next_expected_seq`
    /// to `u64::MAX` so the next accepted envelope overflows and
    /// asserts that the staging buffer is still empty and the
    /// counter is still at the saturation point.
    #[test]
    fn accept_post_hello_overflow_leaves_session_state_unchanged() {
        let (mut session, session_id, _) = session_after_hello();
        session.next_expected_seq = u64::MAX;
        let envelope = envelope_with_payload(
            session_id,
            u64::MAX,
            PayloadOneof::Health(Health {
                monotonic_ns: 1,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "overflow-probe".to_string(),
            }),
        );
        let err = session.accept_post_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::SessionSequence);
        assert!(
            err.detail.contains("overflow"),
            "rejection must surface the overflow detail, got: {}",
            err.detail
        );
        assert!(
            session.staged_incoming.is_empty(),
            "staged buffer must be empty after an overflow rejection"
        );
        assert_eq!(
            session.next_expected_seq,
            u64::MAX,
            "sequence counter must not advance past the overflow point"
        );
    }

    #[test]
    fn accept_post_hello_admits_recording_wire_payloads_in_order() {
        // Invariant: every accepted recording payload is staged under
        // its `session_seq` and acknowledged as `Staged`.
        fn admit(
            session: &mut Session,
            session_id: RuntimeSessionId,
            seq: u64,
            payload: PayloadOneof,
        ) -> IncomingEnvelope {
            let envelope = envelope_with_payload(session_id, seq, payload);
            let (incoming, cmd) = session.accept_post_hello(&envelope).expect("admit");
            match cmd {
                OutgoingCommand::Ack(ack) => {
                    assert_eq!(ack.highest_contiguous_session_seq, seq);
                    assert_eq!(ack.durability, AckDurability::Staged as i32);
                    assert!(ack.rejected.is_empty());
                }
                other => unreachable!("expected Ack, got {other:?}"),
            }
            incoming
        }

        let (mut session, session_id, _) = session_after_hello();
        assert!(session.staged_incoming.is_empty());

        let recording_id = Bytes::copy_from_slice(&[0x01; 16]);
        let started_payload = PayloadOneof::RecordingStarted(wire::RecordingStarted {
            recording_id: recording_id.clone(),
            method: "GET".to_string(),
            ..wire::RecordingStarted::default()
        });
        let batch_payload = PayloadOneof::EventBatch(wire::EventBatch {
            recording_id: recording_id.clone(),
            events: vec![wire::RecordingEvent {
                event_id: "ev-1".to_string(),
                recording_seq: 7,
                ..wire::RecordingEvent::default()
            }],
        });
        let finished_payload = PayloadOneof::RecordingFinished(wire::RecordingFinished {
            recording_id,
            final_recording_seq: 7,
            ..wire::RecordingFinished::default()
        });

        let started = admit(&mut session, session_id, 1, started_payload);
        let batch = admit(&mut session, session_id, 2, batch_payload);
        let finished = admit(&mut session, session_id, 3, finished_payload);

        match started {
            IncomingEnvelope::RecordingStarted(s) => assert_eq!(s.method, "GET"),
            other => unreachable!("expected RecordingStarted, got {other:?}"),
        }
        match batch {
            IncomingEnvelope::EventBatch(b) => {
                assert_eq!(b.events.len(), 1);
                assert_eq!(b.events[0].event_id, "ev-1");
                assert_eq!(b.events[0].recording_seq, 7);
            }
            other => unreachable!("expected EventBatch, got {other:?}"),
        }
        match finished {
            IncomingEnvelope::RecordingFinished(f) => assert_eq!(f.final_recording_seq, 7),
            other => unreachable!("expected RecordingFinished, got {other:?}"),
        }

        let staged = &session.staged_incoming;
        assert_eq!(staged.len(), 3);
        assert!(staged.iter().zip(1u64..).all(|((s, _), i)| *s == i));
        assert_eq!(session.next_expected_seq, 4);
    }

    #[test]
    fn accept_post_hello_rejects_unsupported_payload_without_state_mutation() {
        let (mut session, session_id, _) = session_after_hello();
        let before_seq = session.next_expected_seq;
        assert!(session.staged_incoming.is_empty());

        // `EndpointClaimBatch` is a documented wire payload that the
        // session does not yet admit; the rejection must leave every
        // session field untouched.
        let unsupported = envelope_with_payload(
            session_id,
            1,
            PayloadOneof::EndpointClaims(wire::EndpointClaimBatch::default()),
        );
        let err = session.accept_post_hello(&unsupported).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
        assert!(
            err.detail.contains("unsupported payload after hello"),
            "rejection detail must name the unsupported payload, got: {}",
            err.detail,
        );
        assert!(session.staged_incoming.is_empty());
        assert_eq!(session.next_expected_seq, before_seq);

        // A subsequent recording payload at the same sequence is
        // still admissible: the prior rejection must not have
        // burned the sequence slot.
        let started = envelope_with_payload(
            session_id,
            1,
            PayloadOneof::RecordingStarted(wire::RecordingStarted::default()),
        );
        let (_incoming, cmd) = session.accept_post_hello(&started).expect("admit");
        let ack = match cmd {
            OutgoingCommand::Ack(ack) => ack,
            other => unreachable!("expected Ack, got {other:?}"),
        };
        assert_eq!(ack.highest_contiguous_session_seq, 1);
        assert_eq!(ack.durability, AckDurability::Staged as i32);
        assert_eq!(session.staged_incoming.len(), 1);
        assert_eq!(session.next_expected_seq, before_seq + 1);
    }

    #[test]
    fn build_daemon_hello_produces_a_well_formed_envelope() {
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
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
                assert_eq!(hello.protocol_major, 1);
                assert_eq!(hello.protocol_minor, 0);
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
    fn canonical_manifest_digest_is_always_b3_lowercase_hex() {
        let parsed = ContentHash::from_str(CANONICAL_MANIFEST).expect("canonical");
        assert_eq!(parsed.to_canonical(), CANONICAL_MANIFEST);
        assert!(ContentHash::from_str("not-a-digest").is_err());
        assert!(
            ContentHash::from_str(
                "B3:0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
        assert!(
            ContentHash::from_str(
                "b3:000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
    }

    #[test]
    fn session_inputs_validate_fingerprint_canonically() {
        let secret = SessionSecret::from_bytes(&[0xab; 32]).expect("secret");
        // The handshake inputs only accept a fingerprint that round
        // trips through `RepositoryFingerprint::try_from_canonical`;
        // invalid construction must be visible to the caller as a
        // hard error, not a silently-lowercased value.
        let mut inputs = sample_inputs(vec![0xab; 32]);
        // Sanity check: a missing-prefix string cannot be smuggled
        // in; the parser rejects it before length or hex validation.
        let err = RepositoryFingerprint::try_from_canonical("expected-repo").unwrap_err();
        assert!(matches!(err, xtrace_domain::FingerprintParseError::Prefix));
        // The builder must consume the canonical form. Constructing
        // a fingerprint from an uppercase canonical string must
        // fail to round-trip.
        let upper = CANONICAL_FINGERPRINT.replace('1', "I");
        let err = RepositoryFingerprint::try_from_canonical(&upper).unwrap_err();
        assert!(matches!(
            err,
            xtrace_domain::FingerprintParseError::Hex(_)
                | xtrace_domain::FingerprintParseError::NonCanonical
        ));
        // A prefix but wrong length is also rejected.
        let err = RepositoryFingerprint::try_from_canonical("b3:deadbeef").unwrap_err();
        assert!(matches!(err, xtrace_domain::FingerprintParseError::Length));
        // Force a value to ensure `inputs` is consumed below.
        let _ = secret;
        inputs.expected_repository_fingerprint =
            RepositoryFingerprint::try_from_canonical(CANONICAL_FINGERPRINT).expect("fp");
        let mut session = Session::new(inputs);
        let secret_bytes = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret_bytes, CANONICAL_MANIFEST);
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        session.accept_adapter_hello(&envelope).expect("accept");
    }

    #[test]
    fn accept_adapter_hello_rejects_hash_parse_error_as_hello_decode() {
        // The conversion between `HashParseError` and the session
        // error must always land on `HelloDecode`; a custom mapping
        // would risk exposing parser internals through the wire
        // `ProtocolError.code` field.
        let mut session = Session::new(sample_inputs(vec![0xab; 32]));
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let mut hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        hello.manifest_digest = "b3:deadbeef".to_string();
        let envelope = envelope_with_payload(
            session.inputs().runtime_session_id,
            0,
            PayloadOneof::AdapterHello(hello),
        );
        let err = session.accept_adapter_hello(&envelope).unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::HelloDecode);
    }
}
