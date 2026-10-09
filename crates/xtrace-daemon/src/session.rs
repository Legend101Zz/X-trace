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
//! `staged_incoming` queue, and returns [`AckDurability::Staged`]
//! with the canonical recording watermarks the wired
//! [`xtrace_ingest::IngestValidator`] returns. Persistence,
//! `Committed` durability, and terminal recording state remain outside
//! this IO-free session state machine. The daemon supervisor may dispatch
//! an admission to its optional application capture use case before releasing
//! the staged queue front and emitting the same `Staged` ACK.
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

use std::num::NonZeroUsize;
use std::str::FromStr;

use prost::bytes::Bytes;
use uuid::Uuid;
use xtrace_domain::RecordingId;
use xtrace_domain::ids::Id;
use xtrace_domain::{ContentHash, ProjectId, RepositoryFingerprint, RuntimeSessionId};
use xtrace_ingest::{Acceptance, IngestConfig, IngestError, IngestValidator};

// The ingest cap and the application cap are one limit seen from two layers; both derive it
// from the recording's effective capture mode (see `effective_capture_mode`). The test
// `ingest_and_application_caps_agree` guards that they do not drift apart.
// Likewise the drop-priority bucket bound: ingest and application agree.
const _: () = assert!(
    xtrace_ingest::MAX_DROP_PRIORITY_BUCKETS == xtrace_application::MAX_CAPACITY_DROP_PRIORITIES
);
use xtrace_protocol::envelope::check_protocol_version;
use xtrace_protocol::generated::agent as wire;
use xtrace_protocol::generated::agent::{Ack, AckDurability, AgentEnvelope, ProtocolError};

use crate::error::ProtocolErrorCode;
use crate::runtime::{
    AdapterHelloAck, HealthInterval, IncomingEnvelope, OutgoingCommand, PostHelloAdmission,
    build_protocol_error, compute_daemon_hello_proof, verify_adapter_hello,
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
/// capability staging, recording validation, and post-hello
/// validation run against the same task; cloning would duplicate
/// the secret-bearing inputs and the negotiated protocol minor.
///
/// Each [`Session`] owns exactly one [`IngestValidator`] so the
/// post-hello recording payloads from one authenticated connection
/// share a single lifecycle and per-recording event-budget state.
/// Recording IDs accepted by different sessions cannot leak across
/// connections: the validator is private to the session that
/// created it and is dropped on connection close.
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
    /// Bounded by `STAGED_INCOMING_LIMIT` so a runaway adapter
    /// cannot grow the buffer without bound.
    staged_incoming: std::collections::VecDeque<(u64, IncomingEnvelope)>,
    /// Recording validator owned by this session; session-local so
    /// two recordings accepted on different connections cannot leak
    /// into each other's per-recording state. Dropped on connection
    /// close.
    ingest_validator: IngestValidator,
}

/// Upper bound on the volatile staging buffer. Beyond this bound the
/// session refuses new envelopes with [`ProtocolErrorCode::SessionSequence`]
/// and the supervisor closes the connection, matching the
/// bounded-queue discipline enforced by the architecture-level budgets.
/// The same value is also used as the
/// [`xtrace_ingest::IngestConfig::max_active_recordings`] budget:
/// every distinct accepted recording consumes at least one retained
/// `RecordingStarted` envelope, so the staging buffer is the direct
/// upper bound on the number of recordings the validator can track.
const STAGED_INCOMING_LIMIT: usize = 256;

/// Error returned when the staged incoming queue front does not match the
/// envelope whose processing completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StagedReleaseError {
    /// No admitted envelope remains staged.
    #[error("staged incoming queue is empty")]
    Empty,
    /// The queue front belongs to a different session sequence.
    #[error("staged incoming front sequence mismatch: expected {expected}, found {actual}")]
    FrontMismatch {
        /// Session sequence the caller attempted to release.
        expected: u64,
        /// Session sequence currently at the queue front.
        actual: u64,
    },
}

impl Session {
    /// Constructs a fresh session over the supplied inputs. The
    /// `next_expected_seq` starts at 1 per
    /// `03b-protocol-and-api.md` §2.3 ("`session_seq` begins at 1
    /// after authentication"). The owned [`IngestValidator`] is sized
    /// to the staging limit.
    #[must_use]
    pub fn new(inputs: HandshakeInputs) -> Self {
        let active_recordings =
            NonZeroUsize::new(STAGED_INCOMING_LIMIT).unwrap_or(NonZeroUsize::MIN);
        // The audit redactor runs on every accepted event and finish (the event and finish arms
        // of the post-hello handler), so bindings may be accepted.
        let ingest_config = IngestConfig::mode_derived(active_recordings).with_bindings_audit_active();
        Self::new_with_ingest_config(inputs, ingest_config)
    }

    /// Constructs a fresh session with an explicit
    /// [`IngestConfig`]. Module-private helper used by
    /// [`Session::new`] to derive the production validator config
    /// and by nested tests to exercise the
    /// [`IngestError::ActiveCapacityReached`] and
    /// [`IngestError::EventCapacityReached`] boundaries without
    /// reshaping the staging buffer.
    #[must_use]
    fn new_with_ingest_config(inputs: HandshakeInputs, ingest_config: IngestConfig) -> Self {
        Self {
            inputs,
            next_expected_seq: 1,
            server_nonce: None,
            client_nonce: None,
            adapter_manifest_digest: None,
            negotiated: None,
            staged_incoming: std::collections::VecDeque::with_capacity(STAGED_INCOMING_LIMIT),
            ingest_validator: IngestValidator::new(ingest_config),
        }
    }

    /// Returns the underlying [`IngestValidator`] owned by this
    /// session. Test-only: production callers leave the validator
    /// untouched.
    #[must_use]
    #[cfg(test)]
    pub fn ingest_validator(&self) -> &IngestValidator {
        &self.ingest_validator
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

    /// Validates a post-hello inbound envelope and returns the matching
    /// [`PostHelloAdmission`] the supervisor must serialize next.
    ///
    /// Validation is layered so a later failure leaves every session
    /// field untouched: the session preflights the bounded staging
    /// capacity and the `session_seq` overflow guard before reaching
    /// the recording validator, and the validator's rejection paths
    /// are no-mutation on its side (a successful verdict still
    /// advances the per-recording lifecycle inside the validator).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] when the envelope fails any of the
    /// post-hello identity, sequence, framing, or recording
    /// validation checks. Every ingest rejection carries
    /// `code == ProtocolErrorCode::CaptureIngest`; callers
    /// distinguish recoverability from a session-fatal ingest
    /// rejection by inspecting
    /// [`SessionError::ingest_error`] together with
    /// [`xtrace_ingest::IngestError::is_session_fatal`]. Every
    /// non-ingest [`SessionError`] is session-fatal for the
    /// connection: the supervisor must close the socket and must
    /// not emit a `CaptureCommand` to solicit a retry.
    pub fn accept_post_hello(
        &mut self,
        envelope: &AgentEnvelope,
    ) -> Result<PostHelloAdmission, SessionError> {
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
        // Cross-layer preflight: the bounded staging buffer and the
        // monotonic `session_seq` guard are checked before the
        // validator runs so a later validator error cannot leave
        // either field advanced without a matching staged envelope.
        // `checked_add` is preferred over `saturating_add` because a
        // sequence counter that silently stops advancing would mask
        // a bug as success. The exhaustion is unreachable in practice
        // because the session lifetime is bounded by the configured
        // queue capacity and the admission control.
        if self.staged_incoming.len() >= STAGED_INCOMING_LIMIT {
            return Err(SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "staged ingress capacity exhausted".to_string(),
            ));
        }
        let staged_seq = self.next_expected_seq;
        let next_seq = self.next_expected_seq.checked_add(1).ok_or_else(|| {
            SessionError::new(
                ProtocolErrorCode::SessionSequence,
                "session_seq overflow".to_string(),
            )
        })?;

        match &envelope.payload {
            Some(wire::agent_envelope::Payload::CapabilitySet(set)) => {
                let incoming = IncomingEnvelope::CapabilitySet(set.clone());
                Ok(self.admit_simple(incoming, staged_seq, next_seq))
            }
            Some(wire::agent_envelope::Payload::Health(health)) => {
                let incoming = IncomingEnvelope::Health(health.clone());
                Ok(self.admit_simple(incoming, staged_seq, next_seq))
            }
            Some(wire::agent_envelope::Payload::RecordingStarted(started)) => {
                let recording_id = decode_recording_id(&started.recording_id)
                    .map_err(SessionError::with_ingest)?;
                // Captured before `accept_started` so a `StartedRetry`
                // verdict reports the watermark that was already on
                // file.
                let default_watermark = self.ingest_validator.highest_contiguous_seq(recording_id);
                let acceptance = self
                    .ingest_validator
                    .accept_started(
                        started,
                        crate::recording_pipeline::effective_capture_mode(
                            xtrace_domain::CaptureMode::Standard,
                            &started.capture_policy_id,
                        ),
                    )
                    .map_err(SessionError::with_ingest)?;
                let incoming = IncomingEnvelope::RecordingStarted(started.clone());
                Ok(self.admit_recording(
                    recording_id,
                    incoming,
                    acceptance,
                    default_watermark,
                    staged_seq,
                    next_seq,
                ))
            }
            Some(wire::agent_envelope::Payload::EventBatch(batch)) => {
                let recording_id =
                    decode_recording_id(&batch.recording_id).map_err(SessionError::with_ingest)?;
                let acceptance = self
                    .ingest_validator
                    .accept_events(batch)
                    .map_err(SessionError::with_ingest)?;
                // CONTRACTS 9.3: the daemon audit redactor is the second pass over every
                // accepted event, before the batch is translated and encoded into an XTF segment.
                let mut audited = batch.clone();
                for event in &mut audited.events {
                    let _ = xtrace_ingest::redaction_audit::audit_event(event);
                }
                let incoming = IncomingEnvelope::EventBatch(audited);
                Ok(self.admit_recording(
                    recording_id,
                    incoming,
                    acceptance,
                    None,
                    staged_seq,
                    next_seq,
                ))
            }
            Some(wire::agent_envelope::Payload::RecordingFinished(finished)) => {
                let recording_id = decode_recording_id(&finished.recording_id)
                    .map_err(SessionError::with_ingest)?;
                // The just-validated `final_recording_seq` is the
                // authoritative structural watermark for both
                // `Finalizing` and `FinishedRetry`.
                let structural_watermark = finished.final_recording_seq;
                let acceptance = self
                    .ingest_validator
                    .accept_finished(finished)
                    .map_err(SessionError::with_ingest)?;
                let mut audited = finished.clone();
                let _ = xtrace_ingest::redaction_audit::audit_finished(&mut audited);
                let incoming = IncomingEnvelope::RecordingFinished(audited);
                Ok(self.admit_recording(
                    recording_id,
                    incoming,
                    acceptance,
                    Some(structural_watermark),
                    staged_seq,
                    next_seq,
                ))
            }
            Some(wire::agent_envelope::Payload::ProtocolError(err)) => Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                format!("adapter returned ProtocolError: {}", err.message),
            )),
            Some(other) => Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                format!("unsupported payload after hello: {}", payload_kind(other)),
            )),
            None => Err(SessionError::new(
                ProtocolErrorCode::HelloDecode,
                "envelope carried no payload after hello".to_string(),
            )),
        }
    }

    /// Releases exactly the staged queue front for an envelope after its
    /// configured downstream handling succeeds.
    ///
    /// A mismatch or empty queue leaves the session unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`StagedReleaseError::Empty`] when no envelope is staged, or
    /// [`StagedReleaseError::FrontMismatch`] when the front sequence differs
    /// from `expected_session_seq`.
    pub fn release_staged_front(
        &mut self,
        expected_session_seq: u64,
    ) -> Result<(), StagedReleaseError> {
        let Some((actual_session_seq, _)) = self.staged_incoming.front() else {
            return Err(StagedReleaseError::Empty);
        };
        if *actual_session_seq != expected_session_seq {
            return Err(StagedReleaseError::FrontMismatch {
                expected: expected_session_seq,
                actual: *actual_session_seq,
            });
        }
        let Some(_) = self.staged_incoming.pop_front() else {
            return Err(StagedReleaseError::Empty);
        };
        Ok(())
    }

    /// Commits a `CapabilitySet` or `Health` envelope and returns the
    /// matching [`PostHelloAdmission`] with an empty watermark map
    /// because the validator does not examine these variants.
    fn admit_simple(
        &mut self,
        incoming: IncomingEnvelope,
        staged_seq: u64,
        next_seq: u64,
    ) -> PostHelloAdmission {
        self.stage_committed(staged_seq, incoming.clone(), next_seq);
        let ack = build_ack(next_seq - 1, std::collections::HashMap::new());
        PostHelloAdmission { incoming, acceptance: None, command: OutgoingCommand::Ack(ack) }
    }

    /// Commits a recording variant envelope and returns the matching
    /// [`PostHelloAdmission`] with a single-entry watermark map keyed
    /// by the canonical lowercase UUID. See [`recording_watermark`]
    /// for the per-variant seed contract.
    fn admit_recording(
        &mut self,
        recording_id: RecordingId,
        incoming: IncomingEnvelope,
        acceptance: Acceptance,
        watermark: Option<u64>,
        staged_seq: u64,
        next_seq: u64,
    ) -> PostHelloAdmission {
        let watermark = recording_watermark(&acceptance, watermark);
        let mut recording_watermarks = std::collections::HashMap::with_capacity(1);
        recording_watermarks.insert(recording_id.as_string(), watermark);
        self.stage_committed(staged_seq, incoming.clone(), next_seq);
        let ack = build_ack(next_seq - 1, recording_watermarks);
        PostHelloAdmission {
            incoming,
            acceptance: Some(acceptance),
            command: OutgoingCommand::Ack(ack),
        }
    }

    /// Commits the staged envelope and the advanced sequence in one
    /// step. Any validator error causes this helper to be skipped, so
    /// a partially admitted envelope is unreachable.
    fn stage_committed(&mut self, staged_seq: u64, incoming: IncomingEnvelope, next_seq: u64) {
        self.staged_incoming.push_back((staged_seq, incoming));
        self.next_expected_seq = next_seq;
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

fn build_ack(
    highest_session_seq: u64,
    recording_watermarks: std::collections::HashMap<String, u64>,
) -> Ack {
    // Successful acknowledgement carries an empty `rejected` list
    // because a message is only rejected when it explicitly violates
    // a stable rule; honest acknowledgement never stamps an empty
    // reason code on the message id.
    //
    // `AckDurability::Staged` documents that the acknowledged data is
    // held in connection/session memory and is therefore volatile;
    // nothing in this crate ever reports it as committed.
    //
    // `highest_contiguous_recording_seq` carries the canonical
    // lowercase UUID of every accepted recording alongside its
    // current highest contiguous `recording_seq` watermark, or an
    // empty map for non-recording envelopes. Every key is the
    // canonical UUID form rendered from the validated
    // [`xtrace_domain::RecordingId`] rather than from the wire bytes,
    // and every recording ACK carries exactly one entry.
    Ack {
        highest_contiguous_session_seq: highest_session_seq,
        highest_contiguous_recording_seq: recording_watermarks,
        durability: AckDurability::Staged as i32,
        rejected: Vec::new(),
    }
}

/// Failure mode of a session state transition. The supervisor maps
/// the [`ProtocolErrorCode`] to a stable `ProtocolError` envelope and
/// closes the connection (or, for a recoverable ingest rejection,
/// continues the loop so the adapter can retry the same
/// `session_seq`).
#[derive(Debug)]
pub struct SessionError {
    /// Stable wire code. Always an `XTR-DAEMON-*` value except when
    /// the wired `xtrace-ingest` validator rejected the envelope, in
    /// which case it is `XTR-CAPTURE-INGEST`.
    pub code: ProtocolErrorCode,
    /// Human-readable diagnostic that never embeds a captured value,
    /// secret, or peer-supplied identifier. When
    /// [`SessionError::ingest_error`] is `Some`, the diagnostic names
    /// the [`xtrace_ingest::IngestError`] variant rather than any
    /// payload bytes.
    pub detail: String,
    /// Typed [`xtrace_ingest::IngestError`] retained for callers that
    /// need to inspect the underlying reason; always `Some(_)` when
    /// `code == ProtocolErrorCode::CaptureIngest`.
    ingest: Option<IngestError>,
}

impl SessionError {
    /// Builds a session error from a raw `(code, detail)` pair with
    /// no attached ingest reason.
    #[must_use]
    pub const fn new(code: ProtocolErrorCode, detail: String) -> Self {
        Self { code, detail, ingest: None }
    }

    /// Builds a session error that retains the typed
    /// [`xtrace_ingest::IngestError`] returned by the wired validator.
    /// The session-level code is always
    /// [`ProtocolErrorCode::CaptureIngest`].
    #[must_use]
    pub fn with_ingest(err: IngestError) -> Self {
        let detail = format!("ingest rejection: {}", ingest_variant_name(&err));
        Self { code: ProtocolErrorCode::CaptureIngest, detail, ingest: Some(err) }
    }

    /// Returns the typed [`xtrace_ingest::IngestError`] when this
    /// error was produced by the session-bound validator, or `None`
    /// for every other failure mode.
    #[must_use]
    pub fn ingest_error(&self) -> Option<&IngestError> {
        self.ingest.as_ref()
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
        Self { code, detail: format!("{err}"), ingest: None }
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

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ingest.as_ref().map(|err| err as &(dyn std::error::Error + 'static))
    }
}

/// Names the [`xtrace_ingest::IngestError`] variant without leaking
/// any captured value into the operator-facing detail.
fn ingest_variant_name(err: &IngestError) -> &'static str {
    match err {
        IngestError::InvalidStartSeq { .. } => "invalid_start_seq",
        IngestError::UnknownRecording(_) => "unknown_recording",
        IngestError::NonMonotonicBatch { .. } => "non_monotonic_batch",
        IngestError::InvalidRecordingId { .. } => "invalid_recording_id",
        IngestError::ReplayPayloadMismatch { .. } => "replay_payload_mismatch",
        IngestError::RetransmissionNeeded { .. } => "retransmission_needed",
        IngestError::EventAfterFinalization { .. } => "event_after_finalization",
        IngestError::FinishSeqMismatch { .. } => "finish_seq_mismatch",
        IngestError::StartedConflict(_) => "started_conflict",
        IngestError::FinishedConflict(_) => "finished_conflict",
        IngestError::ActiveCapacityReached { .. } => "active_capacity_reached",
        IngestError::EventCapacityReached { .. } => "event_capacity_reached",
        IngestError::BindingsOverBudget { .. } => "bindings_over_budget",
        IngestError::BindingNameTooLong { .. } => "binding_name_too_long",
        IngestError::BindingNameInvalid { .. } => "binding_name_invalid",
        IngestError::BindingPreviewTooLong { .. } => "binding_preview_too_long",
        IngestError::EventValueBytesOverBudget { .. } => "event_value_bytes_over_budget",
        IngestError::ValueMissing { .. } => "value_missing",
        IngestError::LineCursorInvalid { .. } => "line_cursor_invalid",
        IngestError::LineEventNotAllowedInStandardMode { .. } => {
            "line_event_not_allowed_in_standard_mode"
        }
        IngestError::LocalsNotAllowedInStandardMode { .. } => "locals_not_allowed_in_standard_mode",
        IngestError::GapPayloadInvalid { .. } => "gap_payload_invalid",
        IngestError::HashOnRedacted { .. } => "hash_on_redacted",
        IngestError::SourceBindingMismatch { .. } => "source_binding_mismatch",
        IngestError::SourcePathInvalid { .. } => "source_path_invalid",
        IngestError::BindingRoleKindMismatch { .. } => "binding_role_kind_mismatch",
        IngestError::BindingsNotAcceptedYet { .. } => "bindings_not_accepted_yet",
        IngestError::RedactionRuleIdInvalid { .. } => "redaction_rule_id_invalid",
        IngestError::InteractionFieldInvalid { .. } => "interaction_field_invalid",
        IngestError::ContentHashInvalid { .. } => "content_hash_invalid",
        IngestError::SymbolRequired { .. } => "symbol_required",
        IngestError::ExceptionFieldInvalid { .. } => "exception_field_invalid",
        IngestError::RuntimeFactsInvalid { .. } => "runtime_facts_invalid",
        IngestError::UnknownEnumValue { .. } => "unknown_enum_value",
        IngestError::OutcomeInvalid { .. } => "outcome_invalid",
    }
}

/// Decodes a wire `recording_id` byte string into a typed
/// [`RecordingId`]; returns the same
/// [`xtrace_ingest::IngestError::InvalidRecordingId`] the validator
/// would produce for the same input.
fn decode_recording_id(bytes: &[u8]) -> Result<RecordingId, IngestError> {
    if bytes.len() != 16 {
        return Err(IngestError::InvalidRecordingId { got: bytes.len() });
    }
    let uuid = Uuid::from_slice(bytes)
        .map_err(|_| IngestError::InvalidRecordingId { got: bytes.len() })?;
    Ok(RecordingId::from_uuid(uuid))
}

/// Computes the `recording_seq` watermark the session reports on the
/// matching `Ack`. `watermark` is the seed passed in by the caller:
/// the pre-call `highest_contiguous_seq` for `RecordingStarted`, and
/// the just-validated `final_recording_seq` for `RecordingFinished`.
/// `EventBatch` ignores the seed because the verdict carries its own
/// `highest_contiguous`. The `unwrap_or(1)` fallback is defensive
/// and unreachable on the production path: a successful
/// `accept_started` always leaves the validator with a non-`None`
/// entry, and `final_recording_seq` is at least 1 when
/// `accept_finished` returns `Ok`.
fn recording_watermark(acceptance: &Acceptance, watermark: Option<u64>) -> u64 {
    match acceptance {
        Acceptance::Started => 1,
        Acceptance::StartedRetry => watermark.unwrap_or(1),
        Acceptance::Events { highest_contiguous, .. } => *highest_contiguous,
        Acceptance::Finalizing | Acceptance::FinishedRetry => watermark.unwrap_or(1),
    }
}

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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        let admission = session.accept_post_hello(&envelope).expect("accept");
        let ack = match admission.command {
            OutgoingCommand::Ack(ack) => ack,
            other => unreachable!("expected Ack, got {other:?}"),
        };
        assert!(ack.rejected.is_empty());
        assert_eq!(ack.highest_contiguous_session_seq, 1);
        assert_eq!(ack.durability, AckDurability::Staged as i32);
        assert!(admission.acceptance.is_none(), "Health envelopes must not produce a verdict");
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
            let admission = session.accept_post_hello(&envelope).expect("accept");
            match admission.command {
                OutgoingCommand::Ack(_) => {}
                other => unreachable!("expected Ack, got {other:?}"),
            }
            assert!(admission.acceptance.is_none(), "Health envelopes must not produce a verdict");
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
        // its `session_seq`, carries the canonical recording
        // watermark on the matching `Ack`, exposes the typed
        // `Acceptance` verdict, and is acknowledged as `Staged`.
        let (mut session, session_id, _) = session_after_hello();
        let key = canonical_key(0x01);

        let start = session
            .accept_post_hello(&envelope_with_payload(
                session_id,
                1,
                PayloadOneof::RecordingStarted(valid_started(0x01)),
            ))
            .expect("start");
        let batch = session
            .accept_post_hello(&envelope_with_payload(
                session_id,
                2,
                PayloadOneof::EventBatch(batch_with(0x01, vec![event(2, 0xaa)])),
            ))
            .expect("batch");
        let finish = session
            .accept_post_hello(&envelope_with_payload(
                session_id,
                3,
                PayloadOneof::RecordingFinished(finished(0x01, 2)),
            ))
            .expect("finish");

        assert!(matches!(start.acceptance, Some(Acceptance::Started)));
        assert!(matches!(
            batch.acceptance,
            Some(Acceptance::Events { accepted: 1, duplicates: 0, highest_contiguous: 2 })
        ));
        assert!(matches!(finish.acceptance, Some(Acceptance::Finalizing)));

        // Every recording ACK carries exactly one canonical watermark
        // keyed by the lowercase UUID string.
        let expected = [(&start, 1u64), (&batch, 2), (&finish, 2)];
        for (admission, watermark) in expected {
            let map = watermarks(admission);
            assert_eq!(map.len(), 1, "exactly one recording watermark per ACK");
            assert_eq!(map.get(&key), Some(&watermark));
            assert!(map.keys().all(|k| k == &key));
        }

        assert_eq!(session.next_expected_seq, 4);
        assert_eq!(session.staged_incoming.len(), 3);
    }

    #[test]
    fn staged_release_requires_exact_front_and_errors_do_not_mutate_queue() {
        let (mut session, sid, _) = session_after_hello();
        drive(&mut session, sid, 1, PayloadOneof::CapabilitySet(wire::CapabilitySet::default()));
        drive(&mut session, sid, 2, PayloadOneof::Health(wire::Health::default()));
        assert_eq!(session.staged_incoming.len(), 2);

        assert_eq!(
            session.release_staged_front(2),
            Err(StagedReleaseError::FrontMismatch { expected: 2, actual: 1 }),
        );
        assert_eq!(session.staged_incoming.len(), 2);
        assert_eq!(session.staged_incoming.front().map(|entry| entry.0), Some(1));

        session.release_staged_front(1).expect("release exact front");
        assert_eq!(session.staged_incoming.len(), 1);
        assert_eq!(
            session.release_staged_front(1),
            Err(StagedReleaseError::FrontMismatch { expected: 1, actual: 2 }),
        );
        assert_eq!(session.staged_incoming.len(), 1);
        session.release_staged_front(2).expect("release next exact front");
        assert_eq!(session.release_staged_front(3), Err(StagedReleaseError::Empty));
        assert!(session.staged_incoming.is_empty());
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

        // A subsequent recording payload at the same sequence is still
        // admissible: the prior rejection must not have burned the
        // sequence slot. The fixture uses the minimum valid
        // recording start so the wired validator accepts it.
        let recording_id = Bytes::copy_from_slice(&[0x01; 16]);
        let started = envelope_with_payload(
            session_id,
            1,
            PayloadOneof::RecordingStarted(wire::RecordingStarted {
                recording_id: recording_id.clone(),
                recording_seq: 1,
                ..wire::RecordingStarted::default()
            }),
        );
        let admission = session.accept_post_hello(&started).expect("admit");
        let ack = match admission.command {
            OutgoingCommand::Ack(ack) => ack,
            other => unreachable!("expected Ack, got {other:?}"),
        };
        assert_eq!(ack.highest_contiguous_session_seq, 1);
        assert_eq!(ack.durability, AckDurability::Staged as i32);
        assert!(ack.rejected.is_empty());
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

    // Helpers shared by the new ingest integration cases.
    fn rid_bytes(seed: u8) -> Bytes {
        Bytes::copy_from_slice(&[seed; 16])
    }

    fn valid_started(seed: u8) -> wire::RecordingStarted {
        wire::RecordingStarted {
            recording_id: rid_bytes(seed),
            recording_seq: 1,
            method: "GET".to_string(),
            ..wire::RecordingStarted::default()
        }
    }

    fn event(seq: u64, body: u8) -> wire::RecordingEvent {
        wire::RecordingEvent {
            event_id: format!("ev-{body}"),
            recording_seq: seq,
            ..wire::RecordingEvent::default()
        }
    }

    #[test]
    #[allow(clippy::panic, reason = "test asserts the staged payload kind")]
    fn audit_redactor_downgrades_secret_values_before_they_are_staged() {
        // CONTRACTS 9.3 / review A-01: the audit runs on every accepted event, so a value under a
        // secret-looking name never reaches the translator as a captured preview.
        let (mut session, session_id, _) = session_after_hello();
        session
            .accept_post_hello(&envelope_with_payload(
                session_id,
                1,
                PayloadOneof::RecordingStarted(valid_started(0x01)),
            ))
            .expect("start");
        let preview = "hunter2-canary";
        let mut secret_event = event(2, 0xaa);
        secret_event.kind = wire::RecordingEventKind::FrameEnter as i32;
        secret_event.bindings = vec![wire::ValueBinding {
            name: "password".to_owned(),
            role: wire::BindingRole::Argument as i32,
            name_origin: wire::NameOrigin::Declared as i32,
            value: Some(wire::CapturedValue {
                value: Some(wire::captured_value::Value::Captured(wire::CapturedValueCaptured {
                    shape: wire::ValueShape::String as i32,
                    preview: preview.to_owned(),
                    content_hash: blake3::hash(preview.as_bytes()).as_bytes().to_vec().into(),
                })),
            }),
        }];
        session
            .accept_post_hello(&envelope_with_payload(
                session_id,
                2,
                PayloadOneof::EventBatch(batch_with(0x01, vec![secret_event])),
            ))
            .expect("batch is accepted, then audited");
        let staged = match session.staged_incoming.back() {
            Some((_, IncomingEnvelope::EventBatch(batch))) => batch.clone(),
            other => panic!("expected a staged event batch, got {other:?}"),
        };
        let value = staged.events[0].bindings[0].value.as_ref().and_then(|v| v.value.as_ref());
        assert!(
            matches!(value, Some(wire::captured_value::Value::Redacted(_))),
            "secret-named binding must be downgraded to Redacted, got {value:?}"
        );
        assert!(!format!("{staged:?}").contains(preview), "the canary preview must not be staged");
    }

    fn batch_with(seed: u8, events: Vec<wire::RecordingEvent>) -> wire::EventBatch {
        wire::EventBatch { recording_id: rid_bytes(seed), events }
    }

    fn finished(seed: u8, final_seq: u64) -> wire::RecordingFinished {
        wire::RecordingFinished {
            recording_id: rid_bytes(seed),
            final_recording_seq: final_seq,
            ..wire::RecordingFinished::default()
        }
    }

    fn canonical_key(seed: u8) -> String {
        xtrace_domain::RecordingId::from_uuid(uuid::Uuid::from_bytes([seed; 16])).as_string()
    }

    fn watermarks(admission: &PostHelloAdmission) -> &std::collections::HashMap<String, u64> {
        match &admission.command {
            OutgoingCommand::Ack(ack) => &ack.highest_contiguous_recording_seq,
            other => unreachable!("expected Ack, got {other:?}"),
        }
    }

    fn drive(session: &mut Session, sid: RuntimeSessionId, seq: u64, payload: PayloadOneof) {
        let envelope = envelope_with_payload(sid, seq, payload);
        session.accept_post_hello(&envelope).expect("drive must admit");
    }

    #[test]
    fn accept_post_hello_interleaves_two_recording_ids_independently() {
        let (mut session, sid, _) = session_after_hello();
        let key_a = canonical_key(0xa1);
        let key_b = canonical_key(0xb2);

        let timeline = [
            (1u64, PayloadOneof::RecordingStarted(valid_started(0xa1)), key_a.clone(), 1u64),
            (2, PayloadOneof::RecordingStarted(valid_started(0xb2)), key_b.clone(), 1),
            (3, PayloadOneof::EventBatch(batch_with(0xa1, vec![event(2, 0x01)])), key_a.clone(), 2),
            (4, PayloadOneof::EventBatch(batch_with(0xb2, vec![event(2, 0x02)])), key_b.clone(), 2),
            (5, PayloadOneof::EventBatch(batch_with(0xa1, vec![event(3, 0x03)])), key_a.clone(), 3),
            (6, PayloadOneof::RecordingFinished(finished(0xb2, 2)), key_b, 2),
            (7, PayloadOneof::RecordingFinished(finished(0xa1, 3)), key_a, 3),
        ];

        let mut previous = 0u64;
        for (seq, payload, key, expected_watermark) in timeline {
            let envelope = envelope_with_payload(sid, seq, payload);
            let a = session.accept_post_hello(&envelope).expect("admit");
            assert_eq!(seq, previous + 1);
            previous = seq;
            let map = watermarks(&a);
            assert_eq!(map.len(), 1);
            assert_eq!(map.get(&key), Some(&expected_watermark));
        }

        assert_eq!(session.next_expected_seq, 8);
        assert_eq!(session.ingest_validator().len(), 2);
    }

    #[test]
    fn accept_post_hello_recording_retries_do_not_burn_watermark() {
        let (mut session, sid, _) = session_after_hello();
        let key = canonical_key(0xc3);

        for (seq, payload) in [
            (1u64, PayloadOneof::RecordingStarted(valid_started(0xc3))),
            (2, PayloadOneof::EventBatch(batch_with(0xc3, vec![event(2, 0xaa), event(3, 0xab)]))),
            (3, PayloadOneof::RecordingFinished(finished(0xc3, 3))),
        ] {
            drive(&mut session, sid, seq, payload);
        }

        let start = session
            .accept_post_hello(&envelope_with_payload(
                sid,
                4,
                PayloadOneof::RecordingStarted(valid_started(0xc3)),
            ))
            .expect("retry start");
        assert!(matches!(start.acceptance, Some(Acceptance::StartedRetry)));
        assert_eq!(watermarks(&start).get(&key), Some(&3));

        let batch = session
            .accept_post_hello(&envelope_with_payload(
                sid,
                5,
                PayloadOneof::EventBatch(batch_with(0xc3, vec![event(2, 0xaa), event(3, 0xab)])),
            ))
            .expect("retry batch");
        assert!(matches!(
            batch.acceptance,
            Some(Acceptance::Events { accepted: 0, duplicates: 2, highest_contiguous: 3 })
        ));
        assert_eq!(watermarks(&batch).get(&key), Some(&3));

        let finish = session
            .accept_post_hello(&envelope_with_payload(
                sid,
                6,
                PayloadOneof::RecordingFinished(finished(0xc3, 3)),
            ))
            .expect("retry finish");
        assert!(matches!(finish.acceptance, Some(Acceptance::FinishedRetry)));
        assert_eq!(watermarks(&finish).get(&key), Some(&3));

        assert_eq!(session.next_expected_seq, 7);
    }

    /// Compact rejection table: every representative cross-layer
    /// failure surfaces `XTR-CAPTURE-INGEST`, leaves the typed cause
    /// inspectable through `ingest_error()`, preserves the staging
    /// buffer and sequence counter, and accepts a corrected envelope
    /// at the same `session_seq`. Exhaustive variant coverage lives in
    /// `xtrace-ingest`; this test only proves the cross-layer
    /// projection.
    #[test]
    fn accept_post_hello_recording_rejections_preserve_session_state() {
        struct Case {
            name: &'static str,
            setup: Vec<PayloadOneof>,
            rejected: PayloadOneof,
            assert: fn(&IngestError),
        }
        let cases = [
            Case {
                name: "malformed_id",
                setup: Vec::new(),
                rejected: PayloadOneof::RecordingStarted(wire::RecordingStarted {
                    recording_id: Bytes::copy_from_slice(&[0xab; 15]),
                    recording_seq: 1,
                    method: "GET".to_string(),
                    ..wire::RecordingStarted::default()
                }),
                assert: |err| assert!(matches!(err, IngestError::InvalidRecordingId { got: 15 })),
            },
            Case {
                name: "recoverable_gap",
                setup: vec![PayloadOneof::RecordingStarted(valid_started(0x01))],
                rejected: PayloadOneof::EventBatch(batch_with(0x01, vec![event(4, 0xaa)])),
                assert: |err| assert!(matches!(err, IngestError::RetransmissionNeeded { .. })),
            },
            Case {
                name: "fatal_changed_replay",
                setup: vec![
                    PayloadOneof::RecordingStarted(valid_started(0x01)),
                    PayloadOneof::EventBatch(batch_with(0x01, vec![event(2, 0xaa)])),
                ],
                rejected: PayloadOneof::EventBatch(batch_with(0x01, vec![event(2, 0xff)])),
                assert: |err| assert!(matches!(err, IngestError::ReplayPayloadMismatch { .. })),
            },
            Case {
                name: "finish_mismatch",
                setup: vec![PayloadOneof::RecordingStarted(valid_started(0x01))],
                rejected: PayloadOneof::RecordingFinished(finished(0x01, 99)),
                assert: |err| assert!(matches!(err, IngestError::FinishSeqMismatch { .. })),
            },
            Case {
                name: "event_after_finalization",
                setup: vec![
                    PayloadOneof::RecordingStarted(valid_started(0x01)),
                    PayloadOneof::EventBatch(batch_with(0x01, vec![event(2, 0xaa)])),
                    PayloadOneof::RecordingFinished(finished(0x01, 2)),
                ],
                rejected: PayloadOneof::EventBatch(batch_with(0x01, vec![event(3, 0xab)])),
                assert: |err| assert!(matches!(err, IngestError::EventAfterFinalization { .. })),
            },
        ];

        for case in &cases {
            let Case { name, setup, rejected, assert } = case;
            let mut session = session_after_hello().0;
            let sid = session.inputs().runtime_session_id;
            for setup_payload in setup {
                let seq = session.next_expected_seq;
                session
                    .accept_post_hello(&envelope_with_payload(sid, seq, setup_payload.clone()))
                    .expect("setup");
            }
            let before_seq = session.next_expected_seq;
            let before_staged = session.staged_incoming.len();
            let err = session
                .accept_post_hello(&envelope_with_payload(sid, before_seq, rejected.clone()))
                .unwrap_err();

            assert_eq!(err.code, ProtocolErrorCode::CaptureIngest, "case {name}: code");
            assert!(err.detail.starts_with("ingest rejection: "));
            assert!(!err.detail.contains("GET") && !err.detail.contains("ev-"));
            assert(err.ingest_error().expect("typed ingest retained"));
            assert!(std::error::Error::source(&err).is_some());
            assert_eq!(session.next_expected_seq, before_seq);
            assert_eq!(session.staged_incoming.len(), before_staged);

            // A corrected envelope at the same session_seq succeeds, proving the
            // slot was not burned.
            let a = session
                .accept_post_hello(&envelope_with_payload(
                    sid,
                    before_seq,
                    PayloadOneof::RecordingStarted(valid_started(0x01)),
                ))
                .expect("corrected");
            assert!(watermarks(&a).contains_key(&canonical_key(0x01)));
            assert_eq!(session.next_expected_seq, before_seq + 1);
        }
    }

    #[test]
    fn accept_post_hello_capacity_rejections_leave_session_untouched() {
        // Active capacity reached: a second start is rejected without
        // disturbing the first recording.
        let mut session = session_with_ingest(IngestConfig::new(NonZeroUsize::new(1).unwrap()));
        let sid = session.inputs().runtime_session_id;
        drive(&mut session, sid, 1, PayloadOneof::RecordingStarted(valid_started(0x01)));
        let err = session
            .accept_post_hello(&envelope_with_payload(
                sid,
                2,
                PayloadOneof::RecordingStarted(valid_started(0x02)),
            ))
            .unwrap_err();
        assert_eq!(err.code, ProtocolErrorCode::CaptureIngest);
        assert!(matches!(err.ingest_error(), Some(IngestError::ActiveCapacityReached { .. })));
        assert_eq!(session.next_expected_seq, 2);
        assert_eq!(session.staged_incoming.len(), 1);

        // Event capacity (owner-ordered F5 contract change): a single-event
        // budget no longer refuses the next contiguous event. The session
        // admits it, advances the watermark, and the validator counts the
        // drop by the event's own priority without retaining its digest.
        let mut session = session_with_ingest(
            IngestConfig::new(NonZeroUsize::new(8).unwrap())
                .with_limit(NonZeroUsize::new(1).unwrap()),
        );
        let sid = session.inputs().runtime_session_id;
        drive(&mut session, sid, 1, PayloadOneof::RecordingStarted(valid_started(0x01)));
        drive(
            &mut session,
            sid,
            2,
            PayloadOneof::EventBatch(batch_with(0x01, vec![event(2, 0xaa)])),
        );
        let over = wire::RecordingEvent { priority: 40, ..event(3, 0xab) };
        let admission = session
            .accept_post_hello(&envelope_with_payload(
                sid,
                3,
                PayloadOneof::EventBatch(batch_with(0x01, vec![over])),
            ))
            .expect("event over the cap is admitted and counted");
        assert!(matches!(
            admission.acceptance,
            Some(Acceptance::Events { accepted: 0, duplicates: 0, highest_contiguous: 3 })
        ));
        let recording_id = decode_recording_id(&rid_bytes(0x01)).unwrap();
        let drops = session.ingest_validator().capacity_drops(recording_id).unwrap();
        assert_eq!(drops.get(&40), Some(&1));
        assert_eq!(session.next_expected_seq, 4);

        // The finish carries the high-water mark, gap included.
        let finish = session
            .accept_post_hello(&envelope_with_payload(
                sid,
                4,
                PayloadOneof::RecordingFinished(finished(0x01, 3)),
            ))
            .expect("finish accepts the capacity gap");
        assert!(matches!(finish.acceptance, Some(Acceptance::Finalizing)));

        // Default `Session::new` sizes `max_active_recordings` to the
        // staging limit (every recording consumes at least one
        // `RecordingStarted` envelope).
        let session = Session::new(sample_inputs(vec![0xab; 32]));
        assert_eq!(
            session.ingest_validator().config().max_active_recordings.get(),
            STAGED_INCOMING_LIMIT,
        );
    }

    fn session_with_ingest(ingest_config: IngestConfig) -> Session {
        let mut inputs = sample_inputs(vec![0xab; 32]);
        inputs.session_secret = SessionSecret::from_bytes(&[0xab; 32]).expect("secret");
        let mut session = Session::new_with_ingest_config(inputs, ingest_config);
        let sid = session.inputs().runtime_session_id;
        let secret = session.inputs().session_secret.read_secret().to_vec();
        let hello = sample_adapter_hello(&session, &secret, CANONICAL_MANIFEST);
        session
            .accept_adapter_hello(&envelope_with_payload(sid, 0, PayloadOneof::AdapterHello(hello)))
            .expect("hello");
        session
    }

    #[test]
    fn session_error_with_ingest_maps_to_xtr_capture_ingest() {
        let err = SessionError::with_ingest(IngestError::InvalidStartSeq {
            recording_id: xtrace_domain::RecordingId::from_uuid(uuid::Uuid::from_bytes([0x42; 16])),
            got: 9,
        });
        assert_eq!(err.code.as_str(), "XTR-CAPTURE-INGEST");
        assert!(err.detail.contains("invalid_start_seq"));
        assert!(
            !err.detail.contains("42"),
            "detail must not embed recording bytes: {:?}",
            err.detail
        );
        let ingest = err.ingest_error().expect("typed ingest retained");
        assert!(matches!(ingest, IngestError::InvalidStartSeq { got: 9, .. }));
        let wire = err.to_protocol_error();
        assert_eq!(wire.code, "XTR-CAPTURE-INGEST");
        assert!(std::error::Error::source(&err).is_some());

        let plain = SessionError::new(ProtocolErrorCode::SessionSequence, "gap".to_string());
        assert!(plain.ingest_error().is_none());
        assert!(std::error::Error::source(&plain).is_none());
    }
}
