//! Daemon builder and run loop.
//!
//! The builder pattern keeps the configuration flow explicit: callers
//! set the project / session identifiers and (optionally) the
//! bootstrap artifact path, then call [`DaemonBuilder::bind`] which
//! allocates the listener, certificate, secret, and TLS materials.
//! The returned [`BoundDaemon`] owns the listener and exposes a
//! [`BoundDaemon::serve`] future that completes on shutdown.
//!
//! The run loop supervises one [`tokio::task`] per connection. Every
//! task is awaited before the run future returns so an orderly
//! shutdown is provably complete.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use rustls::server::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use xtrace_domain::ids::Id;
use xtrace_domain::{ProjectId, RuntimeSessionId};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{AgentEnvelope, ProtocolError};

use crate::bootstrap::{BootstrapArtifact, BootstrapArtifactFields, BootstrapOwner};
use crate::config::DaemonConfig;
use crate::error::DaemonError;
use crate::framing::{EnvelopeAsyncDecoder, EnvelopeAsyncEncoder};
use crate::listener::LoopbackListener;
use crate::runtime::HealthInterval;
use crate::secret::SessionSecret;
use crate::session::{HandshakeInputs, HandshakeRole, Session};
use crate::tls::{EphemeralCertificate, TlsServerMaterials};

/// Length in bytes of the TLS exporter keying material the daemon
/// requests from rustls after the handshake completes. The value
/// matches the XTP-Agent transcript proof tag size so the entire
/// exporter can be folded into the HMAC without truncation.
pub const TLS_EXPORTER_LEN: usize = 32;
/// Stable exporter label used on both sides of the handshake. The
/// label is encoded into the rustls `export_keying_material` call so
/// the same context cannot be replayed across different protocol
/// versions or unrelated X-trace subsystems.
pub const TLS_EXPORTER_LABEL: &[u8] = b"xtrace-adapter-transport-v1";
/// Constant channel capacity for per-connection commands. Matches the
/// `adapter socket decode` row of `docs/plans/x-trace/02-architecture.md`
/// §6 so a slow consumer triggers TCP/TLS backpressure.
const CONNECTION_COMMAND_CAPACITY: usize = 64;

/// Bound daemon state: a loopback listener, TLS materials, and the
/// freshly minted session secret. The struct is the input to
/// [`BoundDaemon::serve`].
pub struct BoundDaemon {
    config: DaemonConfig,
    listener: LoopbackListener,
    tls_materials: TlsServerMaterials,
    session_secret: SessionSecret,
    runtime_session_id: RuntimeSessionId,
    project_id: ProjectId,
    /// Optional bootstrap artifact guard. `Some` when the daemon owns
    /// the file; `None` when the caller has read it themselves.
    bootstrap: Option<BootstrapArtifact>,
}

impl BoundDaemon {
    /// Returns the local address the daemon is bound to.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr()
    }

    /// Returns the ephemeral certificate. Tests use it to seed the
    /// fake adapter's pin verifier.
    #[must_use]
    pub fn certificate(&self) -> &EphemeralCertificate {
        &self.tls_materials.certificate
    }

    /// Returns the session secret. Only used by tests that drive the
    /// handshake directly.
    #[must_use]
    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    /// Returns the runtime session identifier.
    #[must_use]
    pub fn runtime_session_id(&self) -> RuntimeSessionId {
        self.runtime_session_id
    }

    /// Returns the project identifier.
    #[must_use]
    pub fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Runs the daemon supervisor until the supplied shutdown future
    /// resolves. Every connection is awaited before the future
    /// returns so an orderly shutdown is observable from the caller.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Join`] when a connection task panics or
    /// is cancelled. Returns [`DaemonError::BindFailed`] when the
    /// supervisor fails to accept the next connection.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), DaemonError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let config = self.config;
        let listener = self.listener;
        let tls_materials = self.tls_materials;
        let session_secret = self.session_secret;
        let runtime_session_id = self.runtime_session_id;
        let project_id = self.project_id;
        let _bootstrap = self.bootstrap;

        let supervisor = SupervisorContext {
            config,
            tls_config: tls_materials.server_config.clone(),
            certificate_summary: tls_materials.certificate_summary.clone(),
            session_secret,
            runtime_session_id,
            project_id,
        };

        let mut tasks: Vec<JoinHandle<Result<(), DaemonError>>> = Vec::new();
        let shutdown_signal = Arc::new(tokio::sync::Notify::new());
        let signal_clone = shutdown_signal.clone();
        let shutdown_task: JoinHandle<()> = tokio::spawn(async move {
            shutdown.await;
            signal_clone.notify_waiters();
        });

        loop {
            tokio::select! {
                biased;
                _ = shutdown_signal.notified() => {
                    debug!("daemon supervisor received shutdown signal");
                    break;
                }
                accept_result = listener.accept() => {
                    let (stream, peer) = match accept_result {
                        Ok(pair) => pair,
                        Err(err) => {
                            warn!(error = %err, "listener accept failed");
                            if tasks.is_empty() {
                                return Err(err);
                            }
                            return join_tasks(tasks).await.and(Err(err));
                        }
                    };
                    debug!(peer = %peer, "daemon accepted new connection");
                    let ctx = supervisor.clone();
                    let task = tokio::spawn(async move { handle_connection(ctx, stream).await });
                    tasks.push(task);
                }
            }
        }

        shutdown_task.abort();
        let _ = shutdown_task.await;
        join_tasks(tasks).await
    }
}

/// Builder for [`BoundDaemon`].
#[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
pub struct DaemonBuilder {
    config: DaemonConfig,
    project_id: Option<ProjectId>,
    runtime_session_id: Option<RuntimeSessionId>,
    bootstrap_artifact: Option<PathBuf>,
}

impl DaemonBuilder {
    /// Constructs a new builder with the supplied configuration.
    pub fn new(config: DaemonConfig) -> Self {
        Self { config, project_id: None, runtime_session_id: None, bootstrap_artifact: None }
    }

    /// Sets the project identifier the daemon will require on every
    /// post-hello envelope. Required.
    #[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
    pub fn with_project_id(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    /// Sets the runtime session identifier the daemon will require on
    /// every post-hello envelope. Required.
    #[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
    pub fn with_runtime_session_id(mut self, session_id: RuntimeSessionId) -> Self {
        self.runtime_session_id = Some(session_id);
        self
    }

    /// Sets the optional bootstrap artifact path. When set, the
    /// daemon writes the artifact with owner-only permissions before
    /// serving and removes it on orderly shutdown.
    #[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
    pub fn with_bootstrap_artifact(mut self, path: PathBuf) -> Self {
        self.bootstrap_artifact = Some(path);
        self
    }

    /// Binds the loopback listener, generates the ephemeral
    /// certificate, and writes the bootstrap artifact. Returns a
    /// [`BoundDaemon`] ready to serve.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::InvalidConfig`] when the project or
    /// runtime session identifier has not been supplied,
    /// [`DaemonError::Bootstrap`] when the artifact cannot be
    /// written, and [`DaemonError::BindFailed`] when the OS refuses
    /// the loopback bind.
    pub async fn bind(self) -> Result<BoundDaemon, DaemonError> {
        let project_id = self
            .project_id
            .ok_or_else(|| DaemonError::InvalidConfig("project_id is required".to_string()))?;
        let runtime_session_id = self.runtime_session_id.ok_or_else(|| {
            DaemonError::InvalidConfig("runtime_session_id is required".to_string())
        })?;
        let listener = LoopbackListener::bind(self.config.loopback_policy).await?;
        let certificate = EphemeralCertificate::generate()?;
        let tls_materials = TlsServerMaterials::build(certificate)?;
        let session_secret = SessionSecret::generate()
            .map_err(|err| DaemonError::Bootstrap(format!("session secret: {err}")))?;
        let bootstrap = self
            .bootstrap_artifact
            .as_ref()
            .map(|path| {
                let fields = BootstrapArtifactFields::new(
                    listener.local_addr().ip().to_string(),
                    listener.local_addr().port(),
                    tls_materials.certificate.pin().to_string(),
                    runtime_session_id,
                    &session_secret,
                    project_id,
                    1,
                    0,
                );
                BootstrapArtifact::write(path, fields, BootstrapOwner::Daemon)
            })
            .transpose()?;
        info!(
            address = %listener.local_addr(),
            project_id = %project_id,
            runtime_session_id = %runtime_session_id,
            "xtrace daemon bound to loopback",
        );
        Ok(BoundDaemon {
            config: self.config,
            listener,
            tls_materials,
            session_secret,
            runtime_session_id,
            project_id,
            bootstrap,
        })
    }
}

#[derive(Clone)]
struct SupervisorContext {
    /// Daemon-wide tunables shared with every per-connection task.
    /// Some fields (like `channel_capacity`) are not yet read by the
    /// supervisor; the dead-code allow documents the deliberate
    /// carry rather than the future-proof field drop.
    #[allow(dead_code, reason = "carried for future supervisor tunables")]
    config: DaemonConfig,
    tls_config: Arc<ServerConfig>,
    certificate_summary: String,
    session_secret: SessionSecret,
    runtime_session_id: RuntimeSessionId,
    project_id: ProjectId,
}

async fn handle_connection(ctx: SupervisorContext, stream: TcpStream) -> Result<(), DaemonError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(ctx.tls_config.clone());
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => stream,
        Err(err) => {
            debug!(error = %err, "tls handshake failed");
            return Ok(());
        }
    };
    let tls_exporter = match extract_tls_exporter(&tls_stream) {
        Ok(bytes) => bytes,
        Err(err) => {
            debug!(error = %err, "tls exporter extraction failed");
            return Ok(());
        }
    };
    let (reader, writer) = tokio::io::split(tls_stream);
    let mut session = Session::new(HandshakeInputs {
        session_secret: ctx.session_secret,
        tls_exporter,
        runtime_session_id: ctx.runtime_session_id,
        project_id: ctx.project_id,
        max_envelope_bytes: ctx.config.max_envelope_bytes,
        max_batch_events: ctx.config.max_batch_events,
        max_protocol_major: 1,
        max_protocol_minor: 0,
        manifest_digest: ctx.certificate_summary.clone(),
        health_interval: HealthInterval(ctx.config.health_interval),
        role: HandshakeRole::Daemon,
    });
    let mut decoder = EnvelopeAsyncDecoder::new(reader, session.max_envelope_bytes());
    let mut encoder = EnvelopeAsyncEncoder::new(writer, session.max_envelope_bytes());

    let first = match decoder.read_envelope().await {
        Ok(envelope) => envelope,
        Err(err) => {
            return send_protocol_error(
                &session,
                &mut encoder,
                &ProtocolError {
                    code: crate::error::ProtocolErrorCode::Transport.as_str().to_string(),
                    message: format!("{err}"),
                },
            )
            .await;
        }
    };

    if let Err(err) = session.accept_adapter_hello(&first) {
        return send_protocol_error(&session, &mut encoder, &err.to_protocol_error()).await;
    }

    let server_nonce = random_server_nonce();
    let envelope = match session.build_daemon_hello(server_nonce, current_monotonic_ns()) {
        Ok(envelope) => envelope,
        Err(err) => {
            return send_protocol_error(&session, &mut encoder, &err.to_protocol_error()).await;
        }
    };
    if let Err(err) = encoder.write_envelope(&envelope).await {
        return Err(DaemonError::Transport(format!("write daemon hello: {err}")));
    }

    let (tx, mut rx) =
        mpsc::channel::<crate::runtime::OutgoingCommand>(CONNECTION_COMMAND_CAPACITY);
    let health_session = session.clone();
    let health_tx = tx.clone();
    let health_task: JoinHandle<()> = tokio::spawn(async move {
        let interval = health_session.health_interval().0.max(Duration::from_secs(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now_ns = current_monotonic_ns();
            let cmd = health_session.next_health(now_ns);
            if health_tx.send(cmd).await.is_err() {
                break;
            }
        }
    });

    let mut outbound_seq: u64 = 1;
    let post_hello_result: Result<(), crate::session::SessionError> = async {
        loop {
            tokio::select! {
                biased;
                incoming = decoder.read_envelope() => {
                    let envelope = incoming.map_err(|err| {
                        let code = match err.kind() {
                            std::io::ErrorKind::UnexpectedEof => crate::error::ProtocolErrorCode::Shutdown,
                            _ => crate::error::ProtocolErrorCode::Transport,
                        };
                        crate::session::SessionError::new(code, format!("read envelope: {err}"))
                    })?;
                    let (_incoming, ack) = session.accept_post_hello(&envelope)?;
                    if tx.send(ack).await.is_err() {
                        break;
                    }
                }
                Some(cmd) = rx.recv() => {
                    let payload = cmd.into_envelope_payload();
                    let envelope = AgentEnvelope {
                        protocol_major: session.inputs().max_protocol_major,
                        protocol_minor: session.inputs().max_protocol_minor,
                        runtime_session_id: prost::bytes::Bytes::copy_from_slice(session.runtime_session_id().as_uuid().as_bytes()),
                        session_seq: outbound_seq,
                        sent_monotonic_ns: current_monotonic_ns(),
                        message_id: format!("daemon-{outbound_seq}"),
                        correlation_token: String::new(),
                        payload: Some(payload),
                    };
                    outbound_seq = outbound_seq.saturating_add(1);
                    if let Err(err) = encoder.write_envelope(&envelope).await {
                        let _ = err;
                        break;
                    }
                }
                else => break,
            }
        }
        Ok(())
    }
    .await;

    health_task.abort();
    let _ = health_task.await;

    if let Err(err) = post_hello_result {
        let _ = send_protocol_error(&session, &mut encoder, &err.to_protocol_error()).await;
    }
    Ok(())
}

async fn send_protocol_error<W>(
    session: &Session,
    encoder: &mut EnvelopeAsyncEncoder<W>,
    err: &ProtocolError,
) -> Result<(), DaemonError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let envelope = AgentEnvelope {
        protocol_major: session.inputs().max_protocol_major,
        protocol_minor: session.inputs().max_protocol_minor,
        runtime_session_id: prost::bytes::Bytes::copy_from_slice(
            session.runtime_session_id().as_uuid().as_bytes(),
        ),
        session_seq: 0,
        sent_monotonic_ns: current_monotonic_ns(),
        message_id: "daemon-error".to_string(),
        correlation_token: String::new(),
        payload: Some(PayloadOneof::ProtocolError(err.clone())),
    };
    encoder
        .write_envelope(&envelope)
        .await
        .map_err(|err| DaemonError::Transport(format!("write protocol error: {err}")))
}

async fn join_tasks(tasks: Vec<JoinHandle<Result<(), DaemonError>>>) -> Result<(), DaemonError> {
    let mut first_error: Option<DaemonError> = None;
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(join_err) => {
                if first_error.is_none() {
                    first_error = Some(DaemonError::Join(format!("{join_err}")));
                }
            }
        }
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn current_monotonic_ns() -> u64 {
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    u64::try_from(now.as_nanos()).unwrap_or(u64::MAX)
}

fn random_server_nonce() -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    let _ = rng.fill(&mut bytes);
    bytes.to_vec()
}

/// Extracts the per-connection TLS exporter from a freshly accepted
/// rustls server stream.
///
/// The exporter is the RFC 5705 keying material derived from the TLS
/// 1.3 key schedule and labelled with [`TLS_EXPORTER_LABEL`]. The
/// adapter must call `export_keying_material` with the same label and
/// the same empty context so the daemon and the adapter agree on the
/// byte sequence folded into the AdapterHello/DaemonHello HMAC
/// transcript proof.
///
/// # Errors
///
/// Returns [`DaemonError::Transport`] when rustls reports the
/// handshake has not completed, the negotiated cipher suite does not
/// support exporters, or the requested length is zero. The exporter
/// label and context are stable across releases so an error here
/// means the rustls ABI or TLS 1.3 implementation is wrong.
fn extract_tls_exporter<S>(
    tls_stream: &tokio_rustls::server::TlsStream<S>,
) -> Result<Vec<u8>, DaemonError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (_, conn) = tls_stream.get_ref();
    let mut out = [0u8; TLS_EXPORTER_LEN];
    conn.export_keying_material(&mut out, TLS_EXPORTER_LABEL, None)
        .map_err(|err| DaemonError::Transport(format!("tls exporter: {err}")))?;
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xtrace_protocol::handshake::{compute_transcript_proof, verify_transcript_proof};

    /// The exporter label is part of the protocol contract: both the
    /// daemon and the adapter feed it to `export_keying_material` so
    /// the same byte sequence flows into the transcript proof. Any
    /// change requires an ADR and a coordinated adapter update.
    #[test]
    fn exporter_label_matches_the_documented_v1_contract() {
        assert_eq!(TLS_EXPORTER_LABEL, b"xtrace-adapter-transport-v1");
    }

    /// The exporter length matches the HMAC tag size so the value
    /// can be folded into the transcript proof without truncation
    /// or zero-padding. Changing it requires a Gate 3 amendment.
    #[test]
    fn exporter_length_matches_transcript_proof_tag_size() {
        assert_eq!(TLS_EXPORTER_LEN, 32);
    }

    /// The two-proof nonce-ordering resolution is the canonical byte
    /// layout used for the inbound AdapterHello HMAC. The adapter
    /// hashes `client_nonce` together with a fixed zero server nonce
    /// because the daemon has not yet emitted its own nonce; the
    /// canonical proof with `server_nonce = [0u8; 32]` is the only
    /// value the daemon accepts at this stage. A flipped layout
    /// would let an attacker reuse an old transcript.
    #[test]
    fn adapter_proof_layout_uses_zero_server_nonce_until_daemon_hello() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let client = [0xaa_u8; 16];
        // Inbound direction: server nonce is the canonical zero
        // placeholder; the daemon recognises this layout because the
        // server nonce has not been exchanged yet.
        let inbound =
            compute_transcript_proof(secret, exporter, session, &client, &[0u8; 32], manifest)
                .expect("HMAC accepts the test secret");
        // Same inputs but a non-zero server nonce would never match
        // the inbound verifier; this is the safety net.
        let wrong_layout =
            compute_transcript_proof(secret, exporter, session, &client, &[0x55_u8; 32], manifest)
                .expect("HMAC accepts the test secret");
        assert_ne!(inbound, wrong_layout);
        verify_transcript_proof(secret, exporter, session, &client, &[0u8; 32], manifest, &inbound)
            .expect("inbound verifier accepts the canonical layout");
    }

    /// The outbound DaemonHello proof uses the daemon's server nonce
    /// together with a canonical zero client nonce because the
    /// adapter is expected to recompute the proof with its own
    /// client nonce. The two sides therefore agree on a fixed-length
    /// transcript without leaking the missing nonce through padding.
    #[test]
    fn daemon_proof_layout_uses_zero_client_nonce_for_outbound_direction() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let server = [0xbb_u8; 32];
        let outbound =
            compute_transcript_proof(secret, exporter, session, &[0u8; 32], &server, manifest)
                .expect("HMAC accepts the test secret");
        let wrong_layout =
            compute_transcript_proof(secret, exporter, session, &[0x55_u8; 32], &server, manifest)
                .expect("HMAC accepts the test secret");
        assert_ne!(outbound, wrong_layout);
    }
}
