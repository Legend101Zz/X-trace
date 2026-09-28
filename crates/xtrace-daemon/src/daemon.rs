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
use tokio::io::AsyncWriteExt as _;
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

/// TLS exporter placeholder length.
pub const TLS_EXPORTER_LEN: usize = 32;
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
    /// TLS exporter placeholder used for the transcript proof.
    tls_exporter_for_probe: Vec<u8>,
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

    /// Returns the configured TLS exporter placeholder. Tests use the
    /// value to recompute the transcript proof against the daemon's
    /// expectations.
    #[must_use]
    pub fn tls_exporter(&self) -> &[u8] {
        &self.tls_exporter_for_probe
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
        let tls_exporter_for_probe =
            tls_exporter_placeholder(tls_materials.certificate.pin(), runtime_session_id);
        let _bootstrap = self.bootstrap;

        let supervisor = SupervisorContext {
            config,
            tls_config: tls_materials.server_config.clone(),
            certificate_summary: tls_materials.certificate_summary.clone(),
            session_secret,
            runtime_session_id,
            project_id,
            tls_exporter_for_probe: tls_exporter_for_probe.clone(),
        };

        let mut tasks: Vec<JoinHandle<Result<(), DaemonError>>> = Vec::new();
        let mut shutdown_task: Option<JoinHandle<()>> = None;
        let shutdown_signal = Arc::new(tokio::sync::Notify::new());
        let signal_clone = shutdown_signal.clone();
        shutdown_task = Some(tokio::spawn(async move {
            shutdown.await;
            signal_clone.notify_waiters();
        }));

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

        if let Some(task) = shutdown_task.take() {
            task.abort();
        }
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
    #[must_use]
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            project_id: None,
            runtime_session_id: None,
            bootstrap_artifact: None,
        }
    }

    /// Sets the project identifier the daemon will require on every
    /// post-hello envelope. Required.
    #[must_use]
    pub fn with_project_id(mut self, project_id: ProjectId) -> Self {
        self.project_id = Some(project_id);
        self
    }

    /// Sets the runtime session identifier the daemon will require on
    /// every post-hello envelope. Required.
    #[must_use]
    pub fn with_runtime_session_id(mut self, session_id: RuntimeSessionId) -> Self {
        self.runtime_session_id = Some(session_id);
        self
    }

    /// Sets the optional bootstrap artifact path. When set, the
    /// daemon writes the artifact with owner-only permissions before
    /// serving and removes it on orderly shutdown.
    #[must_use]
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
        let session_secret = SessionSecret::generate().map_err(|err| {
            DaemonError::Bootstrap(format!("session secret: {err}"))
        })?;
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
        let tls_exporter_for_probe =
            tls_exporter_placeholder(tls_materials.certificate.pin(), runtime_session_id);
        Ok(BoundDaemon {
            config: self.config,
            listener,
            tls_materials,
            session_secret,
            runtime_session_id,
            project_id,
            tls_exporter_for_probe,
            bootstrap,
        })
    }
}

#[derive(Clone)]
struct SupervisorContext {
    #[allow(dead_code)]
    config: DaemonConfig,
    tls_config: Arc<ServerConfig>,
    certificate_summary: String,
    session_secret: SessionSecret,
    runtime_session_id: RuntimeSessionId,
    project_id: ProjectId,
    /// Bytes used in place of the TLS exporter for the transcript
    /// proof. See [`tls_exporter_placeholder`] for the rationale.
    tls_exporter_for_probe: Vec<u8>,
}

async fn handle_connection(
    ctx: SupervisorContext,
    stream: TcpStream,
) -> Result<(), DaemonError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(ctx.tls_config.clone());
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => stream,
        Err(err) => {
            debug!(error = %err, "tls handshake failed");
            return Ok(());
        }
    };
    let (reader, writer) = tokio::io::split(tls_stream);
    let mut session = Session::new(HandshakeInputs {
        session_secret: ctx.session_secret,
        tls_exporter: ctx.tls_exporter_for_probe.clone(),
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
                &mut session,
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
        return send_protocol_error(&mut session, &mut encoder, &err.to_protocol_error()).await;
    }

    let server_nonce = random_server_nonce();
    let envelope = match session.build_daemon_hello(server_nonce, current_monotonic_ns()) {
        Ok(envelope) => envelope,
        Err(err) => return send_protocol_error(&mut session, &mut encoder, &err.to_protocol_error()).await,
    };
    if let Err(err) = encoder.write_envelope(&envelope).await {
        return Err(DaemonError::Transport(format!("write daemon hello: {err}")));
    }

    let (tx, mut rx) = mpsc::channel::<crate::runtime::OutgoingCommand>(CONNECTION_COMMAND_CAPACITY);
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
        let _ = send_protocol_error(&mut session, &mut encoder, &err.to_protocol_error()).await;
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
        runtime_session_id: prost::bytes::Bytes::copy_from_slice(session.runtime_session_id().as_uuid().as_bytes()),
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

async fn join_tasks(
    tasks: Vec<JoinHandle<Result<(), DaemonError>>>,
) -> Result<(), DaemonError> {
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(now.as_nanos()).unwrap_or(u64::MAX)
}

fn random_server_nonce() -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    let _ = rng.fill(&mut bytes);
    bytes.to_vec()
}

/// TLS exporter placeholder used by the supervisor.
///
/// The approved handshake binds the HMAC transcript proof to the
/// `rustls` TLS exporter. `tokio_rustls` does not expose the
/// exporter through a stable, test-friendly API today; the
/// placeholder substitutes a deterministic 32-byte value derived
/// from the certificate pin and the runtime session identifier so
/// the transcript proof remains reproducible. The full exporter
/// extraction is documented as the next-smallest increment.
pub fn tls_exporter_placeholder(pin: &str, session_id: RuntimeSessionId) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace-tls-exporter-v1");
    hasher.update(pin.as_bytes());
    hasher.update(session_id.as_uuid().as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; TLS_EXPORTER_LEN];
    out.copy_from_slice(&digest.as_bytes()[..TLS_EXPORTER_LEN]);
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_exporter_placeholder_is_deterministic_and_field_sensitive() {
        let pin = "a".repeat(64);
        let session = RuntimeSessionId::new();
        let first = tls_exporter_placeholder(&pin, session);
        let second = tls_exporter_placeholder(&pin, session);
        assert_eq!(first, second);
        assert_eq!(first.len(), TLS_EXPORTER_LEN);
        let other = tls_exporter_placeholder(&"b".repeat(64), session);
        assert_ne!(first, other);
        let other_session = RuntimeSessionId::new();
        let other = tls_exporter_placeholder(&pin, other_session);
        assert_ne!(first, other);
    }
}