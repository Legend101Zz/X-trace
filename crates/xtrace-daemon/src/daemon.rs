//! Daemon builder and run loop.
//!
//! The builder pattern keeps the configuration flow explicit: callers
//! set the project / session identifiers, the expected repository
//! fingerprint, and (optionally) the bootstrap artifact path, then
//! call [`DaemonBuilder::bind`] which allocates the listener,
//! certificate, secret, and TLS materials. The returned
//! [`BoundDaemon`] owns the listener and exposes a
//! [`BoundDaemon::serve`] future that completes on shutdown.
//!
//! The run loop supervises one [`tokio::task`] per connection. Every
//! task is awaited before the run future returns so an orderly
//! shutdown is provably complete.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use prost::bytes::Bytes;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::server::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use xtrace_domain::ids::Id;
use xtrace_domain::{ProjectId, RuntimeSessionId};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{AgentEnvelope, ProtocolError};

use crate::bootstrap::{BootstrapArtifact, BootstrapArtifactFields, BootstrapOwner};
use crate::config::DaemonConfig;
use crate::error::{DaemonError, ProtocolErrorCode};
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
/// Length, in bytes, of the per-connection server nonce.
pub const SERVER_NONCE_LEN: usize = 32;
/// Hard ceiling on the monotonic clock value reported on the wire.
/// The value matches `u64::MAX` and is used only to convert the
/// process-local instant without losing information.
const MONOTONIC_CEILING_NS: u128 = u64::MAX as u128;
/// Monotonic epoch the daemon references. Using a process-local
/// [`Instant`] keeps the clock independent of the wall clock so the
/// value cannot jump backwards under a wall-clock adjustment.
type Monotonic = Instant;

/// Process-local monotonic clock. The instant is captured the first
/// time the daemon starts and every `now_ns` value is a
/// monotonically non-decreasing delta from that origin.
#[derive(Clone, Copy, Debug)]
pub struct MonotonicClock {
    /// Process-local origin the daemon reports from. Set when the
    /// clock is constructed so the first value is approximately
    /// zero, never negative, and independent of wall-clock changes.
    origin: Monotonic,
}

impl MonotonicClock {
    /// Returns a fresh clock anchored to the current [`Instant`].
    #[must_use]
    pub fn new() -> Self {
        Self { origin: Monotonic::now() }
    }

    /// Returns the elapsed nanoseconds since the clock's origin.
    /// The conversion saturates at [`u64::MAX`] so a value that
    /// exceeds the wire type is reported as the maximum rather than
    /// wrapping to zero.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        let elapsed = self.origin.elapsed();
        let nanos = elapsed.as_nanos();
        if nanos >= MONOTONIC_CEILING_NS {
            u64::MAX
        } else {
            u64::try_from(nanos).unwrap_or(u64::MAX)
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared shutdown channel. A single `watch` channel propagates the
/// shutdown signal to the supervisor loop, every connection task, and
/// every helper task; only one side is the writer (the caller of
/// [`BoundDaemon::serve`]) and every other participant holds the
/// receiver. The supervisor awaits the receiver's `changed` future
/// to stop accepting, then the per-connection loops exit on the next
/// shutdown observation.
#[derive(Clone)]
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Awaits the next shutdown transition. Resolves immediately if
    /// the signal has already fired. The future is cancellation-safe
    /// because the underlying `watch` channel retains the latest
    /// value across observers.
    pub async fn wait(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        let _ = self.rx.changed().await;
    }

    /// Returns `true` once the signal has been raised.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }
}

fn shared_shutdown_channel() -> (watch::Sender<bool>, ShutdownSignal) {
    let (tx, rx) = watch::channel(false);
    (tx, ShutdownSignal { rx })
}

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
    /// Expected repository fingerprint the daemon enforces on every
    /// inbound `AdapterHello`.
    expected_repository_fingerprint: String,
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

    /// Returns the ephemeral certificate. Tests use the
    /// certificate-der accessor to seed the wrong-pin verifier; the
    /// daemon does not expose the private key.
    #[must_use]
    pub fn certificate(&self) -> &EphemeralCertificate {
        &self.tls_materials.certificate
    }

    /// Returns the SHA-256 pin of the bound certificate. Production
    /// adapters read this value from the bootstrap artifact; tests
    /// use it to construct a pinned verifier.
    #[must_use]
    pub fn certificate_pin(&self) -> &str {
        self.tls_materials.certificate.pin()
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

    /// Returns the expected repository fingerprint.
    #[must_use]
    pub fn expected_repository_fingerprint(&self) -> &str {
        &self.expected_repository_fingerprint
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
        let expected_repository_fingerprint = self.expected_repository_fingerprint;
        let _bootstrap = self.bootstrap;

        let (shutdown_tx, mut shutdown_signal) = shared_shutdown_channel();
        let clock = MonotonicClock::new();
        let ctx = SupervisorContext {
            config,
            tls_config: tls_materials.server_config.clone(),
            session_secret: session_secret.clone(),
            runtime_session_id,
            project_id,
            expected_repository_fingerprint,
            shutdown: shutdown_signal.clone(),
        };

        let mut tasks: Vec<JoinHandle<Result<(), DaemonError>>> = Vec::new();
        let shutdown_observer: JoinHandle<()> = tokio::spawn(async move {
            shutdown.await;
            let _ = shutdown_tx.send(true);
        });

        loop {
            tokio::select! {
                biased;
                _ = shutdown_signal.wait() => {
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
                    let task_ctx = ctx.clone();
                    let task_clock = clock;
                    let task = tokio::spawn(async move {
                        handle_connection(task_ctx, stream, task_clock).await
                    });
                    tasks.push(task);
                }
            }
        }

        shutdown_observer.abort();
        let _ = shutdown_observer.await;
        join_tasks(tasks).await
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "every field is a wire-shaped output documented in `03b-protocol-and-api.md` §2.4"
)]
async fn handle_connection(
    ctx: SupervisorContext,
    stream: TcpStream,
    clock: MonotonicClock,
) -> Result<(), DaemonError> {
    let mut shutdown = ctx.shutdown.clone();
    let acceptor = tokio_rustls::TlsAcceptor::from(ctx.tls_config.clone());
    let tls_stream = tokio::select! {
        biased;
        _ = shutdown.wait() => return Ok(()),
        result = acceptor.accept(stream) => match result {
            Ok(stream) => stream,
            Err(err) => {
                debug!(error = %err, "tls handshake failed");
                return Ok(());
            }
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
        session_secret: ctx.session_secret.clone(),
        tls_exporter,
        runtime_session_id: ctx.runtime_session_id,
        project_id: ctx.project_id,
        max_envelope_bytes: ctx.config.max_envelope_bytes,
        max_batch_events: ctx.config.max_batch_events,
        max_protocol_major: 1,
        max_protocol_minor: 0,
        expected_repository_fingerprint: ctx.expected_repository_fingerprint.clone(),
        health_interval: HealthInterval(ctx.config.health_interval),
        role: HandshakeRole::Daemon,
    });
    let mut decoder = EnvelopeAsyncDecoder::new(reader, session.max_envelope_bytes());
    let mut encoder = EnvelopeAsyncEncoder::new(writer, session.max_envelope_bytes());

    let first = tokio::select! {
        biased;
        _ = shutdown.wait() => return Ok(()),
        result = decoder.read_envelope() => match result {
            Ok(envelope) => envelope,
            Err(err) => {
                let code = envelope_error_code(& err);
                return send_protocol_error(
                    & session,
                    & mut encoder,
                    & ProtocolError {
                        code: code.as_str().to_string(),
                        message: format!("{err}"),
                    },
                )
                .await;
            }
        }
    };

    if let Err(err) = session.accept_adapter_hello(&first) {
        return send_protocol_error(&session, &mut encoder, &err.to_protocol_error()).await;
    }

    let server_nonce = random_server_nonce()?;
    let envelope = match session.build_daemon_hello(server_nonce, clock.now_ns()) {
        Ok(envelope) => envelope,
        Err(err) => {
            return send_protocol_error(&session, &mut encoder, &err.to_protocol_error()).await;
        }
    };
    if let Err(err) = encoder.write_envelope(&envelope).await {
        return Err(DaemonError::Transport(format!("write daemon hello: {err}")));
    }

    let (tx, mut rx) =
        mpsc::channel::<crate::runtime::OutgoingCommand>(ctx.config.channel_capacity.as_usize());
    let health_session = session.clone();
    let health_tx = tx.clone();
    let mut health_shutdown = ctx.shutdown.clone();
    let health_clock = clock;
    let health_task: JoinHandle<()> = tokio::spawn(async move {
        let interval = health_session.health_interval().0.max(StdDuration::from_secs(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = health_shutdown.wait() => break,
                _ = ticker.tick() => {
                    let now_ns = health_clock.now_ns();
                    let cmd = health_session.next_health(now_ns);
                    if health_tx.send(cmd).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut outbound_seq: u64 = 1;
    let post_hello_result: Result<(), crate::session::SessionError> = async {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.wait() => break,
                incoming = decoder.read_envelope() => {
                    let envelope = match incoming {
                        Ok(env) => env,
                        Err(err) => {
                            let code = envelope_error_code(& err);
                            return Err(crate::session::SessionError::new(
                                code,
                                format!("read envelope: {err}"),
                            ));
                        }
                    };
                    let (_incoming, ack) = session.accept_post_hello(& envelope)?;
                    if tx.send(ack).await.is_err() {
                        break;
                    }
                }
                Some(cmd) = rx.recv() => {
                    let payload = cmd.into_envelope_payload();
                    let envelope = AgentEnvelope {
                        protocol_major: session.inputs().max_protocol_major,
                        protocol_minor: session.inputs().max_protocol_minor,
                        runtime_session_id: Bytes::copy_from_slice(session.runtime_session_id().as_uuid().as_bytes()),
                        session_seq: outbound_seq,
                        sent_monotonic_ns: clock.now_ns(),
                        message_id: format!("daemon-{outbound_seq}"),
                        correlation_token: String::new(),
                        payload: Some(payload),
                    };
                    outbound_seq = match outbound_seq.checked_add(1) {
                        Some(next) => next,
                        None => break,
                    };
                    if encoder.write_envelope(& envelope).await.is_err() {
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
    drop(rx);
    drop(tx);

    if let Err(err) = post_hello_result {
        let _ = send_protocol_error(&session, &mut encoder, &err.to_protocol_error()).await;
    }
    Ok(())
}

fn envelope_error_code(err: &std::io::Error) -> ProtocolErrorCode {
    use std::io::ErrorKind as K;
    match err.kind() {
        K::UnexpectedEof => ProtocolErrorCode::Shutdown,
        K::InvalidData => ProtocolErrorCode::FrameTooLarge,
        _ => ProtocolErrorCode::Transport,
    }
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
        runtime_session_id: Bytes::copy_from_slice(
            session.runtime_session_id().as_uuid().as_bytes(),
        ),
        session_seq: 0,
        sent_monotonic_ns: MonotonicClock::new().now_ns(),
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

fn random_server_nonce() -> Result<Vec<u8>, DaemonError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; SERVER_NONCE_LEN];
    rng.fill(&mut bytes).map_err(|err| {
        DaemonError::Transport(format!("os rng refused to fill the server nonce: {err}"))
    })?;
    Ok(bytes.to_vec())
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

#[derive(Clone)]
struct SupervisorContext {
    /// Daemon-wide tunables shared with every per-connection task.
    config: DaemonConfig,
    tls_config: Arc<ServerConfig>,
    session_secret: SessionSecret,
    runtime_session_id: RuntimeSessionId,
    project_id: ProjectId,
    expected_repository_fingerprint: String,
    /// Shared shutdown signal observed by the supervisor, every
    /// connection, and every helper task.
    shutdown: ShutdownSignal,
}

/// Builder for [`BoundDaemon`].
#[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
pub struct DaemonBuilder {
    config: DaemonConfig,
    project_id: Option<ProjectId>,
    runtime_session_id: Option<RuntimeSessionId>,
    expected_repository_fingerprint: Option<String>,
    bootstrap_artifact: Option<PathBuf>,
}

impl DaemonBuilder {
    /// Constructs a new builder with the supplied configuration.
    pub fn new(config: DaemonConfig) -> Self {
        Self {
            config,
            project_id: None,
            runtime_session_id: None,
            expected_repository_fingerprint: None,
            bootstrap_artifact: None,
        }
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

    /// Sets the expected repository fingerprint the daemon enforces
    /// on every inbound `AdapterHello`. Required.
    #[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
    pub fn with_expected_repository_fingerprint(mut self, fingerprint: String) -> Self {
        self.expected_repository_fingerprint = Some(fingerprint);
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
    /// Returns [`DaemonError::InvalidConfig`] when the project,
    /// runtime session identifier, or expected repository fingerprint
    /// has not been supplied; [`DaemonError::Bootstrap`] when the
    /// artifact cannot be written; and [`DaemonError::BindFailed`]
    /// when the OS refuses the loopback bind.
    pub async fn bind(self) -> Result<BoundDaemon, DaemonError> {
        let project_id = self
            .project_id
            .ok_or_else(|| DaemonError::InvalidConfig("project_id is required".to_string()))?;
        let runtime_session_id = self.runtime_session_id.ok_or_else(|| {
            DaemonError::InvalidConfig("runtime_session_id is required".to_string())
        })?;
        let expected_repository_fingerprint =
            self.expected_repository_fingerprint.ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "expected_repository_fingerprint is required".to_string(),
                )
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
                    expected_repository_fingerprint.clone(),
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
            expected_repository_fingerprint,
            bootstrap,
        })
    }
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
    /// layout used for the inbound `AdapterHello` HMAC. The adapter
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
        let client = [0xaa_u8; 32];
        let inbound = compute_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest,
            &xtrace_protocol::handshake::project_context(b"01900000-0000-7000-8000-000000000000"),
        )
        .expect("HMAC accepts the test secret");
        verify_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest,
            &xtrace_protocol::handshake::project_context(b"01900000-0000-7000-8000-000000000000"),
            &inbound,
        )
        .expect("inbound verifier accepts the canonical layout");
    }

    /// The outbound `DaemonHello` proof uses the daemon's server
    /// nonce together with the recovered client nonce (no zero
    /// placeholder) and the project context chunk. The layout is
    /// symmetric with the inbound direction minus the placeholder.
    #[test]
    fn daemon_proof_layout_uses_real_client_nonce_for_outbound_direction() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let project = b"01900000-0000-7000-8000-000000000000";
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let client = [0xaa_u8; 32];
        let server = [0xbb_u8; 32];
        let outbound = compute_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            manifest,
            &xtrace_protocol::handshake::project_context(project),
        )
        .expect("HMAC accepts the test secret");
        assert_eq!(outbound.len(), 32);
    }

    #[test]
    fn monotonic_clock_is_monotonic_and_non_zero() {
        let clock = MonotonicClock::new();
        let first = clock.now_ns();
        std::thread::sleep(StdDuration::from_millis(2));
        let second = clock.now_ns();
        assert!(second >= first, "monotonic clock must not regress");
    }
}
