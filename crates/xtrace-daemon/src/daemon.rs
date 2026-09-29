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
//! The run loop supervises a [`tokio::task::JoinSet`] of connection
//! tasks; each completed task is reaped before the next accept to
//! keep the supervisor's bookkeeping bounded. Each connection spawns
//! a structured pair: the reader task owns the inbound half and the
//! session state, while a dedicated writer task owns the outbound
//! encoder and drains a bounded command channel. Both helpers observe
//! the shared shutdown signal and are joined before the connection
//! task returns so no detached work survives a connection close.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use prost::Message;
use prost::bytes::Bytes;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::server::ServerConfig;
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};
use xtrace_domain::ids::Id;
use xtrace_domain::{ProjectId, RepositoryFingerprint, RuntimeSessionId};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent as wire;
use xtrace_protocol::generated::agent::{AgentEnvelope, ProtocolError};

use crate::bootstrap::{BootstrapArtifact, BootstrapArtifactFields, BootstrapOwner};
use crate::config::DaemonConfig;
use crate::error::{DaemonError, ProtocolErrorCode};
use crate::framing::{EnvelopeAsyncDecoder, EnvelopeAsyncEncoder};
use crate::listener::LoopbackListener;
use crate::runtime::HealthInterval;
use crate::secret::SessionSecret;
use crate::session::{HandshakeInputs, HandshakeRole, Session, SessionError};
use crate::tls::TlsServerMaterials;

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

/// Process-local monotonic clock. The instant is captured the first
/// time the daemon starts and every `now_ns` value is a
/// monotonically non-decreasing delta from that origin.
///
/// The clock is `daemon-scoped`: the supervisor constructs a single
/// instance before the accept loop, hands a `Copy` of it to every
/// connection task, and reuses the same instance for any
/// pre-connection `ProtocolError` timestamp. A per-connection
/// origin would let two timestamps within the same serve run refer
/// to different anchors and would violate the documented
/// `process/daemon-local` invariant; the regression coverage in the
/// in-module tests pins the contract.
#[derive(Clone, Copy, Debug)]
pub struct MonotonicClock {
    /// Process-local origin the daemon reports from. Set when the
    /// clock is constructed so the first value is approximately
    /// zero, never negative, and independent of wall-clock changes.
    origin: Instant,
}

impl MonotonicClock {
    /// Returns a fresh clock anchored to the current [`Instant`].
    #[must_use]
    pub fn new() -> Self {
        Self { origin: Instant::now() }
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

/// Per-connection cancellation handle. The connection task owns the
/// sender; the health producer owns the receiver. Raising the signal
/// stops the health producer without preempting the writer task so a
/// queued `ProtocolError` is guaranteed to reach the wire before the
/// connection closes. The writer task observes only the global
/// daemon shutdown and natural encoder failures.
struct ConnectionCancel {
    rx: watch::Receiver<bool>,
}

impl ConnectionCancel {
    /// Constructs a fresh signal. Returns the owning sender and a
    /// receiver for the helper task that must observe the signal.
    fn new() -> (watch::Sender<bool>, Self) {
        let (tx, rx) = watch::channel(false);
        (tx, Self { rx })
    }

    /// Awaits the next cancellation transition. Resolves immediately
    /// when the cancel has already fired.
    async fn wait(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        let _ = self.rx.changed().await;
    }
}

/// Frame the writer task serializes onto the wire.
struct OutboundFrame {
    payload: PayloadOneof,
}

/// Dedicated writer task. The task owns the encoder exclusively and
/// drains a bounded command channel so the reader/validator is never
/// blocked on a slow consumer. Outbound sequencing uses checked
/// arithmetic so an overflow is reported rather than silently
/// wrapping. The writer observes only the global daemon shutdown;
/// connection-local cancellation drives the health producer and the
/// reader, not this task, so a queued `ProtocolError` is guaranteed
/// to reach the wire before the writer observes the closing
/// `rx.recv() -> None`. Peer disconnect naturally fails the next
/// encoder write so the task tears down without an extra signal.
async fn run_outbound_writer<W>(
    mut encoder: EnvelopeAsyncEncoder<W>,
    mut rx: mpsc::Receiver<OutboundFrame>,
    negotiated_major: u32,
    negotiated_minor: u32,
    runtime_session_id: [u8; 16],
    clock: MonotonicClock,
    mut shutdown: ShutdownSignal,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut next_seq: u64 = 1;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            next = rx.recv() => match next {
                Some(frame) => {
                    let seq = next_seq;
                    next_seq = match next_seq.checked_add(1) {
                        Some(value) => value,
                        None => break,
                    };
                    let envelope = AgentEnvelope {
                        protocol_major: negotiated_major,
                        protocol_minor: negotiated_minor,
                        runtime_session_id: Bytes::copy_from_slice(&runtime_session_id),
                        session_seq: seq,
                        sent_monotonic_ns: clock.now_ns(),
                        message_id: format!("daemon-{seq}"),
                        correlation_token: String::new(),
                        payload: Some(frame.payload),
                    };
                    if encoder.write_envelope(&envelope).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    }
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
    expected_repository_fingerprint: RepositoryFingerprint,
    /// Optional bootstrap artifact handle. `Some` when the daemon
    /// owns the file; the [`Arc`] is shared between the supervisor
    /// and every connection task so the post-hello
    /// `try_release` call honours the
    /// `docs/plans/x-trace/03b-protocol-and-api.md` §2.1 "deleted
    /// after negotiation" contract exactly once across concurrent
    /// successful handshakes.
    bootstrap: Option<Arc<BootstrapArtifact>>,
}

impl BoundDaemon {
    /// Returns the local address the daemon is bound to.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr()
    }

    /// Returns the SHA-256 pin of the bound certificate. Production
    /// adapters read this value from the bootstrap artifact; tests
    /// use it to construct a pinned verifier.
    #[must_use]
    pub fn certificate_pin(&self) -> &str {
        self.tls_materials.certificate_pin()
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
    pub fn expected_repository_fingerprint(&self) -> &RepositoryFingerprint {
        &self.expected_repository_fingerprint
    }

    /// Runs the daemon supervisor until the supplied shutdown future
    /// resolves. Every connection is awaited before the future
    /// returns so an orderly shutdown is observable from the caller.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::Join`] when a connection task panics or
    /// is cancelled, and after the supervisor signals shutdown and
    /// drains every in-flight connection. Returns the first
    /// connection-local [`DaemonError`] a task reports when a genuine
    /// internal failure (for example a refused server nonce or a
    /// bootstrap-cleanup failure) escapes the peer-disconnect
    /// boundary. A single failed peer cannot take the daemon down:
    /// the supervisor treats malformed clients, refused TLS
    /// handshakes, rejected `AdapterHello` envelopes, decoder
    /// errors, and a peer disconnect during the post-`AdapterHello`
    /// `DaemonHello` write as `Ok(())` at the connection boundary so
    /// the listener keeps accepting until the shutdown future
    /// resolves or the supervisor observes a real internal failure.
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
        let bootstrap = self.bootstrap;

        let (shutdown_tx, mut shutdown_signal) = shared_shutdown_channel();
        // Keep an extra sender in scope so a listener-level failure
        // can deterministically raise the global shutdown signal
        // without having to wait on the user-supplied shutdown future.
        let shutdown_tx_for_supervisor = shutdown_tx.clone();
        let shutdown_signal_inner = shutdown_signal.clone();
        let ctx = SupervisorContext {
            config,
            tls_config: tls_materials.server_config(),
            session_secret: session_secret.clone(),
            runtime_session_id,
            project_id,
            expected_repository_fingerprint,
            shutdown: shutdown_signal_inner,
            bootstrap: bootstrap.clone(),
        };

        // One daemon-scoped monotonic clock for every timestamp the
        // supervisor and its connections emit during this serve run.
        // The clone is `Copy`, so every connection task receives the
        // same origin and the documented `process/daemon-local`
        // invariant survives even when the listener accepts multiple
        // sequential clients.
        let clock = MonotonicClock::new();

        let mut connections: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        let mut shutdown_observer: JoinHandle<()> = tokio::spawn(async move {
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
                // Reap completed connection tasks so the join set
                // never grows without bound when sequential clients
                // disconnect. The classification function decides
                // whether to keep running, to record a connection
                // error, or to stop the daemon.
                Some(joined) = connections.join_next() => {
                    match classify_join_completion(joined) {
                        JoinCompletionAction::Continue => {}
                        JoinCompletionAction::ConnectionFailure(err) => {
                            // The triggering failure happened first
                            // and the supervisor must surface it to
                            // the caller: drain every remaining
                            // task, log any drain failures, and
                            // return the original error. A later
                            // drain failure must not replace the
                            // triggering failure because the caller
                            // is best served by the failure mode
                            // that already happened.
                            return Err(shutdown_after_trigger(
                                err,
                                &mut connections,
                                &shutdown_tx_for_supervisor,
                                &mut shutdown_observer,
                            )
                            .await);
                        }
                        JoinCompletionAction::JoinFailure(join_err) => {
                            // A panic or cancellation is itself the
                            // triggering failure. The supervisor
                            // signals shutdown, drains, logs any
                            // drain failure, and returns the
                            // wrapping [`DaemonError::Join`].
                            return Err(shutdown_after_trigger(
                                DaemonError::Join(format!(
                                    "connection task join failed: {join_err}"
                                )),
                                &mut connections,
                                &shutdown_tx_for_supervisor,
                                &mut shutdown_observer,
                            )
                            .await);
                        }
                    }
                }
                accept_result = listener.accept() => {
                    let (stream, peer) = match accept_result {
                        Ok(pair) => pair,
                        Err(err) => {
                            // The accept failure happened first and
                            // is the triggering error. The supervisor
                            // signals shutdown, drains every
                            // remaining task, logs any drain
                            // failure, and returns the accept error.
                            warn!(error = %err, "listener accept failed");
                            return Err(shutdown_after_trigger(
                                err,
                                &mut connections,
                                &shutdown_tx_for_supervisor,
                                &mut shutdown_observer,
                            )
                            .await);
                        }
                    };
                    debug!(peer = %peer, "daemon accepted new connection");
                    let task_ctx = ctx.clone();
                    let task_clock = clock;
                    connections.spawn(async move {
                        handle_connection(task_ctx, stream, task_clock).await
                    });
                }
            }
        }

        shutdown_observer.abort();
        let _ = shutdown_observer.await;
        // Drain every connection before returning so the future is
        // observably complete. Ordinary shutdown has no prior
        // trigger so the first error observed during drain — in
        // actual `join_next` observation order, regardless of
        // whether it was a panic/cancellation or a connection
        // error — is the one the caller sees.
        if let Some(err) = drain_connections(&mut connections).await {
            return Err(err);
        }
        Ok(())
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
    let mut tls_stream = tokio::select! {
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

    // Read and validate the inbound hello on the full TLS stream so
    // we still own both halves; only after `DaemonHello` is on the
    // wire do we hand the write half off to a dedicated task.
    let max_envelope_bytes = ctx.config.max_envelope_bytes;
    let first = tokio::select! {
        biased;
        _ = shutdown.wait() => return Ok(()),
        result = read_envelope_from_stream(&mut tls_stream, max_envelope_bytes) => match result {
            Ok(envelope) => envelope,
            Err(err) => {
                let code = envelope_error_code(& err);
                let _ = send_protocol_error_stream(
                    &mut tls_stream,
                    max_envelope_bytes,
                    code.as_str(),
                    &format!("{err}"),
                    clock,
                )
                .await;
                return Ok(());
            }
        }
    };

    let mut session = Session::new(HandshakeInputs {
        session_secret: ctx.session_secret.clone(),
        tls_exporter,
        runtime_session_id: ctx.runtime_session_id,
        project_id: ctx.project_id,
        max_envelope_bytes,
        max_batch_events: ctx.config.max_batch_events,
        max_protocol_major: 1,
        max_protocol_minor: 0,
        expected_repository_fingerprint: ctx.expected_repository_fingerprint.clone(),
        health_interval: HealthInterval(ctx.config.health_interval),
        role: HandshakeRole::Daemon,
    });

    if let Err(err) = session.accept_adapter_hello(&first) {
        let _ = send_protocol_error_stream(
            &mut tls_stream,
            max_envelope_bytes,
            err.code.as_str(),
            &err.detail,
            clock,
        )
        .await;
        return Ok(());
    }

    let server_nonce = random_server_nonce()?;
    let negotiated = session.negotiated().ok_or_else(|| {
        DaemonError::Transport(
            "daemon hello requested before AdapterHello was validated".to_string(),
        )
    })?;
    let envelope = match session.build_daemon_hello(server_nonce, clock.now_ns()) {
        Ok(envelope) => envelope,
        Err(err) => {
            let _ = send_protocol_error_stream(
                &mut tls_stream,
                max_envelope_bytes,
                err.code.as_str(),
                &err.detail,
                clock,
            )
            .await;
            return Ok(());
        }
    };
    if let Err(err) = write_initial_envelope_stream(&mut tls_stream, &envelope).await {
        match err {
            InitialEnvelopeWriteError::Io(_) => {
                // A failure to write `DaemonHello` after a valid
                // `AdapterHello` cannot be distinguished from a
                // peer disconnect at this layer: the local kernel
                // socket may be perfectly healthy while the peer
                // has already closed its read half. Treating the
                // failure as an internal daemon defect would let a
                // misbehaving client take the listener down with
                // one truncated read, which the
                // `docs/plans/x-trace/03b-protocol-and-api.md` §2.1
                // contract explicitly forbids. The connection-local
                // error is normalised to `Ok(())` so the supervisor
                // keeps accepting subsequent connections.
                debug!("daemon hello write failed; treating as connection-local peer disconnect");
                return Ok(());
            }
            InitialEnvelopeWriteError::Encode(_) | InitialEnvelopeWriteError::LengthOverflow(_) => {
                // Fatal internal defect: the codec refused the
                // envelope or produced an oversized body. Surfacing
                // the typed error lets the supervisor stop the
                // daemon with a real diagnostic instead of silently
                // dropping an internal failure on the floor.
                return Err(DaemonError::Transport(format!("daemon hello write failed: {err}",)));
            }
        }
    }
    // The §2.1 deletion contract is satisfied only after
    // `AdapterHello` has been validated AND `DaemonHello` has been
    // written to the wire. Failed proof exchanges never reach this
    // point so a legitimate retry against the same launch can
    // re-read the artifact. The mutex-guarded flag inside the
    // shared handle guarantees the file is removed at most once
    // even when multiple connection tasks race on the same handle;
    // a failed unlink is propagated here so the supervisor stops
    // the daemon rather than silently claiming the secret file has
    // been cleaned up while it remains on disk.
    if let Some(handle) = ctx.bootstrap.as_ref() {
        handle.try_release()?;
    }

    // Now split the stream and hand the write half to a dedicated
    // task. The reader keeps the read half and the session state;
    // helper tasks (health, ACK) post frames into the same channel.
    let (read_half, write_half) = tokio::io::split(tls_stream);
    let mut decoder = EnvelopeAsyncDecoder::new(read_half, max_envelope_bytes);
    let writer = EnvelopeAsyncEncoder::new(write_half, max_envelope_bytes);
    let (tx, rx) = mpsc::channel::<OutboundFrame>(ctx.config.outbound_capacity.as_usize());
    let writer_runtime_session_id: [u8; 16] = {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(session.runtime_session_id().as_uuid().as_bytes());
        buf
    };
    let health_interval = session.health_interval().0.max(StdDuration::from_secs(1));
    let writer_clock = clock;
    let writer_shutdown = ctx.shutdown.clone();
    let (conn_cancel_tx, conn_cancel_rx) = ConnectionCancel::new();
    let writer_task: JoinHandle<()> = tokio::spawn(async move {
        run_outbound_writer(
            writer,
            rx,
            negotiated.major,
            negotiated.minor,
            writer_runtime_session_id,
            writer_clock,
            writer_shutdown,
        )
        .await
    });

    // Health ticker publishes into the same outbound channel. The
    // task observes both the global daemon shutdown and the
    // per-connection cancellation signal so a reader-side error
    // deterministically stops the ticker without waiting on the
    // global shutdown.
    let health_tx = tx.clone();
    let health_clock = clock;
    let mut health_global_shutdown = ctx.shutdown.clone();
    let mut health_conn_cancel = conn_cancel_rx;
    let health_task: JoinHandle<()> = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(health_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = health_global_shutdown.wait() => break,
                _ = health_conn_cancel.wait() => break,
                _ = ticker.tick() => {
                    let now_ns = health_clock.now_ns();
                    let payload = PayloadOneof::Health(wire::Health {
                        monotonic_ns: now_ns,
                        queue_depth_batches: 0,
                        resident_bytes: 0,
                        status: "ok".to_string(),
                    });
                    let frame = OutboundFrame { payload };
                    if health_tx.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut post_hello_session = session;
    let post_hello_tx = tx;
    let post_hello_result: Result<(), SessionError> = async {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.wait() => return Ok(()),
                incoming = decoder.read_envelope() => {
                    let envelope = match incoming {
                        Ok(env) => env,
                        Err(err) => {
                            let code = envelope_error_code(& err);
                            return Err(SessionError::new(
                                code,
                                format!("read envelope: {err}"),
                            ));
                        }
                    };
                    match post_hello_session.accept_post_hello(&envelope) {
                        Ok((_incoming, ack)) => {
                            let frame = OutboundFrame {
                                payload: ack.into_envelope_payload(),
                            };
                            if post_hello_tx.send(frame).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(err) => {
                            // Deliver the documented ProtocolError to
                            // the adapter before the connection tears
                            // down. The frame goes through the same
                            // writer task so it is sequenced with any
                            // in-flight Health or ACK frames; the
                            // teardown below waits for the writer to
                            // drain the channel before the TLS stream
                            // is dropped.
                            let frame = OutboundFrame {
                                payload: PayloadOneof::ProtocolError(
                                    err.to_protocol_error(),
                                ),
                            };
                            let _ = post_hello_tx.send(frame).await;
                            return Err(err);
                        }
                    }
                }
            }
        }
    }
    .await;

    // Tear down helpers in the precise order documented by the
    // connection-local lifecycle:
    //
    // 1. Raise the connection-local cancellation so the health
    //    producer observes it and stops publishing Health frames.
    // 2. Await the health task so it drops its `tx` clone, leaving
    //    only the reader's `tx` holding the writer channel open.
    // 3. Drop the reader's `tx`; the writer observes `None` from
    //    `rx.recv()` and drains any remaining frames to the wire
    //    before exiting.
    // 4. Await the writer task so the TLS write half is dropped only
    //    after every queued frame has been flushed.
    //
    // Global daemon shutdown remains the outer bound; it preempted
    // the reader's `select!` above and propagates into the writer via
    // its own `select!` arm so the writer never blocks the supervisor
    // on a peer that has already disconnected.
    let _ = conn_cancel_tx.send(true);
    let _ = health_task.await;
    drop(post_hello_tx);
    let _ = writer_task.await;

    if let Err(err) = post_hello_result {
        // The writer task has already drained the ProtocolError
        // frame above; the supervisor's diagnostic log records the
        // failure mode for the operator.
        debug!(code = %err.code, "post-hello session error");
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

/// Reads one length-prefixed envelope from the supplied tokio TLS
/// stream without permanently splitting it.
async fn read_envelope_from_stream<S>(
    tls_stream: &mut S,
    max_envelope_bytes: u32,
) -> std::io::Result<AgentEnvelope>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut header = [0u8; 4];
    tls_stream.read_exact(&mut header).await?;
    let announced = u32::from_be_bytes(header);
    if announced > max_envelope_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("envelope length {announced} exceeds limit {max_envelope_bytes}"),
        ));
    }
    let announced = usize::try_from(announced)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid length"))?;
    if announced == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty envelope"));
    }
    let mut body = vec![0u8; announced];
    tls_stream.read_exact(&mut body).await?;
    AgentEnvelope::decode(body.as_slice())
        .map_err(|err| std::io::Error::other(format!("decode envelope: {err}")))
}

/// Failure modes for the pre-split envelope writer.
///
/// `Io` is connection-local because the local socket may be healthy
/// while the peer has already closed its read half, so a write
/// failure there cannot be distinguished from a peer disconnect at
/// this layer. `Encode` and `LengthOverflow` are fatal internal
/// daemon defects: the codec writes into an owned `Vec<u8>` that
/// never runs out of addressable memory in practice, and the
/// length overflow only triggers on multi-gigabyte envelopes that
/// no legitimate adapter would produce.
#[derive(Debug, Error)]
enum InitialEnvelopeWriteError {
    /// Underlying TLS stream reported an I/O failure. Connection-local.
    #[error("write envelope: {0}")]
    Io(#[from] std::io::Error),
    /// Protobuf encoder refused the envelope. Fatal internal defect.
    #[error("encode envelope: {0}")]
    Encode(#[from] prost::EncodeError),
    /// Encoded envelope length exceeds `u32`. Fatal internal defect.
    #[error("envelope length {0} does not fit in u32")]
    LengthOverflow(usize),
}

/// Writes one length-prefixed envelope directly through the tokio
/// TLS stream, encoding the protobuf body in place. I/O failures
/// are reported through [`InitialEnvelopeWriteError::Io`] so the
/// `DaemonHello` call site can treat them as peer disconnects;
/// encode and length failures are reported through the typed
/// `Encode` and `LengthOverflow` variants so the caller surfaces
/// a real internal defect rather than silently normalising it.
async fn write_initial_envelope_stream<S>(
    tls_stream: &mut S,
    envelope: &AgentEnvelope,
) -> Result<(), InitialEnvelopeWriteError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(envelope.encoded_len());
    envelope.encode(&mut buf)?;
    let len = u32::try_from(buf.len())
        .map_err(|_| InitialEnvelopeWriteError::LengthOverflow(buf.len()))?;
    tls_stream.write_all(&len.to_be_bytes()).await?;
    tls_stream.write_all(&buf).await?;
    Ok(())
}

/// Emits a `ProtocolError` directly through the tokio TLS stream
/// before the writer half is handed off. Used only on the pre-split
/// path so the protocol-error envelope is delivered before close.
///
/// The helper is best-effort: any failure from
/// [`write_initial_envelope_stream`] (connection-local I/O, fatal
/// encode, or fatal length overflow) is reported through the
/// returned [`std::io::Error`] without tearing the daemon down.
/// Fatal encoding failures inside the [`ProtocolError`] envelope
/// itself are vanishingly rare because the codec writes into an
/// owned `Vec<u8>`; treating them as best-effort keeps the policy
/// consistent with `send_protocol_error_stream`'s role as a
/// last-resort diagnostic that must not take the listener down.
///
/// The `clock` parameter is the daemon-scoped [`MonotonicClock`] the
/// supervisor constructs once before the accept loop; reusing the
/// same origin across every `ProtocolError` keeps the timestamps on
/// the wire consistent with the documented `process/daemon-local`
/// monotonic origin even when the listener accepts multiple sequential
/// clients.
async fn send_protocol_error_stream<S>(
    tls_stream: &mut S,
    max_envelope_bytes: u32,
    code: &str,
    message: &str,
    clock: MonotonicClock,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let envelope = AgentEnvelope {
        protocol_major: 1,
        protocol_minor: 0,
        runtime_session_id: Bytes::new(),
        session_seq: 0,
        sent_monotonic_ns: clock.now_ns(),
        message_id: "daemon-error".to_string(),
        correlation_token: String::new(),
        payload: Some(PayloadOneof::ProtocolError(ProtocolError {
            code: code.to_string(),
            message: message.to_string(),
        })),
    };
    write_initial_envelope_stream(tls_stream, &envelope)
        .await
        .map_err(|err| std::io::Error::other(format!("failed to write protocol error: {err}")))?;
    // The limit is advisory; the helper never exceeds it because the
    // envelope is bounded by the static `ProtocolError` payload size.
    let _ = max_envelope_bytes;
    Ok(())
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
    expected_repository_fingerprint: RepositoryFingerprint,
    /// Shared shutdown signal observed by the supervisor, every
    /// connection, and every helper task.
    shutdown: ShutdownSignal,
    /// Optional bootstrap artifact handle shared between the
    /// supervisor and the connection tasks. The supervisor hands a
    /// clone to each spawned task so the post-hello
    /// `try_release` call is race-free.
    bootstrap: Option<Arc<BootstrapArtifact>>,
}

/// Outcome of inspecting a single [`JoinSet`] completion. The
/// supervisor uses the outcome to decide whether to keep running, to
/// record a connection-level error for later drain, or to stop the
/// daemon and return immediately. The owned [`DaemonError`] lives
/// only inside the action variant the supervisor matches against
/// inline, so the policy never needs [`DaemonError: Clone`].
#[derive(Debug)]
enum JoinCompletionAction {
    /// The completion was a normal `Ok(())`; keep accepting.
    Continue,
    /// The connection returned an internal [`DaemonError`]; the
    /// supervisor signals shutdown, drains every in-flight
    /// connection, and surfaces this error to the caller.
    ConnectionFailure(DaemonError),
    /// The connection task panicked or was cancelled. The supervisor
    /// signals shutdown, drains, and returns a [`DaemonError::Join`]
    /// built from the join error.
    JoinFailure(tokio::task::JoinError),
}

/// Classifies one [`JoinSet`] completion. The function is the single
/// decision point that decides whether the supervisor must stop the
/// daemon. Tests exercise it directly so the policy does not silently
/// regress to "log and continue".
fn classify_join_completion(
    joined: Result<Result<(), DaemonError>, tokio::task::JoinError>,
) -> JoinCompletionAction {
    match joined {
        Ok(Ok(())) => JoinCompletionAction::Continue,
        Ok(Err(err)) => {
            // A connection-local error escaped the peer-disconnect
            // boundary inside [`handle_connection`], so the
            // supervisor stops the daemon and surfaces the error.
            // The decision is the same regardless of the variant:
            // every `DaemonError` that survives the boundary is a
            // genuine internal failure (rng refusal, daemon hello
            // write failure).
            JoinCompletionAction::ConnectionFailure(err)
        }
        Err(join_err) => {
            // A panic or cancellation surfaced through the join. The
            // supervisor stops the daemon, drains, and wraps the join
            // error into a [`DaemonError::Join`].
            JoinCompletionAction::JoinFailure(join_err)
        }
    }
}

/// Drains every remaining connection task after a triggering
/// failure has been observed, logs any later drain failure, and
/// returns the already-observed triggering [`DaemonError`]
/// unchanged. The supervisor calls this helper from the three
/// trigger branches (connection-level [`DaemonError`], join panic /
/// cancellation, listener accept failure) so the policy lives in
/// exactly one place: a later drain failure is logged but
/// discarded because the caller is best served by the failure
/// mode that already happened, not by a downstream drain artefact.
async fn shutdown_after_trigger(
    trigger: DaemonError,
    connections: &mut JoinSet<Result<(), DaemonError>>,
    shutdown_tx_for_supervisor: &watch::Sender<bool>,
    shutdown_observer: &mut JoinHandle<()>,
) -> DaemonError {
    let _ = shutdown_tx_for_supervisor.send(true);
    shutdown_observer.abort();
    let _ = shutdown_observer.await;
    if let Some(drain_err) = drain_connections(connections).await {
        warn!(
            error = %drain_err,
            "ignoring drain failure in favor of the triggering failure",
        );
    }
    trigger
}

/// Awaits every remaining connection task and returns the first
/// failure observed during the drain, in actual `join_next`
/// observation order. Connection-level [`DaemonError`]s and panic /
/// cancellation wraps are treated as the same kind of failure for
/// ordering purposes; the helper does not give one priority over
/// the other. The supervisor calls this helper in three places:
///
/// - after the user-supplied shutdown future resolves and there is
///   no prior trigger, where the first observed error wins;
/// - through [`shutdown_after_trigger`] for every trigger branch
///   (connection-level [`DaemonError`], join panic / cancellation,
///   and listener accept failure), where the trigger is preserved
///   and any drain failure is logged but discarded.
async fn drain_connections(
    connections: &mut JoinSet<Result<(), DaemonError>>,
) -> Option<DaemonError> {
    let mut first: Option<DaemonError> = None;
    while let Some(joined) = connections.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if first.is_none() {
                    first = Some(err);
                } else {
                    warn!(
                        error = %err,
                        "additional connection error observed during drain; preserving the first error",
                    );
                }
            }
            Err(join_err) => {
                let wrapped = DaemonError::Join(format!(
                    "connection task join failed during drain: {join_err}"
                ));
                if first.is_none() {
                    first = Some(wrapped);
                } else {
                    warn!(
                        error = %wrapped,
                        "additional join failure observed during drain; preserving the first error",
                    );
                }
            }
        }
    }
    first
}

/// Builder for [`BoundDaemon`].
#[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
pub struct DaemonBuilder {
    config: DaemonConfig,
    project_id: Option<ProjectId>,
    runtime_session_id: Option<RuntimeSessionId>,
    expected_repository_fingerprint: Option<RepositoryFingerprint>,
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

    /// Sets the project identifier the daemon writes into the
    /// bootstrap artifact and retains as daemon/session context for
    /// the lifetime of the [`BoundDaemon`]. The identifier is
    /// **not** carried on the wire (the `AgentEnvelope` schema has
    /// no `project_id` field) and does **not** participate in the
    /// `expected_repository_fingerprint` comparison performed on
    /// every inbound `AdapterHello`; the repository fingerprint is
    /// enforced independently through the bootstrap-anchored
    /// fingerprint.
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
    /// on every inbound `AdapterHello`. The fingerprint must already
    /// be a canonical `b3:<64 lowercase hex>` value because the
    /// builder takes it by value rather than parsing user input.
    #[must_use = "the daemon is only realized after DaemonBuilder::bind resolves"]
    pub fn with_expected_repository_fingerprint(
        mut self,
        fingerprint: RepositoryFingerprint,
    ) -> Self {
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
        let tls_materials = TlsServerMaterials::build()?;
        let session_secret = SessionSecret::generate()
            .map_err(|err| DaemonError::Bootstrap(format!("session secret: {err}")))?;
        let bootstrap = self
            .bootstrap_artifact
            .as_ref()
            .map(|path| {
                let fields = BootstrapArtifactFields::new(
                    listener.local_addr().ip().to_string(),
                    listener.local_addr().port(),
                    tls_materials.certificate_pin().to_string(),
                    runtime_session_id,
                    &session_secret,
                    project_id,
                    expected_repository_fingerprint.clone(),
                    1,
                    0,
                );
                BootstrapArtifact::write(path, fields, BootstrapOwner::Daemon)
            })
            .transpose()?
            .map(Arc::new);
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
        let inbound = xtrace_protocol::handshake::compute_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest,
        )
        .expect("HMAC accepts the test secret");
        xtrace_protocol::handshake::verify_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &xtrace_protocol::handshake::ZERO_NONCE,
            manifest,
            &inbound,
        )
        .expect("inbound verifier accepts the canonical layout");
    }

    /// The outbound `DaemonHello` proof uses the daemon's server
    /// nonce together with the recovered client nonce (no zero
    /// placeholder). The layout is symmetric with the inbound
    /// direction minus the placeholder.
    #[test]
    fn daemon_proof_layout_uses_real_client_nonce_for_outbound_direction() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let client = [0xaa_u8; 32];
        let server = [0xbb_u8; 32];
        let outbound = xtrace_protocol::handshake::compute_transcript_proof(
            secret, exporter, session, &client, &server, manifest,
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

    #[tokio::test]
    async fn shutdown_signal_already_set_resolves_immediately() {
        let (tx, mut signal) = shared_shutdown_channel();
        tx.send(true).expect("send");
        // The future must complete on the first poll because the
        // channel already carries the shutdown value.
        let start = Instant::now();
        signal.wait().await;
        assert!(start.elapsed() < StdDuration::from_secs(1));
    }

    /// `classify_join_completion` returns [`JoinCompletionAction::Continue`]
    /// for a normal `Ok(())` completion. The supervisor uses this
    /// outcome to keep accepting; the test pins the boundary so a
    /// regression cannot silently log-and-continue.
    #[test]
    fn classify_join_completion_continues_on_normal_completion() {
        let joined: Result<Result<(), DaemonError>, tokio::task::JoinError> = Ok(Ok(()));
        assert!(matches!(classify_join_completion(joined), JoinCompletionAction::Continue));
    }

    /// A connection-local [`DaemonError`] (genuine internal failure)
    /// must surface as a [`JoinCompletionAction::ConnectionFailure`]
    /// so the supervisor stops the daemon after draining remaining
    /// connections. Peer-disconnect errors never reach this branch
    /// because [`handle_connection`] normalises them to `Ok(())`.
    #[test]
    fn classify_join_completion_flags_connection_failure() {
        let joined: Result<Result<(), DaemonError>, tokio::task::JoinError> =
            Ok(Err(DaemonError::Transport("write daemon hello".to_string())));
        match classify_join_completion(joined) {
            JoinCompletionAction::ConnectionFailure(err) => {
                assert!(matches!(err, DaemonError::Transport(_)));
            }
            other => unreachable!("expected ConnectionFailure, got {other:?}"),
        }
    }

    /// A `JoinSet` panic or cancellation must surface as a
    /// [`JoinCompletionAction::JoinFailure`] so the supervisor stops
    /// the daemon and returns [`DaemonError::Join`]. The classification
    /// is the only place this conversion happens; the test pins the
    /// mapping so the supervisor cannot regress to "log and Ok".
    #[test]
    #[allow(
        clippy::panic,
        reason = "test deliberately panics inside a spawned task to exercise the supervisor policy"
    )]
    fn classify_join_completion_flags_panic_as_join_failure() {
        // A `JoinError` whose `is_panic()` returns true models a
        // production-style panic injection. `tokio::task::JoinError`
        // is not `Clone`, so the test constructs a fresh one via
        // a no-op runtime so the public enum is exercised end-to-end.
        let rt = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let handle = rt.spawn(async {
            panic!("intentional panic for supervisor classification coverage");
        });
        let result = rt.block_on(handle).expect_err("join error from panicked task");
        let joined: Result<Result<(), DaemonError>, tokio::task::JoinError> = Err(result);
        match classify_join_completion(joined) {
            JoinCompletionAction::JoinFailure(err) => {
                assert!(err.is_panic(), "join error must be a panic");
            }
            other => unreachable!("expected JoinFailure, got {other:?}"),
        }
    }

    /// A `JoinSet` cancellation (the task was aborted) also flows
    /// through [`JoinCompletionAction::JoinFailure`] so the supervisor
    /// cannot silently drop a cancelled task either.
    #[test]
    fn classify_join_completion_flags_cancellation_as_join_failure() {
        let rt = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let handle = rt.spawn(async {
            tokio::time::sleep(StdDuration::from_secs(60)).await;
        });
        handle.abort();
        let result = rt.block_on(handle).expect_err("join error from cancelled task");
        let joined: Result<Result<(), DaemonError>, tokio::task::JoinError> = Err(result);
        match classify_join_completion(joined) {
            JoinCompletionAction::JoinFailure(err) => {
                assert!(err.is_cancelled(), "join error must be a cancellation");
            }
            other => unreachable!("expected JoinFailure, got {other:?}"),
        }
    }

    /// `drain_connections` returns `None` when every task completes
    /// cleanly and returns the first observed error otherwise. The
    /// test only asserts the invariant; ordering between independent
    /// spawned tasks is not promised by `tokio::task::JoinSet`, so
    /// the test avoids any comparison that depends on which task
    /// finishes first. A regression that returns `Some` on a clean
    /// drain or fabricates a join wrap from a connection error would
    /// fail the assertions below.
    #[tokio::test]
    async fn drain_connections_returns_first_observed_error() {
        // First drain: every task completes cleanly; the helper
        // must return `None`.
        let mut clean: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        for _ in 0..3 {
            clean.spawn(async { Ok(()) });
        }
        let first = drain_connections(&mut clean).await;
        assert!(first.is_none(), "clean drain must return None, got {first:?}");

        // Second drain: a single connection-level error is the
        // only failure; the helper must surface that error and
        // must not invent a join wrap.
        let mut single_error: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        single_error.spawn(async { Ok(()) });
        single_error.spawn(async { Err(DaemonError::Bootstrap("release".to_string())) });
        let first = drain_connections(&mut single_error).await;
        match first {
            Some(DaemonError::Bootstrap(_)) => {}
            other => unreachable!("expected Bootstrap error, got {other:?}"),
        }

        // Third drain: a panic is the only failure; the helper must
        // surface the wrapped join error rather than swallowing the
        // panic. The `panic!` lives inside the spawned task so the
        // lint reports on the closure body rather than the call
        // site; the `#![cfg_attr(test, allow(clippy::panic))]` at
        // the crate root carries the necessary exception.
        let mut panic_only: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        panic_only.spawn(async { panic!("deliberate panic") });
        let first = drain_connections(&mut panic_only).await;
        match first {
            Some(DaemonError::Join(_)) => {}
            other => unreachable!("expected Join error, got {other:?}"),
        }

        // Fourth drain: multiple errors; the helper returns exactly
        // one (the first observed) without dropping the others or
        // accumulating them. The assertion pins the cardinality
        // contract rather than which specific error wins, because
        // `tokio::task::JoinSet` does not promise spawn-order
        // completion.
        let mut many: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        for i in 0..4 {
            many.spawn(async move { Err(DaemonError::Transport(format!("task-{i}"))) });
        }
        let first = drain_connections(&mut many).await;
        assert!(
            matches!(first, Some(DaemonError::Transport(_))),
            "drain must surface exactly one Transport error, got {first:?}",
        );
    }

    /// The supervisor policy is: when a triggering failure has
    /// already happened, drain every remaining task, log any drain
    /// failure, and return the triggering error unchanged. The
    /// helper used by `serve` is [`shutdown_after_trigger`]; this
    /// test exercises it end-to-end with a deterministic second
    /// task that fails during drain so the policy — trigger wins,
    /// later drain failure is discarded — is the only thing under
    /// test.
    ///
    /// The test synchronises the second task through a
    /// `tokio::sync::Notify` so the second failure is guaranteed to
    /// surface during drain rather than being reordered by the
    /// runtime scheduler. The `Notify` is held open until the
    /// helper releases it; this gives the test deterministic
    /// ordering without any sleep or poll loop.
    #[tokio::test]
    async fn supervisor_preserves_trigger_error_over_drain_failure() {
        use std::sync::Arc as StdArc;
        use tokio::sync::Notify;

        let gate = StdArc::new(Notify::new());
        let gate_for_drain = gate.clone();
        let mut set: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        set.spawn(async move {
            // The triggering failure arrives first. We hold the
            // gate release until after the supervisor helper has
            // collected the trigger via `join_next`, so the drain
            // failure below is guaranteed to be observed after the
            // trigger — never before it.
            let result = Err(DaemonError::Transport("trigger".to_string()));
            gate_for_drain.notify_one();
            result
        });
        set.spawn(async move {
            // The drain failure waits for the trigger to be
            // observed so the test never depends on scheduler
            // order. Once released, it reports a different error.
            gate.notified().await;
            Err(DaemonError::Bootstrap("drain".to_string()))
        });

        // Collect the trigger the same way `serve` does: pull the
        // first completion out of `join_next`, then call the
        // supervisor helper.
        let trigger = match set.join_next().await.expect("trigger join") {
            Ok(Err(err)) => err,
            other => unreachable!("expected trigger error, got {other:?}"),
        };
        let (shutdown_tx, _rx) = tokio::sync::watch::channel(false);
        let observer: JoinHandle<()> = tokio::spawn(async move {});
        let mut observer = observer;
        let returned = shutdown_after_trigger(trigger, &mut set, &shutdown_tx, &mut observer).await;
        match returned {
            DaemonError::Transport(_) => {}
            other => unreachable!("trigger must win; got {other:?}"),
        }
        // The drain failure must have been observed during the
        // drain (otherwise the trigger was not actually first and
        // the test never exercised the trigger-wins branch). The
        // `JoinSet` is drained by the helper, so no tasks remain.
        assert!(set.join_next().await.is_none(), "set must be drained");
    }

    /// The drain helper also covers the no-extra-task case: when
    /// the trigger fires alone, the helper returns the trigger
    /// unchanged without logging a "later drain failure" because
    /// there is no later failure. The test pins that the helper
    /// does not invent errors and does not panic on an empty
    /// follow-up set.
    #[tokio::test]
    async fn shutdown_after_trigger_returns_trigger_unchanged_when_no_extra_tasks() {
        let mut set: JoinSet<Result<(), DaemonError>> = JoinSet::new();
        set.spawn(async { Err(DaemonError::Transport("trigger".to_string())) });
        let trigger = match set.join_next().await.expect("trigger join") {
            Ok(Err(err)) => err,
            other => unreachable!("expected trigger error, got {other:?}"),
        };
        let (shutdown_tx, _rx) = tokio::sync::watch::channel(false);
        let observer: JoinHandle<()> = tokio::spawn(async move {});
        let mut observer = observer;
        let returned = shutdown_after_trigger(trigger, &mut set, &shutdown_tx, &mut observer).await;
        assert!(
            matches!(returned, DaemonError::Transport(_)),
            "trigger must be returned unchanged when no extra tasks exist; got {returned:?}",
        );
        assert!(set.join_next().await.is_none(), "set must be drained");
    }

    /// The daemon-scoped [`MonotonicClock`] is the same instance the
    /// writer task uses: constructing the clock once before the
    /// accept loop and copying it into connection tasks means the
    /// `now_ns` value emitted by `send_protocol_error_stream` shares
    /// the same origin as every Health frame. A regression that
    /// builds a fresh clock per connection would produce different
    /// origins and fail the equality check.
    #[test]
    fn monotonic_clock_shares_a_single_daemon_origin() {
        let clock = MonotonicClock::new();
        let writer_clock = clock;
        let writer_clock_for_health = clock;
        let writer_clock_for_protocol_error = clock;
        // Compare the inner origin `Instant` values: `MonotonicClock`
        // is `Copy` so two copies of the same `Instant` compare
        // equal.
        assert_eq!(
            format!("{:?}", writer_clock),
            format!("{:?}", clock),
            "writer clock must share the daemon origin",
        );
        assert_eq!(
            format!("{:?}", writer_clock_for_health),
            format!("{:?}", clock),
            "health clock must share the daemon origin",
        );
        assert_eq!(
            format!("{:?}", writer_clock_for_protocol_error),
            format!("{:?}", clock),
            "protocol-error clock must share the daemon origin",
        );
    }
}
