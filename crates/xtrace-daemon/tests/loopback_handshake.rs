//! End-to-end loopback integration coverage.
//!
//! These tests bring up a real [`BoundDaemon`] on the OS-assigned
//! loopback port, connect with a real rustls client configured to
//! pin the daemon's certificate, exercise the `AdapterHello` /
//! `DaemonHello` transcript proof over the negotiated TLS 1.3
//! channel, and exchange post-hello traffic. Every test runs against
//! the live [`BoundDaemon::serve`] future so the post-hello
//! writer-task split and the bounded outbound capacity are exercised
//! for real, not stubbed out.
//!
//! The Slice 1B acceptance criteria this file proves:
//!
//! - the daemon binds loopback only and refuses any other bind
//!   address through the production [`xtrace_daemon::validate_loopback`]
//!   entry point;
//! - the ephemeral certificate is pinned through a real rustls
//!   verifier so a different daemon certificate never connects
//!   (verified via TLS verification failure, not connection refusal);
//! - the per-connection TLS exporter is folded into the
//!   `AdapterHello`/`DaemonHello` HMAC transcript proof rather than
//!   a placeholder;
//! - a wrong transcript proof (different client nonce / wrong
//!   secret / wrong manifest) is rejected with
//!   `XTR-DAEMON-HELLO-PROOF`;
//! - the bootstrap artifact is owner-only, contains the right pin
//!   and the expected repository fingerprint, and is removed on
//!   orderly shutdown;
//! - the supervisor stops accepting, cancels every connection, and
//!   joins every task while a live authenticated client is still
//!   connected;
//! - the daemon rejects an `AdapterHello` that does not match the
//!   expected repository fingerprint or has an incompatible
//!   protocol version;
//! - the runtime `Ack` for an accepted envelope has an empty
//!   `rejected` list and a stable `XTR-DAEMON-SESSION-SEQUENCE`
//!   rejection for replay or gap;
//! - the bounded outbound capacity of 1 still delivers every ACK
//!   under a timeout without deadlock (regression coverage for the
//!   pre-fix reader/writer deadlock).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert on fallible fixture data and supervisor paths"
)]

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use prost::bytes::Bytes;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use xtrace_daemon::bootstrap::{BootstrapArtifact, BootstrapArtifactFields};
use xtrace_daemon::listener::validate_loopback;

use xtrace_application::recording::{
    BeginRecording, BeginRecordingDisposition, BeginRecordingReceipt,
    DEFAULT_MAX_RETAINED_RECORDINGS, FinishRecording, FinishRecordingReceipt, RecordEvents,
    RecordEventsReceipt, RecordingCapture, SegmentPolicy,
};
use xtrace_application::recording_queries::{RecordingReadPort, ShowWindowRequest};
use xtrace_application::{PortError, PortErrorKind, ProjectRepository};
use xtrace_daemon::{
    BoundDaemon, DaemonBuilder, DaemonConfig, DaemonError, HandshakeInputs, HandshakeRole,
    LoopbackPolicy, OutboundCapacity, Session, SessionSecret, TLS_EXPORTER_LABEL,
    build_pinned_client_config,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    Project, ProjectId, RecordingId, RepositoryFingerprint as DomainFingerprint,
    RepositoryFingerprint, RuntimeSessionId, WallTime,
};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    AckDurability, AdapterHello, AgentEnvelope, Capability, CapabilitySet, EventBatch, Health,
    ProtocolError, RecordingEvent, RecordingFinished, RecordingStarted,
};
use xtrace_protocol::handshake;
use xtrace_protocol::xtf::XtfEventEnvelope;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

/// Canonical fingerprint used by every happy-path integration test.
/// The value is the canonical `b3:<64 lowercase hex>` form produced
/// by `RepositoryFingerprint::from_canonical_path`; tests pass it
/// through `try_from_canonical` so any malformed input would be
/// rejected at the daemon boundary.
const EXPECTED_REPOSITORY_FINGERPRINT: &str =
    "b3:1111111111111111111111111111111111111111111111111111111111111111";

/// Distinct canonical fingerprint used by the wrong-binding test.
const WRONG_REPOSITORY_FINGERPRINT: &str =
    "b3:2222222222222222222222222222222222222222222222222222222222222222";

/// Canonical manifest digest carried in the AdapterHello transcript.
/// The value is intentionally distinct from the certificate pin so
/// the happy path cannot conflate the two identities.
const HAPPY_MANIFEST_DIGEST: &str =
    "b3:3333333333333333333333333333333333333333333333333333333333333333";

/// Default budget for any helper that waits for the daemon to emit
/// an `Ack` or `ProtocolError`. The bounded deadline makes a
/// regression fail rather than hang the test suite forever.
const READ_ENVELOPE_BUDGET: Duration = Duration::from_secs(5);

fn expected_fingerprint() -> DomainFingerprint {
    DomainFingerprint::try_from_canonical(EXPECTED_REPOSITORY_FINGERPRINT)
        .expect("canonical fingerprint")
}

/// Builds a fresh daemon bound to loopback with a TLS 1.3-only
/// configuration. Returns the bound daemon, the bootstrap secret it
/// wrote, the runtime session identifier, the project identifier,
/// the local address, and the certificate pin. Tests use the
/// bootstrap artifact to read the session secret so the daemon's
/// private key never leaves the daemon process.
async fn spawn_daemon(
    bootstrap_path: std::path::PathBuf,
    health_interval: Duration,
    outbound_capacity: usize,
    repository_fingerprint: &DomainFingerprint,
    project_id: ProjectId,
    runtime_session_id: RuntimeSessionId,
) -> Result<
    (BoundDaemon, SessionSecret, RuntimeSessionId, ProjectId, std::net::SocketAddr, String),
    DaemonError,
> {
    let mut config = DaemonConfig {
        loopback_policy: LoopbackPolicy::V4Only,
        health_interval,
        ..DaemonConfig::default()
    };
    config.outbound_capacity = OutboundCapacity::new(outbound_capacity).unwrap_or_default();
    let bound = DaemonBuilder::new(config)
        .with_project_id(project_id)
        .with_runtime_session_id(runtime_session_id)
        .with_expected_repository_fingerprint(repository_fingerprint.clone())
        .with_bootstrap_artifact(bootstrap_path.clone())
        .bind()
        .await?;
    let secret = read_bootstrap_secret(&bootstrap_path);
    let address = bound.local_addr();
    let pin = bound.certificate_pin().to_string();
    Ok((bound, secret, runtime_session_id, project_id, address, pin))
}

async fn spawn_daemon_with_capture(
    bootstrap_path: std::path::PathBuf,
    health_interval: Duration,
    outbound_capacity: usize,
    repository_fingerprint: &DomainFingerprint,
    project_id: ProjectId,
    runtime_session_id: RuntimeSessionId,
    capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>>,
) -> Result<
    (BoundDaemon, SessionSecret, RuntimeSessionId, ProjectId, std::net::SocketAddr, String),
    DaemonError,
> {
    let mut config = DaemonConfig {
        loopback_policy: LoopbackPolicy::V4Only,
        health_interval,
        ..DaemonConfig::default()
    };
    config.outbound_capacity = OutboundCapacity::new(outbound_capacity).unwrap_or_default();
    let bound = DaemonBuilder::new(config)
        .with_project_id(project_id)
        .with_runtime_session_id(runtime_session_id)
        .with_expected_repository_fingerprint(repository_fingerprint.clone())
        .with_bootstrap_artifact(bootstrap_path.clone())
        .with_recording_capture(capture)
        .bind()
        .await?;
    let secret = read_bootstrap_secret(&bootstrap_path);
    let address = bound.local_addr();
    let pin = bound.certificate_pin().to_string();
    Ok((bound, secret, runtime_session_id, project_id, address, pin))
}

/// Reads the bootstrap artifact from disk and returns the session
/// secret it carried. Production adapters read the bootstrap
/// directly; this helper is the integration-test analogue that lets
/// the test driver stay out of the daemon crate's private state.
fn read_bootstrap_secret(path: &std::path::Path) -> SessionSecret {
    let artifact = BootstrapArtifact::read(path).expect("read bootstrap");
    artifact.fields().session_secret().expect("decoded secret")
}

/// Drives the daemon on the current tokio runtime until the
/// supplied shutdown future resolves. Returns the join error so
/// callers can assert on cancellation/panic behaviour.
async fn drive_until_shutdown<F>(bound: BoundDaemon, shutdown: F) -> Result<(), DaemonError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    bound.serve(shutdown).await
}

/// Runs the daemon on a background task and returns a oneshot
/// shutdown trigger plus a join handle. Tests use this to bring the
/// daemon up without leaking a tokio task.
fn daemon_task(
    bound: BoundDaemon,
) -> (tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<Result<(), DaemonError>>) {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        drive_until_shutdown(bound, async move {
            let _ = rx.await;
        })
        .await
    });
    (tx, handle)
}

/// Builds the `AdapterHello` envelope for the supplied parameters
/// using the documented two-proof nonce-ordering layout. The
/// inbound direction substitutes the documented zero server nonce
/// placeholder; the adapter does not yet know the daemon's nonce.
#[allow(
    clippy::too_many_arguments,
    reason = "test helper threads each transcript field through independently"
)]
fn build_adapter_hello(
    secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &RuntimeSessionId,
    manifest_digest: &str,
    client_nonce: &[u8],
    repository_fingerprint: &str,
    protocol_major_max: u32,
    protocol_minor_max: u32,
) -> AdapterHello {
    let proof = handshake::compute_transcript_proof(
        secret,
        tls_exporter,
        runtime_session_id.as_uuid().as_bytes(),
        client_nonce,
        &handshake::ZERO_NONCE,
        manifest_digest.as_bytes(),
    )
    .expect("HMAC accepts the test secret");
    AdapterHello {
        adapter_name: "fake-integration".to_string(),
        adapter_version: "0.0.0".to_string(),
        adapter_build_hash: String::new(),
        signing_identity: String::new(),
        manifest_digest: manifest_digest.to_string(),
        language: "rust".to_string(),
        runtime_name: "test".to_string(),
        runtime_version: "0.0.0".to_string(),
        pid: 0,
        process_start_monotonic_ns: 0,
        parent_launch_id: String::new(),
        repository_fingerprint: repository_fingerprint.to_string(),
        protocol_major_max,
        protocol_minor_max,
        client_nonce: prost::bytes::Bytes::copy_from_slice(client_nonce),
        hmac: prost::bytes::Bytes::copy_from_slice(&proof),
    }
}

/// Computes the `DaemonHello` proof that the adapter side would
/// recompute when validating the daemon's reply. The function uses
/// the documented real-nonce outbound direction: no zero nonce
/// placeholder, both nonces are the actual values.
#[allow(
    clippy::too_many_arguments,
    reason = "test helper threads each transcript field through independently"
)]
fn compute_expected_daemon_proof(
    secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &RuntimeSessionId,
    server_nonce: &[u8],
    client_nonce: &[u8],
    manifest_digest: &str,
) -> [u8; 32] {
    handshake::compute_transcript_proof(
        secret,
        tls_exporter,
        runtime_session_id.as_uuid().as_bytes(),
        client_nonce,
        server_nonce,
        manifest_digest.as_bytes(),
    )
    .expect("HMAC accepts the test secret")
}

/// Encodes an envelope with the supplied payload using the
/// documented 4-byte big-endian length prefix.
async fn write_envelope<W>(
    writer: &mut W,
    payload: PayloadOneof,
    session_id: &RuntimeSessionId,
    seq: u64,
    monotonic_ns: u64,
) -> Result<(), std::io::Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let envelope = AgentEnvelope {
        protocol_major: 1,
        protocol_minor: 0,
        runtime_session_id: prost::bytes::Bytes::copy_from_slice(session_id.as_uuid().as_bytes()),
        session_seq: seq,
        sent_monotonic_ns: monotonic_ns,
        message_id: format!("test-{seq}"),
        correlation_token: String::new(),
        payload: Some(payload),
    };
    let mut buf = Vec::with_capacity(envelope.encoded_len());
    envelope
        .encode(&mut buf)
        .map_err(|err| std::io::Error::other(format!("encode envelope: {err}")))?;
    let len = u32::try_from(buf.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "envelope too large"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&buf).await?;
    Ok(())
}

/// Reads one length-prefixed envelope from the supplied stream. The
/// reader rejects any announced length above 1 MiB before
/// allocating, matching the daemon's own codec.
async fn read_envelope<R>(reader: &mut R) -> Result<AgentEnvelope, std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let announced = u32::from_be_bytes(header);
    if announced > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("envelope length {announced} exceeds limit"),
        ));
    }
    let announced = usize::try_from(announced)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad length"))?;
    let mut body = vec![0u8; announced];
    reader.read_exact(&mut body).await?;
    AgentEnvelope::decode(body.as_slice())
        .map_err(|err| std::io::Error::other(format!("decode envelope: {err}")))
}

/// Reads one length-prefixed envelope from the supplied stream with
/// a bounded [`READ_ENVELOPE_BUDGET`]. Tests use this in place of
/// [`read_envelope`] whenever a single envelope is expected so a
/// regression that hangs the reader surfaces as a test failure
/// rather than a CI hang.
async fn read_envelope_bounded<R>(reader: &mut R, label: &str) -> AgentEnvelope
where
    R: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(READ_ENVELOPE_BUDGET, read_envelope(reader)).await {
        Ok(Ok(env)) => env,
        Ok(Err(err)) => panic!("{label}: read failed: {err}"),
        Err(_) => panic!("{label}: timed out waiting for envelope after {READ_ENVELOPE_BUDGET:?}"),
    }
}

/// Reads envelopes from the supplied stream until the next `Ack`
/// payload arrives, dropping any intervening `Health` echoes from
/// the daemon's periodic ticker. The helper makes the post-hello
/// happy path deterministic when the daemon emits a Health between
/// the adapter's outbound messages. A bounded [`READ_ENVELOPE_BUDGET`]
/// makes the helper fail rather than hang when the daemon never
/// delivers the expected payload.
async fn next_ack<R>(reader: &mut R, label: &str) -> xtrace_protocol::generated::agent::Ack
where
    R: tokio::io::AsyncRead + Unpin,
{
    let start = std::time::Instant::now();
    loop {
        let envelope = match tokio::time::timeout(
            READ_ENVELOPE_BUDGET.saturating_sub(start.elapsed()),
            read_envelope(reader),
        )
        .await
        {
            Ok(Ok(env)) => env,
            Ok(Err(err)) => panic!("{label}: read failed: {err}"),
            Err(_) => panic!("{label}: timed out waiting for Ack after {READ_ENVELOPE_BUDGET:?}"),
        };
        match envelope.payload {
            Some(PayloadOneof::Ack(ack)) => return ack,
            Some(PayloadOneof::Health(_)) => continue,
            Some(PayloadOneof::ProtocolError(err)) => {
                unreachable!(
                    "unexpected ProtocolError from daemon after {label}: {} {}",
                    err.code, err.message,
                );
            }
            other => unreachable!("expected Ack after {label}, got {other:?}"),
        }
    }
}

/// Reads envelopes from the supplied stream until the next
/// `ProtocolError` arrives, dropping any intervening `Health`
/// echoes from the daemon's periodic ticker. A bounded
/// [`READ_ENVELOPE_BUDGET`] keeps a regression that never delivers
/// the error from hanging the suite.
async fn next_protocol_error<R>(reader: &mut R, label: &str) -> ProtocolError
where
    R: tokio::io::AsyncRead + Unpin,
{
    let start = std::time::Instant::now();
    loop {
        let envelope = match tokio::time::timeout(
            READ_ENVELOPE_BUDGET.saturating_sub(start.elapsed()),
            read_envelope(reader),
        )
        .await
        {
            Ok(Ok(env)) => env,
            Ok(Err(err)) => panic!("{label}: read failed: {err}"),
            Err(_) => panic!(
                "{label}: timed out waiting for ProtocolError after {READ_ENVELOPE_BUDGET:?}"
            ),
        };
        match envelope.payload {
            Some(PayloadOneof::ProtocolError(err)) => return err,
            Some(PayloadOneof::Health(_)) => continue,
            Some(other) => {
                unreachable!("unexpected payload before ProtocolError after {label}: {other:?}")
            }
            None => unreachable!("empty envelope after {label}"),
        }
    }
}

/// Spawns a pinned rustls client connection against the supplied
/// loopback address. The TLS 1.3 channel is established before the
/// caller exchanges any XTP envelopes.
async fn connect_pinned(
    address: std::net::SocketAddr,
    pin: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let config = build_pinned_client_config(pin)
        .map_err(|err| std::io::Error::other(format!("pinned client config: {err}")))?;
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        rustls_pki_types::ServerName::IpAddress(rustls_pki_types::IpAddr::from(address.ip()));
    let stream = TcpStream::connect(address).await?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|err| std::io::Error::other(format!("tls connect: {err}")))
}

async fn connect_authenticated(
    address: std::net::SocketAddr,
    pin: &str,
    secret: &SessionSecret,
    session_id: &RuntimeSessionId,
    client_nonce: &[u8; 32],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut tls_stream = connect_pinned(address, pin).await.expect("pinned connect");
    let mut exporter = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        session_id,
        HAPPY_MANIFEST_DIGEST,
        client_nonce,
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(hello), session_id, 0, 1)
        .await
        .expect("write AdapterHello");
    let daemon_hello = read_envelope_bounded(&mut reader, "DaemonHello").await;
    assert!(matches!(daemon_hello.payload, Some(PayloadOneof::DaemonHello(_))));
    drop(reader);
    drop(writer);
    tls_stream
}

#[derive(Default)]
struct ObservedCapture {
    operations: std::sync::Mutex<Vec<&'static str>>,
    fail_next_begin: std::sync::atomic::AtomicBool,
}

impl ObservedCapture {
    fn operations(&self) -> Vec<&'static str> {
        self.operations.lock().expect("capture operations").clone()
    }
}

impl RecordingCapture for ObservedCapture {
    type Event = XtfEventEnvelope;

    fn begin_recording(&self, request: BeginRecording) -> Result<BeginRecordingReceipt, PortError> {
        self.operations.lock().expect("capture operations").push("start");
        if self.fail_next_begin.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(PortError::new(
                PortErrorKind::Internal,
                "captured private message that must not go on the wire",
                xtrace_domain::CorrelationId::new(),
            )
            .with_source("private source detail"));
        }
        Ok(BeginRecordingReceipt {
            recording_id: request.recording_id,
            disposition: BeginRecordingDisposition::Inserted,
        })
    }

    fn record_events(
        &self,
        request: RecordEvents<Self::Event>,
    ) -> Result<RecordEventsReceipt, PortError> {
        self.operations.lock().expect("capture operations").push("batch");
        Ok(RecordEventsReceipt { accepted: request.events.len(), ..RecordEventsReceipt::default() })
    }

    fn finish_recording(
        &self,
        request: FinishRecording,
    ) -> Result<FinishRecordingReceipt, PortError> {
        self.operations.lock().expect("capture operations").push("finish");
        Ok(FinishRecordingReceipt {
            recording_id: request.recording_id,
            persisted_segments: 0,
            exact_replay: false,
            completion: xtrace_application::recording::RecordingCompletion::Partial,
        })
    }
}

fn secure_tempdir(prefix: &str) -> TempDir {
    let temp_base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let directory =
        tempfile::Builder::new().prefix(prefix).tempdir_in(temp_base).expect("temp directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("owner-only temp directory");
    }
    directory
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_happy_path_handshake_and_post_hello_traffic() {
    let temp = TempDir::new().expect("temp dir");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let client_nonce = [0x77_u8; 32];

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &client_nonce,
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let daemon_hello_envelope = read_envelope_bounded(&mut reader, "daemon hello").await;
    let daemon_hello = match daemon_hello_envelope.payload {
        Some(PayloadOneof::DaemonHello(hello)) => hello,
        other => unreachable!("expected DaemonHello, got {other:?}"),
    };
    assert_eq!(daemon_hello.protocol_major, 1);
    assert_eq!(daemon_hello.protocol_minor, 0);
    assert_eq!(daemon_hello.max_envelope_bytes, 1024 * 1024);
    assert_eq!(daemon_hello.max_batch_events, 256);
    assert_eq!(daemon_hello.manifest_digest, HAPPY_MANIFEST_DIGEST);
    assert_ne!(
        daemon_hello.manifest_digest, pin,
        "manifest digest must differ from the certificate pin"
    );
    assert_eq!(daemon_hello.server_nonce.len(), 32);
    let expected_proof = compute_expected_daemon_proof(
        secret.read_secret(),
        &exporter,
        &session_id,
        &daemon_hello.server_nonce,
        &client_nonce,
        HAPPY_MANIFEST_DIGEST,
    );
    assert_eq!(
        daemon_hello.hmac.as_ref(),
        expected_proof.as_slice(),
        "DaemonHello HMAC must match the documented real-nonce outbound layout",
    );

    let capabilities = CapabilitySet {
        capabilities: vec![Capability {
            name: "endpoint_discovery".to_string(),
            config: Default::default(),
        }],
    };
    write_envelope(&mut writer, PayloadOneof::CapabilitySet(capabilities), &session_id, 1, 2)
        .await
        .expect("write capability set");
    let ack = next_ack(&mut reader, "ack 1").await;
    assert_eq!(ack.highest_contiguous_session_seq, 1);
    assert!(ack.rejected.is_empty(), "successful ack must carry no rejected messages");

    let health = Health {
        monotonic_ns: 99,
        queue_depth_batches: 0,
        resident_bytes: 0,
        status: "ok".to_string(),
    };
    write_envelope(&mut writer, PayloadOneof::Health(health), &session_id, 2, 3)
        .await
        .expect("write health");
    let ack = next_ack(&mut reader, "ack 2").await;
    assert_eq!(ack.highest_contiguous_session_seq, 2);
    assert!(ack.rejected.is_empty());

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_client_rejects_wrong_certificate_at_tls_verification() {
    // The wrong-pin path connects to a live daemon using a
    // different pin. The test proves the failure happens at TLS
    // verification, not at TCP connect.
    let temp_a = TempDir::new().expect("temp a");
    let temp_b = TempDir::new().expect("temp b");
    let bootstrap_a = temp_a.path().join("bootstrap-a.json");
    let bootstrap_b = temp_b.path().join("bootstrap-b.json");

    let project_id_a = ProjectId::new();
    let session_id_a = RuntimeSessionId::new();
    let first = DaemonBuilder::new(DaemonConfig {
        loopback_policy: LoopbackPolicy::V4Only,
        ..DaemonConfig::default()
    })
    .with_project_id(project_id_a)
    .with_runtime_session_id(session_id_a)
    .with_expected_repository_fingerprint(expected_fingerprint())
    .with_bootstrap_artifact(bootstrap_a.clone())
    .bind()
    .await
    .expect("first bind");
    let first_pin = first.certificate_pin().to_string();

    let second = DaemonBuilder::new(DaemonConfig {
        loopback_policy: LoopbackPolicy::V4Only,
        ..DaemonConfig::default()
    })
    .with_project_id(ProjectId::new())
    .with_runtime_session_id(RuntimeSessionId::new())
    .with_expected_repository_fingerprint(expected_fingerprint())
    .with_bootstrap_artifact(bootstrap_b.clone())
    .bind()
    .await
    .expect("second bind");
    let second_address = second.local_addr();
    // The second daemon stays up so the pinned client can attempt a
    // TLS handshake against a different certificate. We use a
    // channel-based shutdown so the test can stop the daemon at the
    // end without leaking the listener.
    let (second_tx, second_rx) = tokio::sync::oneshot::channel::<()>();
    let second_handle = tokio::spawn(async move {
        second
            .serve(async move {
                let _ = second_rx.await;
            })
            .await
    });

    let (tx, handle) = daemon_task(first);
    let pinned_pin = first_pin.clone();
    let connect = tokio::spawn(async move { connect_pinned(second_address, &pinned_pin).await });
    let connect_result = connect.await.expect("connect task");
    let err = connect_result.expect_err("pin mismatch must fail at TLS verification");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("leaf certificate sha-256 does not match")
            || rendered.contains("tls connect")
            || rendered.contains("certificate"),
        "expected pin mismatch error, got {rendered:?}",
    );

    let _ = tx.send(());
    let _ = second_tx.send(());
    let _ = handle.await;
    let _ = second_handle.await;
    drop(temp_a);
    drop(temp_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_transcript_proof_is_rejected_with_documented_code() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, _secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let wrong_secret = [0x11_u8; 32];
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        &wrong_secret,
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x42_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let protocol_error_envelope =
        read_envelope_bounded(&mut reader, "protocol error envelope").await;
    let err = match protocol_error_envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-HELLO-PROOF");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_loopback_bind_is_rejected_by_address_validator() {
    // Production callers must not be able to bind a non-loopback
    // address through the loopback address validator. The daemon
    // binds the kernel socket through `LoopbackListener`; here we
    // exercise the production [`validate_loopback`] entry point
    // directly so the rejection is observed at the boundary the
    // brief requires, not just inside a predicate.
    let public: std::net::SocketAddr = "8.8.8.8:443".parse().unwrap();
    let err = validate_loopback(public).unwrap_err();
    let rendered = format!("{err}");
    assert!(rendered.contains("non-loopback"), "got {rendered}");

    let private: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
    assert!(validate_loopback(private).is_err());

    let loopback_v4: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    assert!(validate_loopback(loopback_v4).is_ok());

    let loopback_v6: std::net::SocketAddr = "[::1]:0".parse().unwrap();
    assert!(validate_loopback(loopback_v6).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_is_rejected_with_frame_too_large() {
    // Establish a pinned TLS listener and write an oversized
    // length prefix directly into the framed reader. The daemon
    // emits a `ProtocolError` with code `XTR-DAEMON-FRAME-TOO-LARGE`.
    //
    // The write half must stay alive while the reader drains the
    // `ProtocolError` envelope; calling `shutdown()` on the client
    // TLS stream before reading would deliver a TLS close_notify
    // alert that races the daemon's `ProtocolError` write and
    // occasionally closes the listener before the daemon can
    // respond. Keeping the writer open and dropping it after the
    // bounded read removes the race without any timing primitive.
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, _secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    // Announce a length greater than the daemon's 1 MiB envelope
    // limit. The reader rejects the announced length before any
    // allocation, then the daemon writes a ProtocolError before
    // closing.
    writer.write_all(&(2u32 * 1024 * 1024).to_be_bytes()).await.expect("write length");

    let envelope = read_envelope_bounded(&mut reader, "protocol error envelope").await;
    let err = match envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-FRAME-TOO-LARGE");

    drop(writer);
    drop(reader);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    let _ = daemon_handle.await;
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_protocol_version_is_rejected_with_documented_code() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    // The adapter offers only major 0; the daemon must reject the
    // offer because the daemon's major 1 is not in the offer.
    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        0,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let protocol_error_envelope =
        read_envelope_bounded(&mut reader, "protocol error envelope").await;
    let err = match protocol_error_envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-PROTOCOL-MAJOR");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_runtime_session_id_is_rejected_with_session_identity_code() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let wrong_session_id = RuntimeSessionId::new();
    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &wrong_session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &wrong_session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let protocol_error_envelope =
        read_envelope_bounded(&mut reader, "protocol error envelope").await;
    let err = match protocol_error_envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-SESSION-IDENTITY");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_repository_binding_is_rejected_with_project_identity_code() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        WRONG_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let protocol_error_envelope =
        read_envelope_bounded(&mut reader, "protocol error envelope").await;
    let err = match protocol_error_envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-PROJECT-IDENTITY");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gap_is_rejected_with_session_sequence_code() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope_bounded(&mut reader, "daemon hello").await;

    let capabilities = CapabilitySet {
        capabilities: vec![Capability {
            name: "endpoint_discovery".to_string(),
            config: Default::default(),
        }],
    };
    // Gap: session_seq jumps from 1 to 3.
    write_envelope(&mut writer, PayloadOneof::CapabilitySet(capabilities), &session_id, 3, 5)
        .await
        .expect("write capability set gap");
    let err = next_protocol_error(&mut reader, "gap error").await;
    assert_eq!(err.code, "XTR-DAEMON-SESSION-SEQUENCE");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_is_rejected_with_session_sequence_code() {
    // Authenticate and exchange seq 1. Resend seq 1 and observe
    // the documented `XTR-DAEMON-SESSION-SEQUENCE` rejection.
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope_bounded(&mut reader, "daemon hello").await;

    let capabilities = CapabilitySet {
        capabilities: vec![Capability {
            name: "endpoint_discovery".to_string(),
            config: Default::default(),
        }],
    };
    write_envelope(
        &mut writer,
        PayloadOneof::CapabilitySet(capabilities.clone()),
        &session_id,
        1,
        2,
    )
    .await
    .expect("write seq 1");
    let ack = next_ack(&mut reader, "ack 1").await;
    assert_eq!(ack.highest_contiguous_session_seq, 1);

    // Resend seq 1; the daemon must observe the replay and emit
    // the documented error code.
    write_envelope(&mut writer, PayloadOneof::CapabilitySet(capabilities), &session_id, 1, 3)
        .await
        .expect("resend seq 1");
    let err = next_protocol_error(&mut reader, "replay error").await;
    assert_eq!(err.code, "XTR-DAEMON-SESSION-SEQUENCE");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capacity_one_outbound_still_delivers_every_ack_without_deadlock() {
    // Regression coverage for the pre-fix reader/writer deadlock.
    // The outbound capacity of 1 used to deadlock the connection
    // because the reader task owned both halves of the TLS stream;
    // the dedicated writer task drains the channel one frame at a
    // time, so the reader always makes progress.
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_secs(60),
        1,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope_bounded(&mut reader, "daemon hello").await;

    let capabilities = CapabilitySet {
        capabilities: vec![Capability {
            name: "endpoint_discovery".to_string(),
            config: Default::default(),
        }],
    };
    let count = 4u64;
    for seq in 1..=count {
        write_envelope(
            &mut writer,
            PayloadOneof::CapabilitySet(capabilities.clone()),
            &session_id,
            seq,
            seq + 1,
        )
        .await
        .expect("write seq");
        let ack = next_ack(&mut reader, "ack").await;
        assert_eq!(ack.highest_contiguous_session_seq, seq);
    }

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    // Bound the shutdown to a generous budget so a regression
    // surfaces as a test failure rather than hanging the suite.
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_with_live_authenticated_client() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();
    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope_bounded(&mut reader, "daemon hello").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown must complete within budget")
        .expect("join task")
        .expect("serve must complete cleanly");
    drop(reader);
    drop(writer);
    drop(tls_stream);
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_artifact_round_trips_pin_and_session_secret() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, _secret, _, _, _address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let artifact = BootstrapArtifact::read(&bootstrap_path).expect("read bootstrap");
    assert_eq!(artifact.fields().certificate_sha256_pin, pin);
    assert_eq!(artifact.fields().runtime_session_id, session_id.to_string());
    assert_eq!(artifact.fields().project_id, project_id.to_string());
    assert_eq!(artifact.fields().expected_repository_fingerprint, EXPECTED_REPOSITORY_FINGERPRINT);
    assert_eq!(artifact.fields().max_protocol_major, 1);
    assert_eq!(artifact.fields().max_protocol_minor, 0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&bootstrap_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "bootstrap file must be owner-only");
    }

    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    assert!(!bootstrap_path.exists(), "bootstrap file must be removed on orderly shutdown");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_fields_helper_serialises_canonical_layout() {
    let session = RuntimeSessionId::new();
    let project = ProjectId::new();
    let secret = SessionSecret::generate().expect("secret");
    let fingerprint = expected_fingerprint();
    let fields = BootstrapArtifactFields::new(
        "127.0.0.1".to_string(),
        49152,
        "a".repeat(64),
        session,
        &secret,
        project,
        fingerprint.clone(),
        1,
        0,
    );
    let json = serde_json::to_string(&fields).expect("serialize");
    let parsed: BootstrapArtifactFields = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed, fields);
    let parsed_fingerprint =
        parsed.expected_repository_fingerprint().expect("canonical fingerprint");
    assert_eq!(parsed_fingerprint, fingerprint);
}

#[tokio::test]
async fn session_rejects_adapter_role_when_building_daemon_hello() {
    let inputs = HandshakeInputs {
        session_secret: SessionSecret::generate().expect("secret"),
        tls_exporter: vec![0u8; 32],
        runtime_session_id: RuntimeSessionId::new(),
        project_id: ProjectId::new(),
        max_envelope_bytes: 1024,
        max_batch_events: 1,
        max_protocol_major: 1,
        max_protocol_minor: 0,
        expected_repository_fingerprint: expected_fingerprint(),
        health_interval: xtrace_daemon::runtime::HealthInterval::default(),
        role: HandshakeRole::Adapter,
    };
    let mut session = Session::new(inputs);
    let err = session.build_daemon_hello(vec![0u8; 32], 1).unwrap_err();
    assert!(format!("{err}").contains("adapter role"));
}

/// Slice 1B §2.1 deletion contract: the owner-readable bootstrap
/// file is removed exactly once after `DaemonHello` has been
/// written to the wire, while a failed proof exchange leaves it
/// available for a legitimate retry, and the daemon stays up
/// throughout. The test proves every leg of the lifecycle on a real
/// loopback daemon: pre-negotiation existence, post-failed-proof
/// survival, and post-successful-DaemonHello deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_artifact_is_deleted_only_after_successful_daemon_hello() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_secs(60),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    // 1. Pre-negotiation: the bootstrap file is on disk with the
    //    daemon-owned permissions.
    assert!(bootstrap_path.exists(), "bootstrap file must exist before any negotiation begins",);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&bootstrap_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "bootstrap file must remain owner-only");
    }

    // 2. Failed proof: connect with a wrong secret, observe the
    //    documented `XTR-DAEMON-HELLO-PROOF` rejection, and confirm
    //    the bootstrap file survives so a legitimate retry can read
    //    it.
    {
        let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect bad");
        let wrong_secret = [0x99_u8; 32];
        let mut exporter_buf = [0u8; 32];
        tls_stream
            .get_ref()
            .1
            .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
            .expect("exporter");
        let adapter_hello = build_adapter_hello(
            &wrong_secret,
            &exporter_buf,
            &session_id,
            HAPPY_MANIFEST_DIGEST,
            &[0x42_u8; 32],
            EXPECTED_REPOSITORY_FINGERPRINT,
            1,
            0,
        );
        let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
        write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
            .await
            .expect("write bad hello");
        let envelope = read_envelope_bounded(&mut reader, "protocol error").await;
        match envelope.payload {
            Some(PayloadOneof::ProtocolError(err)) => {
                assert_eq!(err.code, "XTR-DAEMON-HELLO-PROOF");
            }
            other => unreachable!("expected ProtocolError, got {other:?}"),
        }
        drop(reader);
        drop(writer);
        drop(tls_stream);
    }
    assert!(
        bootstrap_path.exists(),
        "bootstrap file must survive a failed proof exchange so a legitimate retry can read it",
    );

    // 3. Successful proof: connect with the real secret, exchange
    //    `AdapterHello`/`DaemonHello`, and confirm the file is gone
    //    while the daemon is still running.
    {
        let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect good");
        let mut exporter_buf = [0u8; 32];
        tls_stream
            .get_ref()
            .1
            .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
            .expect("exporter");
        let adapter_hello = build_adapter_hello(
            secret.read_secret(),
            &exporter_buf,
            &session_id,
            HAPPY_MANIFEST_DIGEST,
            &[0x77_u8; 32],
            EXPECTED_REPOSITORY_FINGERPRINT,
            1,
            0,
        );
        let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
        write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
            .await
            .expect("write good hello");
        let daemon_hello_envelope = read_envelope_bounded(&mut reader, "daemon hello").await;
        match daemon_hello_envelope.payload {
            Some(PayloadOneof::DaemonHello(_)) => {}
            other => unreachable!("expected DaemonHello, got {other:?}"),
        }
        drop(reader);
        drop(writer);
        drop(tls_stream);
    }
    // The daemon is still running; the §2.1 contract says the file
    // is removed as soon as `DaemonHello` is on the wire. The brief
    // requires bounded waiting so a regression surfaces as a test
    // failure rather than hanging the suite.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while bootstrap_path.exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !bootstrap_path.exists(),
        "bootstrap file must be deleted while the daemon is still running after a successful DaemonHello",
    );

    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    drop(temp);
}

#[tokio::test]
async fn verify_transcript_proof_round_trip_with_real_layout() {
    let secret = [0x42_u8; 32];
    let exporter = [0x99_u8; 32];
    let session = RuntimeSessionId::new();
    let server = [0xab_u8; 32];
    let client = [0xcd_u8; 32];
    let manifest = "b3:0000000000000000000000000000000000000000000000000000000000000000";
    let tag = handshake::compute_transcript_proof(
        &secret,
        &exporter,
        session.as_uuid().as_bytes(),
        &client,
        &server,
        manifest.as_bytes(),
    )
    .expect("HMAC accepts the test secret");
    handshake::verify_transcript_proof(
        &secret,
        &exporter,
        session.as_uuid().as_bytes(),
        &client,
        &server,
        manifest.as_bytes(),
        &tag,
    )
    .expect("canonical layout verifies");
}

/// Slice 1B review round 5 defect 3: a peer disconnect during the
/// `DaemonHello` write must remain connection-local. The test
/// sends a valid `AdapterHello`, drops the TLS stream without
/// reading `DaemonHello`, and then opens a fresh pinned connection
/// that completes the full handshake. The supervisor policy under
/// test is that the listener stays up after a peer disconnect; the
/// direct second connection is sufficient to demonstrate the
/// policy without polling loops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_disconnect_during_daemon_hello_does_not_take_down_listener() {
    let temp = TempDir::new().expect("temp");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_secs(60),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    // 1. Send a valid AdapterHello, then drop the TLS stream
    //    without reading DaemonHello. This is the documented
    //    peer-disconnect shape the daemon must normalise to Ok(()).
    {
        let mut tls_stream =
            connect_pinned(address, &pin).await.expect("pinned connect disconnect");
        let mut exporter_buf = [0u8; 32];
        tls_stream
            .get_ref()
            .1
            .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
            .expect("client exporter");
        let adapter_hello = build_adapter_hello(
            secret.read_secret(),
            &exporter_buf,
            &session_id,
            HAPPY_MANIFEST_DIGEST,
            &[0x77_u8; 32],
            EXPECTED_REPOSITORY_FINGERPRINT,
            1,
            0,
        );
        let (_reader, mut writer) = tokio::io::split(&mut tls_stream);
        write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
            .await
            .expect("write adapter hello");
        drop(_reader);
        drop(writer);
        drop(tls_stream);
    }

    // 2. The listener must accept a fresh connection and complete
    //    a full handshake after the peer disconnect.
    let mut tls_stream = connect_pinned(address, &pin).await.expect("second pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("second client exporter");
    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter_buf,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &[0x55_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write second adapter hello");
    let envelope = read_envelope_bounded(&mut reader, "second daemon hello").await;
    match envelope.payload {
        Some(PayloadOneof::DaemonHello(_)) => {}
        Some(PayloadOneof::ProtocolError(err)) => {
            panic!(
                "unexpected ProtocolError on second connection after peer disconnect: {} {}",
                err.code, err.message,
            );
        }
        other => panic!("unexpected payload on second connection: {other:?}"),
    }
    drop(reader);
    drop(writer);
    drop(tls_stream);

    let _ = shutdown_tx.send(());
    daemon_handle
        .await
        .expect("daemon task")
        .expect("serve must complete cleanly because the peer disconnect was normalised to Ok(())");
    drop(temp);
}

// `RecordingStarted` -> one `EventBatch` -> `RecordingFinished`
// at `session_seq` 1, 2, 3 must each be admitted by the daemon's
// session over the real TLS 1.3 loopback and acknowledged with a
// `Staged` `Ack` whose `highest_contiguous_session_seq` matches the
// accepted sequence. The bounded helpers fail rather than hang if
// any ACK never arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_recording_wire_admission_acks_through_session_seq_three() {
    let temp = TempDir::new().expect("temp dir");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_secs(60),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let client_nonce = [0x6a_u8; 32];
    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &client_nonce,
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope_bounded(&mut reader, "daemon hello").await;

    // Slice 1C.3 fixture: the structural start carries
    // `recording_seq == 1`; the empty `EventBatch` is a valid no-op
    // for the known recording; the finish marker matches the
    // validator's highest contiguous value (1 because no events
    // were accepted).
    let recording_id = Bytes::copy_from_slice(&[0xa1_u8; 16]);
    let payloads = [
        (
            1u64,
            PayloadOneof::RecordingStarted(RecordingStarted {
                recording_id: recording_id.clone(),
                method: "GET".to_string(),
                recording_seq: 1,
                ..RecordingStarted::default()
            }),
        ),
        (
            2,
            PayloadOneof::EventBatch(EventBatch {
                recording_id: recording_id.clone(),
                events: Vec::new(),
            }),
        ),
        (
            3,
            PayloadOneof::RecordingFinished(RecordingFinished {
                recording_id,
                final_recording_seq: 1,
                ..RecordingFinished::default()
            }),
        ),
    ];
    for (seq, payload) in &payloads {
        write_envelope(&mut writer, payload.clone(), &session_id, *seq, seq + 1)
            .await
            .expect("write recording envelope");
        let ack = next_ack(&mut reader, "ack").await;
        assert_eq!(
            ack.highest_contiguous_session_seq, *seq,
            "session_seq {seq} must be acknowledged in order",
        );
        assert!(ack.rejected.is_empty(), "successful ack must carry no rejected messages");
        assert_eq!(
            ack.durability,
            xtrace_protocol::generated::agent::AckDurability::Staged as i32,
            "wire-admission ACK must report Staged durability; durable storage is out of scope",
        );
        assert_eq!(
            ack.highest_contiguous_recording_seq.len(),
            1,
            "every recording ACK must report the canonical recording watermark",
        );
    }

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    // Bound the shutdown so a regression surfaces as a test failure
    // rather than hanging the suite.
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
    drop(temp);
}

// Slice 1C.3 recoverable path: send an invalid recording envelope,
// observe the safe `XTR-CAPTURE-INGEST` `ProtocolError`, resend a
// corrected envelope at the same `session_seq`, receive a `Staged`
// ACK, and then complete a valid start/event/finish journey with
// canonical watermark values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_recording_recoverable_rejection_then_valid_journey() {
    let temp = TempDir::new().expect("temp dir");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let (bound, secret, _, _, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_secs(60),
        64,
        &expected_fingerprint(),
        project_id,
        session_id,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let client_nonce = [0x6c_u8; 32];
    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let mut exporter_buf = [0u8; 32];
    tls_stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter_buf, TLS_EXPORTER_LABEL, None)
        .expect("client exporter");
    let exporter = exporter_buf.to_vec();

    let adapter_hello = build_adapter_hello(
        secret.read_secret(),
        &exporter,
        &session_id,
        HAPPY_MANIFEST_DIGEST,
        &client_nonce,
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope_bounded(&mut reader, "daemon hello").await;

    let recording_id_bytes = Bytes::copy_from_slice(&[0xa2_u8; 16]);
    let canonical_key =
        xtrace_domain::RecordingId::from_uuid(uuid::Uuid::from_bytes([0xa2; 16])).as_string();

    // First attempt: a `RecordingStarted` with the wrong `recording_seq`
    // is a recoverable `InvalidStartSeq` rejection.
    let invalid = PayloadOneof::RecordingStarted(RecordingStarted {
        recording_id: recording_id_bytes.clone(),
        recording_seq: 7,
        method: "GET".to_string(),
        ..RecordingStarted::default()
    });
    write_envelope(&mut writer, invalid, &session_id, 1, 2).await.expect("write invalid start");
    let protocol_error = next_protocol_error(&mut reader, "ingest error").await;
    assert_eq!(
        protocol_error.code, "XTR-CAPTURE-INGEST",
        "recoverable ingest rejection must surface the safe capture-ingest code",
    );
    assert_eq!(
        protocol_error.message, "ingest rejection: invalid_start_seq",
        "recoverable ingest rejection must surface the exact safe variant name",
    );
    assert!(
        !protocol_error.message.contains("GET")
            && !protocol_error.message.contains("payload")
            && !protocol_error.message.contains("recording"),
        "ProtocolError message must not embed captured values, got {:?}",
        protocol_error.message,
    );

    // Corrected envelope at the same session_seq succeeds with a
    // Staged ACK carrying the canonical recording watermark.
    let corrected = PayloadOneof::RecordingStarted(RecordingStarted {
        recording_id: recording_id_bytes.clone(),
        recording_seq: 1,
        method: "GET".to_string(),
        ..RecordingStarted::default()
    });
    write_envelope(&mut writer, corrected, &session_id, 1, 3).await.expect("write corrected start");
    let ack = next_ack(&mut reader, "ack start").await;
    assert_eq!(ack.highest_contiguous_session_seq, 1);
    assert_eq!(
        ack.durability,
        xtrace_protocol::generated::agent::AckDurability::Staged as i32,
        "Staged ACK after recoverable rejection must still report Staged durability",
    );
    assert!(ack.rejected.is_empty());
    assert_eq!(
        ack.highest_contiguous_recording_seq.get(&canonical_key),
        Some(&1),
        "Staged ACK must carry the canonical recording watermark",
    );

    // Complete the valid start -> event -> finish journey.
    let batch = PayloadOneof::EventBatch(EventBatch {
        recording_id: recording_id_bytes.clone(),
        events: vec![xtrace_protocol::generated::agent::RecordingEvent {
            event_id: "ev-1".to_string(),
            recording_seq: 2,
            ..Default::default()
        }],
    });
    write_envelope(&mut writer, batch, &session_id, 2, 2).await.expect("write event batch");
    let ack = next_ack(&mut reader, "ack batch").await;
    assert_eq!(ack.highest_contiguous_session_seq, 2);
    assert_eq!(ack.highest_contiguous_recording_seq.get(&canonical_key), Some(&2));

    let finish = PayloadOneof::RecordingFinished(RecordingFinished {
        recording_id: recording_id_bytes,
        final_recording_seq: 2,
        ..RecordingFinished::default()
    });
    write_envelope(&mut writer, finish, &session_id, 3, 3).await.expect("write finish");
    let ack = next_ack(&mut reader, "ack finish").await;
    assert_eq!(ack.highest_contiguous_session_seq, 3);
    assert_eq!(ack.highest_contiguous_recording_seq.get(&canonical_key), Some(&2));

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
    drop(temp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_capture_runs_before_each_staged_ack_in_message_order() {
    let temp = secure_tempdir("xtrace-capture-live-");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let capture = Arc::new(ObservedCapture::default());
    let capture_port: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> = capture.clone();
    let (bound, secret, _, _, address, pin) = spawn_daemon_with_capture(
        bootstrap_path,
        Duration::from_secs(60),
        8,
        &expected_fingerprint(),
        project_id,
        session_id,
        capture_port,
    )
    .await
    .expect("bind configured daemon");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);
    let mut tls_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x81; 32]).await;
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    let recording_id = Bytes::copy_from_slice(&[0x31; 16]);

    write_envelope(
        &mut writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: recording_id.clone(),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("write start");
    let ack = next_ack(&mut reader, "start ACK").await;
    assert_eq!(ack.durability, AckDurability::Staged as i32);
    assert_eq!(capture.operations(), ["start"]);

    write_envelope(
        &mut writer,
        PayloadOneof::EventBatch(EventBatch {
            recording_id: recording_id.clone(),
            events: vec![RecordingEvent {
                event_id: "live-event".to_owned(),
                recording_seq: 2,
                monotonic_ns: 12,
                ..RecordingEvent::default()
            }],
        }),
        &session_id,
        2,
        2,
    )
    .await
    .expect("write batch");
    let ack = next_ack(&mut reader, "batch ACK").await;
    assert_eq!(ack.durability, AckDurability::Staged as i32);
    assert_eq!(capture.operations(), ["start", "batch"]);

    write_envelope(
        &mut writer,
        PayloadOneof::RecordingFinished(RecordingFinished {
            recording_id,
            final_recording_seq: 2,
            ..RecordingFinished::default()
        }),
        &session_id,
        3,
        3,
    )
    .await
    .expect("write finish");
    let ack = next_ack(&mut reader, "finish ACK").await;
    assert_eq!(ack.durability, AckDurability::Staged as i32);
    assert_eq!(capture.operations(), ["start", "batch", "finish"]);

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_failure_is_safe_closes_only_connection_and_supervisor_accepts_again() {
    let temp = secure_tempdir("xtrace-capture-failure-");
    let bootstrap_path = temp.path().join("bootstrap.json");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let capture = Arc::new(ObservedCapture::default());
    capture.fail_next_begin.store(true, std::sync::atomic::Ordering::SeqCst);
    let capture_port: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> = capture.clone();
    let (bound, secret, _, _, address, pin) = spawn_daemon_with_capture(
        bootstrap_path,
        Duration::from_secs(60),
        8,
        &expected_fingerprint(),
        project_id,
        session_id,
        capture_port,
    )
    .await
    .expect("bind configured daemon");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let mut failed_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x82; 32]).await;
    let (mut failed_reader, mut failed_writer) = tokio::io::split(&mut failed_stream);
    write_envelope(
        &mut failed_writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: Bytes::copy_from_slice(&[0x32; 16]),
            recording_seq: 1,
            method: "private-method".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("write failing start");
    let error = next_protocol_error(&mut failed_reader, "capture failure").await;
    assert_eq!(error.code, "XTR-DAEMON-TRANSPORT");
    assert_eq!(error.message, "recording capture operation failed");
    assert!(!error.message.contains("private"));
    let close = tokio::time::timeout(READ_ENVELOPE_BUDGET, read_envelope(&mut failed_reader))
        .await
        .expect("connection close timeout");
    assert!(close.is_err(), "capture failure must close the connection");
    drop(failed_reader);
    drop(failed_writer);
    drop(failed_stream);

    let mut recovered_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x83; 32]).await;
    let (mut reader, mut writer) = tokio::io::split(&mut recovered_stream);
    write_envelope(
        &mut writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: Bytes::copy_from_slice(&[0x33; 16]),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("write subsequent start");
    let ack = next_ack(&mut reader, "subsequent connection ACK").await;
    assert_eq!(ack.durability, AckDurability::Staged as i32);
    assert_eq!(capture.operations(), ["start", "start"]);

    drop(reader);
    drop(writer);
    drop(recovered_stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("owner-only path permissions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_daemon_persists_verified_sqlite_segment_with_staged_acks() {
    let daemon_temp = secure_tempdir("xtrace-sqlite-daemon-");
    let bootstrap_path = daemon_temp.path().join("bootstrap.json");
    let project_root = secure_tempdir("xtrace-project-data-");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let store =
        SqliteStore::open(&project_root.path().join("metadata.sqlite3"), OpenOptions::default())
            .expect("open project SQLite store");
    #[cfg(unix)]
    set_owner_only(&project_root.path().join("metadata.sqlite3"), 0o600);
    let timestamp = WallTime::now();
    let project = Project {
        id: project_id,
        canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/repo"),
        display_name: "daemon integration project".to_owned(),
        created_at: timestamp,
        last_opened_at: timestamp,
        config_schema_version: 1,
        effective_config_hash: String::new(),
        active_capture_policy_id: None,
        active_redaction_policy_id: None,
    };
    store.project_repository().insert_project(&project).expect("insert project");

    let adapter = Arc::new(SqliteRecordingPersistence::new(store, project_root.path()));
    let capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> =
        Arc::new(xtrace_application::recording::RecordingCaptureService::new(
            adapter.clone(),
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(DEFAULT_MAX_RETAINED_RECORDINGS)
                .expect("non-zero retained recording limit"),
        ));
    let (bound, secret, _, _, address, pin) = spawn_daemon_with_capture(
        bootstrap_path,
        Duration::from_secs(60),
        8,
        &expected_fingerprint(),
        project_id,
        session_id,
        capture,
    )
    .await
    .expect("bind SQLite-backed daemon");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);
    let mut tls_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x84; 32]).await;
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    let recording_id_bytes = Bytes::copy_from_slice(&[0x34; 16]);
    let recording_id = RecordingId::from_uuid(uuid::Uuid::from_bytes([0x34; 16]));

    write_envelope(
        &mut writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: recording_id_bytes.clone(),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("write start");
    assert_eq!(
        next_ack(&mut reader, "SQLite start ACK").await.durability,
        AckDurability::Staged as i32
    );

    let event = RecordingEvent {
        event_id: "sqlite-event-2".to_owned(),
        recording_seq: 2,
        monotonic_ns: 23,
        ..RecordingEvent::default()
    };
    write_envelope(
        &mut writer,
        PayloadOneof::EventBatch(EventBatch {
            recording_id: recording_id_bytes.clone(),
            events: vec![event.clone()],
        }),
        &session_id,
        2,
        2,
    )
    .await
    .expect("write batch");
    assert_eq!(
        next_ack(&mut reader, "SQLite batch ACK").await.durability,
        AckDurability::Staged as i32
    );

    write_envelope(
        &mut writer,
        PayloadOneof::RecordingFinished(RecordingFinished {
            recording_id: recording_id_bytes,
            final_recording_seq: 2,
            ..RecordingFinished::default()
        }),
        &session_id,
        3,
        3,
    )
    .await
    .expect("write finish");
    assert_eq!(
        next_ack(&mut reader, "SQLite finish ACK").await.durability,
        AckDurability::Staged as i32
    );

    let payload = XtfEventEnvelope { recording_seq: 2, event: Some(event) };
    let segment = xtrace_application::recording::PersistRecordingSegment {
        project_id,
        recording_id,
        segment_ordinal: 0,
        events: vec![xtrace_application::recording::AcceptedRecordingEvent {
            recording_seq: 2,
            monotonic_ns: 23,
            canonical_bytes: payload.encode_to_vec(),
            payload,
        }],
    };
    let verified = xtrace_application::recording::RecordingPersistencePort::persist_segment(
        adapter.as_ref(),
        &segment,
    )
    .expect("SQLite exact replay verifies committed object and segment");
    assert_eq!(
        verified.disposition,
        xtrace_application::recording::PersistSegmentDisposition::ExactReplay
    );

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_finish_can_replay_on_same_runtime_and_restart_keeps_open_capture_unavailable() {
    let daemon_temp = secure_tempdir("xtrace-finish-replay-daemon-");
    let bootstrap_path = daemon_temp.path().join("bootstrap.json");
    let project_root = secure_tempdir("xtrace-finish-replay-project-");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let database_path = project_root.path().join("metadata.sqlite3");
    let store = SqliteStore::open(&database_path, OpenOptions::default())
        .expect("open project SQLite store");
    #[cfg(unix)]
    set_owner_only(&database_path, 0o600);
    let timestamp = WallTime::now();
    let project = Project {
        id: project_id,
        canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/repo"),
        display_name: "finish replay integration project".to_owned(),
        created_at: timestamp,
        last_opened_at: timestamp,
        config_schema_version: 1,
        effective_config_hash: String::new(),
        active_capture_policy_id: None,
        active_redaction_policy_id: None,
    };
    store.project_repository().insert_project(&project).expect("insert project");

    let adapter = Arc::new(SqliteRecordingPersistence::new(store.clone(), project_root.path()));
    let capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> =
        Arc::new(xtrace_application::recording::RecordingCaptureService::new(
            adapter.clone(),
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(DEFAULT_MAX_RETAINED_RECORDINGS)
                .expect("non-zero retained recording limit"),
        ));
    let (bound, secret, _, _, address, pin) = spawn_daemon_with_capture(
        bootstrap_path,
        Duration::from_secs(60),
        8,
        &expected_fingerprint(),
        project_id,
        session_id,
        Arc::clone(&capture),
    )
    .await
    .expect("bind SQLite-backed daemon");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);
    let recording_id_bytes = Bytes::copy_from_slice(&[0x36; 16]);
    let recording_id = RecordingId::from_uuid(uuid::Uuid::from_bytes([0x36; 16]));
    let first_event = RecordingEvent {
        event_id: "retry-event-2".to_owned(),
        recording_seq: 2,
        monotonic_ns: 23,
        ..RecordingEvent::default()
    };

    let mut first_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x85; 32]).await;
    let (mut first_reader, mut first_writer) = tokio::io::split(&mut first_stream);
    write_envelope(
        &mut first_writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: recording_id_bytes.clone(),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("write initial start");
    assert_eq!(
        next_ack(&mut first_reader, "initial start").await.durability,
        AckDurability::Staged as i32
    );
    write_envelope(
        &mut first_writer,
        PayloadOneof::EventBatch(EventBatch {
            recording_id: recording_id_bytes.clone(),
            events: vec![first_event.clone()],
        }),
        &session_id,
        2,
        2,
    )
    .await
    .expect("write initial event");
    assert_eq!(
        next_ack(&mut first_reader, "initial event").await.durability,
        AckDurability::Staged as i32
    );

    let malformed_finish = RecordingFinished {
        recording_id: recording_id_bytes.clone(),
        final_recording_seq: 2,
        event_digest: Bytes::copy_from_slice(blake3::hash(b"retry-event-2").as_bytes()),
        response_summary: Some(xtrace_protocol::generated::agent::CapturedValue {
            value: Some(xtrace_protocol::generated::agent::captured_value::Value::Redacted(
                xtrace_protocol::generated::agent::CapturedValueRedacted {
                    rule_id: "FINISH_PRIVACY_CANARY".to_owned(),
                    shape_hint: i32::MAX,
                },
            )),
        }),
        ..RecordingFinished::default()
    };
    write_envelope(
        &mut first_writer,
        PayloadOneof::RecordingFinished(malformed_finish),
        &session_id,
        3,
        3,
    )
    .await
    .expect("write malformed finish");
    let failure = next_protocol_error(&mut first_reader, "malformed finish").await;
    assert_eq!(failure.code, "XTR-DAEMON-TRANSPORT");
    assert_eq!(failure.message, "recording capture operation failed");
    assert!(!failure.message.contains("FINISH_PRIVACY_CANARY"));
    assert!(
        tokio::time::timeout(Duration::from_secs(3), read_envelope(&mut first_reader))
            .await
            .expect("connection close timed out")
            .is_err()
    );
    drop(first_reader);
    drop(first_writer);
    drop(first_stream);

    let reader = SqliteRecordingReader::new(store.clone(), project_root.path());
    let (before_retry, _) =
        reader.list_recordings(project_id, None, 10).expect("read persisted start before retry");
    let opened_at_before_retry = before_retry
        .iter()
        .find(|item| item.recording_id == recording_id)
        .expect("recording anchor before retry")
        .opened_at
        .clone();
    let pending_before_retry = before_retry
        .iter()
        .find(|item| item.recording_id == recording_id)
        .expect("recording anchor before retry");
    assert_eq!(
        pending_before_retry.status,
        xtrace_application::recording_queries::RecordingStatus::Recording
    );
    assert_eq!(
        pending_before_retry.completion,
        xtrace_application::recording_queries::RecordingCompletionEvidence::Unavailable
    );

    let mut retry_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x86; 32]).await;
    let (mut retry_reader, mut retry_writer) = tokio::io::split(&mut retry_stream);
    write_envelope(
        &mut retry_writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: recording_id_bytes.clone(),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("replay original start");
    assert_eq!(
        next_ack(&mut retry_reader, "replayed start").await.durability,
        AckDurability::Staged as i32
    );
    write_envelope(
        &mut retry_writer,
        PayloadOneof::EventBatch(EventBatch {
            recording_id: recording_id_bytes.clone(),
            events: vec![first_event],
        }),
        &session_id,
        2,
        2,
    )
    .await
    .expect("replay original event");
    assert_eq!(
        next_ack(&mut retry_reader, "replayed event").await.durability,
        AckDurability::Staged as i32
    );
    write_envelope(
        &mut retry_writer,
        PayloadOneof::RecordingFinished(RecordingFinished {
            recording_id: recording_id_bytes,
            final_recording_seq: 2,
            event_digest: Bytes::copy_from_slice(blake3::hash(b"retry-event-2").as_bytes()),
            ..RecordingFinished::default()
        }),
        &session_id,
        3,
        3,
    )
    .await
    .expect("write corrected finish");
    assert_eq!(
        next_ack(&mut retry_reader, "corrected finish").await.durability,
        AckDurability::Staged as i32
    );
    drop(retry_reader);
    drop(retry_writer);
    drop(retry_stream);

    let (after_retry, _) =
        reader.list_recordings(project_id, None, 10).expect("read completed recording");
    assert_eq!(after_retry.len(), 1, "retry must not duplicate the recording anchor");
    assert_eq!(after_retry[0].opened_at, opened_at_before_retry);
    assert_eq!(after_retry[0].event_count, "1");
    assert_eq!(
        after_retry[0].completion,
        xtrace_application::recording_queries::RecordingCompletionEvidence::Complete
    );
    let completed_window = reader
        .show_recording(&ShowWindowRequest {
            project_id,
            recording_id,
            limit: 10,
            after_sequence: None,
        })
        .expect("read completed replay");
    assert_eq!(completed_window.segment_count, "1");
    assert_eq!(completed_window.events.len(), 1);
    assert!(completed_window.events[0].frame_id.is_some());

    let interrupted_id_bytes = Bytes::copy_from_slice(&[0x37; 16]);
    let interrupted_id = RecordingId::from_uuid(uuid::Uuid::from_bytes([0x37; 16]));
    let mut interrupted_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x87; 32]).await;
    let (mut interrupted_reader, mut interrupted_writer) =
        tokio::io::split(&mut interrupted_stream);
    write_envelope(
        &mut interrupted_writer,
        PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: interrupted_id_bytes.clone(),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        }),
        &session_id,
        1,
        1,
    )
    .await
    .expect("write interrupted start");
    assert_eq!(
        next_ack(&mut interrupted_reader, "interrupted start").await.durability,
        AckDurability::Staged as i32
    );
    write_envelope(
        &mut interrupted_writer,
        PayloadOneof::EventBatch(EventBatch {
            recording_id: interrupted_id_bytes,
            events: vec![RecordingEvent {
                event_id: "interrupted-event-2".to_owned(),
                recording_seq: 2,
                ..RecordingEvent::default()
            }],
        }),
        &session_id,
        2,
        2,
    )
    .await
    .expect("write interrupted event");
    assert_eq!(
        next_ack(&mut interrupted_reader, "interrupted event").await.durability,
        AckDurability::Staged as i32
    );
    drop(interrupted_reader);
    drop(interrupted_writer);
    drop(interrupted_stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");

    drop(reader);
    drop(capture);
    drop(adapter);
    drop(store);
    let reopened = SqliteStore::open(&database_path, OpenOptions::default())
        .expect("reopen store after daemon restart");
    let reopened_reader = SqliteRecordingReader::new(reopened.clone(), project_root.path());
    let (reopened_rows, _) =
        reopened_reader.list_recordings(project_id, None, 10).expect("read after daemon restart");
    assert_eq!(reopened_rows.len(), 2);
    let completed_after_reopen = reopened_rows
        .iter()
        .find(|row| row.recording_id == recording_id)
        .expect("completed row after reopen");
    assert_eq!(
        completed_after_reopen.completion,
        xtrace_application::recording_queries::RecordingCompletionEvidence::Complete
    );
    assert_eq!(completed_after_reopen.opened_at, opened_at_before_retry);
    let completed_reopen_window = reopened_reader
        .show_recording(&ShowWindowRequest {
            project_id,
            recording_id,
            limit: 10,
            after_sequence: None,
        })
        .expect("read completed frame index after reopen");
    assert_eq!(completed_reopen_window.events[0].frame_id, completed_window.events[0].frame_id);
    let interrupted = reopened_rows
        .iter()
        .find(|row| row.recording_id == interrupted_id)
        .expect("interrupted anchor after restart");
    assert_eq!(
        interrupted.status,
        xtrace_application::recording_queries::RecordingStatus::Recording
    );
    assert_eq!(
        interrupted.completion,
        xtrace_application::recording_queries::RecordingCompletionEvidence::Unavailable
    );

    let restarted_adapter =
        Arc::new(SqliteRecordingPersistence::new(reopened.clone(), project_root.path()));
    let restarted_capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> =
        Arc::new(xtrace_application::recording::RecordingCaptureService::new(
            restarted_adapter.clone(),
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(DEFAULT_MAX_RETAINED_RECORDINGS)
                .expect("non-zero retained recording limit"),
        ));
    let (restarted_bound, _, _, _, _, _) = spawn_daemon_with_capture(
        daemon_temp.path().join("restarted-bootstrap.json"),
        Duration::from_secs(60),
        8,
        &expected_fingerprint(),
        project_id,
        session_id,
        restarted_capture,
    )
    .await
    .expect("restart daemon with fresh runtime capture state");
    let (restarted_shutdown_tx, restarted_handle) = daemon_task(restarted_bound);
    let _ = restarted_shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), restarted_handle)
        .await
        .expect("restarted daemon shutdown timed out")
        .expect("restarted daemon task")
        .expect("restarted daemon serve");
    let (after_restart, _) = reopened_reader
        .list_recordings(project_id, None, 10)
        .expect("read status after fresh daemon shutdown");
    let interrupted_after_restart = after_restart
        .iter()
        .find(|row| row.recording_id == interrupted_id)
        .expect("interrupted row after fresh runtime");
    assert_eq!(
        interrupted_after_restart.status,
        xtrace_application::recording_queries::RecordingStatus::Recording
    );
    assert_eq!(
        interrupted_after_restart.completion,
        xtrace_application::recording_queries::RecordingCompletionEvidence::Unavailable
    );
}
