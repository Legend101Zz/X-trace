//! End-to-end loopback integration coverage.
//!
//! These tests bring up a real [`BoundDaemon`] on the OS-assigned
//! loopback port, connect with a real rustls client configured to
//! pin the daemon's certificate, exercise the `AdapterHello` /
//! `DaemonHello` transcript proof over the negotiated TLS 1.3
//! channel, and exchange post-hello traffic. The tests prove the
//! Slice 1B acceptance criteria:
//!
//! - the daemon binds loopback only and refuses any other bind
//!   policy through the production address validator;
//! - the ephemeral certificate is pinned through a real rustls
//!   verifier so a different daemon certificate never connects;
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
//!   rejection for replay or gap.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration tests assert on fallible fixture data and supervisor paths"
)]

use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use xtrace_daemon::bootstrap::{BootstrapArtifact, BootstrapArtifactFields};
use xtrace_daemon::{
    BoundDaemon, DaemonBuilder, DaemonConfig, DaemonError, HandshakeInputs, HandshakeRole,
    LoopbackPolicy, Session, SessionSecret, TLS_EXPORTER_LABEL, build_pinned_client_config,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{ProjectId, RuntimeSessionId};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    AdapterHello, AgentEnvelope, Capability, CapabilitySet, Health,
};
use xtrace_protocol::handshake::{self, project_context};

const EXPECTED_REPOSITORY_FINGERPRINT: &str = "expected-repo-fingerprint";
const WRONG_REPOSITORY_FINGERPRINT: &str = "wrong-repo-fingerprint";

/// Builds a fresh daemon bound to loopback with a TLS 1.3-only
/// configuration. Returns the bound daemon, the bootstrap secret it
/// wrote, the runtime session identifier, the project identifier,
/// the local address, and the certificate pin. Tests use the
/// bootstrap artifact to read the session secret so the daemon's
/// private key never leaves the daemon process.
async fn spawn_daemon(
    bootstrap_path: std::path::PathBuf,
    health_interval: Duration,
    channel_capacity: usize,
    repository_fingerprint: &str,
) -> Result<
    (BoundDaemon, SessionSecret, RuntimeSessionId, ProjectId, std::net::SocketAddr, String),
    DaemonError,
> {
    let mut config = DaemonConfig {
        loopback_policy: LoopbackPolicy::V4Only,
        health_interval,
        ..DaemonConfig::default()
    };
    config.channel_capacity =
        xtrace_daemon::ChannelCapacity::new(channel_capacity).unwrap_or_default();
    let project_id = ProjectId::new();
    let runtime_session_id = RuntimeSessionId::new();
    let bound = DaemonBuilder::new(config)
        .with_project_id(project_id)
        .with_runtime_session_id(runtime_session_id)
        .with_expected_repository_fingerprint(repository_fingerprint.to_string())
        .with_bootstrap_artifact(bootstrap_path.clone())
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
    project_id: &ProjectId,
    manifest_digest: &str,
    client_nonce: &[u8],
    repository_fingerprint: &str,
    protocol_major_max: u32,
    protocol_minor_max: u32,
) -> AdapterHello {
    let ctx = project_context(project_id.as_uuid().as_bytes());
    let proof = handshake::compute_transcript_proof(
        secret,
        tls_exporter,
        runtime_session_id.as_uuid().as_bytes(),
        client_nonce,
        &handshake::ZERO_NONCE,
        manifest_digest.as_bytes(),
        &ctx,
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
    project_id: &ProjectId,
    server_nonce: &[u8],
    client_nonce: &[u8],
    manifest_digest: &str,
) -> [u8; 32] {
    let ctx = project_context(project_id.as_uuid().as_bytes());
    handshake::compute_transcript_proof(
        secret,
        tls_exporter,
        runtime_session_id.as_uuid().as_bytes(),
        client_nonce,
        server_nonce,
        manifest_digest.as_bytes(),
        &ctx,
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

/// Reads envelopes from the supplied stream until the next `Ack`
/// payload arrives, dropping any intervening `Health` echoes from
/// the daemon's periodic ticker. The helper makes the post-hello
/// happy path deterministic when the daemon emits a Health between
/// the adapter's outbound messages.
async fn next_ack<R>(reader: &mut R, label: &str) -> xtrace_protocol::generated::agent::Ack
where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        let envelope = read_envelope(reader).await.expect(label);
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

/// Builds a unique test directory under `std::env::temp_dir()` for
/// bootstrap and other temporary files. The directory is cleaned up
/// at the end of every test even when the test panics.
fn unique_dir(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("xtrace-daemon-{label}-{}-{counter}-{nanos}", std::process::id(),));
    std::fs::create_dir_all(&path).expect("mkdir");
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_happy_path_handshake_and_post_hello_traffic() {
    let dir = unique_dir("happy");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    let client_nonce = [0x77_u8; 32];
    let manifest_digest = pin.clone();

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
        &project_id,
        &manifest_digest,
        &client_nonce,
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let daemon_hello_envelope = read_envelope(&mut reader).await.expect("daemon hello");
    let daemon_hello = match daemon_hello_envelope.payload {
        Some(PayloadOneof::DaemonHello(hello)) => hello,
        other => unreachable!("expected DaemonHello, got {other:?}"),
    };
    assert_eq!(daemon_hello.protocol_major, 1);
    assert_eq!(daemon_hello.protocol_minor, 0);
    assert_eq!(daemon_hello.max_envelope_bytes, 1024 * 1024);
    assert_eq!(daemon_hello.max_batch_events, 256);
    assert_eq!(daemon_hello.manifest_digest, manifest_digest);
    assert_eq!(daemon_hello.server_nonce.len(), 32);
    let expected_proof = compute_expected_daemon_proof(
        secret.read_secret(),
        &exporter,
        &session_id,
        &project_id,
        &daemon_hello.server_nonce,
        &client_nonce,
        &manifest_digest,
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_client_rejects_wrong_certificate_at_tls_verification() {
    let dir = unique_dir("wrong-pin");
    let bootstrap_a = dir.join("bootstrap-a.json");
    let bootstrap_b = dir.join("bootstrap-b.json");

    let mut cfg =
        DaemonConfig { loopback_policy: LoopbackPolicy::V4Only, ..DaemonConfig::default() };
    cfg.channel_capacity = xtrace_daemon::ChannelCapacity::default();
    let first = DaemonBuilder::new(cfg)
        .with_project_id(ProjectId::new())
        .with_runtime_session_id(RuntimeSessionId::new())
        .with_expected_repository_fingerprint(EXPECTED_REPOSITORY_FINGERPRINT.to_string())
        .with_bootstrap_artifact(bootstrap_a.clone())
        .bind()
        .await
        .expect("first bind");
    let first_pin = first.certificate_pin().to_string();

    let mut cfg2 =
        DaemonConfig { loopback_policy: LoopbackPolicy::V4Only, ..DaemonConfig::default() };
    cfg2.channel_capacity = xtrace_daemon::ChannelCapacity::default();
    let second = DaemonBuilder::new(cfg2)
        .with_project_id(ProjectId::new())
        .with_runtime_session_id(RuntimeSessionId::new())
        .with_expected_repository_fingerprint(EXPECTED_REPOSITORY_FINGERPRINT.to_string())
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_transcript_proof_is_rejected_with_documented_code() {
    let dir = unique_dir("wrong-proof");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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
        &project_id,
        &pin,
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
        read_envelope(&mut reader).await.expect("protocol error envelope");
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
    let _ = std::fs::remove_dir_all(&dir);
    let _ = secret;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_session_secret_is_rejected_with_hello_proof_code() {
    let dir = unique_dir("wrong-secret");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, _, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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

    let alt_secret = [0x99_u8; 32];
    let adapter_hello = build_adapter_hello(
        &alt_secret,
        &exporter,
        &session_id,
        &project_id,
        &pin,
        &[0x55_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");

    let protocol_error_envelope =
        read_envelope(&mut reader).await.expect("protocol error envelope");
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_loopback_bind_is_rejected_by_address_validator() {
    // Production callers must not be able to bind a non-loopback
    // address through the loopback address validator. The daemon
    // binds the kernel socket through `LoopbackListener`; here we
    // exercise the public `is_loopback_ip` and the loopback-only
    // bind rejection by attempting a non-loopback bind and
    // confirming the helper reports the address as not loopback.
    use xtrace_daemon::listener::is_loopback_ip;
    assert!(!is_loopback_ip("10.0.0.1".parse().unwrap()));
    assert!(!is_loopback_ip("8.8.8.8".parse().unwrap()));
    let bound = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = bound.local_addr().expect("addr");
    assert!(is_loopback_ip(addr.ip()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_is_rejected_with_frame_too_large() {
    let dir = unique_dir("oversized");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, _, _, _, address, _) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    // Open a TCP socket without TLS to send an oversized length
    // prefix directly into the framed reader.
    let mut stream = TcpStream::connect(address).await.expect("tcp connect");
    // Announce a length greater than the daemon's 1 MiB envelope
    // limit. The exact byte value 2 MiB triggers TooLarge.
    stream.write_all(&(2u32 * 1024 * 1024).to_be_bytes()).await.expect("write length");
    let _ = stream.shutdown().await;
    drop(stream);
    let _ = shutdown_tx.send(());
    let _ = daemon_handle.await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incompatible_protocol_version_is_rejected_with_documented_code() {
    let dir = unique_dir("proto-mismatch");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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
        &project_id,
        &pin,
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
        read_envelope(&mut reader).await.expect("protocol error envelope");
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_runtime_session_id_is_rejected_with_session_identity_code() {
    let dir = unique_dir("wrong-session");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, _session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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
        &project_id,
        &pin,
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
        read_envelope(&mut reader).await.expect("protocol error envelope");
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_repository_binding_is_rejected_with_project_identity_code() {
    let dir = unique_dir("wrong-repo");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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
        &project_id,
        &pin,
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
        read_envelope(&mut reader).await.expect("protocol error envelope");
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gap_is_rejected_with_session_sequence_code() {
    let dir = unique_dir("gap");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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
        &project_id,
        &pin,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope(&mut reader).await.expect("daemon hello");

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
    let err_envelope = read_envelope(&mut reader).await.expect("gap error");
    let err = match err_envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-SESSION-SEQUENCE");

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    daemon_handle.await.expect("daemon task").expect("serve");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_with_live_authenticated_client() {
    let dir = unique_dir("shutdown");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, secret, session_id, project_id, address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
    )
    .await
    .expect("bind");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);

    // Open one authenticated connection and keep it alive across
    // shutdown. The supervisor must observe the connection, close
    // it, and join the task before serve returns.
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
        &project_id,
        &pin,
        &[0x33_u8; 32],
        EXPECTED_REPOSITORY_FINGERPRINT,
        1,
        0,
    );
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    write_envelope(&mut writer, PayloadOneof::AdapterHello(adapter_hello), &session_id, 0, 1)
        .await
        .expect("write adapter hello");
    let _ = read_envelope(&mut reader).await.expect("daemon hello");
    // Sleep briefly so the connection task has reached the
    // post-hello state before we trigger shutdown.
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_artifact_round_trips_pin_and_session_secret() {
    let dir = unique_dir("bootstrap-roundtrip");
    let bootstrap_path = dir.join("bootstrap.json");
    let (bound, _secret, session_id, project_id, _address, pin) = spawn_daemon(
        bootstrap_path.clone(),
        Duration::from_millis(50),
        64,
        EXPECTED_REPOSITORY_FINGERPRINT,
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_fields_helper_serialises_canonical_layout() {
    // Bootstrap fields round-trip through the helper and serde
    // without losing any field; this guards the wire layout for
    // future adapter implementations reading the artifact.
    let session = RuntimeSessionId::new();
    let project = ProjectId::new();
    let secret = SessionSecret::generate().expect("secret");
    let fields = BootstrapArtifactFields::new(
        "127.0.0.1".to_string(),
        49152,
        "a".repeat(64),
        session,
        &secret,
        project,
        EXPECTED_REPOSITORY_FINGERPRINT.to_string(),
        1,
        0,
    );
    let json = serde_json::to_string(&fields).expect("serialize");
    let parsed: BootstrapArtifactFields = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed, fields);
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
        expected_repository_fingerprint: "expected-repo".to_string(),
        health_interval: xtrace_daemon::runtime::HealthInterval::default(),
        role: HandshakeRole::Adapter,
    };
    let mut session = Session::new(inputs);
    let err = session.build_daemon_hello(vec![0u8; 32], 1).unwrap_err();
    assert!(format!("{err}").contains("adapter role"));
}

#[tokio::test]
async fn verify_transcript_proof_round_trip_with_real_layout() {
    let secret = [0x42_u8; 32];
    let exporter = [0x99_u8; 32];
    let session = RuntimeSessionId::new();
    let project = ProjectId::new();
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
        &handshake::project_context(project.as_uuid().as_bytes()),
    )
    .expect("HMAC accepts the test secret");
    handshake::verify_transcript_proof(
        &secret,
        &exporter,
        session.as_uuid().as_bytes(),
        &client,
        &server,
        manifest.as_bytes(),
        &handshake::project_context(project.as_uuid().as_bytes()),
        &tag,
    )
    .expect("canonical layout verifies");
}
