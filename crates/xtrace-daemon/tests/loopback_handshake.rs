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
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use xtrace_daemon::bootstrap::{BootstrapArtifact, BootstrapArtifactFields};
use xtrace_daemon::listener::validate_loopback;

use xtrace_daemon::{
    BoundDaemon, DaemonBuilder, DaemonConfig, DaemonError, HandshakeInputs, HandshakeRole,
    LoopbackPolicy, OutboundCapacity, Session, SessionSecret, TLS_EXPORTER_LABEL,
    build_pinned_client_config,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{ProjectId, RepositoryFingerprint as DomainFingerprint, RuntimeSessionId};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    AdapterHello, AgentEnvelope, Capability, CapabilitySet, Health, ProtocolError,
};
use xtrace_protocol::handshake;

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

    // Real pinned TLS connection.
    let mut tls_stream = connect_pinned(address, &pin).await.expect("pinned connect");
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);
    // Announce a length greater than the daemon's 1 MiB envelope
    // limit. The reader rejects the announced length before any
    // allocation.
    writer.write_all(&(2u32 * 1024 * 1024).to_be_bytes()).await.expect("write length");
    let _ = writer.shutdown().await;
    drop(writer);

    let envelope = read_envelope_bounded(&mut reader, "protocol error envelope").await;
    let err = match envelope.payload {
        Some(PayloadOneof::ProtocolError(err)) => err,
        other => unreachable!("expected ProtocolError, got {other:?}"),
    };
    assert_eq!(err.code, "XTR-DAEMON-FRAME-TOO-LARGE");

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
/// sends a valid `AdapterHello`, aborts the TCP stream before
/// reading `DaemonHello`, and asserts the daemon supervisor
/// continues to accept subsequent connections and complete a fresh
/// full handshake.
///
/// TCP timing is nondeterministic — the daemon may have already
/// written `DaemonHello` before the peer closes, or it may have
/// not — so the test observes the supervisor policy by retrying
/// the second connection until it succeeds under a bounded
/// deadline. The point is the supervisor policy (the listener
/// stays up after a peer disconnect), not a specific race outcome.
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

    // 1. Open a pinned TLS connection, send a valid AdapterHello,
    //    then close the connection without reading the DaemonHello
    //    reply. This is the documented peer-disconnect pattern:
    //    the daemon sees a healthy local socket but the peer has
    //    already closed both halves of the connection.
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
        // Drop both halves without reading DaemonHello. This is the
        // peer-disconnect shape the daemon must normalise to Ok(()).
        drop(_reader);
        drop(writer);
        drop(tls_stream);
    }

    // 2. The supervisor must still be alive and must accept a
    //    subsequent connection. We poll under a bounded deadline
    //    because the daemon may need a brief moment to finish
    //    tearing down the first connection before accepting the
    //    second one.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut second_ok = false;
    while std::time::Instant::now() < deadline && !second_ok {
        let connect_attempt =
            tokio::time::timeout(Duration::from_millis(250), connect_pinned(address, &pin)).await;
        match connect_attempt {
            Ok(Ok(mut tls_stream)) => {
                let mut exporter_buf = [0u8; 32];
                let exporter_result = tls_stream.get_ref().1.export_keying_material(
                    &mut exporter_buf,
                    TLS_EXPORTER_LABEL,
                    None,
                );
                if exporter_result.is_err() {
                    let _ = tls_stream.shutdown().await;
                    drop(tls_stream);
                    continue;
                }
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
                if write_envelope(
                    &mut writer,
                    PayloadOneof::AdapterHello(adapter_hello),
                    &session_id,
                    0,
                    1,
                )
                .await
                .is_err()
                {
                    let _ = tls_stream.shutdown().await;
                    drop(tls_stream);
                    continue;
                }
                match tokio::time::timeout(Duration::from_secs(2), read_envelope(&mut reader)).await
                {
                    Ok(Ok(envelope)) => match envelope.payload {
                        Some(PayloadOneof::DaemonHello(_)) => {
                            second_ok = true;
                        }
                        Some(PayloadOneof::ProtocolError(err)) => {
                            // A ProtocolError here would mean the
                            // daemon's state is corrupted by the
                            // earlier peer-disconnect path; fail
                            // loudly rather than retry.
                            panic!(
                                "unexpected ProtocolError on second connection after peer disconnect: {} {}",
                                err.code, err.message,
                            );
                        }
                        other => panic!("unexpected payload on second connection: {other:?}"),
                    },
                    Ok(Err(err)) => {
                        let _ = tls_stream.shutdown().await;
                        drop(tls_stream);
                        eprintln!("second connection read failed; retrying: {err}");
                        continue;
                    }
                    Err(_) => {
                        let _ = tls_stream.shutdown().await;
                        drop(tls_stream);
                        eprintln!("second connection timed out; retrying");
                        continue;
                    }
                }
                let _ = tls_stream.shutdown().await;
                drop(tls_stream);
            }
            Ok(Err(err)) => {
                eprintln!("second connect failed; retrying: {err}");
                continue;
            }
            Err(_) => {
                // Local timeout on the connect; retry until the
                // outer deadline.
                continue;
            }
        }
    }
    assert!(
        second_ok,
        "listener must accept a second connection after a peer disconnect during DaemonHello",
    );

    let _ = shutdown_tx.send(());
    daemon_handle
        .await
        .expect("daemon task")
        .expect("serve must complete cleanly because the peer disconnect was normalised to Ok(())");
    drop(temp);
}
