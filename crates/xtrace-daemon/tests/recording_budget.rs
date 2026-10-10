//! Daemon-level resource-budget journey (CONTRACTS 4.1): finished recordings must not consume
//! the active recording budget, in the ingest validator or in the application capture service.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_arguments,
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
use xtrace_application::ProjectRepository;
use xtrace_application::recording::{RecordingCapture, SegmentPolicy};
use xtrace_daemon::bootstrap::BootstrapArtifact;
use xtrace_daemon::{
    BoundDaemon, DaemonBuilder, DaemonConfig, DaemonError, LoopbackPolicy, OutboundCapacity,
    SessionSecret, TLS_EXPORTER_LABEL, build_pinned_client_config,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    Project, ProjectId, RepositoryFingerprint as DomainFingerprint, RepositoryFingerprint,
    RuntimeSessionId, WallTime,
};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    AckDurability, AdapterHello, AgentEnvelope, RecordingFinished, RecordingStarted,
};
use xtrace_protocol::handshake;
use xtrace_protocol::xtf::XtfEventEnvelope;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

const EXPECTED_REPOSITORY_FINGERPRINT: &str =
    "b3:1111111111111111111111111111111111111111111111111111111111111111";
const HAPPY_MANIFEST_DIGEST: &str =
    "b3:3333333333333333333333333333333333333333333333333333333333333333";
const READ_ENVELOPE_BUDGET: Duration = Duration::from_secs(5);

fn expected_fingerprint() -> DomainFingerprint {
    DomainFingerprint::try_from_canonical(EXPECTED_REPOSITORY_FINGERPRINT)
        .expect("canonical fingerprint")
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
        ..Default::default()
    }
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

fn secure_tempdir(prefix: &str) -> TempDir {
    let temp_base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(temp_base)
        .expect("temp directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("owner-only temp directory");
    }
    directory
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("owner-only path permissions");
}

const FINISHED_REQUESTS: u128 = 300;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_257_is_accepted_after_256_finished_recordings() {
    let daemon_temp = secure_tempdir("xtrace-budget-daemon-");
    let bootstrap_path = daemon_temp.path().join("bootstrap.json");
    let project_root = secure_tempdir("xtrace-budget-data-");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let store =
        SqliteStore::open(&project_root.path().join("metadata.sqlite3"), OpenOptions::default())
            .expect("open project SQLite store");
    set_owner_only(&project_root.path().join("metadata.sqlite3"), 0o600);
    let timestamp = WallTime::now();
    let project = Project {
        id: project_id,
        canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/repo"),
        display_name: "budget project".to_owned(),
        created_at: timestamp,
        last_opened_at: timestamp,
        config_schema_version: 1,
        effective_config_hash: String::new(),
        active_capture_policy_id: None,
        active_redaction_policy_id: None,
    };
    store.project_repository().insert_project(&project).expect("insert project");
    let adapter = Arc::new(SqliteRecordingPersistence::new(store, project_root.path()));
    // A retained-ID bound far below the request count proves the application layer also stops
    // counting finished recordings.
    let capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> =
        Arc::new(xtrace_application::recording::RecordingCaptureService::new(
            adapter,
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(16).expect("non-zero"),
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
    .expect("bind daemon");
    let (shutdown_tx, daemon_handle) = daemon_task(bound);
    let mut tls_stream =
        connect_authenticated(address, &pin, &secret, &session_id, &[0x85; 32]).await;
    let (mut reader, mut writer) = tokio::io::split(&mut tls_stream);

    let mut session_seq = 1_u64;
    for request in 1..=FINISHED_REQUESTS {
        let recording_id = Bytes::copy_from_slice(&(0x0100_0000_u128 + request).to_be_bytes());
        for payload in [
            PayloadOneof::RecordingStarted(RecordingStarted {
                recording_id: recording_id.clone(),
                recording_seq: 1,
                method: "GET".to_owned(),
                ..RecordingStarted::default()
            }),
            PayloadOneof::RecordingFinished(RecordingFinished {
                recording_id: recording_id.clone(),
                final_recording_seq: 1,
                ..RecordingFinished::default()
            }),
        ] {
            write_envelope(&mut writer, payload, &session_id, session_seq, session_seq)
                .await
                .expect("write recording envelope");
            let ack = next_ack(&mut reader, &format!("request {request} ack")).await;
            assert_eq!(ack.highest_contiguous_session_seq, session_seq);
            assert!(ack.rejected.is_empty(), "request {request} was rejected: {:?}", ack.rejected);
            assert_eq!(ack.durability, AckDurability::Staged as i32);
            session_seq += 1;
        }
    }

    // Acks are staged; read the store back (second read-only connection) until every
    // recording is durable and finished, so the test proves the persisted outcome too.
    let database = project_root.path().join("metadata.sqlite3");
    let wanted = i64::try_from(FINISHED_REQUESTS).expect("fits");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let connection = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("read-only store connection");
        let total: i64 = connection
            .query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get(0))
            .expect("count recordings");
        let finished: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM recordings WHERE status IN ('complete', 'partial')",
                [],
                |row| row.get(0),
            )
            .expect("count finished recordings");
        if total == wanted && finished == wanted {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "store never reached {wanted} finished recordings (total {total}, finished {finished})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    drop(reader);
    drop(writer);
    drop(tls_stream);
    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(10), daemon_handle)
        .await
        .expect("shutdown timed out")
        .expect("daemon task")
        .expect("serve");
}
