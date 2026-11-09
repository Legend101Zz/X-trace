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
use xtrace_application::recording_queries::{
    RecordingCompletionEvidence, RecordingReadPort as _, RecordingStatus, ShowWindowRequest,
};
use xtrace_daemon::bootstrap::BootstrapArtifact;
use xtrace_daemon::{
    BoundDaemon, DaemonBuilder, DaemonConfig, DaemonError, LoopbackPolicy, OutboundCapacity,
    SessionSecret, TLS_EXPORTER_LABEL, build_pinned_client_config,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    Project, ProjectId, RecordingId, RepositoryFingerprint as DomainFingerprint,
    RepositoryFingerprint, RuntimeSessionId, WallTime,
};
use xtrace_protocol::envelope::xtp_payload_ctor::PayloadOneof;
use xtrace_protocol::generated::agent::{
    AckDurability, AdapterHello, AgentEnvelope, EventBatch, RecordingEvent, RecordingEventKind,
    RecordingFinished, RecordingStarted,
};
use xtrace_protocol::handshake;
use xtrace_protocol::xtf::XtfEventEnvelope;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteRecordingReader, SqliteStore};

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
async fn streamed_batches_are_visible_while_open_and_complete_at_the_finish_ack() {
    streamed_recording_journey(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn focused_streamed_batches_complete_at_the_finish_ack() {
    streamed_recording_journey(true).await;
}

async fn streamed_recording_journey(focused: bool) {
    let daemon_temp = secure_tempdir("xtrace-stream-daemon-");
    if focused {
        let capture = daemon_temp.path().join("capture.json");
        std::fs::write(&capture, r#"{"capture_schema_version":1,"capture":{"mode":"focused"}}"#)
            .expect("write focused arming policy");
        set_owner_only(&capture, 0o600);
    }
    let project_root = secure_tempdir("xtrace-stream-data-");
    let project_id = ProjectId::new();
    let session_id = RuntimeSessionId::new();
    let store =
        SqliteStore::open(&project_root.path().join("metadata.sqlite3"), OpenOptions::default())
            .expect("open SQLite");
    set_owner_only(&project_root.path().join("metadata.sqlite3"), 0o600);
    store
        .project_repository()
        .insert_project(&Project {
            id: project_id,
            canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/repo"),
            display_name: "streamed recording".to_owned(),
            created_at: WallTime::now(),
            last_opened_at: WallTime::now(),
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        })
        .expect("insert project");
    let capture = Arc::new(xtrace_application::recording::RecordingCaptureService::new(
        Arc::new(SqliteRecordingPersistence::new(store, project_root.path())),
        SegmentPolicy::default(),
        std::num::NonZeroUsize::new(1).expect("retention"),
    ));
    let (bound, secret, _, _, address, pin) = spawn_daemon_with_capture(
        daemon_temp.path().join("bootstrap.json"),
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
    let mut tls = connect_authenticated(address, &pin, &secret, &session_id, &[0x86; 32]).await;
    let (mut reader, mut writer) = tokio::io::split(&mut tls);
    // An independent handle prevents volatile assembly state from satisfying the assertions.
    let persisted = SqliteRecordingReader::new(
        SqliteStore::open(
            &project_root.path().join("metadata.sqlite3"),
            OpenOptions::default().with_must_exist(true),
        )
        .expect("reopen SQLite"),
        project_root.path(),
    );
    let recording_id = RecordingId::new();
    let bytes = Bytes::copy_from_slice(recording_id.as_uuid().as_bytes());
    let events: Vec<_> = (2..=451)
        .map(|sequence| RecordingEvent {
            event_id: format!("event-{sequence}"),
            recording_seq: sequence,
            monotonic_ns: sequence * 10,
            kind: RecordingEventKind::FrameEnter as i32,
            symbol: "streaming.handler".to_owned(),
            ..RecordingEvent::default()
        })
        .collect();
    let mut digest = blake3::Hasher::new();
    for event in &events {
        digest.update(event.event_id.as_bytes());
    }
    let mut payloads = vec![PayloadOneof::RecordingStarted(RecordingStarted {
        recording_id: bytes.clone(),
        recording_seq: 1,
        method: "GET".to_owned(),
        matched_route_template: "/streaming".to_owned(),
        capture_policy_id: if focused {
            xtrace_domain::CAPTURE_POLICY_FOCUSED_ID.to_owned()
        } else {
            xtrace_domain::CAPTURE_POLICY_STANDARD_ID.to_owned()
        },
        ..RecordingStarted::default()
    })];
    payloads.extend(events.chunks(200).map(|chunk| {
        PayloadOneof::EventBatch(EventBatch { recording_id: bytes.clone(), events: chunk.to_vec() })
    }));
    payloads.push(PayloadOneof::RecordingFinished(RecordingFinished {
        recording_id: bytes,
        final_recording_seq: 451,
        duration_ns: 5000,
        event_digest: Bytes::copy_from_slice(digest.finalize().as_bytes()),
        ..RecordingFinished::default()
    }));
    for (index, payload) in payloads.into_iter().enumerate() {
        let finishing = matches!(payload, PayloadOneof::RecordingFinished(_));
        let session_seq = index as u64 + 1;
        write_envelope(&mut writer, payload, &session_id, session_seq, session_seq)
            .await
            .expect("send recording evidence");
        let ack = next_ack(&mut reader, "streaming recording").await;
        assert!(ack.rejected.is_empty());
        assert_eq!(ack.highest_contiguous_session_seq, session_seq);
        let (listed, more) = persisted.list_recordings(project_id, None, 10).expect("live list");
        assert!(!more);
        assert_eq!(listed.len(), 1, "Start must be visible before any events or Finish");
        let item = &listed[0];
        assert_eq!(item.recording_id, recording_id);
        assert_eq!(
            item.status,
            if finishing { RecordingStatus::Complete } else { RecordingStatus::Recording }
        );
        assert_eq!(
            item.completion,
            if finishing {
                RecordingCompletionEvidence::Complete
            } else {
                RecordingCompletionEvidence::Unavailable
            }
        );
        let expected_events = if finishing { 450 } else { (index * 200).min(450) };
        assert_eq!(item.event_count, expected_events.to_string());
        if !finishing {
            assert_eq!(item.segment_count, "0", "small batches stay in the journal until Finish");
        }
    }
    // The count limit is also bounded by the 256 KiB projection budget.
    // Read every page immediately after ACK, without waiting for more ingest.
    let mut observed = Vec::new();
    let mut after_sequence = None;
    loop {
        let window = persisted
            .show_recording(&ShowWindowRequest {
                project_id,
                recording_id,
                limit: 500,
                after_sequence,
            })
            .expect("complete detail");
        assert_eq!(window.status, RecordingStatus::Complete);
        assert_eq!(window.completion, RecordingCompletionEvidence::Complete);
        assert_eq!(
            window.capacity.as_ref().expect("terminal capacity").event_cap,
            if focused {
                xtrace_domain::FOCUSED_EVENT_CAP as u32
            } else {
                xtrace_domain::STANDARD_EVENT_CAP as u32
            }
        );
        assert!(window.incomplete_evidence.is_empty());
        assert!(!window.events.is_empty(), "every page makes progress");
        let last = window.events.last().unwrap().sequence.parse::<u64>().expect("sequence");
        assert!(after_sequence.is_none_or(|previous| last > previous));
        after_sequence = Some(last);
        observed.extend(window.events);
        assert!(observed.len() <= events.len(), "no duplicated or invented events");
        if !window.has_more {
            break;
        }
    }
    assert_eq!(observed.len(), events.len());
    for (actual, sent) in observed.iter().zip(&events) {
        assert_eq!(actual.sequence, sent.recording_seq.to_string());
        assert_eq!(actual.event_id.as_deref(), Some(sent.event_id.as_str()));
    }
    drop(reader);
    drop(writer);
    drop(tls);
    shutdown_tx.send(()).expect("request shutdown");
    tokio::time::timeout(Duration::from_secs(10), daemon_handle)
        .await
        .expect("shutdown deadline")
        .expect("daemon task")
        .expect("serve");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_257_is_accepted_after_256_finished_recordings() {
    finished_recording_budget_journey(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_recordings_release_capacity_and_read_as_partial_with_an_active_companion() {
    finished_recording_budget_journey(true).await;
}

async fn finished_recording_budget_journey(abandoned: bool) {
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
    let adapter = Arc::new(SqliteRecordingPersistence::new(store.clone(), project_root.path()));
    // A retained-ID bound far below the request count proves the application layer also stops
    // counting finished recordings.
    let capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>> =
        Arc::new(xtrace_application::recording::RecordingCaptureService::new(
            adapter,
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(if abandoned { 2 } else { 16 }).expect("non-zero"),
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
    let persisted = SqliteRecordingReader::new(store, project_root.path());
    let companion_id = RecordingId::new();
    let companion_bytes = Bytes::copy_from_slice(companion_id.as_uuid().as_bytes());

    let mut session_seq = 1_u64;
    if abandoned {
        write_envelope(
            &mut writer,
            PayloadOneof::RecordingStarted(RecordingStarted {
                recording_id: companion_bytes.clone(),
                recording_seq: 1,
                method: "GET".to_owned(),
                ..RecordingStarted::default()
            }),
            &session_id,
            session_seq,
            session_seq,
        )
        .await
        .expect("start active companion");
        let ack = next_ack(&mut reader, "companion start").await;
        assert!(ack.rejected.is_empty());
        session_seq += 1;
    }
    for request in 1..=FINISHED_REQUESTS {
        let recording_id = Bytes::copy_from_slice(&(0x0100_0000_u128 + request).to_be_bytes());
        let mut payloads = vec![PayloadOneof::RecordingStarted(RecordingStarted {
            recording_id: recording_id.clone(),
            recording_seq: 1,
            method: "GET".to_owned(),
            ..RecordingStarted::default()
        })];
        // Exercise abandonment immediately after Start and after an acknowledged event.
        let has_prefix = abandoned && request % 2 == 0;
        if has_prefix {
            payloads.push(PayloadOneof::EventBatch(EventBatch {
                recording_id: recording_id.clone(),
                events: vec![RecordingEvent {
                    event_id: "observed-prefix".to_owned(),
                    recording_seq: 2,
                    monotonic_ns: 10,
                    kind: RecordingEventKind::FrameEnter as i32,
                    symbol: "fixture.handler".to_owned(),
                    ..RecordingEvent::default()
                }],
            }));
        }
        // Missing digest is unknown terminal loss, independently of measured drops. Cover a
        // prefix whose events all arrived and both empty/nonempty prefixes with known drops.
        let known_drops = if abandoned && request % 3 == 0 { 7 } else { 0 };
        payloads.push(PayloadOneof::RecordingFinished(RecordingFinished {
            recording_id: recording_id.clone(),
            final_recording_seq: if has_prefix { 2 } else { 1 },
            drop_counts_by_priority: if known_drops > 0 {
                [(1, known_drops)].into_iter().collect()
            } else {
                Default::default()
            },
            ..RecordingFinished::default()
        }));
        for payload in payloads {
            write_envelope(&mut writer, payload, &session_id, session_seq, session_seq)
                .await
                .expect("write recording envelope");
            let ack = next_ack(&mut reader, &format!("request {request} ack")).await;
            assert_eq!(ack.highest_contiguous_session_seq, session_seq);
            assert!(ack.rejected.is_empty(), "request {request} was rejected: {:?}", ack.rejected);
            assert_eq!(ack.durability, AckDurability::Staged as i32);
            session_seq += 1;
        }
        if abandoned {
            let window = persisted
                .show_recording(&ShowWindowRequest {
                    project_id,
                    recording_id: RecordingId::from_uuid(
                        uuid::Uuid::from_slice(&recording_id).expect("recording UUID"),
                    ),
                    limit: 10,
                    after_sequence: None,
                })
                .expect("abandoned recording reads at finish ACK");
            assert_eq!(window.status, RecordingStatus::Partial);
            assert_eq!(window.completion, RecordingCompletionEvidence::Partial);
            assert_eq!(window.events.len(), usize::from(has_prefix));
            let expected_drops = if known_drops > 0 {
                [(1, known_drops.to_string())].into()
            } else {
                Default::default()
            };
            assert_eq!(window.drop_counts_by_priority, expected_drops);
            assert!(window.duration_ns.is_none(), "no duration was observed");
            // A minimal Finish is terminal evidence. The read contract exposes an
            // unobserved outcome for it; null is reserved for no Finish at all.
            let outcome = window.outcome.expect("minimal Finish has unobserved terminal evidence");
            assert_eq!(outcome.kind, "unobserved");
            assert!(outcome.http_status.is_none(), "no HTTP status was observed");
            assert!(outcome.exception.is_none(), "no exception was observed");
            assert!(outcome.thrown_from_event_id.is_none(), "no throw link was observed");
            assert!(!window.incomplete_evidence.is_empty());
        }
    }

    if abandoned {
        let companion = persisted
            .show_recording(&ShowWindowRequest {
                project_id,
                recording_id: companion_id,
                limit: 10,
                after_sequence: None,
            })
            .expect("companion remained active across abandoned requests");
        assert_eq!(companion.status, RecordingStatus::Recording);
        assert!(companion.outcome.is_none(), "the active companion has no Finish evidence");
        let later_id = RecordingId::new();
        let later_bytes = Bytes::copy_from_slice(later_id.as_uuid().as_bytes());
        // A subsequent recording and the still-active companion both finish as verified complete.
        for payload in [
            PayloadOneof::RecordingStarted(RecordingStarted {
                recording_id: later_bytes.clone(),
                recording_seq: 1,
                method: "GET".to_owned(),
                ..RecordingStarted::default()
            }),
            PayloadOneof::RecordingFinished(RecordingFinished {
                recording_id: later_bytes,
                final_recording_seq: 1,
                event_digest: Bytes::copy_from_slice(blake3::hash(&[]).as_bytes()),
                ..RecordingFinished::default()
            }),
            PayloadOneof::RecordingFinished(RecordingFinished {
                recording_id: companion_bytes,
                final_recording_seq: 1,
                event_digest: Bytes::copy_from_slice(blake3::hash(&[]).as_bytes()),
                ..RecordingFinished::default()
            }),
        ] {
            write_envelope(&mut writer, payload, &session_id, session_seq, session_seq)
                .await
                .expect("later recording and companion completion");
            let ack = next_ack(&mut reader, "completion after repeated abandonment").await;
            assert_eq!(ack.highest_contiguous_session_seq, session_seq);
            assert!(ack.rejected.is_empty());
            session_seq += 1;
        }
        for recording_id in [later_id, companion_id] {
            let window = persisted
                .show_recording(&ShowWindowRequest {
                    project_id,
                    recording_id,
                    limit: 10,
                    after_sequence: None,
                })
                .expect("verified complete recording");
            assert_eq!(window.status, RecordingStatus::Complete);
            assert_eq!(window.completion, RecordingCompletionEvidence::Complete);
            assert!(window.incomplete_evidence.is_empty());
            assert_eq!(window.duration_ns.as_deref(), Some("0"));
        }
    }

    // Acks are staged; read the store back (second read-only connection) until every
    // recording is durable and finished, so the test proves the persisted outcome too.
    let database = project_root.path().join("metadata.sqlite3");
    let wanted = i64::try_from(FINISHED_REQUESTS + if abandoned { 2 } else { 0 }).expect("fits");
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
