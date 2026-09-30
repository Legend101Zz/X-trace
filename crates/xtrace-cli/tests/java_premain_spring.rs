#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "end-to-end test asserts on controlled local process and fixture state"
)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use prost::Message as _;
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;
use xtrace_domain::ContentHash;
use xtrace_protocol::generated::agent::{InteractionKind, RecordingEvent, RecordingEventKind};
use xtrace_protocol::xtf::{XtfEventEnvelope, XtfHeader};
use xtrace_store::verify_compressed_segment;

const CANARIES: &[&str] = &[
    "BODY_CANARY_1D3",
    "AUTH_CANARY_1D3",
    "COOKIE_CANARY_1D3",
    "HEADER_CANARY_1D3",
    "QUERY_CANARY_1D3",
    "SQL_BIND_CANARY_1D3",
    "ERROR_CANARY_1D3",
];

struct ManagedChild(Child);

impl std::ops::Deref for ManagedChild {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ManagedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct CapturedProcess {
    child: ManagedChild,
    stdout: thread::JoinHandle<ScannedOutput>,
    stderr: thread::JoinHandle<ScannedOutput>,
}

impl CapturedProcess {
    fn spawn(mut command: Command, label: &str) -> Self {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = ManagedChild(command.spawn().unwrap_or_else(|error| {
            panic!("spawn {label}: {error}");
        }));
        let mut stdout = child.stdout.take().expect("captured child stdout");
        let mut stderr = child.stderr.take().expect("captured child stderr");
        Self {
            child,
            stdout: thread::spawn(move || drain_scanned(&mut stdout, 256 * 1024)),
            stderr: thread::spawn(move || drain_scanned(&mut stderr, 256 * 1024)),
        }
    }

    fn stop(mut self) -> (ScannedOutput, ScannedOutput) {
        signal_and_wait(&mut self.child, "-TERM");
        let stdout = self.stdout.join().expect("join fixture stdout");
        let stderr = self.stderr.join().expect("join fixture stderr");
        (stdout, stderr)
    }
}

#[test]
fn premain_captures_real_spring_request_and_fails_open_without_leaking_canaries() {
    let root = temp_root();
    let repo = root.path().join("repository with spaces");
    let data_home = root.path().join("data home");
    fs::create_dir_all(&repo).expect("create repository");
    let initialized = run_cli(&["init", "--project-dir"], &repo, &data_home);
    assert!(initialized.status.success(), "init failed: {}", text(&initialized.stderr));

    let mut daemon = ManagedChild(
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["daemon", "--project-dir"])
            .arg(&repo)
            .env("XTRACE_DATA_HOME", &data_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn xtrace daemon"),
    );
    let stdout = daemon.stdout.take().expect("daemon stdout");
    let mut daemon_stderr = daemon.stderr.take().expect("daemon stderr");
    let daemon_stderr_reader = thread::spawn(move || drain_scanned(&mut daemon_stderr, 64 * 1024));
    let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
    let readiness_reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let _ = ready_send.send((reader, line, result));
    });
    let (mut daemon_stdout, readiness, read_result) = ready_receive
        .recv_timeout(Duration::from_secs(10))
        .expect("daemon readiness within deadline");
    read_result.expect("read daemon readiness");
    let daemon_stdout_reader = thread::spawn(move || drain_scanned(&mut daemon_stdout, 64 * 1024));
    let ready: Value = serde_json::from_str(&readiness).expect("readiness JSON");
    let bootstrap = PathBuf::from(ready["bootstrap_path"].as_str().expect("bootstrap path"));
    let project_id = ready["project_id"].as_str().expect("project id");
    let project_root = data_home.join("projects").join(project_id);
    let unavailable_bootstrap = copy_private_bootstrap(root.path(), &bootstrap);

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        repo_root.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    let fixture =
        repo_root.join("adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar");
    assert!(agent.is_file(), "Gradle agentDist must run before this test");
    assert!(fixture.is_file(), "Gradle fixtureBootJar must run before this test");
    assert_agent_distribution_is_private(&agent, &fixture);

    let mut java_version_command = Command::new("java");
    java_version_command.arg("-version");
    let java_version = bounded_output(java_version_command, "java -version");
    assert!(java_version.status.success());
    let version_text = text(&java_version.stderr);
    assert!(
        version_text.contains("17.") || version_text.contains("21."),
        "local proof requires JDK 17 or 21, got: {version_text}"
    );

    let port = free_port();
    let valid = launch_fixture(&agent, &fixture, &bootstrap, port);
    wait_for_fixture(port);
    let isolation = http(port, "GET", "/__fixture/isolation", &[], None);
    assert_eq!(isolation.status, 200);
    let isolation_json: Value = serde_json::from_slice(&isolation.body).expect("isolation JSON");
    for key in ["byte_buddy", "protobuf", "conscrypt", "agent_runtime"] {
        assert_eq!(isolation_json[key], false, "{key} leaked into application classloader");
    }

    let response = post_order(port);
    assert_eq!(response.status, 201);
    assert_eq!(response.body, br#"{"status":"created"}"#);
    let count = http(port, "GET", "/__fixture/count", &[], None);
    assert_eq!(serde_json::from_slice::<Value>(&count.body).unwrap()["count"], 1);

    let recordings = wait_for_recordings(&project_root, 1);
    let (recording_id, object) = &recordings[0];
    let logical = zstd::stream::decode_all(object.as_slice()).expect("decompress stored XTF");
    let events = decode_events(&logical);
    assert_real_event_order(&events);
    assert_canaries_absent("decoded XTF", &logical);

    let error_response = post_error(port);
    assert_eq!(error_response.status, 500);
    assert_eq!(error_response.body, br#"{"status":"failed"}"#);
    let count = http(port, "GET", "/__fixture/count", &[], None);
    assert_eq!(serde_json::from_slice::<Value>(&count.body).unwrap()["count"], 1);
    let recordings = wait_for_recordings(&project_root, 2);
    let error_logical =
        zstd::stream::decode_all(recordings[1].1.as_slice()).expect("decompress error XTF");
    let error_events = decode_events(&error_logical);
    assert_error_event_order(&error_events);
    assert_canaries_absent("decoded error XTF", &error_logical);

    let database = project_root.join("metadata.sqlite3");
    let before_query = database_state(&database);
    let pointer = repo.join(".xtrace/config.toml");
    let pointer_before = file_metadata_state(&pointer);
    let listed = run_cli(&["recording", "list", "--project-dir"], &repo, &data_home);
    assert!(listed.status.success(), "recording list failed: {}", text(&listed.stderr));
    let listed_again = run_cli(&["recording", "list", "--project-dir"], &repo, &data_home);
    assert!(listed_again.status.success(), "repeat list failed: {}", text(&listed_again.stderr));
    assert_eq!(listed.stdout, listed_again.stdout, "list JSON changes across processes");
    let list_json: Value = serde_json::from_slice(&listed.stdout).expect("recording list JSON");
    let rows = list_json["recordings"].as_array().expect("recordings array");
    assert_eq!(rows.len(), 2, "two completed fixture requests are listed");
    let ids = rows
        .iter()
        .map(|row| row["recording_id"].as_str().expect("recording ID").to_owned())
        .collect::<Vec<_>>();
    for recording_id in &ids {
        let shown = run_recording_show_cli(&repo, &data_home, recording_id);
        assert!(shown.status.success(), "recording show failed: {}", text(&shown.stderr));
        let shown_again = run_recording_show_cli(&repo, &data_home, recording_id);
        assert!(shown_again.status.success(), "repeat show failed: {}", text(&shown_again.stderr));
        assert_eq!(shown.stdout, shown_again.stdout, "show JSON changes across processes");
        let detail: Value = serde_json::from_slice(&shown.stdout).expect("recording show JSON");
        let events = detail["events"].as_array().expect("event window");
        assert!(!events.is_empty(), "each request has persisted event evidence");
        assert!(events.windows(2).all(|pair| {
            pair[0]["sequence"].as_str().expect("sequence").parse::<u64>().unwrap()
                < pair[1]["sequence"].as_str().expect("sequence").parse::<u64>().unwrap()
        }));
        assert_eq!(detail["unavailable"]["source"], "unavailable");
        assert_eq!(detail["unavailable"]["values"], "unavailable");
        assert_eq!(detail["unavailable"]["completion"], "unavailable");
        assert_canaries_absent("recording query output", &shown.stdout);
    }
    let mut unknown_id = ids[0].clone().into_bytes();
    unknown_id[0] = if unknown_id[0] == b'0' { b'1' } else { b'0' };
    let unknown_id = String::from_utf8(unknown_id).expect("recording ID is ASCII");
    let missing = run_recording_show_cli(&repo, &data_home, &unknown_id);
    assert!(!missing.status.success(), "unknown recording ID must fail");
    assert_canaries_absent("unknown recording error", &missing.stderr);
    assert_eq!(database_state(&database), before_query, "query commands wrote store state");
    assert_eq!(file_metadata_state(&pointer), pointer_before, "query rewrote repo pointer");

    let copied_repo = root.path().join("repository with copied pointer");
    fs::create_dir_all(copied_repo.join(".xtrace")).expect("create copied pointer directory");
    fs::copy(&pointer, copied_repo.join(".xtrace/config.toml")).expect("copy repository pointer");
    let copied_pointer = copied_repo.join(".xtrace/config.toml");
    let copied_pointer_before = file_metadata_state(&copied_pointer);
    let wrong_repository =
        run_cli(&["recording", "list", "--project-dir"], &copied_repo, &data_home);
    assert!(!wrong_repository.status.success(), "copied pointer must not bypass repo binding");
    assert!(!text(&wrong_repository.stderr).contains(copied_repo.to_string_lossy().as_ref()));
    assert_eq!(database_state(&database), before_query, "fingerprint failure wrote store state");
    assert_eq!(file_metadata_state(&pointer), pointer_before, "fingerprint check rewrote pointer");
    assert_eq!(file_metadata_state(&copied_pointer), copied_pointer_before);

    let wrong_data_home = root.path().join("different XTRACE_DATA_HOME");
    fs::create_dir_all(&wrong_data_home).expect("create alternate data home");
    let wrong_home_list = run_cli(&["recording", "list", "--project-dir"], &repo, &wrong_data_home);
    assert!(!wrong_home_list.status.success(), "mismatched data home must fail closed");
    assert_canaries_absent("wrong data-home error", &wrong_home_list.stderr);
    assert!(!wrong_data_home.join("projects").exists(), "query created project directories");
    assert_eq!(database_state(&database), before_query, "data-home failure wrote store state");
    assert_eq!(file_metadata_state(&pointer), pointer_before, "data-home failure rewrote pointer");

    signal_and_wait(&mut daemon, "-INT");
    let disconnected_response = post_order(port);
    assert_eq!(disconnected_response.status, 201, "daemon disconnect changed app behavior");
    let disconnected_count = http(port, "GET", "/__fixture/count", &[], None);
    assert_eq!(serde_json::from_slice::<Value>(&disconnected_count.body).unwrap()["count"], 2);
    thread::sleep(Duration::from_millis(250));
    let (valid_stdout, valid_stderr) = valid.stop();
    assert!(
        text(&valid_stderr.sample).contains("XTR-JAVA-CAPTURE-INCOMPLETE"),
        "forced disconnect must report incomplete telemetry: {}",
        text(&valid_stderr.sample)
    );

    let unavailable_port = free_port();
    let unavailable = launch_fixture(&agent, &fixture, &unavailable_bootstrap, unavailable_port);
    wait_for_fixture(unavailable_port);
    assert_eq!(post_order(unavailable_port).status, 201);
    let (unavailable_stdout, unavailable_stderr) = unavailable.stop();
    assert!(text(&unavailable_stderr.sample).contains("XTR-JAVA-AGENT-UNAVAILABLE"));

    let invalid_port = free_port();
    let invalid_path = root.path().join("missing private bootstrap.json");
    let invalid = launch_fixture(&agent, &fixture, &invalid_path, invalid_port);
    wait_for_fixture(invalid_port);
    assert_eq!(post_order(invalid_port).status, 201);
    let (invalid_stdout, invalid_stderr) = invalid.stop();
    assert!(text(&invalid_stderr.sample).contains("XTR-JAVA-AGENT-UNAVAILABLE"));

    for (surface, output) in [
        ("valid stdout", &valid_stdout),
        ("valid stderr", &valid_stderr),
        ("unavailable stdout", &unavailable_stdout),
        ("unavailable stderr", &unavailable_stderr),
        ("invalid stdout", &invalid_stdout),
        ("invalid stderr", &invalid_stderr),
    ] {
        assert_scanned_clean(surface, output);
    }

    let mut privacy_surfaces = vec![
        ("HTTP response", response.body),
        ("error HTTP response", error_response.body),
        ("daemon readiness", readiness.into_bytes()),
    ];
    privacy_surfaces
        .extend(read_files(&project_root).into_iter().map(|bytes| ("X-trace store", bytes)));
    for (surface, bytes) in privacy_surfaces {
        assert_canaries_absent(surface, &bytes);
    }
    assert!(!recording_id.is_empty());
    let daemon_error = daemon_stderr_reader.join().expect("join daemon stderr");
    assert_scanned_clean("daemon stderr", &daemon_error);
    assert!(daemon_error.sample.is_empty(), "daemon diagnostics: {}", text(&daemon_error.sample));
    let daemon_output = daemon_stdout_reader.join().expect("join daemon stdout");
    assert_scanned_clean("daemon stdout", &daemon_output);
    readiness_reader.join().expect("join daemon readiness reader");
}

fn database_state(database: &Path) -> Vec<(PathBuf, Option<Vec<u8>>, Option<SystemTime>)> {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
        PathBuf::from(format!("{}-journal", database.display())),
    ]
    .into_iter()
    .map(|path| {
        let metadata = fs::metadata(&path).ok();
        let content = metadata.as_ref().and_then(|_| fs::read(&path).ok());
        let modified = metadata.as_ref().and_then(|value| value.modified().ok());
        (path, content, modified)
    })
    .collect()
}

#[cfg(unix)]
fn file_metadata_state(path: &Path) -> (Vec<u8>, SystemTime, u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::metadata(path).expect("read file metadata");
    (
        fs::read(path).expect("read file bytes"),
        metadata.modified().expect("read modification time"),
        metadata.permissions().mode(),
    )
}

#[test]
fn shared_java_rust_event_digest_golden_matches() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schema/fixtures/java-premain-event-digest.json");
    let value: Value = serde_json::from_slice(&fs::read(fixture).expect("read digest golden"))
        .expect("parse digest golden");
    let mut bytes = Vec::new();
    for id in value["event_ids"].as_array().expect("event IDs") {
        bytes.extend_from_slice(id.as_str().expect("event ID string").as_bytes());
    }
    assert_eq!(
        blake3::hash(&bytes).to_hex().as_str(),
        value["concatenated_utf8_blake3"].as_str().expect("golden digest")
    );
}

#[test]
fn output_scanner_detects_canary_after_sample_and_across_read_boundary() {
    let mut stream = vec![b'x'; 4_090];
    stream.extend_from_slice(b"ERROR_CANARY_1D3");
    let output = drain_scanned(&mut stream.as_slice(), 16);
    assert_eq!(output.sample, vec![b'x'; 16]);
    assert_eq!(output.leaked_canaries, vec!["ERROR_CANARY_1D3"]);
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("canonical temporary root");
    tempfile::Builder::new()
        .prefix("xtrace java premain ")
        .tempdir_in(base)
        .expect("temporary test root")
}

fn run_cli(args: &[&str], repo: &Path, data_home: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(args)
        .arg(repo)
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("run xtrace CLI")
}

fn run_recording_show_cli(
    repo: &Path,
    data_home: &Path,
    recording_id: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["recording", "show", "--project-dir"])
        .arg(repo)
        .arg(recording_id)
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("run xtrace recording show")
}

fn copy_private_bootstrap(root: &Path, source: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let parent = root.join("private unavailable bootstrap");
    fs::create_dir(&parent).expect("create private bootstrap parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("secure parent");
    let target = parent.join("bootstrap.json");
    fs::copy(source, &target).expect("copy bootstrap for unavailable daemon");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("secure bootstrap");
    target
}

fn launch_fixture(agent: &Path, fixture: &Path, bootstrap: &Path, port: u16) -> CapturedProcess {
    let mut command = Command::new("java");
    command
        .arg(format!("-javaagent:{}={}", agent.display(), bootstrap.display()))
        .args(["-jar"])
        .arg(fixture)
        .arg(format!("--server.port={port}"));
    CapturedProcess::spawn(command, "Spring fixture")
}

fn wait_for_fixture(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = try_http(port, "GET", "/__fixture/count", &[], None) {
            if response.status == 200 {
                return;
            }
        }
        assert!(Instant::now() < deadline, "Spring fixture did not become ready");
        thread::sleep(Duration::from_millis(25));
    }
}

fn post_order(port: u16) -> HttpResponse {
    let body =
        br#"{"description":"SQL_BIND_CANARY_1D3","bodyCanary":"BODY_CANARY_1D3","errorCanary":""}"#;
    post_fixture_request(port, body)
}

fn post_error(port: u16) -> HttpResponse {
    let body = br#"{"description":"safe","bodyCanary":"BODY_CANARY_1D3","errorCanary":"ERROR_CANARY_1D3"}"#;
    post_fixture_request(port, body)
}

fn post_fixture_request(port: u16, body: &[u8]) -> HttpResponse {
    http(
        port,
        "POST",
        "/orders?probe=QUERY_CANARY_1D3",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer AUTH_CANARY_1D3"),
            ("Cookie", "session=COOKIE_CANARY_1D3"),
            ("X-Canary", "HEADER_CANARY_1D3"),
        ],
        Some(body),
    )
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResponse {
    try_http(port, method, path, headers, body).expect("fixture HTTP request")
}

fn try_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> std::io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let payload = body.unwrap_or_default();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n")?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Content-Length: {}\r\n\r\n", payload.len())?;
    stream.write_all(payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&response[..split]).unwrap();
    let status = head.lines().next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    let raw_body = &response[split + 4..];
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        decode_chunked(raw_body)?
    } else {
        raw_body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk length"))?;
        let length = usize::from_str_radix(
            std::str::from_utf8(&input[..end])
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk UTF-8"))?,
            16,
        )
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk integer"))?;
        input = &input[end + 2..];
        if length == 0 {
            return Ok(output);
        }
        if input.len() < length + 2 || &input[length..length + 2] != b"\r\n" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk body"));
        }
        output.extend_from_slice(&input[..length]);
        input = &input[length + 2..];
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

fn wait_for_recordings(project_root: &Path, expected_count: usize) -> Vec<(String, Vec<u8>)> {
    let database = project_root.join("metadata.sqlite3");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let connection = Connection::open(&database).expect("selected-root SQLite");
        let mut statement = connection
            .prepare(
                "SELECT hex(rs.recording_id), rs.object_hash \
                 FROM recording_segments rs WHERE rs.segment_ordinal = 0 ORDER BY rs.rowid",
            )
            .expect("prepare recording query");
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))
            .expect("query recordings")
            .collect::<Result<Vec<_>, _>>()
            .expect("read recording rows");
        if rows.len() >= expected_count {
            return rows
                .into_iter()
                .map(|(recording_hex, object_hash)| {
                    let hash = lower_hex(&object_hash);
                    let path = project_root
                        .join("objects/b3")
                        .join(&hash[..2])
                        .join(format!("{}.xtf.zst", &hash[2..]));
                    let object = fs::read(path).expect("read immutable XTF object");
                    let expected = format!("b3:{hash}").parse::<ContentHash>().unwrap();
                    verify_compressed_segment(&object, expected).expect("verify XTF object");
                    (recording_hex, object)
                })
                .collect();
        }
        assert!(
            Instant::now() < deadline,
            "{expected_count} recordings were not persisted before deadline"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn decode_events(logical: &[u8]) -> Vec<RecordingEvent> {
    let header_len = u32::from_be_bytes(logical[8..12].try_into().unwrap()) as usize;
    let header = XtfHeader::decode(&logical[12..12 + header_len]).expect("decode XTF header");
    let mut offset = 12 + header_len;
    let mut events = Vec::new();
    for _ in 0..header.event_count {
        let length = u32::from_be_bytes(logical[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let envelope = XtfEventEnvelope::decode(&logical[offset..offset + length]).unwrap();
        events.push(envelope.event.expect("typed event"));
        offset += length;
    }
    events
}

fn assert_real_event_order(events: &[RecordingEvent]) {
    let expected = [
        (RecordingEventKind::RequestUpdate, "http.request POST /orders"),
        (RecordingEventKind::FrameEnter, "OrderController.create"),
        (RecordingEventKind::FrameEnter, "OrderService.place"),
        (RecordingEventKind::FrameEnter, "OrderRepository.save"),
        (RecordingEventKind::DatabaseStart, "h2.executeUpdate"),
        (RecordingEventKind::DatabaseEnd, "h2.executeUpdate"),
        (RecordingEventKind::FrameExit, "OrderRepository.save"),
        (RecordingEventKind::FrameExit, "OrderService.place"),
        (RecordingEventKind::FrameExit, "OrderController.create"),
        (RecordingEventKind::Response, "http.response 201"),
    ];
    assert_eq!(events.len(), expected.len());
    for (index, (event, (kind, symbol))) in events.iter().zip(expected).enumerate() {
        assert_eq!(event.recording_seq, index as u64 + 2);
        assert_eq!(event.kind, kind as i32);
        assert_eq!(event.symbol, symbol);
    }
    assert_eq!(events[1].parent_event_id, events[0].event_id);
    assert_eq!(events[2].parent_event_id, events[1].event_id);
    assert_eq!(events[3].parent_event_id, events[2].event_id);
    assert_eq!(events[4].parent_event_id, events[3].event_id);
    assert_eq!(events[5].parent_event_id, events[4].event_id);
    assert_eq!(events[6].parent_event_id, events[3].event_id);
    assert_eq!(events[7].parent_event_id, events[2].event_id);
    assert_eq!(events[8].parent_event_id, events[1].event_id);
    assert_eq!(events[9].parent_event_id, events[0].event_id);
    let request = events[0].interaction.as_ref().unwrap();
    assert_eq!(request.kind, InteractionKind::Framework as i32);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/orders");
    let database = events[4].interaction.as_ref().unwrap();
    assert_eq!(database.kind, InteractionKind::Database as i32);
    assert_eq!(database.driver, "h2");
    assert_eq!(database.method, "executeUpdate");
    assert!(database.table.is_empty());
    let response = events[9].interaction.as_ref().unwrap();
    assert_eq!(response.method, "status");
    assert_eq!(response.path, "201");
}

fn assert_error_event_order(events: &[RecordingEvent]) {
    let expected = [
        (RecordingEventKind::RequestUpdate, "http.request POST /orders"),
        (RecordingEventKind::FrameEnter, "OrderController.create"),
        (RecordingEventKind::FrameEnter, "OrderService.place"),
        (RecordingEventKind::FrameThrow, "OrderService.place"),
        (RecordingEventKind::FrameExit, "OrderController.create"),
        (RecordingEventKind::Response, "http.response 500"),
    ];
    assert_eq!(events.len(), expected.len());
    for (event, (kind, symbol)) in events.iter().zip(expected) {
        assert_eq!(event.kind, kind as i32);
        assert_eq!(event.symbol, symbol);
    }
    assert_eq!(events[1].parent_event_id, events[0].event_id);
    assert_eq!(events[2].parent_event_id, events[1].event_id);
    assert_eq!(events[3].parent_event_id, events[2].event_id);
    assert_eq!(events[4].parent_event_id, events[1].event_id);
    assert_eq!(events[5].parent_event_id, events[0].event_id);
}

fn assert_agent_distribution_is_private(agent: &Path, fixture: &Path) {
    let mut agent_scan = Command::new("jar");
    agent_scan.args(["tf"]).arg(agent);
    let agent_entries = bounded_output(agent_scan, "agent jar scan");
    assert!(agent_entries.status.success());
    let entries = text(&agent_entries.stdout);
    for forbidden in
        ["net/bytebuddy/", "com/google/protobuf/", "org/conscrypt/", "org/springframework/"]
    {
        assert!(!entries.contains(forbidden), "bootstrap jar leaked {forbidden}");
    }
    let mut fixture_scan = Command::new("jar");
    fixture_scan.args(["tf"]).arg(fixture);
    let fixture_entries = bounded_output(fixture_scan, "fixture jar scan");
    assert!(fixture_entries.status.success());
    assert!(!text(&fixture_entries.stdout).contains("dev/xtrace/agent/"));
}

fn assert_canaries_absent(surface: &str, bytes: &[u8]) {
    for canary in CANARIES {
        assert!(
            !bytes.windows(canary.len()).any(|window| window == canary.as_bytes()),
            "{canary} leaked into {surface}"
        );
    }
}

struct ScannedOutput {
    sample: Vec<u8>,
    leaked_canaries: Vec<&'static str>,
}

fn assert_scanned_clean(surface: &str, output: &ScannedOutput) {
    assert!(
        output.leaked_canaries.is_empty(),
        "canaries {:?} leaked into {surface}",
        output.leaked_canaries
    );
}

fn read_files(root: &Path) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).expect("privacy scan metadata");
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).expect("privacy scan directory") {
                pending.push(entry.expect("privacy scan entry").path());
            }
        } else if metadata.is_file() {
            result.push(fs::read(path).expect("privacy scan file"));
        }
    }
    result
}

fn drain_scanned(reader: &mut impl Read, limit: usize) -> ScannedOutput {
    let mut kept = Vec::new();
    let mut leaked_canaries = Vec::new();
    let mut tail = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader.read(&mut buffer).expect("drain child output");
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
        let mut searchable = Vec::with_capacity(tail.len() + count);
        searchable.extend_from_slice(&tail);
        searchable.extend_from_slice(&buffer[..count]);
        for canary in CANARIES {
            if !leaked_canaries.contains(canary)
                && searchable.windows(canary.len()).any(|window| window == canary.as_bytes())
            {
                leaked_canaries.push(*canary);
            }
        }
        let tail_length = CANARIES
            .iter()
            .map(|canary| canary.len().saturating_sub(1))
            .max()
            .unwrap_or_default()
            .min(searchable.len());
        tail.clear();
        tail.extend_from_slice(&searchable[searchable.len() - tail_length..]);
    }
    ScannedOutput { sample: kept, leaked_canaries }
}

fn signal_and_wait(child: &mut Child, signal: &str) {
    if child.try_wait().expect("poll child before signal").is_some() {
        return;
    }
    let pid = child.id().to_string();
    assert!(Command::new("kill").args([signal, &pid]).status().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().expect("poll child").is_some() {
            return;
        }
        assert!(Instant::now() < deadline, "child did not stop after {signal}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn bounded_output(mut command: Command, label: &str) -> std::process::Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{label} exceeded its timeout");
        }
        thread::sleep(Duration::from_millis(10));
    };
    std::process::Output { status, stdout: out.join().unwrap(), stderr: err.join().unwrap() }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
